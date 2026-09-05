//! Persistance des sessions de rafraîchissement, dans un `Secret` par utilisateur.
//!
//! Un `Secret` distinct de celui des credentials, et non un champ de plus dans le même : le
//! store des credentials écrit en Server-Side Apply avec `force`, ce qui efface les champs
//! absents de l'objet appliqué. Une session ouverte pendant qu'un mot de passe est réinitialisé
//! disparaîtrait sans que rien ne le signale.
//!
//! Les écritures sont conditionnées par la `resourceVersion` : deux `kubectl` lancés en même
//! temps sur deux postes ouvrent deux sessions, et aucune ne doit effacer l'autre. Le perdant
//! relit et rejoue, il n'écrase pas.

use crate::sessions::refresh::SessionSet;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kdt_identity_api::KdtUser;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::{Resource, ResourceExt};
use std::collections::BTreeMap;

/// Préfixe du nom des `Secret` de sessions.
pub const SECRET_PREFIX: &str = "kdt-identity-oidc-";

/// Type du `Secret`, pour le distinguer d'un `Opaque` quelconque dans le namespace.
pub const SECRET_TYPE: &str = "identity.kdt.sh/oidc-sessions";

const SESSIONS_FIELD: &str = "sessions";

/// Nombre de tentatives avant d'abandonner une écriture en conflit.
///
/// Trois : au-delà, ce n'est plus une course entre deux clients mais un problème qu'un
/// quatrième essai ne réglera pas.
const MAX_ATTEMPTS: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("appel à l'API Kubernetes : {0}")]
    Kube(#[from] kube::Error),
    #[error("les sessions stockées sont illisibles : {0}")]
    Corrupt(String),
    #[error("le KdtUser {0:?} n'a pas d'UID : impossible de rattacher ses sessions")]
    NoUid(String),
    #[error("écriture en conflit après {MAX_ATTEMPTS} tentatives")]
    Contended,
}

pub fn secret_name(user: &str) -> String {
    format!("{SECRET_PREFIX}{user}")
}

#[derive(Clone)]
pub struct SessionStore {
    secrets: Api<Secret>,
}

impl SessionStore {
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            secrets: Api::namespaced(client, namespace),
        }
    }

    /// Lit les sessions d'un compte. Un compte qui ne s'est jamais connecté n'a pas de `Secret`,
    /// ce qui n'est pas une erreur : c'est un ensemble vide.
    pub async fn get(&self, user: &str) -> Result<SessionSet, SessionStoreError> {
        match self.secrets.get_opt(&secret_name(user)).await? {
            Some(secret) => decode(&secret),
            None => Ok(SessionSet::default()),
        }
    }

    /// Applique `change` aux sessions du compte et écrit le résultat.
    ///
    /// La fonction peut être appelée plusieurs fois : en cas de conflit, l'état est relu et le
    /// changement rejoué dessus. Elle ne doit donc rien faire d'autre que modifier l'ensemble
    /// qu'on lui passe.
    pub async fn update<T>(
        &self,
        user: &KdtUser,
        mut change: impl FnMut(&mut SessionSet) -> T,
    ) -> Result<T, SessionStoreError> {
        let name = user.name_any();
        let uid = user.uid().ok_or_else(|| SessionStoreError::NoUid(name.clone()))?;

        for _ in 0..MAX_ATTEMPTS {
            let existing = self.secrets.get_opt(&secret_name(&name)).await?;
            let mut sessions = match &existing {
                Some(secret) => decode(secret)?,
                None => SessionSet::default(),
            };

            let outcome = change(&mut sessions);
            let body = encode(&name, &uid, &sessions, existing.as_ref())?;

            let written = match &existing {
                Some(_) => self
                    .secrets
                    .replace(&secret_name(&name), &PostParams::default(), &body)
                    .await
                    .map(|_| ()),
                None => self
                    .secrets
                    .create(&PostParams::default(), &body)
                    .await
                    .map(|_| ()),
            };

            match written {
                Ok(()) => return Ok(outcome),
                // 409 : quelqu'un a écrit entre notre lecture et notre écriture. On relit.
                Err(kube::Error::Api(e)) if e.code == 409 => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err(SessionStoreError::Contended)
    }
}

fn encode(
    user: &str,
    uid: &str,
    sessions: &SessionSet,
    existing: Option<&Secret>,
) -> Result<Secret, SessionStoreError> {
    let json = serde_json::to_vec(sessions)
        .map_err(|e| SessionStoreError::Corrupt(format!("sérialisation : {e}")))?;

    Ok(Secret {
        metadata: ObjectMeta {
            name: Some(secret_name(user)),
            // Présente seulement sur une mise à jour : c'est elle qui fait échouer l'écriture
            // si l'objet a changé entre-temps.
            resource_version: existing.and_then(|s| s.metadata.resource_version.clone()),
            owner_references: Some(vec![
                k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                    api_version: KdtUser::api_version(&()).to_string(),
                    kind: KdtUser::kind(&()).to_string(),
                    name: user.to_string(),
                    uid: uid.to_string(),
                    block_owner_deletion: Some(false),
                    controller: Some(true),
                },
            ]),
            ..Default::default()
        },
        type_: Some(SECRET_TYPE.to_string()),
        data: Some(BTreeMap::from([(
            SESSIONS_FIELD.to_string(),
            ByteString(json),
        )])),
        ..Default::default()
    })
}

/// Relit un `Secret` de sessions.
///
/// Un contenu illisible est une erreur, jamais un ensemble vide : traiter un JSON corrompu
/// comme « aucune session » referait passer pour révoqué quelqu'un qui ne l'est pas — et
/// surtout, la révocation suivante croirait n'avoir rien à faire.
fn decode(secret: &Secret) -> Result<SessionSet, SessionStoreError> {
    let Some(raw) = secret.data.as_ref().and_then(|d| d.get(SESSIONS_FIELD)) else {
        return Ok(SessionSet::default());
    };
    serde_json::from_slice(&raw.0).map_err(|e| SessionStoreError::Corrupt(format!("JSON : {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn secret_with(sessions: &SessionSet) -> Secret {
        Secret {
            data: Some(BTreeMap::from([(
                SESSIONS_FIELD.to_string(),
                ByteString(serde_json::to_vec(sessions).unwrap()),
            )])),
            ..Default::default()
        }
    }

    #[test]
    fn un_aller_retour_preserve_les_sessions() {
        let mut sessions = SessionSet::default();
        let issued = sessions.open(now(), chrono::Duration::days(7));

        let relu = decode(&secret_with(&sessions)).unwrap();
        assert!(relu.verify(&issued.token, now()).is_ok());
    }

    #[test]
    fn un_secret_sans_champ_vaut_aucune_session() {
        assert!(decode(&Secret::default()).unwrap().is_empty());
    }

    /// Un JSON corrompu doit remonter comme une erreur : le lire « zéro session » ferait croire
    /// à une révocation déjà faite.
    #[test]
    fn un_contenu_corrompu_est_une_erreur() {
        let secret = Secret {
            data: Some(BTreeMap::from([(
                SESSIONS_FIELD.to_string(),
                ByteString(b"{ pas du JSON".to_vec()),
            )])),
            ..Default::default()
        };
        assert!(decode(&secret).is_err());
    }

    /// La `resourceVersion` n'est posée que sur une mise à jour. Sur une création, l'API la
    /// refuserait.
    #[test]
    fn la_version_n_est_posee_que_sur_une_mise_a_jour() {
        let sessions = SessionSet::default();

        let creation = encode("alice", "uid-1", &sessions, None).unwrap();
        assert!(creation.metadata.resource_version.is_none());

        let mut ancien = secret_with(&sessions);
        ancien.metadata.resource_version = Some("42".to_string());
        let mise_a_jour = encode("alice", "uid-1", &sessions, Some(&ancien)).unwrap();
        assert_eq!(mise_a_jour.metadata.resource_version.as_deref(), Some("42"));
    }

    /// Le `Secret` est détruit avec son utilisateur : sans `ownerReference`, supprimer un
    /// compte laisserait ses sessions derrière lui.
    #[test]
    fn le_secret_appartient_a_son_utilisateur() {
        let secret = encode("alice", "uid-1", &SessionSet::default(), None).unwrap();
        let owner = &secret.metadata.owner_references.unwrap()[0];

        assert_eq!(owner.kind, "KdtUser");
        assert_eq!(owner.name, "alice");
        assert_eq!(owner.uid, "uid-1");
    }

    #[test]
    fn le_nom_du_secret_derive_du_compte() {
        assert_eq!(secret_name("alice"), "kdt-identity-oidc-alice");
    }
}

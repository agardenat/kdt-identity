//! Persistance des credentials, dans un `Secret` par utilisateur.
//!
//! Rien de secret ne vit dans le `KdtUser` : une CRD est lisible par quiconque a le droit de
//! lister les utilisateurs, ce qui est exactement le public auquel une empreinte de mot de
//! passe et un secret TOTP ne doivent pas être exposés. Les `Secret` vivent dans le seul
//! namespace de l'opérateur, où le RBAC peut les isoler.
//!
//! Chaque `Secret` porte une `ownerReference` vers son `KdtUser`. Kubernetes autorise un
//! propriétaire cluster-scoped pour un dépendant namespacé : supprimer l'utilisateur emporte
//! donc ses credentials, sans code de nettoyage à écrire ni à oublier.

use crate::auth::invite::InviteRecord;
use crate::auth::lockout::Lockout;
use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kdt_identity_api::{KdtUser, CREDENTIAL_SECRET_TYPE};
use kube::api::{Api, ObjectMeta, Patch, PatchParams};
use kube::{Resource, ResourceExt};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Préfixe du nom des `Secret`, pour qu'ils se repèrent d'un coup d'œil dans un namespace.
pub const SECRET_PREFIX: &str = "kdt-identity-cred-";

/// Gestionnaire de champ, pour que le contrôleur ne se batte pas avec lui-même en Server-Side
/// Apply.
const FIELD_MANAGER: &str = "kdt-identity";

mod keys {
    pub const PASSWORD_HASH: &str = "password-hash";
    pub const TOTP_SECRET: &str = "totp-secret";
    pub const TOTP_LAST_STEP: &str = "totp-last-step";
    pub const INVITE_TOKEN_HASH: &str = "invite-token-hash";
    pub const INVITE_EXPIRES_AT: &str = "invite-expires-at";
    pub const FAILED_ATTEMPTS: &str = "failed-attempts";
    pub const LOCKED_UNTIL: &str = "locked-until";
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("appel à l'API Kubernetes : {0}")]
    Kube(#[from] kube::Error),
    #[error("le champ {0:?} du Secret est illisible : {1}")]
    CorruptField(&'static str, String),
    #[error("le KdtUser {0:?} n'a pas d'UID : impossible de rattacher ses credentials")]
    NoUid(String),
}

/// Tout ce que le portail conserve d'un utilisateur entre deux tentatives.
///
/// `Default` correspond à un compte invité mais jamais activé : ni mot de passe, ni TOTP.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub password_hash: Option<Zeroizing<String>>,
    pub totp_secret: Option<Zeroizing<String>>,
    /// Dernier pas TOTP accepté, pour refuser le rejeu.
    pub totp_last_step: Option<u64>,
    pub invite: Option<InviteRecord>,
    pub lockout: Lockout,
}

/// `Debug` manuscrit : cette structure porte une empreinte de mot de passe et un secret TOTP,
/// dont l'un suffit à générer des codes valides indéfiniment.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("password_hash", &self.password_hash.as_ref().map(|_| "<omis>"))
            .field("totp_secret", &self.totp_secret.as_ref().map(|_| "<omis>"))
            .field("totp_last_step", &self.totp_last_step)
            .field("invite", &self.invite.as_ref().map(|_| "<omis>"))
            .field("lockout", &self.lockout)
            .finish()
    }
}

impl Credentials {
    /// Vrai si l'utilisateur dispose de quoi se connecter au portail.
    ///
    /// Les deux facteurs sont exigés : un compte à moitié activé — mot de passe posé mais TOTP
    /// pas encore enrôlé — ne doit pas pouvoir servir.
    pub fn is_activated(&self) -> bool {
        self.password_hash.is_some() && self.totp_secret.is_some()
    }
}

/// Nom du `Secret` portant les credentials de `user`.
pub fn secret_name(user: &str) -> String {
    format!("{SECRET_PREFIX}{user}")
}

pub struct CredentialStore {
    secrets: Api<Secret>,
}

impl CredentialStore {
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            secrets: Api::namespaced(client, namespace),
        }
    }

    /// Lit les credentials d'un utilisateur. `None` si le `Secret` n'existe pas encore.
    pub async fn get(&self, user: &str) -> Result<Option<Credentials>, StoreError> {
        match self.secrets.get_opt(&secret_name(user)).await? {
            Some(secret) => decode(&secret.data.unwrap_or_default()).map(Some),
            None => Ok(None),
        }
    }

    /// Écrit les credentials, en créant le `Secret` au besoin.
    pub async fn put(&self, user: &KdtUser, credentials: &Credentials) -> Result<(), StoreError> {
        let name = user.name_any();
        let uid = user
            .uid()
            .ok_or_else(|| StoreError::NoUid(name.clone()))?;

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name(&name)),
                owner_references: Some(vec![k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                    api_version: KdtUser::api_version(&()).to_string(),
                    kind: KdtUser::kind(&()).to_string(),
                    name: name.clone(),
                    uid,
                    // Le Secret n'a aucun sens sans son utilisateur : la suppression en
                    // cascade est le comportement attendu, pas un effet de bord.
                    block_owner_deletion: Some(false),
                    controller: Some(true),
                }]),
                ..Default::default()
            },
            type_: Some(CREDENTIAL_SECRET_TYPE.to_string()),
            data: Some(encode(credentials)),
            ..Default::default()
        };

        self.secrets
            .patch(
                &secret_name(&name),
                &PatchParams::apply(FIELD_MANAGER).force(),
                &Patch::Apply(&secret),
            )
            .await?;
        Ok(())
    }
}

fn encode(credentials: &Credentials) -> BTreeMap<String, ByteString> {
    let mut data = BTreeMap::new();
    let mut put = |key: &str, value: String| {
        data.insert(key.to_string(), ByteString(value.into_bytes()));
    };

    if let Some(hash) = &credentials.password_hash {
        put(keys::PASSWORD_HASH, hash.to_string());
    }
    if let Some(secret) = &credentials.totp_secret {
        put(keys::TOTP_SECRET, secret.to_string());
    }
    if let Some(step) = credentials.totp_last_step {
        put(keys::TOTP_LAST_STEP, step.to_string());
    }
    if let Some(invite) = &credentials.invite {
        put(keys::INVITE_TOKEN_HASH, invite.token_hash.clone());
        put(keys::INVITE_EXPIRES_AT, invite.expires_at.to_rfc3339());
    }
    if credentials.lockout.failed_attempts > 0 {
        put(
            keys::FAILED_ATTEMPTS,
            credentials.lockout.failed_attempts.to_string(),
        );
    }
    if let Some(until) = credentials.lockout.locked_until {
        put(keys::LOCKED_UNTIL, until.to_rfc3339());
    }

    data
}

/// Relit un `Secret`.
///
/// Échoue sur une donnée illisible plutôt que de lui substituer une valeur par défaut : un
/// compteur d'échecs qu'on ne sait pas relire ne doit pas se lire « zéro échec », et un verrou
/// illisible ne doit pas se lire « déverrouillé ».
fn decode(data: &BTreeMap<String, ByteString>) -> Result<Credentials, StoreError> {
    let text = |key: &'static str| -> Result<Option<String>, StoreError> {
        match data.get(key) {
            None => Ok(None),
            Some(raw) => String::from_utf8(raw.0.clone())
                .map(Some)
                .map_err(|e| StoreError::CorruptField(key, format!("UTF-8 : {e}"))),
        }
    };
    let timestamp = |key: &'static str| -> Result<Option<DateTime<Utc>>, StoreError> {
        match text(key)? {
            None => Ok(None),
            Some(raw) => DateTime::parse_from_rfc3339(&raw)
                .map(|d| Some(d.with_timezone(&Utc)))
                .map_err(|e| StoreError::CorruptField(key, format!("RFC 3339 : {e}"))),
        }
    };

    let invite = match (
        text(keys::INVITE_TOKEN_HASH)?,
        timestamp(keys::INVITE_EXPIRES_AT)?,
    ) {
        (Some(token_hash), Some(expires_at)) => Some(InviteRecord {
            token_hash,
            expires_at,
        }),
        (None, None) => None,
        // Une invitation sans date d'expiration serait éternelle, une date sans empreinte est
        // orpheline : dans les deux cas la donnée est incohérente, pas incomplète.
        _ => {
            return Err(StoreError::CorruptField(
                keys::INVITE_TOKEN_HASH,
                "empreinte et date d'expiration doivent être présentes ensemble".to_string(),
            ))
        }
    };

    Ok(Credentials {
        password_hash: text(keys::PASSWORD_HASH)?.map(Zeroizing::new),
        totp_secret: text(keys::TOTP_SECRET)?.map(Zeroizing::new),
        totp_last_step: match text(keys::TOTP_LAST_STEP)? {
            None => None,
            Some(raw) => Some(raw.parse().map_err(|e| {
                StoreError::CorruptField(keys::TOTP_LAST_STEP, format!("entier : {e}"))
            })?),
        },
        invite,
        lockout: Lockout {
            failed_attempts: match text(keys::FAILED_ATTEMPTS)? {
                None => 0,
                Some(raw) => raw.parse().map_err(|e| {
                    StoreError::CorruptField(keys::FAILED_ATTEMPTS, format!("entier : {e}"))
                })?,
            },
            locked_until: timestamp(keys::LOCKED_UNTIL)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn instant() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn complete() -> Credentials {
        Credentials {
            password_hash: Some(Zeroizing::new("$argon2id$v=19$...".to_string())),
            totp_secret: Some(Zeroizing::new("JBSWY3DPEHPK3PXP".to_string())),
            totp_last_step: Some(56_666_666),
            invite: Some(InviteRecord {
                token_hash: "a".repeat(64),
                expires_at: instant() + Duration::hours(72),
            }),
            lockout: Lockout {
                failed_attempts: 3,
                locked_until: Some(instant() + Duration::minutes(2)),
            },
        }
    }

    #[test]
    fn un_aller_retour_complet_preserve_tout() {
        assert_eq!(decode(&encode(&complete())).unwrap(), complete());
    }

    #[test]
    fn un_compte_neuf_fait_un_aller_retour_vide() {
        let vide = Credentials::default();
        assert!(encode(&vide).is_empty());
        assert_eq!(decode(&encode(&vide)).unwrap(), vide);
    }

    /// Les deux facteurs sont exigés : un compte à moitié activé ne doit pas servir.
    #[test]
    fn l_activation_exige_les_deux_facteurs() {
        assert!(complete().is_activated());

        let mut sans_totp = complete();
        sans_totp.totp_secret = None;
        assert!(!sans_totp.is_activated());

        let mut sans_mdp = complete();
        sans_mdp.password_hash = None;
        assert!(!sans_mdp.is_activated());

        assert!(!Credentials::default().is_activated());
    }

    /// Un compteur d'échecs illisible ne doit surtout pas se lire « zéro échec » : ce serait
    /// désarmer le verrouillage en corrompant un champ.
    #[test]
    fn un_compteur_illisible_echoue_au_lieu_de_valoir_zero() {
        let mut data = encode(&complete());
        data.insert(
            keys::FAILED_ATTEMPTS.to_string(),
            ByteString(b"beaucoup".to_vec()),
        );

        assert!(matches!(
            decode(&data),
            Err(StoreError::CorruptField(keys::FAILED_ATTEMPTS, _))
        ));
    }

    /// Même raisonnement : un verrou illisible ne doit pas se lire « déverrouillé ».
    #[test]
    fn un_verrou_illisible_echoue_au_lieu_de_deverrouiller() {
        let mut data = encode(&complete());
        data.insert(
            keys::LOCKED_UNTIL.to_string(),
            ByteString(b"demain".to_vec()),
        );

        assert!(matches!(
            decode(&data),
            Err(StoreError::CorruptField(keys::LOCKED_UNTIL, _))
        ));
    }

    /// Une invitation sans expiration serait éternelle.
    #[test]
    fn une_invitation_incomplete_est_refusee() {
        let mut data = encode(&complete());
        data.remove(keys::INVITE_EXPIRES_AT);
        assert!(matches!(decode(&data), Err(StoreError::CorruptField(_, _))));

        let mut data = encode(&complete());
        data.remove(keys::INVITE_TOKEN_HASH);
        assert!(matches!(decode(&data), Err(StoreError::CorruptField(_, _))));
    }

    #[test]
    fn un_champ_non_utf8_est_signale() {
        let mut data = encode(&complete());
        data.insert(
            keys::PASSWORD_HASH.to_string(),
            ByteString(vec![0xff, 0xfe]),
        );

        assert!(matches!(
            decode(&data),
            Err(StoreError::CorruptField(keys::PASSWORD_HASH, _))
        ));
    }

    /// Un `{:?}` égaré dans une trace ne doit pas publier l'empreinte ni le secret TOTP.
    #[test]
    fn le_debug_ne_laisse_fuir_aucun_secret() {
        let rendu = format!("{:?}", complete());

        assert!(!rendu.contains("argon2id"), "{rendu}");
        assert!(!rendu.contains("JBSWY3DPEHPK3PXP"), "{rendu}");
        assert!(!rendu.contains(&"a".repeat(64)), "{rendu}");
        // Ce qui n'est pas secret reste visible, sinon le Debug ne sert à rien.
        assert!(rendu.contains("failed_attempts: 3"), "{rendu}");
    }

    #[test]
    fn le_nom_du_secret_est_prefixe() {
        assert_eq!(secret_name("alice"), "kdt-identity-cred-alice");
    }
}

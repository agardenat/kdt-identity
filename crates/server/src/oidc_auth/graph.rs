//! Ce que le jeton ne dit pas, demandé à Microsoft Graph.
//!
//! Deux manques, et une seule réponse pour les deux.
//!
//! Le premier est immédiat : au-delà d'environ deux cents groupes, Entra ID cesse de les mettre
//! dans le jeton et n'y laisse qu'un renvoi. Sans ce module, la personne la mieux dotée en
//! groupes est précisément celle dont la connexion est refusée.
//!
//! Le second est différé, et c'est le plus important : une session se renouvelle en silence, sans
//! jamais revenir au fournisseur. Un retrait de groupe fait chez lui ne se voit donc côté cluster
//! qu'à la prochaine connexion interactive — jusqu'à `refreshTtl` plus tard. Le mode ldap n'a pas
//! ce problème parce que le contrôleur relit l'annuaire ; ce module est ce qui rend la même
//! relecture possible ici.
//!
//! # Pourquoi un second jeu d'identifiants
//!
//! Le portail parle ici en son nom, pas au nom de la personne : la relecture a lieu quand
//! personne n'est connecté. C'est donc un `client_credentials`, avec une permission
//! d'application — `GroupMember.Read.All` et `User.Read.All`, consenties par un administrateur du
//! tenant. Réutiliser le jeton de la personne serait impossible pour la relecture et obligerait à
//! le conserver, ce que le portail se refuse à faire.

use super::OidcError;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Marge retirée à la durée de vie d'un jeton d'application.
///
/// Un jeton qui expire pendant l'appel qu'il autorise produit un 401 qu'aucune trace n'explique.
/// Trente secondes suffisent : ce jeton vaut une heure.
const TOKEN_MARGIN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct GraphConfig {
    pub tenant_id: String,
    /// Application qui interroge Graph.
    ///
    /// Le plus souvent la même que celle du portail : elle a déjà une identité dans le tenant, et
    /// lui ajouter une permission d'application est un geste de moins qu'en enregistrer une
    /// seconde. Séparable pour qui veut isoler les deux rôles.
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    /// Racine de l'API. Autre chose que le défaut dans les clouds souverains.
    pub endpoint: String,
    /// Racine du service de jetons.
    pub authority: String,
    /// Intervalle entre deux relectures par le contrôleur.
    pub resync: Duration,
    pub timeout: Duration,
}

/// Ce que Graph dit d'un compte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Groupes et rôles dont il est membre, transitivité comprise.
    pub member_of: Vec<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct MemberObjects {
    value: Vec<String>,
}

#[derive(Deserialize)]
struct User {
    /// Absent du schéma de certaines réponses, et c'est alors qu'on ne peut rien conclure : seul
    /// un `false` explicite désigne un compte fermé.
    #[serde(rename = "accountEnabled")]
    account_enabled: Option<bool>,
}

struct CachedToken {
    value: Zeroizing<String>,
    expires: Instant,
}

pub struct Graph {
    config: GraphConfig,
    http: reqwest::Client,
    token: RwLock<Option<CachedToken>>,
}

impl Graph {
    pub fn new(config: GraphConfig) -> Result<Self, OidcError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!("kdt-identity/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| OidcError::Config(format!("client HTTP de Graph : {e}")))?;

        Ok(Self {
            config,
            http,
            token: RwLock::new(None),
        })
    }

    pub fn config(&self) -> &GraphConfig {
        &self.config
    }

    /// Jeton d'application, retiré du cache tant qu'il vaut.
    async fn access_token(&self) -> Result<Zeroizing<String>, OidcError> {
        if let Some(cached) = self.token.read().await.as_ref() {
            if Instant::now() < cached.expires {
                return Ok(cached.value.clone());
            }
        }

        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.config.authority.trim_end_matches('/'),
            self.config.tenant_id
        );
        let scope = format!("{}/.default", self.config.endpoint.trim_end_matches('/'));

        let response = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
                ("scope", scope.as_str()),
            ])
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(format!("jeton d'application ({url}) : {e}")))?;

        let status = response.status();
        let body: TokenResponse = response.json().await.map_err(|e| {
            OidcError::Unavailable(format!("réponse du service de jetons ({status}) : {e}"))
        })?;

        if let Some(error) = body.error {
            let detail = body.error_description.unwrap_or_default();
            // Le cas courant : consentement d'administrateur jamais donné, ou secret périmé. Les
            // deux se corrigent dans le tenant, et le message d'Entra les nomme.
            return Err(OidcError::Config(format!(
                "Graph refuse les identifiants d'application : {error} {detail}"
            )));
        }

        let value = body
            .access_token
            .ok_or_else(|| OidcError::Unavailable("jeton d'application absent".to_string()))?;
        let vie = Duration::from_secs(body.expires_in.unwrap_or(3600)).saturating_sub(TOKEN_MARGIN);

        *self.token.write().await = Some(CachedToken {
            value: Zeroizing::new(value.clone()),
            expires: Instant::now() + vie,
        });
        Ok(Zeroizing::new(value))
    }

    /// Groupes et rôles d'une personne, par son identifiant d'objet.
    ///
    /// La réponse est transitive : `getMemberObjects` rend aussi les groupes hérités, ce que le
    /// claim du jeton ne fait que si l'application est configurée pour. Une différence assumée —
    /// dans les deux cas, seuls comptent les identifiants que la table de correspondance nomme.
    pub async fn member_objects(&self, object_id: &str) -> Result<Vec<String>, OidcError> {
        let url = format!(
            "{}/v1.0/users/{}/getMemberObjects",
            self.config.endpoint.trim_end_matches('/'),
            urlencode(object_id)
        );

        let response = self
            .http
            .post(&url)
            .bearer_auth(self.access_token().await?.as_str())
            .json(&serde_json::json!({ "securityEnabledOnly": false }))
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(format!("appartenance ({url}) : {e}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(Self::explain(status, &url));
        }

        let body: MemberObjects = response
            .json()
            .await
            .map_err(|e| OidcError::Unavailable(format!("appartenance illisible : {e}")))?;
        Ok(body.value)
    }

    /// L'état d'un compte chez le fournisseur, ou `None` s'il n'y est plus.
    ///
    /// « Plus là » couvre deux cas que le cluster traite pareil : le compte a été supprimé, ou il
    /// a été **désactivé**. Le second n'existe pas en LDAP, où la disparition de l'entrée est le
    /// seul signal ; ici, un départ se traduit d'abord par un `accountEnabled: false`, et
    /// l'ignorer laisserait l'accès ouvert jusqu'à la suppression définitive — qui n'arrive
    /// parfois jamais.
    ///
    /// Une panne n'est jamais un `None` : c'est toute la règle de la relecture.
    pub async fn account(&self, object_id: &str) -> Result<Option<Account>, OidcError> {
        let url = format!(
            "{}/v1.0/users/{}?$select=id,accountEnabled",
            self.config.endpoint.trim_end_matches('/'),
            urlencode(object_id)
        );

        let response = self
            .http
            .get(&url)
            .bearer_auth(self.access_token().await?.as_str())
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(format!("lecture du compte ({url}) : {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = response.status();
        if !status.is_success() {
            return Err(Self::explain(status, &url));
        }

        let user: User = response
            .json()
            .await
            .map_err(|e| OidcError::Unavailable(format!("compte illisible : {e}")))?;

        if user.account_enabled == Some(false) {
            info!(objet = %object_id, "compte fermé chez le fournisseur");
            return Ok(None);
        }

        Ok(Some(Account {
            member_of: self.member_objects(object_id).await?,
        }))
    }

    /// Traduit un statut d'erreur en quelque chose qui dit où corriger.
    ///
    /// Le 403 est le cas de loin le plus fréquent à la mise en service, et le seul que le message
    /// d'Entra n'explique pas : une permission déléguée y ressemble à une permission
    /// d'application tant qu'aucun administrateur n'a consenti.
    fn explain(status: reqwest::StatusCode, url: &str) -> OidcError {
        match status {
            reqwest::StatusCode::FORBIDDEN => OidcError::Config(format!(
                "Graph refuse l'accès ({url}) : la permission d'application \
                 GroupMember.Read.All et User.Read.All doit être accordée **et** consentie par \
                 un administrateur du tenant"
            )),
            reqwest::StatusCode::UNAUTHORIZED => {
                OidcError::Config(format!("Graph refuse le jeton d'application ({url})"))
            }
            // 429 et 5xx : le tenant limite, ou le service passe. Rien à corriger, tout à
            // réessayer — et surtout pas à confondre avec un compte disparu.
            other => {
                warn!(statut = %other, url = %url, "Graph indisponible");
                OidcError::Unavailable(format!("Graph a répondu {other}"))
            }
        }
    }
}

fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L'identifiant d'objet part dans un chemin d'URL. Un GUID n'y pose pas de problème, mais
    /// rien ne garantit que ce soit toujours un GUID : le claim est configurable.
    #[test]
    fn l_identifiant_est_encode_dans_le_chemin() {
        assert_eq!(
            urlencode("8f4a1c2e-0b77-4e3b-9a21-2c5d8e7f0a11"),
            "8f4a1c2e-0b77-4e3b-9a21-2c5d8e7f0a11"
        );
        assert_eq!(urlencode("a/../b"), "a%2F..%2Fb");
        assert_eq!(urlencode("alice@example.com"), "alice%40example.com");
    }

    /// Ce qui se corrige dans le tenant et ce qui se réessaie ne doivent pas se confondre : le
    /// second fait abandonner un tour de relecture, le premier doit être lu par un humain.
    #[test]
    fn un_refus_de_permission_ne_se_lit_pas_comme_une_panne() {
        let url = "https://graph.microsoft.com/v1.0/users/x";

        assert!(matches!(
            Graph::explain(reqwest::StatusCode::FORBIDDEN, url),
            OidcError::Config(_)
        ));
        assert!(matches!(
            Graph::explain(reqwest::StatusCode::UNAUTHORIZED, url),
            OidcError::Config(_)
        ));
        assert!(matches!(
            Graph::explain(reqwest::StatusCode::TOO_MANY_REQUESTS, url),
            OidcError::Unavailable(_)
        ));
        assert!(matches!(
            Graph::explain(reqwest::StatusCode::SERVICE_UNAVAILABLE, url),
            OidcError::Unavailable(_)
        ));
    }
}

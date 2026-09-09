//! Fédération d'identité sur un fournisseur OpenID Connect.
//!
//! Le portail ne voit jamais le mot de passe : il envoie le navigateur chez le fournisseur, qui
//! seul décide, et récupère au retour un jeton d'identité. Tout ce que le mode ldap obtient d'un
//! bind — l'identifiant, l'adresse, les groupes — se lit ici dans les claims de ce jeton.
//!
//! # À ne pas confondre avec le module `oidc`
//!
//! `crate::oidc` fait de kdt-identity un **émetteur**, dont l'apiserver vérifie les jetons. Ce
//! module-ci en fait un **client**, qui consomme ceux d'un autre. Les deux se combinent
//! librement, et un déploiement peut n'utiliser ni l'un ni l'autre.
//!
//! # Pourquoi le mot de passe ne peut pas être relayé
//!
//! Le mode ldap présente le mot de passe saisi à l'annuaire. La transposition directe
//! existerait — OAuth 2.0 la nomme *resource owner password credentials* — mais elle est sans
//! avenir : Entra ID la refuse dès qu'un second facteur ou une politique d'accès conditionnel
//! s'applique, ce qui est le cas de tout tenant d'entreprise. La redirection du navigateur est
//! donc le seul chemin, et c'est elle qui impose au portail de perdre son formulaire de
//! connexion dans ce mode.
//!
//! # Ce que le portail vérifie, et ce qu'il ne vérifie pas
//!
//! La signature du jeton d'identité n'est pas contrôlée, et son JWKS n'est jamais lu. Ce n'est
//! pas un raccourci : le jeton n'arrive pas par le navigateur mais par un échange direct avec le
//! point d'accès du fournisseur, sur une connexion TLS dont le certificat est vérifié, et cet
//! échange présente le `code_verifier` que seul le portail détient. OpenID Connect Core §3.1.3.7
//! autorise explicitement à s'en remettre au TLS dans ce cas précis. Émetteur, audience,
//! expiration et `nonce` sont, eux, vérifiés — ce sont les seuls qui parlent de *ce* jeton-ci.

pub mod claims;
pub mod graph;

use crate::config::OidcAuthConfig;
use crate::federation::FederatedUser;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Chemin du document de découverte, fixé par la RFC 8414.
const DISCOVERY_SUFFIX: &str = "/.well-known/openid-configuration";

/// Durée pendant laquelle le document de découverte est réutilisé sans être relu.
///
/// Un fournisseur change rarement ses points d'accès, et les relire à chaque connexion ferait
/// dépendre chaque ouverture de session d'un aller-retour de plus. Dix minutes bornent le retard
/// en cas de changement, sans le rendre invisible.
const DISCOVERY_TTL: Duration = Duration::from_secs(600);

/// Tolérance d'horloge sur l'expiration d'un jeton.
///
/// Le portail et le fournisseur ne partagent pas la même horloge. Sans marge, un décalage de
/// quelques secondes ferait refuser des jetons parfaitement valides, et le message ne dirait pas
/// que le problème est l'heure.
pub const CLOCK_SKEW: i64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// Le fournisseur n'a pas répondu, ou pas comme il faut.
    ///
    /// Distingué du refus pour la même raison qu'en LDAP : une panne n'est pas un mauvais mot de
    /// passe, et les deux ne se corrigent pas au même endroit.
    #[error("fournisseur injoignable : {0}")]
    Unavailable(String),
    /// Le fournisseur a répondu, et il refuse.
    #[error("refusé par le fournisseur : {0}")]
    Rejected(String),
    /// Le fournisseur a répondu, mais ce qu'il rend ne permet pas de construire un compte.
    #[error("{0}")]
    Unusable(String),
    /// Le portail lui-même est mal configuré. Constaté au démarrage, jamais à la connexion.
    #[error("configuration : {0}")]
    Config(String),
}

/// Ce que le document de découverte apprend au portail.
///
/// Seuls les trois champs dont l'échange a besoin sont lus. Le `jwks_uri` n'en fait pas partie :
/// voir la note du module sur la signature.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// Ce que le portail retient entre le départ vers le fournisseur et le retour.
///
/// Confié au navigateur dans un cookie signé plutôt que gardé côté serveur : le portail est sans
/// état, et une table de connexions en cours ne survivrait ni à un redémarrage ni à une seconde
/// instance. La signature suffit à ce qu'on ne puisse pas la fabriquer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    /// Valeur rendue telle quelle par le fournisseur, et comparée au retour. C'est ce qui lie le
    /// retour au navigateur qui est parti : sans elle, n'importe qui pourrait faire aboutir une
    /// connexion dans le navigateur de quelqu'un d'autre.
    pub state: String,
    /// Secret dont seul le hachage est parti chez le fournisseur (PKCE, RFC 7636). Un code
    /// intercepté ne s'échange pas sans lui.
    pub verifier: String,
    /// Valeur reportée dans le jeton d'identité, et comparée à la lecture : elle interdit de
    /// rejouer un jeton obtenu lors d'une autre connexion.
    pub nonce: String,
    /// Où reprendre une fois la connexion faite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

impl Pending {
    /// Tire les trois valeurs d'une nouvelle tentative de connexion.
    pub fn new(next: Option<String>) -> Self {
        Self {
            state: random_b64url(),
            // 32 octets en base64url donnent 43 caractères, soit exactement le plancher que la
            // RFC 7636 fixe au `code_verifier`.
            verifier: random_b64url(),
            nonce: random_b64url(),
            next,
        }
    }
}

/// Réponse du point d'accès aux jetons, réduite à ce qui sert.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

struct Cached {
    metadata: Metadata,
    lu: Instant,
}

pub struct Provider {
    config: OidcAuthConfig,
    /// L'accès à l'API du fournisseur, quand il est configuré.
    ///
    /// Absent, deux choses n'existent pas : la résolution des groupes déportés, et la relecture
    /// périodique. Le portail fonctionne quand même — c'est le sens de « facultatif » — mais il
    /// refuse alors les connexions dont le jeton ne porte pas les groupes, plutôt que d'ouvrir
    /// une session dont l'appartenance serait muette.
    graph: Option<graph::Graph>,
    http: reqwest::Client,
    /// Découverte gardée en mémoire, relue quand elle a vieilli.
    ///
    /// Paresseuse, et non faite au démarrage : un fournisseur momentanément injoignable
    /// empêcherait le portail de démarrer, donc de servir les sessions déjà ouvertes et le
    /// renouvellement silencieux, qui n'ont pourtant besoin de personne.
    cache: RwLock<Option<Cached>>,
}

impl Provider {
    pub fn new(config: OidcAuthConfig) -> Result<Self, OidcError> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!("kdt-identity/", env!("CARGO_PKG_VERSION")));

        // La CA d'un fournisseur interne s'ajoute aux racines publiques, elle ne les remplace
        // pas : le portail joint aussi d'autres services, et un magasin réduit à cette seule
        // autorité les rendrait tous injoignables.
        if let Some(path) = &config.ca_file {
            let pem = std::fs::read(path)
                .map_err(|e| OidcError::Config(format!("lecture de la CA {path} : {e}")))?;
            for certificate in reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| OidcError::Config(format!("CA {path} illisible : {e}")))?
            {
                builder = builder.add_root_certificate(certificate);
            }
        }

        let http = builder
            .build()
            .map_err(|e| OidcError::Config(format!("client HTTP : {e}")))?;

        let graph = config
            .graph
            .clone()
            .map(graph::Graph::new)
            .transpose()?;

        Ok(Self {
            config,
            graph,
            http,
            cache: RwLock::new(None),
        })
    }

    pub fn config(&self) -> &OidcAuthConfig {
        &self.config
    }

    pub fn graph(&self) -> Option<&graph::Graph> {
        self.graph.as_ref()
    }

    /// Document de découverte, relu quand il a vieilli.
    pub async fn metadata(&self) -> Result<Metadata, OidcError> {
        if let Some(cached) = self.cache.read().await.as_ref() {
            if cached.lu.elapsed() < DISCOVERY_TTL {
                return Ok(cached.metadata.clone());
            }
        }

        let url = format!("{}{DISCOVERY_SUFFIX}", self.config.issuer);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(format!("découverte {url} : {e}")))?;

        if !response.status().is_success() {
            return Err(OidcError::Unavailable(format!(
                "découverte {url} : {}",
                response.status()
            )));
        }

        let metadata: Metadata = response
            .json()
            .await
            .map_err(|e| OidcError::Unavailable(format!("découverte {url} illisible : {e}")))?;

        // L'émetteur annoncé doit être celui qu'on a configuré, sans quoi les jetons porteront un
        // `iss` que le portail refusera ensuite — et le message parlerait alors du jeton, pas de
        // la configuration qui l'a causé.
        if metadata.issuer.trim_end_matches('/') != self.config.issuer {
            return Err(OidcError::Config(format!(
                "le fournisseur se nomme {:?} alors que {:?} est configuré",
                metadata.issuer, self.config.issuer
            )));
        }

        info!(
            emetteur = %metadata.issuer,
            autorisation = %metadata.authorization_endpoint,
            "découverte du fournisseur d'identité"
        );

        *self.cache.write().await = Some(Cached {
            metadata: metadata.clone(),
            lu: Instant::now(),
        });
        Ok(metadata)
    }

    /// URL où envoyer le navigateur pour ouvrir une session.
    pub async fn authorize_url(
        &self,
        pending: &Pending,
        redirect_uri: &str,
    ) -> Result<String, OidcError> {
        use sha2::{Digest, Sha256};

        let metadata = self.metadata().await?;
        let challenge = b64url(&Sha256::digest(pending.verifier.as_bytes()));

        let separateur = if metadata.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };

        Ok(format!(
            "{}{separateur}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            metadata.authorization_endpoint,
            urlencode(&self.config.client_id),
            urlencode(redirect_uri),
            urlencode(&self.config.scopes),
            urlencode(&pending.state),
            urlencode(&pending.nonce),
            urlencode(&challenge),
        ))
    }

    /// Échange le code contre un jeton d'identité, et en tire une personne.
    ///
    /// Le code ne figure dans aucun journal : il s'échange contre une session de plusieurs
    /// heures, et le journal d'un portail est lu par plus de monde que ses secrets.
    pub async fn authenticate(
        &self,
        code: &str,
        pending: &Pending,
        redirect_uri: &str,
        now: i64,
    ) -> Result<FederatedUser, OidcError> {
        let metadata = self.metadata().await?;

        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", self.config.client_id.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret.as_str()));
        }

        let response = self
            .http
            .post(&metadata.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| {
                OidcError::Unavailable(format!("échange sur {} : {e}", metadata.token_endpoint))
            })?;

        let status = response.status();
        let body: TokenResponse = response.json().await.map_err(|e| {
            OidcError::Unavailable(format!(
                "réponse illisible du point d'accès aux jetons ({status}) : {e}"
            ))
        })?;

        if let Some(error) = body.error {
            let detail = body.error_description.unwrap_or_default();
            warn!(erreur = %error, detail = %detail, "échange de code refusé");
            return Err(OidcError::Rejected(format!("{error} {detail}").trim().to_string()));
        }

        let id_token = body.id_token.ok_or_else(|| {
            OidcError::Unusable(
                "le fournisseur n'a rendu aucun jeton d'identité : la portée openid est-elle \
                 accordée à cette application ?"
                    .to_string(),
            )
        })?;

        let identity = claims::extract(
            &id_token,
            &claims::Expectations {
                issuer: &metadata.issuer,
                audience: &self.config.client_id,
                nonce: &pending.nonce,
                now,
            },
            &self.config.claims,
        )?;

        self.resolve_groups(identity).await
    }

    /// Complète une identité dont le fournisseur a déporté les groupes.
    ///
    /// Sans accès à son API, la connexion est refusée plutôt qu'ouverte sans droits : une session
    /// dont l'appartenance est muette se traduit par des refus du cluster que personne ne
    /// rattachera à cette cause.
    async fn resolve_groups(&self, identity: claims::Identity) -> Result<FederatedUser, OidcError> {
        if !identity.groups_deferred {
            return Ok(identity.user);
        }

        let Some(graph) = &self.graph else {
            return Err(OidcError::Unusable(format!(
                "le fournisseur n'a pas transmis le claim {:?} : au-delà d'environ deux cents \
                 groupes, il le remplace par un renvoi vers son API. Déclarer l'accès à cette \
                 API, ou restreindre les groupes émis à ceux qui sont assignés à cette \
                 application.",
                self.config.claims.groups
            )));
        };

        let mut user = identity.user;
        user.member_of = graph.member_objects(&user.pin).await?;
        info!(
            login = %user.login,
            groupes = user.member_of.len(),
            "appartenance relue chez le fournisseur, le jeton l'avait déportée"
        );
        Ok(user)
    }
}

/// Le fournisseur vu par la relecture périodique.
///
/// Un type à part plutôt qu'un `impl` sur [`Provider`] : la relecture vit dans le contrôleur, qui
/// n'a ni portail ni session à servir, et n'existe que si l'accès à l'API du fournisseur est
/// déclaré. Le dire par un type qu'on ne peut pas construire sans lui vaut mieux que par une
/// méthode qui échouerait à chaque tour.
pub struct Resync {
    graph: graph::Graph,
    mappings: crate::federation::mapping::GroupMappings,
}

impl Resync {
    /// Rend la relecture si le déploiement l'a déclarée.
    pub fn from_config(config: &OidcAuthConfig) -> Result<Option<Self>, OidcError> {
        let Some(graph_config) = config.graph.clone() else {
            return Ok(None);
        };

        Ok(Some(Self {
            graph: graph::Graph::new(graph_config)?,
            mappings: config.group_mappings.clone(),
        }))
    }
}

impl crate::federation::Federated for Resync {
    fn source(&self) -> crate::federation::Source {
        crate::federation::Source::Oidc
    }

    fn interval(&self) -> Duration {
        self.graph.config().resync
    }

    fn mappings(&self) -> &crate::federation::mapping::GroupMappings {
        &self.mappings
    }

    async fn lookup_groups(
        &self,
        pin: &str,
    ) -> Result<Option<Vec<String>>, crate::federation::Error> {
        match self.graph.account(pin).await {
            Ok(account) => Ok(account.map(|account| account.member_of)),
            // Une configuration fautive — permission jamais consentie, secret périmé — ne se
            // corrige pas d'elle-même, mais elle ne dit rien non plus des comptes : elle passe
            // pour une indisponibilité, ce qui fait abandonner le tour sans rien désactiver.
            Err(e @ (OidcError::Unavailable(_) | OidcError::Config(_) | OidcError::Rejected(_))) => {
                Err(crate::federation::Error::Unavailable(format!("{e}")))
            }
            Err(OidcError::Unusable(raison)) => Err(crate::federation::Error::Unusable(raison)),
        }
    }
}

/// 32 octets tirés du CSPRNG, en base64url.
fn random_b64url() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("CSPRNG du système indisponible");
    b64url(&bytes)
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Encodage d'un paramètre d'URL, sur le jeu sûr de la RFC 3986.
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
    use crate::config::OidcClaims;
    use crate::federation::mapping::GroupMappings;
    use crate::federation::Source;

    fn config() -> OidcAuthConfig {
        OidcAuthConfig {
            issuer: "https://idp.example.com".to_string(),
            client_id: "kdt identity".to_string(),
            client_secret: None,
            scopes: "openid profile email".to_string(),
            claims: OidcClaims::default(),
            group_mappings: GroupMappings::empty(Source::Oidc),
            ca_file: None,
            timeout: Duration::from_secs(10),
            provider_name: "Fournisseur".to_string(),
            graph: None,
        }
    }

    /// Deux tentatives n'ont jamais les mêmes secrets : sans cela, un `state` deviné laisserait
    /// aboutir une connexion dans le navigateur de quelqu'un d'autre.
    #[test]
    fn chaque_tentative_tire_ses_propres_valeurs() {
        let a = Pending::new(None);
        let b = Pending::new(None);

        assert_ne!(a.state, b.state);
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.nonce, b.nonce);

        // Le plancher que la RFC 7636 fixe au `code_verifier`.
        assert_eq!(a.verifier.len(), 43);
    }

    /// Un identifiant de client ou une adresse de retour portent des caractères qui ouvriraient
    /// un paramètre de plus s'ils partaient tels quels.
    #[tokio::test]
    async fn l_url_d_autorisation_encode_ses_parametres() {
        let provider = Provider::new(config()).unwrap();
        *provider.cache.write().await = Some(Cached {
            metadata: Metadata {
                issuer: "https://idp.example.com".to_string(),
                authorization_endpoint: "https://idp.example.com/authorize".to_string(),
                token_endpoint: "https://idp.example.com/token".to_string(),
            },
            lu: Instant::now(),
        });

        let pending = Pending::new(None);
        let url = provider
            .authorize_url(&pending, "https://identity.example.com/login/callback")
            .await
            .unwrap();

        assert!(url.contains("client_id=kdt%20identity"), "{url}");
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fidentity.example.com%2Flogin%2Fcallback"),
            "{url}"
        );
        assert!(url.contains("scope=openid%20profile%20email"), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        // Le vérificateur lui-même ne part jamais : c'est tout l'objet de PKCE.
        assert!(!url.contains(&pending.verifier), "{url}");
    }

    /// Un point d'accès qui porte déjà une requête — le cas d'Entra ID sur certains tenants —
    /// ne doit pas recevoir un second `?`, qui ferait de tout ce qui suit une seule valeur.
    #[tokio::test]
    async fn un_point_d_acces_deja_parametre_recoit_un_esperluette() {
        let provider = Provider::new(config()).unwrap();
        *provider.cache.write().await = Some(Cached {
            metadata: Metadata {
                issuer: "https://idp.example.com".to_string(),
                authorization_endpoint: "https://idp.example.com/authorize?p=b2c_1_si".to_string(),
                token_endpoint: "https://idp.example.com/token".to_string(),
            },
            lu: Instant::now(),
        });

        let url = provider
            .authorize_url(&Pending::new(None), "https://identity.example.com/login/callback")
            .await
            .unwrap();

        assert!(url.contains("?p=b2c_1_si&response_type=code"), "{url}");
        assert_eq!(url.matches('?').count(), 1, "{url}");
    }
}

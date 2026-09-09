//! Configuration du serveur, lue dans l'environnement.
//!
//! Les valeurs sensibles — mot de passe SMTP — arrivent par variable d'environnement pour être
//! injectées depuis un `Secret` monté par le chart, sans jamais transiter par un ConfigMap ni
//! par un argument de ligne de commande, où `ps` les exposerait à tout le nœud.

use crate::federation::mapping::GroupMappings;
use crate::federation::Source;
use crate::oidc_auth::graph::GraphConfig;
use crate::ldap::profile::{LdapAttributes, LdapProfile};
use crate::mail::{Encryption, SmtpConfig};
use kdt_identity_api::portal::{AuthMode, CredentialMode};
use std::time::Duration;
use zeroize::Zeroizing;

/// Durée de vie par défaut d'un certificat remis au plugin.
///
/// Dix minutes, soit le plancher de l'API Kubernetes sur `expirationSeconds`. C'est le délai
/// maximal entre une révocation et sa prise d'effet, et il ne coûte rien : le plugin renouvelle
/// tout seul contre son droit de session, sans rien redemander à personne.
pub const DEFAULT_CERT_TTL: Duration = Duration::from_secs(600);

/// Durée de vie par défaut d'un certificat téléchargé depuis le portail.
///
/// Huit heures, et non dix minutes : ce fichier-là est autoportant, personne ne le renouvelle,
/// et il serait périmé avant d'être rangé. C'est le seul accès que la révocation ne peut pas
/// couper — un compromis assumé pour que le portail reste utilisable sans rien installer.
pub const DEFAULT_DOWNLOAD_CERT_TTL: Duration = Duration::from_secs(8 * 3600);

/// Durée de vie par défaut du droit de renouveler.
///
/// Sept jours : c'est l'intervalle entre deux saisies de mot de passe et de code. Aussi long
/// n'aurait aucun sens sans révocation ; ici, ce droit vit dans le cluster et se retire à tout
/// moment, ce qui découple la durée de la session de celle de l'accès.
pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Bornes acceptées pour la durée d'un droit de renouveler.
const REFRESH_TTL_RANGE: (Duration, Duration) =
    (Duration::from_secs(3600), Duration::from_secs(90 * 24 * 3600));

/// Bornes acceptées pour la durée d'un certificat.
///
/// Le plancher est celui de l'API Kubernetes, qui refuse toute `expirationSeconds` inférieure.
/// Le plafond réel dépend du `--cluster-signing-duration` du cluster, que kdt-identity ne
/// connaît pas : au-delà, le signeur raccourcit sans le dire, et c'est l'émission qui
/// l'avertit.
const CERT_TTL_RANGE: (Duration, Duration) =
    (Duration::from_secs(600), Duration::from_secs(30 * 24 * 3600));

/// Durée de vie par défaut d'un jeton d'identité.
///
/// Cinq minutes : c'est le délai maximal entre une révocation et sa prise d'effet, et le seul
/// coût d'une valeur basse est un aller-retour de plus vers le portail — silencieux, puisqu'il
/// se fait contre le jeton de rafraîchissement.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(5 * 60);

/// Bornes acceptées pour la durée d'un jeton d'identité.
///
/// Au-delà d'une heure, la révocation n'est plus « immédiate » en aucun sens utile, et autant
/// rester en mode certificat. En deçà d'une minute, le moindre décalage d'horloge entre le
/// portail et l'apiserver fait refuser des jetons valides.
const TOKEN_TTL_RANGE: (Duration, Duration) = (Duration::from_secs(60), Duration::from_secs(3600));

/// Délai au-delà duquel l'annuaire est tenu pour injoignable.
///
/// Dix secondes : au-delà, c'est la page de connexion qui reste suspendue, et une panne
/// d'annuaire se lit alors comme un portail en panne.
pub const DEFAULT_LDAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Bornes acceptées pour ce délai.
const LDAP_TIMEOUT_RANGE: (Duration, Duration) =
    (Duration::from_secs(1), Duration::from_secs(60));

/// Intervalle par défaut entre deux relectures de l'annuaire.
///
/// Quinze minutes : c'est le délai maximal entre un retrait de groupe côté annuaire et sa prise
/// d'effet sur le cluster, pour un coût d'une recherche par compte fédéré et par quart d'heure.
pub const DEFAULT_LDAP_RESYNC: Duration = Duration::from_secs(15 * 60);

/// Bornes acceptées pour cet intervalle.
///
/// Le plancher protège l'annuaire : sous la minute, un parc de quelques centaines de comptes
/// produirait une charge continue pour une fraîcheur que personne ne mesure.
const LDAP_RESYNC_RANGE: (Duration, Duration) =
    (Duration::from_secs(60), Duration::from_secs(24 * 3600));

/// Délai au-delà duquel le fournisseur d'identité est tenu pour injoignable.
///
/// Même valeur et même raison que pour l'annuaire : au-delà, c'est le retour de connexion qui
/// reste suspendu, et une panne du fournisseur se lit comme un portail en panne.
pub const DEFAULT_OIDC_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Bornes acceptées pour ce délai.
const OIDC_AUTH_TIMEOUT_RANGE: (Duration, Duration) =
    (Duration::from_secs(1), Duration::from_secs(60));

/// Portées demandées par défaut au fournisseur.
///
/// `openid` est obligatoire — sans elle il n'y a pas de jeton d'identité — et ajoutée d'office
/// si la configuration l'oublie. Les deux autres portent le nom et l'adresse, sans lesquels le
/// `KdtUser` ne peut pas être créé.
pub const DEFAULT_OIDC_AUTH_SCOPES: &str = "openid profile email";

/// Plafond du droit de renouveler quand rien ne relit le fournisseur.
///
/// Une session se renouvelle en silence, sans jamais revenir au fournisseur : sur cette durée,
/// un retrait de groupe fait chez lui ne se voit donc pas côté cluster. Sans relecture
/// périodique, la seule borne est celle-ci — un jour, contre sept en mode local ou ldap, où le
/// contrôleur relit l'annuaire. Déclarer l'accès à l'API du fournisseur rétablit cette relecture,
/// et lève du même coup ce plafond.
pub const OIDC_AUTH_REFRESH_CEILING: Duration = Duration::from_secs(24 * 3600);

/// Intervalle par défaut entre deux relectures du fournisseur.
///
/// Même valeur et même raison qu'en LDAP : c'est le délai maximal entre un retrait de groupe fait
/// chez lui et sa prise d'effet ici.
pub const DEFAULT_GRAPH_RESYNC: Duration = Duration::from_secs(15 * 60);

/// Racine de l'API du fournisseur, hors clouds souverains.
pub const DEFAULT_GRAPH_ENDPOINT: &str = "https://graph.microsoft.com";

/// Racine du service de jetons, hors clouds souverains.
pub const DEFAULT_GRAPH_AUTHORITY: &str = "https://login.microsoftonline.com";

/// Claim d'épinglage exigé dès que l'API du fournisseur est déclarée.
///
/// La relecture demande à Graph ce qu'il sait d'un compte, en le désignant par son identifiant
/// d'objet dans le tenant. Le `sub` d'un jeton ne convient pas : il est propre à l'application qui
/// l'a reçu, et Graph ne le connaît pas.
pub const GRAPH_SUBJECT_CLAIM: &str = "oid";

/// Emplacement du magasin d'autorités de l'image.
///
/// Le bundle servi à tout le TLS sortant en dérive : voir [`LdapConfig::ca_file`].
pub const IMAGE_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("variable {0} manquante")]
    Missing(&'static str),
    #[error("variable {0} invalide : {1}")]
    Invalid(&'static str, String),
}

/// Tout ce qu'il faut pour interroger un annuaire.
///
/// Absente du [`ServerConfig`] tant que le mode d'authentification est `local` : une
/// configuration LDAP à moitié posée n'a aucune raison d'exister, et la laisser traîner
/// obligerait chaque lecteur à se demander si elle sert.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// `ldaps://hôte:636`, ou `ldap://hôte:389` accompagné de StartTLS.
    pub url: String,
    pub start_tls: bool,
    /// Compte de service qui cherche l'entrée de la personne avant de la faire binder.
    ///
    /// Absent, la recherche est anonyme : FreeIPA l'autorise souvent, Active Directory
    /// pratiquement jamais.
    pub bind_dn: Option<String>,
    pub bind_password: Option<Zeroizing<String>>,
    /// Racine sous laquelle chercher les personnes.
    pub user_search_base: String,
    /// Noms d'attributs, issus du profil et surchargeables un à un.
    pub attributes: LdapAttributes,
    /// Correspondance entre les groupes de l'annuaire et les `KdtGroup`.
    pub group_mappings: GroupMappings,
    /// CA de l'annuaire, en PEM, montée par le chart.
    ///
    /// Elle n'est pas passée à la bibliothèque LDAP, qui n'a pas de quoi la recevoir :
    /// `ldap3` s'en remet à `rustls-native-certs`, dont le seul point d'entrée est la variable
    /// `SSL_CERT_FILE`. Le serveur assemble donc au démarrage un magasin qui réunit celui de
    /// l'image et celle-ci — voir `crate::ldap::trust`.
    pub ca_file: Option<String>,
    pub timeout: Duration,
    /// Intervalle entre deux relectures de l'annuaire par le contrôleur.
    ///
    /// La connexion ne renseigne que la personne qui se connecte. Sans cette relecture, un
    /// retrait de groupe ne prendrait effet qu'à sa prochaine saisie de mot de passe — soit
    /// jusqu'à `refresh_ttl` plus tard, le renouvellement silencieux ne rebindant jamais.
    pub resync: Duration,
}

/// Tout ce qu'il faut pour déléguer l'authentification à un fournisseur OpenID Connect.
///
/// Absente du [`ServerConfig`] tant que le mode d'authentification n'est pas `oidc`, pour la
/// même raison que [`LdapConfig`] : une configuration à moitié posée n'a aucune raison
/// d'exister.
#[derive(Debug, Clone)]
pub struct OidcAuthConfig {
    /// Racine de l'émetteur, telle qu'il se nomme lui-même.
    ///
    /// Le document de découverte est cherché sous `{issuer}/.well-known/openid-configuration`, et
    /// son champ `issuer` est comparé à cette valeur : un fournisseur qui se nomme autrement est
    /// refusé, car c'est aussi cette valeur que porteront les jetons.
    pub issuer: String,
    pub client_id: String,
    /// Secret du client, si l'enregistrement en exige un.
    ///
    /// Absent, le portail se présente en client public et ne tient que par PKCE. C'est valable —
    /// le code ne quitte jamais le navigateur de la personne — mais Entra ID comme Keycloak
    /// distinguent les deux à l'enregistrement, et un secret configuré face à un client déclaré
    /// public est refusé aussi sûrement que l'inverse.
    pub client_secret: Option<Zeroizing<String>>,
    /// Portées demandées, séparées par des espaces. `openid` y est garantie.
    pub scopes: String,
    /// Noms des claims, surchargeables un à un.
    pub claims: OidcClaims,
    /// Correspondance entre les groupes du fournisseur et les `KdtGroup`.
    pub group_mappings: GroupMappings,
    /// CA du fournisseur, en PEM, pour un émetteur interne.
    ///
    /// Contrairement au LDAP, elle n'est pas passée par `SSL_CERT_FILE` : le client HTTP est
    /// bâti sur les racines publiques embarquées, et celle-ci s'y ajoute explicitement.
    pub ca_file: Option<String>,
    pub timeout: Duration,
    /// Nom du fournisseur tel que la page de connexion le nomme.
    ///
    /// Purement cosmétique, et pourtant nécessaire : « Se connecter » sans dire à quoi laisse la
    /// personne deviner sur quel compte elle est sur le point d'engager son accès au cluster.
    pub provider_name: String,
    /// Accès à l'API du fournisseur, s'il est déclaré.
    ///
    /// Facultatif, et pas anodin : sans lui, l'appartenance n'est relue qu'aux connexions
    /// interactives et les jetons dont les groupes sont déportés sont refusés.
    pub graph: Option<GraphConfig>,
}

/// Noms des claims dont le portail tire un compte.
///
/// Aucun n'est deviné : OpenID Connect ne normalise que `sub`, et chaque fournisseur nomme le
/// reste à sa façon. Les défauts couvrent Entra ID et Keycloak ; tout le reste se déclare.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    /// Claim dont on tire l'identifiant de connexion, puis le nom du `KdtUser`.
    pub username: String,
    pub email: String,
    pub display: String,
    /// Claim qui porte les groupes. Chez Entra ID, ce sont des GUID.
    pub groups: String,
    /// Claim épinglé sur le compte, et revérifié à chaque connexion.
    ///
    /// `sub` par défaut, qui est le seul que la spécification garantit stable. Chez Entra ID il
    /// est propre à l'application : réenregistrer le portail change tous les `sub`, et `oid` —
    /// l'identifiant de l'objet dans le tenant — est alors le meilleur choix.
    pub subject: String,
}

impl Default for OidcClaims {
    fn default() -> Self {
        Self {
            username: "preferred_username".to_string(),
            email: "email".to_string(),
            display: "name".to_string(),
            groups: "groups".to_string(),
            subject: "sub".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Namespace où vivent les `Secret` de credentials.
    pub namespace: String,
    /// Racine publique du portail, pour construire les liens d'activation.
    pub portal_url: String,
    /// Nom du cluster affiché aux utilisateurs.
    pub cluster_name: String,
    /// Absente si aucun serveur sortant n'est configuré.
    pub smtp: Option<SmtpConfig>,
    /// Adresse d'écoute du portail.
    pub listen: String,
    /// URL publique de l'apiserver, telle que les postes clients l'atteignent.
    ///
    /// Absente hors cluster, où le kubeconfig courant la fournit.
    pub apiserver_url: Option<String>,
    /// Chemin de la CA du cluster ; à défaut, celle montée dans le pod.
    pub cluster_ca_file: Option<String>,
    /// Clé de signature des jetons, 32 octets en base64.
    ///
    /// Absente, une clé est tirée au démarrage : les sessions ne survivent alors ni à un
    /// redémarrage ni à une seconde instance.
    pub session_key: Option<Zeroizing<String>>,
    /// Ce que le portail remet aux clients : un certificat, ou un jeton OIDC.
    pub credential_mode: CredentialMode,
    /// Qui reconnaît les personnes : le cluster, ou un annuaire.
    ///
    /// Orthogonal au mode de délivrance, et lu séparément : les quatre combinaisons sont
    /// valides.
    pub auth_mode: AuthMode,
    /// Présente si et seulement si `auth_mode` vaut `ldap`.
    pub ldap: Option<LdapConfig>,
    /// Présente si et seulement si `auth_mode` vaut `oidc`.
    pub oidc_auth: Option<OidcAuthConfig>,
    /// Durée de validité des certificats remis au plugin.
    pub cert_ttl: Duration,
    /// Durée de validité des certificats téléchargés depuis le portail.
    pub download_cert_ttl: Duration,
    /// Le portail propose-t-il un kubeconfig à télécharger ?
    ///
    /// Le seul accès qu'une révocation ne peut pas couper : le fichier est autoportant, et vit
    /// sa durée quoi qu'il arrive. Le désactiver rend la révocation sans exception, au prix du
    /// seul chemin qui ne demande rien à installer sur le poste.
    pub kubeconfig_download: bool,
    /// Durée de validité du droit de renouveler, dans les deux modes.
    pub refresh_ttl: Duration,
    /// Audience attendue dans les jetons, à reporter dans la configuration de l'apiserver.
    pub oidc_audience: String,
    /// Durée de vie d'un jeton d'identité.
    pub oidc_token_ttl: Duration,
    /// Racine publique de kdt-web, si elle est déployée.
    ///
    /// Absente, le flow d'autorisation n'existe pas et la page du compte ne mentionne rien :
    /// kdt-web est une installation facultative, et le portail ne suppose jamais la présence de
    /// ce qu'on ne lui a pas déclaré. Une détection — chercher un Service, sonder une URL —
    /// afficherait un lien mort le temps qu'un ingress se propage.
    pub web_url: Option<String>,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self {
            // Dans un pod, l'API downward écrit ce fichier ; hors cluster, la variable prend
            // le relais.
            namespace: env("KDT_IDENTITY_NAMESPACE")
                .or_else(|| {
                    std::fs::read_to_string(
                        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
                    )
                    .ok()
                })
                .unwrap_or_else(|| "kdt-identity".to_string()),

            portal_url: env("KDT_IDENTITY_PORTAL_URL")
                .ok_or(ConfigError::Missing("KDT_IDENTITY_PORTAL_URL"))?
                .trim_end_matches('/')
                .to_string(),

            cluster_name: env("KDT_IDENTITY_CLUSTER_NAME")
                .ok_or(ConfigError::Missing("KDT_IDENTITY_CLUSTER_NAME"))?,

            smtp: smtp_from_env()?,
            listen: env("KDT_IDENTITY_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            apiserver_url: env("KDT_IDENTITY_APISERVER_URL"),
            cluster_ca_file: env("KDT_IDENTITY_CLUSTER_CA_FILE"),
            session_key: env("KDT_IDENTITY_SESSION_KEY").map(Zeroizing::new),
            credential_mode: mode_from_env()?,
            auth_mode: auth_mode_from_env()?,
            ldap: ldap_from_env()?,
            oidc_auth: oidc_auth_from_env()?,
            cert_ttl: duration_from_env(
                "KDT_IDENTITY_CERT_TTL",
                DEFAULT_CERT_TTL,
                CERT_TTL_RANGE,
            )?,
            download_cert_ttl: duration_from_env(
                "KDT_IDENTITY_DOWNLOAD_CERT_TTL",
                DEFAULT_DOWNLOAD_CERT_TTL,
                CERT_TTL_RANGE,
            )?,
            kubeconfig_download: match env("KDT_IDENTITY_KUBECONFIG_DOWNLOAD").as_deref() {
                None | Some("true") => true,
                Some("false") => false,
                Some(other) => {
                    return Err(ConfigError::Invalid(
                        "KDT_IDENTITY_KUBECONFIG_DOWNLOAD",
                        format!("{other:?} inconnu, attendu true ou false"),
                    ))
                }
            },
            refresh_ttl: duration_from_env(
                "KDT_IDENTITY_REFRESH_TTL",
                DEFAULT_REFRESH_TTL,
                REFRESH_TTL_RANGE,
            )?,
            oidc_audience: env("KDT_IDENTITY_OIDC_AUDIENCE")
                .unwrap_or_else(|| "kdt-identity".to_string()),
            oidc_token_ttl: duration_from_env(
                "KDT_IDENTITY_OIDC_TOKEN_TTL",
                DEFAULT_TOKEN_TTL,
                TOKEN_TTL_RANGE,
            )?,
            web_url: env("KDT_IDENTITY_WEB_URL")
                .map(|raw| raw.trim_end_matches('/').to_string()),
        }
        .validated()
    }

    /// Refuse une configuration qui compile mais ne peut pas fonctionner.
    ///
    /// L'apiserver exige un émetteur en HTTPS et n'accepte rien d'autre. Démarrer quand même
    /// produirait un portail parfaitement fonctionnel dont aucun jeton ne serait jamais
    /// accepté, avec côté apiserver un message qui ne dit pas pourquoi.
    fn validated(self) -> Result<Self, ConfigError> {
        if self.credential_mode == CredentialMode::Oidc && !self.portal_url.starts_with("https://")
        {
            return Err(ConfigError::Invalid(
                "KDT_IDENTITY_PORTAL_URL",
                format!(
                    "{:?} : le mode oidc exige une racine en https, c'est l'émetteur que \
                     l'apiserver vérifie",
                    self.portal_url
                ),
            ));
        }

        // Un code d'autorisation voyage dans une URL, et s'échange contre un droit de session de
        // plusieurs jours. En clair sur le réseau, il est lisible par tout ce qui se trouve entre
        // le navigateur et l'application. La boucle locale fait exception : elle ne traverse rien,
        // et c'est le seul chemin praticable derrière un `port-forward`.
        if let Some(web_url) = &self.web_url {
            let local = web_url.starts_with("http://localhost")
                || web_url.starts_with("http://127.0.0.1");
            if !web_url.starts_with("https://") && !local {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_WEB_URL",
                    format!(
                        "{web_url:?} : une racine en https est exigée, un code d'autorisation \
                         n'a pas à voyager en clair"
                    ),
                ));
            }
        }

        if let Some(ldap) = &self.ldap {
            // Un bind simple présente le mot de passe **en clair** dans la requête : c'est le
            // protocole, pas un défaut de configuration. Sans TLS, tout ce qui se trouve entre
            // le portail et l'annuaire lit chaque mot de passe d'entreprise qui passe. Refusé
            // au démarrage, donc, et non signalé par un avertissement que personne ne lit.
            let chiffre = ldap.url.starts_with("ldaps://") || ldap.start_tls;
            if !chiffre {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_LDAP_URL",
                    format!(
                        "{:?} : un bind présente le mot de passe en clair, une racine ldaps:// \
                         ou StartTLS est exigée",
                        ldap.url
                    ),
                ));
            }

            if ldap.url.starts_with("ldaps://") && ldap.start_tls {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_LDAP_START_TLS",
                    "StartTLS négocie le chiffrement sur une connexion en clair : il n'a pas de \
                     sens sur une racine ldaps://, déjà chiffrée"
                        .to_string(),
                ));
            }

            // Une table vide décrit un déploiement où personne n'obtient de groupe, donc où
            // personne n'obtient de droit : c'est presque sûrement un oubli, et le découvrir
            // demanderait de comparer un `kubectl auth can-i` à ce qu'on attendait.
            if ldap.group_mappings.is_empty() {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_LDAP_GROUP_MAPPINGS",
                    "aucune correspondance de groupe : les comptes fédérés n'auraient aucun droit"
                        .to_string(),
                ));
            }
        }

        if let Some(oidc) = &self.oidc_auth {
            // L'émetteur est comparé caractère pour caractère à celui que portent les jetons, et
            // sert à joindre le fournisseur. En clair, les jetons d'identité de tout le cluster
            // traverseraient le réseau en lecture directe.
            if !oidc.issuer.starts_with("https://") {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_AUTH_OIDC_ISSUER",
                    format!(
                        "{:?} : une racine en https est exigée, c'est par là que passent les \
                         jetons d'identité",
                        oidc.issuer
                    ),
                ));
            }

            // L'adresse de retour est construite sur la racine du portail, et c'est elle qui
            // reçoit le code d'autorisation. Les fournisseurs refusent d'ailleurs presque tous
            // d'enregistrer une adresse de retour en clair — sauf sur la boucle locale, seul
            // chemin praticable derrière un `port-forward`.
            let local = self.portal_url.starts_with("http://localhost")
                || self.portal_url.starts_with("http://127.0.0.1");
            if !self.portal_url.starts_with("https://") && !local {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_PORTAL_URL",
                    format!(
                        "{:?} : le mode oidc exige une racine en https, c'est l'adresse de \
                         retour où le code d'autorisation est redirigé",
                        self.portal_url
                    ),
                ));
            }

            // Même raison qu'en mode ldap : une table vide décrit un déploiement où personne
            // n'obtient de droit, ce qui ne se découvrirait qu'au premier `kubectl` refusé.
            if oidc.group_mappings.is_empty() {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_AUTH_OIDC_GROUP_MAPPINGS",
                    "aucune correspondance de groupe : les comptes fédérés n'auraient aucun droit"
                        .to_string(),
                ));
            }

            // La relecture désigne les comptes par leur identifiant d'objet dans le tenant. Le
            // `sub` d'un jeton ne convient pas : il est propre à l'application qui l'a reçu, et
            // l'API du fournisseur ne le connaît pas. Refusé au démarrage, plutôt que de
            // découvrir au premier tour de relecture que pas un compte n'est retrouvé.
            if oidc.graph.is_some() && oidc.claims.subject != GRAPH_SUBJECT_CLAIM {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_AUTH_OIDC_SUBJECT_CLAIM",
                    format!(
                        "{:?} : la relecture par l'API du fournisseur désigne les comptes par \
                         leur identifiant d'objet, que seul le claim {GRAPH_SUBJECT_CLAIM:?} \
                         porte",
                        oidc.claims.subject
                    ),
                ));
            }

            // Rien ne relit le fournisseur entre deux connexions interactives, sauf si son API
            // est déclarée : le droit de renouveler est alors exactement la durée pendant
            // laquelle un retrait de groupe fait chez lui reste sans effet ici. Sept jours sont
            // tenables face à une relecture au quart d'heure ; ils ne le sont pas sans elle.
            if oidc.graph.is_none() && self.refresh_ttl > OIDC_AUTH_REFRESH_CEILING {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_REFRESH_TTL",
                    format!(
                        "{:?} : sans accès déclaré à l'API du fournisseur, aucune relecture ne le \
                         suit entre deux connexions, et ce droit borne le retard de \
                         l'appartenance. Plafond {:?}, ou déclarer cet accès.",
                        self.refresh_ttl, OIDC_AUTH_REFRESH_CEILING
                    ),
                ));
            }
        }

        Ok(self)
    }

    /// Lien d'activation d'une invitation.
    ///
    /// Le jeton est encodé pour l'URL bien qu'il soit déjà en base64url : la garantie vient
    /// alors de la construction du lien, pas d'une propriété de l'appelant.
    pub fn activation_url(&self, user: &str, token: &str) -> String {
        format!(
            "{}/activate?u={}&t={}",
            self.portal_url,
            urlencode(user),
            urlencode(token)
        )
    }
}

fn mode_from_env() -> Result<CredentialMode, ConfigError> {
    match env("KDT_IDENTITY_CREDENTIAL_MODE") {
        None => Ok(CredentialMode::default()),
        Some(raw) => raw
            .parse()
            .map_err(|e: String| ConfigError::Invalid("KDT_IDENTITY_CREDENTIAL_MODE", e)),
    }
}

fn auth_mode_from_env() -> Result<AuthMode, ConfigError> {
    match env("KDT_IDENTITY_AUTH_MODE") {
        None => Ok(AuthMode::default()),
        Some(raw) => raw
            .parse()
            .map_err(|e: String| ConfigError::Invalid("KDT_IDENTITY_AUTH_MODE", e)),
    }
}

/// Lit la configuration de l'annuaire, ou rien si le mode ne l'est pas.
///
/// Le mode commande, et non la présence d'une URL : un déploiement qui garde ses variables LDAP
/// en repassant en `local` ne doit pas continuer à joindre l'annuaire, et l'inverse — un mode
/// `ldap` sans URL — doit refuser de démarrer plutôt que d'accepter toutes les connexions.
fn ldap_from_env() -> Result<Option<LdapConfig>, ConfigError> {
    if auth_mode_from_env()? != AuthMode::Ldap {
        return Ok(None);
    }

    let profile: LdapProfile = match env("KDT_IDENTITY_LDAP_PROFILE") {
        None => return Err(ConfigError::Missing("KDT_IDENTITY_LDAP_PROFILE")),
        Some(raw) => raw
            .parse()
            .map_err(|e: String| ConfigError::Invalid("KDT_IDENTITY_LDAP_PROFILE", e))?,
    };

    // Les défauts du profil, surchargeables un à un : un schéma peut être celui d'Active
    // Directory à un attribut près, et devoir alors tout redéclarer serait une invitation à se
    // tromper sur les autres.
    let defaults = profile.attributes();
    let attributes = LdapAttributes {
        login: env("KDT_IDENTITY_LDAP_LOGIN_ATTR").unwrap_or(defaults.login),
        email: env("KDT_IDENTITY_LDAP_EMAIL_ATTR").unwrap_or(defaults.email),
        display: env("KDT_IDENTITY_LDAP_DISPLAY_ATTR").unwrap_or(defaults.display),
        member_of: env("KDT_IDENTITY_LDAP_MEMBER_ATTR").unwrap_or(defaults.member_of),
        object_class: env("KDT_IDENTITY_LDAP_OBJECT_CLASS").unwrap_or(defaults.object_class),
    };

    let bind_dn = env("KDT_IDENTITY_LDAP_BIND_DN");
    let bind_password = env("KDT_IDENTITY_LDAP_BIND_PASSWORD").map(Zeroizing::new);

    // Même règle que pour SMTP : un DN sans mot de passe produit un bind qui échoue à la
    // première connexion, l'inverse ignore silencieusement le mot de passe fourni.
    if bind_dn.is_some() != bind_password.is_some() {
        return Err(ConfigError::Invalid(
            "KDT_IDENTITY_LDAP_BIND_DN",
            "DN de service et mot de passe vont ensemble".to_string(),
        ));
    }

    let group_mappings = match env("KDT_IDENTITY_LDAP_GROUP_MAPPINGS") {
        None => GroupMappings::empty(Source::Ldap),
        Some(raw) => GroupMappings::parse(&raw, Source::Ldap)
            .map_err(|e| ConfigError::Invalid("KDT_IDENTITY_LDAP_GROUP_MAPPINGS", e))?,
    };

    Ok(Some(LdapConfig {
        url: env("KDT_IDENTITY_LDAP_URL").ok_or(ConfigError::Missing("KDT_IDENTITY_LDAP_URL"))?,
        start_tls: match env("KDT_IDENTITY_LDAP_START_TLS").as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_LDAP_START_TLS",
                    format!("{other:?} inconnu, attendu true ou false"),
                ))
            }
        },
        bind_dn,
        bind_password,
        user_search_base: env("KDT_IDENTITY_LDAP_USER_SEARCH_BASE")
            .ok_or(ConfigError::Missing("KDT_IDENTITY_LDAP_USER_SEARCH_BASE"))?,
        attributes,
        group_mappings,
        ca_file: env("KDT_IDENTITY_LDAP_CA_FILE"),
        timeout: duration_from_env(
            "KDT_IDENTITY_LDAP_TIMEOUT",
            DEFAULT_LDAP_TIMEOUT,
            LDAP_TIMEOUT_RANGE,
        )?,
        resync: duration_from_env(
            "KDT_IDENTITY_LDAP_RESYNC",
            DEFAULT_LDAP_RESYNC,
            LDAP_RESYNC_RANGE,
        )?,
    }))
}

/// Lit la configuration du fournisseur, ou rien si le mode ne l'est pas.
///
/// Même règle que pour l'annuaire : c'est le mode qui commande, et non la présence d'une URL.
fn oidc_auth_from_env() -> Result<Option<OidcAuthConfig>, ConfigError> {
    if auth_mode_from_env()? != AuthMode::Oidc {
        return Ok(None);
    }

    let defaults = OidcClaims::default();
    let claims = OidcClaims {
        username: env("KDT_IDENTITY_AUTH_OIDC_USERNAME_CLAIM").unwrap_or(defaults.username),
        email: env("KDT_IDENTITY_AUTH_OIDC_EMAIL_CLAIM").unwrap_or(defaults.email),
        display: env("KDT_IDENTITY_AUTH_OIDC_DISPLAY_CLAIM").unwrap_or(defaults.display),
        groups: env("KDT_IDENTITY_AUTH_OIDC_GROUPS_CLAIM").unwrap_or(defaults.groups),
        subject: env("KDT_IDENTITY_AUTH_OIDC_SUBJECT_CLAIM").unwrap_or(defaults.subject),
    };

    let group_mappings = match env("KDT_IDENTITY_AUTH_OIDC_GROUP_MAPPINGS") {
        None => GroupMappings::empty(Source::Oidc),
        Some(raw) => GroupMappings::parse(&raw, Source::Oidc)
            .map_err(|e| ConfigError::Invalid("KDT_IDENTITY_AUTH_OIDC_GROUP_MAPPINGS", e))?,
    };

    // `openid` n'est pas une portée comme les autres : sans elle, le fournisseur rend un jeton
    // d'accès et aucun jeton d'identité, et il n'y a alors personne à reconnaître. L'ajouter
    // vaut mieux que refuser — c'est un oubli sans ambiguïté, et le refus se paierait d'un
    // démarrage manqué.
    let scopes = env("KDT_IDENTITY_AUTH_OIDC_SCOPES")
        .unwrap_or_else(|| DEFAULT_OIDC_AUTH_SCOPES.to_string());
    let scopes = if scopes.split_whitespace().any(|scope| scope == "openid") {
        scopes
    } else {
        format!("openid {scopes}")
    };

    Ok(Some(OidcAuthConfig {
        issuer: env("KDT_IDENTITY_AUTH_OIDC_ISSUER")
            .ok_or(ConfigError::Missing("KDT_IDENTITY_AUTH_OIDC_ISSUER"))?
            .trim_end_matches('/')
            .to_string(),
        client_id: env("KDT_IDENTITY_AUTH_OIDC_CLIENT_ID")
            .ok_or(ConfigError::Missing("KDT_IDENTITY_AUTH_OIDC_CLIENT_ID"))?,
        client_secret: env("KDT_IDENTITY_AUTH_OIDC_CLIENT_SECRET").map(Zeroizing::new),
        scopes,
        claims,
        group_mappings,
        ca_file: env("KDT_IDENTITY_AUTH_OIDC_CA_FILE"),
        timeout: duration_from_env(
            "KDT_IDENTITY_AUTH_OIDC_TIMEOUT",
            DEFAULT_OIDC_AUTH_TIMEOUT,
            OIDC_AUTH_TIMEOUT_RANGE,
        )?,
        provider_name: env("KDT_IDENTITY_AUTH_OIDC_PROVIDER_NAME")
            .unwrap_or_else(|| "votre fournisseur d'identité".to_string()),
        graph: graph_from_env()?,
    }))
}

/// Lit l'accès à l'API du fournisseur, ou rien s'il n'est pas déclaré.
///
/// C'est le tenant qui commande : sans lui, le reste n'a pas d'objet. Le secret, en revanche, est
/// exigé dès que le tenant est là — un accès à moitié configuré échouerait à la première
/// relecture, c'est-à-dire un quart d'heure après un démarrage réussi.
fn graph_from_env() -> Result<Option<GraphConfig>, ConfigError> {
    let Some(tenant_id) = env("KDT_IDENTITY_AUTH_OIDC_GRAPH_TENANT_ID") else {
        return Ok(None);
    };

    Ok(Some(GraphConfig {
        tenant_id,
        // Le défaut est l'application du portail : elle a déjà une identité dans le tenant, et
        // lui ajouter une permission coûte moins qu'en enregistrer une seconde.
        client_id: env("KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_ID")
            .or_else(|| env("KDT_IDENTITY_AUTH_OIDC_CLIENT_ID"))
            .ok_or(ConfigError::Missing("KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_ID"))?,
        client_secret: env("KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_SECRET")
            .map(Zeroizing::new)
            .ok_or(ConfigError::Missing(
                "KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_SECRET",
            ))?,
        endpoint: env("KDT_IDENTITY_AUTH_OIDC_GRAPH_ENDPOINT")
            .unwrap_or_else(|| DEFAULT_GRAPH_ENDPOINT.to_string()),
        authority: env("KDT_IDENTITY_AUTH_OIDC_GRAPH_AUTHORITY")
            .unwrap_or_else(|| DEFAULT_GRAPH_AUTHORITY.to_string()),
        resync: duration_from_env(
            "KDT_IDENTITY_AUTH_OIDC_GRAPH_RESYNC",
            DEFAULT_GRAPH_RESYNC,
            LDAP_RESYNC_RANGE,
        )?,
        timeout: duration_from_env(
            "KDT_IDENTITY_AUTH_OIDC_TIMEOUT",
            DEFAULT_OIDC_AUTH_TIMEOUT,
            OIDC_AUTH_TIMEOUT_RANGE,
        )?,
    }))
}

/// Lit une durée bornée, avec les suffixes `s`, `m`, `h` et `d`.
///
/// Les bornes sont refusées au démarrage plutôt que corrigées silencieusement : une durée
/// ramenée sans le dire ferait croire à un réglage qui n'est pas celui en vigueur.
fn duration_from_env(
    key: &'static str,
    default: Duration,
    (min, max): (Duration, Duration),
) -> Result<Duration, ConfigError> {
    let Some(raw) = env(key) else {
        return Ok(default);
    };

    let value = parse_duration(&raw).map_err(|e| ConfigError::Invalid(key, e))?;
    if value < min || value > max {
        return Err(ConfigError::Invalid(
            key,
            format!("{raw:?} hors des bornes {min:?} à {max:?}"),
        ));
    }
    Ok(value)
}

/// Interprète une durée écrite `600s`, `15m`, `8h` ou `7d`.
///
/// Un nombre nu vaut des secondes. Tout le reste est refusé : une unité inconnue prise pour
/// des secondes produirait une durée mille fois trop courte sans que personne ne le remarque.
pub fn parse_duration(raw: &str) -> Result<Duration, String> {
    let (digits, unit) = raw.split_at(
        raw.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(raw.len()),
    );
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("durée {raw:?} : chiffres attendus avant l'unité"))?;
    let seconds = match unit {
        "s" | "" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86400,
        other => return Err(format!("unité {other:?} inconnue, attendu s, m, h ou d")),
    };
    Ok(Duration::from_secs(seconds))
}

/// SMTP est optionnel, mais partiellement configuré ne l'est pas : mieux vaut refuser de
/// démarrer que découvrir à la première invitation qu'aucun message ne partira.
fn smtp_from_env() -> Result<Option<SmtpConfig>, ConfigError> {
    let Some(host) = env("KDT_IDENTITY_SMTP_HOST") else {
        return Ok(None);
    };

    let port = match env("KDT_IDENTITY_SMTP_PORT") {
        None => 587,
        Some(raw) => raw
            .parse()
            .map_err(|e| ConfigError::Invalid("KDT_IDENTITY_SMTP_PORT", format!("{e}")))?,
    };

    let username = env("KDT_IDENTITY_SMTP_USERNAME");
    let password = env("KDT_IDENTITY_SMTP_PASSWORD").map(Zeroizing::new);

    // Un nom d'utilisateur sans mot de passe produit une authentification qui échoue au
    // premier envoi ; l'inverse ignore silencieusement le mot de passe fourni.
    if username.is_some() != password.is_some() {
        return Err(ConfigError::Invalid(
            "KDT_IDENTITY_SMTP_USERNAME",
            "nom d'utilisateur et mot de passe vont ensemble".to_string(),
        ));
    }

    Ok(Some(SmtpConfig {
        host,
        port,
        username,
        password,
        from: env("KDT_IDENTITY_SMTP_FROM")
            .ok_or(ConfigError::Missing("KDT_IDENTITY_SMTP_FROM"))?,
        encryption: match env("KDT_IDENTITY_SMTP_ENCRYPTION").as_deref() {
            None | Some("starttls") => Encryption::StartTls,
            Some("implicit") => Encryption::Implicit,
            Some("none") => Encryption::None,
            Some(other) => {
                return Err(ConfigError::Invalid(
                    "KDT_IDENTITY_SMTP_ENCRYPTION",
                    format!("{other:?} inconnu, attendu starttls, implicit ou none"),
                ))
            }
        },
    }))
}

/// Une variable vide vaut une variable absente : un chart qui rend une valeur optionnelle
/// produit une chaîne vide, pas une variable non définie.
fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
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

    fn config() -> ServerConfig {
        ServerConfig {
            namespace: "kdt-identity".to_string(),
            portal_url: "https://identity.example.com".to_string(),
            cluster_name: "production".to_string(),
            smtp: None,
            listen: "0.0.0.0:8080".to_string(),
            apiserver_url: None,
            cluster_ca_file: None,
            session_key: None,
            web_url: None,
            credential_mode: CredentialMode::Certificate,
            auth_mode: AuthMode::Local,
            ldap: None,
            oidc_auth: None,
            cert_ttl: DEFAULT_CERT_TTL,
            download_cert_ttl: DEFAULT_DOWNLOAD_CERT_TTL,
            kubeconfig_download: true,
            refresh_ttl: DEFAULT_REFRESH_TTL,
            oidc_audience: "kdt-identity".to_string(),
            oidc_token_ttl: DEFAULT_TOKEN_TTL,
        }
    }

    fn with_env<T>(vars: &[(&str, &str)], body: impl FnOnce() -> T) -> T {
        // Les variables d'environnement sont globales au processus : les tests qui y touchent
        // se sérialisent entre eux, et le verrou vaut pour tout le binaire de test — pas
        // seulement pour ce module, `ldap::trust` posant lui aussi une variable.
        let _guard = crate::env_lock();

        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }
        let result = body();
        for (k, _) in vars {
            unsafe { std::env::remove_var(k) };
        }
        result
    }

    #[test]
    fn interprete_les_unites_de_duree() {
        assert_eq!(parse_duration("600s"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_duration("600"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("8h"), Ok(Duration::from_secs(28800)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_secs(604_800)));
    }

    /// Une durée mal comprise silencieusement, c'est un jeton qui vit trop longtemps.
    #[test]
    fn refuse_ce_qu_elle_ne_comprend_pas() {
        for entree in ["", "h", "8j", "huit", "8 h", "-8h", "8hh"] {
            assert!(parse_duration(entree).is_err(), "{entree:?} accepté à tort");
        }
    }

    /// La durée des certificats est réglable, et bornée. Le plancher est celui de l'API
    /// Kubernetes : en deçà, l'émission échouerait à chaque tentative.
    #[test]
    fn la_duree_des_certificats_est_reglable_et_bornee() {
        assert_eq!(config().cert_ttl, DEFAULT_CERT_TTL);

        with_env(&[("KDT_IDENTITY_CERT_TTL", "12h")], || {
            assert_eq!(
                duration_from_env("KDT_IDENTITY_CERT_TTL", DEFAULT_CERT_TTL, CERT_TTL_RANGE)
                    .unwrap(),
                Duration::from_secs(12 * 3600)
            );
        });

        for hors_bornes in ["60s", "365d"] {
            with_env(&[("KDT_IDENTITY_CERT_TTL", hors_bornes)], || {
                assert!(
                    duration_from_env("KDT_IDENTITY_CERT_TTL", DEFAULT_CERT_TTL, CERT_TTL_RANGE)
                        .is_err(),
                    "{hors_bornes} accepté à tort"
                );
            });
        }
    }

    /// Un déploiement qui ne dit rien reste en mode certificat : passer au mode OIDC demande
    /// de configurer l'apiserver, ce ne peut pas être un effet de bord d'une montée de version.
    #[test]
    fn le_mode_par_defaut_est_le_certificat() {
        assert_eq!(config().credential_mode, CredentialMode::Certificate);
        with_env(&[], || {
            assert_eq!(mode_from_env().unwrap(), CredentialMode::Certificate);
        });
    }

    #[test]
    fn un_mode_inconnu_empeche_le_demarrage() {
        with_env(&[("KDT_IDENTITY_CREDENTIAL_MODE", "oid")], || {
            assert!(mode_from_env().is_err());
        });
    }

    /// L'apiserver n'accepte qu'un émetteur en HTTPS. Sans ce contrôle, le portail démarre,
    /// émet des jetons parfaitement formés, et l'apiserver les refuse tous.
    #[test]
    fn le_mode_oidc_exige_un_emetteur_en_https() {
        let mut c = config();
        c.credential_mode = CredentialMode::Oidc;
        c.portal_url = "http://identity.example.com".to_string();
        assert!(c.validated().is_err());

        let mut c = config();
        c.credential_mode = CredentialMode::Oidc;
        assert!(c.validated().is_ok());
    }

    fn ldap() -> LdapConfig {
        LdapConfig {
            url: "ldaps://dc01.example.com:636".to_string(),
            start_tls: false,
            bind_dn: None,
            bind_password: None,
            user_search_base: "ou=users,dc=example,dc=com".to_string(),
            attributes: LdapProfile::ActiveDirectory.attributes(),
            group_mappings: GroupMappings::parse(
                r#"[{"dn": "cn=k8s-admins,dc=example,dc=com", "group": "admins"}]"#,
                Source::Ldap,
            )
            .unwrap(),
            ca_file: None,
            timeout: DEFAULT_LDAP_TIMEOUT,
            resync: DEFAULT_LDAP_RESYNC,
        }
    }

    /// Un déploiement qui ne dit rien garde ses comptes locaux : basculer sur un annuaire est
    /// un geste d'exploitation, jamais un effet de bord d'une montée de version.
    #[test]
    fn le_mode_d_authentification_par_defaut_est_local() {
        assert_eq!(config().auth_mode, AuthMode::Local);

        // Sous le verrou, sans rien poser : lire l'environnement hors verrou reviendrait à le
        // lire pendant qu'un autre test y écrit son propre mode.
        with_env(&[], || {
            assert_eq!(auth_mode_from_env().unwrap(), AuthMode::Local);
        });
    }

    /// Le test le plus important du module. Un bind simple présente le mot de passe en clair :
    /// démarrer sans TLS publierait chaque mot de passe d'entreprise sur le réseau.
    #[test]
    fn un_annuaire_en_clair_empeche_le_demarrage() {
        let mut c = config();
        c.auth_mode = AuthMode::Ldap;
        c.ldap = Some(LdapConfig {
            url: "ldap://dc01.example.com:389".to_string(),
            ..ldap()
        });
        assert!(c.validated().is_err());

        // Le même annuaire en clair, mais avec StartTLS : le chiffrement est négocié après
        // l'ouverture, avant le bind. C'est légitime.
        let mut c = config();
        c.auth_mode = AuthMode::Ldap;
        c.ldap = Some(LdapConfig {
            url: "ldap://dc01.example.com:389".to_string(),
            start_tls: true,
            ..ldap()
        });
        assert!(c.validated().is_ok());
    }

    /// StartTLS négocie le chiffrement sur une connexion en clair. Le demander sur une racine
    /// déjà chiffrée décrit une intention contradictoire, et l'accepter laisserait croire à une
    /// double protection qui n'existe pas.
    #[test]
    fn starttls_sur_ldaps_est_contradictoire() {
        let mut c = config();
        c.auth_mode = AuthMode::Ldap;
        c.ldap = Some(LdapConfig {
            start_tls: true,
            ..ldap()
        });
        assert!(c.validated().is_err());
    }

    /// Sans correspondance de groupe, un compte fédéré se connecte et n'obtient rien. C'est
    /// presque toujours un oubli, et il ne se voit qu'au premier `kubectl` refusé.
    #[test]
    fn un_annuaire_sans_correspondance_empeche_le_demarrage() {
        let mut c = config();
        c.auth_mode = AuthMode::Ldap;
        c.ldap = Some(LdapConfig {
            group_mappings: GroupMappings::empty(Source::Ldap),
            ..ldap()
        });
        assert!(c.validated().is_err());
    }

    /// Le mode commande, pas la présence des variables : un déploiement repassé en local ne
    /// doit plus joindre l'annuaire, même si ses variables sont restées en place.
    #[test]
    fn le_mode_local_ignore_une_configuration_ldap_residuelle() {
        with_env(
            &[
                ("KDT_IDENTITY_LDAP_URL", "ldaps://dc01.example.com:636"),
                ("KDT_IDENTITY_LDAP_PROFILE", "activedirectory"),
            ],
            || {
                assert!(ldap_from_env().unwrap().is_none());
            },
        );
    }

    /// Un mode ldap sans URL ne doit pas démarrer : le portail répondrait à des connexions
    /// qu'il n'a aucun moyen de vérifier.
    #[test]
    fn le_mode_ldap_exige_de_quoi_joindre_l_annuaire() {
        with_env(&[("KDT_IDENTITY_AUTH_MODE", "ldap")], || {
            assert!(ldap_from_env().is_err());
        });

        with_env(
            &[
                ("KDT_IDENTITY_AUTH_MODE", "ldap"),
                ("KDT_IDENTITY_LDAP_PROFILE", "freeipa"),
                ("KDT_IDENTITY_LDAP_URL", "ldaps://ipa.example.com:636"),
            ],
            || {
                // La racine de recherche manque encore.
                assert!(ldap_from_env().is_err());
            },
        );
    }

    /// Un schéma peut être celui d'Active Directory à un attribut près. Devoir alors tout
    /// redéclarer serait une invitation à se tromper sur les autres.
    #[test]
    fn un_attribut_se_surcharge_sans_toucher_aux_autres() {
        with_env(
            &[
                ("KDT_IDENTITY_AUTH_MODE", "ldap"),
                ("KDT_IDENTITY_LDAP_PROFILE", "activedirectory"),
                ("KDT_IDENTITY_LDAP_URL", "ldaps://dc01.example.com:636"),
                ("KDT_IDENTITY_LDAP_USER_SEARCH_BASE", "dc=example,dc=com"),
                ("KDT_IDENTITY_LDAP_LOGIN_ATTR", "userPrincipalName"),
                (
                    "KDT_IDENTITY_LDAP_GROUP_MAPPINGS",
                    r#"[{"dn":"cn=a,dc=x","group":"admins"}]"#,
                ),
            ],
            || {
                let ldap = ldap_from_env().unwrap().unwrap();
                assert_eq!(ldap.attributes.login, "userPrincipalName");
                assert_eq!(ldap.attributes.member_of, "memberOf");
                assert_eq!(ldap.attributes.display, "displayName");
            },
        );
    }

    /// Un DN de service sans mot de passe produit un bind qui échoue à la première connexion,
    /// et l'inverse ignore silencieusement le mot de passe fourni.
    #[test]
    fn un_compte_de_service_incomplet_empeche_le_demarrage() {
        with_env(
            &[
                ("KDT_IDENTITY_AUTH_MODE", "ldap"),
                ("KDT_IDENTITY_LDAP_PROFILE", "activedirectory"),
                ("KDT_IDENTITY_LDAP_URL", "ldaps://dc01.example.com:636"),
                ("KDT_IDENTITY_LDAP_USER_SEARCH_BASE", "dc=example,dc=com"),
                ("KDT_IDENTITY_LDAP_BIND_DN", "cn=svc,dc=example,dc=com"),
            ],
            || {
                assert!(ldap_from_env().is_err());
            },
        );
    }

    /// En mode certificat, l'émetteur ne sert qu'aux liens d'activation : rien n'impose HTTPS
    /// au démarrage, et l'imposer casserait les déploiements de développement existants.
    #[test]
    fn le_mode_certificat_ne_l_exige_pas() {
        let mut c = config();
        c.portal_url = "http://localhost:8080".to_string();
        assert!(c.validated().is_ok());
    }

    #[test]
    fn une_duree_absente_prend_sa_valeur_par_defaut() {
        assert_eq!(
            duration_from_env("KDT_IDENTITY_ABSENTE", DEFAULT_TOKEN_TTL, TOKEN_TTL_RANGE).unwrap(),
            DEFAULT_TOKEN_TTL
        );
    }

    /// Une durée hors bornes est refusée, pas ramenée : un réglage corrigé en silence ferait
    /// croire à une révocation plus rapide qu'elle ne l'est.
    #[test]
    fn une_duree_hors_bornes_est_refusee() {
        for valeur in ["1s", "2h"] {
            with_env(&[("KDT_IDENTITY_OIDC_TOKEN_TTL", valeur)], || {
                assert!(
                    duration_from_env(
                        "KDT_IDENTITY_OIDC_TOKEN_TTL",
                        DEFAULT_TOKEN_TTL,
                        TOKEN_TTL_RANGE
                    )
                    .is_err(),
                    "{valeur} accepté à tort"
                );
            });
        }

        with_env(&[("KDT_IDENTITY_OIDC_TOKEN_TTL", "10m")], || {
            assert_eq!(
                duration_from_env(
                    "KDT_IDENTITY_OIDC_TOKEN_TTL",
                    DEFAULT_TOKEN_TTL,
                    TOKEN_TTL_RANGE
                )
                .unwrap(),
                Duration::from_secs(600)
            );
        });
    }

    #[test]
    fn le_lien_d_activation_porte_le_compte_et_le_jeton() {
        let url = config().activation_url("alice", "jeton-abc");
        assert_eq!(
            url,
            "https://identity.example.com/activate?u=alice&t=jeton-abc"
        );
    }

    /// Le jeton est en base64url, donc déjà sûr dans une URL. L'encodage n'en dépend pas :
    /// c'est la construction du lien qui garantit la structure, pas l'appelant.
    #[test]
    fn le_lien_encode_ce_qui_doit_l_etre() {
        let url = config().activation_url("alice", "a+b/c=d&e");

        // Seule la portion jeton est examinée : la racine du portail contient légitimement
        // des `/`, et un `&` sépare les paramètres.
        let jeton = url.split("&t=").nth(1).expect("paramètre t absent");
        assert_eq!(jeton, "a%2Bb%2Fc%3Dd%26e", "{url}");

        // Un `&` non encodé dans le jeton ouvrirait un paramètre supplémentaire.
        assert_eq!(url.matches('&').count(), 1, "{url}");
    }

    /// Les caractères sûrs de la RFC 3986 doivent traverser intacts, sinon un jeton base64url
    /// légitime se retrouverait percé de séquences `%2D`.
    #[test]
    fn les_caracteres_surs_traversent_intacts() {
        let url = config().activation_url("jean.dupont", "aZ09-_.~");
        assert!(url.ends_with("t=aZ09-_.~"), "{url}");
        assert!(url.contains("u=jean.dupont"), "{url}");
    }

    #[test]
    fn la_racine_du_portail_ne_double_pas_le_slash() {
        let mut c = config();
        c.portal_url = "https://identity.example.com".to_string();
        assert!(!c.activation_url("a", "b").contains("com//"));
    }

    fn oidc_auth() -> OidcAuthConfig {
        OidcAuthConfig {
            issuer: "https://login.microsoftonline.com/tenant/v2.0".to_string(),
            client_id: "client".to_string(),
            client_secret: None,
            scopes: DEFAULT_OIDC_AUTH_SCOPES.to_string(),
            claims: OidcClaims::default(),
            group_mappings: GroupMappings::parse(
                r#"[{"claim": "8f4a1c2e-0b77-4e3b-9a21-2c5d8e7f0a11", "group": "admins"}]"#,
                Source::Oidc,
            )
            .unwrap(),
            ca_file: None,
            timeout: DEFAULT_OIDC_AUTH_TIMEOUT,
            provider_name: "Entra ID".to_string(),
            graph: None,
        }
    }

    fn oidc_config() -> ServerConfig {
        ServerConfig {
            auth_mode: AuthMode::Oidc,
            oidc_auth: Some(oidc_auth()),
            refresh_ttl: OIDC_AUTH_REFRESH_CEILING,
            ..config()
        }
    }

    /// L'émetteur sert à joindre le fournisseur et à comparer ce que portent les jetons : en
    /// clair, ils seraient lisibles par tout ce qui se trouve sur le chemin.
    #[test]
    fn un_emetteur_en_clair_empeche_le_demarrage() {
        let mut c = oidc_config();
        c.oidc_auth = Some(OidcAuthConfig {
            issuer: "http://login.example.com".to_string(),
            ..oidc_auth()
        });
        assert!(c.validated().is_err());
        assert!(oidc_config().validated().is_ok());
    }

    /// Le code d'autorisation revient sur la racine du portail. Les fournisseurs refusent
    /// d'enregistrer une adresse de retour en clair, la boucle locale exceptée.
    #[test]
    fn une_racine_de_portail_en_clair_empeche_le_demarrage_en_mode_oidc() {
        let mut c = oidc_config();
        c.portal_url = "http://identity.example.com".to_string();
        assert!(c.clone().validated().is_err());

        c.portal_url = "http://localhost:8080".to_string();
        assert!(c.validated().is_ok());
    }

    /// Sans correspondance, personne n'obtient de groupe — donc aucun droit — et cela ne se
    /// verrait qu'au premier `kubectl` refusé.
    #[test]
    fn un_fournisseur_sans_correspondance_empeche_le_demarrage() {
        let mut c = oidc_config();
        c.oidc_auth = Some(OidcAuthConfig {
            group_mappings: GroupMappings::empty(Source::Oidc),
            ..oidc_auth()
        });
        assert!(c.validated().is_err());
    }

    /// Rien ne relit le fournisseur entre deux connexions : le droit de renouveler est la durée
    /// exacte pendant laquelle un retrait de groupe reste sans effet. Le défaut de sept jours,
    /// tenable face à un annuaire relu, ne l'est pas ici.
    #[test]
    fn le_droit_de_renouveler_est_plafonne_en_mode_oidc() {
        let mut c = oidc_config();
        c.refresh_ttl = DEFAULT_REFRESH_TTL;
        assert!(c.clone().validated().is_err());

        c.refresh_ttl = OIDC_AUTH_REFRESH_CEILING;
        assert!(c.validated().is_ok());
    }

    /// Sans `openid`, le fournisseur ne rend aucun jeton d'identité et il n'y a personne à
    /// reconnaître. L'oubli se corrige, il ne se punit pas.
    #[test]
    fn la_portee_openid_est_ajoutee_si_elle_manque() {
        let lu = with_env(
            &[
                ("KDT_IDENTITY_AUTH_MODE", "oidc"),
                ("KDT_IDENTITY_AUTH_OIDC_ISSUER", "https://idp.example.com/"),
                ("KDT_IDENTITY_AUTH_OIDC_CLIENT_ID", "kdt"),
                ("KDT_IDENTITY_AUTH_OIDC_SCOPES", "profile email"),
            ],
            || oidc_auth_from_env().unwrap().unwrap(),
        );

        assert_eq!(lu.scopes, "openid profile email");
        assert_eq!(lu.claims.username, "preferred_username");
        // La barre oblique finale est retirée : l'émetteur est comparé caractère pour caractère
        // à celui que portent les jetons, où elle ne figure pas.
        assert_eq!(lu.issuer, "https://idp.example.com");

        let deja = with_env(
            &[
                ("KDT_IDENTITY_AUTH_MODE", "oidc"),
                ("KDT_IDENTITY_AUTH_OIDC_ISSUER", "https://idp.example.com"),
                ("KDT_IDENTITY_AUTH_OIDC_CLIENT_ID", "kdt"),
                ("KDT_IDENTITY_AUTH_OIDC_SCOPES", "openid groups"),
            ],
            || oidc_auth_from_env().unwrap().unwrap(),
        );
        assert_eq!(deja.scopes, "openid groups");
    }

    fn graph() -> GraphConfig {
        GraphConfig {
            tenant_id: "tenant".to_string(),
            client_id: "client".to_string(),
            client_secret: Zeroizing::new("secret".to_string()),
            endpoint: DEFAULT_GRAPH_ENDPOINT.to_string(),
            authority: DEFAULT_GRAPH_AUTHORITY.to_string(),
            resync: DEFAULT_GRAPH_RESYNC,
            timeout: DEFAULT_OIDC_AUTH_TIMEOUT,
        }
    }

    /// La relecture désigne les comptes par leur identifiant d'objet. Épinglés sur le `sub` — qui
    /// est propre à l'application — pas un compte ne serait retrouvé, et le premier tour les
    /// désactiverait tous s'il prenait cette absence pour une disparition.
    #[test]
    fn la_relecture_exige_l_epinglage_sur_l_identifiant_d_objet() {
        let mut c = oidc_config();
        c.oidc_auth = Some(OidcAuthConfig {
            graph: Some(graph()),
            ..oidc_auth()
        });
        assert!(c.clone().validated().is_err());

        c.oidc_auth = Some(OidcAuthConfig {
            graph: Some(graph()),
            claims: OidcClaims {
                subject: GRAPH_SUBJECT_CLAIM.to_string(),
                ..OidcClaims::default()
            },
            ..oidc_auth()
        });
        assert!(c.validated().is_ok());
    }

    /// Le plafond du droit de renouveler n'existe que faute de relecture : déclarer l'accès à
    /// l'API du fournisseur le lève, puisque l'appartenance est alors suivie.
    #[test]
    fn la_relecture_leve_le_plafond_du_droit_de_renouveler() {
        let mut c = oidc_config();
        c.refresh_ttl = DEFAULT_REFRESH_TTL;
        assert!(c.clone().validated().is_err());

        c.oidc_auth = Some(OidcAuthConfig {
            graph: Some(graph()),
            claims: OidcClaims {
                subject: GRAPH_SUBJECT_CLAIM.to_string(),
                ..OidcClaims::default()
            },
            ..oidc_auth()
        });
        assert!(c.validated().is_ok());
    }

    /// Le tenant commande, et le secret va avec : à moitié configuré, l'accès échouerait au
    /// premier tour de relecture, soit un quart d'heure après un démarrage réussi.
    #[test]
    fn l_acces_a_l_api_se_lit_d_un_bloc() {
        let commun = [
            ("KDT_IDENTITY_AUTH_MODE", "oidc"),
            ("KDT_IDENTITY_AUTH_OIDC_ISSUER", "https://idp.example.com"),
            ("KDT_IDENTITY_AUTH_OIDC_CLIENT_ID", "kdt"),
        ];

        // Sans tenant, pas d'accès : les autres variables ne le ressuscitent pas.
        let mut sans = commun.to_vec();
        sans.push(("KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_SECRET", "s"));
        assert!(with_env(&sans, oidc_auth_from_env)
            .unwrap()
            .unwrap()
            .graph
            .is_none());

        // Avec tenant mais sans secret, le démarrage échoue plutôt que la relecture.
        let mut manquant = commun.to_vec();
        manquant.push(("KDT_IDENTITY_AUTH_OIDC_GRAPH_TENANT_ID", "t"));
        assert!(with_env(&manquant, oidc_auth_from_env).is_err());

        // Complet : l'application du portail sert par défaut, puisqu'elle a déjà une identité
        // dans le tenant.
        let mut complet = manquant.clone();
        complet.push(("KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_SECRET", "s"));
        let lu = with_env(&complet, oidc_auth_from_env)
            .unwrap()
            .unwrap()
            .graph
            .expect("accès déclaré");
        assert_eq!(lu.tenant_id, "t");
        assert_eq!(lu.client_id, "kdt");
        assert_eq!(lu.endpoint, DEFAULT_GRAPH_ENDPOINT);
        assert_eq!(lu.resync, DEFAULT_GRAPH_RESYNC);
    }

    /// Le mode commande, et lui seul : des variables de fournisseur laissées derrière un retour
    /// en mode local ne doivent pas ressusciter la configuration.
    #[test]
    fn le_mode_commande_la_lecture_du_fournisseur() {
        let lu = with_env(
            &[
                ("KDT_IDENTITY_AUTH_OIDC_ISSUER", "https://idp.example.com"),
                ("KDT_IDENTITY_AUTH_OIDC_CLIENT_ID", "kdt"),
            ],
            || oidc_auth_from_env().unwrap(),
        );
        assert!(lu.is_none());

        // Et l'inverse : le mode sans l'émetteur refuse de démarrer plutôt que de laisser un
        // portail qui ne saurait à qui parler.
        let manquant = with_env(&[("KDT_IDENTITY_AUTH_MODE", "oidc")], oidc_auth_from_env);
        assert!(manquant.is_err());
    }
}

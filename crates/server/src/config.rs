//! Configuration du serveur, lue dans l'environnement.
//!
//! Les valeurs sensibles — mot de passe SMTP — arrivent par variable d'environnement pour être
//! injectées depuis un `Secret` monté par le chart, sans jamais transiter par un ConfigMap ni
//! par un argument de ligne de commande, où `ps` les exposerait à tout le nœud.

use crate::mail::{Encryption, SmtpConfig};
use kdt_identity_api::portal::CredentialMode;
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



#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("variable {0} manquante")]
    Missing(&'static str),
    #[error("variable {0} invalide : {1}")]
    Invalid(&'static str, String),
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
            credential_mode: CredentialMode::Certificate,
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
        // se sérialisent entre eux.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

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
        assert_eq!(mode_from_env().unwrap(), CredentialMode::Certificate);
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
}

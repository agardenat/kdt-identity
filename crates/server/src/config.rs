//! Configuration du serveur, lue dans l'environnement.
//!
//! Les valeurs sensibles — mot de passe SMTP — arrivent par variable d'environnement pour être
//! injectées depuis un `Secret` monté par le chart, sans jamais transiter par un ConfigMap ni
//! par un argument de ligne de commande, où `ps` les exposerait à tout le nœud.

use crate::mail::{Encryption, SmtpConfig};
use zeroize::Zeroizing;

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
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
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
        })
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

//! Cache local du credential émis.
//!
//! Sans lui, `kubectl` redemanderait le mot de passe et un code TOTP à chaque commande, ce qui
//! rendrait les durées de vie courtes insupportables — et pousserait à les allonger, c'est-à-dire
//! à défaire ce que la brièveté protège.
//!
//! Le fichier contient une clé privée : il est écrit en 0600, dans un répertoire lui-même en
//! 0700, et n'est jamais réutilisé lorsqu'il approche de son expiration.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Marge avant expiration en deçà de laquelle le cache est considéré comme périmé.
///
/// Rendre un certificat qui expire dans dix secondes ferait échouer la commande en cours pour
/// rien : mieux vaut en demander un neuf.
pub const EXPIRY_MARGIN: chrono::Duration = chrono::Duration::minutes(2);

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("répertoire de cache introuvable : ni $KUBECACHEDIR ni $HOME")]
    NoHome,
    #[error("{0} : {1}")]
    Io(PathBuf, std::io::Error),
    #[error("cache illisible : {0}")]
    Corrupt(String),
}

#[derive(Serialize, Deserialize)]
pub struct CachedCredential {
    pub certificate_pem: String,
    pub key_pem: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl CachedCredential {
    /// Vrai si le certificat est encore utilisable pour une commande qui démarre maintenant.
    pub fn is_fresh(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        now + EXPIRY_MARGIN < self.expires_at
    }
}

/// Emplacement du cache pour un couple portail/compte.
///
/// Le nom de fichier est dérivé du portail **et** du compte : deux clusters, ou deux identités
/// sur le même cluster, ne doivent pas se marcher dessus.
pub fn path(portal: &str, user: &str) -> Result<PathBuf, CacheError> {
    use sha2::{Digest, Sha256};

    let base = match std::env::var_os("KUBECACHEDIR") {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = std::env::var_os("HOME").ok_or(CacheError::NoHome)?;
            PathBuf::from(home).join(".kube").join("cache")
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(portal.as_bytes());
    hasher.update([0]);
    hasher.update(user.as_bytes());
    let digest: String = hasher.finalize().iter().take(16).map(|b| format!("{b:02x}")).collect();

    Ok(base.join("kdt-identity").join(format!("{digest}.json")))
}

pub fn read(path: &Path) -> Option<CachedCredential> {
    // Un cache illisible n'est pas une erreur : on le remplacera. Échouer ici bloquerait
    // l'utilisateur sur un fichier corrompu, alors qu'une nouvelle authentification suffit.
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn write(path: &Path, credential: &CachedCredential) -> Result<(), CacheError> {
    let parent = path.parent().ok_or(CacheError::NoHome)?;
    std::fs::create_dir_all(parent).map_err(|e| CacheError::Io(parent.into(), e))?;
    restrict(parent, 0o700)?;

    let json = serde_json::to_string(credential)
        .map_err(|e| CacheError::Corrupt(e.to_string()))?;

    // Écriture puis renommage : une commande interrompue en plein écriture laisserait sinon un
    // fichier tronqué, que la lecture suivante jetterait — au prix d'une authentification.
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, json).map_err(|e| CacheError::Io(temp.clone(), e))?;
    restrict(&temp, 0o600)?;
    std::fs::rename(&temp, path).map_err(|e| CacheError::Io(path.into(), e))?;

    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<(), CacheError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| CacheError::Io(path.into(), e))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<(), CacheError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn credential(expires_in: Duration) -> CachedCredential {
        CachedCredential {
            certificate_pem: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
                .to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nWFla\n-----END PRIVATE KEY-----\n".to_string(),
            expires_at: Utc::now() + expires_in,
        }
    }

    #[test]
    fn un_certificat_encore_valide_est_reutilise() {
        assert!(credential(Duration::hours(4)).is_fresh(Utc::now()));
    }

    /// Rendre un certificat qui expire dans quelques secondes ferait échouer la commande en
    /// cours : la marge existe pour ça.
    #[test]
    fn un_certificat_au_bord_de_l_expiration_est_jete() {
        assert!(!credential(Duration::seconds(30)).is_fresh(Utc::now()));
        assert!(!credential(Duration::zero()).is_fresh(Utc::now()));
        assert!(!credential(-Duration::hours(1)).is_fresh(Utc::now()));
        // Juste au-delà de la marge : conservé.
        assert!(credential(EXPIRY_MARGIN + Duration::seconds(10)).is_fresh(Utc::now()));
    }

    /// Deux identités, ou deux clusters, ne doivent jamais partager un fichier de cache.
    #[test]
    fn le_chemin_distingue_le_portail_et_le_compte() {
        std::env::set_var("KUBECACHEDIR", "/tmp/kdt-cache-test");
        let a = path("https://a.example.com", "alice").unwrap();
        let b = path("https://a.example.com", "bob").unwrap();
        let c = path("https://b.example.com", "alice").unwrap();

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        assert_eq!(a, path("https://a.example.com", "alice").unwrap());
        std::env::remove_var("KUBECACHEDIR");
    }

    #[test]
    fn un_aller_retour_par_le_disque_preserve_le_credential() {
        let dir = std::env::temp_dir().join(format!("kdt-cache-{}", std::process::id()));
        let file = dir.join("test.json");
        let original = credential(Duration::hours(4));

        write(&file, &original).unwrap();
        let relu = read(&file).expect("cache relisible");

        assert_eq!(relu.certificate_pem, original.certificate_pem);
        assert_eq!(relu.key_pem, original.key_pem);
        assert_eq!(relu.expires_at, original.expires_at);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Le fichier porte une clé privée : personne d'autre que son propriétaire ne doit le lire.
    #[cfg(unix)]
    #[test]
    fn le_fichier_de_cache_n_est_lisible_que_par_son_proprietaire() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("kdt-perms-{}", std::process::id()));
        let file = dir.join("test.json");
        write(&file, &credential(Duration::hours(1))).unwrap();

        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions {mode:o}");

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "permissions du répertoire {dir_mode:o}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Un cache corrompu doit conduire à une nouvelle authentification, pas à un blocage.
    #[test]
    fn un_cache_corrompu_est_ignore() {
        let dir = std::env::temp_dir().join(format!("kdt-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.json");

        std::fs::write(&file, "pas du json").unwrap();
        assert!(read(&file).is_none());

        assert!(read(&dir.join("absent.json")).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}

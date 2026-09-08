//! Ajout de la CA de l'annuaire au magasin de confiance du processus.
//!
//! `ldap3` n'offre aucun moyen de lui passer une autorité : `LdapConnSettings` ne porte que le
//! délai, StartTLS et la désactivation — hors de question — de la vérification. La bibliothèque
//! s'en remet à `rustls-native-certs`, dont le seul point d'entrée est la variable
//! `SSL_CERT_FILE`. C'est donc par là que ça passe, et ça n'a rien d'anecdotique : FreeIPA
//! émet toujours depuis sa propre CA, et Active Directory le fait presque toujours.
//!
//! Deux conséquences dont découle tout ce module :
//!
//! - `SSL_CERT_FILE` **remplace** le magasin de la plateforme, il ne s'y ajoute pas. Y pointer
//!   la seule CA d'entreprise couperait tout le reste du TLS sortant — le relais SMTP en
//!   premier. D'où la concaténation avec le magasin de l'image.
//! - la variable vaut pour le processus entier. Elle est donc posée une fois, au démarrage,
//!   avant que quoi que ce soit n'ouvre une connexion.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Répertoire où le magasin assemblé est écrit.
///
/// La racine du conteneur est en lecture seule : le chart y monte un `emptyDir`. Hors cluster,
/// le répertoire est créé s'il manque.
pub const RUNTIME_DIR: &str = "/run/kdt-identity";

const BUNDLE_NAME: &str = "ca-bundle.crt";

/// Assemble le magasin de confiance et le déclare au processus.
///
/// Rend le chemin du magasin écrit. L'absence du magasin de l'image n'est pas une erreur — hors
/// conteneur, il n'existe pas au même endroit — mais elle est signalée par l'appelant, parce
/// qu'un magasin réduit à la seule CA de l'annuaire est un piège silencieux : tout continue de
/// fonctionner jusqu'au premier envoi de courriel.
pub fn install(ca_file: &Path, runtime_dir: &Path) -> anyhow::Result<PathBuf> {
    let entreprise = std::fs::read(ca_file)
        .map_err(|e| anyhow::anyhow!("CA de l'annuaire {} illisible : {e}", ca_file.display()))?;

    if !looks_like_pem(&entreprise) {
        anyhow::bail!(
            "CA de l'annuaire {} : un certificat PEM est attendu, commençant par \
             -----BEGIN CERTIFICATE-----",
            ca_file.display()
        );
    }

    std::fs::create_dir_all(runtime_dir)?;
    let bundle = runtime_dir.join(BUNDLE_NAME);

    let mut fichier = std::fs::File::create(&bundle)?;
    if let Ok(image) = std::fs::read(crate::config::IMAGE_CA_BUNDLE) {
        fichier.write_all(&image)?;
        if !image.ends_with(b"\n") {
            fichier.write_all(b"\n")?;
        }
    }
    fichier.write_all(&entreprise)?;
    if !entreprise.ends_with(b"\n") {
        fichier.write_all(b"\n")?;
    }
    fichier.sync_all()?;

    // Posée avant tout usage du réseau, et pour tout le processus : `rustls-native-certs` la
    // lit à chaque construction de magasin, y compris celles de lettre et de ldap3.
    unsafe { std::env::set_var("SSL_CERT_FILE", &bundle) };

    Ok(bundle)
}

/// Vrai si le magasin de l'image a bien été repris.
///
/// Sert à avertir plutôt qu'à échouer : un magasin sans les autorités publiques reste utilisable
/// pour l'annuaire, et refuser de démarrer pour ça punirait un déploiement qui n'envoie aucun
/// courriel.
pub fn image_store_present() -> bool {
    Path::new(crate::config::IMAGE_CA_BUNDLE).exists()
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .map(|texte| texte.contains("-----BEGIN CERTIFICATE-----"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    /// `install` pose `SSL_CERT_FILE`, qui est global au processus — c'est tout l'objet de ce
    /// module. Le verrou est celui de tout le binaire de test, et non un verrou local : les
    /// tests de `config` écrivent eux aussi l'environnement, et deux verrous distincts ne se
    /// protègent de rien.
    fn serialise() -> std::sync::MutexGuard<'static, ()> {
        crate::env_lock()
    }

    fn temp_dir(nom: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kdt-identity-trust-{nom}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Le magasin assemblé doit contenir la CA de l'annuaire, sans quoi rien de ce module ne
    /// sert.
    #[test]
    fn le_magasin_assemble_contient_la_ca_de_l_annuaire() {
        let _guard = serialise();
        let dir = temp_dir("assemble");
        let ca = dir.join("ldap-ca.crt");
        std::fs::write(&ca, PEM).unwrap();

        let bundle = install(&ca, &dir.join("run")).unwrap();
        let contenu = std::fs::read_to_string(&bundle).unwrap();

        assert!(contenu.contains("-----BEGIN CERTIFICATE-----"), "{contenu}");
        assert_eq!(
            std::env::var("SSL_CERT_FILE").unwrap(),
            bundle.to_string_lossy()
        );
    }

    /// Une CA absente ou vide doit empêcher le démarrage. Écrire un magasin vide produirait un
    /// portail qui démarre et dont chaque connexion à l'annuaire échoue sur une erreur TLS
    /// que rien ne rattache à sa cause.
    #[test]
    fn une_ca_illisible_ou_vide_est_refusee() {
        let dir = temp_dir("refus");

        assert!(install(&dir.join("absente.crt"), &dir).is_err());

        let vide = dir.join("vide.crt");
        std::fs::write(&vide, "").unwrap();
        assert!(install(&vide, &dir).is_err());

        // Le cas courant de la faute de frappe : le contenu d'un Secret rendu en base64 au
        // lieu du PEM lui-même.
        let base64 = dir.join("base64.crt");
        std::fs::write(&base64, "TUlJQg==").unwrap();
        assert!(install(&base64, &dir).is_err());
    }

    /// Une CA qui ne finit pas par un saut de ligne collerait son `-----END-----` au bloc
    /// suivant, et le magasin entier deviendrait illisible.
    #[test]
    fn les_blocs_restent_separes_sans_saut_de_ligne_final() {
        let _guard = serialise();
        let dir = temp_dir("saut");
        let ca = dir.join("ldap-ca.crt");
        std::fs::write(&ca, PEM.trim_end()).unwrap();

        let bundle = install(&ca, &dir.join("run")).unwrap();
        let contenu = std::fs::read_to_string(&bundle).unwrap();

        assert!(contenu.ends_with('\n'), "{contenu:?}");
    }
}

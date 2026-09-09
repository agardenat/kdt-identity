//! Serveur kdt-identity : contrôleur, émission de credentials, portail web.

pub mod auth;
pub mod controller;
pub mod config;
pub mod credentials;
pub mod federation;
pub mod ldap;
pub mod mail;
pub mod manifests;
pub mod oidc;
pub mod oidc_auth;
pub mod sessions;
pub mod web;

/// Verrou des tests qui touchent à l'environnement du processus.
///
/// `set_var` n'est pas sûr en présence d'autres threads : la table d'environnement est unique et
/// partagée, et deux tests qui la modifient en parallèle — même sur des variables différentes —
/// peuvent se lire l'un l'autre à mi-écriture. Un verrou par module ne suffit donc pas, il en
/// faut un seul pour tout le binaire de test.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Installe le fournisseur cryptographique de rustls.
///
/// `rustls` 0.23 refuse de choisir seul dès que plusieurs fournisseurs sont compilables, et
/// panique au premier handshake sinon. À appeler une fois au démarrage — l'appel est
/// idempotent, ce qui permet aussi à chaque test d'intégration de l'invoquer sans se
/// coordonner avec les autres.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

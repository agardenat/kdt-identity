//! Serveur kdt-identity : contrôleur, émission de credentials, portail web.

pub mod auth;
pub mod controller;
pub mod config;
pub mod credentials;
pub mod mail;
pub mod manifests;
pub mod web;

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

//! Jetons signés : session, enrôlement TOTP, anti-CSRF.
//!
//! Le portail est sans état côté serveur : ce qu'il doit retenir entre deux requêtes voyage
//! dans un jeton signé, remis au navigateur. Aucune table de sessions à répliquer entre
//! plusieurs instances, et aucune session à perdre à chaque redémarrage — à condition que la
//! clé soit partagée, ce dont le déploiement se charge.
//!
//! Chaque jeton porte un **usage**, entré dans le calcul de la signature. Sans cette
//! séparation, un cookie d'enrôlement TOTP — que l'on remet à quelqu'un qui n'est pas encore
//! authentifié — serait un cookie de session valide.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Taille de la clé de signature.
pub const KEY_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("jeton mal formé")]
    Malformed,
    #[error("signature invalide")]
    BadSignature,
    #[error("jeton expiré")]
    Expired,
}

#[derive(Clone)]
pub struct Signer {
    key: [u8; KEY_BYTES],
}

impl Signer {
    pub fn new(key: [u8; KEY_BYTES]) -> Self {
        Self { key }
    }

    /// Tire une clé neuve.
    ///
    /// Utilisable en développement ou en instance unique. En production répliquée, la clé doit
    /// venir de la configuration : sans cela chaque instance signe avec la sienne et les
    /// sessions cessent d'être valides dès que la requête suivante tombe ailleurs.
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_BYTES];
        getrandom::fill(&mut key).expect("CSPRNG du système indisponible");
        Self::new(key)
    }

    /// Signe `payload` pour l'usage `purpose`, valable jusqu'à `expires_at` (epoch seconde).
    pub fn sign(&self, purpose: &str, payload: &str, expires_at: i64) -> String {
        let body = format!("{}.{expires_at}", b64(payload.as_bytes()));
        format!("{body}.{}", b64(&self.mac(purpose, &body)))
    }

    /// Vérifie un jeton et rend son contenu.
    ///
    /// La signature est contrôlée avant l'expiration : sans quoi le message d'erreur
    /// distinguerait un jeton périmé d'un jeton forgé, ce qui renseignerait sur la clé.
    pub fn verify(&self, purpose: &str, token: &str, now: i64) -> Result<String, TokenError> {
        let (body, signature) = token.rsplit_once('.').ok_or(TokenError::Malformed)?;
        let (payload, expires_at) = body.split_once('.').ok_or(TokenError::Malformed)?;

        let presented = unb64(signature).ok_or(TokenError::Malformed)?;
        if presented.ct_eq(&self.mac(purpose, body)).unwrap_u8() != 1 {
            return Err(TokenError::BadSignature);
        }

        let expires_at: i64 = expires_at.parse().map_err(|_| TokenError::Malformed)?;
        if now >= expires_at {
            return Err(TokenError::Expired);
        }

        String::from_utf8(unb64(payload).ok_or(TokenError::Malformed)?)
            .map_err(|_| TokenError::Malformed)
    }

    fn mac(&self, purpose: &str, body: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepte toute clé");
        // Le séparateur nul empêche qu'un usage et un corps différents produisent la même
        // entrée concaténée, et donc la même signature.
        mac.update(purpose.as_bytes());
        mac.update(&[0]);
        mac.update(body.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn signer() -> Signer {
        Signer::new([7u8; KEY_BYTES])
    }

    #[test]
    fn un_jeton_signe_se_relit() {
        let s = signer();
        let token = s.sign("session", "alice", NOW + 3600);
        assert_eq!(s.verify("session", &token, NOW).unwrap(), "alice");
    }

    #[test]
    fn un_contenu_quelconque_traverse_intact() {
        let s = signer();
        for payload in ["", "alice", "alice\nJBSWY3DP", "é@#$%^&*().,/\\", &"x".repeat(500)] {
            let token = s.sign("totp", payload, NOW + 60);
            assert_eq!(s.verify("totp", &token, NOW).unwrap(), payload);
        }
    }

    /// Le test qui justifie la séparation par usage : un cookie d'enrôlement TOTP est remis à
    /// quelqu'un qui n'est pas encore authentifié. S'il valait comme session, l'obtenir
    /// suffirait à se connecter.
    #[test]
    fn un_jeton_ne_vaut_que_pour_son_usage() {
        let s = signer();
        let enrolement = s.sign("totp-enrolment", "alice", NOW + 3600);

        assert_eq!(
            s.verify("session", &enrolement, NOW),
            Err(TokenError::BadSignature)
        );
        assert_eq!(
            s.verify("csrf", &enrolement, NOW),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn une_autre_cle_ne_valide_pas() {
        let token = signer().sign("session", "alice", NOW + 3600);
        let autre = Signer::new([9u8; KEY_BYTES]);
        assert_eq!(
            autre.verify("session", &token, NOW),
            Err(TokenError::BadSignature)
        );
    }

    /// Modifier le contenu doit invalider la signature, sinon n'importe qui se déclare admin.
    #[test]
    fn le_contenu_ne_peut_pas_etre_reecrit() {
        let s = signer();
        let token = s.sign("session", "alice", NOW + 3600);
        let (body, sig) = token.rsplit_once('.').unwrap();
        let (_, exp) = body.split_once('.').unwrap();

        use base64::Engine;
        let falsifie = format!(
            "{}.{exp}.{sig}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"mallory")
        );
        assert_eq!(
            s.verify("session", &falsifie, NOW),
            Err(TokenError::BadSignature)
        );
    }

    /// Repousser l'expiration est la falsification la plus tentante : elle doit casser la
    /// signature, puisque l'échéance entre dans son calcul.
    #[test]
    fn l_echeance_ne_peut_pas_etre_repoussee() {
        let s = signer();
        let token = s.sign("session", "alice", NOW + 60);
        let (body, sig) = token.rsplit_once('.').unwrap();
        let (payload, _) = body.split_once('.').unwrap();

        let prolonge = format!("{payload}.{}.{sig}", NOW + 999_999);
        assert_eq!(
            s.verify("session", &prolonge, NOW),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn un_jeton_expire_est_refuse() {
        let s = signer();
        let token = s.sign("session", "alice", NOW + 60);

        assert!(s.verify("session", &token, NOW + 59).is_ok());
        assert_eq!(
            s.verify("session", &token, NOW + 60),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn une_entree_quelconque_ne_fait_pas_paniquer() {
        let s = signer();
        for entree in ["", ".", "..", "a.b.c", "...", "a", "€.€.€", &"a".repeat(10_000)] {
            assert!(
                s.verify("session", entree, NOW).is_err(),
                "{entree:?} accepté à tort"
            );
        }
    }

    #[test]
    fn deux_cles_generees_different() {
        let a = Signer::generate().sign("session", "alice", NOW + 60);
        let b = Signer::generate().sign("session", "alice", NOW + 60);
        assert_ne!(a, b);
    }
}

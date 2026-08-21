//! Second facteur TOTP : enrôlement et vérification.
//!
//! La [RFC 6238 §5.2](https://datatracker.ietf.org/doc/html/rfc6238#section-5.2) exige qu'un
//! code ne soit accepté **qu'une seule fois**. `totp-rs` ne l'applique pas et se contente de
//! renvoyer le pas de temps validé, en laissant la responsabilité à l'appelant : c'est
//! [`verify`] qui la porte ici, en refusant tout pas déjà consommé.
//!
//! Sans cela, un code intercepté — épaule, hameçonnage, journal mal filtré — resterait
//! rejouable pendant toute sa fenêtre de validité.

use totp_rs::{Builder, Secret, Totp};
use zeroize::Zeroizing;

/// Tolérance de dérive d'horloge, en pas de 30 secondes.
///
/// Une valeur de 1 accepte le pas précédent et le suivant, soit environ 90 secondes de
/// fenêtre. Au-delà, on élargit la surface de rejeu sans réel gain d'ergonomie.
pub const SKEW: u16 = 1;

/// Durée d'un pas, en secondes. Valeur conventionnelle, comprise par tous les authenticators.
pub const STEP: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("secret TOTP illisible : {0}")]
    BadSecret(String),
    #[error("construction du TOTP : {0}")]
    Build(String),
    #[error("code invalide")]
    InvalidCode,
    /// Le code est arithmétiquement correct mais son pas a déjà servi.
    #[error("code déjà utilisé : attendre la fenêtre suivante")]
    Replayed,
}

/// Ce qu'il faut présenter à l'utilisateur pour qu'il enrôle son authenticator.
pub struct Enrollment {
    /// Secret en base32, à saisir manuellement si le QR ne passe pas.
    pub secret_base32: Zeroizing<String>,
    /// URL `otpauth://`, à encoder en QR code.
    pub provisioning_url: Zeroizing<String>,
}

/// Tire un nouveau secret et construit l'URL d'enrôlement.
///
/// `issuer` est le nom affiché dans l'application d'authentification ; `account` identifie le
/// compte à l'intérieur. Les deux apparaissent tels quels sur le téléphone de l'utilisateur.
pub fn enroll(account: &str, issuer: &str) -> Result<Enrollment, TotpError> {
    let secret = Secret::generate();
    let secret_base32 = Zeroizing::new(secret.to_base32());
    let totp = build(&secret_base32, account, issuer)?;

    // `to_url`, pas `to_string` : le `Display` de `Totp` est un résumé de debug
    // (« digits: 6; step: 30; … »), qu'aucune application d'authentification ne comprend.
    Ok(Enrollment {
        secret_base32,
        provisioning_url: Zeroizing::new(
            totp.to_url().map_err(|e| TotpError::Build(format!("{e:?}")))?,
        ),
    })
}

/// Confronte un code au secret, puis refuse tout pas déjà consommé.
///
/// `last_used_step` est le dernier pas validé pour ce compte, `None` si aucun. En cas de
/// succès, la valeur renvoyée est le nouveau pas à mémoriser : sans cette mémorisation, la
/// protection anti-rejeu ne fonctionne pas.
pub fn verify(
    secret_base32: &str,
    code: &str,
    now: u64,
    last_used_step: Option<u64>,
) -> Result<u64, TotpError> {
    // `account` et `issuer` n'entrent pas dans le calcul du code, seulement dans l'URL
    // d'enrôlement : des valeurs de remplissage suffisent ici.
    let totp = build(secret_base32, "verify", "kdt-identity")?;

    let step = totp.check(code, now).ok_or(TotpError::InvalidCode)?;

    // `<=` et non `<` : réutiliser le pas courant est le rejeu le plus direct, et un pas
    // antérieur signale une horloge qui recule ou une tentative de rejouer un ancien code.
    if last_used_step.is_some_and(|last| step <= last) {
        return Err(TotpError::Replayed);
    }

    Ok(step)
}

fn build(secret_base32: &str, account: &str, issuer: &str) -> Result<Totp, TotpError> {
    let secret = Secret::try_from_base32(secret_base32)
        .map_err(|e| TotpError::BadSecret(format!("{e:?}")))?;

    Builder::new()
        .with_secret(secret)
        .with_skew(SKEW)
        .with_step_duration(STEP)
        .with_account_name(account)
        .with_issuer(Some(issuer))
        .build()
        .map_err(|e| TotpError::Build(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Code attendu à `now` pour ce secret, calculé par la bibliothèque elle-même.
    fn code_at(secret_base32: &str, now: u64) -> String {
        build(secret_base32, "verify", "kdt-identity")
            .unwrap()
            .generate(now)
            .to_string()
    }

    fn secret() -> Zeroizing<String> {
        enroll("alice", "kdt-identity").unwrap().secret_base32
    }

    #[test]
    fn l_enrolement_produit_une_url_otpauth_exploitable() {
        let e = enroll("alice", "kdt-identity").unwrap();
        assert!(e.provisioning_url.starts_with("otpauth://totp/"), "{}", *e.provisioning_url);
        assert!(e.provisioning_url.contains("kdt-identity"));
        assert!(e.provisioning_url.contains("alice"));
        assert!(!e.secret_base32.is_empty());
    }

    #[test]
    fn deux_enrolements_ne_partagent_pas_leur_secret() {
        assert_ne!(*secret(), *secret());
    }

    #[test]
    fn accepte_le_code_courant() {
        let s = secret();
        let now = 1_700_000_000;
        let step = verify(&s, &code_at(&s, now), now, None).unwrap();
        assert_eq!(step, now / STEP);
    }

    #[test]
    fn refuse_un_code_faux() {
        let s = secret();
        let now = 1_700_000_000;
        assert!(matches!(
            verify(&s, "000000", now, None),
            Err(TotpError::InvalidCode) | Ok(_)
        ));
        // Un code manifestement mal formé doit être refusé sans ambiguïté.
        for mauvais in ["", "abcdef", "12345", "1234567"] {
            assert!(
                matches!(verify(&s, mauvais, now, None), Err(TotpError::InvalidCode)),
                "{mauvais:?} accepté à tort"
            );
        }
    }

    /// La tolérance de dérive doit accepter le pas précédent et le suivant, pas au-delà.
    #[test]
    fn tolere_une_derive_d_un_pas() {
        let s = secret();
        let now = 1_700_000_000;

        assert!(verify(&s, &code_at(&s, now - STEP), now, None).is_ok());
        assert!(verify(&s, &code_at(&s, now + STEP), now, None).is_ok());
        assert!(matches!(
            verify(&s, &code_at(&s, now - 3 * STEP), now, None),
            Err(TotpError::InvalidCode)
        ));
    }

    /// Le test qui justifie ce module : un code valide ne vaut qu'une fois.
    #[test]
    fn un_code_ne_sert_qu_une_fois() {
        let s = secret();
        let now = 1_700_000_000;
        let code = code_at(&s, now);

        let step = verify(&s, &code, now, None).expect("première présentation");
        assert!(matches!(
            verify(&s, &code, now, Some(step)),
            Err(TotpError::Replayed)
        ));
    }

    /// Rejouer un code plus ancien que le dernier accepté doit échouer aussi : sinon la
    /// fenêtre de tolérance devient une fenêtre de rejeu.
    #[test]
    fn un_code_anterieur_au_dernier_accepte_est_refuse() {
        let s = secret();
        let now = 1_700_000_000;
        let dernier = now / STEP;

        assert!(matches!(
            verify(&s, &code_at(&s, now - STEP), now, Some(dernier)),
            Err(TotpError::Replayed)
        ));
    }

    #[test]
    fn le_pas_suivant_reste_accepte_apres_une_authentification() {
        let s = secret();
        let now = 1_700_000_000;
        let step = verify(&s, &code_at(&s, now), now, None).unwrap();

        let plus_tard = now + STEP;
        let suivant = verify(&s, &code_at(&s, plus_tard), plus_tard, Some(step)).unwrap();
        assert_eq!(suivant, step + 1);
    }

    #[test]
    fn refuse_un_secret_illisible() {
        assert!(matches!(
            verify("pas du base32 !", "123456", 1_700_000_000, None),
            Err(TotpError::BadSecret(_))
        ));
    }
}

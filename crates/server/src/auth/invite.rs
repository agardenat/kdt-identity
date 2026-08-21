//! Jetons d'invitation et de réinitialisation de mot de passe.
//!
//! Le jeton en clair n'existe qu'une fois, le temps d'être envoyé par courriel. Ce qui est
//! stocké est son empreinte SHA-256 : une fuite de la base ne donne alors aucun moyen
//! d'activer un compte, alors qu'un jeton stocké en clair serait immédiatement utilisable.
//!
//! Le même mécanisme sert à l'invitation initiale et à la réinitialisation : ce sont deux
//! formulations du même besoin — prouver qu'on relève la boîte mail du compte.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Taille du jeton tiré, en octets.
///
/// 256 bits de matériel aléatoire : un jeton d'invitation vaut une authentification complète
/// tant qu'il n'est pas consommé, il ne doit pas être devinable.
pub const TOKEN_BYTES: usize = 32;

/// Durée de validité par défaut d'une invitation.
pub const DEFAULT_VALIDITY: Duration = Duration::hours(72);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("jeton invalide")]
    Invalid,
    #[error("jeton expiré depuis le {0}")]
    Expired(DateTime<Utc>),
    #[error("empreinte stockée illisible")]
    CorruptRecord,
}

/// Ce que le serveur conserve d'une invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    /// SHA-256 du jeton, en hexadécimal minuscule.
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

/// Une invitation fraîchement créée : le jeton à envoyer, et ce qu'il faut stocker.
pub struct NewInvite {
    /// À placer dans le lien du courriel, et nulle part ailleurs. Jamais journalisé.
    pub token: Zeroizing<String>,
    pub record: InviteRecord,
}

/// Tire une invitation valable `validity` à partir de `now`.
pub fn create(now: DateTime<Utc>, validity: Duration) -> NewInvite {
    let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
    getrandom::fill(bytes.as_mut_slice()).expect("CSPRNG du système indisponible");

    // base64url sans remplissage : le jeton voyage dans une URL, il ne doit ni être réencodé
    // ni se faire tronquer par un client mail qui traiterait `=` comme une fin de lien.
    let token = Zeroizing::new(base64_url_nopad(bytes.as_slice()));

    NewInvite {
        record: InviteRecord {
            token_hash: digest(&token),
            expires_at: now + validity,
        },
        token,
    }
}

/// Confronte un jeton présenté à l'empreinte stockée.
///
/// La comparaison est à temps constant : une comparaison naïve fuit, octet par octet, la
/// longueur du préfixe correct, ce qui suffit à reconstituer une empreinte par essais
/// successifs.
pub fn verify(
    record: &InviteRecord,
    presented: &str,
    now: DateTime<Utc>,
) -> Result<(), InviteError> {
    let expected = decode_hex(&record.token_hash).ok_or(InviteError::CorruptRecord)?;
    let actual = Sha256::digest(presented.as_bytes());

    if actual.as_slice().ct_eq(&expected).unwrap_u8() != 1 {
        return Err(InviteError::Invalid);
    }

    // L'expiration n'est vérifiée qu'après coup : le contraire distinguerait, par le message
    // d'erreur, un jeton expiré d'un jeton faux, et confirmerait au passage qu'une invitation
    // a bien existé pour ce compte.
    if now >= record.expires_at {
        return Err(InviteError::Expired(record.expires_at));
    }

    Ok(())
}

fn digest(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn base64_url_nopad(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn un_jeton_frais_se_verifie() {
        let invite = create(now(), DEFAULT_VALIDITY);
        assert_eq!(verify(&invite.record, &invite.token, now()), Ok(()));
    }

    /// Ce qui est stocké ne doit jamais permettre de reconstituer le jeton.
    #[test]
    fn le_jeton_en_clair_n_est_pas_stocke() {
        let invite = create(now(), DEFAULT_VALIDITY);
        assert_ne!(invite.record.token_hash, *invite.token);
        assert!(!invite.record.token_hash.contains(invite.token.as_str()));
        assert_eq!(invite.record.token_hash.len(), 64);
    }

    #[test]
    fn deux_invitations_ne_partagent_ni_jeton_ni_empreinte() {
        let a = create(now(), DEFAULT_VALIDITY);
        let b = create(now(), DEFAULT_VALIDITY);
        assert_ne!(*a.token, *b.token);
        assert_ne!(a.record.token_hash, b.record.token_hash);
    }

    #[test]
    fn refuse_un_jeton_faux() {
        let invite = create(now(), DEFAULT_VALIDITY);
        for faux in ["", "x", &"A".repeat(43)] {
            assert_eq!(
                verify(&invite.record, faux, now()),
                Err(InviteError::Invalid),
                "{faux:?} accepté à tort"
            );
        }
    }

    /// Un jeton tronqué ne doit pas passer : c'est le cas classique du lien coupé par un
    /// client mail, et l'accepter reviendrait à réduire l'entropie du jeton.
    #[test]
    fn refuse_un_jeton_tronque_ou_rallonge() {
        let invite = create(now(), DEFAULT_VALIDITY);
        let tronque = &invite.token[..invite.token.len() - 1];
        let rallonge = format!("{}x", *invite.token);

        assert_eq!(verify(&invite.record, tronque, now()), Err(InviteError::Invalid));
        assert_eq!(verify(&invite.record, &rallonge, now()), Err(InviteError::Invalid));
    }

    #[test]
    fn refuse_un_jeton_expire() {
        let invite = create(now(), Duration::hours(1));
        let plus_tard = now() + Duration::hours(2);

        assert_eq!(
            verify(&invite.record, &invite.token, plus_tard),
            Err(InviteError::Expired(invite.record.expires_at))
        );
    }

    /// L'instant exact de l'expiration est déjà trop tard.
    #[test]
    fn l_expiration_est_exclusive() {
        let invite = create(now(), Duration::hours(1));
        let juste_avant = invite.record.expires_at - Duration::seconds(1);

        assert!(verify(&invite.record, &invite.token, juste_avant).is_ok());
        assert!(verify(&invite.record, &invite.token, invite.record.expires_at).is_err());
    }

    /// Un jeton faux ET expiré doit se signaler comme faux : répondre « expiré » confirmerait
    /// à un tiers qu'une invitation a existé pour ce compte.
    #[test]
    fn un_jeton_faux_et_expire_se_signale_comme_faux() {
        let invite = create(now(), Duration::hours(1));
        let plus_tard = now() + Duration::hours(2);

        assert_eq!(
            verify(&invite.record, "jeton-inventé", plus_tard),
            Err(InviteError::Invalid)
        );
    }

    #[test]
    fn refuse_une_empreinte_stockee_illisible() {
        for mauvaise in ["", "zz", &"z".repeat(64), &"a".repeat(63)] {
            let record = InviteRecord {
                token_hash: mauvaise.to_string(),
                expires_at: now() + Duration::hours(1),
            };
            assert_eq!(
                verify(&record, "peu importe", now()),
                Err(InviteError::CorruptRecord),
                "{mauvaise:?} aurait dû être signalée illisible"
            );
        }
    }

    /// Le jeton voyage dans une URL : aucun caractère ne doit y être réencodé.
    #[test]
    fn le_jeton_traverse_une_url_sans_encodage() {
        let invite = create(now(), DEFAULT_VALIDITY);
        assert!(
            invite
                .token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{}",
            *invite.token
        );
    }
}

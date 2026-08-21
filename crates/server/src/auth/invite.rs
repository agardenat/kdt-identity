//! Invitations : lien d'activation et code hors bande.
//!
//! Activer un compte demande **deux** éléments, délibérément séparés :
//!
//! - un jeton long, placé dans le lien ;
//! - un code court, lisible à voix haute, que l'administrateur transmet par un autre moyen.
//!
//! Les deux sont exigés. C'est ce qui rend l'interception du seul lien inutile — or le lien
//! voyage souvent par courriel, c'est-à-dire par le canal le moins maîtrisé de la chaîne.
//!
//! Aucun des deux n'est stocké en clair : ce sont leurs empreintes SHA-256 qui sont conservées.
//! Une fuite de la base ne donne alors aucun moyen d'activer un compte.
//!
//! Le même mécanisme sert à l'invitation initiale et à la réinitialisation de mot de passe :
//! ce sont deux formulations du même besoin.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Taille du jeton du lien, en octets.
///
/// 256 bits : tant qu'il n'est pas consommé, ce jeton est la moitié d'une authentification.
pub const TOKEN_BYTES: usize = 32;

/// Nombre de caractères du code hors bande.
///
/// Huit caractères sur un alphabet de 31 font près de 40 bits — hors de portée d'un devinage,
/// d'autant que le verrouillage progressif s'applique aux tentatives d'activation. Assez court
/// pour être dicté au téléphone sans erreur.
pub const CODE_LENGTH: usize = 8;

/// Alphabet du code, amputé de tout ce qui se confond à l'oral ou à l'écrit : ni `O`/`0`, ni
/// `I`/`1`/`L`. Un code mal recopié n'est pas une faute de l'utilisateur mais du concepteur.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// Durée de validité par défaut d'une invitation.
pub const DEFAULT_VALIDITY: Duration = Duration::hours(72);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    /// Jeton ou code faux — l'erreur ne distingue pas lequel, pour ne rien apprendre à qui
    /// cherche à en deviner un.
    #[error("lien ou code d'activation invalide")]
    Invalid,
    #[error("invitation expirée depuis le {0}")]
    Expired(DateTime<Utc>),
    #[error("empreinte stockée illisible")]
    CorruptRecord,
}

/// Ce que le serveur conserve d'une invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    /// SHA-256 du jeton du lien, en hexadécimal minuscule.
    pub token_hash: String,
    /// SHA-256 du code hors bande, normalisé avant hachage.
    pub code_hash: String,
    pub expires_at: DateTime<Utc>,
}

/// Une invitation fraîchement créée.
///
/// Le jeton et le code n'existent en clair qu'ici, le temps d'être affichés une fois à
/// l'administrateur. Ni l'un ni l'autre ne doit être journalisé, ni écrit dans le statut d'un
/// `KdtUser` — un statut est lisible par quiconque peut lister les utilisateurs.
pub struct NewInvite {
    /// À placer dans le lien d'activation.
    pub token: Zeroizing<String>,
    /// À transmettre par un autre canal que le lien. Présenté par groupes de quatre.
    pub activation_code: Zeroizing<String>,
    pub record: InviteRecord,
}

/// Tire une invitation valable `validity` à partir de `now`.
pub fn create(now: DateTime<Utc>, validity: Duration) -> NewInvite {
    let mut token_bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
    getrandom::fill(token_bytes.as_mut_slice()).expect("CSPRNG du système indisponible");

    // base64url sans remplissage : le jeton voyage dans une URL, il ne doit ni être réencodé
    // ni se faire tronquer par un client mail qui traiterait `=` comme une fin de lien.
    let token = Zeroizing::new(base64_url_nopad(token_bytes.as_slice()));
    let activation_code = generate_code();

    NewInvite {
        record: InviteRecord {
            token_hash: digest(&token),
            code_hash: digest(&normalize_code(&activation_code)),
            expires_at: now + validity,
        },
        token,
        activation_code,
    }
}

/// Confronte un lien et un code à l'invitation stockée.
///
/// Les deux comparaisons ont lieu systématiquement, même si la première échoue : s'arrêter au
/// premier écart apprendrait, par le temps de réponse, lequel des deux éléments est correct.
pub fn verify(
    record: &InviteRecord,
    presented_token: &str,
    presented_code: &str,
    now: DateTime<Utc>,
) -> Result<(), InviteError> {
    let expected_token = decode_hex(&record.token_hash).ok_or(InviteError::CorruptRecord)?;
    let expected_code = decode_hex(&record.code_hash).ok_or(InviteError::CorruptRecord)?;

    let token_ok = Sha256::digest(presented_token.as_bytes())
        .as_slice()
        .ct_eq(&expected_token);
    let code_ok = Sha256::digest(normalize_code(presented_code).as_bytes())
        .as_slice()
        .ct_eq(&expected_code);

    if (token_ok & code_ok).unwrap_u8() != 1 {
        return Err(InviteError::Invalid);
    }

    // L'expiration n'est vérifiée qu'après coup : le contraire distinguerait, par le message
    // d'erreur, une invitation expirée d'un lien faux, et confirmerait au passage qu'une
    // invitation a bien existé pour ce compte.
    if now >= record.expires_at {
        return Err(InviteError::Expired(record.expires_at));
    }

    Ok(())
}

/// Rend un code comparable quelle que soit la façon dont il a été recopié.
///
/// Le code est dicté puis saisi à la main : la casse, les espaces et les tirets de
/// présentation ne doivent pas décider d'un échec d'activation.
pub fn normalize_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Met le code en forme pour l'affichage : `ABCD-EFGH`.
pub fn format_code(code: &str) -> String {
    let normalized = normalize_code(code);
    normalized
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn generate_code() -> Zeroizing<String> {
    let mut raw = Zeroizing::new([0u8; CODE_LENGTH]);
    getrandom::fill(raw.as_mut_slice()).expect("CSPRNG du système indisponible");

    // 256 n'est pas un multiple de 31 : réduire modulo l'alphabet favorise légèrement ses
    // premiers caractères. Le biais est de l'ordre de 3 % sur un caractère, négligeable
    // devant les 40 bits du code, et le rejet d'échantillon coûterait une boucle non bornée
    // pour un gain nul ici.
    Zeroizing::new(
        raw.iter()
            .map(|b| CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char)
            .collect(),
    )
}

fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
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
    fn une_invitation_fraiche_se_verifie() {
        let i = create(now(), DEFAULT_VALIDITY);
        assert_eq!(
            verify(&i.record, &i.token, &i.activation_code, now()),
            Ok(())
        );
    }

    /// Le cœur du dispositif : le lien seul ne suffit pas.
    #[test]
    fn le_lien_seul_ne_suffit_pas() {
        let i = create(now(), DEFAULT_VALIDITY);
        assert_eq!(
            verify(&i.record, &i.token, "", now()),
            Err(InviteError::Invalid)
        );
        assert_eq!(
            verify(&i.record, &i.token, "AAAA-AAAA", now()),
            Err(InviteError::Invalid)
        );
    }

    /// Et le code seul non plus : il est court, donc devinable si on l'acceptait seul.
    #[test]
    fn le_code_seul_ne_suffit_pas() {
        let i = create(now(), DEFAULT_VALIDITY);
        assert_eq!(
            verify(&i.record, "", &i.activation_code, now()),
            Err(InviteError::Invalid)
        );
    }

    /// Le code est dicté au téléphone puis recopié : ni la casse ni la mise en forme ne
    /// doivent décider d'un échec.
    #[test]
    fn le_code_est_tolerant_a_la_saisie() {
        let i = create(now(), DEFAULT_VALIDITY);

        for variante in [
            i.activation_code.to_lowercase(),
            format_code(&i.activation_code),
            format!(" {} ", *i.activation_code),
            i.activation_code
                .chars()
                .flat_map(|c| [c, ' '])
                .collect::<String>(),
        ] {
            assert_eq!(
                verify(&i.record, &i.token, &variante, now()),
                Ok(()),
                "variante {variante:?} refusée"
            );
        }
    }

    /// Le code est lu et recopié par des humains : aucun caractère ambigu ne doit y figurer.
    #[test]
    fn le_code_evite_les_caracteres_confondables() {
        for _ in 0..200 {
            let i = create(now(), DEFAULT_VALIDITY);
            assert_eq!(i.activation_code.len(), CODE_LENGTH);
            for c in i.activation_code.chars() {
                assert!(
                    !"O0I1L".contains(c),
                    "caractère ambigu {c:?} dans {}",
                    *i.activation_code
                );
                assert!(c.is_ascii_uppercase() || c.is_ascii_digit(), "{c:?}");
            }
        }
    }

    #[test]
    fn le_code_s_affiche_par_groupes_de_quatre() {
        assert_eq!(format_code("ABCDEFGH"), "ABCD-EFGH");
        assert_eq!(format_code("abcd efgh"), "ABCD-EFGH");
    }

    /// Ce qui est stocké ne doit jamais permettre de reconstituer l'un ou l'autre.
    #[test]
    fn ni_le_jeton_ni_le_code_ne_sont_stockes_en_clair() {
        let i = create(now(), DEFAULT_VALIDITY);
        assert_ne!(i.record.token_hash, *i.token);
        assert_ne!(i.record.code_hash, *i.activation_code);
        assert!(!i.record.code_hash.contains(i.activation_code.as_str()));
        assert_eq!(i.record.token_hash.len(), 64);
        assert_eq!(i.record.code_hash.len(), 64);
    }

    #[test]
    fn deux_invitations_ne_partagent_rien() {
        let a = create(now(), DEFAULT_VALIDITY);
        let b = create(now(), DEFAULT_VALIDITY);
        assert_ne!(*a.token, *b.token);
        assert_ne!(*a.activation_code, *b.activation_code);
        assert_ne!(a.record.token_hash, b.record.token_hash);
        assert_ne!(a.record.code_hash, b.record.code_hash);
    }

    /// Un lien tronqué par un client mail ne doit pas passer : l'accepter reviendrait à
    /// réduire l'entropie du jeton.
    #[test]
    fn refuse_un_jeton_tronque_ou_rallonge() {
        let i = create(now(), DEFAULT_VALIDITY);
        let tronque = &i.token[..i.token.len() - 1];
        let rallonge = format!("{}x", *i.token);

        assert_eq!(
            verify(&i.record, tronque, &i.activation_code, now()),
            Err(InviteError::Invalid)
        );
        assert_eq!(
            verify(&i.record, &rallonge, &i.activation_code, now()),
            Err(InviteError::Invalid)
        );
    }

    #[test]
    fn refuse_une_invitation_expiree() {
        let i = create(now(), Duration::hours(1));
        let plus_tard = now() + Duration::hours(2);

        assert_eq!(
            verify(&i.record, &i.token, &i.activation_code, plus_tard),
            Err(InviteError::Expired(i.record.expires_at))
        );
    }

    #[test]
    fn l_expiration_est_exclusive() {
        let i = create(now(), Duration::hours(1));
        let juste_avant = i.record.expires_at - Duration::seconds(1);

        assert!(verify(&i.record, &i.token, &i.activation_code, juste_avant).is_ok());
        assert!(verify(&i.record, &i.token, &i.activation_code, i.record.expires_at).is_err());
    }

    /// Un lien faux ET expiré se signale comme faux : répondre « expiré » confirmerait à un
    /// tiers qu'une invitation a existé pour ce compte.
    #[test]
    fn un_lien_faux_et_expire_se_signale_comme_faux() {
        let i = create(now(), Duration::hours(1));
        let plus_tard = now() + Duration::hours(2);

        assert_eq!(
            verify(&i.record, "jeton-inventé", &i.activation_code, plus_tard),
            Err(InviteError::Invalid)
        );
    }

    #[test]
    fn refuse_une_empreinte_stockee_illisible() {
        let bonne = create(now(), Duration::hours(1));
        for mauvaise in ["", "zz", &"z".repeat(64), &"a".repeat(63)] {
            for record in [
                InviteRecord {
                    token_hash: mauvaise.to_string(),
                    ..bonne.record.clone()
                },
                InviteRecord {
                    code_hash: mauvaise.to_string(),
                    ..bonne.record.clone()
                },
            ] {
                assert_eq!(
                    verify(&record, "peu importe", "peu importe", now()),
                    Err(InviteError::CorruptRecord),
                    "{mauvaise:?} aurait dû être signalée illisible"
                );
            }
        }
    }

    /// Le jeton voyage dans une URL : aucun caractère ne doit y être réencodé.
    #[test]
    fn le_jeton_traverse_une_url_sans_encodage() {
        let i = create(now(), DEFAULT_VALIDITY);
        assert!(
            i.token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{}",
            *i.token
        );
    }
}

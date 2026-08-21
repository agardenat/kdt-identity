//! Mots de passe : politique, hachage Argon2id, vérification.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use zeroize::Zeroizing;

/// Longueur minimale exigée.
///
/// Douze caractères plutôt que huit : c'est ce qui rend inutile l'essentiel des listes de mots
/// de passe courants, dont la quasi-totalité des entrées est plus courte.
pub const MIN_LENGTH: usize = 12;

/// Longueur maximale acceptée.
///
/// Argon2 est délibérément coûteux : sans plafond, une entrée de plusieurs mégaoctets soumise
/// en boucle suffirait à saturer le serveur. Le plafond est haut pour ne gêner personne.
pub const MAX_LENGTH: usize = 1024;

/// Mots de passe assez longs pour passer [`MIN_LENGTH`] mais trop répandus pour être admis.
///
/// Volontairement court : à douze caractères, les listes classiques sont déjà hors-jeu. Ce qui
/// reste, ce sont les rallonges évidentes de mots de passe connus. Un déploiement exposé
/// gagnerait à brancher une liste plus large ou une vérification HIBP.
const TOO_COMMON: &[&str] = &[
    "password1234",
    "motdepasse12",
    "123456789012",
    "qwertyuiop12",
    "azertyuiop12",
    "administrator",
    "passwordpassword",
    "kubernetes12",
    "letmein12345",
    "welcome12345",
    "iloveyou1234",
    "changeme1234",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("mot de passe trop court : {0} caractères, minimum {MIN_LENGTH}")]
    TooShort(usize),
    #[error("mot de passe trop long : {0} caractères, maximum {MAX_LENGTH}")]
    TooLong(usize),
    #[error("mot de passe composé d'un seul caractère répété")]
    SingleCharacter,
    #[error("mot de passe formé d'une suite de caractères consécutifs")]
    Sequence,
    #[error("mot de passe trop répandu")]
    TooCommon,
    #[error("le mot de passe contient le nom du compte")]
    ContainsAccountName,
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("hachage du mot de passe : {0}")]
    Hash(argon2::password_hash::Error),
    /// L'empreinte stockée est illisible. Ce n'est pas un mauvais mot de passe mais un
    /// problème de données : à signaler, jamais à confondre avec un échec d'authentification.
    #[error("empreinte stockée illisible : {0}")]
    CorruptStoredHash(argon2::password_hash::Error),
}

/// Vérifie qu'un mot de passe est acceptable, avant tout hachage.
///
/// `account` est le nom du compte : un mot de passe qui le contient est trivialement devinable
/// par quiconque connaît l'utilisateur, ce qui est le cas de tout le monde dans un annuaire.
pub fn check_policy(password: &str, account: &str) -> Result<(), PolicyError> {
    let length = password.chars().count();
    if length < MIN_LENGTH {
        return Err(PolicyError::TooShort(length));
    }
    if length > MAX_LENGTH {
        return Err(PolicyError::TooLong(length));
    }

    let lowered = password.to_lowercase();

    if password.chars().skip(1).all(|c| Some(c) == password.chars().next()) {
        return Err(PolicyError::SingleCharacter);
    }
    if is_sequence(password) {
        return Err(PolicyError::Sequence);
    }
    if TOO_COMMON.contains(&lowered.as_str()) {
        return Err(PolicyError::TooCommon);
    }
    // En dessous de quatre caractères, un nom de compte se retrouverait par hasard dans trop
    // de mots de passe légitimes.
    if account.chars().count() >= 4 && lowered.contains(&account.to_lowercase()) {
        return Err(PolicyError::ContainsAccountName);
    }

    Ok(())
}

/// Vrai si le mot de passe entier est une suite de caractères consécutifs, croissante ou
/// décroissante — `123456789012` ou `abcdefghijkl`.
fn is_sequence(password: &str) -> bool {
    let codes: Vec<u32> = password.chars().map(u32::from).collect();
    let ascending = codes.windows(2).all(|w| w[1] == w[0] + 1);
    let descending = codes.windows(2).all(|w| w[0] == w[1] + 1);
    ascending || descending
}

/// Hache un mot de passe en Argon2id, paramètres par défaut de la bibliothèque.
///
/// Le résultat est une chaîne PHC : elle embarque le sel, l'algorithme et ses paramètres, ce
/// qui permettra de durcir ceux-ci plus tard sans invalider les empreintes existantes.
pub fn hash(password: &str) -> Result<Zeroizing<String>, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| Zeroizing::new(h.to_string()))
        .map_err(PasswordError::Hash)
}

/// Confronte un mot de passe à une empreinte stockée.
///
/// `Ok(false)` signifie « mauvais mot de passe » ; `Err` signifie « l'empreinte en base est
/// inutilisable ». Les deux refusent l'accès, mais seul le second appelle une intervention.
pub fn verify(password: &str, stored: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(stored).map_err(PasswordError::CorruptStoredHash)?;

    // Une chaîne PHC réduite à son identifiant d'algorithme se parse sans erreur mais ne
    // contient aucune empreinte à comparer. La vérification échouerait alors comme un simple
    // mauvais mot de passe, masquant une donnée inutilisable derrière un refus banal.
    if parsed.hash.is_none() {
        return Err(PasswordError::CorruptStoredHash(
            argon2::password_hash::Error::PhcStringField,
        ));
    }

    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(other) => Err(PasswordError::CorruptStoredHash(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepte_un_mot_de_passe_correct() {
        assert_eq!(check_policy("cheval-Correct-42!", "alice"), Ok(()));
        assert_eq!(check_policy("Tr0ubad0ur&3xtra", "alice"), Ok(()));
    }

    #[test]
    fn refuse_en_dessous_du_minimum() {
        assert_eq!(check_policy("court1!", "alice"), Err(PolicyError::TooShort(7)));
        // Exactement à la limite : accepté.
        assert_eq!(check_policy("abcdEF12!@#$", "alice"), Ok(()));
    }

    /// Le plafond protège le serveur, pas l'utilisateur : Argon2 sur une entrée démesurée est
    /// un déni de service offert.
    #[test]
    fn refuse_au_dessus_du_plafond() {
        let enorme = "a".repeat(MAX_LENGTH + 1);
        assert_eq!(
            check_policy(&enorme, "alice"),
            Err(PolicyError::TooLong(MAX_LENGTH + 1))
        );
    }

    #[test]
    fn refuse_les_mots_de_passe_degeneres() {
        assert_eq!(
            check_policy("aaaaaaaaaaaaaaaa", "alice"),
            Err(PolicyError::SingleCharacter)
        );
        assert_eq!(
            check_policy("abcdefghijklmnop", "alice"),
            Err(PolicyError::Sequence)
        );
        assert_eq!(
            check_policy("ponmlkjihgfedcba", "alice"),
            Err(PolicyError::Sequence)
        );
    }

    #[test]
    fn refuse_les_mots_de_passe_trop_repandus() {
        assert_eq!(check_policy("password1234", "alice"), Err(PolicyError::TooCommon));
        // La casse ne doit pas suffire à contourner la liste.
        assert_eq!(check_policy("PassWord1234", "alice"), Err(PolicyError::TooCommon));
    }

    /// Le nom du compte est public : l'inclure revient à publier une partie du mot de passe.
    #[test]
    fn refuse_un_mot_de_passe_contenant_le_nom_du_compte() {
        assert_eq!(
            check_policy("alice-mot-de-passe", "alice"),
            Err(PolicyError::ContainsAccountName)
        );
        assert_eq!(
            check_policy("xxALICExx1234", "alice"),
            Err(PolicyError::ContainsAccountName)
        );
    }

    /// Un nom de compte très court apparaîtrait par hasard partout.
    #[test]
    fn un_nom_de_compte_tres_court_n_est_pas_recherche() {
        assert_eq!(check_policy("abc-quelque-chose", "abc"), Ok(()));
    }

    #[test]
    fn le_hachage_se_verifie() {
        let stored = hash("cheval-Correct-42!").unwrap();
        assert!(verify("cheval-Correct-42!", &stored).unwrap());
        assert!(!verify("cheval-Correct-43!", &stored).unwrap());
    }

    /// Le sel doit être tiré à chaque appel, sinon deux comptes partageant un mot de passe
    /// partagent une empreinte, et une seule cassure les compromet tous les deux.
    #[test]
    fn deux_hachages_du_meme_mot_de_passe_different() {
        let a = hash("cheval-Correct-42!").unwrap();
        let b = hash("cheval-Correct-42!").unwrap();
        assert_ne!(*a, *b);
        assert!(verify("cheval-Correct-42!", &a).unwrap());
        assert!(verify("cheval-Correct-42!", &b).unwrap());
    }

    #[test]
    fn l_empreinte_est_bien_de_l_argon2id() {
        let stored = hash("cheval-Correct-42!").unwrap();
        assert!(stored.starts_with("$argon2id$"), "{}", *stored);
    }

    /// Une empreinte corrompue ne doit pas se confondre avec un mot de passe faux : la
    /// première demande une intervention, le second est un évènement ordinaire.
    #[test]
    fn une_empreinte_illisible_est_distinguee_d_un_mauvais_mot_de_passe() {
        for corrompue in ["", "pas une empreinte", "$argon2id$bidon"] {
            assert!(
                matches!(
                    verify("cheval-Correct-42!", corrompue),
                    Err(PasswordError::CorruptStoredHash(_))
                ),
                "{corrompue:?} aurait dû être signalée comme corrompue"
            );
        }
    }
}

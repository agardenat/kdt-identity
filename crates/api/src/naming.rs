//! Règles de nommage des identités émises par kdt-identity.
//!
//! Deux invariants tiennent toute la sécurité du projet :
//!
//! 1. aucune identité émise ne peut usurper `system:*` — approuver une CSR
//!    `kubernetes.io/kube-apiserver-client` permettrait sinon de forger `O=system:masters` ;
//! 2. toute identité émise porte le préfixe [`SUBJECT_PREFIX`], pour ne jamais entrer en
//!    collision avec un sujet RBAC déjà utilisé par Rancher (`u-*`), Entra (UPN/GUID) ou par
//!    l'un des groupes intégrés de Kubernetes.
//!
//! Le préfixe n'est jamais saisi : il est ajouté à l'émission. Un nom stocké qui contiendrait
//! déjà `kdt:` est refusé, ce qui rend le doublement impossible.

use std::fmt;

/// Préfixe porté par toute identité émise, utilisateur comme groupe.
pub const SUBJECT_PREFIX: &str = "kdt:";

/// Longueur maximale d'un nom stocké.
///
/// X.509 plafonne `CN` et `O` à 64 caractères (RFC 5280, `ub-common-name` /
/// `ub-organization-name`). Le préfixe en consomme 4.
pub const MAX_NAME_LEN: usize = 64 - SUBJECT_PREFIX.len();

/// Jeu de caractères admis, exprimé en expression régulière.
///
/// N'est pas utilisé par [`validate_name`], qui teste les caractères un à un : c'est la forme
/// destinée à la `ValidatingAdmissionPolicy`, qui valide en CEL côté apiserver. Les deux
/// barrières doivent décrire exactement le même langage, ce que verrouille le test
/// `la_regex_et_la_validation_decrivent_le_meme_langage`.
pub const NAME_PATTERN: &str = "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("nom vide")]
    Empty,
    #[error("nom trop long : {0} caractères, maximum {MAX_NAME_LEN} (CN/O sont plafonnés à 64 par la RFC 5280)")]
    TooLong(usize),
    #[error("caractère interdit {0:?} : seuls [a-z0-9], '-' et '.' sont acceptés")]
    InvalidChar(char),
    #[error("le nom doit commencer et finir par [a-z0-9]")]
    BadBoundary,
    #[error("préfixe réservé {0:?} : le nom stocké ne doit pas être préfixé, kdt-identity ajoute {SUBJECT_PREFIX:?} à l'émission")]
    ReservedPrefix(&'static str),
}

/// Sujet RBAC prêt à être placé dans un certificat ou un binding.
///
/// Ne peut être construit qu'en passant par [`Subject::user`] ou [`Subject::group`], donc
/// tout `Subject` existant est déjà validé et préfixé.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject(String);

impl Subject {
    /// Sujet d'un utilisateur, destiné au `CN` du certificat.
    pub fn user(name: &str) -> Result<Self, NameError> {
        validate_name(name)?;
        Ok(Self(format!("{SUBJECT_PREFIX}{name}")))
    }

    /// Sujet d'un groupe, destiné à un `O` du certificat.
    pub fn group(name: &str) -> Result<Self, NameError> {
        validate_name(name)?;
        Ok(Self(format!("{SUBJECT_PREFIX}{name}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Nom stocké, préfixe retiré.
    pub fn name(&self) -> &str {
        &self.0[SUBJECT_PREFIX.len()..]
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Valide un nom stocké dans `metadata.name` d'un `KdtUser` ou d'un `KdtGroup`.
///
/// Le jeu de caractères est celui d'un sous-domaine RFC 1123, ce qui exclut mécaniquement `:`
/// et donc toute forme de `system:...` ou de préfixe déjà appliqué. Les préfixes réservés sont
/// tout de même testés explicitement : la barrière ne doit pas dépendre d'un effet de bord du
/// jeu de caractères.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong(name.len()));
    }

    for reserved in ["system:", "kubernetes:", SUBJECT_PREFIX] {
        if name.len() >= reserved.len() && name[..reserved.len()].eq_ignore_ascii_case(reserved) {
            return Err(NameError::ReservedPrefix(match reserved {
                "system:" => "system:",
                "kubernetes:" => "kubernetes:",
                _ => SUBJECT_PREFIX,
            }));
        }
    }

    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '.'))
    {
        return Err(NameError::InvalidChar(c));
    }

    let first = name.chars().next().expect("non vide");
    let last = name.chars().next_back().expect("non vide");
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(NameError::BadBoundary);
    }

    Ok(())
}

/// Dernière barrière, à appeler juste avant de construire une CSR.
///
/// Rejoue les invariants sur la chaîne finale, indépendamment du chemin qui l'a produite —
/// admission, API, UI ou reconstruction depuis un objet existant. Un `Subject` valide la passe
/// toujours ; une chaîne fabriquée ailleurs, non.
pub fn assert_emittable(subject: &str) -> Result<(), NameError> {
    let rest = subject
        .strip_prefix(SUBJECT_PREFIX)
        .ok_or(NameError::ReservedPrefix(SUBJECT_PREFIX))?;
    validate_name(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepte_un_nom_courant() {
        assert!(validate_name("jean.dupont").is_ok());
        assert!(validate_name("data-team").is_ok());
        assert!(validate_name("a").is_ok());
        assert_eq!(Subject::user("alice").unwrap().as_str(), "kdt:alice");
        assert_eq!(Subject::group("data-team").unwrap().as_str(), "kdt:data-team");
    }

    #[test]
    fn refuse_toute_usurpation_de_system() {
        for name in ["system:masters", "system:anonymous", "SYSTEM:masters", "system:"] {
            assert_eq!(
                validate_name(name),
                Err(NameError::ReservedPrefix("system:")),
                "{name} aurait dû être refusé"
            );
        }
    }

    #[test]
    fn refuse_le_prefixe_deja_applique() {
        // Sans quoi l'émission produirait "kdt:kdt:alice".
        assert_eq!(
            validate_name("kdt:alice"),
            Err(NameError::ReservedPrefix(SUBJECT_PREFIX))
        );
        assert!(Subject::user("kdt:alice").is_err());
    }

    #[test]
    fn refuse_les_caracteres_hors_rfc1123() {
        assert!(matches!(validate_name("Alice"), Err(NameError::InvalidChar('A'))));
        assert!(matches!(validate_name("a b"), Err(NameError::InvalidChar(' '))));
        assert!(matches!(validate_name("a/b"), Err(NameError::InvalidChar('/'))));
        assert!(matches!(validate_name("a\nb"), Err(NameError::InvalidChar('\n'))));
        assert!(matches!(validate_name("a:b"), Err(NameError::InvalidChar(':'))));
    }

    #[test]
    fn refuse_les_bornes_non_alphanumeriques() {
        assert_eq!(validate_name("-alice"), Err(NameError::BadBoundary));
        assert_eq!(validate_name("alice-"), Err(NameError::BadBoundary));
        assert_eq!(validate_name(".alice"), Err(NameError::BadBoundary));
    }

    #[test]
    fn borne_la_longueur_sur_la_limite_x509() {
        let max = "a".repeat(MAX_NAME_LEN);
        assert!(validate_name(&max).is_ok());
        assert_eq!(Subject::user(&max).unwrap().as_str().len(), 64);

        let trop = "a".repeat(MAX_NAME_LEN + 1);
        assert_eq!(validate_name(&trop), Err(NameError::TooLong(MAX_NAME_LEN + 1)));
    }

    #[test]
    fn la_derniere_barriere_refuse_ce_qui_contourne_subject() {
        assert!(assert_emittable("kdt:alice").is_ok());
        // Chaînes fabriquées sans passer par `Subject` : toutes refusées.
        assert!(assert_emittable("system:masters").is_err());
        assert!(assert_emittable("alice").is_err());
        assert!(assert_emittable("kdt:system:masters").is_err());
        assert!(assert_emittable("kdt:kdt:alice").is_err());
        assert!(assert_emittable("").is_err());
    }

    /// Deux barrières valident les noms : [`validate_name`] à l'exécution, et la
    /// `ValidatingAdmissionPolicy` en CEL à l'admission, construite depuis [`NAME_PATTERN`].
    /// Si elles divergent, un nom peut être stocké puis refusé à l'émission — ou l'inverse.
    /// Ce test les confronte sur un corpus qui couvre les bords.
    #[test]
    fn la_regex_et_la_validation_decrivent_le_meme_langage() {
        let re = regex::Regex::new(NAME_PATTERN).unwrap();

        let corpus = [
            "a", "0", "alice", "jean.dupont", "data-team", "a-b.c-d", "x1", "1x",
            "-alice", "alice-", ".alice", "alice.", "a--b", "a..b", "",
            "Alice", "ALICE", "a b", "a_b", "a/b", "a:b", "a@b", "aé", "a\nb", "a.",
            "system:masters", "kdt:alice", "kubernetes:x", "systemx", "kdtalice",
        ];

        for nom in corpus {
            // Le préfixe réservé est une règle distincte du jeu de caractères : la regex ne le
            // couvre pas, et n'a pas à le couvrir puisque `:` en est déjà exclu.
            if matches!(validate_name(nom), Err(NameError::ReservedPrefix(_))) {
                assert!(!re.is_match(nom), "{nom:?} : la regex devrait déjà l'exclure");
                continue;
            }
            // Idem pour la longueur, portée par une règle CEL séparée.
            if matches!(validate_name(nom), Err(NameError::TooLong(_))) {
                continue;
            }
            assert_eq!(
                validate_name(nom).is_ok(),
                re.is_match(nom),
                "désaccord sur {nom:?} : validate_name={:?}, regex={}",
                validate_name(nom),
                re.is_match(nom)
            );
        }
    }

    #[test]
    fn le_sujet_sait_revenir_au_nom_stocke() {
        let s = Subject::user("jean.dupont").unwrap();
        assert_eq!(s.name(), "jean.dupont");
    }
}

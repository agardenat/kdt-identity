//! Construction du filtre de recherche.
//!
//! Un filtre LDAP se concatène, et ce qu'on y concatène vient de la page de connexion. Sans
//! échappement, saisir `*` comme identifiant rendrait la première entrée venue, et
//! `x)(objectClass=*` transformerait le filtre en un autre filtre. C'est le pendant exact de
//! l'injection SQL, avec ceci de particulier que l'annuaire ne rendra jamais d'erreur : il
//! répondra correctement à la mauvaise question.

use super::profile::LdapAttributes;

/// Filtre qui désigne la personne dont l'identifiant de connexion est `login`.
///
/// L'échappement est délégué à `ldap3::ldap_escape`, qui applique la RFC 4515 — `\`, `*`, `(`,
/// `)` et l'octet nul passent en `\XX`. Réécrire cette table ici la ferait diverger de celle
/// que la bibliothèque applique partout ailleurs.
///
/// Seule la saisie est échappée. Les noms d'attributs et la classe d'objet viennent de la
/// configuration du déploiement : les échapper laisserait croire qu'ils sont de même nature,
/// alors que les traiter en données produirait un filtre littéralement faux.
pub fn user_filter(attributes: &LdapAttributes, login: &str) -> String {
    format!(
        "(&(objectClass={})({}={}))",
        attributes.object_class,
        attributes.login,
        ldap3::ldap_escape(login)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::profile::LdapProfile;

    fn attributes() -> LdapAttributes {
        LdapProfile::ActiveDirectory.attributes()
    }

    #[test]
    fn le_filtre_cible_la_personne_demandee() {
        assert_eq!(
            user_filter(&attributes(), "alice"),
            "(&(objectClass=user)(sAMAccountName=alice))"
        );
    }

    /// Le test qui compte. Sans échappement, `*` rendrait la première entrée de l'annuaire et
    /// la personne se connecterait sous une identité qui n'est pas la sienne.
    #[test]
    fn une_saisie_ne_peut_pas_elargir_la_recherche() {
        let filtre = user_filter(&attributes(), "*");
        assert_eq!(filtre, "(&(objectClass=user)(sAMAccountName=\\2a))");
        assert!(!filtre.contains("=*)"), "{filtre}");
    }

    /// Ni refermer la parenthèse pour en ouvrir une autre : c'est la forme qui transforme le
    /// filtre en un filtre différent, celui que l'attaquant a écrit.
    #[test]
    fn une_saisie_ne_peut_pas_reecrire_le_filtre() {
        let filtre = user_filter(&attributes(), "x)(objectClass=*");

        // Trois parenthèses ouvrantes et trois fermantes : celles de `&`, de `objectClass` et
        // de l'attribut de connexion. Aucune de plus, donc aucune clause injectée.
        assert_eq!(filtre.matches('(').count(), 3, "{filtre}");
        assert_eq!(filtre.matches(')').count(), 3, "{filtre}");
    }

    /// L'antislash sert à échapper : le laisser passer tel quel permettrait de neutraliser
    /// l'échappement du caractère suivant.
    #[test]
    fn l_antislash_est_echappe_lui_aussi() {
        assert_eq!(
            user_filter(&attributes(), "a\\b"),
            "(&(objectClass=user)(sAMAccountName=a\\5cb))"
        );
    }
}

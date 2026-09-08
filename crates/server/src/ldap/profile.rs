//! Les deux annuaires que kdt-identity sait interroger, et ce qui les distingue.
//!
//! Un profil n'est qu'un jeu de valeurs par défaut : tout ce qu'il pose se surcharge une
//! variable à la fois. Il existe parce qu'un déploiement typique n'a aucune raison de connaître
//! le nom de l'attribut qui porte un identifiant de connexion — c'est une propriété du schéma,
//! pas une décision d'exploitation.

/// Noms d'attributs à lire sur l'entrée d'une personne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapAttributes {
    /// Attribut qui porte l'identifiant de connexion.
    pub login: String,
    /// Attribut qui porte l'adresse électronique. `KdtUserSpec::email` est requis, donc son
    /// absence empêche la création du compte.
    pub email: String,
    /// Attribut qui porte le nom affiché.
    pub display: String,
    /// Attribut multivalué qui porte les DN des groupes de la personne.
    pub member_of: String,
    /// Classe d'objet qui restreint la recherche aux personnes.
    pub object_class: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapProfile {
    ActiveDirectory,
    FreeIpa,
}

impl LdapProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ActiveDirectory => "activedirectory",
            Self::FreeIpa => "freeipa",
        }
    }

    /// Attributs par défaut du schéma.
    ///
    /// Les deux annuaires peuplent `memberOf` sur l'entrée de la personne — AD nativement,
    /// FreeIPA par le greffon du même nom, actif par défaut sur 389-ds. C'est ce qui permet de
    /// n'avoir qu'un seul chemin de lecture des groupes au lieu d'une recherche inverse par
    /// annuaire.
    pub fn attributes(&self) -> LdapAttributes {
        let (login, display, object_class) = match self {
            Self::ActiveDirectory => ("sAMAccountName", "displayName", "user"),
            Self::FreeIpa => ("uid", "cn", "person"),
        };

        LdapAttributes {
            login: login.to_string(),
            email: "mail".to_string(),
            display: display.to_string(),
            member_of: "memberOf".to_string(),
            object_class: object_class.to_string(),
        }
    }
}

impl std::fmt::Display for LdapProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LdapProfile {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "activedirectory" => Ok(Self::ActiveDirectory),
            "freeipa" => Ok(Self::FreeIpa),
            other => Err(format!(
                "profil {other:?} inconnu, attendu activedirectory ou freeipa"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Les deux annuaires ne nomment pas l'identifiant de connexion pareil. Confondre les deux
    /// ferait chercher un attribut qui n'existe pas, et l'annuaire répondrait « aucune entrée »
    /// — soit exactement ce que répond un mot de passe faux.
    #[test]
    fn chaque_profil_nomme_son_attribut_de_connexion() {
        assert_eq!(
            LdapProfile::ActiveDirectory.attributes().login,
            "sAMAccountName"
        );
        assert_eq!(LdapProfile::FreeIpa.attributes().login, "uid");
    }

    /// `memberOf` est le seul chemin de lecture des groupes, et il vaut pour les deux profils.
    /// Si l'un des deux en changeait, toute l'appartenance deviendrait vide en silence — la
    /// personne se connecterait sans le moindre droit.
    #[test]
    fn les_deux_profils_lisent_les_groupes_au_meme_endroit() {
        assert_eq!(
            LdapProfile::ActiveDirectory.attributes().member_of,
            LdapProfile::FreeIpa.attributes().member_of
        );
    }

    #[test]
    fn un_profil_se_lit_depuis_une_chaine() {
        assert_eq!(
            LdapProfile::from_str("freeipa"),
            Ok(LdapProfile::FreeIpa)
        );
        assert!(LdapProfile::from_str("ActiveDirectory").is_err());
        assert!(LdapProfile::from_str("openldap").is_err());
    }
}

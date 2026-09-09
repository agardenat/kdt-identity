//! Ce qui est commun à toute fédération d'identité, quelle qu'en soit la source.
//!
//! Un annuaire LDAP et un fournisseur OpenID Connect ne se ressemblent en rien sur la façon de
//! vérifier une identité — un bind d'un côté, une redirection de navigateur de l'autre. Mais ce
//! qu'ils produisent est identique : une personne, ses groupes, et une valeur qui l'identifie de
//! façon stable chez elle. Tout ce qui suit — création du `KdtUser`, report de l'appartenance,
//! désactivation d'un compte disparu — ne dépend que de cela, et vit donc ici plutôt que d'être
//! écrit deux fois.
//!
//! # L'épinglage, et pourquoi il n'est pas facultatif
//!
//! Le nom du compte est **dérivé** de l'identifiant de connexion, par une normalisation qui
//! n'est pas injective : `Jean_Dupont` et `jean-dupont` donnent le même `KdtUser`. Sans autre
//! garde-fou, la seconde personne à se connecter hériterait des droits de la première. D'où la
//! valeur épinglée à la création — le DN pour un annuaire, le sujet du jeton pour un
//! fournisseur — revérifiée à chaque connexion, et qui seule décide de l'identité.

pub mod mapping;
pub mod provision;

/// Ce qui reconnaît les personnes, du point de vue des comptes qu'on en tire.
///
/// Porté par un label sur le `KdtUser` et le `KdtGroup`, et non par un champ de spec : un label
/// se liste (`kubectl get kdtusers -l identity.kdt.sh/source=oidc`) là où un champ demanderait
/// un `jsonpath`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Ldap,
    Oidc,
}

impl Source {
    /// Valeur du label `identity.kdt.sh/source`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ldap => "ldap",
            Self::Oidc => "oidc",
        }
    }

    /// Annotation qui garde la valeur épinglée.
    ///
    /// Une par source, et non une seule partagée : un déploiement qui passe d'un annuaire à un
    /// fournisseur ne doit pas voir ses DN relus comme des sujets de jetons. Les comptes de
    /// l'ancienne source restent alors visiblement rattachés à elle, ce qui est exactement ce
    /// que l'administrateur doit savoir pour décider quoi en faire.
    pub fn pin_annotation(&self) -> &'static str {
        match self {
            Self::Ldap => "identity.kdt.sh/ldap-dn",
            Self::Oidc => "identity.kdt.sh/oidc-subject",
        }
    }

    /// Gestionnaire de champs des écritures faites au nom de cette source.
    pub fn field_manager(&self) -> &'static str {
        match self {
            Self::Ldap => "kdt-identity-ldap",
            Self::Oidc => "kdt-identity-oidc",
        }
    }

    /// Deux valeurs épinglées désignent-elles la même identité ?
    ///
    /// Un DN se compare après normalisation : l'annuaire ne le rend pas toujours tel qu'il a été
    /// écrit. Un sujet de jeton, lui, est une chaîne opaque que le fournisseur rend à
    /// l'identique — la moindre tolérance y ferait correspondre deux sujets distincts.
    pub fn same_pin(&self, a: &str, b: &str) -> bool {
        match self {
            Self::Ldap => mapping::normalize_dn(a) == mapping::normalize_dn(b),
            Self::Oidc => a == b,
        }
    }

    /// Description posée sur un groupe créé depuis cette source.
    pub fn group_description(&self) -> &'static str {
        match self {
            Self::Ldap => "Groupe alimenté depuis l'annuaire.",
            Self::Oidc => "Groupe alimenté depuis le fournisseur d'identité.",
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Ce que la source dit d'une personne, une fois traduit dans les termes du cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedUser {
    /// Valeur épinglée sur le `KdtUser` à sa création, et revérifiée ensuite : le DN pour un
    /// annuaire, le sujet du jeton pour un fournisseur.
    pub pin: String,
    /// Identifiant de connexion, tel que la source le porte — pas tel qu'il a été saisi.
    pub login: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// Ce dont la personne est membre, avant toute correspondance : des DN pour un annuaire,
    /// des valeurs de claim pour un fournisseur.
    pub member_of: Vec<String>,
}

/// Ce qui peut empêcher un compte fédéré d'aboutir, une fois l'identité établie.
///
/// Les refus d'identifiants n'y figurent pas : ils appartiennent au protocole qui a servi à la
/// vérifier, et chaque module garde les siens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// La source a répondu, mais ce qu'elle rend ne permet pas de construire un compte.
    #[error("{0}")]
    Unusable(String),
    /// La source n'a pas répondu, ou pas comme il faut.
    ///
    /// La distinction qui gouverne toute la relecture : une panne n'est pas une disparition. Les
    /// confondre désactiverait tous les comptes du cluster à la première coupure réseau, et la
    /// coupure survivrait très largement à sa propre résolution.
    #[error("source injoignable : {0}")]
    Unavailable(String),
    /// La source a répondu, mais le cluster n'a pas suivi.
    ///
    /// Séparé des deux autres parce que le diagnostic n'est pas le même : l'un se corrige chez le
    /// fournisseur, l'autre dans le cluster.
    #[error("cluster : {0}")]
    Cluster(String),
}

/// Ce qu'une source doit savoir faire pour être relue périodiquement.
///
/// Un annuaire et un fournisseur n'ont rien de commun dans la façon d'interroger — un `search` en
/// `Base` sur un DN, un appel HTTP sur un identifiant d'objet — mais la boucle qui les emploie,
/// elle, est la même, et surtout ses règles le sont. Les écrire deux fois, c'est n'en corriger
/// qu'une le jour où l'une se révèle fausse.
pub trait Federated: Send + Sync {
    fn source(&self) -> Source;

    /// Intervalle entre deux tours.
    fn interval(&self) -> std::time::Duration;

    fn mappings(&self) -> &mapping::GroupMappings;

    /// Relit l'appartenance d'une personne, par la valeur épinglée sur son compte.
    ///
    /// `Ok(None)` dit que la personne n'a plus d'accès — entrée supprimée, compte fermé — et
    /// **seulement** cela. Tout le reste est une erreur, jamais un `None`.
    fn lookup_groups(
        &self,
        pin: &str,
    ) -> impl std::future::Future<Output = Result<Option<Vec<String>>, Error>> + Send;
}

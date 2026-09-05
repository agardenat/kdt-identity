//! CRDs `KdtUser` et `KdtGroup`.
//!
//! Les kinds sont préfixés parce que Rancher expose déjà un kind `User`
//! (`management.cattle.io/v3`) : sans préfixe, `kubectl get user` deviendrait ambigu sur les
//! clusters gérés par Rancher. Même raison pour les shortNames, qui ne réutilisent jamais
//! `user` ni `group`.
//!
//! L'appartenance a une source de vérité unique : [`KdtGroupSpec::members`]. Le contrôleur en
//! dérive [`KdtUserStatus::member_of`], qui n'est donc qu'un index de lecture.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Groupe d'API de toutes les ressources kdt-identity.
pub const API_GROUP: &str = "identity.kdt.sh";
/// Version servie.
pub const API_VERSION: &str = "v1alpha1";
/// Type des `Secret` portant les credentials d'un utilisateur.
pub const CREDENTIAL_SECRET_TYPE: &str = "identity.kdt.sh/credential";

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "identity.kdt.sh",
    version = "v1alpha1",
    kind = "KdtUser",
    plural = "kdtusers",
    shortname = "kdtuser",
    status = "KdtUserStatus",
    printcolumn = r#"{"name":"Email","type":"string","jsonPath":".spec.email"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Groupes","type":"string","jsonPath":".status.memberOf"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct KdtUserSpec {
    /// Adresse à laquelle est envoyée l'invitation de première connexion.
    pub email: String,

    /// Nom affiché dans l'interface. Sans effet sur l'identité émise, qui dérive toujours de
    /// `metadata.name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Bloque immédiatement toute nouvelle émission de credential.
    ///
    /// N'invalide pas les certificats déjà émis : Kubernetes ne consulte aucune CRL. Pour
    /// couper l'accès sans attendre l'expiration, retirer les bindings du groupe concerné.
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KdtUserStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<UserPhase>,

    /// Groupes dont l'utilisateur est membre, dérivés des `KdtGroup`. Lecture seule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_of: Vec<String>,

    /// Nom du `Secret` portant hash de mot de passe, secret TOTP et invitation en cours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_secret_ref: Option<String>,

    /// Horodatage RFC 3339 de la dernière connexion réussie au portail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login: Option<String>,

    /// Horodatage RFC 3339 de la dernière émission de certificat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_issued_at: Option<String>,

    /// Nombre total de certificats émis, pour l'audit.
    #[serde(default)]
    pub issued_count: u64,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum UserPhase {
    /// Invitation envoyée, mot de passe pas encore défini.
    Pending,
    /// Mot de passe et TOTP en place, émission possible.
    Active,
    /// `spec.disabled` est vrai.
    Disabled,
    /// Verrouillé temporairement après trop d'échecs d'authentification.
    Locked,
}

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "identity.kdt.sh",
    version = "v1alpha1",
    kind = "KdtGroup",
    plural = "kdtgroups",
    shortname = "kdtgroup",
    status = "KdtGroupStatus",
    printcolumn = r#"{"name":"Membres","type":"integer","jsonPath":".status.memberCount"}"#,
    printcolumn = r#"{"name":"Sujet","type":"string","jsonPath":".status.subject"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct KdtGroupSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Noms des `KdtUser` membres. Source de vérité de l'appartenance.
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KdtGroupStatus {
    /// Sujet RBAC à référencer dans les bindings, préfixe compris. Affiché tel quel pour que
    /// personne n'ait à deviner qu'il faut écrire `kdt:<nom>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Membres effectivement résolus vers un `KdtUser` existant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_members: Vec<String>,

    /// Membres listés dans la spec mais sans `KdtUser` correspondant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_members: Vec<String>,

    #[serde(default)]
    pub member_count: u32,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Condition au format `metav1.Condition`, redéclarée ici pour éviter d'imposer la feature
/// `schemars` de k8s-openapi à tous les consommateurs du crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    pub type_: String,
    pub status: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub last_transition_time: String,
}

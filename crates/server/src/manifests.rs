//! Génération des manifestes d'installation.
//!
//! Les CRDs sont dérivées des types Rust et la `ValidatingAdmissionPolicy` des constantes de
//! [`kdt_identity_api::naming`]. Rien n'est recopié à la main : un YAML figé finirait par
//! décrire un schéma que le code ne sert plus, ou par valider des noms que
//! [`kdt_identity_api::validate_name`] refuse.

use kdt_identity_api::naming::{MAX_NAME_LEN, NAME_PATTERN, SUBJECT_PREFIX};
use kdt_identity_api::{KdtGroup, KdtUser, API_GROUP, API_VERSION};
use kube::CustomResourceExt;

/// Nom de la politique d'admission et de son binding.
pub const POLICY_NAME: &str = "kdt-identity-names";

/// Tous les manifestes d'installation, concaténés en un flux YAML multi-documents.
pub fn all() -> Result<String, serde_yaml::Error> {
    let documents = [
        serde_yaml::to_string(&KdtUser::crd())?,
        serde_yaml::to_string(&KdtGroup::crd())?,
        validating_admission_policy()?,
        validating_admission_policy_binding()?,
    ];
    Ok(documents.join("---\n"))
}

/// Politique d'admission rejouant, côté apiserver, les règles de nommage du code.
///
/// C'est la barrière qui protège les noms **stockés**. Elle ne remplace pas la vérification
/// faite à l'émission : une CRD peut être créée avant l'installation de la politique, ou la
/// politique être retirée. Les deux existent pour ne pas dépendre l'une de l'autre.
pub fn validating_admission_policy() -> Result<String, serde_yaml::Error> {
    // `system:` et `kdt:` contiennent `:`, que le jeu de caractères exclut déjà. La règle est
    // écrite quand même : elle dit l'intention, et survivrait à un élargissement du jeu.
    let reserved = ["system:", "kubernetes:", SUBJECT_PREFIX];
    let no_reserved_prefix = |expr: &str| {
        reserved
            .iter()
            .map(|p| format!("!{expr}.lowerAscii().startsWith('{p}')"))
            .collect::<Vec<_>>()
            .join(" && ")
    };

    let policy = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": { "name": POLICY_NAME },
        "spec": {
            // Un nom mal formé qui passerait faute d'évaluation vaut moins qu'un refus : on
            // préfère bloquer la création plutôt que laisser entrer une identité douteuse.
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [{
                    "apiGroups": [API_GROUP],
                    "apiVersions": [API_VERSION],
                    "operations": ["CREATE", "UPDATE"],
                    "resources": ["kdtusers", "kdtgroups"],
                }]
            },
            "validations": [
                {
                    "expression": format!("object.metadata.name.size() <= {MAX_NAME_LEN}"),
                    "reason": "Invalid",
                    "message": format!(
                        "le nom dépasse {MAX_NAME_LEN} caractères : préfixé de '{SUBJECT_PREFIX}', \
                         il ne tiendrait pas dans un CN/O X.509 (plafonné à 64 par la RFC 5280)"
                    ),
                },
                {
                    "expression": format!("object.metadata.name.matches('{NAME_PATTERN}')"),
                    "reason": "Invalid",
                    "message": "le nom doit être composé de [a-z0-9], '-' et '.', et commencer \
                                et finir par [a-z0-9]",
                },
                {
                    "expression": no_reserved_prefix("object.metadata.name"),
                    "reason": "Invalid",
                    "message": format!(
                        "préfixe réservé : kdt-identity ajoute lui-même '{SUBJECT_PREFIX}' à \
                         l'émission, et n'émettra jamais d'identité 'system:'"
                    ),
                },
                {
                    // Les membres d'un groupe désignent des KdtUser : ils suivent les mêmes
                    // règles. `has()` neutralise la règle sur les KdtUser, qui n'ont pas ce
                    // champ.
                    "expression": format!(
                        "!has(object.spec) || !has(object.spec.members) || \
                         object.spec.members.all(m, m.size() <= {MAX_NAME_LEN} && \
                         m.matches('{NAME_PATTERN}'))"
                    ),
                    "reason": "Invalid",
                    "message": "un membre de groupe doit être un nom de KdtUser valide",
                },
            ],
        }
    });
    serde_yaml::to_string(&policy)
}

pub fn validating_admission_policy_binding() -> Result<String, serde_yaml::Error> {
    let binding = serde_json::json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": { "name": POLICY_NAME },
        "spec": {
            "policyName": POLICY_NAME,
            "validationActions": ["Deny"],
        }
    });
    serde_yaml::to_string(&binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn documents() -> Vec<serde_yaml::Value> {
        serde_yaml::Deserializer::from_str(&all().unwrap())
            .map(|d| serde_yaml::Value::deserialize(d).unwrap())
            .collect()
    }
    use serde::Deserialize;

    #[test]
    fn produit_les_quatre_manifestes_attendus() {
        let kinds: Vec<String> = documents()
            .iter()
            .map(|d| d["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            kinds,
            vec![
                "CustomResourceDefinition",
                "CustomResourceDefinition",
                "ValidatingAdmissionPolicy",
                "ValidatingAdmissionPolicyBinding",
            ]
        );
    }

    /// Les shortNames ne doivent jamais entrer en collision avec ceux d'un autre gestionnaire
    /// d'identités déjà installé — Rancher expose `user` sur `management.cattle.io`.
    #[test]
    fn n_occupe_aucun_nom_court_generique() {
        for doc in documents().iter().take(2) {
            let names = &doc["spec"]["names"];
            let short: Vec<&str> = names["shortNames"]
                .as_sequence()
                .map(|s| s.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            for interdit in ["user", "users", "group", "groups", "u", "g"] {
                assert!(
                    !short.contains(&interdit),
                    "shortName {interdit:?} revendiqué par {:?}",
                    names["kind"]
                );
            }
            assert!(names["kind"].as_str().unwrap().starts_with("Kdt"));
        }
    }

    #[test]
    fn les_crds_sont_cluster_scoped() {
        for doc in documents().iter().take(2) {
            assert_eq!(doc["spec"]["scope"], "Cluster");
        }
    }

    /// La politique doit refuser, pas seulement signaler.
    #[test]
    fn la_politique_denie_et_echoue_en_securite() {
        let docs = documents();
        assert_eq!(docs[2]["spec"]["failurePolicy"], "Fail");
        assert_eq!(docs[3]["spec"]["validationActions"][0], "Deny");
        assert_eq!(docs[3]["spec"]["policyName"], docs[2]["metadata"]["name"]);
    }

    /// Le seuil de longueur vient de la constante Rust : si `MAX_NAME_LEN` change, la
    /// politique doit changer avec lui.
    #[test]
    fn les_regles_derivent_des_constantes_du_code() {
        let policy = validating_admission_policy().unwrap();
        assert!(policy.contains(&format!("<= {MAX_NAME_LEN}")), "{policy}");
        assert!(policy.contains(NAME_PATTERN), "{policy}");
        for reserve in ["system:", "kubernetes:", SUBJECT_PREFIX] {
            assert!(policy.contains(reserve), "règle manquante pour {reserve:?}");
        }
    }
}

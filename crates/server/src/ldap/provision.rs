//! Création des comptes et report de l'appartenance depuis l'annuaire.
//!
//! # Ce qui distingue un compte fédéré
//!
//! Un label, `identity.kdt.sh/source: ldap`, et une annotation qui garde son DN. Ni l'un ni
//! l'autre n'est dans la spec, et c'est délibéré : les CRD n'ont pas à changer pour ça, et un
//! label se liste (`kubectl get kdtusers -l identity.kdt.sh/source=ldap`) là où un champ de spec
//! demanderait un `jsonpath`.
//!
//! # L'appartenance reste dans la spec
//!
//! La synchronisation écrit `KdtGroup.spec.members`, elle ne double pas la source de vérité.
//! L'annuaire alimente la spec, la spec reste ce qui décide — donc `logic::member_of` et
//! `subjects()` continuent de lire au même endroit, sans rien savoir de LDAP.

use super::{DirectoryUser, LdapError};
use kdt_identity_api::{validate_name, KdtGroup, KdtGroupSpec, KdtUser, KdtUserSpec};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use std::collections::BTreeMap;
use tracing::{info, warn};

/// Label qui marque l'origine d'un compte ou d'un groupe.
pub const SOURCE_LABEL: &str = "identity.kdt.sh/source";
/// Valeur du label pour ce qui vient d'un annuaire.
pub const SOURCE_LDAP: &str = "ldap";
/// Annotation qui garde le DN de l'entrée d'origine.
pub const DN_ANNOTATION: &str = "identity.kdt.sh/ldap-dn";

/// Nom de gestionnaire des écritures d'appartenance.
const FIELD_MANAGER: &str = "kdt-identity-ldap";

/// Nombre de reprises sur conflit d'écriture.
///
/// Même valeur et même raison que dans `sessions::store` : deux connexions simultanées peuvent
/// vouloir modifier le même groupe, et la seconde doit relire plutôt qu'écraser.
const MAX_ATTEMPTS: usize = 3;

/// Vrai si ce compte vient d'un annuaire.
pub fn is_federated(user: &KdtUser) -> bool {
    user.metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(SOURCE_LABEL))
        .map(|source| source == SOURCE_LDAP)
        .unwrap_or(false)
}

/// DN épinglé sur un compte à sa création.
pub fn recorded_dn(user: &KdtUser) -> Option<&str> {
    user.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(DN_ANNOTATION))
        .map(String::as_str)
}

/// Nom de `KdtUser` correspondant à un identifiant de connexion.
///
/// La normalisation est nécessaire — un `sAMAccountName` porte des majuscules et des soulignés,
/// qu'un nom de ressource Kubernetes n'accepte pas — et elle est **ambiguë** : `Jean_Dupont` et
/// `jean-dupont` aboutissent au même nom. C'est exactement pour ça que le DN est épinglé et
/// revérifié : la normalisation ne garantit pas l'unicité, l'épinglage si.
pub fn normalize_login(login: &str) -> Result<String, String> {
    let normalise: String = login
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c == '_' || c == ' ' { '-' } else { c })
        .collect();

    validate_name(&normalise)
        .map_err(|e| format!("l'identifiant {login:?} ne donne pas un nom de compte valide : {e}"))?;

    Ok(normalise)
}

/// Garantit qu'un `KdtUser` existe pour cette personne, et le rend.
///
/// Le compte est créé s'il manque. S'il existe, son DN est **revérifié** : c'est la barrière qui
/// empêche deux identités distinctes de l'annuaire, normalisées vers le même nom, de partager un
/// compte — et donc à la seconde d'hériter des droits de la première.
pub async fn ensure_user(
    users: &Api<KdtUser>,
    directory_user: &DirectoryUser,
) -> Result<KdtUser, LdapError> {
    let name = normalize_login(&directory_user.login).map_err(LdapError::Unusable)?;

    let existant = users
        .get_opt(&name)
        .await
        .map_err(|e| LdapError::Cluster(format!("lecture du compte {name} : {e}")))?;

    if let Some(user) = existant {
        return verify_existing(user, &name, directory_user);
    }

    // `KdtUserSpec::email` est requis par le schéma : sans adresse, l'objet serait refusé par
    // l'apiserver. Le dire ici nomme l'attribut manquant, plutôt que de laisser remonter une
    // erreur de validation qui parle de `spec.email`.
    let email = directory_user.email.clone().ok_or_else(|| {
        LdapError::Unusable(format!(
            "l'entrée {} ne porte pas d'adresse électronique, requise pour créer le compte",
            directory_user.dn
        ))
    })?;

    let user = KdtUser {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            labels: Some(BTreeMap::from([(
                SOURCE_LABEL.to_string(),
                SOURCE_LDAP.to_string(),
            )])),
            annotations: Some(BTreeMap::from([(
                DN_ANNOTATION.to_string(),
                directory_user.dn.clone(),
            )])),
            ..Default::default()
        },
        spec: KdtUserSpec {
            email,
            display_name: directory_user.display_name.clone(),
            disabled: false,
        },
        status: None,
    };

    match users.create(&PostParams::default(), &user).await {
        Ok(cree) => {
            info!(compte = %name, dn = %directory_user.dn, "compte créé depuis l'annuaire");
            Ok(cree)
        }
        // Deux connexions simultanées de la même personne : l'autre a gagné, et son objet est
        // le bon. Le relire vaut mieux que refuser une connexion légitime.
        Err(kube::Error::Api(e)) if e.code == 409 => {
            let user = users
                .get(&name)
                .await
                .map_err(|e| LdapError::Cluster(format!("relecture du compte {name} : {e}")))?;
            verify_existing(user, &name, directory_user)
        }
        Err(e) => Err(LdapError::Cluster(format!(
            "création du compte {name} : {e}"
        ))),
    }
}

/// Barrière d'identité sur un compte qui existe déjà.
fn verify_existing(
    user: KdtUser,
    name: &str,
    directory_user: &DirectoryUser,
) -> Result<KdtUser, LdapError> {
    match recorded_dn(&user) {
        // Le cas nominal : le même DN qu'à la création.
        Some(dn) if super::mapping::normalize_dn(dn) == super::mapping::normalize_dn(&directory_user.dn) => {
            Ok(user)
        }
        // Un DN différent sous le même nom : deux personnes de l'annuaire se disputent un
        // compte. Refusé, jamais arbitré — laisser passer donnerait à la seconde les droits de
        // la première.
        Some(dn) => {
            warn!(
                compte = %name,
                dn_epingle = %dn,
                dn_presente = %directory_user.dn,
                "le compte est épinglé sur un autre DN, connexion refusée"
            );
            Err(LdapError::Unusable(format!(
                "le compte {name} est déjà rattaché à une autre entrée de l'annuaire"
            )))
        }
        // Un compte local qui porte ce nom. On ne le fédère pas d'office : ce serait prendre
        // possession d'un compte que quelqu'un a créé à la main, avec son mot de passe et son
        // TOTP.
        None => {
            warn!(
                compte = %name,
                dn = %directory_user.dn,
                "un compte local porte déjà ce nom, connexion refusée"
            );
            Err(LdapError::Unusable(format!(
                "un compte local nommé {name} existe déjà"
            )))
        }
    }
}

/// Aligne l'appartenance de cette personne sur ce que dit l'annuaire.
///
/// `wanted` est ce à quoi elle a droit, `managed` l'ensemble des groupes que la table de
/// correspondance gouverne. Le second est nécessaire : sans lui on saurait ajouter, jamais
/// retirer, et un départ d'équipe ne se traduirait par rien.
pub async fn sync_groups(
    groups: &Api<KdtGroup>,
    user: &str,
    wanted: &[String],
    managed: &[String],
) -> Result<(), LdapError> {
    for group in managed {
        let member = wanted.iter().any(|g| g == group);
        sync_one(groups, group, user, member).await?;
    }
    Ok(())
}

async fn sync_one(
    groups: &Api<KdtGroup>,
    group: &str,
    user: &str,
    member: bool,
) -> Result<(), LdapError> {
    for _ in 0..MAX_ATTEMPTS {
        let existant = groups
            .get_opt(group)
            .await
            .map_err(|e| LdapError::Cluster(format!("lecture du groupe {group} : {e}")))?;

        let Some(mut objet) = existant else {
            // Le groupe est déclaré dans la table mais n'existe pas encore. Le créer vide quand
            // la personne n'en est pas membre serait tout aussi correct, mais inutile : rien ne
            // le référencerait.
            if !member {
                return Ok(());
            }
            match groups
                .create(&PostParams::default(), &federated_group(group, user))
                .await
            {
                Ok(_) => {
                    info!(groupe = %group, "groupe créé depuis l'annuaire");
                    return Ok(());
                }
                // Créé entre-temps par une autre connexion : on repasse par la lecture.
                Err(kube::Error::Api(e)) if e.code == 409 => continue,
                Err(e) => {
                    return Err(LdapError::Cluster(format!(
                        "création du groupe {group} : {e}"
                    )))
                }
            }
        };

        // Un groupe qui n'est pas marqué comme venant de l'annuaire est géré à la main. Y
        // écrire écraserait le travail d'un administrateur, et le silence serait total.
        if !group_is_federated(&objet) {
            warn!(
                groupe = %group,
                "groupe déclaré dans la table mais non fédéré, appartenance laissée intacte"
            );
            return Ok(());
        }

        let Some(members) = members_after(&objet.spec.members, user, member) else {
            return Ok(());
        };
        objet.spec.members = members;

        // `resourceVersion` est porté par l'objet relu : un `replace` conditionné dessus échoue
        // en 409 si quelqu'un a écrit entre-temps, ce qui est exactement le comportement
        // voulu.
        match groups.replace(group, &PostParams::default(), &objet).await {
            Ok(_) => return Ok(()),
            Err(kube::Error::Api(e)) if e.code == 409 => continue,
            Err(e) => {
                return Err(LdapError::Cluster(format!(
                    "mise à jour du groupe {group} : {e}"
                )))
            }
        }
    }

    Err(LdapError::Cluster(format!(
        "groupe {group} modifié sans relâche par ailleurs, abandon après {MAX_ATTEMPTS} essais"
    )))
}

/// Liste des membres après ajout ou retrait, ou `None` s'il n'y a rien à écrire.
///
/// Rendre `None` plutôt qu'une liste identique n'est pas une optimisation : chaque écriture
/// inutile est un `resourceVersion` de plus, donc un conflit de plus pour les connexions
/// simultanées, et une réconciliation de plus pour le contrôleur.
pub fn members_after(current: &[String], user: &str, member: bool) -> Option<Vec<String>> {
    let present = current.iter().any(|m| m == user);
    if present == member {
        return None;
    }

    let mut members: Vec<String> = current.iter().filter(|m| *m != user).cloned().collect();
    if member {
        members.push(user.to_string());
        members.sort();
    }
    Some(members)
}

fn group_is_federated(group: &KdtGroup) -> bool {
    group
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(SOURCE_LABEL))
        .map(|source| source == SOURCE_LDAP)
        .unwrap_or(false)
}

fn federated_group(name: &str, user: &str) -> KdtGroup {
    KdtGroup {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(BTreeMap::from([(
                SOURCE_LABEL.to_string(),
                SOURCE_LDAP.to_string(),
            )])),
            ..Default::default()
        },
        spec: KdtGroupSpec {
            description: Some("Groupe alimenté depuis l'annuaire.".to_string()),
            members: vec![user.to_string()],
        },
        status: None,
    }
}

/// Désactive un compte dont l'entrée a disparu de l'annuaire.
///
/// Désactivé, jamais supprimé : un compte effacé emporterait ses `Secret` par cascade, et une
/// panne de lecture de l'annuaire prise pour une disparition ferait perdre des comptes. La
/// désactivation, elle, se défait — et le contrôleur ferme déjà les sessions qu'elle laisse
/// ouvertes.
pub async fn disable(users: &Api<KdtUser>, name: &str) -> Result<(), LdapError> {
    let patch = serde_json::json!({ "spec": { "disabled": true } });

    users
        .patch(name, &PatchParams::apply(FIELD_MANAGER).force(), &Patch::Merge(&patch))
        .await
        .map_err(|e| LdapError::Cluster(format!("désactivation du compte {name} : {e}")))?;

    info!(compte = %name, "compte désactivé, entrée absente de l'annuaire");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_with(labels: &[(&str, &str)], annotations: &[(&str, &str)]) -> KdtUser {
        KdtUser {
            metadata: ObjectMeta {
                name: Some("alice".to_string()),
                labels: Some(
                    labels
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                annotations: Some(
                    annotations
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                ..Default::default()
            },
            spec: KdtUserSpec {
                email: "alice@example.com".to_string(),
                display_name: None,
                disabled: false,
            },
            status: None,
        }
    }

    fn directory_user(dn: &str) -> DirectoryUser {
        DirectoryUser {
            dn: dn.to_string(),
            login: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: None,
            member_of: vec![],
        }
    }

    #[test]
    fn un_identifiant_devient_un_nom_de_ressource() {
        assert_eq!(normalize_login("Alice").unwrap(), "alice");
        assert_eq!(normalize_login("Jean_Dupont").unwrap(), "jean-dupont");
        assert_eq!(normalize_login("  bob  ").unwrap(), "bob");
    }

    /// Un compte de service Active Directory finit par `$`, et un DN complet porte des `=` et
    /// des virgules. Aucun des deux ne donne un nom de ressource : mieux vaut refuser que
    /// fabriquer un nom approchant.
    #[test]
    fn un_identifiant_intraduisible_est_refuse() {
        for login in ["DC01$", "cn=alice,dc=x", "alice@example.com", "", "-alice"] {
            assert!(normalize_login(login).is_err(), "{login:?} accepté à tort");
        }
    }

    /// Le test qui justifie tout l'épinglage. Deux identités distinctes de l'annuaire donnent
    /// le même nom kdt : sans vérification du DN, la seconde se connecterait sur le compte de
    /// la première et hériterait de ses droits.
    #[test]
    fn deux_identifiants_peuvent_donner_le_meme_nom() {
        assert_eq!(
            normalize_login("Jean_Dupont").unwrap(),
            normalize_login("jean-dupont").unwrap()
        );
    }

    /// Et voici la barrière qui rattrape cette ambiguïté.
    #[test]
    fn un_compte_epingle_sur_un_autre_dn_refuse_la_connexion() {
        let user = user_with(
            &[(SOURCE_LABEL, SOURCE_LDAP)],
            &[(DN_ANNOTATION, "cn=jean dupont,ou=a,dc=x")],
        );

        assert!(verify_existing(user.clone(), "jean-dupont", &directory_user("cn=jean-dupont,ou=b,dc=x")).is_err());

        // Le même DN à la casse et aux espaces près reste le même DN.
        assert!(verify_existing(
            user,
            "jean-dupont",
            &directory_user("CN=Jean Dupont, OU=A, DC=X")
        )
        .is_ok());
    }

    /// Un compte créé à la main, avec son mot de passe et son TOTP, ne se fait pas absorber par
    /// l'annuaire parce qu'il porte le même nom.
    #[test]
    fn un_compte_local_n_est_pas_repris_par_l_annuaire() {
        let local = user_with(&[], &[]);
        assert!(!is_federated(&local));
        assert!(verify_existing(local, "alice", &directory_user("cn=alice,dc=x")).is_err());
    }

    #[test]
    fn l_appartenance_ne_s_ecrit_que_si_elle_change() {
        let membres = vec!["alice".to_string(), "bob".to_string()];

        assert_eq!(members_after(&membres, "alice", true), None);
        assert_eq!(members_after(&membres, "carol", false), None);

        assert_eq!(
            members_after(&membres, "alice", false),
            Some(vec!["bob".to_string()])
        );
        assert_eq!(
            members_after(&membres, "carol", true),
            Some(vec![
                "alice".to_string(),
                "bob".to_string(),
                "carol".to_string()
            ])
        );
    }

    /// Le retrait est ce qui traduit un départ d'équipe. Sans lui, l'appartenance ne ferait que
    /// croître et personne ne perdrait jamais de droits.
    #[test]
    fn un_retrait_de_groupe_se_traduit_par_un_retrait_de_membre() {
        let membres = vec!["alice".to_string()];
        assert_eq!(members_after(&membres, "alice", false), Some(vec![]));
    }
}

//! Création des comptes et report de l'appartenance depuis une source fédérée.
//!
//! # Ce qui distingue un compte fédéré
//!
//! Un label, `identity.kdt.sh/source`, et une annotation qui garde la valeur sur laquelle il est
//! épinglé. Ni l'un ni l'autre n'est dans la spec, et c'est délibéré : les CRD n'ont pas à
//! changer pour ça, et un label se liste (`kubectl get kdtusers -l
//! identity.kdt.sh/source=ldap`) là où un champ de spec demanderait un `jsonpath`.
//!
//! # L'appartenance reste dans la spec
//!
//! La synchronisation écrit `KdtGroup.spec.members`, elle ne double pas la source de vérité.
//! La source alimente la spec, la spec reste ce qui décide — donc `logic::member_of` et
//! `subjects()` continuent de lire au même endroit, sans rien savoir de la fédération.

use super::{Error, FederatedUser, Source};
use kdt_identity_api::{validate_name, KdtGroup, KdtGroupSpec, KdtUser, KdtUserSpec};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use std::collections::BTreeMap;
use tracing::{info, warn};

/// Label qui marque l'origine d'un compte ou d'un groupe.
pub const SOURCE_LABEL: &str = "identity.kdt.sh/source";

/// Nombre de reprises sur conflit d'écriture.
///
/// Même valeur et même raison que dans `sessions::store` : deux connexions simultanées peuvent
/// vouloir modifier le même groupe, et la seconde doit relire plutôt qu'écraser.
const MAX_ATTEMPTS: usize = 3;

/// Vrai si ce compte vient d'une source fédérée, quelle qu'elle soit.
///
/// La question posée par le contrôleur est « ce compte est-il gouverné ailleurs ? », pas « par
/// quelle source ». Un compte laissé par un ancien mode compte donc encore comme fédéré, ce qui
/// est la réponse utile : il n'a ni mot de passe ni TOTP à lui.
pub fn is_federated(user: &KdtUser) -> bool {
    source_of(user).is_some()
}

/// Source qui gouverne ce compte, si elle est connue.
pub fn source_of(user: &KdtUser) -> Option<Source> {
    match user
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(SOURCE_LABEL))
        .map(String::as_str)
    {
        Some("ldap") => Some(Source::Ldap),
        Some("oidc") => Some(Source::Oidc),
        _ => None,
    }
}

/// Valeur épinglée sur un compte à sa création : DN pour un annuaire, sujet pour un
/// fournisseur.
pub fn recorded_pin(user: &KdtUser, source: Source) -> Option<&str> {
    user.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(source.pin_annotation()))
        .map(String::as_str)
}

/// Nom de `KdtUser` correspondant à un identifiant de connexion.
///
/// La normalisation est nécessaire — un `sAMAccountName` comme un `preferred_username` portent
/// des majuscules, des soulignés et parfois un `@`, qu'un nom de ressource Kubernetes n'accepte
/// pas — et elle est **ambiguë** : `Jean_Dupont` et `jean-dupont` aboutissent au même nom. C'est
/// exactement pour ça que la valeur d'origine est épinglée et revérifiée : la normalisation ne
/// garantit pas l'unicité, l'épinglage si.
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
/// Le compte est créé s'il manque. S'il existe, sa valeur épinglée est **revérifiée** : c'est la
/// barrière qui empêche deux identités distinctes de la source, normalisées vers le même nom, de
/// partager un compte — et donc à la seconde d'hériter des droits de la première.
pub async fn ensure_user(
    users: &Api<KdtUser>,
    federated: &FederatedUser,
    source: Source,
) -> Result<KdtUser, Error> {
    let name = normalize_login(&federated.login).map_err(Error::Unusable)?;

    let existant = users
        .get_opt(&name)
        .await
        .map_err(|e| Error::Cluster(format!("lecture du compte {name} : {e}")))?;

    if let Some(user) = existant {
        return verify_existing(user, &name, federated, source);
    }

    // `KdtUserSpec::email` est requis par le schéma : sans adresse, l'objet serait refusé par
    // l'apiserver. Le dire ici nomme l'attribut manquant, plutôt que de laisser remonter une
    // erreur de validation qui parle de `spec.email`.
    let email = federated.email.clone().ok_or_else(|| {
        Error::Unusable(format!(
            "l'identité {} ne porte pas d'adresse électronique, requise pour créer le compte",
            federated.pin
        ))
    })?;

    let user = KdtUser {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            labels: Some(BTreeMap::from([(
                SOURCE_LABEL.to_string(),
                source.label().to_string(),
            )])),
            annotations: Some(BTreeMap::from([(
                source.pin_annotation().to_string(),
                federated.pin.clone(),
            )])),
            ..Default::default()
        },
        spec: KdtUserSpec {
            email,
            display_name: federated.display_name.clone(),
            disabled: false,
        },
        status: None,
    };

    match users.create(&PostParams::default(), &user).await {
        Ok(cree) => {
            info!(compte = %name, source = %source, epingle = %federated.pin, "compte créé depuis la fédération");
            Ok(cree)
        }
        // Deux connexions simultanées de la même personne : l'autre a gagné, et son objet est
        // le bon. Le relire vaut mieux que refuser une connexion légitime.
        Err(kube::Error::Api(e)) if e.code == 409 => {
            let user = users
                .get(&name)
                .await
                .map_err(|e| Error::Cluster(format!("relecture du compte {name} : {e}")))?;
            verify_existing(user, &name, federated, source)
        }
        Err(e) => Err(Error::Cluster(format!("création du compte {name} : {e}"))),
    }
}

/// Barrière d'identité sur un compte qui existe déjà.
fn verify_existing(
    user: KdtUser,
    name: &str,
    federated: &FederatedUser,
    source: Source,
) -> Result<KdtUser, Error> {
    match recorded_pin(&user, source) {
        // Le cas nominal : la même valeur épinglée qu'à la création.
        Some(pin) if source.same_pin(pin, &federated.pin) => Ok(user),
        // Une valeur différente sous le même nom : deux personnes de la source se disputent un
        // compte. Refusé, jamais arbitré — laisser passer donnerait à la seconde les droits de
        // la première.
        Some(pin) => {
            warn!(
                compte = %name,
                epingle = %pin,
                presente = %federated.pin,
                "le compte est épinglé sur une autre identité, connexion refusée"
            );
            Err(Error::Unusable(format!(
                "le compte {name} est déjà rattaché à une autre identité"
            )))
        }
        // Un compte local — ou venu d'une autre source — porte ce nom. On ne le reprend pas
        // d'office : ce serait prendre possession d'un compte que quelqu'un a créé à la main,
        // avec son mot de passe et son TOTP, ou qu'une autre fédération gouverne.
        None => {
            warn!(
                compte = %name,
                epingle_par = ?source_of(&user).map(|s| s.label()),
                presente = %federated.pin,
                "un compte de même nom existe déjà sans être épinglé sur cette source, connexion refusée"
            );
            Err(Error::Unusable(format!(
                "un compte nommé {name} existe déjà et n'est pas gouverné par cette source"
            )))
        }
    }
}

/// Aligne l'appartenance de cette personne sur ce que dit la source.
///
/// `wanted` est ce à quoi elle a droit, `managed` l'ensemble des groupes que la table de
/// correspondance gouverne. Le second est nécessaire : sans lui on saurait ajouter, jamais
/// retirer, et un départ d'équipe ne se traduirait par rien.
pub async fn sync_groups(
    groups: &Api<KdtGroup>,
    user: &str,
    wanted: &[String],
    managed: &[String],
    source: Source,
) -> Result<(), Error> {
    for group in managed {
        let member = wanted.iter().any(|g| g == group);
        sync_one(groups, group, user, member, source).await?;
    }
    Ok(())
}

async fn sync_one(
    groups: &Api<KdtGroup>,
    group: &str,
    user: &str,
    member: bool,
    source: Source,
) -> Result<(), Error> {
    for _ in 0..MAX_ATTEMPTS {
        let existant = groups
            .get_opt(group)
            .await
            .map_err(|e| Error::Cluster(format!("lecture du groupe {group} : {e}")))?;

        let Some(mut objet) = existant else {
            // Le groupe est déclaré dans la table mais n'existe pas encore. Le créer vide quand
            // la personne n'en est pas membre serait tout aussi correct, mais inutile : rien ne
            // le référencerait.
            if !member {
                return Ok(());
            }
            match groups
                .create(&PostParams::default(), &federated_group(group, user, source))
                .await
            {
                Ok(_) => {
                    info!(groupe = %group, source = %source, "groupe créé depuis la fédération");
                    return Ok(());
                }
                // Créé entre-temps par une autre connexion : on repasse par la lecture.
                Err(kube::Error::Api(e)) if e.code == 409 => continue,
                Err(e) => return Err(Error::Cluster(format!("création du groupe {group} : {e}"))),
            }
        };

        // Un groupe qui n'est pas marqué comme venant de cette source est géré à la main, ou
        // par une autre. Y écrire écraserait le travail d'un administrateur, et le silence
        // serait total.
        if !group_is_from(&objet, source) {
            warn!(
                groupe = %group,
                source = %source,
                "groupe déclaré dans la table mais gouverné ailleurs, appartenance laissée intacte"
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
                return Err(Error::Cluster(format!(
                    "mise à jour du groupe {group} : {e}"
                )))
            }
        }
    }

    Err(Error::Cluster(format!(
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

fn group_is_from(group: &KdtGroup, source: Source) -> bool {
    group
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(SOURCE_LABEL))
        .map(|label| label == source.label())
        .unwrap_or(false)
}

fn federated_group(name: &str, user: &str, source: Source) -> KdtGroup {
    KdtGroup {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(BTreeMap::from([(
                SOURCE_LABEL.to_string(),
                source.label().to_string(),
            )])),
            ..Default::default()
        },
        spec: KdtGroupSpec {
            description: Some(source.group_description().to_string()),
            members: vec![user.to_string()],
        },
        status: None,
    }
}

/// Désactive un compte dont l'identité a disparu de la source.
///
/// Désactivé, jamais supprimé : un compte effacé emporterait ses `Secret` par cascade, et une
/// panne de lecture de la source prise pour une disparition ferait perdre des comptes. La
/// désactivation, elle, se défait — et le contrôleur ferme déjà les sessions qu'elle laisse
/// ouvertes.
pub async fn disable(users: &Api<KdtUser>, name: &str, source: Source) -> Result<(), Error> {
    let patch = serde_json::json!({ "spec": { "disabled": true } });

    users
        .patch(
            name,
            &PatchParams::apply(source.field_manager()).force(),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| Error::Cluster(format!("désactivation du compte {name} : {e}")))?;

    info!(compte = %name, source = %source, "compte désactivé, identité absente de la source");
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

    fn federated(pin: &str) -> FederatedUser {
        FederatedUser {
            pin: pin.to_string(),
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

    /// Le test qui justifie tout l'épinglage. Deux identités distinctes de la source donnent
    /// le même nom kdt : sans vérification de la valeur épinglée, la seconde se connecterait
    /// sur le compte de la première et hériterait de ses droits.
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
        let source = Source::Ldap;
        let user = user_with(
            &[(SOURCE_LABEL, source.label())],
            &[(source.pin_annotation(), "cn=jean dupont,ou=a,dc=x")],
        );

        assert!(verify_existing(
            user.clone(),
            "jean-dupont",
            &federated("cn=jean-dupont,ou=b,dc=x"),
            source
        )
        .is_err());

        // Le même DN à la casse et aux espaces près reste le même DN.
        assert!(verify_existing(
            user,
            "jean-dupont",
            &federated("CN=Jean Dupont, OU=A, DC=X"),
            source
        )
        .is_ok());
    }

    /// Un sujet de jeton est opaque : rien n'autorise à le comparer à la tolérance près, et
    /// deux sujets qui ne diffèrent que par la casse sont deux personnes différentes.
    #[test]
    fn un_sujet_de_jeton_se_compare_a_l_identique() {
        let source = Source::Oidc;
        let user = user_with(
            &[(SOURCE_LABEL, source.label())],
            &[(source.pin_annotation(), "AbC-123")],
        );

        assert!(verify_existing(user.clone(), "alice", &federated("AbC-123"), source).is_ok());
        assert!(verify_existing(user, "alice", &federated("abc-123"), source).is_err());
    }

    /// Un compte créé à la main, avec son mot de passe et son TOTP, ne se fait pas absorber par
    /// la fédération parce qu'il porte le même nom. Un compte laissé par une autre source non
    /// plus : l'annotation d'épinglage n'est pas la même.
    #[test]
    fn un_compte_d_une_autre_origine_n_est_pas_repris() {
        let local = user_with(&[], &[]);
        assert!(!is_federated(&local));
        assert!(verify_existing(local, "alice", &federated("cn=alice,dc=x"), Source::Ldap).is_err());

        let ldap = user_with(
            &[(SOURCE_LABEL, Source::Ldap.label())],
            &[(Source::Ldap.pin_annotation(), "cn=alice,dc=x")],
        );
        assert!(is_federated(&ldap));
        assert_eq!(source_of(&ldap), Some(Source::Ldap));
        assert!(verify_existing(ldap, "alice", &federated("sub-42"), Source::Oidc).is_err());
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

//! Calculs de réconciliation, isolés de toute plomberie Kubernetes.
//!
//! Tout ce qui décide de quelque chose vit ici, en fonctions pures : la réconciliation est un
//! endroit où une erreur silencieuse coûte cher — un utilisateur qui hérite d'un groupe qu'il
//! ne devrait pas est un problème d'autorisation, pas un défaut d'affichage.

use kdt_identity_api::{KdtGroup, KdtUser, UserPhase};
use std::collections::BTreeSet;

/// Groupes dont `user_name` est membre, dédupliqués et triés.
///
/// L'appartenance a une source de vérité unique — `KdtGroup.spec.members` — et cette fonction
/// est la seule à en dériver la vue inverse. Le tri rend le statut stable d'une réconciliation
/// à l'autre, ce qui évite des écritures inutiles.
pub fn member_of(user_name: &str, groups: &[KdtGroup]) -> Vec<String> {
    groups
        .iter()
        .filter(|g| g.spec.members.iter().any(|m| m == user_name))
        .filter_map(|g| g.metadata.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Sépare les membres déclarés d'un groupe selon qu'ils désignent un `KdtUser` existant.
///
/// Les membres inconnus ne sont pas silencieusement écartés : les exposer dans le statut est
/// le seul moyen de repérer une faute de frappe qui, autrement, priverait quelqu'un de ses
/// droits sans que rien ne le signale.
pub fn resolve_members(group: &KdtGroup, users: &[KdtUser]) -> (Vec<String>, Vec<String>) {
    let known: BTreeSet<&str> = users
        .iter()
        .filter_map(|u| u.metadata.name.as_deref())
        .collect();

    let declared: BTreeSet<&str> = group.spec.members.iter().map(String::as_str).collect();

    let (resolved, unknown): (Vec<&str>, Vec<&str>) =
        declared.into_iter().partition(|m| known.contains(m));

    (
        resolved.into_iter().map(String::from).collect(),
        unknown.into_iter().map(String::from).collect(),
    )
}

/// Phase d'un utilisateur, déduite de sa spec et de l'état de ses credentials.
///
/// `has_credentials` traduit la présence d'un mot de passe défini. Tant que la gestion des
/// credentials n'est pas en place, il vaut toujours `false` et l'utilisateur reste `Pending` :
/// c'est correct, il n'a effectivement pas encore de moyen de se connecter au portail.
pub fn phase(user: &KdtUser, has_credentials: bool) -> UserPhase {
    // `disabled` prime sur tout le reste : c'est le geste d'un admin qui coupe un accès, il ne
    // doit jamais être masqué par un autre état.
    if user.spec.disabled {
        return UserPhase::Disabled;
    }
    if has_credentials {
        UserPhase::Active
    } else {
        UserPhase::Pending
    }
}

/// Vrai si l'utilisateur peut demander lui-même un credential depuis le portail.
///
/// Volontairement restrictif : seul `Active` autorise l'émission. Un utilisateur `Pending` n'a
/// pas encore prouvé son identité, un `Locked` est en cours de verrouillage.
pub fn may_request_own_credential(phase: UserPhase) -> bool {
    matches!(phase, UserPhase::Active)
}

/// Vrai si un administrateur peut émettre un credential pour cet utilisateur.
///
/// Distinct de [`may_request_own_credential`], et pour une raison de fond : la phase mesure ce
/// que l'utilisateur a prouvé au portail, alors qu'ici l'administrateur a déjà prouvé qui il
/// est auprès de l'apiserver. Exiger `Active` interdirait de fournir un accès à quelqu'un qui
/// n'a pas encore activé son compte, ce qui est précisément le cas courant en amorçage.
///
/// `disabled`, en revanche, s'applique aux deux : c'est le geste explicite d'un administrateur
/// qui coupe un accès, et rien ne doit le contourner.
pub fn may_be_issued_by_admin(user: &KdtUser) -> bool {
    !user.spec.disabled
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt_identity_api::{KdtGroupSpec, KdtUserSpec};
    use kube::api::ObjectMeta;

    fn group(name: &str, members: &[&str]) -> KdtGroup {
        KdtGroup {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: KdtGroupSpec {
                description: None,
                members: members.iter().map(|m| m.to_string()).collect(),
            },
            status: None,
        }
    }

    fn user(name: &str) -> KdtUser {
        user_with(name, false)
    }

    fn user_with(name: &str, disabled: bool) -> KdtUser {
        KdtUser {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: KdtUserSpec {
                email: format!("{name}@example.com"),
                display_name: None,
                disabled,
                cert_ttl: None,
            },
            status: None,
        }
    }

    #[test]
    fn l_appartenance_est_deduite_des_groupes() {
        let groups = [
            group("ops", &["alice", "bob"]),
            group("lecteurs", &["alice"]),
            group("finance", &["carol"]),
        ];
        assert_eq!(member_of("alice", &groups), vec!["lecteurs", "ops"]);
        assert_eq!(member_of("bob", &groups), vec!["ops"]);
        assert_eq!(member_of("carol", &groups), vec!["finance"]);
    }

    #[test]
    fn un_utilisateur_sans_groupe_n_herite_de_rien() {
        let groups = [group("ops", &["alice"])];
        assert!(member_of("mallory", &groups).is_empty());
        assert!(member_of("alice", &[]).is_empty());
    }

    /// Un même nom déclaré deux fois dans un groupe ne doit pas produire deux appartenances :
    /// le résultat finit en `O=` répétés dans un certificat.
    #[test]
    fn un_membre_declare_deux_fois_ne_compte_qu_une_fois() {
        let groups = [group("ops", &["alice", "alice"])];
        assert_eq!(member_of("alice", &groups), vec!["ops"]);
    }

    /// Le tri garantit un statut stable, sinon chaque réconciliation réécrit l'objet.
    #[test]
    fn l_ordre_des_groupes_est_deterministe() {
        let desordre = [
            group("zeta", &["alice"]),
            group("alpha", &["alice"]),
            group("mu", &["alice"]),
        ];
        assert_eq!(member_of("alice", &desordre), vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn les_membres_inconnus_sont_signales_et_non_ignores() {
        let g = group("ops", &["alice", "fantome", "bob"]);
        let users = [user("alice"), user("bob")];

        let (resolved, unknown) = resolve_members(&g, &users);
        assert_eq!(resolved, vec!["alice", "bob"]);
        assert_eq!(unknown, vec!["fantome"]);
    }

    #[test]
    fn un_groupe_vide_se_resout_sans_erreur() {
        let (resolved, unknown) = resolve_members(&group("vide", &[]), &[user("alice")]);
        assert!(resolved.is_empty());
        assert!(unknown.is_empty());
    }

    #[test]
    fn disabled_prime_sur_tout_le_reste() {
        // Même avec des credentials valides, un compte désactivé ne redevient pas actif.
        assert_eq!(phase(&user_with("alice", true), true), UserPhase::Disabled);
        assert_eq!(phase(&user_with("alice", true), false), UserPhase::Disabled);
    }

    #[test]
    fn un_utilisateur_sans_credentials_reste_en_attente() {
        assert_eq!(phase(&user("alice"), false), UserPhase::Pending);
        assert_eq!(phase(&user("alice"), true), UserPhase::Active);
    }

    /// Le libre-service est le point où une erreur devient un accès : seul `Active` le permet.
    #[test]
    fn seule_la_phase_active_autorise_le_libre_service() {
        assert!(may_request_own_credential(UserPhase::Active));
        for refusee in [UserPhase::Pending, UserPhase::Disabled, UserPhase::Locked] {
            assert!(
                !may_request_own_credential(refusee),
                "{refusee:?} ne doit pas émettre"
            );
        }
    }

    /// Un admin peut amorcer l'accès de quelqu'un qui n'a pas encore activé son compte…
    #[test]
    fn un_admin_peut_emettre_pour_un_compte_non_active() {
        assert!(may_be_issued_by_admin(&user("alice")));
    }

    /// …mais jamais contourner une désactivation.
    #[test]
    fn disabled_bloque_meme_un_admin() {
        assert!(!may_be_issued_by_admin(&user_with("alice", true)));
    }
}

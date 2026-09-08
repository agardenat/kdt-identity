//! Relecture périodique de l'annuaire.
//!
//! Une connexion ne renseigne que la personne qui se connecte. Sans cette boucle, un retrait de
//! groupe côté annuaire n'aurait d'effet qu'à sa prochaine saisie de mot de passe — et comme le
//! renouvellement silencieux ne rebinde jamais, cela peut vouloir dire une semaine entière avec
//! des droits qu'elle n'a plus.
//!
//! # La règle qui gouverne tout ce module
//!
//! Une panne d'annuaire n'est pas une disparition de comptes. Un `Ok(None)` sur une entrée dit
//! qu'elle a été supprimée ; une erreur ne dit rien du tout. Confondre les deux désactiverait
//! tous les comptes du cluster à la première coupure réseau, et la coupure survivrait alors très
//! largement à sa propre résolution.

use crate::ldap::{provision, Directory, LdapError};
use kdt_identity_api::{KdtGroup, KdtUser};
use kube::api::{Api, ListParams};
use std::sync::Arc;
use tracing::{info, warn};

/// Sélecteur des comptes que l'annuaire gouverne.
fn federated() -> ListParams {
    ListParams::default().labels(&format!(
        "{}={}",
        provision::SOURCE_LABEL,
        provision::SOURCE_LDAP
    ))
}

/// Boucle jusqu'à l'arrêt du processus.
pub async fn run(users: Api<KdtUser>, groups: Api<KdtGroup>, directory: Arc<Directory>) {
    let interval = directory.config().resync;
    info!(intervalle = ?interval, "relecture périodique de l'annuaire");

    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = pass(&users, &groups, &directory).await {
            warn!(erreur = %e, "relecture de l'annuaire abandonnée pour ce tour");
        }
    }
}

/// Un tour complet.
///
/// Rend une erreur dès que l'annuaire se dérobe, sans traiter les comptes suivants : après une
/// panne, la seule chose qu'on sache est qu'on ne sait rien, et poursuivre reviendrait à
/// prendre cette ignorance pour de l'information.
async fn pass(
    users: &Api<KdtUser>,
    groups: &Api<KdtGroup>,
    directory: &Directory,
) -> Result<(), LdapError> {
    let comptes = users
        .list(&federated())
        .await
        .map_err(|e| LdapError::Cluster(format!("liste des comptes fédérés : {e}")))?;

    let mappings = &directory.config().group_mappings;
    let managed = mappings.managed_groups();

    for user in comptes {
        let (Some(name), Some(dn)) = (user.metadata.name.clone(), provision::recorded_dn(&user))
        else {
            // Un compte marqué comme fédéré mais sans DN épinglé n'est rattachable à rien. Le
            // signaler suffit : c'est une anomalie d'exploitation, pas un état à corriger
            // d'office.
            warn!(
                compte = ?user.metadata.name,
                "compte fédéré sans DN épinglé, laissé tel quel"
            );
            continue;
        };

        match directory.lookup_dn(dn).await {
            Ok(Some(directory_user)) => {
                if user.spec.disabled {
                    // Réactiver serait défaire le geste d'un administrateur : `spec.disabled`
                    // peut avoir été posé à la main pour couper un accès, et l'annuaire n'a pas
                    // à en décider.
                    continue;
                }
                let wanted = mappings.resolve(&directory_user.member_of);
                provision::sync_groups(groups, &name, &wanted, &managed).await?;
            }
            Ok(None) => {
                if !user.spec.disabled {
                    provision::disable(users, &name).await?;
                }
            }
            // Une entrée devenue illisible ne justifie pas d'abandonner le tour : c'est un
            // problème propre à ce compte, pas à l'annuaire.
            Err(e @ LdapError::Unusable(_)) => {
                warn!(compte = %name, erreur = %e, "entrée illisible, compte ignoré");
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

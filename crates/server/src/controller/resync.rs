//! Relecture périodique de la source d'identité.
//!
//! Une connexion ne renseigne que la personne qui se connecte. Sans cette boucle, un retrait de
//! groupe fait chez la source n'aurait d'effet qu'à sa prochaine connexion interactive — et comme
//! le renouvellement silencieux ne rebinde ni ne repasse jamais par le fournisseur, cela peut
//! vouloir dire une semaine entière avec des droits qu'elle n'a plus.
//!
//! # La règle qui gouverne tout ce module
//!
//! Une panne de la source n'est pas une disparition de comptes. Un `Ok(None)` sur une personne dit
//! qu'elle n'a plus d'accès ; une erreur ne dit rien du tout. Confondre les deux désactiverait
//! tous les comptes du cluster à la première coupure réseau, et la coupure survivrait alors très
//! largement à sa propre résolution.
//!
//! # Une seule boucle pour les deux sources
//!
//! Ce qui change d'un annuaire à un fournisseur — comment on interroge, par quoi on désigne une
//! personne — vit derrière [`Federated`]. Ce qui ne change pas est ici : la règle ci-dessus, le
//! refus de réactiver ce qu'un administrateur a désactivé, et l'abandon du tour dès que la source
//! se dérobe.

use crate::federation::{provision, Error, Federated};
use kdt_identity_api::{KdtGroup, KdtUser};
use kube::api::{Api, ListParams};
use std::sync::Arc;
use tracing::{info, warn};

/// Boucle jusqu'à l'arrêt du processus.
pub async fn run<F: Federated + 'static>(
    users: Api<KdtUser>,
    groups: Api<KdtGroup>,
    source: Arc<F>,
) {
    let interval = source.interval();
    info!(
        source = %source.source(),
        intervalle = ?interval,
        "relecture périodique de la source d'identité"
    );

    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = pass(&users, &groups, source.as_ref()).await {
            warn!(
                source = %source.source(),
                erreur = %e,
                "relecture abandonnée pour ce tour"
            );
        }
    }
}

/// Un tour complet.
///
/// Rend une erreur dès que la source se dérobe, sans traiter les comptes suivants : après une
/// panne, la seule chose qu'on sache est qu'on ne sait rien, et poursuivre reviendrait à prendre
/// cette ignorance pour de l'information.
async fn pass<F: Federated>(
    users: &Api<KdtUser>,
    groups: &Api<KdtGroup>,
    source: &F,
) -> Result<(), Error> {
    let kind = source.source();
    let selector = ListParams::default().labels(&format!(
        "{}={}",
        provision::SOURCE_LABEL,
        kind.label()
    ));

    let comptes = users
        .list(&selector)
        .await
        .map_err(|e| Error::Cluster(format!("liste des comptes fédérés : {e}")))?;

    let mappings = source.mappings();
    let managed = mappings.managed_groups();

    for user in comptes {
        let (Some(name), Some(pin)) = (
            user.metadata.name.clone(),
            provision::recorded_pin(&user, kind),
        ) else {
            // Un compte marqué comme fédéré mais sans valeur épinglée n'est rattachable à rien.
            // Le signaler suffit : c'est une anomalie d'exploitation, pas un état à corriger
            // d'office.
            warn!(
                compte = ?user.metadata.name,
                source = %kind,
                "compte fédéré sans identité épinglée, laissé tel quel"
            );
            continue;
        };

        match source.lookup_groups(pin).await {
            Ok(Some(member_of)) => {
                if user.spec.disabled {
                    // Réactiver serait défaire le geste d'un administrateur : `spec.disabled`
                    // peut avoir été posé à la main pour couper un accès, et la source n'a pas
                    // à en décider.
                    continue;
                }
                let wanted = mappings.resolve(&member_of);
                provision::sync_groups(groups, &name, &wanted, &managed, kind).await?;
            }
            Ok(None) => {
                if !user.spec.disabled {
                    provision::disable(users, &name, kind).await?;
                }
            }
            // Une identité devenue illisible ne justifie pas d'abandonner le tour : c'est un
            // problème propre à ce compte, pas à la source.
            Err(e @ Error::Unusable(_)) => {
                warn!(compte = %name, erreur = %e, "identité illisible, compte ignoré");
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

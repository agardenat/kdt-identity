//! Réconciliation des `KdtUser` et `KdtGroup`.
//!
//! Le contrôleur ne décide de rien par lui-même : il lit l'état, appelle les fonctions pures
//! de [`logic`], et n'écrit que si le statut calculé diffère de celui déjà publié. Cette
//! dernière condition n'est pas une optimisation — sans elle, chaque écriture de statut
//! déclenche un nouvel évènement et le contrôleur tourne en boucle sur lui-même.

pub mod logic;

use futures::StreamExt;
use kdt_identity_api::crd::{KdtGroupStatus, KdtUserStatus};
use kdt_identity_api::naming::Subject;
use kdt_identity_api::{KdtGroup, KdtUser};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::{watcher, Controller};
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Resynchronisation périodique, filet de sécurité si un évènement se perd.
const RESYNC: Duration = Duration::from_secs(300);
/// Attente avant nouvelle tentative après une erreur de réconciliation.
const RETRY: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("appel à l'API Kubernetes : {0}")]
    Kube(#[from] kube::Error),
    #[error("objet sans nom")]
    Unnamed,
    #[error("nom stocké invalide : {0}")]
    Name(#[from] kdt_identity_api::NameError),
}

pub struct Context {
    users: Api<KdtUser>,
    groups: Api<KdtGroup>,
}

/// Fait tourner les deux contrôleurs jusqu'à l'arrêt du processus.
pub async fn run(client: Client) {
    let users: Api<KdtUser> = Api::all(client.clone());
    let groups: Api<KdtGroup> = Api::all(client);
    let ctx = Arc::new(Context {
        users: users.clone(),
        groups: groups.clone(),
    });

    // L'appartenance d'un utilisateur est portée par les groupes : modifier un `KdtGroup` doit
    // rafraîchir le statut de chacun de ses membres, sans quoi `memberOf` reste périmé
    // jusqu'à la resynchronisation.
    let user_controller = Controller::new(users, watcher::Config::default())
        .watches(groups.clone(), watcher::Config::default(), |g: KdtGroup| {
            g.spec
                .members
                .into_iter()
                .map(|m| ObjectRef::<KdtUser>::new(&m))
                .collect::<Vec<_>>()
        })
        .run(reconcile_user, on_error::<KdtUser>, ctx.clone())
        .for_each(|_| futures::future::ready(()));

    // Symétrique, mais la relation ne se remonte pas : un `KdtUser` ne sait pas quels groupes
    // le nomment, donc aucun mapper ne peut désigner les groupes à réconcilier. On réconcilie
    // donc tous les groupes à chaque évènement utilisateur. Le nombre de groupes d'un cluster
    // se compte en dizaines et la réconciliation n'écrit que si le statut change : le coût est
    // négligeable devant un `memberOf` faux pendant cinq minutes.
    //
    // Le flux du watcher n'est que `Send`, là où `reconcile_all_on` réclame `Sync` : on le
    // relaie par un canal. La capacité de 1 avec `try_send` est délibérée — si un signal est
    // déjà en attente, en empiler un second ne changerait rien puisque la réconciliation qui
    // suivra lira l'état courant de toute façon. Les rafales se fondent ainsi en un seul
    // passage.
    let (mut tx, on_user_change) = futures::channel::mpsc::channel::<()>(1);
    let watched_users = ctx.users.clone();
    tokio::spawn(async move {
        let mut events = watcher::watcher(watched_users, watcher::Config::default()).boxed();
        while let Some(event) = events.next().await {
            if event.is_ok() {
                let _ = tx.try_send(());
            }
        }
    });

    let group_controller = Controller::new(groups, watcher::Config::default())
        .reconcile_all_on(on_user_change)
        .run(reconcile_group, on_error::<KdtGroup>, ctx)
        .for_each(|_| futures::future::ready(()));

    futures::join!(user_controller, group_controller);
}

async fn reconcile_user(user: Arc<KdtUser>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = user.metadata.name.clone().ok_or(Error::Unnamed)?;
    let groups = ctx.groups.list(&ListParams::default()).await?.items;

    let desired = KdtUserStatus {
        member_of: logic::member_of(&name, &groups),
        // Les credentials n'existent pas encore : la phase reste dérivée de la seule spec.
        phase: Some(logic::phase(&user, false)),
        ..user.status.clone().unwrap_or_default()
    };

    if user.status.as_ref().is_some_and(|s| equivalent_user(s, &desired)) {
        return Ok(Action::requeue(RESYNC));
    }

    info!(user = %name, groups = ?desired.member_of, phase = ?desired.phase, "statut mis à jour");
    ctx.users
        .patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": desired })),
        )
        .await?;

    Ok(Action::requeue(RESYNC))
}

async fn reconcile_group(group: Arc<KdtGroup>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = group.metadata.name.clone().ok_or(Error::Unnamed)?;
    let users = ctx.users.list(&ListParams::default()).await?.items;
    let (resolved, unknown) = logic::resolve_members(&group, &users);

    if !unknown.is_empty() {
        // Ni bloquant ni silencieux : un membre inexistant est presque toujours une faute de
        // frappe, et elle se traduit par des droits manquants côté utilisateur.
        warn!(group = %name, membres = ?unknown, "membres déclarés sans KdtUser correspondant");
    }

    let desired = KdtGroupStatus {
        // Publié pour que personne n'ait à deviner qu'un binding doit viser `kdt:<nom>`.
        subject: Some(Subject::group(&name)?.as_str().to_string()),
        member_count: resolved.len() as u32,
        resolved_members: resolved,
        unknown_members: unknown,
        conditions: group
            .status
            .clone()
            .map(|s| s.conditions)
            .unwrap_or_default(),
    };

    if group.status.as_ref().is_some_and(|s| equivalent_group(s, &desired)) {
        return Ok(Action::requeue(RESYNC));
    }

    info!(group = %name, membres = desired.member_count, "statut mis à jour");
    ctx.groups
        .patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": desired })),
        )
        .await?;

    Ok(Action::requeue(RESYNC))
}

fn equivalent_user(current: &KdtUserStatus, desired: &KdtUserStatus) -> bool {
    current.member_of == desired.member_of && current.phase == desired.phase
}

fn equivalent_group(current: &KdtGroupStatus, desired: &KdtGroupStatus) -> bool {
    current.subject == desired.subject
        && current.resolved_members == desired.resolved_members
        && current.unknown_members == desired.unknown_members
        && current.member_count == desired.member_count
}

fn on_error<K: ResourceExt>(object: Arc<K>, err: &Error, _ctx: Arc<Context>) -> Action {
    warn!(objet = %object.name_any(), erreur = %err, "réconciliation en échec");
    Action::requeue(RETRY)
}

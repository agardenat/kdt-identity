//! Proxy d'accès au cluster : ce qui rend un kubeconfig révocable sans rien demander à
//! l'apiserver.
//!
//! # Pourquoi se mettre devant plutôt que dedans
//!
//! Un kubeconfig lisible par `kubectl` et `helm` sans rien installer n'a que deux formes : un
//! certificat client, qu'aucune révocation ne rattrape parce que Kubernetes ne consulte pas de
//! CRL, ou un jeton. Un jeton n'est révocable que s'il est vérifié **en ligne**, et les deux
//! mécanismes qui le permettent — webhook d'authentification, fournisseur OIDC déclaré — se
//! règlent par des options de l'apiserver que les offres managées n'exposent pas : ni l'un ni
//! l'autre sur AKS, le seul webhook sur ce qu'on administre soi-même.
//!
//! D'où ce proxy. Le kubeconfig pointe sur lui, il vérifie le jeton contre l'état du cluster,
//! puis relaie à l'apiserver en **impersonation**. Rien à configurer en amont, donc toutes les
//! distributions ; et l'identité vue par l'apiserver reste `kdt:<compte>` avec ses groupes, donc
//! les `RoleBinding` déjà posés s'appliquent sans changer une ligne.
//!
//! # Ce qui coupe un accès, et en combien de temps
//!
//! Chaque requête est vérifiée. Fermer les sessions, désactiver le compte ou le sortir d'un
//! groupe prend effet au prochain appel, à [`ProxyConfig::cache_ttl`] près — c'est le seul
//! curseur, et il n'existe que pour ne pas relire un `Secret` à chaque `kubectl get`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body as AxumBody;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use chrono::Utc;
use kube::api::{Api, ListParams};
use kube::ResourceExt;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::warn;

use kdt_identity_api::naming::{validate_name, Subject};
use kdt_identity_api::{KdtGroup, KdtUser};

use crate::auth::store::CredentialStore;
use crate::controller::logic;
use crate::sessions::{split_kubeconfig_token, SessionKind, SessionStore};

pub mod upgrade;

#[cfg(test)]
mod tests;

/// En-têtes d'impersonation posés par le proxy.
///
/// Ils sont **écrasés**, jamais transmis : un `kubectl --as` présenté par un porteur de jeton ne
/// doit pas traverser, sinon le proxy prêterait son propre droit d'impersonation à qui le lui
/// demande. C'est l'invariant le plus important de ce module.
const IMPERSONATE_PREFIX: &str = "impersonate-";
const IMPERSONATE_USER: &str = "impersonate-user";
const IMPERSONATE_GROUP: &str = "impersonate-group";
const IMPERSONATE_UID: &str = "impersonate-uid";

/// En-têtes qui décrivent la connexion elle-même et ne se relaient pas d'un saut à l'autre
/// (RFC 9110 §7.6.1). `authorization` s'y ajoute : celui de l'amont est posé par le client
/// Kubernetes, pas par le porteur du jeton.
const HOP_BY_HOP: &[&str] = &[
    "authorization",
    "connection",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Taille maximale du corps d'une requête relayée.
///
/// Les corps sans fin sont ceux des connexions promues (`exec`, `attach`, `port-forward`), qui
/// suivent un autre chemin. Ce qui passe ici est borné par nature : un manifeste, un patch.
const MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Nom du cluster, tel qu'il figure dans l'URL et dans le kubeconfig remis.
    pub cluster_name: String,
    /// Durée pendant laquelle une identité vérifiée est réutilisée sans relire le cluster.
    pub cache_ttl: Duration,
}

/// Une identité reconstruite à partir du jeton, telle qu'elle sera présentée à l'apiserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub user: Subject,
    pub groups: Vec<Subject>,
    pub uid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    #[error("aucun jeton présenté")]
    NoToken,
    #[error("ce jeton n'est pas celui d'un kubeconfig kdt-identity")]
    NotOurs,
    #[error("jeton invalide ou révoqué")]
    Invalid,
    #[error("le compte n'est pas actif")]
    NotActive,
    #[error("cluster inconnu")]
    UnknownCluster,
}

struct CacheEntry {
    identity: Identity,
    seen: Instant,
}

pub struct ProxyState {
    users: Api<KdtUser>,
    groups: Api<KdtGroup>,
    sessions: SessionStore,
    store: CredentialStore,
    upstream: kube::Client,
    /// La même configuration que celle du client, pour les connexions promues : elles ouvrent
    /// leur propre socket en HTTP/1.1, mais doivent viser le même apiserver avec la même
    /// confiance. Deux configurations TLS finiraient par diverger.
    upstream_config: kube::Config,
    config: ProxyConfig,
    cache: RwLock<HashMap<[u8; 32], CacheEntry>>,
}

pub type Shared = Arc<ProxyState>;

impl ProxyState {
    pub fn new(
        client: kube::Client,
        upstream_config: kube::Config,
        namespace: &str,
        config: ProxyConfig,
    ) -> Self {
        Self {
            users: Api::all(client.clone()),
            groups: Api::all(client.clone()),
            sessions: SessionStore::new(client.clone(), namespace),
            store: CredentialStore::new(client.clone(), namespace),
            upstream: client,
            upstream_config,
            config,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Oublie tout ce qui a été vérifié. Sert aux tests et à un éventuel signal d'exploitation ;
    /// la révocation, elle, n'a pas besoin de ce geste — elle attend simplement l'expiration.
    pub async fn forget_all(&self) {
        self.cache.write().await.clear();
    }
}

/// Les routes du proxy, greffées sur le portail ou servies à part.
///
/// Pas de `/healthz` ici : greffé, il entrerait en conflit avec celui du portail ; à part, il
/// décrirait le même processus que lui. Les sondes du pod visent le portail dans les deux cas.
pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/k8s/{*rest}", any(handle))
        .with_state(state)
}

async fn handle(State(state): State<Shared>, request: Request) -> Response {
    let raw = request.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let Some(target) = upstream_path_and_query(raw, &state.config.cluster_name) else {
        return deny(DenyReason::UnknownCluster);
    };

    let identity = match authenticate(&state, request.headers()).await {
        Ok(identity) => identity,
        Err(reason) => return deny(reason),
    };

    let mut headers = forward_headers(request.headers(), &identity);

    // `exec`, `attach`, `port-forward` et `cp` ne passent pas par le relais ordinaire : leur
    // corps n'a pas de fin, et ce qui suit le 101 n'est plus du HTTP.
    if upgrade::is_upgrade(request.headers()) {
        upgrade::upgrade_headers(request.headers(), &mut headers);
        let target = target.clone();
        return match upgrade::relay(&state.upstream_config, request, &target, headers).await {
            Ok(response) => response,
            Err(e) => {
                warn!(erreur = %e, "promotion de connexion impossible");
                StatusCode::BAD_GATEWAY.into_response()
            }
        };
    }

    let method = request.method().clone();

    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "corps trop volumineux").into_response(),
    };

    let mut upstream = match Request::builder()
        .method(method)
        .uri(target)
        .body(kube::client::Body::from(body.to_vec()))
    {
        Ok(request) => request,
        Err(e) => {
            warn!(erreur = %e, "requête amont impossible à construire");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    *upstream.headers_mut() = headers;

    match state.upstream.send(upstream).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            Response::from_parts(parts, AxumBody::new(body))
        }
        Err(e) => {
            warn!(erreur = %e, "relais vers l'apiserver impossible");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Reconstruit le chemin à présenter à l'apiserver.
///
/// L'URI brute est reprise telle quelle, sans passer par un extracteur de chemin : décoder puis
/// réencoder les `%XX` changerait les requêtes qui portent un `fieldSelector` ou un nom
/// d'objet inhabituel.
fn upstream_path_and_query(raw: &str, cluster: &str) -> Option<String> {
    let rest = raw.strip_prefix("/k8s/")?;
    let (name, tail) = match rest.split_once('/') {
        Some((name, tail)) => (name, tail),
        // `/k8s/<cluster>` seul, ou suivi seulement d'une query.
        None => match rest.split_once('?') {
            Some((name, query)) => return (name == cluster).then(|| format!("/?{query}")),
            None => (rest, ""),
        },
    };
    if name != cluster {
        return None;
    }
    Some(format!("/{tail}"))
}

/// Recopie les en-têtes du client, puis impose l'identité.
///
/// Tout `Impersonate-*` présenté est retiré avant que les nôtres ne soient posés : c'est la
/// seule barrière entre un porteur de jeton et le droit d'impersonation du proxy.
fn forward_headers(incoming: &HeaderMap, identity: &Identity) -> HeaderMap {
    let mut headers = HeaderMap::new();

    for (name, value) in incoming {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || lower.starts_with(IMPERSONATE_PREFIX) {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }

    // `Subject` ne peut contenir que [a-z0-9.-] et le préfixe `kdt:` : la conversion en valeur
    // d'en-tête ne peut pas échouer, mais on ne le suppose pas.
    if let Ok(value) = HeaderValue::from_str(identity.user.as_str()) {
        headers.insert(HeaderName::from_static(IMPERSONATE_USER), value);
    }
    for group in &identity.groups {
        if let Ok(value) = HeaderValue::from_str(group.as_str()) {
            headers.append(HeaderName::from_static(IMPERSONATE_GROUP), value);
        }
    }
    if let Some(uid) = &identity.uid {
        if let Ok(value) = HeaderValue::from_str(uid) {
            headers.insert(HeaderName::from_static(IMPERSONATE_UID), value);
        }
    }

    headers
}

/// Vérifie le jeton présenté et rend l'identité à impersonner.
async fn authenticate(state: &ProxyState, headers: &HeaderMap) -> Result<Identity, DenyReason> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(DenyReason::NoToken)?;

    // Écarté sans lire le moindre objet : un jeton de `ServiceAccount` présenté ici n'est pas
    // une erreur, c'est juste un jeton qui ne nous appartient pas.
    let (user, credential) = split_kubeconfig_token(presented).ok_or(DenyReason::NotOurs)?;
    // Le compte sert à composer un nom de `Secret` : il est validé avant, jamais après.
    validate_name(user).map_err(|_| DenyReason::Invalid)?;

    let key: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    if let Some(identity) = state.cached(&key).await {
        return Ok(identity);
    }

    let identity = state.resolve(user, credential).await?;
    state.remember(key, identity.clone()).await;
    Ok(identity)
}

impl ProxyState {
    async fn cached(&self, key: &[u8; 32]) -> Option<Identity> {
        let cache = self.cache.read().await;
        let entry = cache.get(key)?;
        (entry.seen.elapsed() < self.config.cache_ttl).then(|| entry.identity.clone())
    }

    async fn remember(&self, key: [u8; 32], identity: Identity) {
        let mut cache = self.cache.write().await;
        // Le ménage se fait ici, faute de quoi rien ne viendrait jamais le faire : les entrées
        // périmées d'un compte qui ne revient pas resteraient indéfiniment.
        cache.retain(|_, e| e.seen.elapsed() < self.config.cache_ttl);
        cache.insert(
            key,
            CacheEntry {
                identity,
                seen: Instant::now(),
            },
        );
    }

    /// Relit l'état du cluster : session ouverte, compte actif, groupes courants.
    ///
    /// Les groupes viennent des `KdtGroup`, jamais de `status.memberOf` : c'est ce qui rend un
    /// retrait de groupe immédiat, alors qu'un certificat déjà émis garde les siens.
    async fn resolve(&self, user: &str, credential: &str) -> Result<Identity, DenyReason> {
        let sessions = self.sessions.get(user).await.map_err(|e| {
            warn!(user, erreur = %e, "sessions illisibles");
            DenyReason::Invalid
        })?;
        sessions
            .verify(credential, Utc::now(), SessionKind::Kubeconfig)
            .map_err(|_| DenyReason::Invalid)?;

        let object = self.users.get(user).await.map_err(|_| DenyReason::Invalid)?;
        let activated = self
            .store
            .get(user)
            .await
            .map_err(|_| DenyReason::Invalid)?
            .map(|c| c.is_activated())
            .unwrap_or(false);
        if !logic::may_request_own_credential(logic::phase(&object, activated)) {
            return Err(DenyReason::NotActive);
        }

        let groups = self
            .groups
            .list(&ListParams::default())
            .await
            .map_err(|e| {
                warn!(user, erreur = %e, "groupes illisibles");
                DenyReason::Invalid
            })?
            .items;

        Ok(Identity {
            user: Subject::user(user).map_err(|_| DenyReason::Invalid)?,
            groups: logic::member_of(user, &groups)
                .iter()
                .map(|g| Subject::group(g))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| DenyReason::Invalid)?,
            uid: object.uid(),
        })
    }
}

/// Refuse en parlant la langue de `kubectl`.
///
/// Un `Status` plutôt qu'un corps vide : c'est ce que client-go sait afficher, et un accès coupé
/// doit se lire comme une phrase, pas comme un code.
fn deny(reason: DenyReason) -> Response {
    let code = match reason {
        DenyReason::UnknownCluster => StatusCode::NOT_FOUND,
        _ => StatusCode::UNAUTHORIZED,
    };
    let body = serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": reason.to_string(),
        "reason": match reason {
            DenyReason::UnknownCluster => "NotFound",
            _ => "Unauthorized",
        },
        "code": code.as_u16(),
    });
    (code, axum::Json(body)).into_response()
}

/// Adresse à inscrire dans le kubeconfig pour ce cluster.
pub fn server_url(base: &str, cluster: &str) -> String {
    format!("{}/k8s/{cluster}", base.trim_end_matches('/'))
}

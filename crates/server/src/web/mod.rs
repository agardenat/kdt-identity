//! Portail web : activation, connexion, kubeconfig.
//!
//! # Ce que le portail ne dit pas
//!
//! Aucune réponse ne distingue « ce compte n'existe pas » de « le mot de passe est faux », ni
//! « ce lien est faux » de « ce lien a expiré ». Un portail qui répond précisément est un
//! annuaire : il permet d'énumérer les comptes du cluster depuis l'extérieur. Les journaux,
//! eux, gardent la raison exacte — c'est là qu'elle est utile.
//!
//! # Ce qui ne transite jamais
//!
//! Ni le jeton d'un lien d'activation, ni un code, ni un mot de passe n'apparaît dans un
//! journal. Le secret TOTP en cours d'enrôlement traverse le navigateur, ce qui est sans
//! conséquence : il est destiné à cette personne, et le cookie qui le porte est signé pour
//! empêcher qu'on lui en substitue un autre.

pub mod signer;
pub mod views;

use crate::auth::store::{CredentialStore, Credentials};
use crate::auth::{invite, lockout::Lockout, password, totp};
use crate::config::ServerConfig;
use crate::controller::logic;
use crate::credentials::kubeconfig::ClusterEndpoint;
use crate::credentials::{kubeconfig, Issuer};
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use kdt_identity_api::naming::Subject;
use kdt_identity_api::portal::{
    CredentialRequest, CredentialResponse, SessionRequest, SessionResponse,
};
use kdt_identity_api::{KdtGroup, KdtUser};
use kube::api::{Api, ListParams};
use serde::Deserialize;
use signer::Signer;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Usages des jetons signés. Deux usages distincts ne peuvent pas être confondus.
mod purpose {
    pub const SESSION: &str = "session";
    pub const CSRF: &str = "csrf";
    /// Jeton remis au plugier `exec` entre l'authentification et la demande de certificat.
    pub const API_CREDENTIAL: &str = "api-credential";
}

const SESSION_COOKIE: &str = "kdt_identity_session";
const SESSION_TTL: chrono::Duration = chrono::Duration::hours(12);

/// Durée de validité du certificat émis par le portail.
const CERT_TTL: Duration = Duration::from_secs(8 * 3600);

/// Message unique de tout échec d'authentification.
const GENERIC_AUTH_FAILURE: &str =
    "Compte, mot de passe ou code incorrect. Vérifiez vos identifiants et réessayez.";

const GENERIC_ACTIVATION_FAILURE: &str =
    "Ce lien ou ce code d'activation est invalide ou a expiré. Demandez une nouvelle invitation \
     à votre administrateur.";

pub struct AppState {
    users: Api<KdtUser>,
    groups: Api<KdtGroup>,
    store: CredentialStore,
    issuer: Issuer,
    signer: Signer,
    endpoint: ClusterEndpoint,
    config: ServerConfig,
}

type Shared = Arc<AppState>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(account_page))
        .route("/activate", get(activate_page).post(activate_submit))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/kubeconfig", post(download_kubeconfig))
        .route(kdt_identity_api::portal::SESSION_PATH, post(api_session))
        .route(kdt_identity_api::portal::CREDENTIAL_PATH, post(api_credential))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

pub fn state(
    client: kube::Client,
    config: ServerConfig,
    endpoint: ClusterEndpoint,
    signer: Signer,
) -> Shared {
    Arc::new(AppState {
        users: Api::all(client.clone()),
        groups: Api::all(client.clone()),
        store: CredentialStore::new(client.clone(), &config.namespace),
        issuer: Issuer::new(client),
        signer,
        endpoint,
        config,
    })
}

// ---------------------------------------------------------------- activation

#[derive(Deserialize)]
pub struct ActivateQuery {
    #[serde(default, rename = "u")]
    user: String,
    #[serde(default, rename = "t")]
    token: String,
}

/// Affiche le formulaire d'activation.
///
/// Le secret TOTP est tiré ici et proposé au navigateur, **sans** vérifier au préalable que le
/// compte existe ni que le lien est bon : répondre différemment selon le cas transformerait
/// cette page en oracle d'existence des comptes. Le secret n'a de valeur qu'une fois
/// l'activation réussie, qui exige elle le jeton et le code.
async fn activate_page(
    State(state): State<Shared>,
    Query(query): Query<ActivateQuery>,
) -> Response {
    render_activation(&state, &query.user, &query.token, None, None)
}

#[derive(Deserialize)]
pub struct ActivateForm {
    user: String,
    token: String,
    secret: String,
    code: String,
    password: String,
    confirm: String,
    totp: String,
}

async fn activate_submit(State(state): State<Shared>, Form(form): Form<ActivateForm>) -> Response {
    let reject = |reason: &str| {
        warn!(user = %form.user, raison = reason, "activation refusée");
        render_activation(
            &state,
            &form.user,
            &form.token,
            Some(&form.secret),
            Some(GENERIC_ACTIVATION_FAILURE),
        )
    };

    // La confirmation est la seule erreur qu'on nomme : elle ne renseigne sur rien, et la
    // taire ferait buter l'utilisateur sur un message générique pour une faute de frappe.
    if form.password != form.confirm {
        return render_activation(
            &state,
            &form.user,
            &form.token,
            Some(&form.secret),
            Some("Les deux mots de passe ne correspondent pas."),
        );
    }

    let Ok(user) = state.users.get(&form.user).await else {
        return reject("compte inconnu");
    };
    if user.spec.disabled {
        return reject("compte désactivé");
    }

    let Ok(Some(credentials)) = state.store.get(&form.user).await else {
        return reject("aucun credential enregistré");
    };
    let Some(record) = credentials.invite.as_ref() else {
        return reject("aucune invitation en cours");
    };

    // Le verrouillage protège aussi l'activation : le code hors bande est court, il ne doit
    // pas pouvoir être deviné par répétition.
    let now = Utc::now();
    if credentials.lockout.is_locked(now) {
        return reject("compte temporairement verrouillé");
    }

    if invite::verify(record, &form.token, &form.code, now).is_err() {
        let failed = Credentials {
            lockout: credentials.lockout.record_failure(now),
            ..credentials.clone()
        };
        let _ = state.store.put(&user, &failed).await;
        return reject("lien ou code invalide");
    }

    if let Err(e) = password::check_policy(&form.password, &form.user) {
        // Une politique de mot de passe se dit : la taire empêche de la satisfaire.
        return render_activation(
            &state,
            &form.user,
            &form.token,
            Some(&form.secret),
            Some(&e.to_string()),
        );
    }

    // Le code TOTP prouve que l'authenticator a bien enregistré le secret. Sans cette
    // vérification, un QR mal scanné produirait un compte que personne ne peut plus ouvrir.
    if totp::verify(&form.secret, &form.totp, now.timestamp() as u64, None).is_err() {
        return render_activation(
            &state,
            &form.user,
            &form.token,
            Some(&form.secret),
            Some("Code à 6 chiffres incorrect. Vérifiez l'heure de votre téléphone et réessayez."),
        );
    }

    let Ok(hash) = password::hash(&form.password) else {
        return reject("hachage du mot de passe");
    };

    // `activated` consomme l'invitation dans la même écriture : le code ne peut pas resservir.
    let activated = credentials.activated(hash, Zeroizing::new(form.secret.clone()));
    if state.store.put(&user, &activated).await.is_err() {
        return reject("enregistrement des credentials");
    }

    info!(user = %form.user, "compte activé");
    Html(
        views::message(
            "Accès activé",
            "Votre accès est activé",
            "Vous pouvez maintenant vous connecter avec votre mot de passe et votre application \
             d'authentification.",
        )
        .into_string(),
    )
    .into_response()
}

/// Rend le formulaire d'activation, en réutilisant le secret déjà proposé s'il y en a un.
///
/// Réutiliser le secret évite de faire rescanner un QR à chaque erreur de saisie ; en tirer un
/// nouveau à chaque tentative rendrait l'activation pratiquement impraticable.
fn render_activation(
    state: &AppState,
    user: &str,
    token: &str,
    secret: Option<&str>,
    error: Option<&str>,
) -> Response {
    let enrolment = match secret {
        Some(existing) => Zeroizing::new(existing.to_string()),
        None => match totp::enroll(user, &state.config.cluster_name) {
            Ok(e) => e.secret_base32,
            Err(e) => {
                warn!(erreur = %e, "enrôlement TOTP impossible");
                return internal_error();
            }
        },
    };

    let qr = match totp::enroll_url(user, &state.config.cluster_name, &enrolment) {
        Ok(url) => qr_svg(&url),
        Err(e) => {
            warn!(erreur = %e, "URL d'enrôlement impossible");
            return internal_error();
        }
    };

    Html(
        views::activate(
            user,
            token,
            &qr,
            &enrolment,
            password::MIN_LENGTH,
            error,
        )
        .into_string(),
    )
    .into_response()
}

// ---------------------------------------------------------------- connexion

async fn login_page(headers: HeaderMap, State(state): State<Shared>) -> Response {
    if current_user(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    Html(views::login(None).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    user: String,
    password: String,
    totp: String,
}

async fn login_submit(State(state): State<Shared>, Form(form): Form<LoginForm>) -> Response {
    match authenticate(&state, &form.user, &form.password, &form.totp).await {
        Ok(_) => {
            info!(user = %form.user, "connexion réussie");
            let token = state.signer.sign(
                purpose::SESSION,
                &form.user,
                (Utc::now() + SESSION_TTL).timestamp(),
            );
            (
                [(header::SET_COOKIE, session_cookie(&token, SESSION_TTL.num_seconds()))],
                Redirect::to("/"),
            )
                .into_response()
        }
        Err(reason) => {
            warn!(user = %form.user, raison = reason, "connexion refusée");
            (
                StatusCode::UNAUTHORIZED,
                Html(views::login(Some(GENERIC_AUTH_FAILURE)).into_string()),
            )
                .into_response()
        }
    }
}

/// Authentifie un compte par mot de passe et code TOTP.
///
/// Chemin unique pour le formulaire du portail et pour l'API du plugin `exec` : verrouillage,
/// anti-rejeu TOTP et remise à zéro du compteur ne doivent pas dépendre de la porte d'entrée.
/// La raison de l'échec est rendue à l'appelant pour le journal, jamais pour le visiteur.
async fn authenticate(
    state: &AppState,
    name: &str,
    password: &str,
    totp_code: &str,
) -> Result<KdtUser, &'static str> {
    let now = Utc::now();
    let user = state.users.get(name).await.map_err(|_| "compte inconnu")?;
    let credentials = state
        .store
        .get(name)
        .await
        .map_err(|_| "credentials illisibles")?
        .ok_or("aucun credential")?;

    if credentials.lockout.is_locked(now) {
        return Err("verrouillé");
    }
    if user.spec.disabled {
        return Err("compte désactivé");
    }
    let (Some(stored_hash), Some(totp_secret)) =
        (&credentials.password_hash, &credentials.totp_secret)
    else {
        return Err("compte non activé");
    };

    let password_ok = match password::verify(password, stored_hash) {
        Ok(ok) => ok,
        Err(e) => {
            // Empreinte illisible : ce n'est pas la faute de l'utilisateur, et ça demande une
            // intervention. Le journal doit le dire, le visiteur n'a pas à le savoir.
            warn!(user = %name, erreur = %e, "empreinte de mot de passe inutilisable");
            false
        }
    };

    // Le code TOTP est vérifié même si le mot de passe est faux. Ne le faire qu'en cas de
    // succès rendrait la réponse mesurablement plus rapide quand le mot de passe est mauvais,
    // ce qui distinguerait les deux cas malgré le message unique.
    let step = totp::verify(
        totp_secret,
        totp_code,
        now.timestamp() as u64,
        credentials.totp_last_step,
    );

    let (true, Ok(step)) = (password_ok, step) else {
        record_failure(state, &user, &credentials, now).await;
        return Err("mot de passe ou code invalide");
    };

    // Le pas TOTP est mémorisé : c'est ce qui rend le code inutilisable une seconde fois.
    let ok = Credentials {
        totp_last_step: Some(step),
        lockout: Lockout::default(),
        ..credentials.clone()
    };
    state
        .store
        .put(&user, &ok)
        .await
        .map_err(|_| "enregistrement du pas TOTP")?;

    Ok(user)
}

/// Incrémente le compteur d'échecs, ce qui déclenche le verrouillage progressif.
///
/// Un échec d'enregistrement n'interrompt pas le refus : mieux vaut un compteur en retard
/// qu'une authentification qui aboutit parce que le compteur n'a pas pu être écrit.
async fn record_failure(
    state: &AppState,
    user: &KdtUser,
    credentials: &Credentials,
    now: chrono::DateTime<Utc>,
) {
    let failed = Credentials {
        lockout: credentials.lockout.record_failure(now),
        ..credentials.clone()
    };
    if let Err(e) = state.store.put(user, &failed).await {
        warn!(erreur = %e, "compteur d'échecs non enregistré");
    }
}

async fn logout(headers: HeaderMap, State(state): State<Shared>) -> Response {
    if let Some(user) = current_user(&state, &headers) {
        info!(user = %user, "déconnexion");
    }
    (
        [(header::SET_COOKIE, session_cookie("", 0))],
        Redirect::to("/login"),
    )
        .into_response()
}

// ---------------------------------------------------------------- compte

async fn account_page(headers: HeaderMap, State(state): State<Shared>) -> Response {
    let Some(user) = current_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    render_account(&state, &user, None).await
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

async fn download_kubeconfig(
    headers: HeaderMap,
    State(state): State<Shared>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(user) = current_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if state
        .signer
        .verify(purpose::CSRF, &form.csrf, Utc::now().timestamp())
        .ok()
        .as_deref()
        != Some(user.as_str())
    {
        warn!(user = %user, "jeton anti-CSRF absent ou invalide");
        return (StatusCode::FORBIDDEN, "requête refusée").into_response();
    }

    // L'émission relit l'état courant : phase, désactivation et groupes. Une session ouverte
    // avant qu'un compte soit désactivé ne doit pas continuer à produire des certificats.
    let Ok(kdt_user) = state.users.get(&user).await else {
        return render_account(&state, &user, Some("Compte introuvable.")).await;
    };
    let Ok(Some(credentials)) = state.store.get(&user).await else {
        return render_account(&state, &user, Some("Compte non activé.")).await;
    };
    let phase = logic::phase(&kdt_user, credentials.is_activated());
    if !logic::may_request_own_credential(phase) {
        warn!(user = %user, ?phase, "émission refusée");
        return render_account(
            &state,
            &user,
            Some("Votre compte ne permet pas d'émettre un accès. Contactez votre administrateur."),
        )
        .await;
    }

    let (subject, group_subjects) = match subjects(&state, &user).await {
        Ok(pair) => pair,
        Err(message) => return render_account(&state, &user, Some(&message)).await,
    };

    let credential = match state
        .issuer
        .issue_with_generated_key(&subject, &group_subjects, CERT_TTL)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!(user = %user, erreur = %e, "émission du certificat en échec");
            return render_account(
                &state,
                &user,
                Some("L'émission du certificat a échoué. Réessayez dans un instant."),
            )
            .await;
        }
    };

    let yaml = match kubeconfig::standalone(&state.endpoint, &subject, &credential) {
        Ok(yaml) => yaml,
        Err(e) => {
            warn!(user = %user, erreur = %e, "assemblage du kubeconfig en échec");
            return internal_error();
        }
    };

    info!(user = %user, expire = %credential.not_after, "kubeconfig téléchargé");
    (
        [
            (header::CONTENT_TYPE, "application/yaml".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"{}-{}.kubeconfig\"",
                    state.endpoint.name, user
                ),
            ),
            // Un kubeconfig contient une clé privée : aucun cache, nulle part.
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        yaml,
    )
        .into_response()
}

async fn render_account(state: &AppState, user: &str, error: Option<&str>) -> Response {
    let (subject, groups) = match subjects(state, user).await {
        Ok((subject, groups)) => (
            subject.as_str().to_string(),
            groups.iter().map(|g| g.as_str().to_string()).collect(),
        ),
        Err(_) => (String::new(), Vec::new()),
    };

    let csrf = state.signer.sign(
        purpose::CSRF,
        user,
        (Utc::now() + SESSION_TTL).timestamp(),
    );

    Html(
        views::account(
            user,
            &subject,
            &groups,
            &state.config.cluster_name,
            &csrf,
            error,
        )
        .into_string(),
    )
    .into_response()
}

/// Sujet et groupes effectifs, relus depuis les `KdtGroup`.
///
/// Jamais repris de `status.memberOf` : ce statut n'est qu'un index entretenu par le
/// contrôleur, et ce qui décide du contenu d'un certificat doit venir de la source.
async fn subjects(state: &AppState, user: &str) -> Result<(Subject, Vec<Subject>), String> {
    let groups = state
        .groups
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("lecture des groupes : {e}"))?
        .items;

    let subject = Subject::user(user).map_err(|e| e.to_string())?;
    let group_subjects = logic::member_of(user, &groups)
        .iter()
        .map(|g| Subject::group(g))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok((subject, group_subjects))
}

// ---------------------------------------------------------------- API plugin

/// Durée de vie du jeton remis au plugin entre les deux appels.
///
/// Le temps de construire une demande de signature, pas davantage : ce jeton autorise
/// l'émission d'un certificat, il n'a aucune raison de survivre à l'échange.
const API_TOKEN_TTL: chrono::Duration = chrono::Duration::seconds(60);

/// Authentifie le plugin et lui rend de quoi construire sa demande.
///
/// Séparé de l'émission parce qu'un code TOTP ne sert qu'une fois : le plugin ne peut pas
/// s'authentifier deux fois de suite pour apprendre ses groupes puis demander son certificat.
async fn api_session(
    State(state): State<Shared>,
    axum::Json(request): axum::Json<SessionRequest>,
) -> Response {
    let user = match authenticate(&state, &request.user, &request.password, &request.totp).await {
        Ok(user) => user,
        Err(reason) => {
            warn!(user = %request.user, raison = reason, "session API refusée");
            return unauthorized_json();
        }
    };

    let phase = match state.store.get(&request.user).await {
        Ok(Some(credentials)) => logic::phase(&user, credentials.is_activated()),
        _ => return unauthorized_json(),
    };
    if !logic::may_request_own_credential(phase) {
        warn!(user = %request.user, ?phase, "session API refusée");
        return unauthorized_json();
    }

    let (subject, groups) = match subjects(&state, &request.user).await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(user = %request.user, erreur = %e, "groupes illisibles");
            return internal_error_json();
        }
    };

    info!(user = %request.user, "session API ouverte");
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(SessionResponse {
            token: state.signer.sign(
                purpose::API_CREDENTIAL,
                &request.user,
                (Utc::now() + API_TOKEN_TTL).timestamp(),
            ),
            subject: subject.as_str().to_string(),
            groups: groups.iter().map(|g| g.as_str().to_string()).collect(),
        }),
    )
        .into_response()
}

/// Émet un certificat pour une demande construite par le client.
///
/// Le sujet de la demande n'est pas cru sur parole : [`Issuer::issue_from_csr`] le confronte à
/// l'identité authentifiée, et les groupes sont **relus depuis le cluster** plutôt que repris
/// de ce que la session avait annoncé. Un groupe retiré entre les deux appels doit faire
/// échouer l'émission, pas se glisser dans un certificat valide huit heures.
async fn api_credential(
    State(state): State<Shared>,
    axum::Json(request): axum::Json<CredentialRequest>,
) -> Response {
    let Ok(name) = state
        .signer
        .verify(purpose::API_CREDENTIAL, &request.token, Utc::now().timestamp())
    else {
        warn!("jeton d'émission absent, invalide ou expiré");
        return unauthorized_json();
    };

    let (subject, groups) = match subjects(&state, &name).await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(user = %name, erreur = %e, "groupes illisibles");
            return internal_error_json();
        }
    };

    match state
        .issuer
        .issue_from_csr(&request.csr, &subject, &groups, CERT_TTL)
        .await
    {
        Ok(credential) => {
            info!(user = %name, expire = %credential.not_after, "credential émis pour le plugin");
            (
                [(header::CACHE_CONTROL, "no-store")],
                axum::Json(CredentialResponse {
                    certificate: credential.certificate_pem,
                    expires_at: credential.not_after.to_rfc3339(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            warn!(user = %name, erreur = %e, "émission refusée");
            // Un sujet qui ne correspond pas est une tentative, ou des groupes qui ont changé
            // entre les deux appels : dans les deux cas ce n'est pas une panne, et le
            // distinguer d'une 500 évite que ça se noie dans les erreurs d'exploitation.
            match e {
                crate::credentials::IssueError::SubjectMismatch(_) => (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "error": "la demande ne correspond pas à l'identité authentifiée"
                    })),
                )
                    .into_response(),
                _ => internal_error_json(),
            }
        }
    }
}

fn unauthorized_json() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": GENERIC_AUTH_FAILURE })),
    )
        .into_response()
}

fn internal_error_json() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({ "error": "émission impossible" })),
    )
        .into_response()
}

// ---------------------------------------------------------------- outils

/// Compte authentifié, s'il y en a un.
fn current_user(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    let token = cookies
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value)?;

    state
        .signer
        .verify(purpose::SESSION, token, Utc::now().timestamp())
        .ok()
}

/// Cookie de session.
///
/// `HttpOnly` le rend invisible au JavaScript, `Secure` interdit le transport en clair et
/// `SameSite=Strict` empêche qu'un autre site déclenche une action authentifiée — ce qui,
/// combiné au jeton anti-CSRF des formulaires, ferme les deux voies.
fn session_cookie(token: &str, max_age: i64) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"
    )
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            views::message(
                "Erreur",
                "Une erreur est survenue",
                "Réessayez dans un instant. Si le problème persiste, contactez votre \
                 administrateur.",
            )
            .into_string(),
        ),
    )
        .into_response()
}

/// Rend une URL `otpauth://` en QR code SVG, embarqué dans la page.
fn qr_svg(url: &str) -> String {
    use qrcode::render::svg;
    use qrcode::QrCode;

    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            let rendered = code
                .render::<svg::Color>()
                .min_dimensions(150, 150)
                .quiet_zone(true)
                .build();

            // Le rendu commence par un prologue `<?xml …?>`, correct pour un fichier SVG
            // autonome mais invalide au milieu d'un document HTML, où il est interprété comme
            // un commentaire bâtard. On ne garde que l'élément.
            match rendered.find("<svg") {
                Some(start) => rendered[start..].to_string(),
                None => rendered,
            }
        }
        Err(e) => {
            warn!(erreur = %e, "génération du QR impossible");
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_cookie_de_session_porte_toutes_ses_protections() {
        let cookie = session_cookie("abc", 3600);
        for attribut in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(cookie.contains(attribut), "{attribut} manquant : {cookie}");
        }
    }

    /// La déconnexion doit effacer le cookie, pas seulement rediriger.
    #[test]
    fn la_deconnexion_expire_le_cookie() {
        assert!(session_cookie("", 0).contains("Max-Age=0"));
    }

    /// Le SVG est inséré tel quel dans une page HTML : il doit être un élément, pas un
    /// document autonome avec son prologue XML.
    #[test]
    fn le_qr_est_un_element_svg_sans_prologue() {
        let svg = qr_svg("otpauth://totp/kdt-identity:alice?secret=JBSWY3DPEHPK3PXP");
        assert!(svg.starts_with("<svg"), "{svg}");
        assert!(!svg.contains("<?xml"), "{svg}");
        assert!(svg.ends_with("</svg>"), "{}", &svg[svg.len() - 40..]);
    }

    /// Les deux messages génériques ne doivent rien apprendre sur l'existence d'un compte.
    #[test]
    fn les_messages_d_echec_ne_distinguent_aucun_cas() {
        for message in [GENERIC_AUTH_FAILURE, GENERIC_ACTIVATION_FAILURE] {
            let bas = message.to_lowercase();
            for revelateur in ["n'existe pas", "inconnu", "introuvable", "désactivé"] {
                assert!(!bas.contains(revelateur), "{message:?} révèle trop");
            }
        }
    }
}

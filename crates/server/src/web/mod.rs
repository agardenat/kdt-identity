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
use crate::oidc::discovery::{self, DISCOVERY_PATH, JWKS_PATH};
use crate::oidc::key::JwkSet;
use crate::oidc::{jwt, SigningMaterial};
use crate::sessions::SessionStore;
use kdt_identity_api::portal::{
    CredentialMode, CredentialRequest, CredentialResponse, RevokeRequest, SessionGrant,
    SessionRequest, SessionResponse, TokenRequest, TokenResponse,
};
use kdt_identity_api::{KdtGroup, KdtUser};
use kube::api::{Api, ListParams};
use serde::Deserialize;
use signer::Signer;
use std::sync::Arc;
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

/// Message unique de tout échec d'authentification.
const GENERIC_AUTH_FAILURE: &str =
    "Compte, mot de passe ou code incorrect. Vérifiez vos identifiants et réessayez.";

const GENERIC_ACTIVATION_FAILURE: &str =
    "Ce lien ou ce code d'activation est invalide ou a expiré. Demandez une nouvelle invitation \
     à votre administrateur.";

/// Ce que le mode OIDC ajoute à l'état du portail : de quoi signer des jetons.
///
/// Absent en mode certificat, et les points d'accès correspondants ne sont alors pas montés du
/// tout, plutôt que montés et refusant tout. Un apiserver qui découvrirait un document de
/// découverte servi par un portail incapable d'émettre des jetons échouerait plus tard, et
/// plus obscurément.
///
/// Le magasin de sessions n'en fait pas partie : il sert dans les deux modes, puisque c'est de
/// lui que vient la révocation.
pub struct OidcState {
    pub material: SigningMaterial,
}

pub struct AppState {
    users: Api<KdtUser>,
    groups: Api<KdtGroup>,
    store: CredentialStore,
    sessions: SessionStore,
    issuer: Issuer,
    signer: Signer,
    endpoint: ClusterEndpoint,
    config: ServerConfig,
    oidc: Option<OidcState>,
}

type Shared = Arc<AppState>;

pub fn router(state: Shared) -> Router {
    let router = Router::new()
        .route("/", get(account_page))
        .route("/activate", get(activate_page).post(activate_submit))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/kubeconfig", post(download_kubeconfig))
        .route(kdt_identity_api::portal::SESSION_PATH, post(api_session))
        .route(kdt_identity_api::portal::CREDENTIAL_PATH, post(api_credential))
        // La fermeture de session vaut dans les deux modes : c'est le mécanisme de
        // renouvellement qu'elle coupe, pas la façon dont l'identité est ensuite matérialisée.
        .route(kdt_identity_api::portal::REVOKE_PATH, post(api_revoke))
        .route("/healthz", get(|| async { "ok" }));

    // Les points d'accès OIDC n'existent qu'en mode OIDC. Le document de découverte est
    // public et non authentifié : le servir sans pouvoir émettre de jeton inviterait un
    // administrateur à configurer un apiserver contre un émetteur inerte.
    let router = match state.oidc {
        None => router,
        Some(_) => router
            .route(DISCOVERY_PATH, get(discovery_document))
            .route(JWKS_PATH, get(jwks_document))
            .route(kdt_identity_api::portal::TOKEN_PATH, post(api_token)),
    };

    router.with_state(state)
}

pub fn state(
    client: kube::Client,
    config: ServerConfig,
    endpoint: ClusterEndpoint,
    signer: Signer,
    oidc: Option<OidcState>,
) -> Shared {
    Arc::new(AppState {
        users: Api::all(client.clone()),
        groups: Api::all(client.clone()),
        store: CredentialStore::new(client.clone(), &config.namespace),
        sessions: SessionStore::new(client.clone(), &config.namespace),
        issuer: Issuer::new(client),
        signer,
        endpoint,
        config,
        oidc,
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

    // La page n'affiche plus ce bouton quand le téléchargement est fermé, mais la route reste
    // atteignable. Émettre ici rendrait un accès de plusieurs heures que « revoke » ne peut
    // pas couper : exactement ce que la fermeture du téléchargement vise à empêcher.
    if !state.config.kubeconfig_download || state.config.credential_mode == CredentialMode::Oidc {
        warn!(user = %user, "téléchargement de kubeconfig refusé : mode oidc");
        return render_account(
            &state,
            &user,
            Some(
                "Le téléchargement d'un kubeconfig n'est pas proposé sur ce cluster. Utilisez \
                 le plugin kdt-identity, comme indiqué ci-dessous.",
            ),
        )
        .await;
    }

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
        .issue_with_generated_key(&subject, &group_subjects, state.config.download_cert_ttl)
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
        views::account(views::Account {
            user,
            subject: &subject,
            groups: &groups,
            cluster: &state.config.cluster_name,
            csrf: &csrf,
            error,
            mode: state.config.credential_mode,
            portal_url: &state.config.portal_url,
            download: state.config.kubeconfig_download
                && state.config.credential_mode == CredentialMode::Certificate,
        })
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

/// Ouvre une session pour le plugin et lui rend de quoi construire sa demande.
///
/// Séparé de l'émission parce qu'un code TOTP ne sert qu'une fois : le plugin ne peut pas
/// s'authentifier deux fois de suite pour apprendre ses groupes puis demander son credential.
///
/// Deux façons d'entrer, un seul chemin ensuite. Le mot de passe et le code ouvrent un droit
/// de renouveler ; ce droit rouvre une session sans rien redemander. Dans les deux cas l'état
/// du compte est relu depuis le cluster et ses groupes depuis les `KdtGroup` : c'est ce qui
/// fait qu'une désactivation ou un changement d'appartenance prend effet au renouvellement
/// suivant, sans attendre l'expiration de quoi que ce soit.
async fn api_session(
    State(state): State<Shared>,
    axum::Json(request): axum::Json<SessionRequest>,
) -> Response {
    let grant = match request.grant() {
        Ok(grant) => grant,
        Err(raison) => {
            warn!(user = %request.user, raison, "demande de session mal formée");
            return bad_request_json(raison);
        }
    };
    let now = Utc::now();

    // Une ouverture par mot de passe rend un droit de renouveler ; un renouvellement n'en rend
    // pas un second. Sans cela, une session volée se prolongerait indéfiniment d'elle-même.
    let ouvre_un_droit = match grant {
        SessionGrant::Password { password, totp } => {
            if let Err(reason) = authenticate(&state, &request.user, password, totp).await {
                warn!(user = %request.user, raison = reason, "session API refusée");
                return unauthorized_json();
            }
            true
        }
        SessionGrant::Refresh { refresh_token } => {
            let sessions = match state.sessions.get(&request.user).await {
                Ok(sessions) => sessions,
                Err(e) => {
                    warn!(user = %request.user, erreur = %e, "sessions illisibles");
                    return internal_error_json();
                }
            };
            if let Err(e) = sessions.verify(refresh_token, now) {
                // Refus d'identité, pas panne : le client doit repasser par une
                // authentification complète, et le distinguer lui évite de réessayer en boucle.
                warn!(user = %request.user, raison = %e, "renouvellement refusé");
                return unauthorized_json();
            }
            false
        }
    };

    // L'état courant fait foi, quelle que soit la porte d'entrée.
    let Ok(user) = state.users.get(&request.user).await else {
        warn!(user = %request.user, "compte introuvable");
        return unauthorized_json();
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

    let refresh = if ouvre_un_droit {
        let validity = chrono::Duration::from_std(state.config.refresh_ttl)
            .expect("durée bornée à la lecture de la configuration");
        match state
            .sessions
            .update(&user, |sessions| {
                let issued = sessions.open(now, validity);
                (issued.token.to_string(), issued.session.expires_at)
            })
            .await
        {
            Ok(pair) => Some(pair),
            Err(e) => {
                warn!(user = %request.user, erreur = %e, "ouverture de session impossible");
                return internal_error_json();
            }
        }
    } else {
        None
    };

    info!(user = %request.user, renouvellement = !ouvre_un_droit, "session API ouverte");
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(SessionResponse {
            token: state.signer.sign(
                purpose::API_CREDENTIAL,
                &request.user,
                (now + API_TOKEN_TTL).timestamp(),
            ),
            subject: subject.as_str().to_string(),
            groups: groups.iter().map(|g| g.as_str().to_string()).collect(),
            mode: state.config.credential_mode,
            refresh_token: refresh.as_ref().map(|(token, _)| token.clone()),
            refresh_expires_at: refresh.as_ref().map(|(_, at)| at.to_rfc3339()),
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
    // En mode OIDC, aucun certificat n'est émis : un client qui en demande un est un plugin
    // trop ancien pour connaître le mode, ou un client qui a ignoré ce que la session lui a
    // annoncé. Les deux méritent une réponse qui le dise.
    if state.config.credential_mode == CredentialMode::Oidc {
        warn!("demande de certificat sur un déploiement en mode oidc");
        return mode_mismatch_json(CredentialMode::Oidc);
    }

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
        .issue_from_csr(&request.csr, &subject, &groups, state.config.cert_ttl)
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

// ---------------------------------------------------------------- API OIDC

/// Le document de découverte, lu par l'apiserver pour trouver le JWKS.
///
/// Public et non authentifié : il ne contient aucun secret, et l'apiserver le récupère sans
/// identifiants. Le cache est court — l'émetteur ne change pas, mais une clé peut être
/// remplacée, et cinq minutes bornent la fenêtre pendant laquelle un intermédiaire servirait
/// une réponse périmée.
async fn discovery_document(State(state): State<Shared>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        axum::Json(discovery::document(&state.config.portal_url)),
    )
        .into_response()
}

/// Les clés publiques de vérification.
async fn jwks_document(State(state): State<Shared>) -> Response {
    let Some(oidc) = &state.oidc else {
        return mode_mismatch_json(CredentialMode::Certificate);
    };

    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        axum::Json(JwkSet {
            keys: vec![oidc.material.public_jwk()],
        }),
    )
        .into_response()
}

/// Émet un jeton d'identité pour une session déjà ouverte.
///
/// Le contrôle de l'état du compte a eu lieu à l'ouverture de session, quelques secondes plus
/// tôt : c'est la durée de vie du jeton présenté ici. Les groupes sont malgré tout relus, pour
/// la même raison qu'à l'émission d'un certificat — ce qui décide du contenu d'une identité
/// doit venir de la source, pas de ce qu'un appel précédent a annoncé.
async fn api_token(
    State(state): State<Shared>,
    axum::Json(request): axum::Json<TokenRequest>,
) -> Response {
    let Some(oidc) = &state.oidc else {
        return mode_mismatch_json(CredentialMode::Certificate);
    };
    let now = Utc::now();

    let Ok(name) = state
        .signer
        .verify(purpose::API_CREDENTIAL, &request.token, now.timestamp())
    else {
        warn!("jeton de session absent, invalide ou expiré");
        return unauthorized_json();
    };

    let (subject, groups) = match subjects(&state, &name).await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(user = %name, erreur = %e, "groupes illisibles");
            return internal_error_json();
        }
    };

    let ttl = chrono::Duration::from_std(state.config.oidc_token_ttl)
        .expect("durée bornée à la lecture de la configuration");
    match jwt::issue(
        &oidc.material,
        &state.config.portal_url,
        &state.config.oidc_audience,
        &subject,
        &groups,
        now,
        ttl,
    ) {
        Ok(issued) => {
            info!(user = %name, expire = %issued.expires_at, "jeton émis");
            (
                [(header::CACHE_CONTROL, "no-store")],
                axum::Json(TokenResponse {
                    id_token: issued.token,
                    expires_at: issued.expires_at.to_rfc3339(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            warn!(user = %name, erreur = %e, "signature du jeton en échec");
            internal_error_json()
        }
    }
}

/// Ferme une session : le jeton de renouvellement cesse immédiatement de valoir.
///
/// Présenter le jeton est l'autorisation : personne d'autre ne le détient. La réponse est la
/// même qu'il ait été fermé ou qu'il n'ait jamais existé — se déconnecter deux fois n'est pas
/// une erreur, et une réponse qui distinguerait les deux cas dirait à qui essaie s'il a mis la
/// main sur un jeton valide.
async fn api_revoke(
    State(state): State<Shared>,
    axum::Json(request): axum::Json<RevokeRequest>,
) -> Response {
    let Ok(user) = state.users.get(&request.user).await else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let now = Utc::now();

    let closed = state
        .sessions
        .update(&user, |sessions| match sessions.verify(&request.refresh_token, now) {
            Ok(id) => {
                sessions.close(&id);
                true
            }
            // Le ménage des sessions expirées a lieu quand même : c'est le seul moment où
            // quelqu'un regarde cette liste.
            Err(_) => {
                sessions.prune(now);
                false
            }
        })
        .await;

    match closed {
        Ok(true) => info!(user = %request.user, "session fermée"),
        Ok(false) => warn!(user = %request.user, "fermeture d'une session inconnue"),
        Err(e) => {
            warn!(user = %request.user, erreur = %e, "fermeture de session impossible");
            return internal_error_json();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Refus d'un point d'accès qui n'appartient pas au mode en service.
///
/// Ce n'est ni une panne ni un défaut d'identifiants : c'est un client qui parle le mauvais
/// protocole, et le lui dire explicitement évite de chercher une erreur d'authentification qui
/// n'existe pas.
fn mode_mismatch_json(expected: CredentialMode) -> Response {
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "error": format!(
                "ce cluster est en mode {expected} : ce point d'accès n'y est pas servi"
            )
        })),
    )
        .into_response()
}

/// Refus d'une demande mal formée. Le motif est rendu : ce n'est pas une question d'identité,
/// et le taire laisserait un client corriger à l'aveugle.
fn bad_request_json(reason: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": reason })),
    )
        .into_response()
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

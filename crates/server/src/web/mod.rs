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

pub mod authorize;
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
use crate::ldap::{provision, Directory, LdapError};
use kdt_identity_api::portal::{
    AuthMode, AuthorizeTokenRequest, CredentialMode, CredentialRequest, CredentialResponse,
    PortalDescriptor, RevokeRequest, SessionGrant, SessionRequest, SessionResponse, TokenRequest,
    TokenResponse,
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
    /// Code d'autorisation, remis au navigateur puis échangé par l'application.
    pub const AUTHORIZE_CODE: &str = "authorize-code";
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
    /// L'annuaire, si le mode d'authentification est `ldap`.
    ///
    /// Même raison que pour `oidc` : absent, les chemins qui en dépendent n'existent pas, plutôt
    /// que d'exister et de refuser.
    directory: Option<Directory>,
    /// L'application autorisée à demander des identités, si elle est déclarée.
    ///
    /// Absente — `webUrl` non renseignée — le flow d'autorisation n'est pas monté du tout. kdt-web
    /// est facultatif : un portail qui servirait `/authorize` sans connaître personne ne pourrait
    /// que refuser, et donnerait à croire qu'il manque une permission plutôt qu'une déclaration.
    client: Option<authorize::Client>,
    /// Les codes déjà échangés, pour qu'un code ne serve qu'une fois.
    used_codes: authorize::UsedCodes,
}

type Shared = Arc<AppState>;

pub fn router(state: Shared) -> Router {
    let router = Router::new()
        .route("/", get(account_page))
        .route("/login", get(login_page).post(login_submit))
        // Le descripteur est monté dans tous les modes et sans authentification : c'est ce que
        // le plugin lit pour savoir quoi demander, donc avant d'avoir quoi que ce soit à
        // présenter.
        .route(kdt_identity_api::portal::PORTAL_PATH, get(portal_descriptor))
        .route("/logout", post(logout))
        .route("/kubeconfig", post(download_kubeconfig))
        .route(kdt_identity_api::portal::SESSION_PATH, post(api_session))
        .route(kdt_identity_api::portal::CREDENTIAL_PATH, post(api_credential))
        // La fermeture de session vaut dans les deux modes : c'est le mécanisme de
        // renouvellement qu'elle coupe, pas la façon dont l'identité est ensuite matérialisée.
        .route(kdt_identity_api::portal::REVOKE_PATH, post(api_revoke))
        .route("/healthz", get(|| async { "ok" }));

    // L'activation n'existe que pour les comptes que le cluster porte. En mode ldap il n'y a ni
    // invitation, ni mot de passe à poser, ni TOTP à enrôler : servir la page inviterait à
    // définir un mot de passe que rien ne vérifierait jamais.
    let router = match state.config.auth_mode {
        AuthMode::Local => router.route("/activate", get(activate_page).post(activate_submit)),
        AuthMode::Ldap => router,
    };

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

    // Le flow d'autorisation n'existe que si une application est déclarée, pour la même raison :
    // monté sans client, il ne saurait que refuser.
    let router = match state.client {
        None => router,
        Some(_) => router
            .route(
                kdt_identity_api::portal::AUTHORIZE_PATH,
                get(authorize_page).post(authorize_submit),
            )
            .route(
                kdt_identity_api::portal::AUTHORIZE_TOKEN_PATH,
                post(api_authorize_token),
            ),
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
    let authorized = config.web_url.as_deref().map(authorize::Client::from_web_url);
    let directory = config.ldap.clone().map(Directory::new);

    Arc::new(AppState {
        directory,
        users: Api::all(client.clone()),
        groups: Api::all(client.clone()),
        store: CredentialStore::new(client.clone(), &config.namespace),
        sessions: SessionStore::new(client.clone(), &config.namespace),
        issuer: Issuer::new(client),
        signer,
        endpoint,
        config,
        oidc,
        client: authorized,
        used_codes: authorize::UsedCodes::new(),
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

#[derive(Deserialize)]
pub struct LoginQuery {
    /// Où reprendre après la connexion. Seul `/authorize?…` est accepté ; voir [`safe_next`].
    #[serde(default)]
    next: String,
}

async fn login_page(
    headers: HeaderMap,
    State(state): State<Shared>,
    Query(query): Query<LoginQuery>,
) -> Response {
    let next = safe_next(&query.next);
    if current_user(&state, &headers).is_some() {
        // Déjà connecté : on ne redemande rien, on reprend là où la demande allait.
        return Redirect::to(next.as_deref().unwrap_or("/")).into_response();
    }
    Html(views::login(None, next.as_deref()).into_string()).into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    user: String,
    password: String,
    totp: String,
    #[serde(default)]
    next: String,
}

async fn login_submit(State(state): State<Shared>, Form(form): Form<LoginForm>) -> Response {
    let next = safe_next(&form.next);
    let totp = (!form.totp.trim().is_empty()).then_some(form.totp.as_str());

    match authenticate(&state, &form.user, &form.password, totp).await {
        Ok(user) => {
            // Le cookie est signé pour le compte tel que le cluster le nomme, jamais tel qu'il
            // a été tapé : en mode ldap, l'identifiant saisi peut différer du nom du `KdtUser`
            // par sa casse, et une session signée pour un nom qui ne résout pas serait rejetée
            // à chaque page.
            let name = user.metadata.name.clone().unwrap_or_else(|| form.user.clone());
            info!(user = %name, "connexion réussie");
            let token = state.signer.sign(
                purpose::SESSION,
                &name,
                (Utc::now() + SESSION_TTL).timestamp(),
            );
            (
                [(header::SET_COOKIE, session_cookie(&token, SESSION_TTL.num_seconds()))],
                Redirect::to(next.as_deref().unwrap_or("/")),
            )
                .into_response()
        }
        Err(reason) => {
            warn!(user = %form.user, raison = reason, "connexion refusée");
            (
                StatusCode::UNAUTHORIZED,
                Html(views::login(Some(GENERIC_AUTH_FAILURE), next.as_deref()).into_string()),
            )
                .into_response()
        }
    }
}

/// Ce que le portail dit de lui-même, sans rien demander.
///
/// Non authentifié, et ce n'est pas un oubli : le client a besoin de ces valeurs *avant* d'avoir
/// quoi que ce soit à présenter. Rien de sensible n'y figure — ce sont les deux modes du
/// déploiement, que la page de connexion expose déjà par sa seule forme.
async fn portal_descriptor(State(state): State<Shared>) -> Response {
    axum::Json(PortalDescriptor {
        credential_mode: state.config.credential_mode,
        auth_mode: state.config.auth_mode,
        totp_required: state.config.auth_mode.totp_required(),
    })
    .into_response()
}

/// Authentifie un compte, quelle que soit la source qui porte son identité.
///
/// Chemin unique pour le formulaire du portail et pour l'API du plugin `exec` : verrouillage,
/// anti-rejeu TOTP et remise à zéro du compteur ne doivent pas dépendre de la porte d'entrée.
/// La raison de l'échec est rendue à l'appelant pour le journal, jamais pour le visiteur.
///
/// C'est aussi le seul endroit où le mode d'authentification se lit. Tout ce qui suit —
/// sessions, émission, sujets RBAC — ne sait pas comment l'identité a été prouvée, et n'a pas
/// à le savoir.
async fn authenticate(
    state: &AppState,
    name: &str,
    password: &str,
    totp_code: Option<&str>,
) -> Result<KdtUser, &'static str> {
    match state.config.auth_mode {
        AuthMode::Local => {
            // Un portail local sans code ne peut rien vérifier : le refuser ici évite qu'un
            // client mal configuré croie s'authentifier à un facteur.
            let totp_code = totp_code.ok_or("code attendu")?;
            authenticate_local(state, name, password, totp_code).await
        }
        AuthMode::Ldap => authenticate_ldap(state, name, password).await,
    }
}

/// Authentifie un compte porté par le cluster, par mot de passe et code TOTP.
async fn authenticate_local(
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

/// Authentifie un compte porté par un annuaire, et l'aligne sur ce que celui-ci déclare.
///
/// L'ordre des étapes n'est pas indifférent :
///
/// 1. le nom est normalisé d'abord, parce que c'est lui qui désigne le compteur d'échecs ;
/// 2. le verrou et `spec.disabled` sont lus **avant** de joindre l'annuaire — un compte coupé
///    ici ne doit pas produire de trafic vers l'annuaire, ni compter dans *sa* politique de
///    verrouillage ;
/// 3. le bind vient ensuite, et lui seul décide ;
/// 4. le compte et ses groupes ne sont écrits qu'après.
///
/// Une panne d'annuaire n'incrémente jamais le compteur d'échecs. Compter une indisponibilité
/// comme un mot de passe faux verrouillerait tous les comptes du cluster en quelques minutes,
/// et la panne survivrait alors à sa propre résolution.
async fn authenticate_ldap(
    state: &AppState,
    login: &str,
    password: &str,
) -> Result<KdtUser, &'static str> {
    let now = Utc::now();
    let Some(directory) = &state.directory else {
        return Err("annuaire non configuré");
    };

    let name = provision::normalize_login(login).map_err(|_| "identifiant hors du jeu accepté")?;

    let credentials = state
        .store
        .get(&name)
        .await
        .map_err(|_| "credentials illisibles")?
        .unwrap_or_default();

    if credentials.lockout.is_locked(now) {
        return Err("verrouillé");
    }

    // Le compte n'existe pas encore à la première connexion : c'est le cas nominal, pas une
    // erreur. Seul un compte déjà connu peut être désactivé.
    let existant = state
        .users
        .get_opt(&name)
        .await
        .map_err(|_| "lecture du compte")?;
    if existant.as_ref().is_some_and(|u| u.spec.disabled) {
        return Err("compte désactivé");
    }

    let directory_user = match directory.authenticate(login, password).await {
        Ok(user) => user,
        Err(LdapError::InvalidCredentials) => {
            // Le compteur ne peut s'écrire que sur un compte existant : le `Secret` est
            // rattaché au `KdtUser` par une `ownerReference`. Avant la première connexion
            // réussie, c'est donc la politique de l'annuaire qui protège, pas la nôtre.
            if let Some(user) = &existant {
                record_failure(state, user, &credentials, now).await;
            }
            return Err("identifiants refusés par l'annuaire");
        }
        Err(e @ LdapError::Unavailable(_)) => {
            warn!(erreur = %e, "annuaire injoignable");
            return Err("annuaire injoignable");
        }
        Err(e) => {
            warn!(login = %login, erreur = %e, "entrée d'annuaire inutilisable");
            return Err("entrée d'annuaire inutilisable");
        }
    };

    let user = provision::ensure_user(&state.users, &directory_user)
        .await
        .map_err(|e| {
            warn!(login = %login, erreur = %e, "compte non provisionné");
            "compte non provisionné"
        })?;

    // Un compte peut avoir été désactivé entre la lecture ci-dessus et maintenant, ou exister
    // déjà désactivé sans que la normalisation l'ait désigné — on revérifie sur l'objet réel.
    if user.spec.disabled {
        return Err("compte désactivé");
    }

    let mappings = &directory.config().group_mappings;
    let wanted = mappings.resolve(&directory_user.member_of);
    if let Err(e) = provision::sync_groups(
        &state.groups,
        &name,
        &wanted,
        &mappings.managed_groups(),
    )
    .await
    {
        // L'appartenance n'a pas pu être écrite, mais le mot de passe était bon. Refuser la
        // connexion sur cet échec donnerait des droits périmés à qui se connecte ensuite ;
        // l'accepter en silence donnerait des droits périmés tout court. On refuse : entre les
        // deux, seul le refus est visible.
        warn!(compte = %name, erreur = %e, "appartenance non synchronisée");
        return Err("appartenance non synchronisée");
    }

    // Le compteur d'échecs se remet à zéro comme en mode local. Rien d'autre n'est écrit : un
    // compte fédéré n'a ni empreinte de mot de passe ni secret TOTP à conserver.
    if credentials.lockout != Lockout::default() {
        let remis = Credentials {
            lockout: Lockout::default(),
            ..credentials
        };
        if let Err(e) = state.store.put(&user, &remis).await {
            warn!(erreur = %e, "compteur d'échecs non remis à zéro");
        }
    }

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
            web_url: state.config.web_url.as_deref(),
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

// ---------------------------------------------------------------- autorisation

/// Ouvre le flow : reconnaît la demande, puis demande l'accord de la personne.
///
/// L'ordre des contrôles n'est pas indifférent. Le client et l'adresse de retour sont validés
/// **avant** tout le reste, y compris avant de regarder s'il y a une session : tant qu'ils ne
/// sont pas reconnus, aucune redirection ne doit avoir lieu — pas même pour signaler l'erreur,
/// puisque rediriger vers une adresse non validée est précisément ce qu'il faut empêcher.
async fn authorize_page(
    headers: HeaderMap,
    State(state): State<Shared>,
    Query(query): Query<authorize::AuthorizeQuery>,
) -> Response {
    let redirect_uri = match authorize::check(&query, state.client.as_ref()) {
        Ok(uri) => uri,
        Err(e) => {
            warn!(client = %query.client_id, raison = %e, "demande d'autorisation refusée");
            return authorize_refused();
        }
    };

    let Some(user) = current_user(&state, &headers) else {
        // La personne n'est pas connectée : on l'y envoie, en gardant la demande pour reprendre
        // le flow après. Le chemin de retour est relatif et vérifié à l'arrivée.
        return Redirect::to(&login_with_next(&query, &redirect_uri)).into_response();
    };

    render_consent(&state, &user, &query, &redirect_uri, None).await
}

#[derive(Deserialize)]
pub struct ConsentForm {
    csrf: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
}

/// Émet le code et renvoie le navigateur vers l'application.
///
/// Les paramètres reviennent du formulaire, donc du navigateur : ils sont revalidés intégralement
/// plutôt que crus sur parole. Un formulaire est un aller-retour par le client, et ce qui en
/// revient n'a pas plus de valeur que ce qui arrive dans une URL.
async fn authorize_submit(
    headers: HeaderMap,
    State(state): State<Shared>,
    Form(form): Form<ConsentForm>,
) -> Response {
    let query = authorize::AuthorizeQuery {
        client_id: form.client_id,
        redirect_uri: form.redirect_uri,
        state: form.state,
        code_challenge: form.code_challenge,
        code_challenge_method: form.code_challenge_method,
    };

    let redirect_uri = match authorize::check(&query, state.client.as_ref()) {
        Ok(uri) => uri,
        Err(e) => {
            warn!(client = %query.client_id, raison = %e, "accord refusé");
            return authorize_refused();
        }
    };

    let Some(user) = current_user(&state, &headers) else {
        return Redirect::to(&login_with_next(&query, &redirect_uri)).into_response();
    };

    let now = Utc::now();
    if state
        .signer
        .verify(purpose::CSRF, &form.csrf, now.timestamp())
        .ok()
        .as_deref()
        != Some(user.as_str())
    {
        warn!(user = %user, "jeton anti-CSRF absent ou invalide");
        return (StatusCode::FORBIDDEN, "requête refusée").into_response();
    }

    // L'état du compte est relu ici, et le sera de nouveau à l'échange. Ce n'est pas redondant :
    // entre les deux, quelqu'un a pu poser `spec.disabled`, et un code déjà émis ne doit pas
    // valoir autorisation.
    match account_may_issue(&state, &user).await {
        Ok(()) => {}
        Err(message) => {
            warn!(user = %user, raison = %message, "autorisation refusée");
            return render_consent(&state, &user, &query, &redirect_uri, Some(&message)).await;
        }
    }

    let payload = authorize::CodePayload {
        u: user.clone(),
        c: query.client_id.clone(),
        r: redirect_uri.clone(),
        d: query.code_challenge.clone(),
        j: authorize::new_jti(),
    };
    let Ok(encoded) = serde_json::to_string(&payload) else {
        return internal_error();
    };
    let code = state.signer.sign(
        purpose::AUTHORIZE_CODE,
        &encoded,
        (now + authorize::CODE_TTL).timestamp(),
    );

    info!(user = %user, client = %query.client_id, "autorisation accordée");
    Redirect::to(&authorize::redirect_with_code(
        &redirect_uri,
        &code,
        &query.state,
    ))
    .into_response()
}

/// Échange un code d'autorisation contre un droit de session.
///
/// Appelé par l'application, pas par le navigateur : c'est ici que le code cesse d'être un
/// laissez-passer public — il faut le vérificateur, que seule l'application détient.
///
/// La session ouverte est une session ordinaire : elle apparaît dans le compte des sessions,
/// `revoke` la ferme, et `spec.disabled` la coupe. Rien ne la distingue de celle d'un poste, ce
/// qui est le point : il n'y a pas deux façons de révoquer.
async fn api_authorize_token(
    State(state): State<Shared>,
    axum::Json(request): axum::Json<AuthorizeTokenRequest>,
) -> Response {
    let now = Utc::now();

    let Ok(encoded) = state
        .signer
        .verify(purpose::AUTHORIZE_CODE, &request.code, now.timestamp())
    else {
        warn!("code d'autorisation absent, invalide ou expiré");
        return unauthorized_json();
    };
    let Ok(payload) = serde_json::from_str::<authorize::CodePayload>(&encoded) else {
        warn!("code d'autorisation illisible");
        return unauthorized_json();
    };

    // Le code enferme l'application et l'adresse de retour pour lesquelles il a été émis : un
    // code obtenu ailleurs ne s'échange pas ici.
    if payload.c != request.client_id || payload.r != request.redirect_uri {
        warn!(user = %payload.u, "code présenté pour une autre application ou une autre adresse");
        return unauthorized_json();
    }

    if let Err(e) = authorize::verify_pkce(&request.code_verifier, &payload.d) {
        warn!(user = %payload.u, raison = %e, "vérificateur refusé");
        return unauthorized_json();
    }

    // Consommé en dernier, une fois tout le reste vérifié : un code refusé pour une autre raison
    // n'a pas à être brûlé, sinon une requête malformée suffirait à couper une autorisation en
    // cours.
    if let Err(e) = state.used_codes.consume(
        &payload.j,
        (now + authorize::CODE_TTL).timestamp(),
        now.timestamp(),
    ) {
        warn!(user = %payload.u, raison = %e, "code rejoué");
        return unauthorized_json();
    }

    if let Err(message) = account_may_issue(&state, &payload.u).await {
        warn!(user = %payload.u, raison = %message, "échange refusé");
        return unauthorized_json();
    }

    let (subject, groups) = match subjects(&state, &payload.u).await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(user = %payload.u, erreur = %e, "groupes illisibles");
            return internal_error_json();
        }
    };

    let Ok(user) = state.users.get(&payload.u).await else {
        return unauthorized_json();
    };
    let validity = chrono::Duration::from_std(state.config.refresh_ttl)
        .expect("durée bornée à la lecture de la configuration");
    let refresh = match state
        .sessions
        .update(&user, |sessions| {
            let issued = sessions.open(now, validity);
            (issued.token.to_string(), issued.session.expires_at)
        })
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            warn!(user = %payload.u, erreur = %e, "ouverture de session impossible");
            return internal_error_json();
        }
    };

    info!(user = %payload.u, client = %payload.c, "session ouverte par autorisation");
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(SessionResponse {
            token: state.signer.sign(
                purpose::API_CREDENTIAL,
                &payload.u,
                (now + API_TOKEN_TTL).timestamp(),
            ),
            subject: subject.as_str().to_string(),
            groups: groups.iter().map(|g| g.as_str().to_string()).collect(),
            mode: state.config.credential_mode,
            refresh_token: Some(refresh.0),
            refresh_expires_at: Some(refresh.1.to_rfc3339()),
        }),
    )
        .into_response()
}

/// Le compte est-il en état d'obtenir une identité ?
///
/// Même contrôle qu'à l'ouverture d'une session par mot de passe, et pour la même raison : ce qui
/// décide est l'état courant du cluster, jamais ce qu'une étape précédente avait constaté.
async fn account_may_issue(state: &AppState, name: &str) -> Result<(), String> {
    let user = state
        .users
        .get(name)
        .await
        .map_err(|_| "compte introuvable".to_string())?;
    let credentials = state
        .store
        .get(name)
        .await
        .map_err(|_| "credentials illisibles".to_string())?
        .ok_or_else(|| "compte non activé".to_string())?;

    let phase = logic::phase(&user, credentials.is_activated());
    if !logic::may_request_own_credential(phase) {
        return Err(format!("phase {phase:?}"));
    }
    Ok(())
}

async fn render_consent(
    state: &AppState,
    user: &str,
    query: &authorize::AuthorizeQuery,
    redirect_uri: &str,
    error: Option<&str>,
) -> Response {
    let (subject, groups) = match subjects(state, user).await {
        Ok((subject, groups)) => (
            subject.as_str().to_string(),
            groups.iter().map(|g| g.as_str().to_string()).collect(),
        ),
        Err(_) => (String::new(), Vec::new()),
    };

    let csrf = state
        .signer
        .sign(purpose::CSRF, user, (Utc::now() + SESSION_TTL).timestamp());

    Html(
        views::consent(views::Consent {
            user,
            subject: &subject,
            groups: &groups,
            cluster: &state.config.cluster_name,
            application: &query.client_id,
            redirect_uri,
            csrf: &csrf,
            state: &query.state,
            code_challenge: &query.code_challenge,
            code_challenge_method: &query.code_challenge_method,
            refresh_ttl: &humanize(state.config.refresh_ttl),
            error,
        })
        .into_string(),
    )
    .into_response()
}

/// Refus d'une demande d'autorisation, rendu **sur le portail**.
///
/// Jamais par redirection : si l'adresse de retour n'a pas été reconnue, l'envoyer une erreur
/// reviendrait à s'en servir, ce que le refus vient justement d'interdire.
fn authorize_refused() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(
            views::message(
                "Demande refusée",
                "Cette demande d'accès n'est pas reconnue",
                "L'application qui vous a envoyé ici n'est pas celle déclarée sur ce cluster, ou \
                 son adresse de retour ne correspond pas. Prévenez votre administrateur plutôt \
                 que de réessayer.",
            )
            .into_string(),
        ),
    )
        .into_response()
}

/// Adresse de connexion qui ramène ensuite au flow.
///
/// Le chemin de retour est **reconstruit** à partir des paramètres validés, jamais recopié depuis
/// l'URL reçue : c'est ce qui garantit qu'il ne peut désigner que `/authorize`, avec des valeurs
/// déjà passées par `authorize::check`.
fn login_with_next(query: &authorize::AuthorizeQuery, redirect_uri: &str) -> String {
    let next = format!(
        "{}?client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method={}",
        kdt_identity_api::portal::AUTHORIZE_PATH,
        urlencode(&query.client_id),
        urlencode(redirect_uri),
        urlencode(&query.state),
        urlencode(&query.code_challenge),
        urlencode(&query.code_challenge_method),
    );
    format!("/login?next={}", urlencode(&next))
}

/// Le chemin de retour, s'il est acceptable.
///
/// Une seule forme est admise : un chemin relatif visant `/authorize`. Ni URL absolue, ni double
/// barre oblique — qui serait lue comme un hôte —, ni caractère de contrôle, qui permettrait
/// d'injecter une seconde en-tête dans la réponse. Tout le reste ramène à la racine, sans
/// message : ce n'est pas à l'utilisateur de comprendre ce qui a été refusé.
fn safe_next(raw: &str) -> Option<String> {
    let prefix = format!("{}?", kdt_identity_api::portal::AUTHORIZE_PATH);
    if !raw.starts_with(&prefix) {
        return None;
    }
    if raw.contains(['\r', '\n']) || raw.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(raw.to_string())
}

/// Écrit une durée comme le chart la déclare : `7d`, `12h`, `30m`.
fn humanize(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    if seconds.is_multiple_of(86_400) {
        format!("{}d", seconds / 86_400)
    } else if seconds.is_multiple_of(3_600) {
        format!("{}h", seconds / 3_600)
    } else if seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
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

    // Le compte tel que le cluster le nomme. En mode local c'est ce qui a été envoyé ; en mode
    // ldap l'identifiant saisi peut en différer, et tout ce qui suit — sessions, credentials,
    // groupes — se lit sous le nom du `KdtUser`, jamais sous celui qui a été tapé.
    let mut name = match state.config.auth_mode {
        AuthMode::Local => request.user.clone(),
        AuthMode::Ldap => {
            provision::normalize_login(&request.user).unwrap_or_else(|_| request.user.clone())
        }
    };

    // Une ouverture par mot de passe rend un droit de renouveler ; un renouvellement n'en rend
    // pas un second. Sans cela, une session volée se prolongerait indéfiniment d'elle-même.
    let ouvre_un_droit = match grant {
        SessionGrant::Password { password, totp } => {
            match authenticate(&state, &request.user, password, totp).await {
                Ok(user) => {
                    if let Some(canonique) = user.metadata.name {
                        name = canonique;
                    }
                }
                Err(reason) => {
                    warn!(user = %request.user, raison = reason, "session API refusée");
                    return unauthorized_json();
                }
            }
            true
        }
        SessionGrant::Refresh { refresh_token } => {
            let sessions = match state.sessions.get(&name).await {
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
    let Ok(user) = state.users.get(&name).await else {
        warn!(user = %name, "compte introuvable");
        return unauthorized_json();
    };
    // Un compte fédéré n'a pas de credentials locaux : l'absence de `Secret` est son état
    // normal, pas un compte à moitié créé.
    let phase = match state.store.get(&name).await {
        Ok(credentials) => logic::phase(
            &user,
            credentials.map(|c| c.is_activated()).unwrap_or(false),
        ),
        Err(_) => return unauthorized_json(),
    };
    if !logic::may_request_own_credential(phase) {
        warn!(user = %name, ?phase, "session API refusée");
        return unauthorized_json();
    }

    let (subject, groups) = match subjects(&state, &name).await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(user = %name, erreur = %e, "groupes illisibles");
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

    info!(user = %name, renouvellement = !ouvre_un_droit, "session API ouverte");
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(SessionResponse {
            // Signé pour le nom du compte, pas pour celui qui a été envoyé : c'est ce jeton que
            // l'émission reverifiera, et il doit désigner la même identité que le sujet
            // ci-dessous.
            token: state.signer.sign(
                purpose::API_CREDENTIAL,
                &name,
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

    /// Le chemin de retour après connexion est la porte d'entrée d'une redirection ouverte : ce
    /// qui n'est pas exactement `/authorize?…` ne doit jamais sortir d'ici.
    #[test]
    fn le_retour_apres_connexion_n_accepte_que_l_autorisation() {
        assert_eq!(
            safe_next("/authorize?client_id=kdt-web&state=x"),
            Some("/authorize?client_id=kdt-web&state=x".to_string())
        );

        for hostile in [
            "https://evil.test/",
            "//evil.test/",
            "/authorize",
            "/authorizeevil?x=1",
            "/",
            "",
            "javascript:alert(1)",
            "/logout",
            "\\/evil.test",
            // Injection d'en-tête : un saut de ligne dans un `Location` ajouterait une seconde
            // en-tête à la réponse.
            "/authorize?a=1\r\nSet-Cookie: x=y",
            "/authorize?a=1\nLocation: https://evil.test",
        ] {
            assert_eq!(safe_next(hostile), None, "{hostile:?} accepté à tort");
        }
    }

    /// Le chemin de retour est reconstruit à partir de valeurs déjà validées, jamais recopié :
    /// c'est ce qui garantit qu'il ne peut désigner que `/authorize`.
    #[test]
    fn le_retour_se_reconstruit_encode() {
        let query = authorize::AuthorizeQuery {
            client_id: "kdt-web".to_string(),
            redirect_uri: "https://kdt.example.com/auth/callback".to_string(),
            state: "a&b=c".to_string(),
            code_challenge: "abc".to_string(),
            code_challenge_method: "S256".to_string(),
        };
        let url = login_with_next(&query, &query.redirect_uri);

        assert!(url.starts_with("/login?next=%2Fauthorize%3F"), "{url}");
        assert!(!url.contains("a&b=c"), "l'état doit être encodé : {url}");

        // Et ce qui en sort doit repasser le contrôle d'entrée.
        let next = url.strip_prefix("/login?next=").unwrap();
        let decoded = next
            .replace("%2F", "/")
            .replace("%3F", "?")
            .replace("%3D", "=")
            .replace("%26", "&");
        assert!(safe_next(&decoded).is_some(), "{decoded}");
    }

    #[test]
    fn une_duree_s_ecrit_comme_le_chart_la_declare() {
        use std::time::Duration;
        assert_eq!(humanize(Duration::from_secs(7 * 86_400)), "7d");
        assert_eq!(humanize(Duration::from_secs(12 * 3_600)), "12h");
        assert_eq!(humanize(Duration::from_secs(30 * 60)), "30m");
        assert_eq!(humanize(Duration::from_secs(90)), "90s");
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

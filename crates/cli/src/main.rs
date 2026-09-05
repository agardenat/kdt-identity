//! Plugin `exec` de kubeconfig pour kdt-identity.
//!
//! `kubectl` appelle ce binaire quand il a besoin d'un credential, lit un `ExecCredential` sur
//! sa sortie standard, et s'en sert pour la requête. Ce détour a une raison précise : **la clé
//! privée est engendrée ici et ne quitte jamais le poste**. Seule la demande de signature part
//! sur le réseau, ce que le téléchargement d'un kubeconfig depuis le navigateur ne permet pas.
//!
//! Le certificat obtenu est mis en cache jusqu'à son expiration. Sans cela, chaque `kubectl`
//! redemanderait un mot de passe et un code TOTP, ce qui pousserait à allonger les durées de
//! vie — c'est-à-dire à défaire ce que leur brièveté protège.

mod cache;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use kdt_identity_api::csr;
use kdt_identity_api::naming::Subject;
use kdt_identity_api::portal::{
    CredentialMode, CredentialRequest, CredentialResponse, RevokeRequest, SessionRequest,
    SessionResponse, TokenRequest, TokenResponse, CREDENTIAL_PATH, REVOKE_PATH, SESSION_PATH,
    TOKEN_PATH,
};
use serde::Serialize;
use std::io::Write;

#[derive(Parser)]
#[command(
    name = "kdt-identity",
    version,
    about = "Plugin d'authentification kubectl pour kdt-identity"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Rend un ExecCredential à kubectl, en réutilisant le cache si possible.
    Credential {
        /// Racine du portail, par exemple `https://identity.example.com`.
        #[arg(long, env = "KDT_IDENTITY_PORTAL_URL")]
        portal: String,

        /// Nom du compte, sans le préfixe.
        #[arg(long)]
        user: String,
    },

    /// Force une nouvelle authentification en effaçant le cache.
    Logout {
        #[arg(long, env = "KDT_IDENTITY_PORTAL_URL")]
        portal: String,
        #[arg(long)]
        user: String,
    },

    /// Écrit sur la sortie standard un kubeconfig utilisant ce plugin.
    Kubeconfig {
        #[arg(long, env = "KDT_IDENTITY_PORTAL_URL")]
        portal: String,
        #[arg(long)]
        user: String,
        /// Nom du cluster dans le kubeconfig produit.
        #[arg(long)]
        cluster: String,
        /// URL de l'apiserver.
        #[arg(long)]
        server: String,
        /// Fichier PEM de l'autorité de certification du cluster.
        #[arg(long)]
        ca_file: String,
    },
}

/// Ce que `kubectl` attend sur la sortie standard.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredential {
    api_version: &'static str,
    kind: &'static str,
    status: ExecCredentialStatus,
}

/// Un `ExecCredential` porte soit un certificat et sa clé, soit un jeton — jamais les deux.
///
/// Les champs inutilisés sont omis plutôt que vides : client-go tente de lire tout champ
/// présent, et une chaîne vide là où il attend du PEM échoue sur « failed to find any PEM
/// data » plutôt que sur ce qui manque réellement.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredentialStatus {
    expiration_timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_certificate_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_key_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 refuse de choisir seul son fournisseur cryptographique dès que plusieurs
    // sont compilables, et panique au premier handshake sinon.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match Cli::parse().command {
        Command::Credential { portal, user } => credential(&portal, &user).await,
        Command::Logout { portal, user } => logout(&portal, &user).await,
        Command::Kubeconfig {
            portal,
            user,
            cluster,
            server,
            ca_file,
        } => print_kubeconfig(&portal, &user, &cluster, &server, &ca_file),
    }
}

async fn credential(portal: &str, user: &str) -> anyhow::Result<()> {
    let portal = portal.trim_end_matches('/');
    let path = cache::path(portal, user)?;
    let now = chrono::Utc::now();
    let cached = cache::read(&path);

    if let Some(cached) = &cached {
        if cached.is_fresh(now) {
            return emit(cached);
        }
    }

    // Le renouvellement silencieux d'abord. C'est lui qui rend les durées courtes tenables :
    // sans lui, un credential de dix minutes redemanderait un mot de passe six fois par heure.
    if let Some(refresh) = cached.as_ref().and_then(|c| c.usable_refresh(now)) {
        match obtain(portal, SessionRequest::refresh(user, &refresh.token), Some(refresh)).await {
            Ok(fresh) => {
                store(&path, &fresh);
                return emit(&fresh);
            }
            // Refus explicite : session révoquée, compte désactivé, ou jeton inconnu. Se
            // ré-authentifier est la suite normale, pas un échec.
            Err(Attempt::Refused(raison)) => {
                eprintln!("kdt-identity : renouvellement refusé ({raison})");
            }
            // Une panne du portail ne doit pas se traduire par une demande de mot de passe :
            // la saisie serait perdue, et l'utilisateur croirait ses identifiants en cause.
            Err(Attempt::Unreachable(e)) => return Err(e),
        }
    }

    let (password, totp) = prompt_credentials(user, portal)?;
    let fresh = obtain(
        portal,
        SessionRequest::password(user, &password, &totp),
        None,
    )
    .await
    .map_err(|e| match e {
        Attempt::Refused(raison) => anyhow::anyhow!("{raison}"),
        Attempt::Unreachable(e) => e,
    })?;

    store(&path, &fresh);
    emit(&fresh)
}

/// Écrit le cache sans faire échouer la commande en cas de problème.
///
/// Un échec d'écriture ne doit pas priver l'utilisateur du credential qu'il vient d'obtenir :
/// il paiera une authentification de plus, rien de pire.
fn store(path: &std::path::Path, credential: &cache::CachedCredential) {
    if let Err(e) = cache::write(path, credential) {
        eprintln!("kdt-identity : cache non écrit ({e})");
    }
}

/// Ce qui peut arriver à une tentative, et qui ne se traite pas pareil.
enum Attempt {
    /// Le serveur a répondu, et il refuse.
    Refused(String),
    /// Le serveur n'a pas répondu, ou a répondu autre chose. Rien ne sert d'insister.
    Unreachable(anyhow::Error),
}

/// Ouvre une session et en tire un credential utilisable.
///
/// L'échange se fait en deux temps, et pas par confort : le sujet d'un certificat X.509 est
/// fixé dans la demande, signée par une clé que seul ce processus détient. Le portail ne peut
/// donc pas corriger un sujet incomplet — il ne peut que l'accepter ou le refuser. Le plugin
/// doit connaître ses groupes **avant** de signer, et un code TOTP ne servant qu'une fois, il
/// ne peut pas s'authentifier deux fois pour les apprendre.
///
/// `kept_refresh` est le droit de renouveler déjà en cache : le portail ne le renvoie qu'à une
/// ouverture par mot de passe, et le perdre ici imposerait une saisie à chaque expiration.
async fn obtain(
    portal: &str,
    request: SessionRequest,
    kept_refresh: Option<&cache::CachedRefresh>,
) -> Result<cache::CachedCredential, Attempt> {
    let http = reqwest::Client::new();
    let user = request.user.clone();

    let response = http
        .post(format!("{portal}{SESSION_PATH}"))
        .json(&request)
        .send()
        .await
        .map_err(|e| {
            Attempt::Unreachable(anyhow::Error::new(e).context(format!("appel du portail {portal}")))
        })?;

    // Tout refus du serveur conduit à une authentification complète, pas à un échec : session
    // révoquée (401), ou déploiement dont le contrat a changé (400, 404, 409).
    if response.status().is_client_error() {
        let status = response.status();
        let detail = error_detail(response).await;
        return Err(Attempt::Refused(match status.as_u16() {
            401 => "compte, mot de passe, code ou session invalide".to_string(),
            _ => detail,
        }));
    }

    let session: SessionResponse = read_json(response).await.map_err(Attempt::Unreachable)?;

    let subject = Subject::user(&user)
        .context("nom de compte invalide")
        .map_err(Attempt::Unreachable)?;
    if session.subject != subject.as_str() {
        // Le portail désigne quelqu'un d'autre que ce qui a été demandé : construire une
        // demande là-dessus reviendrait à réclamer une identité qui n'est pas la nôtre.
        return Err(Attempt::Unreachable(anyhow::anyhow!(
            "le portail a répondu pour {} alors que {} était demandé",
            session.subject,
            subject.as_str()
        )));
    }

    let refresh = match (&session.refresh_token, &session.refresh_expires_at) {
        (Some(token), Some(expires_at)) => Some(cache::CachedRefresh {
            token: token.clone(),
            expires_at: parse_time(expires_at).map_err(Attempt::Unreachable)?,
        }),
        // Un renouvellement ne rend pas de nouveau droit : celui du cache reste en vigueur.
        _ => kept_refresh.cloned(),
    };

    let groups = session
        .groups
        .iter()
        .map(|g| {
            g.strip_prefix(kdt_identity_api::naming::SUBJECT_PREFIX)
                .ok_or_else(|| anyhow::anyhow!("groupe {g:?} sans préfixe attendu"))
                .and_then(|name| Ok(Subject::group(name)?))
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(Attempt::Unreachable)?;

    let material = match session.mode {
        CredentialMode::Certificate => {
            certificate(&http, portal, &subject, &groups, session.token).await
        }
        CredentialMode::Oidc => token(&http, portal, session.token).await,
    }
    .map_err(Attempt::Unreachable)?;

    Ok(cache::CachedCredential {
        material: material.0,
        expires_at: material.1,
        refresh,
    })
}

/// Fait signer une demande construite localement, et rend le certificat obtenu.
///
/// Le portail relit les groupes depuis le cluster et refusera si l'appartenance a changé entre
/// les deux appels — auquel cas il suffit de recommencer.
async fn certificate(
    http: &reqwest::Client,
    portal: &str,
    subject: &Subject,
    groups: &[Subject],
    session_token: String,
) -> anyhow::Result<(cache::Material, chrono::DateTime<chrono::Utc>)> {
    let generated = csr::generate(subject, groups).context("génération de la demande")?;

    let issued: CredentialResponse = read_json(
        http.post(format!("{portal}{CREDENTIAL_PATH}"))
            .json(&CredentialRequest {
                token: session_token,
                csr: generated.csr_pem.clone(),
            })
            .send()
            .await
            .with_context(|| format!("appel du portail {portal}"))?,
    )
    .await?;

    Ok((
        cache::Material::Certificate {
            certificate_pem: issued.certificate,
            // La clé n'a jamais quitté ce processus : elle rejoint le cache, pas le réseau.
            key_pem: generated.key_pem.to_string(),
        },
        parse_time(&issued.expires_at)?,
    ))
}

/// Obtient un jeton d'identité signé par le portail.
///
/// Aucune demande de signature ici : le sujet du jeton est décidé par le portail, qui le signe
/// lui-même. Le client n'a rien à construire ni à prouver au-delà de sa session.
async fn token(
    http: &reqwest::Client,
    portal: &str,
    session_token: String,
) -> anyhow::Result<(cache::Material, chrono::DateTime<chrono::Utc>)> {
    let issued: TokenResponse = read_json(
        http.post(format!("{portal}{TOKEN_PATH}"))
            .json(&TokenRequest {
                token: session_token,
            })
            .send()
            .await
            .with_context(|| format!("appel du portail {portal}"))?,
    )
    .await?;

    Ok((
        cache::Material::Token {
            id_token: issued.id_token,
        },
        parse_time(&issued.expires_at)?,
    ))
}

/// Extrait le message d'erreur d'une réponse, ou rend le corps brut.
async fn error_detail(response: reqwest::Response) -> String {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("le portail a refusé la demande ({status})"))
}

fn parse_time(raw: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("date {raw:?} illisible"))?
        .with_timezone(&chrono::Utc))
}

/// Lit une réponse JSON, en remontant le message du portail plutôt qu'un code nu.
async fn read_json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> anyhow::Result<T> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or(body);
        bail!("le portail a refusé la demande ({status}) : {detail}");
    }

    serde_json::from_str(&body).context("réponse du portail illisible")
}

/// Demande mot de passe et code TOTP sur le terminal de contrôle.
///
/// Les deux saisies passent par `/dev/tty`, jamais par l'entrée standard : `kubectl` invoque ce
/// plugin avec ses propres tubes, et lire sur stdin capterait ce qui était destiné à la
/// commande — ou bloquerait indéfiniment sur un tube que personne n'alimente.
fn prompt_credentials(user: &str, portal: &str) -> anyhow::Result<(String, String)> {
    use std::io::{BufRead, BufReader};

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            anyhow::anyhow!(
                "authentification nécessaire pour {user} sur {portal}, mais aucun terminal \
                 n'est disponible. Lancez une commande interactive pour renouveler le credential."
            )
        })?;

    writeln!(tty, "Authentification kdt-identity — {user} sur {portal}")?;

    // La saisie du mot de passe est masquée par rpassword, qui lit lui aussi sur /dev/tty.
    let password = rpassword::prompt_password("Mot de passe : ")
        .context("lecture du mot de passe")?;

    write!(tty, "Code à 6 chiffres : ")?;
    tty.flush()?;

    let mut totp = String::new();
    BufReader::new(&tty)
        .read_line(&mut totp)
        .context("lecture du code")?;

    Ok((password, totp.trim().to_string()))
}

fn emit(credential: &cache::CachedCredential) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string(&exec_credential(credential))?);
    Ok(())
}

/// Met le credential dans la forme que `kubectl` attend.
///
/// Le PEM part tel quel. Contrairement aux champs `*-data` d'un kubeconfig, ceux d'un
/// `ExecCredential` ne sont pas encodés en base64 : client-go les lit directement comme du
/// PEM, et un base64 supplémentaire lui fait répondre « failed to find any PEM data ».
fn exec_credential(credential: &cache::CachedCredential) -> ExecCredential {
    let status = match &credential.material {
        cache::Material::Certificate {
            certificate_pem,
            key_pem,
        } => ExecCredentialStatus {
            expiration_timestamp: credential.expires_at.to_rfc3339(),
            client_certificate_data: Some(certificate_pem.clone()),
            client_key_data: Some(key_pem.clone()),
            token: None,
        },
        cache::Material::Token { id_token } => ExecCredentialStatus {
            expiration_timestamp: credential.expires_at.to_rfc3339(),
            client_certificate_data: None,
            client_key_data: None,
            token: Some(id_token.clone()),
        },
    };

    ExecCredential {
        api_version: "client.authentication.k8s.io/v1",
        kind: "ExecCredential",
        status,
    }
}

/// Efface le credential local et, en mode OIDC, ferme la session côté serveur.
///
/// Les deux comptent, et pas également : effacer le fichier empêche ce poste de s'en resservir,
/// fermer la session empêche quiconque aurait copié le jeton de continuer. En mode certificat,
/// il n'y a rien à fermer — c'est précisément ce que ce mode ne sait pas faire.
async fn logout(portal: &str, user: &str) -> anyhow::Result<()> {
    let portal = portal.trim_end_matches('/');
    let path = cache::path(portal, user)?;

    if let Some(refresh) = cache::read(&path).and_then(|c| c.refresh) {
        match revoke(portal, user, &refresh.token).await {
            Ok(()) => eprintln!("session fermée sur le portail"),
            // Le cache est effacé quoi qu'il arrive : laisser un credential utilisable sur le
            // poste parce que le portail est injoignable serait le pire des deux mondes.
            Err(e) => eprintln!("kdt-identity : session non fermée sur le portail ({e:#})"),
        }
    }

    match std::fs::remove_file(&path) {
        Ok(()) => eprintln!("credential effacé"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("aucun credential en cache")
        }
        Err(e) => bail!("suppression de {} : {e}", path.display()),
    }
    Ok(())
}

async fn revoke(portal: &str, user: &str, refresh_token: &str) -> anyhow::Result<()> {
    let response = reqwest::Client::new()
        .post(format!("{portal}{REVOKE_PATH}"))
        .json(&RevokeRequest {
            user: user.to_string(),
            refresh_token: refresh_token.to_string(),
        })
        .send()
        .await
        .with_context(|| format!("appel du portail {portal}"))?;

    if !response.status().is_success() {
        bail!("le portail a refusé la fermeture ({})", response.status());
    }
    Ok(())
}

fn print_kubeconfig(
    portal: &str,
    user: &str,
    cluster: &str,
    server: &str,
    ca_file: &str,
) -> anyhow::Result<()> {
    print!("{}", kubeconfig_yaml(portal, user, cluster, server, ca_file)?);
    Ok(())
}

/// Construit le kubeconfig en mode `exec`.
///
/// Aucun `proxy-url` : atteindre l'apiserver est une propriété du poste, pas du cluster. Qui
/// passe par un tunnel l'ajoute lui-même.
fn kubeconfig_yaml(
    portal: &str,
    user: &str,
    cluster: &str,
    server: &str,
    ca_file: &str,
) -> anyhow::Result<String> {
    use base64::Engine;

    let ca = std::fs::read_to_string(ca_file)
        .with_context(|| format!("lecture de {ca_file}"))?;
    let subject = Subject::user(user).context("nom de compte invalide")?;
    let context_name = format!("{}@{cluster}", subject.as_str());

    let config = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": cluster,
            "cluster": {
                "server": server,
                "certificate-authority-data":
                    base64::engine::general_purpose::STANDARD.encode(ca.as_bytes()),
            }
        }],
        "users": [{
            "name": subject.as_str(),
            "user": {
                "exec": {
                    "apiVersion": "client.authentication.k8s.io/v1",
                    "command": "kdt-identity",
                    "args": ["credential", "--portal", portal, "--user", user],
                    "interactiveMode": "IfAvailable",
                    "provideClusterInfo": false,
                }
            }
        }],
        "contexts": [{
            "name": context_name,
            "context": { "cluster": cluster, "user": subject.as_str() }
        }],
        "current-context": context_name,
    });

    Ok(serde_yaml::to_string(&config)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> cache::CachedCredential {
        cache::CachedCredential {
            material: cache::Material::Certificate {
                certificate_pem: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
                    .to_string(),
                key_pem: "-----BEGIN PRIVATE KEY-----\nWFla\n-----END PRIVATE KEY-----\n"
                    .to_string(),
            },
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-08-21T20:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            refresh: None,
        }
    }

    fn jeton() -> cache::CachedCredential {
        cache::CachedCredential {
            material: cache::Material::Token {
                id_token: "en-tete.charge.signature".to_string(),
            },
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-08-21T20:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            refresh: Some(cache::CachedRefresh {
                token: "id.secret".to_string(),
                expires_at: chrono::DateTime::parse_from_rfc3339("2026-08-28T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            }),
        }
    }

    fn rendu(credential: &cache::CachedCredential) -> serde_json::Value {
        serde_json::from_str(&serde_json::to_string(&exec_credential(credential)).unwrap()).unwrap()
    }

    /// `kubectl` refuse un ExecCredential qui ne porte pas exactement ces champs, et lit le
    /// certificat comme du PEM brut — pas comme du base64, à la différence d'un kubeconfig.
    #[test]
    fn l_exec_credential_porte_le_pem_tel_quel() {
        let json = rendu(&credential());

        assert_eq!(json["apiVersion"], "client.authentication.k8s.io/v1");
        assert_eq!(json["kind"], "ExecCredential");
        assert!(json["status"]["expirationTimestamp"].as_str().is_some());

        let cert = json["status"]["clientCertificateData"].as_str().unwrap();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"), "{cert}");

        let key = json["status"]["clientKeyData"].as_str().unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"), "{key}");
    }

    /// En mode OIDC, `kubectl` attend un jeton et rien d'autre. Un champ de certificat présent
    /// mais vide le fait échouer sur « failed to find any PEM data », qui ne dit pas ce qui
    /// manque réellement.
    #[test]
    fn l_exec_credential_d_un_jeton_ne_porte_que_le_jeton() {
        let json = rendu(&jeton());

        assert_eq!(json["status"]["token"], "en-tete.charge.signature");
        assert!(json["status"].get("clientCertificateData").is_none(), "{json}");
        assert!(json["status"].get("clientKeyData").is_none(), "{json}");
    }

    /// Le jeton de rafraîchissement reste sur le poste : il ne doit jamais partir vers
    /// `kubectl`, qui n'en a pas l'usage et l'écrirait dans ses propres journaux de débogage.
    #[test]
    fn le_rafraichissement_ne_sort_pas_du_plugin() {
        let json = serde_json::to_string(&exec_credential(&jeton())).unwrap();
        assert!(!json.contains("id.secret"), "{json}");
    }

    /// Un certificat n'a pas de jeton, et réciproquement : les deux champs ne doivent jamais
    /// se retrouver ensemble, quelle que soit la forme du cache.
    #[test]
    fn les_deux_formes_s_excluent() {
        let json = rendu(&credential());
        assert!(json["status"].get("token").is_none(), "{json}");
    }

    /// Le kubeconfig produit ne doit contenir aucun secret : c'est tout l'intérêt du mode
    /// `exec` par rapport au téléchargement depuis le navigateur.
    #[test]
    fn le_kubeconfig_en_mode_exec_ne_porte_aucun_secret() {
        let dir = std::env::temp_dir().join(format!("kdt-kc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.crt");
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n")
            .unwrap();

        // La sortie passe par stdout : on vérifie ici la construction, pas l'impression.
        let rendu = kubeconfig_yaml(
            "https://identity.example.com",
            "alice",
            "demo",
            "https://10.0.0.1:6443",
            ca.to_str().unwrap(),
        )
        .unwrap();

        assert!(!rendu.contains("client-key-data"), "{rendu}");
        assert!(!rendu.contains("client-certificate-data"), "{rendu}");
        assert!(!rendu.contains("proxy-url"), "{rendu}");
        assert!(rendu.contains("kdt:alice"), "{rendu}");
        assert!(rendu.contains("client.authentication.k8s.io/v1"), "{rendu}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn le_kubeconfig_refuse_un_nom_de_compte_invalide() {
        assert!(kubeconfig_yaml("https://p", "system:masters", "demo", "https://s", "/dev/null")
            .is_err());
    }
}

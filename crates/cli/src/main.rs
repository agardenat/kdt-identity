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
    CredentialRequest, CredentialResponse, SessionRequest, SessionResponse, CREDENTIAL_PATH,
    SESSION_PATH,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredentialStatus {
    expiration_timestamp: String,
    client_certificate_data: String,
    client_key_data: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 refuse de choisir seul son fournisseur cryptographique dès que plusieurs
    // sont compilables, et panique au premier handshake sinon.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match Cli::parse().command {
        Command::Credential { portal, user } => credential(&portal, &user).await,
        Command::Logout { portal, user } => logout(&portal, &user),
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

    if let Some(cached) = cache::read(&path) {
        if cached.is_fresh(chrono::Utc::now()) {
            return emit(&cached);
        }
    }

    let fresh = obtain(portal, user).await?;
    // Un échec d'écriture du cache ne doit pas priver l'utilisateur du credential qu'il vient
    // d'obtenir : il paiera une authentification de plus, rien de pire.
    if let Err(e) = cache::write(&path, &fresh) {
        eprintln!("kdt-identity : cache non écrit ({e})");
    }
    emit(&fresh)
}

/// Authentifie, fait signer une demande construite localement, rend le credential.
///
/// L'échange se fait en deux temps, et pas par confort : le sujet d'un certificat X.509 est
/// fixé dans la demande, signée par une clé que seul ce processus détient. Le portail ne peut
/// donc pas corriger un sujet incomplet — il ne peut que l'accepter ou le refuser. Le plugin
/// doit connaître ses groupes **avant** de signer, et un code TOTP ne servant qu'une fois, il
/// ne peut pas s'authentifier deux fois pour les apprendre.
async fn obtain(portal: &str, user: &str) -> anyhow::Result<cache::CachedCredential> {
    let http = reqwest::Client::new();
    let (password, totp) = prompt_credentials(user, portal)?;

    // Premier temps : s'authentifier et apprendre son identité effective.
    let session: SessionResponse = read_json(
        http.post(format!("{portal}{SESSION_PATH}"))
            .json(&SessionRequest {
                user: user.to_string(),
                password,
                totp,
            })
            .send()
            .await
            .with_context(|| format!("appel du portail {portal}"))?,
    )
    .await?;

    let subject = Subject::user(user).context("nom de compte invalide")?;
    if session.subject != subject.as_str() {
        // Le portail désigne quelqu'un d'autre que ce qui a été demandé : construire une
        // demande là-dessus reviendrait à réclamer une identité qui n'est pas la nôtre.
        bail!(
            "le portail a répondu pour {} alors que {} était demandé",
            session.subject,
            subject.as_str()
        );
    }

    let groups = session
        .groups
        .iter()
        .map(|g| {
            g.strip_prefix(kdt_identity_api::naming::SUBJECT_PREFIX)
                .ok_or_else(|| anyhow::anyhow!("groupe {g:?} sans préfixe attendu"))
                .and_then(|name| Ok(Subject::group(name)?))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let generated = csr::generate(&subject, &groups).context("génération de la demande")?;

    // Second temps : faire signer. Le portail relit les groupes depuis le cluster et refusera
    // si l'appartenance a changé entre les deux appels — auquel cas il suffit de recommencer.
    let issued: CredentialResponse = read_json(
        http.post(format!("{portal}{CREDENTIAL_PATH}"))
            .json(&CredentialRequest {
                token: session.token,
                csr: generated.csr_pem.clone(),
            })
            .send()
            .await
            .with_context(|| format!("appel du portail {portal}"))?,
    )
    .await?;

    Ok(cache::CachedCredential {
        certificate_pem: issued.certificate,
        // La clé n'a jamais quitté ce processus : elle rejoint le cache, pas le réseau.
        key_pem: generated.key_pem.to_string(),
        expires_at: chrono::DateTime::parse_from_rfc3339(&issued.expires_at)
            .context("date d'expiration illisible")?
            .with_timezone(&chrono::Utc),
    })
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
    // Le PEM part tel quel. Contrairement aux champs `*-data` d'un kubeconfig, ceux d'un
    // `ExecCredential` ne sont pas encodés en base64 : client-go les lit directement comme du
    // PEM, et un base64 supplémentaire lui fait répondre « failed to find any PEM data ».
    let exec = ExecCredential {
        api_version: "client.authentication.k8s.io/v1",
        kind: "ExecCredential",
        status: ExecCredentialStatus {
            expiration_timestamp: credential.expires_at.to_rfc3339(),
            client_certificate_data: credential.certificate_pem.clone(),
            client_key_data: credential.key_pem.clone(),
        },
    };

    println!("{}", serde_json::to_string(&exec)?);
    Ok(())
}

fn logout(portal: &str, user: &str) -> anyhow::Result<()> {
    let path = cache::path(portal.trim_end_matches('/'), user)?;
    match std::fs::remove_file(&path) {
        Ok(()) => eprintln!("credential effacé"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("aucun credential en cache")
        }
        Err(e) => bail!("suppression de {} : {e}", path.display()),
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
            certificate_pem: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
                .to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nWFla\n-----END PRIVATE KEY-----\n".to_string(),
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-08-21T20:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    /// `kubectl` refuse un ExecCredential qui ne porte pas exactement ces champs, et lit le
    /// certificat comme du PEM brut — pas comme du base64, à la différence d'un kubeconfig.
    #[test]
    fn l_exec_credential_porte_le_pem_tel_quel() {
        let c = credential();
        let exec = ExecCredential {
            api_version: "client.authentication.k8s.io/v1",
            kind: "ExecCredential",
            status: ExecCredentialStatus {
                expiration_timestamp: c.expires_at.to_rfc3339(),
                client_certificate_data: c.certificate_pem.clone(),
                client_key_data: c.key_pem.clone(),
            },
        };

        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&exec).unwrap()).unwrap();

        assert_eq!(json["apiVersion"], "client.authentication.k8s.io/v1");
        assert_eq!(json["kind"], "ExecCredential");
        assert!(json["status"]["expirationTimestamp"].as_str().is_some());

        let cert = json["status"]["clientCertificateData"].as_str().unwrap();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"), "{cert}");
        assert_eq!(cert, c.certificate_pem);

        let key = json["status"]["clientKeyData"].as_str().unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"), "{key}");
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
            "hz",
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
        assert!(kubeconfig_yaml("https://p", "system:masters", "hz", "https://s", "/dev/null")
            .is_err());
    }
}

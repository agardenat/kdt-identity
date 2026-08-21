use anyhow::{bail, Context as _};
use clap::{Parser, Subcommand};
use kdt_identity_api::naming::Subject;
use kdt_identity_api::{KdtGroup, KdtUser};
use kdt_identity_server::auth;
use kdt_identity_server::config::ServerConfig;
use kdt_identity_server::controller::logic;
use kdt_identity_server::mail::{self, Encryption, Mailer};
use kdt_identity_server::credentials::{endpoint, kubeconfig, Issuer};
use kube::api::{Api, ListParams};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "kdt-identity-server",
    version,
    about = "Utilisateurs et groupes locaux pour Kubernetes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Écrit les manifestes d'installation sur la sortie standard.
    Crd,

    /// Réconcilie les KdtUser et KdtGroup jusqu'à l'arrêt du processus.
    Controller,

    /// Crée une invitation et affiche, une seule fois, le lien et le code d'activation.
    ///
    /// Les deux sont à transmettre par des canaux différents : le lien par écrit, le code de
    /// vive voix. Intercepter l'un des deux ne suffit alors pas à activer le compte.
    Invite {
        /// Nom du KdtUser, sans le préfixe.
        user: String,

        /// Durée de validité de l'invitation.
        #[arg(long, default_value = "72h", value_parser = parse_duration)]
        validity: Duration,

        /// Envoie aussi le lien par courriel, si un SMTP est configuré.
        ///
        /// Le code reste affiché ici : le transmettre par le même canal que le lien annulerait
        /// tout l'intérêt de la séparation.
        #[arg(long)]
        send_mail: bool,
    },

    /// Émet un kubeconfig pour un KdtUser existant.
    ///
    /// Commande d'administration : elle s'exécute avec les droits de celui qui l'invoque, y
    /// compris l'approbation des CSR. À ce titre elle contourne la phase du compte, mais
    /// jamais `spec.disabled`.
    Issue {
        /// Nom du KdtUser, sans le préfixe.
        user: String,

        /// Durée de validité demandée, par exemple `8h` ou `600s`.
        #[arg(long, default_value = "8h", value_parser = parse_duration)]
        ttl: Duration,
    },
}

/// Accepte les suffixes `s`, `m`, `h`, `d`.
fn parse_duration(raw: &str) -> Result<Duration, String> {
    let (digits, unit) = raw.split_at(
        raw.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(raw.len()),
    );
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("durée {raw:?} : chiffres attendus avant l'unité"))?;
    let seconds = match unit {
        "s" | "" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86400,
        other => return Err(format!("unité {other:?} inconnue, attendu s, m, h ou d")),
    };
    Ok(Duration::from_secs(seconds))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Les traces vont sur stderr, jamais sur stdout : `issue` écrit un kubeconfig sur la
    // sortie standard, et une ligne de log qui s'y glisserait produirait un fichier que
    // `kubectl` refuse.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kdt_identity_server=info".into()),
        )
        .init();
    kdt_identity_server::install_crypto_provider();

    match Cli::parse().command {
        Command::Crd => print!("{}", kdt_identity_server::manifests::all()?),
        Command::Controller => {
            let config = ServerConfig::from_env().context("configuration")?;
            let client = kube::Client::try_default()
                .await
                .context("connexion au cluster")?;
            kdt_identity_server::controller::run(client, config).await;
        }
        Command::Invite {
            user,
            validity,
            send_mail,
        } => invite(&user, validity, send_mail).await?,
        Command::Issue { user, ttl } => issue(&user, ttl).await?,
    }
    Ok(())
}

/// Crée une invitation et la remet à l'administrateur.
///
/// Le lien et le code ne sont affichés qu'ici, et une seule fois : ils ne sont ni journalisés,
/// ni écrits dans le statut du `KdtUser` — un statut est lisible par quiconque peut lister les
/// utilisateurs, ce qui reviendrait à publier l'invitation.
async fn invite(name: &str, validity: Duration, send_mail: bool) -> anyhow::Result<()> {
    let config = ServerConfig::from_env().context("configuration")?;
    let client = kube::Client::try_default()
        .await
        .context("connexion au cluster")?;

    let users: Api<KdtUser> = Api::all(client.clone());
    let user = users
        .get(name)
        .await
        .with_context(|| format!("KdtUser {name:?} introuvable"))?;

    if user.spec.disabled {
        bail!("{name:?} est désactivé (spec.disabled) : inviter n'aurait aucun effet");
    }

    let validity = chrono::Duration::from_std(validity).context("durée de validité")?;
    let new_invite = auth::invite::create(chrono::Utc::now(), validity);

    // Une nouvelle invitation remplace la précédente et efface tout mot de passe existant :
    // c'est ce qui fait de cette commande le chemin de réinitialisation autant que celui de
    // l'invitation initiale, sans qu'un ancien mot de passe survive à la réémission.
    let store = auth::store::CredentialStore::new(client, &config.namespace);
    let credentials = auth::store::Credentials {
        invite: Some(new_invite.record.clone()),
        ..Default::default()
    };
    store
        .put(&user, &credentials)
        .await
        .context("enregistrement de l'invitation")?;

    let url = config.activation_url(name, &new_invite.token);

    if send_mail {
        let smtp = config
            .smtp
            .as_ref()
            .context("--send-mail demandé mais aucun SMTP configuré")?;
        if smtp.encryption == Encryption::None {
            tracing::warn!(
                "SMTP en clair : le lien d'activation circulera lisible sur le réseau"
            );
        }
        Mailer::new(smtp)
            .context("transport SMTP")?
            .send_invitation(
                &user.spec.email,
                &mail::template::Invitation {
                    display_name: user.spec.display_name.as_deref().unwrap_or(name),
                    activation_url: &url,
                    expires_at: new_invite.record.expires_at,
                    cluster: &config.cluster_name,
                },
            )
            .await
            .context("envoi du courriel")?;
        tracing::info!(destinataire = %user.spec.email, "lien envoyé par courriel");
    }

    // Sur stdout, pour être redirigeable ; les traces, elles, restent sur stderr.
    println!("Invitation pour {name} <{}>", user.spec.email);
    println!("  expire le      {}", new_invite.record.expires_at.format("%d/%m/%Y à %H:%M UTC"));
    if !send_mail {
        println!("  lien           {url}");
    }
    println!(
        "  code           {}",
        auth::invite::format_code(&new_invite.activation_code)
    );
    println!();
    println!("Transmettez le lien et le code par deux canaux différents :");
    println!("le code de vive voix, pour qu'intercepter le lien ne suffise pas.");

    Ok(())
}

async fn issue(name: &str, ttl: Duration) -> anyhow::Result<()> {
    let client = kube::Client::try_default()
        .await
        .context("connexion au cluster")?;

    let users: Api<KdtUser> = Api::all(client.clone());
    let user = users
        .get(name)
        .await
        .with_context(|| format!("KdtUser {name:?} introuvable"))?;

    if !logic::may_be_issued_by_admin(&user) {
        bail!("{name:?} est désactivé (spec.disabled) : aucune émission possible");
    }

    // Les groupes sont relus depuis les `KdtGroup`, jamais repris de `status.memberOf`. Ce
    // statut n'est qu'un index d'affichage entretenu par le contrôleur : s'il est en retard,
    // ou s'il a été édité à la main, il ne doit surtout pas décider de ce qui finit dans un
    // certificat.
    let groups: Api<KdtGroup> = Api::all(client.clone());
    let member_of = logic::member_of(name, &groups.list(&ListParams::default()).await?.items);

    let subject = Subject::user(name)?;
    let group_subjects = member_of
        .iter()
        .map(|g| Subject::group(g))
        .collect::<Result<Vec<_>, _>>()?;

    tracing::info!(
        user = %subject,
        groupes = ?group_subjects.iter().map(Subject::as_str).collect::<Vec<_>>(),
        "émission"
    );

    let credential = Issuer::new(client)
        .issue_with_generated_key(&subject, &group_subjects, ttl)
        .await
        .context("émission du certificat")?;

    tracing::info!(expire = %credential.not_after, "certificat émis");

    let endpoint = endpoint::from_ambient_kubeconfig().context("découverte du cluster")?;
    print!("{}", kubeconfig::standalone(&endpoint, &subject, &credential)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_duration;
    use std::time::Duration;

    #[test]
    fn interprete_les_unites_de_duree() {
        assert_eq!(parse_duration("600s"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_duration("600"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("8h"), Ok(Duration::from_secs(28800)));
        assert_eq!(parse_duration("2d"), Ok(Duration::from_secs(172800)));
    }

    /// Une durée mal comprise silencieusement, c'est un certificat qui vit trop longtemps.
    #[test]
    fn refuse_ce_qu_elle_ne_comprend_pas() {
        for entree in ["", "h", "8j", "huit", "8 h", "-8h", "8hh"] {
            assert!(parse_duration(entree).is_err(), "{entree:?} accepté à tort");
        }
    }
}

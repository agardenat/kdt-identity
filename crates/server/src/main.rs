use anyhow::{bail, Context as _};
use clap::{Parser, Subcommand};
use kdt_identity_api::naming::Subject;
use kdt_identity_api::portal::{AuthMode, CredentialMode};
use kdt_identity_api::{KdtGroup, KdtUser};
use kdt_identity_server::auth;
use kdt_identity_server::config::{parse_duration, ServerConfig};
use kdt_identity_server::controller::logic;
use kdt_identity_server::mail::{self, Encryption, Mailer};
use kdt_identity_server::oidc;
use kdt_identity_server::sessions::SessionStore;
use kdt_identity_server::web;
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
    /// Contexte du kubeconfig à viser.
    ///
    /// À donner systématiquement hors du cluster : le contexte courant n'est presque jamais
    /// celui qu'on vise, et rien ne le signale — une commande qui écrit partirait sur le mauvais
    /// cluster sans que rien ne le rattrape.
    ///
    /// Sans effet dans un pod, où l'identité vient du compte de service.
    #[arg(long, global = true, env = "KDT_IDENTITY_CONTEXT")]
    context: Option<String>,

    #[command(subcommand)]
    command: Command,
}

/// Le client du cluster, sur le contexte demandé.
async fn cluster_client(context: Option<&str>) -> anyhow::Result<kube::Client> {
    let Some(context) = context else {
        return kube::Client::try_default()
            .await
            .context("connexion au cluster");
    };

    let options = kube::config::KubeConfigOptions {
        context: Some(context.to_string()),
        ..Default::default()
    };
    let config = kube::Config::from_kubeconfig(&options)
        .await
        .with_context(|| format!("contexte {context:?} du kubeconfig"))?;
    kube::Client::try_from(config).with_context(|| format!("connexion au cluster {context:?}"))
}

#[derive(Subcommand)]
enum Command {
    /// Écrit les manifestes d'installation sur la sortie standard.
    Crd,

    /// Réconcilie les KdtUser et KdtGroup jusqu'à l'arrêt du processus.
    Controller,

    /// Sert le portail web : activation, connexion, téléchargement du kubeconfig.
    Serve,

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

    /// Ferme toutes les sessions d'un compte, sur tous ses postes.
    ///
    /// Pour un poste perdu ou volé : la personne reste habilitée et se reconnecte ailleurs.
    /// Pour couper quelqu'un, c'est `spec.disabled` qu'il faut poser — le contrôleur ferme
    /// alors les sessions de lui-même, et le portail refuse la connexion.
    Revoke {
        /// Nom du KdtUser, sans le préfixe.
        user: String,
    },
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
    install_directory_trust()?;

    let cli = Cli::parse();
    let context = cli.context.as_deref();

    match cli.command {
        Command::Crd => print!("{}", kdt_identity_server::manifests::all()?),
        Command::Controller => {
            let config = ServerConfig::from_env().context("configuration")?;
            let client = cluster_client(context).await?;
            kdt_identity_server::controller::run(client, config).await;
        }
        Command::Serve => serve(context).await?,
        Command::Invite {
            user,
            validity,
            send_mail,
        } => invite(&user, validity, send_mail, context).await?,
        Command::Issue { user, ttl } => issue(&user, ttl, context).await?,
        Command::Revoke { user } => revoke(&user, context).await?,
    }
    Ok(())
}

/// Ajoute la CA de l'annuaire au magasin de confiance, avant toute connexion.
///
/// Lue directement dans l'environnement plutôt que depuis [`ServerConfig`] : la configuration
/// n'est construite que dans les sous-commandes, alors que la variable `SSL_CERT_FILE` doit être
/// posée avant que quoi que ce soit n'ouvre une connexion TLS — y compris le client Kubernetes.
///
/// Sans CA déclarée, rien n'est touché : le magasin de la plateforme reste celui qui sert.
fn install_directory_trust() -> anyhow::Result<()> {
    let Ok(ca_file) = std::env::var("KDT_IDENTITY_LDAP_CA_FILE") else {
        return Ok(());
    };
    if ca_file.trim().is_empty() {
        return Ok(());
    }

    let runtime_dir = std::env::var("KDT_IDENTITY_RUNTIME_DIR")
        .unwrap_or_else(|_| kdt_identity_server::ldap::trust::RUNTIME_DIR.to_string());

    // Avertir, et non échouer : un magasin réduit à la seule CA de l'annuaire reste utilisable
    // pour l'annuaire, et refuser de démarrer punirait un déploiement qui n'envoie aucun
    // courriel. Mais le silence, lui, serait un piège — le premier envoi échouerait sans que
    // rien ne rattache la panne à ce choix.
    if !kdt_identity_server::ldap::trust::image_store_present() {
        tracing::warn!(
            magasin = kdt_identity_server::config::IMAGE_CA_BUNDLE,
            "magasin d'autorités de l'image absent : le magasin assemblé ne portera que la CA \
             de l'annuaire, et le TLS sortant vers d'autres services échouera"
        );
    }

    let bundle = kdt_identity_server::ldap::trust::install(
        std::path::Path::new(&ca_file),
        std::path::Path::new(&runtime_dir),
    )
    .context("magasin de confiance de l'annuaire")?;

    tracing::info!(magasin = %bundle.display(), "CA de l'annuaire ajoutée au magasin");
    Ok(())
}

async fn serve(context: Option<&str>) -> anyhow::Result<()> {
    let config = ServerConfig::from_env().context("configuration")?;
    let client = cluster_client(context).await?;

    let endpoint = endpoint::resolve(
        config.apiserver_url.as_deref(),
        &config.cluster_name,
        config.cluster_ca_file.as_deref(),
    )
    .context("description du cluster")?;

    // Sans clé partagée, chaque instance signe avec la sienne : une session ouverte sur l'une
    // n'est plus reconnue par l'autre, et un redémarrage déconnecte tout le monde. Acceptable
    // en instance unique, à corriger dès qu'il y en a deux.
    let signer = match &config.session_key {
        Some(encoded) => {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .context("KDT_IDENTITY_SESSION_KEY n'est pas du base64")?;
            let key: [u8; web::signer::KEY_BYTES] = raw.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!(
                    "KDT_IDENTITY_SESSION_KEY fait {} octets, {} attendus",
                    v.len(),
                    web::signer::KEY_BYTES
                )
            })?;
            web::signer::Signer::new(key)
        }
        None => {
            tracing::warn!(
                "aucune KDT_IDENTITY_SESSION_KEY : clé tirée au démarrage, les sessions ne \
                 survivront ni à un redémarrage ni à une seconde instance"
            );
            web::signer::Signer::generate()
        }
    };

    // La clé de signature des jetons, elle, n'est jamais tirée à la volée : un jeton signé
    // par une clé qui disparaît au redémarrage serait refusé par l'apiserver, qui a mis la
    // précédente en cache. Elle vit dans un Secret, créé au premier démarrage.
    let oidc = match config.credential_mode {
        CredentialMode::Certificate => None,
        CredentialMode::Oidc => {
            let material = oidc::key::load_or_create(client.clone(), &config.namespace)
                .await
                .context("clé de signature OIDC")?;
            tracing::info!(
                emetteur = %config.portal_url,
                audience = %config.oidc_audience,
                kid = %material.kid(),
                jeton = ?config.oidc_token_ttl,
                "mode OIDC"
            );
            Some(web::OidcState { material })
        }
    };

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("écoute sur {}", config.listen))?;

    tracing::info!(
        adresse = %config.listen,
        cluster = %config.cluster_name,
        apiserver = %endpoint.server,
        mode = %config.credential_mode,
        authentification = %config.auth_mode,
        "portail démarré"
    );

    if let Some(ldap) = &config.ldap {
        tracing::info!(
            annuaire = %ldap.url,
            racine = %ldap.user_search_base,
            groupes = ldap.group_mappings.managed_groups().len(),
            "fédération d'identité active"
        );
    }

    // Le client du fournisseur est bâti ici, où sa configuration peut encore faire échouer le
    // démarrage — une CA illisible est une erreur d'installation, pas de connexion. Il ne joint
    // personne pour autant : la découverte est faite à la première connexion, pour qu'un
    // fournisseur momentanément absent n'empêche pas le portail de servir les sessions en cours.
    let provider = match config.oidc_auth.clone() {
        None => None,
        Some(oidc_auth) => {
            tracing::info!(
                emetteur = %oidc_auth.issuer,
                client = %oidc_auth.client_id,
                groupes = oidc_auth.group_mappings.managed_groups().len(),
                retour = %format!("{}{}", config.portal_url, web::OIDC_CALLBACK_PATH),
                "fédération d'identité active"
            );
            Some(
                kdt_identity_server::oidc_auth::Provider::new(oidc_auth)
                    .context("fournisseur d'identité")?,
            )
        }
    };

    let state = web::state(client, config, endpoint, signer, oidc, provider);
    axum::serve(listener, web::router(state))
        .await
        .context("service HTTP")?;
    Ok(())
}

/// Crée une invitation et la remet à l'administrateur.
///
/// Le lien et le code ne sont affichés qu'ici, et une seule fois : ils ne sont ni journalisés,
/// ni écrits dans le statut du `KdtUser` — un statut est lisible par quiconque peut lister les
/// utilisateurs, ce qui reviendrait à publier l'invitation.
async fn invite(
    name: &str,
    validity: Duration,
    send_mail: bool,
    context: Option<&str>,
) -> anyhow::Result<()> {
    let config = ServerConfig::from_env().context("configuration")?;

    // En mode ldap, l'invitation n'a plus d'objet : il n'y a ni mot de passe à poser ni TOTP à
    // enrôler, et le portail ne sert même pas la page d'activation. Écrire l'invitation quand
    // même produirait un lien qui mène à un 404.
    if config.auth_mode == AuthMode::Ldap {
        bail!(
            "le mode d'authentification est ldap : les comptes sont créés à la première \
             connexion réussie contre l'annuaire, il n'y a pas d'invitation à envoyer"
        );
    }

    let client = cluster_client(context).await?;

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

async fn issue(name: &str, ttl: Duration, context: Option<&str>) -> anyhow::Result<()> {
    let client = cluster_client(context).await?;

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

/// Ferme toutes les sessions d'un compte.
///
/// Ne touche ni au mot de passe ni au TOTP : la personne peut se reconnecter aussitôt. Pour
/// l'empêcher, c'est `spec.disabled` qu'il faut poser — les deux gestes vont souvent ensemble,
/// mais ils ne disent pas la même chose.
async fn revoke(name: &str, context: Option<&str>) -> anyhow::Result<()> {
    let config = ServerConfig::from_env().context("configuration")?;
    let client = cluster_client(context).await?;
    let users: Api<KdtUser> = Api::all(client.clone());
    let user = users
        .get(name)
        .await
        .with_context(|| format!("KdtUser {name:?} introuvable"))?;

    let closed = SessionStore::new(client, &config.namespace)
        .update(&user, |sessions| sessions.close_all())
        .await
        .context("fermeture des sessions")?;

    match closed {
        0 => println!("{name} : aucune session ouverte"),
        1 => println!("{name} : 1 session fermée"),
        n => println!("{name} : {n} sessions fermées"),
    }
    let fenetre = match config.credential_mode {
        CredentialMode::Certificate => config.cert_ttl,
        CredentialMode::Oidc => config.oidc_token_ttl,
    };
    println!(
        "L'accès s'arrête au prochain renouvellement, dans {} au plus.",
        humanise(fenetre)
    );
    if !user.spec.disabled {
        println!(
            "Le compte reste actif : il peut rouvrir une session. Pour l'en empêcher, \
             kubectl patch kdtuser {name} --type=merge -p '{{\"spec\":{{\"disabled\":true}}}}'"
        );
    }
    Ok(())
}

/// Rend une durée sous une forme lisible dans un message d'administration.
fn humanise(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min", seconds / 60),
        _ => format!("{} h", seconds / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::humanise;
    use std::time::Duration;

    /// Le message d'une révocation annonce le délai avant effet : une durée en secondes brutes
    /// s'y lirait mal, et c'est précisément le chiffre que l'administrateur retient.
    #[test]
    fn les_durees_s_annoncent_lisiblement() {
        assert_eq!(humanise(Duration::from_secs(30)), "30 s");
        assert_eq!(humanise(Duration::from_secs(300)), "5 min");
        assert_eq!(humanise(Duration::from_secs(3600)), "1 h");
        assert_eq!(humanise(Duration::from_secs(7200)), "2 h");
    }
}

//! Envoi des courriels d'invitation et de réinitialisation.
//!
//! Le lien d'activation vaut une authentification tant qu'il n'est pas consommé. Il n'est donc
//! jamais journalisé, et le corps du message est assemblé à partir de valeurs échappées : un
//! nom d'affichage vient de la spec d'un `KdtUser`, donc d'un administrateur, mais rien
//! n'oblige un administrateur à être prudent.

pub mod template;

use lettre::message::{header::ContentType, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("adresse invalide : {0}")]
    BadAddress(String),
    #[error("construction du message : {0}")]
    Build(String),
    #[error("transport SMTP : {0}")]
    Transport(String),
    #[error("envoi : {0}")]
    Send(String),
}

/// Comment la connexion au serveur sortant est protégée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encryption {
    /// STARTTLS sur le port de soumission. Défaut.
    #[default]
    StartTls,
    /// TLS dès l'ouverture de la connexion, typiquement sur le port 465.
    Implicit,
    /// Aucun chiffrement.
    ///
    /// Le courriel d'invitation porte un lien qui vaut une authentification : en clair, il est
    /// lisible par tout ce qui se trouve sur le chemin. Reste néanmoins nécessaire, parce que
    /// beaucoup de relais internes n'exposent que du SMTP nu — et pour les bacs à sable de
    /// développement. Ne s'active que sur demande explicite, et le serveur le signale au
    /// démarrage.
    None,
}

/// Configuration du serveur sortant.
#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    /// Adresse d'expédition, telle qu'elle apparaît chez le destinataire.
    pub from: String,
    pub encryption: Encryption,
}

/// `Debug` manuscrit : la configuration porte le mot de passe SMTP.
impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<omis>"))
            .field("from", &self.from)
            .field("encryption", &self.encryption)
            .finish()
    }
}

pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl Mailer {
    pub fn new(config: &SmtpConfig) -> Result<Self, MailError> {
        let mut builder = match config.encryption {
            Encryption::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|e| MailError::Transport(e.to_string()))?,
            Encryption::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                    .map_err(|e| MailError::Transport(e.to_string()))?
            }
            Encryption::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
            }
        }
        .port(config.port);

        if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            builder = builder.credentials(Credentials::new(user.clone(), pass.to_string()));
        }

        Ok(Self {
            transport: builder.build(),
            from: config.from.clone(),
        })
    }

    /// Envoie une invitation. Le lien n'apparaît que dans le message.
    pub async fn send_invitation(
        &self,
        to: &str,
        invitation: &template::Invitation<'_>,
    ) -> Result<(), MailError> {
        let rendered = template::render_invitation(invitation);

        let message = Message::builder()
            .from(
                self.from
                    .parse()
                    .map_err(|e| MailError::BadAddress(format!("expéditeur : {e}")))?,
            )
            .to(to
                .parse()
                .map_err(|e| MailError::BadAddress(format!("destinataire : {e}")))?)
            .subject(rendered.subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(rendered.text),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(rendered.html),
                    ),
            )
            .map_err(|e| MailError::Build(e.to_string()))?;

        self.transport
            .send(message)
            .await
            .map_err(|e| MailError::Send(e.to_string()))?;
        Ok(())
    }
}

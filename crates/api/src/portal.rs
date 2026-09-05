//! Contrat HTTP entre le portail et le plugin `exec`.
//!
//! Les types sont définis ici une seule fois et utilisés des deux côtés. Les redéclarer de part
//! et d'autre laisserait les deux versions diverger sans que rien ne le signale : un champ
//! renommé d'un côté produit une erreur de désérialisation à l'exécution, pas à la compilation.
//!
//! # Pourquoi l'échange se fait en deux temps
//!
//! Le sujet d'un certificat X.509 — le nom d'utilisateur et les groupes — est fixé dans la
//! demande de signature, elle-même signée par une clé privée que seul le client détient. Le
//! serveur ne peut donc pas compléter un sujet incomplet : il ne peut que l'accepter ou le
//! refuser. Le client doit connaître ses groupes **avant** de signer.
//!
//! Il ne peut pas non plus s'authentifier deux fois pour les apprendre : un code TOTP ne sert
//! qu'une fois. D'où [`SessionResponse::token`], valable quelques secondes, le temps de
//! construire la demande.

use serde::{Deserialize, Serialize};

/// Chemin de l'ouverture de session.
pub const SESSION_PATH: &str = "/api/v1/session";
/// Chemin de la demande de certificat.
pub const CREDENTIAL_PATH: &str = "/api/v1/credentials";
/// Chemin de la demande de jeton, en mode OIDC.
pub const TOKEN_PATH: &str = "/api/v1/token";
/// Chemin de la fermeture d'une session OIDC.
pub const REVOKE_PATH: &str = "/api/v1/revoke";

/// Ce que le déploiement remet aux clients : un certificat, ou un jeton.
///
/// Le client ne choisit pas — c'est une propriété du cluster, qui dépend de la façon dont son
/// apiserver est configuré. Il la découvre à l'ouverture de session et s'y conforme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialMode {
    /// Certificat X.509 signé par la CA du cluster. Ne demande aucune configuration de
    /// l'apiserver, mais ne se révoque pas.
    #[default]
    Certificate,
    /// Jeton signé par kdt-identity, validé par l'apiserver. Se révoque, mais demande que le
    /// control plane connaisse l'émetteur.
    Oidc,
}

impl CredentialMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::Oidc => "oidc",
        }
    }
}

impl std::fmt::Display for CredentialMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CredentialMode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "certificate" => Ok(Self::Certificate),
            "oidc" => Ok(Self::Oidc),
            other => Err(format!("mode {other:?} inconnu, attendu certificate ou oidc")),
        }
    }
}

/// Ce que le client présente pour ouvrir une session.
///
/// Deux jeux de champs mutuellement exclusifs, plutôt qu'un discriminant explicite : une
/// demande écrite par un plugin antérieur au renouvellement silencieux — mot de passe et code,
/// sans autre champ — reste comprise telle quelle. La validation est faite par [`Self::grant`],
/// une fois, plutôt que dispersée dans les appelants.
///
/// Ne dérive volontairement pas `Debug` : un `{:?}` publierait le mot de passe. Pour
/// journaliser une demande, passer par [`SessionRequestRedacted`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// Jeton de renouvellement obtenu lors d'une ouverture de session précédente.
    ///
    /// Le compte est nommé à part : ce jeton ne dit pas à qui il appartient, et le serveur ne
    /// peut pas le chercher — il n'a pas le droit d'énumérer les `Secret` du namespace,
    /// précisément pour qu'une faille du portail ne permette pas de lister les comptes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Ce sur quoi une ouverture de session repose, une fois la demande validée.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionGrant<'a> {
    /// Authentification complète. Ouvre un droit de renouveler.
    Password { password: &'a str, totp: &'a str },
    /// Renouvellement silencieux. N'en ouvre pas un second.
    Refresh { refresh_token: &'a str },
}

impl SessionRequest {
    pub fn password(user: &str, password: &str, totp: &str) -> Self {
        Self {
            user: user.to_string(),
            password: Some(password.to_string()),
            totp: Some(totp.to_string()),
            refresh_token: None,
        }
    }

    pub fn refresh(user: &str, refresh_token: &str) -> Self {
        Self {
            user: user.to_string(),
            password: None,
            totp: None,
            refresh_token: Some(refresh_token.to_string()),
        }
    }

    /// Détermine sur quoi la demande repose, ou pourquoi elle est irrecevable.
    ///
    /// Les deux jeux ensemble sont refusés plutôt qu'arbitrés : accepter les deux laisserait
    /// le serveur choisir lequel vérifier, et un client qui joint un mot de passe vide à un
    /// jeton valide ne doit pas découvrir laquelle des deux vérifications a compté.
    pub fn grant(&self) -> Result<SessionGrant<'_>, &'static str> {
        match (&self.password, &self.totp, &self.refresh_token) {
            (Some(password), Some(totp), None) => Ok(SessionGrant::Password { password, totp }),
            (None, None, Some(refresh_token)) => Ok(SessionGrant::Refresh { refresh_token }),
            (_, _, Some(_)) => Err("un jeton de renouvellement ne se présente pas avec un mot de passe"),
            _ => Err("mot de passe et code sont attendus ensemble"),
        }
    }
}

/// `Debug` manuscrit : cette structure porte un mot de passe et un code à usage unique.
impl std::fmt::Debug for SessionRequestRedacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRequest")
            .field("user", &self.0.user)
            .field("password", &self.0.password.as_ref().map(|_| "<omis>"))
            .field("totp", &self.0.totp.as_ref().map(|_| "<omis>"))
            .field("refresh_token", &self.0.refresh_token.as_ref().map(|_| "<omis>"))
            .finish()
    }
}

/// Enveloppe d'affichage, pour journaliser une demande sans en publier les secrets.
pub struct SessionRequestRedacted<'a>(pub &'a SessionRequest);

/// Ce que le portail rend au client pour qu'il puisse construire une demande acceptable.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    /// Jeton de courte durée, à présenter avec la demande de signature ou de jeton.
    pub token: String,
    /// Sujet complet, préfixe compris, à placer dans le `CN`.
    pub subject: String,
    /// Sujets des groupes, préfixe compris, à placer dans les `O`.
    pub groups: Vec<String>,
    /// Ce que le serveur émet. Absent d'un serveur antérieur au mode OIDC, auquel cas c'est un
    /// certificat — la valeur par défaut fait donc dialoguer un client récent avec un serveur
    /// qui l'ignore.
    #[serde(default)]
    pub mode: CredentialMode,
    /// Jeton de renouvellement, rendu à la seule ouverture de session par mot de passe.
    ///
    /// Absent d'un renouvellement : le jeton en cours reste valable, et le renvoyer à chaque
    /// fois multiplierait les copies d'un secret de longue durée sans rien apporter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Expiration du jeton de renouvellement, au format RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_expires_at: Option<String>,
}

/// Ce que le client présente pour obtenir un jeton d'identité.
///
/// Un seul chemin : le jeton de session rendu par [`SESSION_PATH`]. Le renouvellement
/// silencieux se fait un cran plus tôt, à l'ouverture de session — c'est le même mécanisme
/// pour les deux modes, et il n'a pas à être redit ici.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    /// Jeton de session valable quelques secondes.
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    /// Le jeton d'identité, à présenter à l'apiserver.
    pub id_token: String,
    /// Expiration du jeton d'identité, au format RFC 3339.
    pub expires_at: String,
}

/// Fermeture d'une session : le jeton de rafraîchissement cesse immédiatement de valoir.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeRequest {
    pub user: String,
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    pub token: String,
    /// Demande de signature au format PEM.
    pub csr: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialResponse {
    /// Certificat émis, au format PEM.
    pub certificate: String,
    /// Expiration au format RFC 3339.
    pub expires_at: String,
}

/// Corps d'erreur, commun à tous les refus de l'API.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le contrat sur le fil est en camelCase : ce test le fige, puisque c'est ce que les deux
    /// côtés échangent réellement.
    #[test]
    fn les_champs_sont_en_camel_case_sur_le_fil() {
        let json = serde_json::to_value(CredentialResponse {
            certificate: "PEM".into(),
            expires_at: "2026-08-21T20:00:00Z".into(),
        })
        .unwrap();

        assert!(json.get("expiresAt").is_some(), "{json}");
        assert!(json.get("expires_at").is_none(), "{json}");
    }

    /// Un aller-retour complet garantit que sérialisation et désérialisation s'accordent — la
    /// divergence que ce module existe pour empêcher.
    #[test]
    fn chaque_type_fait_l_aller_retour() {
        let session = SessionResponse {
            token: "jeton".into(),
            subject: "kdt:alice".into(),
            groups: vec!["kdt:ops".into()],
            mode: CredentialMode::Oidc,
            refresh_token: Some("id.secret".into()),
            refresh_expires_at: Some("2026-09-12T12:00:00Z".into()),
        };
        let relu: SessionResponse =
            serde_json::from_str(&serde_json::to_string(&session).unwrap()).unwrap();
        assert_eq!(relu.subject, session.subject);
        assert_eq!(relu.groups, session.groups);
        assert_eq!(relu.mode, session.mode);

        let request = CredentialRequest {
            token: "jeton".into(),
            csr: "PEM".into(),
        };
        let relu: CredentialRequest =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        assert_eq!(relu.csr, request.csr);
    }

    /// Un serveur antérieur au mode OIDC ne renvoie pas ce champ. Le client doit alors lire
    /// « certificat », et non refuser la réponse.
    #[test]
    fn un_mode_absent_vaut_certificat() {
        let json = r#"{"token":"t","subject":"kdt:alice","groups":[]}"#;
        let relu: SessionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(relu.mode, CredentialMode::Certificate);
    }

    #[test]
    fn le_mode_voyage_en_minuscules() {
        let json = serde_json::to_value(SessionResponse {
            token: "t".into(),
            subject: "kdt:alice".into(),
            groups: vec![],
            mode: CredentialMode::Oidc,
            refresh_token: None,
            refresh_expires_at: None,
        })
        .unwrap();
        assert_eq!(json["mode"], "oidc");
    }

    #[test]
    fn le_mode_se_lit_depuis_une_chaine() {
        use std::str::FromStr;

        assert_eq!(CredentialMode::from_str("oidc"), Ok(CredentialMode::Oidc));
        assert_eq!(
            CredentialMode::from_str("certificate"),
            Ok(CredentialMode::Certificate)
        );
        assert!(CredentialMode::from_str("Certificate").is_err());
        assert!(CredentialMode::from_str("").is_err());
    }

    /// Une demande écrite par un plugin antérieur au renouvellement silencieux ne porte que
    /// `user`, `password` et `totp`. Elle doit rester comprise : sans quoi, mettre à jour le
    /// portail casserait tous les postes d'un coup.
    #[test]
    fn une_demande_de_l_ancienne_forme_reste_comprise() {
        let json = r#"{"user":"alice","password":"secret","totp":"123456"}"#;
        let relu: SessionRequest = serde_json::from_str(json).unwrap();

        assert_eq!(
            relu.grant(),
            Ok(SessionGrant::Password {
                password: "secret",
                totp: "123456"
            })
        );
    }

    #[test]
    fn une_demande_de_renouvellement_se_distingue() {
        let request = SessionRequest::refresh("alice", "id.secret");
        let json = serde_json::to_value(&request).unwrap();

        assert_eq!(json["refreshToken"], "id.secret");
        assert!(json.get("password").is_none(), "{json}");
        assert_eq!(
            request.grant(),
            Ok(SessionGrant::Refresh {
                refresh_token: "id.secret"
            })
        );
    }

    /// Présenter les deux à la fois est refusé plutôt qu'arbitré : le serveur n'a pas à
    /// choisir laquelle des deux vérifications compte, et le client n'a pas à le deviner.
    #[test]
    fn une_demande_ambigue_est_refusee() {
        let mut request = SessionRequest::password("alice", "secret", "123456");
        request.refresh_token = Some("id.secret".into());
        assert!(request.grant().is_err());

        let mut incomplete = SessionRequest::password("alice", "secret", "123456");
        incomplete.totp = None;
        assert!(incomplete.grant().is_err());

        let vide = SessionRequest {
            user: "alice".into(),
            password: None,
            totp: None,
            refresh_token: None,
        };
        assert!(vide.grant().is_err());
    }

    /// Un renouvellement ne rend pas de nouveau jeton : le champ doit disparaître de la
    /// réponse plutôt que d'y figurer à `null`.
    #[test]
    fn un_renouvellement_omet_le_jeton_de_renouvellement() {
        let json = serde_json::to_value(SessionResponse {
            token: "t".into(),
            subject: "kdt:alice".into(),
            groups: vec![],
            mode: CredentialMode::Certificate,
            refresh_token: None,
            refresh_expires_at: None,
        })
        .unwrap();

        assert!(json.get("refreshToken").is_none(), "{json}");
    }

    /// Un `{:?}` sur une demande d'authentification ne doit pas publier le mot de passe.
    #[test]
    fn l_affichage_d_une_demande_masque_ses_secrets() {
        let request = SessionRequest::password("alice", "Correct-Horse-Battery9!", "123456");
        let rendu = format!("{:?}", SessionRequestRedacted(&request));

        assert!(!rendu.contains("Correct-Horse"), "{rendu}");
        assert!(!rendu.contains("123456"), "{rendu}");
        assert!(rendu.contains("alice"), "{rendu}");
    }
}

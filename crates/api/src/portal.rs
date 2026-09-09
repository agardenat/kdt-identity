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
/// Chemin d'entrée du flow d'autorisation, où le navigateur est envoyé.
pub const AUTHORIZE_PATH: &str = "/authorize";
/// Chemin de l'échange d'un code d'autorisation contre un droit de session.
pub const AUTHORIZE_TOKEN_PATH: &str = "/api/v1/authorize/token";
/// Chemin du descripteur du portail, lisible sans s'authentifier.
pub const PORTAL_PATH: &str = "/api/v1/portal";

/// Identifiant de l'application autorisée à demander des identités.
///
/// Il n'y en a qu'un : approuver une application qui parle à ce portail revient à lui confier des
/// identités du cluster, ce qui est un geste de déploiement, pas un enregistrement à chaud.
pub const WEB_CLIENT_ID: &str = "kdt-web";

/// Identifiant du plugin `exec` quand il ouvre une session par le navigateur.
///
/// Déclaré ici et non dans la configuration, contrairement à [`WEB_CLIENT_ID`] : ce n'est pas une
/// application tierce qu'un déploiement approuve, c'est l'autre moitié de ce produit. Son adresse
/// de retour est la boucle locale du poste, qu'aucun administrateur ne pourrait déclarer — le
/// port n'est connu qu'au lancement.
pub const CLI_CLIENT_ID: &str = "kdt-identity-cli";

/// Chemin de retour du plugin, sur la boucle locale.
pub const CLI_CALLBACK_PATH: &str = "/callback";

/// Chemin de retour, **côté application**, où le code d'autorisation est redirigé.
///
/// Défini ici plutôt que d'un seul côté : le portail n'accepte que cette adresse, et
/// l'application doit servir exactement celle-là. Les voir diverger produirait un refus dont ni
/// l'un ni l'autre ne pourrait dire d'où il vient.
pub const AUTHORIZE_CALLBACK_PATH: &str = "/auth/callback";

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

/// D'où vient l'identité, et qui vérifie le mot de passe.
///
/// Orthogonal à [`CredentialMode`], et pour une raison de fond : celui-ci décrit ce que le portail
/// **remet**, celui-là qui il **reconnaît**. Les deux se combinent librement — un annuaire peut
/// aussi bien aboutir à un certificat qu'à un jeton — et les confondre en une seule énumération
/// obligerait à écrire les quatre combinaisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Comptes portés par le cluster : mot de passe Argon2id et TOTP dans un `Secret`.
    #[default]
    Local,
    /// Comptes portés par un annuaire LDAP(S). Le mot de passe y est vérifié par un bind, le
    /// `KdtUser` est créé à la première connexion réussie, et le second facteur relève de
    /// l'annuaire.
    Ldap,
    /// Comptes portés par un fournisseur OpenID Connect. Le portail ne voit jamais le mot de
    /// passe : il redirige le navigateur, et c'est le fournisseur qui répond.
    ///
    /// À ne pas confondre avec [`CredentialMode::Oidc`], qui décrit ce que le portail **émet**
    /// vers l'apiserver. Ici le portail est client d'un fournisseur ; là il en est un. Les deux
    /// se combinent, et un déploiement peut n'en avoir aucun des deux.
    Oidc,
}

impl AuthMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ldap => "ldap",
            Self::Oidc => "oidc",
        }
    }

    /// Vrai si le portail attend un code TOTP en plus du mot de passe.
    ///
    /// Seul le mode local en gère un : en mode ldap, le second facteur — s'il existe — est celui
    /// de l'annuaire, et kdt-identity n'a rien à en savoir. En mode oidc, il n'y a pas même de
    /// mot de passe à accompagner.
    pub fn totp_required(&self) -> bool {
        matches!(self, Self::Local)
    }

    /// Vrai si le portail accepte encore qu'on lui présente un mot de passe.
    ///
    /// Faux en mode oidc, et c'est le cœur de ce mode : laisser subsister une porte par mot de
    /// passe à côté du fournisseur reviendrait à contourner tout ce qu'il applique — second
    /// facteur, accès conditionnel, désactivation d'un compte parti.
    pub fn accepts_password(&self) -> bool {
        !matches!(self, Self::Oidc)
    }
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AuthMode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "local" => Ok(Self::Local),
            "ldap" => Ok(Self::Ldap),
            "oidc" => Ok(Self::Oidc),
            other => Err(format!("mode {other:?} inconnu, attendu local, ldap ou oidc")),
        }
    }
}

/// Ce que le portail dit de lui-même avant toute authentification.
///
/// Rendu sans credential parce qu'il sert précisément à savoir quoi demander : sans lui, le
/// plugin ne peut pas décider s'il doit réclamer un code TOTP, et le découvrir après coup
/// obligerait à redemander le mot de passe. Rien de sensible n'y transite — ce sont des
/// propriétés du déploiement, que la page de connexion affiche déjà.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalDescriptor {
    pub credential_mode: CredentialMode,
    pub auth_mode: AuthMode,
    /// Redondant avec `auth_mode`, et volontairement : c'est la seule question que le client se
    /// pose, et la lui faire déduire d'un mode le rendrait solidaire d'une règle qui appartient
    /// au serveur.
    pub totp_required: bool,
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
    ///
    /// Le code est absent quand le déploiement n'en gère pas — c'est le cas dès que l'annuaire
    /// porte l'identité. Le rendre optionnel ici plutôt que d'accepter une chaîne vide évite
    /// qu'un client qui envoie `""` sur un portail à TOTP soit traité comme un client qui n'en
    /// a pas.
    Password {
        password: &'a str,
        totp: Option<&'a str>,
    },
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

    /// Demande sans code, pour un portail dont l'annuaire porte le second facteur.
    pub fn password_only(user: &str, password: &str) -> Self {
        Self {
            user: user.to_string(),
            password: Some(password.to_string()),
            totp: None,
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
    ///
    /// Un code sans mot de passe reste irrecevable : ce n'est pas la moitié d'une
    /// authentification qu'un portail sans TOTP accepterait, c'est une demande malformée.
    /// L'inverse — un mot de passe sans code — est désormais recevable, et c'est au serveur de
    /// dire si son mode s'en contente : lui seul connaît son annuaire.
    pub fn grant(&self) -> Result<SessionGrant<'_>, &'static str> {
        match (&self.password, &self.totp, &self.refresh_token) {
            (Some(password), totp, None) => Ok(SessionGrant::Password {
                password,
                totp: totp.as_deref(),
            }),
            (None, None, Some(refresh_token)) => Ok(SessionGrant::Refresh { refresh_token }),
            (_, _, Some(_)) => {
                Err("un jeton de renouvellement ne se présente pas avec un mot de passe")
            }
            _ => Err("un mot de passe est attendu"),
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

/// Ce qu'une application présente pour échanger un code d'autorisation.
///
/// Le `code_verifier` est ce qui prouve que celle qui échange le code est celle qui l'a demandé :
/// le défi public qui a voyagé dans l'URL en est le condensé, et lui seul ne suffit pas à le
/// reconstituer. Le `redirect_uri` est répété pour être confronté à celui qu'enferme le code —
/// un code obtenu pour une adresse ne s'échange pas depuis une autre.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeTokenRequest {
    pub code: String,
    pub code_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
}

/// `Debug` manuscrit : le vérificateur est un secret d'un seul usage, mais un secret.
impl std::fmt::Debug for AuthorizeTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeTokenRequest")
            .field("code", &"<omis>")
            .field("code_verifier", &"<omis>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
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
                totp: Some("123456")
            })
        );
    }

    /// Un portail dont l'annuaire porte le second facteur ne reçoit pas de code. La demande
    /// doit rester recevable : c'est le serveur qui sait si son mode s'en contente, et refuser
    /// ici interdirait le mode ldap avant même de l'avoir consulté.
    #[test]
    fn une_demande_sans_code_reste_recevable() {
        let request = SessionRequest::password_only("alice", "secret");
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("totp").is_none(), "{json}");

        assert_eq!(
            request.grant(),
            Ok(SessionGrant::Password {
                password: "secret",
                totp: None
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

        // Un code sans mot de passe n'est pas la moitié d'une authentification qu'un portail
        // sans TOTP accepterait : c'est une demande malformée, et elle le reste.
        let sans_mot_de_passe = SessionRequest {
            user: "alice".into(),
            password: None,
            totp: Some("123456".into()),
            refresh_token: None,
        };
        assert!(sans_mot_de_passe.grant().is_err());

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

    /// Un déploiement qui ne dit rien garde ses comptes locaux. Basculer sur un annuaire
    /// demande de le configurer : ce ne peut pas être un effet de bord d'une montée de version.
    #[test]
    fn le_mode_d_authentification_par_defaut_est_local() {
        use std::str::FromStr;

        assert_eq!(AuthMode::default(), AuthMode::Local);
        assert_eq!(AuthMode::from_str("ldap"), Ok(AuthMode::Ldap));
        assert_eq!(AuthMode::from_str("local"), Ok(AuthMode::Local));
        assert_eq!(AuthMode::from_str("oidc"), Ok(AuthMode::Oidc));
        assert!(AuthMode::from_str("LDAP").is_err());
        assert!(AuthMode::from_str("ldaps").is_err());
    }

    /// La règle qui définit le mode oidc : plus aucun mot de passe n'est recevable. Un portail
    /// qui en accepterait encore un offrirait un contournement du fournisseur.
    #[test]
    fn le_mode_oidc_n_accepte_plus_de_mot_de_passe() {
        assert!(AuthMode::Local.accepts_password());
        assert!(AuthMode::Ldap.accepts_password());
        assert!(!AuthMode::Oidc.accepts_password());
        assert!(!AuthMode::Oidc.totp_required());
    }

    /// Le second facteur n'existe que pour les comptes locaux. Si cette règle s'inversait, le
    /// plugin réclamerait un code que personne ne peut produire.
    #[test]
    fn seul_le_mode_local_reclame_un_code() {
        assert!(AuthMode::Local.totp_required());
        assert!(!AuthMode::Ldap.totp_required());
    }

    /// Le descripteur est ce que le plugin lit avant de poser ses questions : ses champs sont
    /// sur le fil, en camelCase comme le reste du contrat.
    #[test]
    fn le_descripteur_annonce_les_deux_modes() {
        let json = serde_json::to_value(PortalDescriptor {
            credential_mode: CredentialMode::Oidc,
            auth_mode: AuthMode::Ldap,
            totp_required: false,
        })
        .unwrap();

        assert_eq!(json["credentialMode"], "oidc");
        assert_eq!(json["authMode"], "ldap");
        assert_eq!(json["totpRequired"], false);
    }
}

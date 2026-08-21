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

/// Ne dérive volontairement pas `Debug` : un `{:?}` publierait le mot de passe. Pour
/// journaliser une demande, passer par [`SessionRequestRedacted`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    pub user: String,
    pub password: String,
    pub totp: String,
}

/// `Debug` manuscrit : cette structure porte un mot de passe et un code à usage unique.
impl std::fmt::Debug for SessionRequestRedacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRequest")
            .field("user", &self.0.user)
            .field("password", &"<omis>")
            .field("totp", &"<omis>")
            .finish()
    }
}

/// Enveloppe d'affichage, pour journaliser une demande sans en publier les secrets.
pub struct SessionRequestRedacted<'a>(pub &'a SessionRequest);

/// Ce que le portail rend au client pour qu'il puisse construire une demande acceptable.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    /// Jeton de courte durée, à présenter avec la demande de signature.
    pub token: String,
    /// Sujet complet, préfixe compris, à placer dans le `CN`.
    pub subject: String,
    /// Sujets des groupes, préfixe compris, à placer dans les `O`.
    pub groups: Vec<String>,
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
        };
        let relu: SessionResponse =
            serde_json::from_str(&serde_json::to_string(&session).unwrap()).unwrap();
        assert_eq!(relu.subject, session.subject);
        assert_eq!(relu.groups, session.groups);

        let request = CredentialRequest {
            token: "jeton".into(),
            csr: "PEM".into(),
        };
        let relu: CredentialRequest =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        assert_eq!(relu.csr, request.csr);
    }

    /// Un `{:?}` sur une demande d'authentification ne doit pas publier le mot de passe.
    #[test]
    fn l_affichage_d_une_demande_masque_ses_secrets() {
        let request = SessionRequest {
            user: "alice".into(),
            password: "Correct-Horse-Battery9!".into(),
            totp: "123456".into(),
        };
        let rendu = format!("{:?}", SessionRequestRedacted(&request));

        assert!(!rendu.contains("Correct-Horse"), "{rendu}");
        assert!(!rendu.contains("123456"), "{rendu}");
        assert!(rendu.contains("alice"), "{rendu}");
    }
}

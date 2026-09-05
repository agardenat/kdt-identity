//! Émission des jetons d'identité, au format JWS compact.
//!
//! L'encodage est écrit ici plutôt que délégué à une bibliothèque : un JWT ES256 tient en une
//! concaténation de trois segments base64url, et les seules subtilités — signature sur les
//! octets ASCII de `en-tête.charge`, signature en `r||s` brut et non en DER — sont précisément
//! celles qu'une dépendance de plus n'éviterait pas de vérifier.
//!
//! # Ce que l'apiserver fait de ces champs
//!
//! `iss` doit être identique à l'URL configurée côté apiserver, `aud` doit contenir l'audience
//! attendue, et `sub` devient le nom d'utilisateur. Le préfixe `kdt:` est déjà dans `sub` : il
//! ne vient pas d'un réglage de l'apiserver, qui pourrait être oublié, mais de l'émission
//! elle-même — la même barrière que pour les certificats.

use crate::oidc::key::{SigningMaterial, ALG};
use base64::Engine;
use chrono::{DateTime, Utc};
use kdt_identity_api::naming::Subject;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize};

/// L'en-tête JOSE. `typ` vaut `JWT` : certains validateurs le vérifient, aucun ne s'en plaint.
#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// La charge utile d'un jeton d'identité.
///
/// Les noms sont ceux des registres IANA, à l'exception de `groups`, qui n'est pas normalisé —
/// c'est le nom que Kubernetes attend par défaut avec `--oidc-groups-claim=groups`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    /// Identifiant unique du jeton, repris dans les journaux d'audit de l'apiserver.
    ///
    /// C'est ce qui permet de relier une requête à une session : un certificat client, lui, ne
    /// laisse que son sujet, identique pour toutes les émissions du même compte.
    pub jti: String,
    pub groups: Vec<String>,
}

/// Un jeton émis, avec son échéance pour que le client sache quand en redemander un.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Signe un jeton d'identité pour `subject`, membre de `groups`.
///
/// `nbf` vaut `iat` sans recul : un décalage d'horloge entre le portail et l'apiserver ferait
/// alors refuser un jeton fraîchement émis. La tolérance appartient au validateur, pas à
/// l'émetteur, qui n'a aucune raison de dater ses jetons dans le passé.
pub fn issue(
    material: &SigningMaterial,
    issuer: &str,
    audience: &str,
    subject: &Subject,
    groups: &[Subject],
    now: DateTime<Utc>,
    ttl: chrono::Duration,
) -> Result<IssuedToken, JwtError> {
    let expires_at = now + ttl;
    let claims = Claims {
        iss: issuer.to_string(),
        sub: subject.as_str().to_string(),
        aud: audience.to_string(),
        exp: expires_at.timestamp(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        jti: random_id(),
        groups: groups.iter().map(|g| g.as_str().to_string()).collect(),
    };

    Ok(IssuedToken {
        token: encode(material, &claims)?,
        expires_at,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("sérialisation des revendications : {0}")]
    Serialize(#[from] serde_json::Error),
}

fn encode(material: &SigningMaterial, claims: &Claims) -> Result<String, JwtError> {
    let header = Header {
        alg: ALG.to_string(),
        typ: "JWT".to_string(),
        kid: material.kid().to_string(),
    };

    let body = format!(
        "{}.{}",
        b64(&serde_json::to_vec(&header)?),
        b64(&serde_json::to_vec(claims)?)
    );

    // ES256 signe le SHA-256 des octets du corps ; la signature part en `r||s` sur 64 octets,
    // pas en DER — un JWT signé en DER est rejeté sans que le message dise pourquoi.
    let signature: Signature = material.signing_key().sign(body.as_bytes());
    Ok(format!("{body}.{}", b64(&signature.to_bytes())))
}

/// Identifiant de jeton : 16 octets du CSPRNG, soit de quoi ne jamais collisionner.
fn random_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("CSPRNG du système indisponible");
    b64(&bytes)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    fn material() -> SigningMaterial {
        SigningMaterial::generate().unwrap().0
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn token(material: &SigningMaterial) -> IssuedToken {
        issue(
            material,
            "https://identity.example.com",
            "kdt-identity",
            &Subject::user("alice").unwrap(),
            &[Subject::group("ops").unwrap()],
            now(),
            chrono::Duration::minutes(5),
        )
        .unwrap()
    }

    fn parts(token: &str) -> (serde_json::Value, serde_json::Value) {
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3, "un JWS compact a trois segments");
        let decode = |s: &str| {
            serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .expect("base64url valide"),
            )
            .expect("JSON valide")
        };
        (decode(segments[0]), decode(segments[1]))
    }

    /// Le test qui compte : ce que nous signons doit se vérifier avec la clé publique publiée
    /// au JWKS. C'est exactement ce que fait l'apiserver.
    #[test]
    fn la_signature_se_verifie_avec_la_cle_publiee() {
        let material = material();
        let issued = token(&material);

        let (body, signature) = issued.token.rsplit_once('.').unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .unwrap();
        let signature = Signature::from_slice(&raw).expect("signature de 64 octets");

        let public: &VerifyingKey = material.signing_key().verifying_key();
        assert!(public.verify(body.as_bytes(), &signature).is_ok());
    }

    /// Une signature au format DER est acceptée par certaines bibliothèques et refusée par
    /// l'apiserver. Elle ne fait pas 64 octets : ce test le vérifie de la façon la plus
    /// directe qui soit.
    #[test]
    fn la_signature_est_en_r_s_brut() {
        let issued = token(&material());
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(issued.token.rsplit_once('.').unwrap().1)
            .unwrap();
        assert_eq!(raw.len(), 64);
    }

    #[test]
    fn l_en_tete_designe_la_cle_et_l_algorithme() {
        let material = material();
        let (header, _) = parts(&token(&material).token);

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], material.kid());
    }

    /// Le préfixe vient de l'émission, jamais d'un réglage de l'apiserver : si `sub` n'est pas
    /// déjà préfixé, un binding visant `kdt:alice` n'attrape rien — ou pire, un binding visant
    /// `alice` attrape quelqu'un d'autre.
    #[test]
    fn le_sujet_porte_deja_le_prefixe() {
        let (_, claims) = parts(&token(&material()).token);

        assert_eq!(claims["sub"], "kdt:alice");
        assert_eq!(claims["groups"][0], "kdt:ops");
    }

    #[test]
    fn les_dates_encadrent_la_duree_demandee() {
        let (_, claims) = parts(&token(&material()).token);

        assert_eq!(claims["iat"], now().timestamp());
        assert_eq!(claims["nbf"], now().timestamp());
        assert_eq!(claims["exp"], now().timestamp() + 300);
    }

    /// Deux jetons émis à la même seconde pour la même personne doivent rester distincts,
    /// sinon `jti` ne sert à rien en audit.
    #[test]
    fn chaque_jeton_porte_un_identifiant_propre() {
        let material = material();
        let (_, a) = parts(&token(&material).token);
        let (_, b) = parts(&token(&material).token);

        assert_ne!(a["jti"], b["jti"]);
        assert!(a["jti"].as_str().is_some_and(|j| !j.is_empty()));
    }

    /// Sans remplissage, et en alphabet URL : un `=` ou un `+` dans un segment casse les
    /// validateurs stricts, et le jeton voyage dans un en-tête HTTP.
    #[test]
    fn les_segments_sont_en_base64url_sans_remplissage() {
        let issued = token(&material());
        assert!(
            !issued.token.contains('=') && !issued.token.contains('+') && !issued.token.contains('/'),
            "{}",
            issued.token
        );
    }

    #[test]
    fn un_compte_sans_groupe_produit_une_liste_vide() {
        let material = material();
        let issued = issue(
            &material,
            "https://identity.example.com",
            "kdt-identity",
            &Subject::user("alice").unwrap(),
            &[],
            now(),
            chrono::Duration::minutes(5),
        )
        .unwrap();

        let (_, claims) = parts(&issued.token);
        assert_eq!(claims["groups"], serde_json::json!([]));
    }
}

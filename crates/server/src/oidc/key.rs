//! Clé de signature des jetons OIDC, et sa publication en JWKS.
//!
//! # Pourquoi ES256 plutôt que RS256
//!
//! L'apiserver accepte les deux. ES256 réutilise la P-256 déjà employée pour les demandes de
//! signature, tient dans une clé courte et se génère instantanément — là où une RSA 2048
//! demanderait une dépendance de plus, dont l'implémentation Rust traîne un avis de sécurité
//! non corrigé. Le prix est un drapeau à poser côté apiserver quand il est configuré par
//! `--oidc-*` : `--oidc-signing-algs=ES256`, la valeur par défaut étant `RS256` seul. La
//! configuration structurée, elle, accepte l'algorithme du JWKS sans rien déclarer.
//!
//! # Où vit la clé
//!
//! Dans un `Secret` du namespace, créé par le serveur au premier démarrage. Ni dans le chart,
//! ni dans une variable : la clé doit être identique d'une réplique à l'autre et survivre aux
//! redémarrages, sans quoi tous les jetons émis deviennent invalides à chaque bascule. La
//! création passe par un `create` — pas un apply — pour que deux répliques qui démarrent
//! ensemble ne s'écrasent pas : la seconde reçoit un conflit et relit ce que la première a
//! écrit.

use base64::Engine;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::{Api, ObjectMeta, PostParams};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::Serialize;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Nom du `Secret` portant la clé de signature.
pub const SECRET_NAME: &str = "kdt-identity-oidc-key";

/// Clé du champ dans ce `Secret`.
const KEY_FIELD: &str = "signing-key.pem";

/// Algorithme annoncé dans l'en-tête des jetons et dans le JWKS.
pub const ALG: &str = "ES256";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("appel à l'API Kubernetes : {0}")]
    Kube(#[from] kube::Error),
    #[error("la clé de signature stockée est illisible : {0}")]
    Corrupt(String),
    #[error("génération de la clé : {0}")]
    Generate(String),
}

/// La clé de signature en service, et son identifiant public.
#[derive(Clone)]
pub struct SigningMaterial {
    key: SigningKey,
    /// `kid` du JWKS : l'empreinte RFC 7638 de la clé publique.
    ///
    /// Dérivé de la clé plutôt que tiré au hasard, pour qu'une même clé porte toujours le même
    /// identifiant — y compris si le `Secret` est recréé à l'identique.
    kid: String,
}

/// `Debug` manuscrit : cette structure porte une clé privée de signature. La publier
/// permettrait de forger l'identité de n'importe qui sur le cluster.
impl std::fmt::Debug for SigningMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningMaterial")
            .field("kid", &self.kid)
            .field("key", &"<omis>")
            .finish()
    }
}

impl SigningMaterial {
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| KeyError::Corrupt(e.to_string()))?;
        let kid = thumbprint(&key);
        Ok(Self { key, kid })
    }

    pub fn generate() -> Result<(Self, Zeroizing<String>), KeyError> {
        let key = SigningKey::generate();
        let pem = Zeroizing::new(
            key.to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| KeyError::Generate(e.to_string()))?
                .to_string(),
        );
        let kid = thumbprint(&key);
        Ok((Self { key, kid }, pem))
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// La clé publique au format JWK, telle qu'elle paraît dans le JWKS.
    pub fn public_jwk(&self) -> Jwk {
        let (x, y) = coordinates(&self.key);
        Jwk {
            kty: "EC",
            crv: "P-256",
            x,
            y,
            use_: "sig",
            alg: ALG,
            kid: self.kid.clone(),
        }
    }
}

/// Une clé publique au format JWK. Seul EC P-256 est produit ici.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub x: String,
    pub y: String,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
}

/// Le document servi sur le point d'accès JWKS.
#[derive(Debug, Serialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Charge la clé depuis le cluster, ou l'y crée si elle n'existe pas encore.
///
/// La course entre deux répliques qui démarrent en même temps se résout par le conflit que
/// l'API renvoie sur le second `create` : le perdant relit, il ne réessaie pas d'écrire.
pub async fn load_or_create(
    client: kube::Client,
    namespace: &str,
) -> Result<SigningMaterial, KeyError> {
    let secrets: Api<Secret> = Api::namespaced(client, namespace);

    if let Some(existing) = secrets.get_opt(SECRET_NAME).await? {
        return read(&existing);
    }

    let (material, pem) = SigningMaterial::generate()?;
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(SECRET_NAME.to_string()),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        data: Some(BTreeMap::from([(
            KEY_FIELD.to_string(),
            ByteString(pem.as_bytes().to_vec()),
        )])),
        ..Default::default()
    };

    match secrets.create(&PostParams::default(), &secret).await {
        Ok(_) => {
            tracing::info!(kid = %material.kid(), "clé de signature OIDC créée");
            Ok(material)
        }
        // 409 : une autre réplique a gagné la course. La sienne fait autorité.
        Err(kube::Error::Api(e)) if e.code == 409 => {
            let existing = secrets.get(SECRET_NAME).await?;
            read(&existing)
        }
        Err(e) => Err(e.into()),
    }
}

fn read(secret: &Secret) -> Result<SigningMaterial, KeyError> {
    let raw = secret
        .data
        .as_ref()
        .and_then(|d| d.get(KEY_FIELD))
        .ok_or_else(|| KeyError::Corrupt(format!("champ {KEY_FIELD:?} absent")))?;
    let pem = std::str::from_utf8(&raw.0).map_err(|e| KeyError::Corrupt(format!("UTF-8 : {e}")))?;
    SigningMaterial::from_pem(pem)
}

/// Les coordonnées publiques, en base64url sans remplissage et sur 32 octets chacune.
///
/// La RFC 7518 impose la longueur fixe de la courbe : une coordonnée dont l'octet de poids
/// fort est nul doit garder son zéro, sinon les bibliothèques qui décodent strictement
/// rejettent la clé.
fn coordinates(key: &SigningKey) -> (String, String) {
    let point = key.verifying_key().to_sec1_point(false);
    let x = point.x().expect("un point non compressé porte ses coordonnées");
    let y = point.y().expect("un point non compressé porte ses coordonnées");
    (b64(x), b64(y))
}

/// Empreinte RFC 7638 de la clé publique.
///
/// Le calcul porte sur un JSON canonique — membres requis seulement, dans l'ordre
/// lexicographique, sans espace — ce que cette fonction écrit à la main plutôt que par
/// sérialisation : un sérialiseur qui réordonnerait les champs changerait l'empreinte sans
/// que rien ne le signale.
fn thumbprint(key: &SigningKey) -> String {
    use sha2::{Digest, Sha256};

    let (x, y) = coordinates(key);
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    b64(&Sha256::digest(canonical.as_bytes()))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn une_cle_engendree_se_relit() {
        let (material, pem) = SigningMaterial::generate().unwrap();
        let relue = SigningMaterial::from_pem(&pem).unwrap();

        assert_eq!(relue.kid(), material.kid());
        assert_eq!(relue.public_jwk(), material.public_jwk());
    }

    /// Le `kid` est dérivé de la clé : deux clés distinctes ne peuvent pas le partager, sans
    /// quoi un client qui choisit la clé de vérification par `kid` en prendrait une mauvaise.
    #[test]
    fn deux_cles_ont_des_identifiants_distincts() {
        let (a, _) = SigningMaterial::generate().unwrap();
        let (b, _) = SigningMaterial::generate().unwrap();
        assert_ne!(a.kid(), b.kid());
    }

    /// La RFC 7518 impose 32 octets par coordonnée sur P-256, remplissage compris. Un décodage
    /// strict rejette une coordonnée plus courte.
    #[test]
    fn les_coordonnees_font_la_taille_de_la_courbe() {
        for _ in 0..32 {
            let (material, _) = SigningMaterial::generate().unwrap();
            let jwk = material.public_jwk();
            for coord in [&jwk.x, &jwk.y] {
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(coord)
                    .expect("base64url valide");
                assert_eq!(bytes.len(), 32, "coordonnée {coord}");
            }
        }
    }

    /// Le JWKS est lu par l'apiserver : les noms de champs sont ceux de la RFC 7517, pas ceux
    /// que Rust aurait choisis.
    #[test]
    fn le_jwk_porte_les_noms_de_la_rfc() {
        let (material, _) = SigningMaterial::generate().unwrap();
        let json = serde_json::to_value(material.public_jwk()).unwrap();

        assert_eq!(json["kty"], "EC");
        assert_eq!(json["crv"], "P-256");
        assert_eq!(json["alg"], "ES256");
        assert_eq!(json["use"], "sig");
        assert!(json.get("use_").is_none(), "{json}");
        assert!(json["kid"].as_str().is_some_and(|k| !k.is_empty()));
    }

    /// Vecteur de la RFC 7638, section 3.1 : l'empreinte y est calculée sur une RSA, mais la
    /// forme canonique — membres requis, ordre lexicographique, aucun espace — est la même.
    /// Ce test fige la nôtre pour EC.
    #[test]
    fn l_empreinte_suit_la_forme_canonique() {
        use sha2::{Digest, Sha256};

        let (material, _) = SigningMaterial::generate().unwrap();
        let jwk = material.public_jwk();
        let attendu = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
            format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                jwk.x, jwk.y
            )
            .as_bytes(),
        ));
        assert_eq!(material.kid(), attendu);
    }

    #[test]
    fn une_cle_illisible_ne_passe_pas_pour_neuve() {
        assert!(SigningMaterial::from_pem("pas du PEM").is_err());
        assert!(SigningMaterial::from_pem("").is_err());
    }
}

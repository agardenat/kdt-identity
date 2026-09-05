//! Le jeton émis se vérifie-t-il avec la seule clé publiée ?
//!
//! C'est exactement ce que fait l'apiserver : il récupère le JWKS, reconstruit une clé de
//! vérification à partir des coordonnées publiées, et contrôle la signature. Un test qui
//! vérifierait avec la clé privée déjà en mémoire ne prouverait rien du JWKS — et une
//! coordonnée mal encodée, tronquée d'un zéro de tête par exemple, ne se verrait qu'en
//! production, sous la forme d'un cluster qui refuse toutes les identités.

use base64::Engine;
use kdt_identity_api::naming::Subject;
use kdt_identity_server::oidc::key::SigningMaterial;
use kdt_identity_server::oidc::{discovery, jwt};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

fn b64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url valide")
}

/// Reconstruit la clé de vérification à partir du seul JWKS, comme le ferait un client.
fn verifying_key_from_jwks(jwks: &serde_json::Value, kid: &str) -> VerifyingKey {
    let key = jwks["keys"]
        .as_array()
        .expect("le JWKS porte un tableau de clés")
        .iter()
        .find(|k| k["kid"] == kid)
        .expect("la clé désignée par l'en-tête est publiée");

    let x = b64(key["x"].as_str().unwrap());
    let y = b64(key["y"].as_str().unwrap());

    // Point SEC1 non compressé : 0x04 puis les deux coordonnées, 32 octets chacune.
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&sec1).expect("coordonnées valides pour P-256")
}

fn emis() -> (SigningMaterial, jwt::IssuedToken) {
    let material = SigningMaterial::generate().unwrap().0;
    let token = jwt::issue(
        &material,
        "https://identity.example.com",
        "kdt-identity",
        &Subject::user("alice").unwrap(),
        &[Subject::group("ops").unwrap(), Subject::group("lecteurs").unwrap()],
        chrono::Utc::now(),
        chrono::Duration::minutes(5),
    )
    .unwrap();
    (material, token)
}

#[test]
fn un_jeton_se_verifie_avec_la_seule_cle_publiee() {
    let (material, issued) = emis();

    let jwks = serde_json::to_value(kdt_identity_server::oidc::JwkSet {
        keys: vec![material.public_jwk()],
    })
    .unwrap();

    let (body, signature) = issued.token.rsplit_once('.').unwrap();
    let header: serde_json::Value = serde_json::from_slice(&b64(body.split('.').next().unwrap()))
        .unwrap();

    let key = verifying_key_from_jwks(&jwks, header["kid"].as_str().unwrap());
    let signature = Signature::from_slice(&b64(signature)).expect("signature de 64 octets");

    assert!(
        key.verify(body.as_bytes(), &signature).is_ok(),
        "le jeton ne se vérifie pas avec la clé du JWKS"
    );
}

/// Une signature valide pour un autre contenu vaudrait usurpation : le test le plus important
/// est celui qui échoue quand la charge est modifiée.
#[test]
fn un_jeton_modifie_ne_se_verifie_plus() {
    let (material, issued) = emis();

    let (body, signature) = issued.token.rsplit_once('.').unwrap();
    let (header, claims) = body.split_once('.').unwrap();

    let mut falsifie: serde_json::Value = serde_json::from_slice(&b64(claims)).unwrap();
    falsifie["groups"] = serde_json::json!(["system:masters"]);
    let corps = format!(
        "{header}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&falsifie).unwrap())
    );

    let key = *material.signing_key().verifying_key();
    let signature = Signature::from_slice(&b64(signature)).unwrap();

    assert!(key.verify(corps.as_bytes(), &signature).is_err());
}

/// Le document de découverte annonce l'adresse du JWKS et l'algorithme : un client qui suit
/// l'un et l'autre doit tomber sur ce que le portail sert réellement.
#[test]
fn la_decouverte_designe_ce_qui_est_servi() {
    let (material, _) = emis();
    let document = serde_json::to_value(discovery::document("https://identity.example.com")).unwrap();

    assert_eq!(
        document["jwks_uri"],
        format!("https://identity.example.com{}", discovery::JWKS_PATH)
    );
    assert_eq!(
        document["id_token_signing_alg_values_supported"][0],
        material.public_jwk().alg
    );
}

/// Les revendications sont celles que l'apiserver lit : le sujet devient le nom d'utilisateur,
/// les groupes deviennent les groupes, l'audience et l'émetteur sont confrontés à sa
/// configuration.
#[test]
fn les_revendications_decrivent_l_identite_attendue() {
    let (_, issued) = emis();
    let claims: serde_json::Value =
        serde_json::from_slice(&b64(issued.token.split('.').nth(1).unwrap())).unwrap();

    assert_eq!(claims["iss"], "https://identity.example.com");
    assert_eq!(claims["aud"], "kdt-identity");
    assert_eq!(claims["sub"], "kdt:alice");
    assert_eq!(claims["groups"], serde_json::json!(["kdt:ops", "kdt:lecteurs"]));
    assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
}

//! Le document de découverte, servi sur `/.well-known/openid-configuration`.
//!
//! L'apiserver le récupère au démarrage — et le rafraîchit ensuite — pour y trouver l'adresse
//! du JWKS. Il vérifie que le champ `issuer` correspond exactement à l'URL qu'on lui a
//! configurée : une différence de schéma, de port ou de barre oblique finale suffit à faire
//! échouer l'authentification, avec un message qui ne dit pas laquelle.
//!
//! # Un document délibérément incomplet
//!
//! kdt-identity n'est pas un fournisseur OAuth interactif : il n'y a ni page de consentement,
//! ni `authorization_endpoint`, ni échange de code. L'authentification se fait par mot de passe
//! et TOTP contre le portail, et le jeton s'obtient par l'API du plugin. Les champs qui
//! décriraient un flux que nous n'implémentons pas sont donc absents plutôt qu'inventés :
//! annoncer un point d'accès qui ne parle pas OAuth ferait échouer, plus tard et plus mal, un
//! client qui l'aurait cru.

use serde::Serialize;

/// Chemin du document de découverte. Fixé par la RFC 8414, pas par nous.
pub const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// Chemin du JWKS. Libre, mais publié dans le document ci-dessus.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

#[derive(Debug, Serialize)]
pub struct Discovery {
    pub issuer: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
}

/// Construit le document pour un émetteur donné.
///
/// `issuer` est repris tel quel : c'est l'URL du portail, débarrassée de sa barre oblique
/// finale à la lecture de la configuration. Le champ doit être identique, octet pour octet, à
/// ce que l'apiserver a dans sa configuration.
pub fn document(issuer: &str) -> Discovery {
    Discovery {
        issuer: issuer.to_string(),
        jwks_uri: format!("{issuer}{JWKS_PATH}"),
        response_types_supported: vec!["id_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec![super::key::ALG],
        scopes_supported: vec!["openid", "groups"],
        claims_supported: vec!["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "groups"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_document_annonce_l_emetteur_et_son_jwks() {
        let json = serde_json::to_value(document("https://identity.example.com")).unwrap();

        assert_eq!(json["issuer"], "https://identity.example.com");
        assert_eq!(
            json["jwks_uri"],
            "https://identity.example.com/.well-known/jwks.json"
        );
    }

    /// L'algorithme annoncé doit être celui avec lequel on signe réellement : un apiserver qui
    /// s'y fie refuserait tout jeton signé autrement.
    #[test]
    fn l_algorithme_annonce_est_celui_qui_signe() {
        let json = serde_json::to_value(document("https://identity.example.com")).unwrap();
        assert_eq!(json["id_token_signing_alg_values_supported"][0], "ES256");
    }

    /// Les noms de champs viennent de la RFC 8414, en snake_case : les renommer en camelCase,
    /// comme le reste de l'API du portail, rendrait le document illisible pour l'apiserver.
    #[test]
    fn les_champs_gardent_les_noms_de_la_rfc() {
        let json = serde_json::to_value(document("https://identity.example.com")).unwrap();

        for champ in [
            "issuer",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ] {
            assert!(json.get(champ).is_some(), "{champ} absent de {json}");
        }
    }
}

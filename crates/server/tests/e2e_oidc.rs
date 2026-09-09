//! Conversation avec un vrai fournisseur d'identité.
//!
//! Ignoré par défaut : ces tests sortent sur le réseau. Ce qu'ils constatent ne se bouchonne pas
//! utilement — un faux fournisseur validerait la façon dont on l'a écrit, pas ce qu'un tenant
//! Entra ID ou un Keycloak servent réellement sous `/.well-known/openid-configuration`.
//!
//! L'échange d'un code n'y figure pas : il exige un navigateur et un second facteur, et un test
//! qui les simulerait ne prouverait rien. Ce qui est vérifié ici, c'est tout ce qui précède —
//! joindre le fournisseur, se reconnaître dans ce qu'il annonce, et construire le départ.
//!
//! ```sh
//! export KDT_TEST_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
//! export KDT_TEST_OIDC_CLIENT_ID=<identifiant d'application>
//! export KDT_TEST_OIDC_CA=/chemin/vers/ca.crt      # facultatif, émetteur interne
//!
//! # Pour les deux tests Graph, qui exigent la permission d'application consentie :
//! export KDT_TEST_GRAPH_TENANT_ID=<tenant-id>
//! export KDT_TEST_GRAPH_CLIENT_SECRET=<secret de l'application>
//! export KDT_TEST_GRAPH_OBJECT_ID=<oid d'un compte du tenant>
//!
//! cargo test -p kdt-identity-server --test e2e_oidc -- --ignored --nocapture
//! ```

use kdt_identity_server::config::{OidcAuthConfig, OidcClaims, DEFAULT_OIDC_AUTH_SCOPES};
use kdt_identity_server::federation::mapping::GroupMappings;
use kdt_identity_server::federation::Source;
use kdt_identity_server::oidc_auth::graph::{Graph, GraphConfig};
use kdt_identity_server::oidc_auth::{Pending, Provider};
use zeroize::Zeroizing;

fn var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} doit être défini, voir l'en-tête du fichier"))
}

fn provider() -> Provider {
    kdt_identity_server::install_crypto_provider();

    Provider::new(OidcAuthConfig {
        issuer: var("KDT_TEST_OIDC_ISSUER").trim_end_matches('/').to_string(),
        client_id: var("KDT_TEST_OIDC_CLIENT_ID"),
        client_secret: None,
        scopes: DEFAULT_OIDC_AUTH_SCOPES.to_string(),
        claims: OidcClaims::default(),
        group_mappings: GroupMappings::parse(
            r#"[{"claim": "groupe-de-test", "group": "e2e-groupe"}]"#,
            Source::Oidc,
        )
        .expect("table de correspondance"),
        ca_file: std::env::var("KDT_TEST_OIDC_CA").ok(),
        timeout: std::time::Duration::from_secs(10),
        provider_name: "fournisseur de test".to_string(),
        graph: None,
    })
    .expect("client du fournisseur")
}

/// Le document de découverte, et la vérification qui en fait plus qu'une lecture : l'émetteur
/// qu'il annonce doit être celui qu'on a configuré, sans quoi les jetons porteront un `iss` que
/// le portail refusera — et le message parlerait alors du jeton, pas de la configuration.
#[tokio::test]
#[ignore]
async fn le_fournisseur_se_decouvre_et_se_reconnait() {
    let provider = provider();
    let metadata = provider.metadata().await.expect("découverte");

    println!("émetteur     : {}", metadata.issuer);
    println!("autorisation : {}", metadata.authorization_endpoint);
    println!("jetons       : {}", metadata.token_endpoint);

    assert!(metadata.authorization_endpoint.starts_with("https://"));
    assert!(metadata.token_endpoint.starts_with("https://"));

    // La seconde lecture passe par le cache, et rend exactement la même chose.
    let relu = provider.metadata().await.expect("seconde découverte");
    assert_eq!(relu.issuer, metadata.issuer);
}

/// L'URL de départ, telle qu'un navigateur la recevrait. Elle est affichée : ouverte à la main,
/// elle mène à la page de connexion du fournisseur, ce qui est le seul moyen de constater que
/// l'application est bien enregistrée avec cette adresse de retour.
#[tokio::test]
#[ignore]
async fn l_url_de_depart_se_construit() {
    let provider = provider();
    let pending = Pending::new(None);
    let redirect_uri = "https://identity.example.com/login/callback";

    let url = provider
        .authorize_url(&pending, redirect_uri)
        .await
        .expect("URL d'autorisation");

    println!("départ : {url}");

    assert!(url.contains("response_type=code"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("scope=openid"));
    // Le secret PKCE ne part jamais : seul son empreinte accompagne la demande.
    assert!(!url.contains(&pending.verifier), "{url}");
}

fn graph() -> Graph {
    kdt_identity_server::install_crypto_provider();

    Graph::new(GraphConfig {
        tenant_id: var("KDT_TEST_GRAPH_TENANT_ID"),
        client_id: var("KDT_TEST_OIDC_CLIENT_ID"),
        client_secret: Zeroizing::new(var("KDT_TEST_GRAPH_CLIENT_SECRET")),
        endpoint: "https://graph.microsoft.com".to_string(),
        authority: "https://login.microsoftonline.com".to_string(),
        resync: std::time::Duration::from_secs(900),
        timeout: std::time::Duration::from_secs(10),
    })
    .expect("client de Graph")
}

/// L'appartenance telle que la relecture la lit, et telle que la connexion la complète quand le
/// jeton l'a déportée. C'est ce que ni un bouchon ni un test unitaire ne prouvent : la permission
/// d'application est-elle réellement accordée, et consentie ?
#[tokio::test]
#[ignore]
async fn l_appartenance_se_lit_chez_le_fournisseur() {
    let object_id = var("KDT_TEST_GRAPH_OBJECT_ID");
    let groupes = graph()
        .member_objects(&object_id)
        .await
        .expect("appartenance");

    println!("groupes : {}", groupes.len());
    for groupe in groupes.iter().take(10) {
        println!("  {groupe}");
    }

    // Tout compte d'un tenant appartient à au moins un objet — ne serait-ce qu'un rôle
    // d'annuaire. Une liste vide sur un compte réel signale plutôt une permission incomplète.
    assert!(!groupes.is_empty(), "aucun groupe : permission incomplète ?");
}

/// Les deux réponses que la relecture doit savoir distinguer : un compte qui est là, et un compte
/// qui n'y est plus. Un identifiant inexistant doit rendre `None` — et surtout pas une erreur, que
/// la boucle prendrait pour une panne, ni un `Some` vide, qu'elle prendrait pour un compte sans
/// groupe.
#[tokio::test]
#[ignore]
async fn un_compte_absent_se_distingue_d_une_panne() {
    let graph = graph();

    let present = graph
        .account(&var("KDT_TEST_GRAPH_OBJECT_ID"))
        .await
        .expect("lecture du compte");
    assert!(present.is_some(), "le compte de test devrait exister");

    // Un GUID bien formé mais qui ne désigne personne.
    let absent = graph
        .account("00000000-0000-0000-0000-000000000000")
        .await
        .expect("un compte absent n'est pas une erreur");
    assert!(absent.is_none(), "{absent:?}");
}

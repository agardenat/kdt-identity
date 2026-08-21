//! Émission de bout en bout contre un vrai cluster.
//!
//! Ignoré par défaut : ces tests créent un `CertificateSigningRequest` et s'authentifient
//! ensuite avec le certificat obtenu. Ils ne créent aucun binding RBAC — l'identité de test
//! doit pouvoir s'authentifier sans obtenir le moindre droit, ce qui est précisément ce qu'on
//! cherche à démontrer.
//!
//! ```sh
//! KUBECONFIG=~/.z/.k/config cargo test -p kdt-identity-server --test e2e_issuance -- --ignored --nocapture
//! ```

use kdt_identity_api::naming::Subject;
use kdt_identity_server::credentials::issuer::{IssueError, Issuer, MIN_TTL};
use kdt_identity_server::credentials::kubeconfig::{self, ClusterEndpoint};
use kdt_identity_server::credentials::endpoint;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use std::time::Duration;

/// Suffixe aléatoire pour que deux exécutions concurrentes ne se marchent pas dessus.
fn unique(prefix: &str) -> String {
    let n: u32 = <u32 as p256::elliptic_curve::Generate>::generate();
    format!("{prefix}-{n:08x}")
}

async fn admin_client() -> Client {
    kdt_identity_server::install_crypto_provider();
    Client::try_default()
        .await
        .expect("kubeconfig introuvable : exporter KUBECONFIG")
}

/// Le cluster désigné par le contexte courant du kubeconfig d'exécution.
fn ambient_cluster() -> (String, kube::config::Cluster) {
    let kubeconfig = Kubeconfig::read().expect("lecture du kubeconfig");
    let context_name = kubeconfig
        .current_context
        .clone()
        .expect("aucun contexte courant");
    let named = kubeconfig
        .contexts
        .iter()
        .find(|c| c.name == context_name)
        .expect("contexte courant absent du kubeconfig");
    let cluster_name = named
        .context
        .as_ref()
        .expect("contexte vide")
        .cluster
        .clone();
    let cluster = kubeconfig
        .clusters
        .iter()
        .find(|c| c.name == cluster_name)
        .and_then(|c| c.cluster.clone())
        .expect("cluster absent du kubeconfig");

    (cluster_name, cluster)
}

/// Le déploiement décrit le cluster ; la lib sait déjà le faire.
fn endpoint_from_ambient_config() -> ClusterEndpoint {
    endpoint::from_ambient_kubeconfig().expect("découverte du cluster")
}

/// Ce que l'apiserver dit de nous, une fois authentifié avec le certificat émis.
async fn whoami(kubeconfig_yaml: &str) -> (String, Vec<String>) {
    kdt_identity_server::install_crypto_provider();
    use k8s_openapi::api::authentication::v1::SelfSubjectReview;
    use kube::api::{Api, PostParams};

    let mut parsed = Kubeconfig::from_yaml(kubeconfig_yaml).expect("kubeconfig produit illisible");

    // Étape strictement côté client, appliquée ici comme un utilisateur la ferait sur son
    // poste : si l'apiserver de ce cluster n'est joignable qu'à travers un tunnel, c'est à
    // celui qui l'utilise de l'indiquer. Le kubeconfig émis, lui, n'en sait rien.
    if let Some(proxy) = ambient_cluster().1.proxy_url {
        for cluster in &mut parsed.clusters {
            if let Some(inner) = cluster.cluster.as_mut() {
                inner.proxy_url = Some(proxy.clone());
            }
        }
    }

    let config = Config::from_custom_kubeconfig(parsed, &KubeConfigOptions::default())
        .await
        .expect("configuration client");
    let client = Client::try_from(config).expect("client");

    let api: Api<SelfSubjectReview> = Api::all(client);
    let review = api
        .create(&PostParams::default(), &SelfSubjectReview::default())
        .await
        .expect("SelfSubjectReview refusée");

    let info = review
        .status
        .expect("statut absent")
        .user_info
        .expect("userInfo absent");
    (
        info.username.unwrap_or_default(),
        info.groups.unwrap_or_default(),
    )
}

#[tokio::test]
#[ignore = "nécessite un cluster : crée un CertificateSigningRequest"]
async fn le_certificat_emis_authentifie_l_identite_et_ses_groupes() {
    let user = Subject::user(&unique("e2e")).unwrap();
    let groups = vec![
        Subject::group(&unique("e2e-grp-a")).unwrap(),
        Subject::group(&unique("e2e-grp-b")).unwrap(),
    ];

    let issuer = Issuer::new(admin_client().await);
    let credential = issuer
        .issue_with_generated_key(&user, &groups, MIN_TTL)
        .await
        .expect("émission");

    let endpoint = endpoint_from_ambient_config();
    let yaml = kubeconfig::standalone(&endpoint, &user, &credential).expect("kubeconfig");

    let (username, actual_groups) = whoami(&yaml).await;

    assert_eq!(username, user.as_str(), "identité vue par l'apiserver");
    for group in &groups {
        assert!(
            actual_groups.iter().any(|g| g == group.as_str()),
            "groupe {} absent de {actual_groups:?}",
            group.as_str()
        );
    }
    // Aucun binding n'a été créé : l'identité doit être authentifiée sans plus.
    assert!(
        actual_groups.iter().all(|g| g != "system:masters"),
        "l'identité émise ne doit jamais être administrateur : {actual_groups:?}"
    );
}

#[tokio::test]
#[ignore = "nécessite un cluster : crée un CertificateSigningRequest"]
async fn le_signeur_respecte_la_duree_demandee() {
    let user = Subject::user(&unique("e2e-ttl")).unwrap();
    let issuer = Issuer::new(admin_client().await);

    let before = chrono::Utc::now();
    let credential = issuer
        .issue_with_generated_key(&user, &[], MIN_TTL)
        .await
        .expect("émission");

    // Kubernetes antidate systématiquement de 5 minutes, d'où la marge haute.
    let lifetime = credential.not_after - before;
    assert!(
        lifetime <= chrono::Duration::from_std(MIN_TTL + Duration::from_secs(360)).unwrap(),
        "durée obtenue {lifetime}, bien au-delà des {MIN_TTL:?} demandées : \
         --cluster-signing-duration écrase-t-il la demande ?"
    );
    assert!(lifetime > chrono::Duration::zero(), "certificat déjà expiré");
}

/// La CSR est un objet éphémère : rien ne doit subsister dans le cluster après émission.
#[tokio::test]
#[ignore = "nécessite un cluster : crée un CertificateSigningRequest"]
async fn l_emission_ne_laisse_aucun_objet_derriere_elle() {
    use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
    use kube::api::{Api, ListParams};

    let client = admin_client().await;
    let user = Subject::user(&unique("e2e-gc")).unwrap();

    Issuer::new(client.clone())
        .issue_with_generated_key(&user, &[], MIN_TTL)
        .await
        .expect("émission");

    let csrs: Api<CertificateSigningRequest> = Api::all(client);
    let restants: Vec<String> = csrs
        .list(&ListParams::default())
        .await
        .expect("liste des CSR")
        .into_iter()
        .filter_map(|c| c.metadata.name)
        .filter(|n| n.starts_with("kdt-identity-"))
        .collect();

    assert!(restants.is_empty(), "CSR non nettoyées : {restants:?}");
}

/// Le contrôle qui protège tout le reste, rejoué contre un vrai cluster : une demande forgée
/// réclamant `system:masters` ne doit jamais atteindre le signeur.
#[tokio::test]
#[ignore = "nécessite un cluster"]
async fn une_demande_usurpant_system_masters_est_refusee_avant_le_cluster() {
    use der::{pem::LineEnding, EncodePem};
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::elliptic_curve::Generate;
    use std::str::FromStr;
    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::name::Name;

    let user = Subject::user(&unique("e2e-evil")).unwrap();
    let key = SigningKey::generate();
    let subject = Name::from_str(&format!("CN={},O=system:masters", user.as_str())).unwrap();
    let forgee = RequestBuilder::new(subject)
        .unwrap()
        .build::<_, DerSignature>(&key)
        .unwrap()
        .to_pem(LineEnding::LF)
        .unwrap();

    let err = Issuer::new(admin_client().await)
        .issue_from_csr(&forgee, &user, &[], MIN_TTL)
        .await
        .expect_err("la demande forgée a été acceptée");

    assert!(matches!(err, IssueError::SubjectMismatch(_)), "{err}");
}

use super::*;

fn identity() -> Identity {
    Identity {
        user: Subject::user("alice").unwrap(),
        groups: vec![
            Subject::group("ops").unwrap(),
            Subject::group("lecteurs").unwrap(),
        ],
        uid: Some("uid-1".to_string()),
    }
}

fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    headers
}

/// L'invariant central du proxy : un `kubectl --as` présenté par un porteur de jeton ne doit
/// jamais traverser. Sinon le proxy prêterait son droit d'impersonation à qui le lui demande,
/// et n'importe quel compte deviendrait `system:masters`.
#[test]
fn une_impersonation_presentee_par_le_client_est_ecrasee() {
    let incoming = header_map(&[
        ("impersonate-user", "system:masters"),
        ("Impersonate-Group", "system:masters"),
        ("IMPERSONATE-UID", "0"),
        ("impersonate-extra-scopes", "tout"),
        ("accept", "application/json"),
    ]);

    let headers = forward_headers(&incoming, &identity());

    assert_eq!(
        headers
            .get_all("impersonate-user")
            .iter()
            .collect::<Vec<_>>(),
        vec!["kdt:alice"]
    );
    assert_eq!(
        headers
            .get_all("impersonate-group")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["kdt:ops", "kdt:lecteurs"]
    );
    assert_eq!(headers.get("impersonate-uid").unwrap(), "uid-1");
    assert!(headers.get("impersonate-extra-scopes").is_none());
    assert_eq!(headers.get("accept").unwrap(), "application/json");
}

/// Le jeton du porteur ne doit pas fuir vers l'apiserver : c'est le client Kubernetes qui pose
/// son propre `Authorization`, et deux en-têtes en conflit seraient refusés.
#[test]
fn le_jeton_du_client_n_est_pas_relaye() {
    let incoming = header_map(&[
        ("authorization", "Bearer kdt_alice_abc.def"),
        ("connection", "keep-alive"),
        ("host", "identity.example.com"),
        ("user-agent", "kubectl/v1.31.0"),
    ]);

    let headers = forward_headers(&incoming, &identity());

    assert!(headers.get("authorization").is_none());
    assert!(headers.get("connection").is_none());
    assert!(headers.get("host").is_none());
    assert_eq!(headers.get("user-agent").unwrap(), "kubectl/v1.31.0");
}

/// Un compte sans groupe ne doit poser aucun `Impersonate-Group` : un en-tête vide ferait
/// authentifier une identité sans groupe du tout, là où l'apiserver en déduit les siens.
#[test]
fn un_compte_sans_groupe_ne_pose_aucun_groupe() {
    let seul = Identity {
        user: Subject::user("bob").unwrap(),
        groups: vec![],
        uid: None,
    };

    let headers = forward_headers(&HeaderMap::new(), &seul);

    assert_eq!(headers.get_all("impersonate-group").iter().count(), 0);
    assert!(headers.get("impersonate-uid").is_none());
    assert_eq!(headers.get("impersonate-user").unwrap(), "kdt:bob");
}

#[test]
fn le_chemin_amont_retire_le_prefixe_du_proxy() {
    for (raw, attendu) in [
        ("/k8s/demo/api/v1/pods", "/api/v1/pods"),
        ("/k8s/demo/api/v1/pods?watch=true", "/api/v1/pods?watch=true"),
        ("/k8s/demo/", "/"),
        ("/k8s/demo", "/"),
        ("/k8s/demo?timeout=5s", "/?timeout=5s"),
        ("/k8s/demo/apis/apps/v1/namespaces/x/deployments", "/apis/apps/v1/namespaces/x/deployments"),
    ] {
        assert_eq!(
            upstream_path_and_query(raw, "demo").as_deref(),
            Some(attendu),
            "{raw}"
        );
    }
}

/// Le pourcentage-encodage doit traverser intact : un `fieldSelector` ou un nom d'objet
/// réencodé désignerait autre chose que ce que le client a demandé.
#[test]
fn le_chemin_amont_ne_reencode_rien() {
    let raw = "/k8s/demo/api/v1/namespaces/x/pods?fieldSelector=metadata.name%3Dweb-0";

    assert_eq!(
        upstream_path_and_query(raw, "demo").as_deref(),
        Some("/api/v1/namespaces/x/pods?fieldSelector=metadata.name%3Dweb-0")
    );
}

#[test]
fn un_autre_cluster_ou_un_chemin_hors_proxy_est_refuse() {
    for raw in [
        "/k8s/autre/api/v1/pods",
        "/api/v1/pods",
        "/healthz",
        "/k8s/",
        "",
    ] {
        assert_eq!(upstream_path_and_query(raw, "demo"), None, "{raw:?}");
    }
}

#[test]
fn l_adresse_du_kubeconfig_porte_le_cluster() {
    assert_eq!(
        server_url("https://identity.example.com", "demo"),
        "https://identity.example.com/k8s/demo"
    );
    assert_eq!(
        server_url("https://identity.example.com/", "demo"),
        "https://identity.example.com/k8s/demo"
    );
}

/// Un refus doit se lire dans `kubectl`, qui affiche le `message` d'un `Status` et rien d'autre.
#[tokio::test]
async fn un_refus_parle_la_langue_de_kubectl() {
    let response = deny(DenyReason::Invalid);
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(parsed["kind"], "Status");
    assert_eq!(parsed["status"], "Failure");
    assert_eq!(parsed["code"], 401);
    assert_eq!(parsed["message"], "jeton invalide ou révoqué");
}

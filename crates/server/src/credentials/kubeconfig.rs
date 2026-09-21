//! Assemblage du kubeconfig remis à l'utilisateur.
//!
//! Le document est construit comme une structure puis sérialisé, jamais par interpolation dans
//! un gabarit texte : un kubeconfig est du YAML exécutable par `kubectl`, et une valeur mal
//! échappée y aurait des conséquences bien au-delà de l'affichage.

use serde::Serialize;

use super::issuer::{b64, IssuedCredential};
use kdt_identity_api::naming::Subject;

/// Identité du cluster : où il se trouve et comment vérifier son certificat serveur.
///
/// Volontairement dépourvu de toute notion d'acheminement réseau — pas de `proxy-url`, pas de
/// bastion. Certains postes atteignent l'apiserver par un tunnel, d'autres en direct : c'est
/// une propriété du poste, pas du cluster. L'inscrire ici imposerait la topologie réseau d'une
/// personne à tous les porteurs d'un kubeconfig émis. Qui doit passer par un proxy le sait et
/// l'ajoute de son côté, dans son kubeconfig ou via `HTTPS_PROXY` / `ALL_PROXY`.
#[derive(Debug, Clone)]
pub struct ClusterEndpoint {
    pub name: String,
    pub server: String,
    /// `None` quand le poste sait déjà vérifier ce serveur : un proxy derrière un Ingress dont
    /// le certificat vient d'une autorité publique n'a rien à faire figurer ici.
    pub certificate_authority_pem: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum KubeconfigError {
    #[error("sérialisation du kubeconfig : {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("le certificat a été émis sans clé privée : ce kubeconfig ne peut pas être autonome")]
    MissingKey,
}

/// Produit un kubeconfig autonome : certificat et clé sont embarqués.
///
/// Suppose que la clé a été générée côté serveur — c'est le chemin du téléchargement
/// navigateur. Pour le plugin `exec`, voir [`with_exec_plugin`].
pub fn standalone(
    endpoint: &ClusterEndpoint,
    user: &Subject,
    credential: &IssuedCredential,
) -> Result<String, KubeconfigError> {
    let key = credential
        .key_pem
        .as_ref()
        .ok_or(KubeconfigError::MissingKey)?;

    let auth = serde_yaml::to_value(AuthCertificate {
        client_certificate_data: b64(&credential.certificate_pem),
        client_key_data: b64(key),
    })?;
    render(endpoint, user, auth)
}

/// Produit un kubeconfig qui délègue l'obtention du credential au plugin `exec`.
///
/// C'est le chemin à privilégier : la clé privée est générée sur le poste et le certificat est
/// renouvelé automatiquement, ce qui rend une durée de validité courte indolore.
pub fn with_exec_plugin(
    endpoint: &ClusterEndpoint,
    user: &Subject,
    portal_url: &str,
    command: &str,
) -> Result<String, KubeconfigError> {
    let auth = serde_yaml::to_value(AuthExec {
        exec: ExecConfig {
            api_version: "client.authentication.k8s.io/v1".to_string(),
            command: command.to_string(),
            args: vec![
                "credential".to_string(),
                "--portal".to_string(),
                portal_url.to_string(),
                "--user".to_string(),
                user.name().to_string(),
            ],
            interactive_mode: "IfAvailable".to_string(),
            provide_cluster_info: false,
        },
    })?;
    render(endpoint, user, auth)
}

/// Produit un kubeconfig qui porte un jeton, adressé au proxy et non à l'apiserver.
///
/// C'est la seule forme à la fois autonome — aucun binaire à installer, `kubectl` et `helm` la
/// lisent nativement — et révocable : le jeton n'est rien par lui-même, sa validité se lit dans
/// le cluster à chaque requête. Le certificat, lui, est autonome mais définitif ; le plugin
/// `exec` est révocable mais suppose qu'on l'installe.
pub fn bearer(
    endpoint: &ClusterEndpoint,
    user: &Subject,
    token: &str,
) -> Result<String, KubeconfigError> {
    let auth = serde_yaml::to_value(AuthToken {
        token: token.to_string(),
    })?;
    render(endpoint, user, auth)
}

fn render(
    endpoint: &ClusterEndpoint,
    user: &Subject,
    auth: serde_yaml::Value,
) -> Result<String, KubeconfigError> {
    // Le nom du contexte reprend le sujet complet, préfixe compris : sur un poste qui a déjà
    // des accès Rancher ou Entra au même cluster, il faut voir d'un coup d'œil lequel est
    // lequel.
    let context_name = format!("{}@{}", user.as_str(), endpoint.name);

    let config = Kubeconfig {
        api_version: "v1",
        kind: "Config",
        clusters: vec![NamedCluster {
            name: endpoint.name.clone(),
            cluster: Cluster {
                server: endpoint.server.clone(),
                certificate_authority_data: endpoint
                    .certificate_authority_pem
                    .as_deref()
                    .map(b64),
            },
        }],
        users: vec![NamedUser {
            name: user.as_str().to_string(),
            user: auth,
        }],
        contexts: vec![NamedContext {
            name: context_name.clone(),
            context: Context {
                cluster: endpoint.name.clone(),
                user: user.as_str().to_string(),
            },
        }],
        current_context: context_name,
    };

    Ok(serde_yaml::to_string(&config)?)
}

/// Un kubeconfig mélange les conventions de nommage : `apiVersion` est en camelCase mais
/// `current-context` en kebab-case. Chaque champ est donc renommé explicitement — un
/// `rename_all` uniforme produit un document que `client-go` charge sans erreur mais dont il
/// ignore le contexte courant.
#[derive(Serialize)]
struct Kubeconfig {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    clusters: Vec<NamedCluster>,
    users: Vec<NamedUser>,
    contexts: Vec<NamedContext>,
    #[serde(rename = "current-context")]
    current_context: String,
}

#[derive(Serialize)]
struct NamedCluster {
    name: String,
    cluster: Cluster,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Cluster {
    server: String,
    /// Omis quand le serveur présente un certificat qu'un poste vérifie déjà — le cas d'un proxy
    /// derrière un Ingress public. L'inscrire quand même obligerait à réémettre tous les
    /// kubeconfigs au premier renouvellement de ce certificat.
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_authority_data: Option<String>,
}

#[derive(Serialize)]
struct NamedUser {
    name: String,
    user: serde_yaml::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthCertificate {
    client_certificate_data: String,
    client_key_data: String,
}

#[derive(Serialize)]
struct AuthToken {
    token: String,
}

#[derive(Serialize)]
struct AuthExec {
    exec: ExecConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecConfig {
    api_version: String,
    command: String,
    args: Vec<String>,
    interactive_mode: String,
    provide_cluster_info: bool,
}

#[derive(Serialize)]
struct NamedContext {
    name: String,
    context: Context,
}

#[derive(Serialize)]
struct Context {
    cluster: String,
    user: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn endpoint() -> ClusterEndpoint {
        ClusterEndpoint {
            name: "demo".to_string(),
            server: "https://127.0.0.1:6443".to_string(),
            certificate_authority_pem: Some(
                "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_string(),
            ),
        }
    }

    /// Le proxy tel qu'il est vu du poste : une URL et, ici, une autorité publique qu'il n'y a
    /// rien à déclarer.
    fn proxy_endpoint() -> ClusterEndpoint {
        ClusterEndpoint {
            name: "demo".to_string(),
            server: "https://identity.example.com/k8s/demo".to_string(),
            certificate_authority_pem: None,
        }
    }

    fn credential() -> IssuedCredential {
        IssuedCredential {
            certificate_pem: "-----BEGIN CERTIFICATE-----\nWFla\n-----END CERTIFICATE-----\n"
                .to_string(),
            key_pem: Some(zeroize::Zeroizing::new(
                "-----BEGIN PRIVATE KEY-----\nMTIz\n-----END PRIVATE KEY-----\n".to_string(),
            )),
            not_after: Utc::now(),
        }
    }

    /// Le document doit être relu comme un kubeconfig valide, avec les champs aux noms exacts
    /// attendus par client-go.
    #[test]
    fn produit_un_kubeconfig_relisible() {
        let user = Subject::user("alice").unwrap();
        let yaml = standalone(&endpoint(), &user, &credential()).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(parsed["apiVersion"], "v1");
        assert_eq!(parsed["kind"], "Config");
        // Kebab-case : `currentContext` serait silencieusement ignoré par client-go.
        assert_eq!(parsed["current-context"], "kdt:alice@demo");
        assert_eq!(parsed["contexts"][0]["context"]["user"], "kdt:alice");
        assert!(parsed["users"][0]["user"]["client-certificate-data"]
            .as_str()
            .is_some());
        assert!(parsed["users"][0]["user"]["client-key-data"]
            .as_str()
            .is_some());
    }

    /// Le kubeconfig émis ne décrit jamais d'acheminement réseau.
    ///
    /// Un `proxy-url` posé par le serveur s'appliquerait à tous les porteurs du kubeconfig,
    /// alors que passer par un tunnel est une propriété du poste. Ceux qui en ont besoin le
    /// savent et l'ajoutent eux-mêmes.
    #[test]
    fn n_impose_jamais_d_acheminement_reseau() {
        let user = Subject::user("alice").unwrap();
        let autonome = standalone(&endpoint(), &user, &credential()).unwrap();
        let exec =
            with_exec_plugin(&endpoint(), &user, "https://identity.example.com", "kdt-identity")
                .unwrap();

        for yaml in [&autonome, &exec] {
            assert!(!yaml.contains("proxy-url"), "{yaml}");
            assert!(!yaml.contains("proxy"), "{yaml}");
        }
    }

    /// Le kubeconfig du proxy doit être lisible par `kubectl` et `helm` sans rien installer :
    /// un `token`, et aucun `exec`.
    #[test]
    fn le_mode_proxy_ne_porte_qu_un_jeton() {
        let user = Subject::user("alice").unwrap();
        let yaml = bearer(&proxy_endpoint(), &user, "kdt_alice_abc.def").unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(parsed["users"][0]["user"]["token"], "kdt_alice_abc.def");
        assert!(parsed["users"][0]["user"]["exec"].is_null());
        assert!(parsed["users"][0]["user"]["client-certificate-data"].is_null());
        assert_eq!(
            parsed["clusters"][0]["cluster"]["server"],
            "https://identity.example.com/k8s/demo"
        );
        assert_eq!(parsed["current-context"], "kdt:alice@demo");
    }

    /// Une autorité absente ne doit pas produire une clé vide : `certificate-authority-data: ""`
    /// fait échouer client-go au lieu de le laisser vérifier avec le magasin du poste.
    #[test]
    fn une_autorite_absente_ne_laisse_pas_de_cle_vide() {
        let user = Subject::user("alice").unwrap();
        let yaml = bearer(&proxy_endpoint(), &user, "kdt_alice_abc.def").unwrap();

        assert!(!yaml.contains("certificate-authority-data"), "{yaml}");
    }

    #[test]
    fn le_mode_exec_ne_contient_aucun_secret() {
        let user = Subject::user("alice").unwrap();
        let yaml =
            with_exec_plugin(&endpoint(), &user, "https://identity.example.com", "kdt-identity")
                .unwrap();

        assert!(!yaml.contains("client-key-data"), "{yaml}");
        assert!(!yaml.contains("client-certificate-data"), "{yaml}");

        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let exec = &parsed["users"][0]["user"]["exec"];
        assert_eq!(exec["apiVersion"], "client.authentication.k8s.io/v1");
        assert_eq!(exec["command"], "kdt-identity");
        // Le plugin reçoit le nom stocké : c'est lui qui reconstruit le sujet préfixé.
        assert_eq!(exec["args"][4], "alice");
    }

    #[test]
    fn refuse_de_produire_un_kubeconfig_autonome_sans_cle() {
        let user = Subject::user("alice").unwrap();
        let mut cred = credential();
        cred.key_pem = None;

        assert!(matches!(
            standalone(&endpoint(), &user, &cred),
            Err(KubeconfigError::MissingKey)
        ));
    }
}

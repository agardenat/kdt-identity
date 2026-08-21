//! Découverte de l'endpoint à inscrire dans les kubeconfigs émis.

use super::kubeconfig::ClusterEndpoint;
use base64::Engine;

/// CA du cluster telle qu'elle est montée dans un pod.
const IN_CLUSTER_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("URL de l'apiserver absente : renseigner KDT_IDENTITY_APISERVER_URL")]
    NoApiserverUrl,
    #[error("lecture du kubeconfig : {0}")]
    Kubeconfig(#[from] kube::config::KubeconfigError),
    #[error("aucun contexte courant dans le kubeconfig")]
    NoCurrentContext,
    #[error("le cluster {0:?} est absent du kubeconfig")]
    UnknownCluster(String),
    #[error("le cluster {0:?} ne déclare pas d'URL de serveur")]
    NoServer(String),
    #[error("le cluster {0:?} ne déclare aucune autorité de certification")]
    NoCertificateAuthority(String),
    #[error("autorité de certification illisible : {0}")]
    BadCertificateAuthority(String),
}

/// Décrit le cluster désigné par le contexte courant du kubeconfig d'exécution.
///
/// Ne reprend **que** l'identité du cluster : nom, URL, autorité de certification. Un éventuel
/// `proxy-url` du kubeconfig source est délibérément ignoré — c'est une propriété du poste qui
/// exécute la commande, pas du cluster, et l'inscrire dans un kubeconfig destiné à quelqu'un
/// d'autre lui imposerait une topologie réseau qui n'est pas la sienne.
pub fn from_ambient_kubeconfig() -> Result<ClusterEndpoint, EndpointError> {
    let kubeconfig = kube::config::Kubeconfig::read()?;

    let context_name = kubeconfig
        .current_context
        .clone()
        .ok_or(EndpointError::NoCurrentContext)?;
    let cluster_name = kubeconfig
        .contexts
        .iter()
        .find(|c| c.name == context_name)
        .and_then(|c| c.context.as_ref())
        .map(|c| c.cluster.clone())
        .ok_or(EndpointError::NoCurrentContext)?;
    let cluster = kubeconfig
        .clusters
        .iter()
        .find(|c| c.name == cluster_name)
        .and_then(|c| c.cluster.as_ref())
        .ok_or_else(|| EndpointError::UnknownCluster(cluster_name.clone()))?;

    let certificate_authority_pem = match (
        cluster.certificate_authority_data.as_ref(),
        cluster.certificate_authority.as_ref(),
    ) {
        (Some(data), _) => {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| EndpointError::BadCertificateAuthority(format!("base64 : {e}")))?;
            String::from_utf8(raw)
                .map_err(|e| EndpointError::BadCertificateAuthority(format!("UTF-8 : {e}")))?
        }
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| EndpointError::BadCertificateAuthority(format!("{path} : {e}")))?,
        (None, None) => {
            return Err(EndpointError::NoCertificateAuthority(cluster_name));
        }
    };

    Ok(ClusterEndpoint {
        name: cluster_name.clone(),
        server: cluster
            .server
            .clone()
            .ok_or(EndpointError::NoServer(cluster_name))?,
        certificate_authority_pem,
    })
}

/// Décrit le cluster pour les kubeconfigs émis, en préférant la configuration explicite.
///
/// Dans un pod, le kubeconfig ambiant n'existe pas, et l'URL interne
/// `https://kubernetes.default.svc` ne sert à rien à un poste de travail : l'adresse publique
/// de l'apiserver doit donc être fournie. Hors cluster, le kubeconfig courant suffit et évite
/// d'avoir à la répéter.
pub fn resolve(
    apiserver_url: Option<&str>,
    cluster_name: &str,
    ca_file: Option<&str>,
) -> Result<ClusterEndpoint, EndpointError> {
    let Some(server) = apiserver_url else {
        return from_ambient_kubeconfig();
    };

    let ca_path = ca_file.unwrap_or(IN_CLUSTER_CA);
    let certificate_authority_pem = std::fs::read_to_string(ca_path)
        .map_err(|e| EndpointError::BadCertificateAuthority(format!("{ca_path} : {e}")))?;

    Ok(ClusterEndpoint {
        name: cluster_name.to_string(),
        server: server.to_string(),
        certificate_authority_pem,
    })
}

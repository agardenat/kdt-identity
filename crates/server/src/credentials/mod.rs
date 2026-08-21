//! Émission de credentials Kubernetes pour les identités kdt-identity.
//!
//! Deux chemins mènent à un certificat, et un seul est vraiment recommandé :
//!
//! - le plugin `exec` génère sa clé sur le poste et n'envoie que la demande — la clé privée
//!   ne traverse jamais le réseau ;
//! - le téléchargement navigateur laisse le serveur générer la paire, faute de mieux.
//!
//! Dans les deux cas, [`issuer::Issuer`] vérifie le sujet de la demande avant de l'approuver.

pub mod csr;
pub mod endpoint;
pub mod kubeconfig;
pub mod issuer;

pub use kubeconfig::{ClusterEndpoint, KubeconfigError};
pub use issuer::{IssueError, IssuedCredential, Issuer, SIGNER_NAME};

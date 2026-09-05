//! Mode OIDC : l'apiserver valide un jeton signé par kdt-identity, plutôt qu'un certificat
//! signé par la CA du cluster.
//!
//! # Ce que ce mode apporte, et ce qu'il coûte
//!
//! Pas la révocation : elle vient des [sessions de renouvellement](crate::sessions), qui
//! s'appliquent aussi bien aux certificats. Ce que l'OIDC apporte, c'est un `jti` par jeton
//! dans les journaux d'audit de l'apiserver — un certificat ne laisse que son sujet, identique
//! d'une émission à l'autre — et un émetteur que d'autres composants peuvent valider.
//!
//! Il apporte aussi le seul chemin praticable là où le signeur
//! `kubernetes.io/kube-apiserver-client` n'est pas servi : sur EKS, notamment, où aucune
//! demande de signature ne produit de certificat client.
//!
//! Il coûte la portabilité. Le mode certificat ne demande aucun changement au control plane ;
//! le mode OIDC exige que l'apiserver connaisse l'émetteur, donc qu'on puisse le configurer —
//! ce qu'AKS ne permet pas pour un émetteur tiers, alors qu'AKS signe très bien les demandes
//! de certificat.

pub mod discovery;
pub mod jwt;
pub mod key;

pub use key::{JwkSet, SigningMaterial};

//! Types et règles partagés entre le serveur kdt-identity et le plugin client.
//!
//! Ce crate ne parle jamais au cluster : il ne contient que des définitions et des invariants,
//! pour que la validation des noms soit exactement la même côté admission, côté API et côté
//! émission de certificat.

#[cfg(feature = "crd")]
pub mod crd;
pub mod csr;
pub mod naming;
pub mod portal;

#[cfg(feature = "crd")]
pub use crd::{
    KdtGroup, KdtGroupSpec, KdtGroupStatus, KdtUser, KdtUserSpec, KdtUserStatus, UserPhase,
    API_GROUP, API_VERSION, CREDENTIAL_SECRET_TYPE,
};
pub use naming::{assert_emittable, validate_name, NameError, Subject, SUBJECT_PREFIX};

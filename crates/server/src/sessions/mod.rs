//! Sessions de renouvellement : ce qui rend la révocation possible, dans les deux modes.
//!
//! Le mécanisme n'a rien d'OIDC, et c'est le constat qui a fait déplacer ce module. Trois
//! pièces suffisent à rendre un accès révocable :
//!
//! - une **durée courte**, qui borne la fenêtre pendant laquelle un accès survit à sa
//!   révocation ;
//! - un **droit de renouveler** conservé dans le cluster, pour que cette brièveté ne se paie
//!   pas en saisies de mot de passe ;
//! - la **suppression de ce droit**, qui est la révocation elle-même.
//!
//! Rien là-dedans ne suppose un jeton signé. Un certificat de dix minutes renouvelé
//! silencieusement se révoque exactement comme un jeton de cinq minutes — sans rien demander
//! au control plane, ce qui le rend utilisable là où l'apiserver ne s'aménage pas.

pub mod refresh;
pub mod store;

pub use refresh::{NewRefresh, RefreshError, Session, SessionSet};
pub use store::{SessionStore, SessionStoreError};

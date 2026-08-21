//! Authentification des utilisateurs auprès du portail.
//!
//! Ces modules ne parlent pas au cluster : ce sont les primitives — politique de mot de passe,
//! second facteur, invitations, verrouillage — que le portail assemble. Les garder purs les
//! rend testables exhaustivement, ce qui compte : chacune décide d'un accès.

pub mod invite;
pub mod lockout;
pub mod password;
pub mod store;
pub mod totp;

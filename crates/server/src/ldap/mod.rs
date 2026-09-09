//! Fédération d'identité sur un annuaire LDAP(S).
//!
//! Le mot de passe n'est pas comparé, il est **présenté** : c'est l'annuaire qui répond, par un
//! bind, s'il est le bon. kdt-identity ne stocke donc rien de secret pour un compte fédéré — ni
//! empreinte, ni secret TOTP — et le `Secret` de credentials ne sert plus qu'à porter le
//! compteur de verrouillage.
//!
//! # La recherche puis le bind, et pourquoi dans cet ordre
//!
//! On ne peut pas binder directement avec ce que la personne a saisi : un bind attend un DN
//! complet, et personne ne connaît le sien. Il faut donc d'abord chercher l'entrée — sous
//! l'identité du compte de service, ou anonymement — pour en tirer le DN, puis binder avec ce
//! DN et le mot de passe saisi. Le second bind ouvre sa propre connexion : rebinder celle de la
//! recherche en changerait l'identité au milieu de son usage.

pub mod filter;
pub mod profile;
pub mod trust;

use crate::config::LdapConfig;
use crate::federation::{self, FederatedUser};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    /// L'annuaire a répondu, et il refuse. C'est le seul cas qui compte un échec.
    #[error("identifiants refusés par l'annuaire")]
    InvalidCredentials,
    /// L'annuaire n'a pas répondu, ou pas comme il faut.
    ///
    /// Distingué du refus, et c'est essentiel : compter une panne d'annuaire comme un mot de
    /// passe faux verrouillerait tous les comptes du cluster en quelques minutes.
    #[error("annuaire injoignable : {0}")]
    Unavailable(String),
    /// L'entrée existe mais ne permet pas de construire un compte.
    #[error("{0}")]
    Unusable(String),
    /// L'annuaire a répondu, mais le cluster n'a pas suivi.
    ///
    /// Séparé des trois autres pour la même raison : ce n'est ni un refus, ni une panne
    /// d'annuaire, et le confondre avec l'un ou l'autre mènerait au mauvais diagnostic.
    #[error("cluster : {0}")]
    Cluster(String),
}

/// Ce que le provisionnement peut refuser, traduit dans les termes de l'annuaire.
///
/// La distinction entre une entrée inutilisable et un cluster qui ne suit pas est déjà faite
/// par [`federation::Error`] : la reporter ici garde les journaux et le verrouillage identiques
/// quelle que soit l'étape qui a échoué.
impl From<federation::Error> for LdapError {
    fn from(error: federation::Error) -> Self {
        match error {
            federation::Error::Unusable(raison) => Self::Unusable(raison),
            federation::Error::Unavailable(raison) => Self::Unavailable(raison),
            federation::Error::Cluster(raison) => Self::Cluster(raison),
        }
    }
}

pub struct Directory {
    config: LdapConfig,
}

/// L'annuaire vu par la relecture périodique.
///
/// Une entrée est désignée par son DN, qui est ce que le compte a épinglé : son nom kdt est une
/// forme *normalisée* de l'identifiant, qu'on ne sait pas dénormaliser.
impl federation::Federated for Directory {
    fn source(&self) -> federation::Source {
        federation::Source::Ldap
    }

    fn interval(&self) -> std::time::Duration {
        self.config.resync
    }

    fn mappings(&self) -> &crate::federation::mapping::GroupMappings {
        &self.config.group_mappings
    }

    async fn lookup_groups(
        &self,
        pin: &str,
    ) -> Result<Option<Vec<String>>, federation::Error> {
        match self.lookup_dn(pin).await {
            Ok(entry) => Ok(entry.map(|user| user.member_of)),
            Err(LdapError::Unusable(raison)) => Err(federation::Error::Unusable(raison)),
            Err(LdapError::Cluster(raison)) => Err(federation::Error::Cluster(raison)),
            // Un refus d'identifiants n'a pas de sens ici — rien n'est présenté — mais s'il
            // survenait, ce serait le bind de service : une panne de configuration, pas une
            // disparition de compte.
            Err(e) => Err(federation::Error::Unavailable(format!("{e}"))),
        }
    }
}

impl Directory {
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &LdapConfig {
        &self.config
    }

    /// Vérifie un mot de passe auprès de l'annuaire et rend ce qu'il sait de la personne.
    pub async fn authenticate(
        &self,
        login: &str,
        password: &str,
    ) -> Result<FederatedUser, LdapError> {
        // Un bind avec un mot de passe vide est un *bind non authentifié* : la RFC 4513 le
        // définit comme une connexion anonyme, et l'annuaire répond `success`. Sans ce refus,
        // n'importe quel identifiant existant ouvrirait une session sans mot de passe.
        if password.is_empty() {
            return Err(LdapError::InvalidCredentials);
        }

        let user = self
            .lookup(login)
            .await?
            .ok_or(LdapError::InvalidCredentials)?;

        // Second bind, sur sa propre connexion, avec le DN trouvé et le mot de passe saisi.
        let (conn, mut ldap) = self.connect().await?;
        ldap3::drive!(conn);

        let resultat = ldap
            .simple_bind(&user.pin, password)
            .await
            .map_err(|e| LdapError::Unavailable(format!("bind : {e}")))?;
        let refuse = resultat.success().is_err();
        let _ = ldap.unbind().await;

        if refuse {
            return Err(LdapError::InvalidCredentials);
        }

        Ok(user)
    }

    /// Cherche une personne sans vérifier de mot de passe.
    ///
    /// Sert à la resynchronisation : le contrôleur relit l'appartenance de comptes dont
    /// personne n'a saisi le mot de passe, et doit pouvoir constater qu'une entrée a disparu.
    pub async fn lookup(&self, login: &str) -> Result<Option<FederatedUser>, LdapError> {
        let (conn, mut ldap) = self.connect().await?;
        ldap3::drive!(conn);

        self.service_bind(&mut ldap).await?;

        let attributes = &self.config.attributes;
        let (entries, _) = ldap
            .search(
                &self.config.user_search_base,
                Scope::Subtree,
                &filter::user_filter(attributes, login),
                &[
                    attributes.login.as_str(),
                    attributes.email.as_str(),
                    attributes.display.as_str(),
                    attributes.member_of.as_str(),
                ],
            )
            .await
            .map_err(|e| LdapError::Unavailable(format!("recherche : {e}")))?
            .success()
            .map_err(|e| LdapError::Unavailable(format!("recherche refusée : {e}")))?;
        let _ = ldap.unbind().await;

        // Plusieurs entrées pour un identifiant de connexion : l'annuaire est ambigu, et
        // choisir la première reviendrait à laisser le hasard décider de qui se connecte.
        if entries.len() > 1 {
            warn!(
                login = %login,
                entrees = entries.len(),
                "plusieurs entrées pour un même identifiant, connexion refusée"
            );
            return Err(LdapError::Unusable(
                "l'annuaire rend plusieurs entrées pour cet identifiant".to_string(),
            ));
        }

        let Some(entry) = entries.into_iter().next() else {
            return Ok(None);
        };
        let entry = SearchEntry::construct(entry);
        let dn = entry.dn.clone();

        // L'identifiant vient de l'annuaire, jamais de la saisie : c'est lui qui nommera le
        // `KdtUser`, et le laisser venir du formulaire ferait dépendre le nom du compte de la
        // casse tapée ce jour-là.
        self.to_federated_user(entry).map(Some).ok_or_else(|| {
            LdapError::Unusable(format!(
                "l'entrée {dn} ne porte pas d'attribut {}",
                attributes.login
            ))
        })
    }

    /// Relit une entrée par son DN, sans passer par l'identifiant de connexion.
    ///
    /// C'est ce dont la resynchronisation a besoin : le DN est ce que le compte a épinglé, alors
    /// que son nom kdt est une forme *normalisée* de l'identifiant, qu'on ne sait pas
    /// dénormaliser. Chercher par DN est en outre exact — une recherche en `Base` porte sur
    /// cette entrée et sur aucune autre.
    ///
    /// `Ok(None)` dit que l'entrée a disparu, et seulement cela : une panne remonte en
    /// [`LdapError::Unavailable`], que l'appelant ne doit surtout pas confondre avec une
    /// disparition.
    pub async fn lookup_dn(&self, dn: &str) -> Result<Option<FederatedUser>, LdapError> {
        let (conn, mut ldap) = self.connect().await?;
        ldap3::drive!(conn);

        self.service_bind(&mut ldap).await?;

        let attributes = &self.config.attributes;
        let resultat = ldap
            .search(
                dn,
                Scope::Base,
                "(objectClass=*)",
                &[
                    attributes.login.as_str(),
                    attributes.email.as_str(),
                    attributes.display.as_str(),
                    attributes.member_of.as_str(),
                ],
            )
            .await
            .map_err(|e| LdapError::Unavailable(format!("relecture de {dn} : {e}")))?;
        let _ = ldap.unbind().await;

        // `noSuchObject` (32) est la réponse normale à une entrée supprimée : c'est un
        // résultat, pas une panne. Tout autre code d'erreur en est une.
        let (entries, _) = match resultat.success() {
            Ok(pair) => pair,
            Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => return Ok(None),
            Err(e) => return Err(LdapError::Unavailable(format!("relecture de {dn} : {e}"))),
        };

        Ok(entries
            .into_iter()
            .next()
            .and_then(|entry| self.to_federated_user(SearchEntry::construct(entry))))
    }

    async fn service_bind(&self, ldap: &mut ldap3::Ldap) -> Result<(), LdapError> {
        let (Some(dn), Some(password)) = (&self.config.bind_dn, &self.config.bind_password) else {
            return Ok(());
        };

        ldap.simple_bind(dn, password)
            .await
            .map_err(|e| LdapError::Unavailable(format!("bind de service : {e}")))?
            .success()
            .map_err(|e| LdapError::Unavailable(format!("bind de service refusé : {e}")))?;
        Ok(())
    }

    /// Traduit une entrée en compte, ou rien si elle ne porte pas d'identifiant de connexion.
    fn to_federated_user(&self, entry: SearchEntry) -> Option<FederatedUser> {
        let attributes = &self.config.attributes;
        Some(FederatedUser {
            login: first(&entry, &attributes.login)?,
            email: first(&entry, &attributes.email),
            display_name: first(&entry, &attributes.display),
            member_of: entry
                .attrs
                .iter()
                .find(|(nom, _)| nom.eq_ignore_ascii_case(&attributes.member_of))
                .map(|(_, valeurs)| valeurs.clone())
                .unwrap_or_default(),
            pin: entry.dn,
        })
    }

    async fn connect(&self) -> Result<(ldap3::LdapConnAsync, ldap3::Ldap), LdapError> {
        // `set_no_tls_verify` n'est jamais appelé : accepter un certificat quelconque rendrait
        // le chiffrement décoratif, un intercepteur pouvant alors lire chaque mot de passe.
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.config.timeout)
            .set_starttls(self.config.start_tls);

        LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| LdapError::Unavailable(format!("connexion à {} : {e}", self.config.url)))
    }
}

/// Première valeur d'un attribut, en tolérant la casse du nom.
///
/// Un annuaire rend les attributs sous la casse de son schéma, pas sous celle de la requête :
/// demander `memberOf` peut donner `memberof`. Chercher la clé exacte marcherait sur un annuaire
/// et rendrait une liste vide sur l'autre, sans erreur.
fn first(entry: &SearchEntry, attribute: &str) -> Option<String> {
    entry
        .attrs
        .iter()
        .find(|(nom, _)| nom.eq_ignore_ascii_case(attribute))
        .and_then(|(_, valeurs)| valeurs.first())
        .map(|valeur| valeur.trim().to_string())
        .filter(|valeur| !valeur.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn entry(attrs: &[(&str, &str)]) -> SearchEntry {
        SearchEntry {
            dn: "cn=alice,dc=example,dc=com".to_string(),
            attrs: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                .collect::<HashMap<_, _>>(),
            bin_attrs: HashMap::new(),
        }
    }

    /// Un annuaire rend ses attributs sous la casse de son schéma. Chercher la clé exacte
    /// marcherait sur l'un et rendrait vide sur l'autre — sans erreur, donc sans groupes.
    #[test]
    fn un_attribut_se_lit_quelle_que_soit_sa_casse() {
        let e = entry(&[("memberof", "cn=g,dc=x"), ("SAMAccountName", "alice")]);

        assert_eq!(first(&e, "memberOf"), Some("cn=g,dc=x".to_string()));
        assert_eq!(first(&e, "sAMAccountName"), Some("alice".to_string()));
        assert_eq!(first(&e, "mail"), None);
    }

    /// Un attribut présent mais vide n'est pas une valeur : le laisser passer produirait un
    /// `KdtUser` dont l'adresse est la chaîne vide, que l'apiserver accepte.
    #[test]
    fn un_attribut_vide_vaut_un_attribut_absent() {
        let e = entry(&[("mail", "   ")]);
        assert_eq!(first(&e, "mail"), None);
    }
}

//! Sessions de rafraîchissement : ce qui rend la révocation possible.
//!
//! Un certificat émis vaut jusqu'à son expiration, sans recours. Un jeton OIDC ne dure que
//! quelques minutes, et le droit d'en obtenir un autre est une ligne dans le cluster : la
//! supprimer coupe l'accès au renouvellement suivant, soit quelques minutes plus tard. C'est
//! toute la différence entre les deux modes, et elle tient dans ce fichier.
//!
//! # Ce qui est conservé
//!
//! Le jeton présenté a la forme `<identifiant>.<secret>`. Seul le SHA-256 du secret est
//! stocké, comme pour les invitations : une fuite du `Secret` ne rend aucun jeton utilisable.
//! L'identifiant, lui, est en clair — il ne sert qu'à retrouver la bonne entrée sans comparer
//! toutes les empreintes.
//!
//! # Ce qui n'est pas fait, et pourquoi
//!
//! Le jeton n'est pas renouvelé à chaque usage. La rotation détecte le rejeu d'un jeton volé,
//! mais impose une écriture dans le cluster à chaque renouvellement — donc un point de panne
//! et une course entre deux `kubectl` lancés en même temps. Le jeton vit sur le poste dans un
//! fichier en 0600, exactement comme la clé privée du mode certificat : le vol qu'il faudrait
//! détecter suppose déjà un accès au compte local.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Taille du secret d'un jeton de rafraîchissement, en octets.
pub const SECRET_BYTES: usize = 32;

/// Taille de l'identifiant de session, en octets.
const ID_BYTES: usize = 8;

/// Nombre de sessions simultanées conservées par compte, **pour chaque usage**.
///
/// Un poste fixe, un portable, une machine de secours : au-delà, les plus anciennes sont
/// évincées. Sans plafond, chaque connexion ajouterait une ligne qu'aucun chemin n'efface, et
/// le `Secret` finirait par grossir sans limite. Le compte est tenu par `SessionKind` : trois
/// kubeconfigs téléchargés ne doivent pas évincer les sessions du plugin.
pub const MAX_SESSIONS: usize = 5;

/// Ce qu'une session autorise.
///
/// Les usages ne sont pas interchangeables : un jeton de renouvellement ne doit pas ouvrir le
/// proxy, et un jeton de proxy ne doit pas émettre de certificat. `verify` exige donc l'usage
/// attendu, et le refus est le même que pour un jeton inconnu.
///
/// Le plafond se compte par usage, et c'est là que la distinction entre les deux usages du proxy
/// gagne sa place : une application renouvelle son accès toutes les dix minutes, un fichier
/// téléchargé vit ses jours. Comptés ensemble, les premiers évinceraient les seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionKind {
    /// Droit de renouveler un credential, présenté par le plugin. C'est le défaut en
    /// désérialisation : les `Secret` écrits avant l'arrivée du proxy n'ont pas ce champ.
    #[default]
    Refresh,
    /// Jeton porté par un kubeconfig téléchargé, présenté au proxy à chaque requête.
    Kubeconfig,
    /// Jeton remis à une application autorisée — kdt-web —, présenté au proxy de la même façon.
    /// Elle le renouvelle toute seule, là où un fichier ne se renouvelle pas.
    Application,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefreshError {
    /// Jeton inconnu, mal formé ou dont le secret ne correspond pas. Les trois cas se
    /// confondent volontairement : les distinguer dirait à qui cherche s'il a trouvé un
    /// identifiant valide.
    #[error("jeton de rafraîchissement invalide")]
    Invalid,
    #[error("jeton de rafraîchissement expiré")]
    Expired,
}

/// Une session ouverte, telle qu'elle est conservée dans le cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    /// SHA-256 du secret, en hexadécimal minuscule.
    pub secret_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub kind: SessionKind,
}

/// Toutes les sessions d'un compte.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionSet {
    sessions: Vec<Session>,
}

/// Un jeton fraîchement émis. Le secret n'existe en clair qu'ici et dans la réponse HTTP.
pub struct NewRefresh {
    pub token: Zeroizing<String>,
    pub session: Session,
}

impl SessionSet {
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Nombre de sessions d'un usage donné. La vue `:identity` de kdt les compte à part.
    pub fn count_of(&self, kind: SessionKind) -> usize {
        self.sessions.iter().filter(|s| s.kind == kind).count()
    }

    /// Ouvre une session valable `validity`, et rend le jeton à remettre au client.
    ///
    /// Les sessions expirées sont retirées au passage : c'est le seul moment où quelqu'un
    /// regarde cette liste, et rien d'autre ne viendrait faire le ménage.
    pub fn open(
        &mut self,
        now: DateTime<Utc>,
        validity: chrono::Duration,
        kind: SessionKind,
    ) -> NewRefresh {
        self.prune(now);

        let mut id_bytes = [0u8; ID_BYTES];
        getrandom::fill(&mut id_bytes).expect("CSPRNG du système indisponible");
        let mut secret_bytes = Zeroizing::new([0u8; SECRET_BYTES]);
        getrandom::fill(secret_bytes.as_mut_slice()).expect("CSPRNG du système indisponible");

        let id = b64(&id_bytes);
        let secret = Zeroizing::new(b64(secret_bytes.as_slice()));

        let session = Session {
            id: id.clone(),
            secret_hash: hex(&Sha256::digest(secret.as_bytes())),
            issued_at: now,
            expires_at: now + validity,
            kind,
        };

        self.sessions.push(session.clone());
        // Le plafond s'applique après l'ajout : ouvrir une session de plus doit réussir, quitte
        // à ce que la plus ancienne tombe. Refuser la nouvelle laisserait quelqu'un dehors à
        // cause de postes qu'il n'utilise plus.
        while self.count_of(kind) > MAX_SESSIONS {
            let doyenne = self
                .sessions
                .iter()
                .filter(|s| s.kind == kind)
                .min_by_key(|s| (s.issued_at, s.id.clone()))
                .map(|s| s.id.clone())
                .expect("au moins une session de cet usage vient d'être ajoutée");
            self.sessions.retain(|s| s.id != doyenne);
        }

        NewRefresh {
            token: Zeroizing::new(format!("{id}.{}", secret.as_str())),
            session,
        }
    }

    /// Vérifie un jeton présenté pour l'usage `expect`, et rend l'identifiant de la session.
    ///
    /// La comparaison est à temps constant, et une session inconnue provoque malgré tout un
    /// calcul d'empreinte : sans cela, le temps de réponse distinguerait un identifiant connu
    /// d'un identifiant inventé. Un jeton présenté pour le mauvais usage est refusé comme un
    /// jeton inconnu.
    pub fn verify(
        &self,
        presented: &str,
        now: DateTime<Utc>,
        expect: SessionKind,
    ) -> Result<String, RefreshError> {
        let (id, secret) = presented.split_once('.').ok_or(RefreshError::Invalid)?;
        let digest = Sha256::digest(secret.as_bytes());

        let found = self
            .sessions
            .iter()
            .find(|s| s.id == id && s.kind == expect);
        let expected = found
            .and_then(|s| decode_hex(&s.secret_hash))
            .unwrap_or([0u8; 32]);

        if digest.as_slice().ct_eq(&expected).unwrap_u8() != 1 || found.is_none() {
            return Err(RefreshError::Invalid);
        }

        let session = found.expect("présente, vérifiée juste au-dessus");
        if now >= session.expires_at {
            return Err(RefreshError::Expired);
        }
        Ok(session.id.clone())
    }

    /// Vérifie un jeton présenté **au proxy**, quel que soit celui des deux usages qui l'ouvre.
    ///
    /// Un fichier téléchargé et une application autorisée ne diffèrent que par ce qui les fait
    /// naître et par le plafond qui les compte : devant le proxy, ils valent la même chose.
    /// L'expiration n'est pas réessayée comme un autre usage — un jeton périmé est périmé.
    pub fn verify_proxy(
        &self,
        presented: &str,
        now: DateTime<Utc>,
    ) -> Result<String, RefreshError> {
        match self.verify(presented, now, SessionKind::Kubeconfig) {
            Err(RefreshError::Invalid) => self.verify(presented, now, SessionKind::Application),
            other => other,
        }
    }

    /// Ferme une session. Sans effet si elle n'existe pas — se déconnecter deux fois n'est pas
    /// une erreur.
    pub fn close(&mut self, id: &str) {
        self.sessions.retain(|s| s.id != id);
    }

    /// Ferme toutes les sessions : c'est la révocation.
    pub fn close_all(&mut self) -> usize {
        let count = self.sessions.len();
        self.sessions.clear();
        count
    }

    /// Retire les sessions expirées.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.sessions.retain(|s| now < s.expires_at);
    }

    /// Les sessions en cours, de la plus ancienne à la plus récente.
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter()
    }
}

/// Préfixe du jeton porté par un kubeconfig téléchargé.
///
/// Il permet au proxy d'écarter d'emblée ce qui ne lui appartient pas — un jeton de
/// `ServiceAccount`, un reste de jeton d'un autre produit — sans lire le moindre `Secret`.
pub const KUBECONFIG_TOKEN_PREFIX: &str = "kdt_";

/// Compose le jeton que le proxy lit : `kdt_<compte>_<identifiant>.<secret>`.
///
/// Le compte y figure parce que le proxy ne reçoit qu'un en-tête `Authorization` : sans lui,
/// rien ne dirait quel `Secret` de sessions relire. Ce n'est pas un secret, et le séparateur
/// est `_` parce que [`NAME_PATTERN`](kdt_identity_api::naming::NAME_PATTERN) l'interdit dans
/// un nom de compte — contrairement au `.`, qu'il admet.
pub fn proxy_token(user: &str, issued: &NewRefresh) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{KUBECONFIG_TOKEN_PREFIX}{user}_{}",
        issued.token.as_str()
    ))
}

/// Sépare un jeton de proxy en compte et paire `<identifiant>.<secret>`.
///
/// Ne valide pas le compte : c'est à l'appelant de le faire avant d'en dériver un nom de
/// `Secret`. Rend `None` sur tout ce qui n'a pas la forme attendue.
pub fn split_proxy_token(presented: &str) -> Option<(&str, &str)> {
    let rest = presented.strip_prefix(KUBECONFIG_TOKEN_PREFIX)?;
    let (user, credential) = rest.split_once('_')?;
    if user.is_empty() || !credential.contains('.') {
        return None;
    }
    Some((user, credential))
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn week() -> Duration {
        Duration::days(7)
    }

    #[test]
    fn un_jeton_emis_se_verifie() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), week(), SessionKind::Refresh);

        assert_eq!(set.verify(&issued.token, now(), SessionKind::Refresh).unwrap(), issued.session.id);
    }

    /// Le secret ne doit pas être conservé en clair : une fuite du Secret ne doit pas rendre
    /// les jetons rejouables.
    #[test]
    fn le_secret_n_est_pas_stocke_en_clair() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), week(), SessionKind::Refresh);
        let secret = issued.token.split_once('.').unwrap().1;

        let stocke = serde_json::to_string(&set).unwrap();
        assert!(!stocke.contains(secret), "{stocke}");
    }

    #[test]
    fn un_jeton_expire_est_refuse() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), Duration::hours(1), SessionKind::Refresh);

        assert!(set
            .verify(&issued.token, now() + Duration::minutes(59), SessionKind::Refresh)
            .is_ok());
        assert_eq!(
            set.verify(&issued.token, now() + Duration::hours(1), SessionKind::Refresh),
            Err(RefreshError::Expired)
        );
    }

    /// La révocation est la raison d'être du mode OIDC : après elle, le jeton ne vaut plus
    /// rien, même s'il n'est pas expiré.
    #[test]
    fn fermer_une_session_invalide_son_jeton() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), week(), SessionKind::Refresh);

        set.close(&issued.session.id);
        assert_eq!(set.verify(&issued.token, now(), SessionKind::Refresh), Err(RefreshError::Invalid));
    }

    #[test]
    fn tout_fermer_invalide_tous_les_jetons() {
        let mut set = SessionSet::default();
        let a = set.open(now(), week(), SessionKind::Refresh);
        let b = set.open(now(), week(), SessionKind::Refresh);

        assert_eq!(set.close_all(), 2);
        assert_eq!(set.verify(&a.token, now(), SessionKind::Refresh), Err(RefreshError::Invalid));
        assert_eq!(set.verify(&b.token, now(), SessionKind::Refresh), Err(RefreshError::Invalid));
    }

    /// Fermer une session ne doit pas fermer celles des autres postes.
    #[test]
    fn fermer_une_session_epargne_les_autres() {
        let mut set = SessionSet::default();
        let poste = set.open(now(), week(), SessionKind::Refresh);
        let portable = set.open(now(), week(), SessionKind::Refresh);

        set.close(&poste.session.id);
        assert!(set.verify(&portable.token, now(), SessionKind::Refresh).is_ok());
    }

    #[test]
    fn un_jeton_falsifie_est_refuse() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), week(), SessionKind::Refresh);
        let (id, _) = issued.token.split_once('.').unwrap();

        for faux in [
            format!("{id}.mauvais-secret"),
            format!("inconnu.{}", issued.token.split_once('.').unwrap().1),
            "sans-point".to_string(),
            String::new(),
            ".".to_string(),
        ] {
            assert_eq!(set.verify(&faux, now(), SessionKind::Refresh), Err(RefreshError::Invalid), "{faux:?}");
        }
    }

    /// Le secret d'une session ne doit pas ouvrir une autre session, même du même compte.
    #[test]
    fn le_secret_d_une_session_ne_vaut_pas_pour_une_autre() {
        let mut set = SessionSet::default();
        let a = set.open(now(), week(), SessionKind::Refresh);
        let b = set.open(now(), week(), SessionKind::Refresh);

        let croise = format!(
            "{}.{}",
            b.session.id,
            a.token.split_once('.').unwrap().1
        );
        assert_eq!(set.verify(&croise, now(), SessionKind::Refresh), Err(RefreshError::Invalid));
    }

    #[test]
    fn les_sessions_expirees_disparaissent_a_l_ouverture_suivante() {
        let mut set = SessionSet::default();
        set.open(now(), Duration::hours(1), SessionKind::Refresh);
        assert_eq!(set.len(), 1);

        set.open(now() + Duration::hours(2), week(), SessionKind::Refresh);
        assert_eq!(set.len(), 1, "la session expirée aurait dû être retirée");
    }

    /// Le plafond protège la taille du Secret. Ouvrir une session de plus doit réussir : c'est
    /// la plus ancienne qui part.
    #[test]
    fn le_plafond_evince_la_plus_ancienne() {
        let mut set = SessionSet::default();
        let mut premiere = None;
        for i in 0..MAX_SESSIONS + 3 {
            let issued = set.open(
                now() + Duration::seconds(i as i64),
                week(),
                SessionKind::Refresh,
            );
            if i == 0 {
                premiere = Some(issued);
            }
        }

        assert_eq!(set.len(), MAX_SESSIONS);
        assert_eq!(
            set.verify(&premiere.unwrap().token, now(), SessionKind::Refresh),
            Err(RefreshError::Invalid)
        );
    }

    /// Les deux usages ne se substituent pas l'un à l'autre : un jeton de renouvellement ne doit
    /// pas ouvrir le proxy, ni l'inverse.
    #[test]
    fn un_jeton_ne_vaut_pas_pour_l_autre_usage() {
        let mut set = SessionSet::default();
        let plugin = set.open(now(), week(), SessionKind::Refresh);
        let fichier = set.open(now(), week(), SessionKind::Kubeconfig);

        assert_eq!(
            set.verify(&plugin.token, now(), SessionKind::Kubeconfig),
            Err(RefreshError::Invalid)
        );
        assert_eq!(
            set.verify(&fichier.token, now(), SessionKind::Refresh),
            Err(RefreshError::Invalid)
        );
        assert!(set.verify(&plugin.token, now(), SessionKind::Refresh).is_ok());
        assert!(set
            .verify(&fichier.token, now(), SessionKind::Kubeconfig)
            .is_ok());
    }

    /// Le plafond se compte par usage : télécharger des kubeconfigs ne doit pas déconnecter les
    /// postes qui utilisent le plugin.
    #[test]
    fn le_plafond_se_compte_par_usage() {
        let mut set = SessionSet::default();
        let plugin = set.open(now(), week(), SessionKind::Refresh);
        for i in 0..MAX_SESSIONS + 3 {
            set.open(
                now() + Duration::seconds(i as i64),
                week(),
                SessionKind::Kubeconfig,
            );
        }

        assert_eq!(set.count_of(SessionKind::Kubeconfig), MAX_SESSIONS);
        assert_eq!(set.count_of(SessionKind::Refresh), 1);
        assert!(set.verify(&plugin.token, now(), SessionKind::Refresh).is_ok());
    }

    /// Une application renouvelle son accès toutes les dix minutes. Comptée avec les fichiers
    /// téléchargés, elle les aurait tous évincés en moins d'une heure — et quelqu'un aurait vu
    /// son `kubectl` s'arrêter sans que personne n'ait rien révoqué.
    #[test]
    fn une_application_qui_renouvelle_n_evince_pas_les_kubeconfigs() {
        let mut set = SessionSet::default();
        let fichier = set.open(now(), week(), SessionKind::Kubeconfig);
        for i in 0..MAX_SESSIONS + 3 {
            set.open(
                now() + Duration::seconds(i as i64),
                week(),
                SessionKind::Application,
            );
        }

        assert_eq!(set.count_of(SessionKind::Kubeconfig), 1);
        assert_eq!(set.count_of(SessionKind::Application), MAX_SESSIONS);
        assert!(set.verify_proxy(&fichier.token, now()).is_ok());
    }

    /// Devant le proxy, les deux usages valent la même chose — et le troisième, non : un droit
    /// de renouveler ne doit pas ouvrir le cluster.
    #[test]
    fn le_proxy_accepte_ses_deux_usages_et_pas_le_troisieme() {
        let mut set = SessionSet::default();
        let fichier = set.open(now(), week(), SessionKind::Kubeconfig);
        let application = set.open(now(), week(), SessionKind::Application);
        let plugin = set.open(now(), week(), SessionKind::Refresh);

        assert!(set.verify_proxy(&fichier.token, now()).is_ok());
        assert!(set.verify_proxy(&application.token, now()).is_ok());
        assert_eq!(
            set.verify_proxy(&plugin.token, now()),
            Err(RefreshError::Invalid)
        );
    }

    /// La révocation vaut pour tout, quel que soit l'usage : c'est ce qui rend le kubeconfig
    /// téléchargé révocable.
    #[test]
    fn tout_fermer_coupe_les_deux_usages() {
        let mut set = SessionSet::default();
        let plugin = set.open(now(), week(), SessionKind::Refresh);
        let fichier = set.open(now(), week(), SessionKind::Kubeconfig);

        assert_eq!(set.close_all(), 2);
        assert_eq!(
            set.verify(&plugin.token, now(), SessionKind::Refresh),
            Err(RefreshError::Invalid)
        );
        assert_eq!(
            set.verify(&fichier.token, now(), SessionKind::Kubeconfig),
            Err(RefreshError::Invalid)
        );
    }

    /// Les `Secret` écrits avant le proxy n'ont pas de champ `kind` : ils doivent se relire en
    /// sessions de renouvellement, pas devenir des jetons de proxy.
    #[test]
    fn une_session_sans_usage_se_relit_en_renouvellement() {
        let ancien = r#"[{"id":"abc","secretHash":"00","issuedAt":"2023-11-14T22:13:20Z","expiresAt":"2033-11-14T22:13:20Z"}]"#;

        let set: SessionSet = serde_json::from_str(ancien).unwrap();
        assert_eq!(set.iter().next().unwrap().kind, SessionKind::Refresh);
    }

    #[test]
    fn le_jeton_de_kubeconfig_se_compose_et_se_separe() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), week(), SessionKind::Kubeconfig);
        let jeton = proxy_token("alice", &issued);

        let (user, credential) = split_proxy_token(&jeton).unwrap();
        assert_eq!(user, "alice");
        assert!(set
            .verify(credential, now(), SessionKind::Kubeconfig)
            .is_ok());
    }

    /// Un nom de compte admet le `.` mais jamais le `_` : c'est ce qui rend la séparation non
    /// ambiguë, y compris quand l'identifiant de session contient lui-même des `_`.
    #[test]
    fn un_compte_pointe_se_separe_quand_meme() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), week(), SessionKind::Kubeconfig);
        let jeton = proxy_token("jean.dupont", &issued);

        assert_eq!(split_proxy_token(&jeton).unwrap().0, "jean.dupont");
    }

    #[test]
    fn un_jeton_qui_n_est_pas_du_proxy_est_ecarte() {
        for faux in [
            "eyJhbGciOiJSUzI1NiIs",
            "kdt_",
            "kdt_alice",
            "kdt_alice_sans-point",
            "kdt__id.secret",
            "alice_id.secret",
            "",
        ] {
            assert!(split_proxy_token(faux).is_none(), "{faux:?}");
        }
    }

    #[test]
    fn l_ensemble_fait_l_aller_retour_json() {
        let mut set = SessionSet::default();
        let issued = set.open(now(), week(), SessionKind::Refresh);

        let relu: SessionSet = serde_json::from_str(&serde_json::to_string(&set).unwrap()).unwrap();
        assert_eq!(relu, set);
        assert!(relu.verify(&issued.token, now(), SessionKind::Refresh).is_ok());
    }
}

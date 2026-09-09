//! Flow d'autorisation : comment une application obtient le droit d'agir au nom de quelqu'un
//! sans jamais voir son mot de passe.
//!
//! Le plugin `exec` présente le mot de passe et le code TOTP directement, ce qui est correct sur
//! un poste de travail : il tourne pour la personne qui les tape. Une application web ne peut pas
//! faire cela — les relayer ferait d'elle un second endroit où les mots de passe du cluster
//! transitent, et le portail n'aurait plus le monopole qui justifie qu'il ne journalise rien.
//!
//! D'où ce détour, qui est celui d'OAuth 2.0 réduit à ce dont kdt-identity a besoin :
//!
//! 1. l'application redirige le navigateur vers `/authorize` ;
//! 2. le portail reconnaît la session ouverte, montre ce qui est demandé, attend un accord ;
//! 3. il redirige vers l'application avec un **code**, valable une minute ;
//! 4. l'application échange ce code contre un droit de session, en prouvant qu'elle est bien
//!    celle qui l'a demandé (PKCE).
//!
//! Le mot de passe ne quitte jamais le portail, et le droit obtenu est une session ordinaire :
//! elle se voit dans la colonne SESS de kdt et se ferme par `revoke`, comme celle d'un poste.
//!
//! # Le cookie et le domaine
//!
//! Le cookie de session est `SameSite=Strict`, et l'étape 1 est une navigation venue d'ailleurs.
//! Le navigateur ne l'enverra que si l'application est **same-site** avec le portail, c'est-à-dire
//! sous le même domaine enregistrable et le même schéma — `https://kdt.example.com` et
//! `https://identity.example.com` le sont. Servie sous un autre domaine, l'application marche
//! encore, mais chaque autorisation repasse par une connexion complète : le navigateur retient le
//! cookie et le portail ne voit personne.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use subtle::ConstantTimeEq;

/// Durée de vie d'un code d'autorisation.
///
/// Le temps d'un aller-retour de redirection, pas davantage. Ce code autorise l'ouverture d'une
/// session de plusieurs jours : il n'a aucune raison de survivre au trajet.
pub const CODE_TTL: chrono::Duration = chrono::Duration::seconds(60);

/// Bornes du `code_verifier`, telles que la RFC 7636 les fixe.
const VERIFIER_MIN: usize = 43;
const VERIFIER_MAX: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizeError {
    #[error("client inconnu")]
    UnknownClient,
    #[error("adresse de retour non déclarée")]
    UnknownRedirect,
    #[error("méthode de défi non supportée")]
    BadChallengeMethod,
    #[error("défi absent ou mal formé")]
    BadChallenge,
    #[error("vérificateur absent ou mal formé")]
    BadVerifier,
    #[error("le vérificateur ne correspond pas au défi")]
    VerifierMismatch,
    #[error("code déjà utilisé")]
    Replayed,
}

/// Ce qu'une application déclare en ouvrant le flow.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeQuery {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    /// Rendu tel quel à l'application, qui s'en sert pour retrouver ce qu'elle faisait.
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
}

/// Ce que porte le code d'autorisation, signé pour l'usage `authorize-code`.
///
/// L'adresse de retour et le défi y sont enfermés : l'échange les compare à ce qu'on lui
/// présente, ce qui empêche de rejouer un code obtenu pour une autre application ou une autre
/// adresse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodePayload {
    /// Compte autorisé.
    pub u: String,
    /// Application, telle qu'elle s'est déclarée.
    pub c: String,
    /// Adresse de retour exacte.
    pub r: String,
    /// Défi PKCE, en base64url sans remplissage.
    pub d: String,
    /// Identifiant unique, pour qu'un code ne serve qu'une fois.
    pub j: String,
}

/// Comment les adresses de retour d'un client sont reconnues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirects {
    /// Adresses déclarées, comparées **en entier**.
    ///
    /// Jamais par préfixe : `https://kdt.example.com/` suivi d'un préfixe accepterait
    /// `https://kdt.example.com.attaquant.test/`, et un code redirigé est un code donné.
    Exact(Vec<String>),
    /// Boucle locale du poste, sur un port quelconque.
    ///
    /// C'est le seul assouplissement, et il est prévu par la RFC 8252 §7.3 pour exactement ce
    /// cas : une application installée écoute sur un port que le système lui attribue au
    /// lancement, et que personne ne peut donc déclarer d'avance. Ce qui reste vérifié est ce qui
    /// compte — l'hôte est une adresse de bouclage **littérale**, jamais un nom, et le chemin est
    /// celui-ci et aucun autre.
    Loopback,
}

/// Une application autorisée à demander des identités.
///
/// Pas de registre dynamique, pas d'enregistrement à chaud. Approuver une application qui parle
/// à ce portail revient à lui confier des identités du cluster : c'est un geste de déploiement,
/// il vit dans les valeurs du chart et se relit dans un dépôt GitOps. La seule exception est le
/// plugin, qui n'est pas une application tierce mais l'autre moitié de ce produit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub id: String,
    /// Nom lisible, tel que la page d'accord le nomme.
    ///
    /// Distinct de l'identifiant : « kdt-identity-cli » ne dit rien à qui lit la page, et c'est
    /// pourtant sur cette page qu'un accès au cluster se donne.
    pub label: String,
    pub redirects: Redirects,
}

impl Client {
    /// L'application déduite de la racine publique de kdt-web.
    ///
    /// Une seule variable de configuration plutôt que trois : l'identifiant et l'adresse de
    /// retour se déduisent de la racine, et une adresse de retour qui ne serait pas sous cette
    /// racine n'aurait aucun sens.
    pub fn from_web_url(web_url: &str) -> Self {
        let root = web_url.trim_end_matches('/');
        Self {
            id: DEFAULT_CLIENT_ID.to_string(),
            label: "kdt-web".to_string(),
            redirects: Redirects::Exact(vec![format!("{root}{CALLBACK_PATH}")]),
        }
    }

    /// Le plugin `exec`, qui écoute sur la boucle locale le temps d'une connexion.
    ///
    /// Toujours déclaré, dans tous les modes : c'est le seul chemin d'ouverture de session en
    /// mode oidc, et il reste utilisable ailleurs pour qui préfère son navigateur au terminal.
    /// Il ne coûte rien à un déploiement qui ne s'en sert pas — un code n'est émis qu'après un
    /// accord donné sur le portail, par quelqu'un qui y est déjà connecté.
    pub fn cli() -> Self {
        Self {
            id: CLI_CLIENT_ID.to_string(),
            label: "le plugin kubectl, sur ce poste".to_string(),
            redirects: Redirects::Loopback,
        }
    }

    fn accepts(&self, redirect_uri: &str) -> bool {
        match &self.redirects {
            Redirects::Exact(uris) => uris.iter().any(|uri| uri == redirect_uri),
            Redirects::Loopback => is_loopback_redirect(redirect_uri),
        }
    }
}

/// Une adresse de retour sur la boucle locale, telle que le plugin la sert.
///
/// Écrit à la main plutôt qu'avec un analyseur d'URL : ce qui est accepté ici doit l'être pour des
/// raisons qu'on peut énoncer, et une bibliothèque généraliste normalise des formes — hôte en
/// majuscules, chemin avec `..`, adresse IPv4 écrite en décimal — dont aucune n'a de raison
/// d'apparaître ici.
fn is_loopback_redirect(redirect_uri: &str) -> bool {
    // En clair, et c'est correct : la requête ne quitte pas la machine. C'est même exigé — un
    // certificat pour `127.0.0.1` n'existe pas.
    let Some(rest) = redirect_uri.strip_prefix("http://") else {
        return false;
    };

    // Ni requête ni fragment : le portail ajoute `?code=…`, et un paramètre déjà présent
    // changerait ce que l'application relit.
    if rest.contains('?') || rest.contains('#') {
        return false;
    }

    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if format!("/{path}") != CLI_CALLBACK_PATH {
        return false;
    }

    // L'hôte est une adresse littérale, jamais un nom : `localhost` se résout par le système, et
    // ce qu'il désigne dépend d'un fichier `hosts` et d'un serveur DNS.
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    if host != "127.0.0.1" && host != "[::1]" {
        return false;
    }

    matches!(port.parse::<u16>(), Ok(port) if port > 0)
}

/// Identifiant de l'unique application déclarée, et son chemin de retour.
///
/// Repris du contrat plutôt que redéclarés : l'application doit servir exactement l'adresse que le
/// portail accepte, et deux constantes séparées finiraient par diverger.
pub use kdt_identity_api::portal::{
    AUTHORIZE_CALLBACK_PATH as CALLBACK_PATH, CLI_CALLBACK_PATH, CLI_CLIENT_ID,
    WEB_CLIENT_ID as DEFAULT_CLIENT_ID,
};

/// Vérifie qu'une demande vise bien l'application déclarée, et rend l'adresse de retour retenue.
///
/// L'ordre compte : tant que le client et l'adresse ne sont pas reconnus, **aucune redirection**
/// ne doit avoir lieu, pas même pour signaler l'erreur. Rediriger vers une adresse non validée
/// est exactement ce que cette fonction existe pour empêcher.
pub fn check<'a>(
    query: &AuthorizeQuery,
    clients: &'a [Client],
) -> Result<(String, &'a Client), AuthorizeError> {
    let client = clients
        .iter()
        .find(|client| client.id == query.client_id)
        .ok_or(AuthorizeError::UnknownClient)?;

    if !client.accepts(&query.redirect_uri) {
        return Err(AuthorizeError::UnknownRedirect);
    }

    // `plain` est refusé : il ferait du défi un secret transporté en clair dans l'URL, donc
    // aucune protection. S256 est le seul mode que la RFC 7636 recommande, et le seul utile.
    if query.code_challenge_method != "S256" {
        return Err(AuthorizeError::BadChallengeMethod);
    }
    if !is_b64url(&query.code_challenge) || query.code_challenge.len() != 43 {
        return Err(AuthorizeError::BadChallenge);
    }

    Ok((query.redirect_uri.clone(), client))
}

/// Vérifie qu'un vérificateur correspond au défi enfermé dans le code.
///
/// La comparaison est à temps constant : le défi est public — il a voyagé dans une URL — mais le
/// vérificateur est le secret qui prouve que celui qui échange le code est celui qui l'a demandé.
pub fn verify_pkce(verifier: &str, challenge: &str) -> Result<(), AuthorizeError> {
    if verifier.len() < VERIFIER_MIN || verifier.len() > VERIFIER_MAX || !is_unreserved(verifier) {
        return Err(AuthorizeError::BadVerifier);
    }

    let computed = b64url(&Sha256::digest(verifier.as_bytes()));
    if computed.as_bytes().ct_eq(challenge.as_bytes()).unwrap_u8() != 1 {
        return Err(AuthorizeError::VerifierMismatch);
    }
    Ok(())
}

/// Les codes déjà échangés, pour qu'un code ne serve qu'une fois.
///
/// En mémoire, et c'est un choix : un code vit une minute, et le porter dans le cluster
/// coûterait une écriture par autorisation pour une fenêtre aussi courte. Deux conséquences
/// assumées — un redémarrage oublie les codes en vol, et une seconde réplique ne voit pas ceux
/// qu'a consommés la première. Rejouer un code demande de toute façon le vérificateur, que seule
/// l'application détient ; ce qu'un rejeu obtiendrait est une session de plus, visible et
/// révocable comme les autres.
#[derive(Default)]
pub struct UsedCodes {
    seen: Mutex<HashMap<String, i64>>,
}

impl UsedCodes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Marque un code comme utilisé. Rend une erreur s'il l'était déjà.
    ///
    /// Les entrées périmées partent au passage : c'est le seul moment où quelqu'un regarde cette
    /// table, et une table qui ne se vide jamais est une fuite de mémoire à croissance lente.
    pub fn consume(&self, jti: &str, expires_at: i64, now: i64) -> Result<(), AuthorizeError> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, exp| *exp > now);
        match seen.insert(jti.to_string(), expires_at) {
            Some(_) => Err(AuthorizeError::Replayed),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

/// Un identifiant de code, tiré au hasard.
pub fn new_jti() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("CSPRNG du système indisponible");
    b64url(&bytes)
}

/// Construit l'adresse de retour, code et état compris.
///
/// L'état est réencodé plutôt que recopié : il vient de l'application, qui a pu y mettre
/// n'importe quoi, et une URL construite par concaténation naïve est une redirection ouverte en
/// puissance.
pub fn redirect_with_code(redirect_uri: &str, code: &str, state: &str) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!(
        "{redirect_uri}{separator}code={}&state={}",
        urlencode(code),
        urlencode(state)
    )
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn is_b64url(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Le jeu de caractères que la RFC 7636 impose au vérificateur.
fn is_unreserved(text: &str) -> bool {
    text.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
    })
}

fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn client() -> Client {
        Client::from_web_url("https://kdt.example.com")
    }

    fn query() -> AuthorizeQuery {
        AuthorizeQuery {
            client_id: DEFAULT_CLIENT_ID.to_string(),
            redirect_uri: "https://kdt.example.com/auth/callback".to_string(),
            state: "xyz".to_string(),
            // SHA-256 de `verifier()`, en base64url.
            code_challenge: b64url(&Sha256::digest(verifier().as_bytes())),
            code_challenge_method: "S256".to_string(),
        }
    }

    fn verifier() -> String {
        "a".repeat(64)
    }

    #[test]
    fn l_adresse_de_retour_se_deduit_de_la_racine() {
        assert_eq!(
            client().redirects,
            Redirects::Exact(vec!["https://kdt.example.com/auth/callback".to_string()])
        );
        // Une barre oblique finale ne doit pas produire une adresse à double barre.
        assert_eq!(
            Client::from_web_url("https://kdt.example.com/").redirects,
            Redirects::Exact(vec!["https://kdt.example.com/auth/callback".to_string()])
        );
    }

    #[test]
    fn une_demande_conforme_est_acceptee() {
        assert_eq!(
            check(&query(), &[client()]).unwrap().0,
            "https://kdt.example.com/auth/callback"
        );
    }

    /// kdt-web est facultatif : un portail où il n'est pas déclaré ne doit pas l'autoriser
    /// parce qu'un autre client, lui, existe.
    #[test]
    fn une_application_non_declaree_est_refusee() {
        assert_eq!(
            check(&query(), &[]).map(|(uri, _)| uri),
            Err(AuthorizeError::UnknownClient)
        );
        assert_eq!(
            check(&query(), &[Client::cli()]).map(|(uri, _)| uri),
            Err(AuthorizeError::UnknownClient)
        );
    }

    /// Le test qui justifie la comparaison en entier : un préfixe accepterait un domaine voisin
    /// contrôlé par quelqu'un d'autre, et rediriger un code revient à le donner.
    #[test]
    fn une_adresse_de_retour_voisine_est_refusee() {
        for usurpee in [
            "https://kdt.example.com.attaquant.test/auth/callback",
            "https://kdt.example.com/auth/callback/../../evil",
            "https://kdt.example.com/auth/callback?next=https://evil.test",
            "http://kdt.example.com/auth/callback",
            "https://kdt.example.com/auth/callback/",
            "https://evil.test/auth/callback",
        ] {
            let mut q = query();
            q.redirect_uri = usurpee.to_string();
            assert_eq!(
                check(&q, &[client()]).map(|(uri, _)| uri),
                Err(AuthorizeError::UnknownRedirect),
                "{usurpee} accepté à tort"
            );
        }
    }

    /// Le port d'un client installé n'est connu qu'à son lancement : la RFC 8252 §7.3 demande
    /// donc de l'accepter quel qu'il soit. Tout le reste de l'adresse, lui, reste fixé.
    #[test]
    fn la_boucle_locale_est_acceptee_sur_n_importe_quel_port() {
        for retour in [
            "http://127.0.0.1:1024/callback",
            "http://127.0.0.1:65535/callback",
            "http://[::1]:41234/callback",
        ] {
            let mut q = query();
            q.client_id = CLI_CLIENT_ID.to_string();
            q.redirect_uri = retour.to_string();
            assert_eq!(
                check(&q, &[Client::cli()]).map(|(uri, _)| uri),
                Ok(retour.to_string()),
                "{retour} refusé à tort"
            );
        }
    }

    /// Ce que l'assouplissement du port ne doit surtout pas ouvrir. `localhost` en fait partie :
    /// c'est un nom, et ce qu'il désigne dépend d'un fichier `hosts` et d'un résolveur.
    #[test]
    fn une_boucle_locale_contrefaite_est_refusee() {
        for usurpee in [
            "http://localhost:8080/callback",
            "http://127.0.0.1:8080/callback?next=https://evil.test",
            "http://127.0.0.1:8080/callback#x",
            "http://127.0.0.1:8080/callback/",
            "http://127.0.0.1:8080/autre",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:99999/callback",
            "http://127.0.0.1:8080@evil.test/callback",
            "http://evil.test/callback",
            "https://127.0.0.1:8080/callback",
            "http://127.0.0.2:8080/callback",
        ] {
            let mut q = query();
            q.client_id = CLI_CLIENT_ID.to_string();
            q.redirect_uri = usurpee.to_string();
            assert_eq!(
                check(&q, &[Client::cli()]).map(|(uri, _)| uri),
                Err(AuthorizeError::UnknownRedirect),
                "{usurpee} accepté à tort"
            );
        }
    }

    /// Les deux clients coexistent sans que l'un ouvre les adresses de l'autre : un code émis
    /// pour kdt-web ne doit pas pouvoir partir vers un port local, ni l'inverse.
    #[test]
    fn chaque_client_garde_ses_adresses() {
        let clients = [Client::cli(), client()];

        let mut q = query();
        q.redirect_uri = "http://127.0.0.1:8080/callback".to_string();
        assert_eq!(
            check(&q, &clients).map(|(uri, _)| uri),
            Err(AuthorizeError::UnknownRedirect)
        );

        let mut q = query();
        q.client_id = CLI_CLIENT_ID.to_string();
        assert_eq!(
            check(&q, &clients).map(|(uri, _)| uri),
            Err(AuthorizeError::UnknownRedirect)
        );
    }

    #[test]
    fn un_autre_client_est_refuse() {
        let mut q = query();
        q.client_id = "autre".to_string();
        assert_eq!(
            check(&q, &[client()]).map(|(uri, _)| uri),
            Err(AuthorizeError::UnknownClient)
        );
    }

    /// `plain` transporterait le secret dans l'URL, ce qui revient à ne rien protéger.
    #[test]
    fn la_methode_plain_est_refusee() {
        for methode in ["plain", "", "s256", "S512"] {
            let mut q = query();
            q.code_challenge_method = methode.to_string();
            assert_eq!(
                check(&q, &[client()]).map(|(uri, _)| uri),
                Err(AuthorizeError::BadChallengeMethod),
                "{methode:?} accepté à tort"
            );
        }
    }

    #[test]
    fn un_defi_mal_forme_est_refuse() {
        for defi in ["", "trop-court", &"a".repeat(44), "a".repeat(43).replace('a', "+").as_str()] {
            let mut q = query();
            q.code_challenge = defi.to_string();
            assert!(
                matches!(
                    check(&q, &[client()]).map(|(uri, _)| uri),
                    Err(AuthorizeError::BadChallenge)
                ),
                "{defi:?} accepté à tort"
            );
        }
    }

    #[test]
    fn un_verificateur_correct_correspond_a_son_defi() {
        let challenge = b64url(&Sha256::digest(verifier().as_bytes()));
        assert_eq!(verify_pkce(&verifier(), &challenge), Ok(()));
    }

    /// C'est tout l'intérêt de PKCE : un code intercepté ne s'échange pas sans le vérificateur.
    #[test]
    fn un_autre_verificateur_ne_correspond_pas() {
        let challenge = b64url(&Sha256::digest(verifier().as_bytes()));
        assert_eq!(
            verify_pkce(&"b".repeat(64), &challenge),
            Err(AuthorizeError::VerifierMismatch)
        );
    }

    #[test]
    fn un_verificateur_hors_bornes_est_refuse() {
        let challenge = b64url(&Sha256::digest(verifier().as_bytes()));
        for mauvais in [
            "a".repeat(VERIFIER_MIN - 1),
            "a".repeat(VERIFIER_MAX + 1),
            String::new(),
            // Hors du jeu de caractères imposé.
            format!("{}+", "a".repeat(50)),
            format!("{} ", "a".repeat(50)),
        ] {
            assert_eq!(
                verify_pkce(&mauvais, &challenge),
                Err(AuthorizeError::BadVerifier),
                "{mauvais:?} accepté à tort"
            );
        }
    }

    #[test]
    fn un_code_ne_sert_qu_une_fois() {
        let used = UsedCodes::new();
        assert_eq!(used.consume("jti-1", NOW + 60, NOW), Ok(()));
        assert_eq!(
            used.consume("jti-1", NOW + 60, NOW),
            Err(AuthorizeError::Replayed)
        );
    }

    #[test]
    fn deux_codes_distincts_ne_se_genent_pas() {
        let used = UsedCodes::new();
        assert_eq!(used.consume("jti-1", NOW + 60, NOW), Ok(()));
        assert_eq!(used.consume("jti-2", NOW + 60, NOW), Ok(()));
    }

    /// La table ne doit pas grossir indéfiniment : elle se purge à chaque passage.
    #[test]
    fn les_codes_perimes_disparaissent() {
        let used = UsedCodes::new();
        used.consume("vieux", NOW + 60, NOW).unwrap();
        assert_eq!(used.len(), 1);

        used.consume("neuf", NOW + 3600, NOW + 120).unwrap();
        assert_eq!(used.len(), 1, "le code périmé aurait dû être retiré");
    }

    #[test]
    fn deux_identifiants_tires_different() {
        assert_ne!(new_jti(), new_jti());
    }

    #[test]
    fn l_adresse_de_retour_porte_le_code_et_l_etat() {
        assert_eq!(
            redirect_with_code("https://kdt.example.com/auth/callback", "abc", "xyz"),
            "https://kdt.example.com/auth/callback?code=abc&state=xyz"
        );
    }

    /// L'état vient de l'application : il doit être encodé, sans quoi il peut ajouter ses
    /// propres paramètres à l'URL de retour.
    #[test]
    fn l_etat_est_encode() {
        let url = redirect_with_code(
            "https://kdt.example.com/auth/callback",
            "abc",
            "x&admin=1#y",
        );
        assert!(url.ends_with("&state=x%26admin%3D1%23y"), "{url}");
    }

    #[test]
    fn le_payload_du_code_fait_l_aller_retour() {
        let payload = CodePayload {
            u: "alice".into(),
            c: DEFAULT_CLIENT_ID.into(),
            r: "https://kdt.example.com/auth/callback".into(),
            d: b64url(&Sha256::digest(verifier().as_bytes())),
            j: new_jti(),
        };
        let relu: CodePayload =
            serde_json::from_str(&serde_json::to_string(&payload).unwrap()).unwrap();
        assert_eq!(relu, payload);
    }
}

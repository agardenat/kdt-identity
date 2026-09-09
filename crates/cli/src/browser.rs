//! Ouverture de session par le navigateur, quand le portail n'accepte plus de mot de passe.
//!
//! Le plugin ne parle jamais au fournisseur d'identité : il parle au portail, comme toujours, et
//! c'est le portail qui délègue. Ce que fait ce module est exactement ce que fait kdt-web depuis
//! le flow d'autorisation — demander un code, l'échanger contre un droit de session — à une
//! différence près : l'adresse de retour est un port de la boucle locale, ouvert le temps d'une
//! connexion.
//!
//! # Pourquoi la boucle locale, et pas un code à recopier
//!
//! Un code affiché puis recopié à la main marcherait aussi, et se passerait d'écouter sur un
//! port. Mais il transiterait par le presse-papier et par les yeux, et surtout il serait
//! interceptable par toute application capable de lire ce que la personne colle. Le port local
//! reçoit le code directement du navigateur, sans passer par personne.
//!
//! # Ce qui ne va jamais sur la sortie standard
//!
//! `kubectl` lit un `ExecCredential` sur stdout et se casse sur tout ce qui s'y ajoute. L'URL, les
//! invites, les avertissements partent donc sur stderr — c'est aussi ce qui les rend visibles
//! quand `kubectl` capture la sortie.

use anyhow::{bail, Context};
use kdt_identity_api::portal::{
    AuthorizeTokenRequest, SessionResponse, AUTHORIZE_PATH, AUTHORIZE_TOKEN_PATH,
    CLI_CALLBACK_PATH, CLI_CLIENT_ID,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Temps laissé pour se connecter chez le portail, second facteur compris.
///
/// Cinq minutes : assez pour une authentification qui passe par un téléphone, assez peu pour
/// qu'un plugin oublié ne garde pas un port ouvert toute la journée.
const WAIT: Duration = Duration::from_secs(300);

/// Taille maximale de la requête lue sur le port local.
///
/// Une redirection de retour tient en quelques centaines d'octets. Lire sans borne offrirait à
/// n'importe quel processus local de faire grossir ce tampon indéfiniment.
const MAX_REQUEST: usize = 8 * 1024;

/// Ouvre une session en passant par le navigateur, et rend ce que le portail accorde.
pub async fn open_session(portal: &str) -> anyhow::Result<SessionResponse> {
    // Port 0 : c'est le système qui en attribue un libre. Le portail accepte n'importe lequel sur
    // la boucle locale, précisément parce que celui-ci n'est connu qu'ici et maintenant.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("ouverture d'un port local pour le retour de connexion")?;
    let port = listener.local_addr().context("port local")?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CLI_CALLBACK_PATH}");

    let verifier = random_b64url();
    let state = random_b64url();
    let challenge = {
        use sha2::{Digest, Sha256};
        b64url(&Sha256::digest(verifier.as_bytes()))
    };

    let url = format!(
        "{portal}{AUTHORIZE_PATH}?client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
        urlencode(CLI_CLIENT_ID),
        urlencode(&redirect_uri),
        urlencode(&state),
        urlencode(&challenge),
    );

    // L'URL est affichée dans tous les cas, y compris quand le navigateur s'ouvre : sur une
    // session distante il n'y a pas de navigateur à ouvrir, et c'est alors le seul moyen de
    // continuer — depuis un poste où l'on peut joindre ce port, ce qui exclut le cas distant.
    eprintln!("kdt-identity : ouverture de session dans le navigateur.");
    eprintln!("Si rien ne s'ouvre, ouvrez cette adresse :\n\n  {url}\n");
    open_browser(&url);

    let code = tokio::time::timeout(WAIT, wait_for_code(&listener, &state))
        .await
        .map_err(|_| {
            anyhow::anyhow!("aucun retour du navigateur au bout de {} s", WAIT.as_secs())
        })??;

    let http = reqwest::Client::new();
    let response = http
        .post(format!("{portal}{AUTHORIZE_TOKEN_PATH}"))
        .json(&AuthorizeTokenRequest {
            code,
            code_verifier: verifier,
            client_id: CLI_CLIENT_ID.to_string(),
            redirect_uri,
        })
        .send()
        .await
        .with_context(|| format!("échange du code auprès du portail {portal}"))?;

    if !response.status().is_success() {
        let status = response.status();
        bail!("le portail a refusé l'échange du code ({status})");
    }

    response
        .json()
        .await
        .context("réponse du portail illisible à l'échange du code")
}

/// Attend le retour du navigateur et rend le code d'autorisation.
///
/// La boucle est nécessaire : un navigateur ouvre volontiers d'autres connexions vers le même
/// port — un `favicon.ico`, une préconnexion — et abandonner à la première requête qui n'est pas
/// la bonne ferait échouer une connexion pourtant en cours.
async fn wait_for_code(listener: &TcpListener, expected_state: &str) -> anyhow::Result<String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("connexion de retour du navigateur")?;

        match handle(stream, expected_state).await {
            Ok(Some(code)) => return Ok(code),
            // Requête sans rapport : on la referme et on continue d'attendre.
            Ok(None) => continue,
            // Le retour a eu lieu mais il est refusé — état qui ne correspond pas, erreur du
            // portail. Insister n'a pas de sens : la tentative est perdue.
            Err(e) => return Err(e),
        }
    }
}

/// Traite une connexion entrante. Rend le code si c'est le retour attendu.
async fn handle(mut stream: TcpStream, expected_state: &str) -> anyhow::Result<Option<String>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    // On lit jusqu'à la fin des en-têtes : le corps ne nous intéresse pas, et un GET n'en a pas.
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.context("lecture du retour")?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buffer);
    let Some(target) = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
    else {
        respond(&mut stream, "400 Bad Request", PAGE_ERREUR).await;
        return Ok(None);
    };

    let Some((path, query)) = target.split_once('?') else {
        respond(&mut stream, "404 Not Found", PAGE_ERREUR).await;
        return Ok(None);
    };
    if path != CLI_CALLBACK_PATH {
        respond(&mut stream, "404 Not Found", PAGE_ERREUR).await;
        return Ok(None);
    }

    let params = parse_query(query);
    let presented = params.iter().find(|(k, _)| k == "state").map(|(_, v)| v);
    let code = params.iter().find(|(k, _)| k == "code").map(|(_, v)| v);

    // L'état lie ce retour à la demande partie d'ici. Sans cette comparaison, un lien fabriqué
    // ouvert dans ce navigateur suffirait à faire échanger au plugin un code obtenu ailleurs,
    // donc à installer sur ce poste une identité que personne n'a choisie.
    if presented.map(String::as_str) != Some(expected_state) {
        respond(&mut stream, "400 Bad Request", PAGE_ERREUR).await;
        bail!("le retour du navigateur ne correspond pas à la demande partie d'ici");
    }

    let Some(code) = code.filter(|code| !code.is_empty()) else {
        respond(&mut stream, "400 Bad Request", PAGE_ERREUR).await;
        bail!("le portail n'a pas rendu de code d'autorisation");
    };

    respond(&mut stream, "200 OK", PAGE_SUCCES).await;
    Ok(Some(code.clone()))
}

/// Écrit une réponse minimale et ferme. Un échec d'écriture n'annule rien : le code est déjà là,
/// et seule la page que verrait la personne serait perdue.
async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

const PAGE_SUCCES: &str = "<!doctype html><meta charset=\"utf-8\"><title>Connexion établie</title>\
<body style=\"font-family:system-ui;margin:3rem auto;max-width:30rem\">\
<h1>Connexion établie</h1><p>Vous pouvez fermer cet onglet et revenir au terminal.</p>";

const PAGE_ERREUR: &str = "<!doctype html><meta charset=\"utf-8\"><title>Connexion échouée</title>\
<body style=\"font-family:system-ui;margin:3rem auto;max-width:30rem\">\
<h1>Connexion échouée</h1><p>Revenez au terminal : le détail y est écrit.</p>";

/// Découpe une chaîne de requête en paires, en décodant le pourcentage.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (urldecode(k), urldecode(v)))
        .collect()
}

fn urldecode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            // `+` vaut une espace dans une chaîne de requête, et seulement là.
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    // Un `%` qui n'introduit pas deux chiffres hexadécimaux est un `%` littéral.
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
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

/// Lance le navigateur du système, sans faire dépendre la connexion de sa réussite.
///
/// Aucune erreur n'est remontée : sur une machine sans environnement graphique, il n'y a rien à
/// ouvrir, et l'URL affichée reste la voie normale. Le processus est détaché de nos flux pour que
/// ce qu'il écrit ne se mélange pas à ce que `kubectl` lit.
fn open_browser(url: &str) {
    use std::process::{Command, Stdio};

    let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "windows") {
        // `start` est une commande interne de l'interpréteur, pas un exécutable ; le premier
        // argument vide est le titre de fenêtre que `start` consomme.
        ("cmd", vec!["/C", "start", "", url])
    } else {
        ("xdg-open", vec![url])
    };

    let _ = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

fn random_b64url() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("CSPRNG du système indisponible");
    b64url(&bytes)
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_verificateur_respecte_les_bornes_de_la_rfc_7636() {
        let verifier = random_b64url();
        assert_eq!(verifier.len(), 43);
        assert!(verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(random_b64url(), random_b64url());
    }

    /// Le code arrive encodé dans l'URL : mal décodé, il serait présenté tel quel à l'échange et
    /// refusé sans que rien n'explique pourquoi.
    #[test]
    fn la_chaine_de_requete_se_decode() {
        let params = parse_query("code=ab%2Bc%2Fd%3D&state=x-y_z&vide=");

        assert_eq!(params[0], ("code".to_string(), "ab+c/d=".to_string()));
        assert_eq!(params[1], ("state".to_string(), "x-y_z".to_string()));
        assert_eq!(params[2], ("vide".to_string(), String::new()));
    }

    /// Un `%` mal formé ne doit ni faire paniquer ni couper la chaîne : il vaut un `%`.
    #[test]
    fn un_pourcentage_isole_ne_casse_rien() {
        assert_eq!(urldecode("100%"), "100%");
        assert_eq!(urldecode("a%zz"), "a%zz");
        assert_eq!(urldecode("a+b"), "a b");
    }

    /// L'aller-retour complet de l'encodage : ce que le plugin met dans l'URL doit revenir
    /// identique après le décodage du navigateur.
    #[test]
    fn l_encodage_et_le_decodage_se_repondent() {
        for valeur in ["simple", "a+b/c=d&e", "http://127.0.0.1:8080/callback", "état"] {
            assert_eq!(urldecode(&urlencode(valeur)), valeur, "{valeur}");
        }
    }

    /// Envoie une requête brute sur le port local et rend ce que le plugin a répondu.
    async fn requete(port: u16, ligne: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(format!("{ligne}\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();

        let mut reponse = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut reponse)
            .await
            .unwrap();
        reponse
    }

    /// Le retour nominal, tel qu'un navigateur l'envoie : le code est rendu, et la personne voit
    /// une page qui lui dit de revenir au terminal.
    #[tokio::test]
    async fn le_retour_du_navigateur_rend_le_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let attente = tokio::spawn(async move { wait_for_code(&listener, "etat-42").await });

        let reponse = requete(port, "GET /callback?code=abc%2Bdef&state=etat-42 HTTP/1.1").await;
        assert!(reponse.starts_with("HTTP/1.1 200 OK"), "{reponse}");
        assert!(reponse.contains("fermer cet onglet"), "{reponse}");

        assert_eq!(attente.await.unwrap().unwrap(), "abc+def");
    }

    /// Un navigateur ouvre volontiers d'autres connexions vers le même port. Abandonner à la
    /// première ferait échouer une connexion pourtant en cours.
    #[tokio::test]
    async fn les_requetes_sans_rapport_sont_ignorees() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let attente = tokio::spawn(async move { wait_for_code(&listener, "etat-42").await });

        for parasite in [
            "GET /favicon.ico HTTP/1.1",
            "GET /callback HTTP/1.1",
            "GET / HTTP/1.1",
        ] {
            let reponse = requete(port, parasite).await;
            assert!(reponse.starts_with("HTTP/1.1 404"), "{parasite} : {reponse}");
        }

        let reponse = requete(port, "GET /callback?code=ok&state=etat-42 HTTP/1.1").await;
        assert!(reponse.starts_with("HTTP/1.1 200 OK"), "{reponse}");
        assert_eq!(attente.await.unwrap().unwrap(), "ok");
    }

    /// Le test qui justifie l'état : un lien fabriqué ouvert dans ce navigateur installerait
    /// sinon sur ce poste une identité que personne n'a choisie.
    #[tokio::test]
    async fn un_retour_dont_l_etat_ne_correspond_pas_est_refuse() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let attente = tokio::spawn(async move { wait_for_code(&listener, "etat-42").await });

        let reponse = requete(port, "GET /callback?code=vole&state=autre HTTP/1.1").await;
        assert!(reponse.starts_with("HTTP/1.1 400"), "{reponse}");
        assert!(attente.await.unwrap().is_err());
    }

    /// Un retour sans code n'est pas une connexion : c'est un refus du portail, ou une URL
    /// ouverte à la main.
    #[tokio::test]
    async fn un_retour_sans_code_est_refuse() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let attente = tokio::spawn(async move { wait_for_code(&listener, "etat-42").await });

        let reponse = requete(port, "GET /callback?state=etat-42&code= HTTP/1.1").await;
        assert!(reponse.starts_with("HTTP/1.1 400"), "{reponse}");
        assert!(attente.await.unwrap().is_err());
    }
}

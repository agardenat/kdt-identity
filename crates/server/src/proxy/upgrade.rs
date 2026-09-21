//! Relais des connexions promues : `kubectl exec`, `attach`, `port-forward`, `cp`.
//!
//! # Pourquoi un chemin à part
//!
//! Ces quatre commandes ne font pas une requête HTTP ordinaire : elles demandent une promotion
//! de connexion (`Connection: Upgrade`), l'apiserver répond `101`, et ce qui suit n'est plus du
//! HTTP mais un flux d'octets — SPDY/3.1 sur les versions anciennes, WebSocket
//! (`v5.channel.k8s.io`) depuis Kubernetes 1.31.
//!
//! Le proxy ne parle **aucun** de ces deux protocoles, et c'est délibéré : les démultiplexer
//! reviendrait à réimplémenter `exec` et `port-forward`, à suivre leurs versions, et à casser
//! le jour où une sixième version du canal apparaît. Il transporte les octets sans les lire.
//!
//! # Ce que ça impose
//!
//! Deux contraintes que `kube::Client` ne peut pas satisfaire, d'où ce module :
//!
//! - **HTTP/1.1 obligatoire.** Une promotion `101` n'existe pas en HTTP/2, et l'apiserver
//!   négocie volontiers h2 par ALPN. La connexion est donc établie à la main, en http1 seul.
//! - **La connexion brute des deux côtés.** Un client HTTP rend un corps de réponse ; ici il
//!   faut le socket lui-même, avant qu'une couche ne s'interpose.
//!
//! Une connexion par promotion, sans mutualisation : ce sont des sessions longues et
//! interactives, un pool n'aurait rien à y réutiliser.

use axum::body::Body as AxumBody;
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tracing::warn;

/// En-têtes que le client envoie pour demander une promotion, et que l'apiserver attend.
///
/// Relayés tels quels — c'est le client et l'apiserver qui se mettent d'accord sur le
/// protocole, le proxy n'a pas son mot à dire.
const UPGRADE_HEADERS: &[&str] = &[
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "x-stream-protocol-version",
];

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("connexion à l'apiserver : {0}")]
    Connect(String),
    #[error("dialogue avec l'apiserver : {0}")]
    Exchange(String),
    #[error("configuration du client : {0}")]
    Config(String),
}

/// La requête demande-t-elle une promotion de connexion ?
///
/// `Connection` est une liste de jetons séparés par des virgules, et la comparaison ignore la
/// casse : `Upgrade`, `keep-alive, Upgrade` et `upgrade` disent tous la même chose.
pub fn is_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        && headers.contains_key("upgrade")
}

/// Établit la connexion amont, renvoie la réponse au client, et met les deux flux bout à bout.
///
/// La réponse est rendue telle que l'apiserver l'a écrite. Un refus — `403`, `404` — n'est pas
/// une promotion et se transmet comme n'importe quelle réponse : c'est à `kubectl` de
/// l'afficher, pas au proxy de la reformuler.
pub async fn relay(
    config: &kube::Config,
    mut incoming: Request<AxumBody>,
    target: &str,
    headers: HeaderMap,
) -> Result<Response<AxumBody>, UpgradeError> {
    let uri: hyper::Uri = format!("{}{target}", config.cluster_url.to_string().trim_end_matches('/'))
        .parse()
        .map_err(|e| UpgradeError::Config(format!("adresse amont : {e}")))?;

    let mut upstream = Request::builder()
        .method(incoming.method().clone())
        .uri(&uri)
        .body(String::new())
        .map_err(|e| UpgradeError::Config(e.to_string()))?;
    *upstream.headers_mut() = headers;
    // `Host` est reconstruit ici, et pas recopié : celui du client nomme le proxy.
    if let Some(authority) = uri.authority() {
        if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
            upstream.headers_mut().insert("host", value);
        }
    }
    if let Some(token) = bearer_token(config)? {
        upstream.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|e| UpgradeError::Config(format!("jeton du compte de service : {e}")))?,
        );
    }

    let io = connect(config, &uri).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| UpgradeError::Connect(e.to_string()))?;
    // `with_upgrades` est ce qui rend la connexion récupérable après le 101. Sans lui, hyper la
    // referme en croyant l'échange terminé.
    tokio::spawn(async move {
        if let Err(e) = connection.with_upgrades().await {
            warn!(erreur = %e, "connexion promue interrompue");
        }
    });

    let response = sender
        .send_request(upstream)
        .await
        .map_err(|e| UpgradeError::Exchange(e.to_string()))?;

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        // L'apiserver a refusé la promotion. Sa réponse est la seule chose utile à rendre.
        let (parts, body) = response.into_parts();
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .map_err(|e| UpgradeError::Exchange(e.to_string()))?
            .to_bytes();
        return Ok(Response::from_parts(parts, AxumBody::from(bytes)));
    }

    // Recopiés avant que `on` ne consomme la réponse, et recopiés parce que le client les
    // vérifie : `Sec-WebSocket-Accept` est calculé à partir de la clé qu'il a envoyée, et
    // `Sec-WebSocket-Protocol` lui dit laquelle de ses propositions a été retenue. Un 101 sans
    // eux est refusé, et `kubectl` n'en dit rien de plus qu'« empty server response ».
    let negotiated = response.headers().clone();
    let upstream_upgrade = hyper::upgrade::on(response);
    let client_upgrade = hyper::upgrade::on(&mut incoming);

    // Les deux promotions ne se résolvent qu'une fois le 101 parti vers le client : la réponse
    // est donc construite d'abord, et le pontage attend dans une tâche.
    tokio::spawn(async move {
        let (client, upstream) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok(pair) => pair,
            Err(e) => {
                warn!(erreur = %e, "promotion de connexion en échec");
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let mut upstream = TokioIo::new(upstream);
        // Une fin de flux d'un côté ferme l'autre : c'est ce qui fait rendre la main à
        // `kubectl exec` quand le shell distant se termine. Une fin brutale n'est pas une
        // anomalie ici — fermer son terminal coupe le flux sans cérémonie, et l'apiserver ne
        // clôt pas toujours son TLS proprement.
        if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
            tracing::debug!(erreur = %e, "flux promu terminé sans clôture");
        }
    });

    Ok(switching_protocols(negotiated))
}

/// Le `101` rendu au client, qui déclenche sa propre promotion.
///
/// Les en-têtes négociés par l'apiserver sont rendus tels quels : c'est lui qui a choisi le
/// protocole parmi ceux proposés, et le client vérifie sa réponse.
fn switching_protocols(negotiated: HeaderMap) -> Response<AxumBody> {
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(AxumBody::empty())
        .expect("réponse constante");
    *response.headers_mut() = negotiated;
    response
}

/// Ouvre la connexion TCP+TLS vers l'apiserver, avec la confiance du cluster.
///
/// La configuration TLS vient de `kube` — CA du cluster, certificat client éventuel — pour
/// qu'il n'y ait qu'une seule vérité sur ce qu'on accepte. Mais elle est reprise et **pas**
/// utilisée telle quelle, pour une raison qui décide de tout ce module : le connecteur de
/// `kube` annonce `h2` en ALPN, et une promotion `101` n'existe pas en HTTP/2. Un apiserver qui
/// accepte h2 — tous le font — répondrait alors à `exec` par une erreur de protocole, sans que
/// rien ne dise pourquoi. ALPN est donc réduit à `http/1.1` sur ces connexions-là, et sur
/// celles-là seulement.
async fn connect(
    config: &kube::Config,
    uri: &hyper::Uri,
) -> Result<impl hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static, UpgradeError> {
    use kube::client::ConfigExt;

    if uri.scheme_str() != Some("https") {
        return Err(UpgradeError::Config(format!(
            "apiserver en {:?} : les connexions promues ne sont ouvertes qu'en https",
            uri.scheme_str().unwrap_or("(aucun)")
        )));
    }
    // Ce chemin ouvre son propre socket et ne traverse donc pas le proxy réseau que
    // `kube::Client` honore, lui. Le cas ne se présente pas dans un pod, qui joint l'apiserver
    // en direct ; il se présente en développement, contre un cluster atteint par un tunnel — et
    // sans ce contrôle, il se manifeste par un refus de connexion que rien n'explique.
    if let Some(proxy) = &config.proxy_url {
        return Err(UpgradeError::Config(format!(
            "un proxy réseau est déclaré ({proxy}) : les connexions promues — exec, attach, \
             port-forward, cp — ouvrent leur propre socket et ne le traversent pas"
        )));
    }

    let mut tls = config
        .rustls_client_config()
        .map_err(|e| UpgradeError::Config(format!("pile TLS : {e}")))?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let host = uri
        .host()
        .ok_or_else(|| UpgradeError::Config("adresse de l'apiserver sans hôte".to_string()))?;
    let port = uri.port_u16().unwrap_or(443);

    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| UpgradeError::Connect(format!("{host}:{port} : {e}")))?;
    // Nagle contre une session interactive : sans cela, chaque frappe de `kubectl exec` attend
    // un acquittement avant de partir.
    let _ = tcp.set_nodelay(true);

    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| UpgradeError::Config(format!("nom {host:?} : {e}")))?;
    let stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
        .connect(name, tcp)
        .await
        .map_err(|e| UpgradeError::Connect(format!("TLS vers {host} : {e}")))?;

    Ok(TokioIo::new(stream))
}

/// Le jeton à présenter à l'apiserver, s'il y en a un.
///
/// Relu à chaque promotion quand il vient d'un fichier : les jetons projetés d'un
/// `ServiceAccount` tournent, et un jeton mis en cache au démarrage finirait par être refusé.
/// Absent quand l'authentification passe par un certificat client — c'est alors le connecteur
/// qui la porte, et il n'y a pas d'en-tête à poser.
fn bearer_token(config: &kube::Config) -> Result<Option<String>, UpgradeError> {
    if let Some(path) = &config.auth_info.token_file {
        return std::fs::read_to_string(path)
            .map(|raw| Some(raw.trim().to_string()))
            .map_err(|e| UpgradeError::Config(format!("{path} : {e}")));
    }
    Ok(config
        .auth_info
        .token
        .as_ref()
        .map(|token| secrecy::ExposeSecret::expose_secret(token).to_string()))
}

/// Les en-têtes de promotion à recopier depuis la requête du client.
///
/// Séparé de la recopie ordinaire parce que ceux-ci sont précisément ceux qu'un relais HTTP
/// doit normalement retirer : ici ils sont la demande elle-même.
pub fn upgrade_headers(incoming: &HeaderMap, headers: &mut HeaderMap) {
    for name in UPGRADE_HEADERS {
        for value in incoming.get_all(*name) {
            headers.append(
                axum::http::HeaderName::from_static(name),
                value.clone(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    /// `Connection` est une liste de jetons, et `kubectl` n'écrit pas toujours la même. Rater
    /// une de ces formes ferait relayer `exec` comme une requête ordinaire, qui échouerait sur
    /// un 101 que personne n'attend.
    #[test]
    fn une_demande_de_promotion_se_reconnait_sous_toutes_ses_formes() {
        for pairs in [
            &[("connection", "Upgrade"), ("upgrade", "SPDY/3.1")][..],
            &[("connection", "upgrade"), ("upgrade", "websocket")][..],
            &[
                ("connection", "keep-alive, Upgrade"),
                ("upgrade", "websocket"),
            ][..],
            &[("Connection", "UPGRADE"), ("Upgrade", "SPDY/3.1")][..],
        ] {
            assert!(is_upgrade(&headers(pairs)), "{pairs:?}");
        }
    }

    #[test]
    fn une_requete_ordinaire_n_est_pas_une_promotion() {
        for pairs in [
            &[("connection", "keep-alive")][..],
            &[("upgrade", "websocket")][..],
            &[("connection", "close")][..],
            &[][..],
        ] {
            assert!(!is_upgrade(&headers(pairs)), "{pairs:?}");
        }
    }

    /// Ces en-têtes sont ceux qu'un relais retire d'ordinaire : ici ils portent la demande, et
    /// les perdre ferait répondre l'apiserver en HTTP ordinaire.
    #[test]
    fn les_entetes_de_promotion_sont_recopies() {
        let incoming = headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-protocol", "v5.channel.k8s.io"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("accept", "*/*"),
        ]);

        let mut out = HeaderMap::new();
        upgrade_headers(&incoming, &mut out);

        assert_eq!(out.get("upgrade").unwrap(), "websocket");
        assert_eq!(
            out.get("sec-websocket-protocol").unwrap(),
            "v5.channel.k8s.io"
        );
        assert!(out.get("sec-websocket-key").is_some());
        // Recopié par le chemin ordinaire, pas par celui-ci.
        assert!(out.get("accept").is_none());
    }
}

//! Pages du portail.
//!
//! Rendu serveur avec `maud`, qui échappe tout ce qui est interpolé : le contenu variable —
//! nom de compte, message d'erreur — vient d'une saisie ou d'une spec, jamais d'une source
//! sûre. Les feuilles de style sont embarquées dans la page : le portail doit rester joignable
//! sans dépendance externe, y compris sur un réseau isolé.

use maud::{html, Markup, DOCTYPE};

const STYLE: &str = r#"
:root { color-scheme: light dark; --bg:#fbfbfd; --fg:#1a1a1a; --muted:#5c5c66;
        --line:#dcdce4; --accent:#1a5fb4; --danger:#a51d2d; --card:#fff; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16161a; --fg:#e8e8ea; --muted:#9a9aa4; --line:#2e2e36;
          --accent:#78aeed; --danger:#f66; --card:#1e1e24; }
}
* { box-sizing: border-box; }
body { margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
       font-family: system-ui, -apple-system, "Segoe UI", sans-serif; line-height:1.55; }
main { max-width:34rem; margin:0 auto; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px;
        padding:1.75rem; }
h1 { font-size:1.35rem; margin:0 0 .35rem; }
.sub { color:var(--muted); margin:0 0 1.5rem; font-size:.92rem; }
label { display:block; font-weight:600; margin:1.1rem 0 .3rem; font-size:.92rem; }
.hint { color:var(--muted); font-weight:400; font-size:.85rem; display:block; margin-top:.15rem; }
input { width:100%; padding:.6rem .7rem; border:1px solid var(--line); border-radius:7px;
        background:var(--bg); color:var(--fg); font-size:1rem; font-family:inherit; }
input:focus { outline:2px solid var(--accent); outline-offset:1px; }
input.code { font-family: ui-monospace, monospace; letter-spacing:.12em; text-transform:uppercase; }
button { margin-top:1.5rem; width:100%; padding:.7rem; border:0; border-radius:7px;
         background:var(--accent); color:#fff; font-size:1rem; font-weight:600; cursor:pointer;
         font-family:inherit; }
button:hover { filter:brightness(1.08); }
.error { border-left:3px solid var(--danger); background:color-mix(in srgb, var(--danger) 8%, transparent);
         padding:.7rem .9rem; border-radius:0 7px 7px 0; margin-bottom:1.2rem; font-size:.92rem; }
.qr { display:flex; gap:1.25rem; align-items:center; flex-wrap:wrap;
      border:1px solid var(--line); border-radius:9px; padding:1rem; margin-top:.4rem; }
.qr svg { width:150px; height:150px; flex:none; background:#fff; border-radius:4px; padding:6px; }
.secret { font-family:ui-monospace, monospace; font-size:.8rem; word-break:break-all;
          color:var(--muted); }
.groups { display:flex; flex-wrap:wrap; gap:.4rem; margin:.3rem 0 0; padding:0; list-style:none; }
.groups li { font-family:ui-monospace, monospace; font-size:.82rem; background:var(--bg);
             border:1px solid var(--line); border-radius:5px; padding:.15rem .5rem; }
.row { display:flex; justify-content:space-between; gap:1rem; padding:.55rem 0;
       border-bottom:1px solid var(--line); font-size:.93rem; }
.row:last-of-type { border-bottom:0; }
.row dt { color:var(--muted); margin:0; }
.row dd { margin:0; font-weight:600; }
footer { text-align:center; color:var(--muted); font-size:.82rem; margin-top:1.5rem; }
a { color:var(--accent); }
"#;

fn page(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="fr" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                // Le portail manipule des credentials : aucune ressource externe, aucun script.
                meta http-equiv="Content-Security-Policy"
                     content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'";
                title { (title) " — kdt-identity" }
                style { (maud::PreEscaped(STYLE)) }
            }
            body { main { (body) } }
        }
    }
}

fn error_box(message: Option<&str>) -> Markup {
    html! {
        @if let Some(message) = message {
            p."error" { (message) }
        }
    }
}

/// Formulaire d'activation : code hors bande, mot de passe, enrôlement TOTP.
pub fn activate(
    user: &str,
    token: &str,
    qr_svg: &str,
    secret_base32: &str,
    min_password_len: usize,
    error: Option<&str>,
) -> Markup {
    page(
        "Activer votre accès",
        html! {
            div."card" {
                h1 { "Activer votre accès" }
                p."sub" { "Compte " strong { (user) } }
                (error_box(error))

                form method="post" action="/activate" {
                    input type="hidden" name="user" value=(user);
                    input type="hidden" name="token" value=(token);
                    input type="hidden" name="secret" value=(secret_base32);

                    label for="code" {
                        "Code d'activation"
                        span."hint" { "Celui que votre administrateur vous a communiqué de vive voix." }
                    }
                    input."code" type="text" id="code" name="code" required
                          autocomplete="off" spellcheck="false" placeholder="XXXX-XXXX";

                    label for="password" {
                        "Mot de passe"
                        span."hint" { "Au moins " (min_password_len) " caractères, et sans votre nom de compte." }
                    }
                    input type="password" id="password" name="password" required
                          autocomplete="new-password";

                    label for="confirm" { "Confirmation du mot de passe" }
                    input type="password" id="confirm" name="confirm" required
                          autocomplete="new-password";

                    label { "Application d'authentification" }
                    div."qr" {
                        (maud::PreEscaped(qr_svg.to_string()))
                        div {
                            p."sub" style="margin:0 0 .4rem" {
                                "Scannez ce code, ou saisissez la clé à la main :"
                            }
                            p."secret" { (secret_base32) }
                        }
                    }

                    label for="totp" {
                        "Code à 6 chiffres"
                        span."hint" { "Affiché par votre application après l'ajout du compte." }
                    }
                    input."code" type="text" id="totp" name="totp" required
                          inputmode="numeric" autocomplete="one-time-code"
                          pattern="[0-9]{6}" placeholder="000000";

                    button type="submit" { "Activer mon accès" }
                }
            }
            footer { "kdt-identity" }
        },
    )
}

pub fn login(error: Option<&str>) -> Markup {
    page(
        "Connexion",
        html! {
            div."card" {
                h1 { "Connexion" }
                p."sub" { "Portail d'accès au cluster Kubernetes." }
                (error_box(error))

                form method="post" action="/login" {
                    label for="user" { "Compte" }
                    input type="text" id="user" name="user" required autocomplete="username"
                          autocapitalize="none" spellcheck="false";

                    label for="password" { "Mot de passe" }
                    input type="password" id="password" name="password" required
                          autocomplete="current-password";

                    label for="totp" { "Code à 6 chiffres" }
                    input."code" type="text" id="totp" name="totp" required
                          inputmode="numeric" autocomplete="one-time-code"
                          pattern="[0-9]{6}" placeholder="000000";

                    button type="submit" { "Se connecter" }
                }
            }
            footer { "kdt-identity" }
        },
    )
}

/// Page du compte : identité effective et téléchargement du kubeconfig.
pub fn account(
    user: &str,
    subject: &str,
    groups: &[String],
    cluster: &str,
    csrf: &str,
    error: Option<&str>,
) -> Markup {
    page(
        "Mon accès",
        html! {
            div."card" {
                h1 { "Mon accès" }
                p."sub" { "Cluster " strong { (cluster) } }
                (error_box(error))

                dl style="margin:0" {
                    div."row" { dt { "Compte" } dd { (user) } }
                    div."row" {
                        dt { "Identité vue par l'apiserver" }
                        dd style="font-family:ui-monospace,monospace" { (subject) }
                    }
                    div."row" {
                        dt { "Groupes" }
                        dd {
                            @if groups.is_empty() {
                                span style="font-weight:400;opacity:.7" { "aucun" }
                            } @else {
                                ul."groups" { @for g in groups { li { (g) } } }
                            }
                        }
                    }
                }

                form method="post" action="/kubeconfig" {
                    input type="hidden" name="csrf" value=(csrf);
                    button type="submit" { "Télécharger mon kubeconfig" }
                }
                p."sub" style="margin:.8rem 0 0" {
                    "Le certificat a une durée de vie courte. Revenez ici pour en obtenir un "
                    "nouveau lorsqu'il expire."
                }
            }

            form method="post" action="/logout" style="margin-top:1rem" {
                input type="hidden" name="csrf" value=(csrf);
                button type="submit"
                       style="background:transparent;color:var(--muted);border:1px solid var(--line)" {
                    "Se déconnecter"
                }
            }
            footer { "kdt-identity" }
        },
    )
}

/// Page de confirmation, sans détail sur ce qui a échoué ni sur ce qui existe.
pub fn message(title: &str, heading: &str, body: &str) -> Markup {
    page(
        title,
        html! {
            div."card" {
                h1 { (heading) }
                p."sub" style="margin-bottom:0" { (body) }
                p style="margin-top:1.2rem" { a href="/login" { "Aller à la connexion" } }
            }
            footer { "kdt-identity" }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tout contenu variable traverse l'échappement de maud : un nom de compte vient d'une
    /// saisie, et un message d'erreur peut reprendre une valeur fournie.
    #[test]
    fn le_contenu_variable_est_echappe() {
        let hostile = "<script>alert(1)</script>";
        let rendus = [
            activate(hostile, hostile, "<svg></svg>", hostile, 12, Some(hostile)).into_string(),
            login(Some(hostile)).into_string(),
            account(hostile, hostile, &[hostile.to_string()], hostile, "x", Some(hostile))
                .into_string(),
            message(hostile, hostile, hostile).into_string(),
        ];

        for rendu in rendus {
            assert!(!rendu.contains("<script>"), "{rendu}");
            assert!(rendu.contains("&lt;script&gt;"), "{rendu}");
        }
    }

    /// Le QR est le seul fragment inséré sans échappement : il est produit par le serveur, et
    /// c'est la raison pour laquelle il ne doit jamais accepter de contenu extérieur.
    #[test]
    fn le_qr_est_insere_tel_quel() {
        let rendu = activate("alice", "t", "<svg id='qr'></svg>", "JBSW", 12, None).into_string();
        assert!(rendu.contains("<svg id='qr'></svg>"), "{rendu}");
    }

    /// Sans script ni ressource externe, une page du portail reste fonctionnelle sur un réseau
    /// isolé — et ne peut pas exfiltrer ce qu'elle affiche.
    ///
    /// Le test cherche ce qui déclenche réellement une requête, pas toute occurrence d'une
    /// URL : un SVG porte un `xmlns="http://www.w3.org/2000/svg"` qui n'est qu'un identifiant
    /// d'espace de noms, jamais déréférencé.
    #[test]
    fn aucune_page_ne_charge_de_ressource_externe() {
        for rendu in [
            activate("alice", "t", "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>", "JBSW", 12, None)
                .into_string(),
            login(None).into_string(),
            account("alice", "kdt:alice", &["kdt:ops".into()], "demo", "x", None).into_string(),
        ] {
            for chargeur in ["<script", "src=", "url(", "@import", "<iframe", "<link"] {
                assert!(!rendu.contains(chargeur), "{chargeur} présent dans {rendu}");
            }
            // Seuls des liens internes et des actions de formulaire vers soi-même.
            assert!(!rendu.contains("href=\"http"), "{rendu}");
            assert!(!rendu.contains("action=\"http"), "{rendu}");
            assert!(rendu.contains("default-src 'none'"), "{rendu}");
        }
    }

    /// Les champs de mot de passe ne doivent pas être réaffichés par le navigateur ni
    /// enregistrés comme un identifiant existant.
    #[test]
    fn les_champs_sensibles_portent_les_bons_attributs() {
        let a = activate("alice", "t", "", "JBSW", 12, None).into_string();
        assert!(a.contains(r#"autocomplete="new-password""#), "{a}");

        let l = login(None).into_string();
        assert!(l.contains(r#"autocomplete="current-password""#), "{l}");
        assert!(l.contains(r#"autocomplete="one-time-code""#), "{l}");
    }

    #[test]
    fn le_message_d_erreur_n_apparait_que_s_il_existe() {
        assert!(!login(None).into_string().contains("class=\"error\""));
        assert!(login(Some("raté")).into_string().contains("raté"));
    }
}

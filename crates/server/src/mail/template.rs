//! Corps des messages, en texte et en HTML.
//!
//! Le rendu est une fonction pure : c'est ce qui permet de vérifier par des tests qu'aucune
//! valeur variable ne peut casser la structure du message, et que le lien n'est présent que là
//! où il doit l'être.

use chrono::{DateTime, Utc};

/// Ce qu'il faut savoir pour rédiger une invitation.
pub struct Invitation<'a> {
    /// Nom d'affichage si l'administrateur en a renseigné un, nom du compte sinon.
    pub display_name: &'a str,
    /// URL complète d'activation, jeton compris.
    pub activation_url: &'a str,
    pub expires_at: DateTime<Utc>,
    /// Nom du cluster, pour que le destinataire sache de quel accès on parle.
    pub cluster: &'a str,
}

pub struct Rendered {
    pub subject: String,
    pub text: String,
    pub html: String,
}

pub fn render_invitation(invitation: &Invitation<'_>) -> Rendered {
    let Invitation {
        display_name,
        activation_url,
        expires_at,
        cluster,
    } = invitation;

    let deadline = expires_at.format("%d/%m/%Y à %H:%M UTC");

    let subject = format!("Votre accès au cluster Kubernetes {cluster}");

    let text = format!(
        "Bonjour {display_name},

Un accès au cluster Kubernetes {cluster} a été créé pour vous.

Pour l'activer, définissez votre mot de passe et enrôlez votre application
d'authentification à cette adresse :

{activation_url}

Ce lien est valable jusqu'au {deadline} et ne fonctionne qu'une fois.
Passé ce délai, demandez une nouvelle invitation à votre administrateur.

Si vous n'attendiez pas ce message, ignorez-le : aucun accès n'est actif tant que
le lien n'a pas été utilisé.
"
    );

    // Le lien est le seul endroit où du contenu variable entre dans une balise. Les autres
    // valeurs traversent `escape_html` : `display_name` et `cluster` viennent de la spec d'un
    // KdtUser, donc d'un humain, et rien ne garantit qu'ils ne contiennent pas de balise.
    let html = format!(
        r#"<!doctype html>
<html lang="fr">
<body style="font-family: system-ui, sans-serif; line-height: 1.5; color: #1a1a1a;">
  <p>Bonjour {name},</p>
  <p>Un accès au cluster Kubernetes <strong>{cluster_html}</strong> a été créé pour vous.</p>
  <p>
    <a href="{url}" style="display: inline-block; padding: 10px 18px; background: #1a5fb4;
       color: #fff; text-decoration: none; border-radius: 6px;">Activer mon accès</a>
  </p>
  <p style="color: #555; font-size: 0.9em;">
    Ce lien est valable jusqu'au {deadline} et ne fonctionne qu'une fois.<br>
    Passé ce délai, demandez une nouvelle invitation à votre administrateur.
  </p>
  <p style="color: #555; font-size: 0.9em;">
    Si vous n'attendiez pas ce message, ignorez-le : aucun accès n'est actif tant que le lien
    n'a pas été utilisé.
  </p>
</body>
</html>
"#,
        name = escape_html(display_name),
        cluster_html = escape_html(cluster),
        url = escape_attribute(activation_url),
    );

    Rendered {
        subject,
        text,
        html,
    }
}

fn escape_html(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Comme [`escape_html`], plus les guillemets : une valeur d'attribut se termine sur le
/// premier guillemet non échappé, et ce qui suit devient un attribut à part entière.
fn escape_attribute(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invitation<'a>(display_name: &'a str, url: &'a str) -> Invitation<'a> {
        Invitation {
            display_name,
            activation_url: url,
            expires_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            cluster: "production",
        }
    }

    #[test]
    fn le_message_porte_le_lien_et_l_echeance() {
        let url = "https://identity.example.com/activate?u=alice&t=jeton";
        let r = render_invitation(&invitation("Alice", url));

        assert!(r.subject.contains("production"));
        assert!(r.text.contains(url));
        assert!(r.text.contains("Alice"));
        assert!(r.text.contains("14/11/2023"));
        assert!(r.html.contains("14/11/2023"));
    }

    /// Un nom d'affichage vient d'un humain via la spec d'un KdtUser : rien ne garantit qu'il
    /// ne contient pas de balise.
    #[test]
    fn un_nom_d_affichage_ne_peut_pas_injecter_de_html() {
        let hostile = "<script>alert(1)</script>";
        let r = render_invitation(&invitation(hostile, "https://example.com/a"));

        assert!(!r.html.contains("<script>"), "{}", r.html);
        assert!(r.html.contains("&lt;script&gt;"), "{}", r.html);
    }

    /// Une URL mal échappée refermerait l'attribut `href` et laisserait injecter les suivants.
    #[test]
    fn une_url_ne_peut_pas_s_echapper_de_son_attribut() {
        let hostile = r#"https://example.com/a" onclick="alert(1)"#;
        let r = render_invitation(&invitation("Alice", hostile));

        assert!(!r.html.contains(r#"" onclick=""#), "{}", r.html);
        assert!(r.html.contains("&quot;"), "{}", r.html);
    }

    /// L'esperluette est légitime dans une URL à paramètres : elle doit être encodée en HTML
    /// mais rester intacte dans la version texte, que le destinataire copiera peut-être.
    #[test]
    fn l_esperluette_survit_dans_la_version_texte() {
        let url = "https://identity.example.com/activate?u=alice&t=jeton";
        let r = render_invitation(&invitation("Alice", url));

        assert!(r.text.contains("?u=alice&t=jeton"), "{}", r.text);
        assert!(r.html.contains("?u=alice&amp;t=jeton"), "{}", r.html);
    }

    /// Le message doit dire quoi faire quand on ne l'attendait pas : une invitation reçue par
    /// erreur ne doit pas ressembler à une compromission.
    #[test]
    fn le_message_rassure_un_destinataire_qui_n_attendait_rien() {
        let r = render_invitation(&invitation("Alice", "https://example.com/a"));
        for corps in [&r.text, &r.html] {
            assert!(corps.contains("ignorez-le"), "{corps}");
        }
    }
}

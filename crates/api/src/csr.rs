//! Génération de la paire de clés et de la demande de signature.
//!
//! Le sujet X.509 est monté depuis des [`Subject`] déjà validés. C'est ce qui rend la mise en
//! forme RFC 4514 sûre : [`naming::validate_name`] n'accepte que `[a-z0-9.-]`, dont aucun
//! caractère n'est un métacaractère RFC 4514 (`,` `+` `"` `\` `<` `>` `;`), et le préfixe est
//! une constante. Aucun nom acceptable ne peut donc altérer la structure du sujet. Les
//! invariants sont malgré tout rejoués ci-dessous, pour ne pas dépendre d'un appelant.

use der::{EncodePem, pem::LineEnding};
use crate::naming::{self, Subject};
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::EncodePrivateKey;
use std::str::FromStr;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::name::Name;

#[derive(Debug, thiserror::Error)]
pub enum CsrError {
    #[error("identité refusée : {0}")]
    Name(#[from] crate::NameError),
    #[error("encodage DER : {0}")]
    Der(#[from] der::Error),
    #[error("construction de la demande : {0}")]
    Build(#[from] x509_cert::builder::Error),
    #[error("sérialisation de la clé privée : {0}")]
    Pkcs8(#[from] p256::pkcs8::Error),
}

/// Une demande de signature et la clé privée qui lui correspond.
pub struct GeneratedCsr {
    /// Demande au format PEM, prête à être placée dans `spec.request`.
    pub csr_pem: String,
    /// Clé privée PKCS#8 au format PEM.
    ///
    /// N'existe que pour le téléchargement navigateur, où le serveur n'a pas d'autre moyen de
    /// produire un kubeconfig complet. Le plugin `exec`, lui, génère sa clé localement et
    /// n'envoie que la demande : c'est le chemin à privilégier.
    pub key_pem: zeroize::Zeroizing<String>,
}

/// Construit une demande de signature pour `user`, membre de `groups`.
///
/// La clé est une P-256 : plus courte qu'une RSA 2048 pour une sécurité équivalente, et le
/// signeur intégré de Kubernetes signe la clé publique telle qu'elle est présentée.
pub fn generate(user: &Subject, groups: &[Subject]) -> Result<GeneratedCsr, CsrError> {
    // Dernière barrière avant la mise en forme cryptographique : on rejoue les invariants sur
    // les chaînes finales, quel que soit le chemin qui les a produites.
    naming::assert_emittable(user.as_str())?;
    for group in groups {
        naming::assert_emittable(group.as_str())?;
    }

    // La représentation RFC 4514 va du RDN le plus spécifique au plus général, soit l'inverse
    // de l'ordre DER. On monte donc la chaîne à l'envers pour que le sujet encodé présente
    // `CN` puis les `O` dans l'ordre déclaré — Kubernetes agrège les `O` sans tenir compte de
    // leur ordre, mais un `openssl x509 -subject` lisible vaut mieux en audit.
    let mut rdns: Vec<String> = groups
        .iter()
        .rev()
        .map(|g| format!("O={}", g.as_str()))
        .collect();
    rdns.push(format!("CN={}", user.as_str()));
    let subject = Name::from_str(&rdns.join(","))?;

    // `Generate::generate` tire directement depuis le CSPRNG du système.
    let signing_key = SigningKey::generate();
    let key_pem = zeroize::Zeroizing::new(
        signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(p256::pkcs8::Error::from)?
            .to_string(),
    );

    let builder = RequestBuilder::new(subject)?;
    let cert_req = builder.build::<_, DerSignature>(&signing_key)?;
    let csr_pem = cert_req.to_pem(LineEnding::LF)?;

    Ok(GeneratedCsr { csr_pem, key_pem })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    fn subjects(user: &str, groups: &[&str]) -> (Subject, Vec<Subject>) {
        (
            Subject::user(user).unwrap(),
            groups.iter().map(|g| Subject::group(g).unwrap()).collect(),
        )
    }

    /// La demande produite doit être relisible par une implémentation tierce, et porter
    /// exactement l'identité demandée — préfixe compris.
    #[test]
    fn le_sujet_porte_le_cn_et_tous_les_o() {
        let (user, groups) = subjects("alice", &["data-team", "lecteurs"]);
        let generated = generate(&user, &groups).unwrap();

        let (_, pem) = x509_parser::pem::parse_x509_pem(generated.csr_pem.as_bytes()).unwrap();
        assert_eq!(pem.label, "CERTIFICATE REQUEST");
        let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        let subject = &csr.certification_request_info.subject;

        let cns: Vec<_> = subject.iter_common_name().filter_map(|a| a.as_str().ok()).collect();
        assert_eq!(cns, vec!["kdt:alice"]);

        let orgs: Vec<_> = subject.iter_organization().filter_map(|a| a.as_str().ok()).collect();
        assert_eq!(orgs, vec!["kdt:data-team", "kdt:lecteurs"]);
    }

    /// La signature de la demande doit être valide, sinon le signeur de Kubernetes la rejette.
    #[test]
    fn la_demande_est_correctement_autosignee() {
        let (user, groups) = subjects("bob", &["ops"]);
        let generated = generate(&user, &groups).unwrap();

        let (_, pem) = x509_parser::pem::parse_x509_pem(generated.csr_pem.as_bytes()).unwrap();
        let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        csr.verify_signature().expect("signature de la CSR invalide");
    }

    #[test]
    fn un_utilisateur_sans_groupe_reste_valide() {
        let user = Subject::user("solo").unwrap();
        let generated = generate(&user, &[]).unwrap();

        let (_, pem) = x509_parser::pem::parse_x509_pem(generated.csr_pem.as_bytes()).unwrap();
        let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        assert_eq!(csr.certification_request_info.subject.iter_organization().count(), 0);
    }

    #[test]
    fn la_cle_privee_est_du_pkcs8_pem() {
        let (user, groups) = subjects("carol", &["ops"]);
        let generated = generate(&user, &groups).unwrap();
        assert!(generated.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(generated.key_pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn deux_appels_ne_produisent_jamais_la_meme_cle() {
        let (user, groups) = subjects("dave", &["ops"]);
        let a = generate(&user, &groups).unwrap();
        let b = generate(&user, &groups).unwrap();
        assert_ne!(*a.key_pem, *b.key_pem);
    }
}

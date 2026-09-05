//! Émission d'un certificat client via l'API `CertificateSigningRequest`.
//!
//! # Pourquoi ce module est le point sensible du projet
//!
//! Approuver une CSR portant `signerName: kubernetes.io/kube-apiserver-client` revient à
//! choisir une identité auprès de l'apiserver. Un émetteur qui approuverait aveuglément une
//! demande fournie par un client laisserait n'importe quel utilisateur authentifié réclamer
//! `O=system:masters`.
//!
//! [`Issuer::issue_from_csr`] ne fait donc jamais confiance à la demande reçue : elle en relit
//! le sujet et exige qu'il corresponde **exactement** à l'identité attendue, groupes compris,
//! avant toute approbation.

use base64::Engine;
use chrono::{DateTime, Utc};
use k8s_openapi::api::certificates::v1::{
    CertificateSigningRequest, CertificateSigningRequestCondition, CertificateSigningRequestSpec,
    CertificateSigningRequestStatus,
};
use kdt_identity_api::naming::{self, Subject};
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::wait::await_condition;
use std::time::Duration;
use x509_parser::prelude::*;

use kdt_identity_api::csr;

/// Le seul signeur que kdt-identity sollicite.
pub const SIGNER_NAME: &str = "kubernetes.io/kube-apiserver-client";

/// Plancher imposé par l'API Kubernetes sur `spec.expirationSeconds`.
pub const MIN_TTL: Duration = Duration::from_secs(600);

/// Au-delà, on considère que le signeur ne répondra pas.
const SIGNING_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("identité refusée : {0}")]
    Name(#[from] kdt_identity_api::NameError),

    #[error("génération de la demande : {0}")]
    Csr(#[from] csr::CsrError),

    #[error("demande illisible : {0}")]
    Malformed(String),

    /// Le sujet reçu ne correspond pas à l'identité authentifiée. Toujours suspect : une
    /// demande légitime est construite à partir de l'identité de session.
    #[error("sujet refusé : {0}")]
    SubjectMismatch(String),

    #[error("durée de validité {0:?} sous le plancher de {MIN_TTL:?} imposé par l'API")]
    TtlTooShort(Duration),

    #[error("le signeur a refusé la demande : {0}")]
    Denied(String),

    #[error("le signeur n'a pas répondu en {SIGNING_TIMEOUT:?} — le contrôleur csrsigning est-il actif sur ce cluster ?")]
    Timeout,

    #[error("appel à l'API Kubernetes : {0}")]
    Kube(#[from] kube::Error),

    #[error("attente de la signature : {0}")]
    Wait(#[from] kube::runtime::wait::Error),

    #[error("certificat émis illisible : {0}")]
    BadCertificate(String),
}

/// Un certificat client émis, prêt à être placé dans un kubeconfig.
pub struct IssuedCredential {
    pub certificate_pem: String,
    /// Présente uniquement quand kdt-identity a généré la clé lui-même (téléchargement
    /// navigateur). Le plugin `exec` garde sa clé sur le poste et reçoit `None`.
    pub key_pem: Option<zeroize::Zeroizing<String>>,
    pub not_after: DateTime<Utc>,
}

/// `Debug` est écrit à la main, jamais dérivé : cette structure transporte une clé privée, et
/// un `{:?}` égaré dans une trace suffirait à la publier.
impl std::fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("certificate_pem", &"<certificat omis>")
            .field(
                "key_pem",
                &self.key_pem.as_ref().map(|_| "<clé privée omise>"),
            )
            .field("not_after", &self.not_after)
            .finish()
    }
}

pub struct Issuer {
    csrs: Api<CertificateSigningRequest>,
}

impl Issuer {
    pub fn new(client: kube::Client) -> Self {
        Self {
            csrs: Api::all(client),
        }
    }

    /// Émet un certificat pour `user`, en générant la paire de clés côté serveur.
    ///
    /// Réservé au téléchargement depuis le navigateur, seul cas où le serveur n'a pas d'autre
    /// moyen de produire un kubeconfig complet.
    pub async fn issue_with_generated_key(
        &self,
        user: &Subject,
        groups: &[Subject],
        ttl: Duration,
    ) -> Result<IssuedCredential, IssueError> {
        let generated = csr::generate(user, groups)?;
        let mut credential = self
            .issue_from_csr(&generated.csr_pem, user, groups, ttl)
            .await?;
        credential.key_pem = Some(generated.key_pem);
        Ok(credential)
    }

    /// Émet un certificat à partir d'une demande construite ailleurs — typiquement par le
    /// plugin `exec`, dont la clé privée ne quitte jamais le poste.
    ///
    /// `user` et `groups` sont l'identité **authentifiée**, pas celle demandée : la demande
    /// est vérifiée contre eux, jamais l'inverse.
    pub async fn issue_from_csr(
        &self,
        csr_pem: &str,
        user: &Subject,
        groups: &[Subject],
        ttl: Duration,
    ) -> Result<IssuedCredential, IssueError> {
        if ttl < MIN_TTL {
            return Err(IssueError::TtlTooShort(ttl));
        }
        naming::assert_emittable(user.as_str())?;
        for group in groups {
            naming::assert_emittable(group.as_str())?;
        }
        verify_csr_subject(csr_pem, user, groups)?;

        let name = self.create(csr_pem, ttl).await?;
        let outcome = self.approve_and_collect(&name).await;

        // La CSR n'a plus d'utilité une fois le certificat récupéré, et la laisser traîner
        // exposerait inutilement l'identité émise. On nettoie quel que soit le résultat.
        let _ = self.csrs.delete(&name, &DeleteParams::default()).await;

        let certificate_pem = outcome?;
        let not_after = parse_not_after(&certificate_pem)?;
        warn_if_shortened(ttl, not_after);

        Ok(IssuedCredential {
            certificate_pem,
            key_pem: None,
            not_after,
        })
    }

    async fn create(&self, csr_pem: &str, ttl: Duration) -> Result<String, IssueError> {
        let request = CertificateSigningRequest {
            metadata: ObjectMeta {
                generate_name: Some("kdt-identity-".to_string()),
                ..Default::default()
            },
            spec: CertificateSigningRequestSpec {
                request: k8s_openapi::ByteString(csr_pem.as_bytes().to_vec()),
                signer_name: SIGNER_NAME.to_string(),
                expiration_seconds: Some(ttl.as_secs() as i32),
                usages: Some(vec![
                    "client auth".to_string(),
                    "digital signature".to_string(),
                    "key encipherment".to_string(),
                ]),
                ..Default::default()
            },
            status: None,
        };

        let created = self.csrs.create(&PostParams::default(), &request).await?;
        created
            .metadata
            .name
            .ok_or_else(|| IssueError::Malformed("l'API n'a pas renvoyé de nom".into()))
    }

    async fn approve_and_collect(&self, name: &str) -> Result<String, IssueError> {
        let status = CertificateSigningRequestStatus {
            certificate: None,
            conditions: Some(vec![CertificateSigningRequestCondition {
                type_: "Approved".to_string(),
                status: "True".to_string(),
                reason: Some("KdtIdentityIssuer".to_string()),
                message: Some("Sujet vérifié contre l'identité authentifiée".to_string()),
                last_update_time: None,
                last_transition_time: None,
            }]),
        };
        self.csrs
            .patch_approval(
                name,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({ "status": status })),
            )
            .await?;

        let settled = await_condition(self.csrs.clone(), name, is_settled);
        let signed = tokio::time::timeout(SIGNING_TIMEOUT, settled)
            .await
            .map_err(|_| IssueError::Timeout)??
            .ok_or(IssueError::Timeout)?;

        let status = signed
            .status
            .ok_or_else(|| IssueError::Malformed("statut absent".into()))?;

        if let Some(reason) = denial_reason(&status) {
            return Err(IssueError::Denied(reason));
        }

        let certificate = status
            .certificate
            .ok_or_else(|| IssueError::Malformed("certificat absent du statut".into()))?;
        String::from_utf8(certificate.0)
            .map_err(|e| IssueError::BadCertificate(format!("certificat non UTF-8 : {e}")))
    }
}

/// Vraie dès que le signeur a tranché, dans un sens ou dans l'autre.
fn is_settled(csr: Option<&CertificateSigningRequest>) -> bool {
    let Some(status) = csr.and_then(|c| c.status.as_ref()) else {
        return false;
    };
    status.certificate.is_some() || denial_reason(status).is_some()
}

fn denial_reason(status: &CertificateSigningRequestStatus) -> Option<String> {
    status.conditions.as_ref()?.iter().find_map(|c| {
        (matches!(c.type_.as_str(), "Denied" | "Failed") && c.status == "True").then(|| {
            c.message
                .clone()
                .or_else(|| c.reason.clone())
                .unwrap_or_else(|| c.type_.clone())
        })
    })
}

/// Exige que le sujet de la demande soit exactement l'identité attendue.
///
/// Toute divergence est une erreur, jamais une correction silencieuse : approuver une demande
/// dont on aurait « rectifié » le sujet reviendrait à approuver ce que le client a écrit.
pub fn verify_csr_subject(
    csr_pem: &str,
    user: &Subject,
    groups: &[Subject],
) -> Result<(), IssueError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes())
        .map_err(|e| IssueError::Malformed(format!("PEM invalide : {e}")))?;
    if pem.label != "CERTIFICATE REQUEST" {
        return Err(IssueError::Malformed(format!(
            "bloc PEM {:?}, attendu \"CERTIFICATE REQUEST\"",
            pem.label
        )));
    }
    let (_, request) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|e| IssueError::Malformed(format!("DER invalide : {e}")))?;

    // Prouve que le demandeur détient la clé privée correspondante.
    request
        .verify_signature()
        .map_err(|e| IssueError::Malformed(format!("demande mal signée : {e}")))?;

    let subject = &request.certification_request_info.subject;

    let cns: Vec<&str> = subject
        .iter_common_name()
        .filter_map(|a| a.as_str().ok())
        .collect();
    if cns != [user.as_str()] {
        return Err(IssueError::SubjectMismatch(format!(
            "CN {cns:?}, attendu [{:?}]",
            user.as_str()
        )));
    }

    let mut found: Vec<&str> = subject
        .iter_organization()
        .filter_map(|a| a.as_str().ok())
        .collect();
    let mut expected: Vec<&str> = groups.iter().map(|g| g.as_str()).collect();
    found.sort_unstable();
    expected.sort_unstable();
    if found != expected {
        return Err(IssueError::SubjectMismatch(format!(
            "groupes {found:?}, attendus {expected:?}"
        )));
    }

    // Un attribut supplémentaire (OU, emailAddress…) n'est jamais légitime ici et pourrait
    // porter du sens pour un autre composant de la chaîne.
    let extra = subject.iter().count() - cns.len() - found.len();
    if extra != 0 {
        return Err(IssueError::SubjectMismatch(format!(
            "{extra} attribut(s) inattendu(s) dans le sujet"
        )));
    }

    Ok(())
}

fn parse_not_after(certificate_pem: &str) -> Result<DateTime<Utc>, IssueError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|e| IssueError::BadCertificate(format!("PEM invalide : {e}")))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| IssueError::BadCertificate(format!("DER invalide : {e}")))?;
    DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(|| IssueError::BadCertificate("date d'expiration hors bornes".into()))
}

/// Encode un PEM pour les champs `*-data` d'un kubeconfig.
pub fn b64(pem: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(pem.as_bytes())
}

/// Signale une durée raccourcie par le signeur du cluster.
///
/// Le kube-controller-manager plafonne à `--cluster-signing-duration` — 24 h par défaut — sans
/// rien renvoyer : la demande est signée, simplement plus courte. Le taire produirait un accès
/// qui expire au milieu d'une session, et un plugin `exec` qui annonce à `kubectl` une échéance
/// que le certificat n'a pas.
///
/// La tolérance de cinq minutes absorbe le délai entre la demande et la signature, qui n'est
/// pas un raccourcissement.
fn warn_if_shortened(requested: Duration, not_after: chrono::DateTime<chrono::Utc>) {
    let Ok(requested) = chrono::Duration::from_std(requested) else {
        return;
    };
    let expected = chrono::Utc::now() + requested;

    if not_after < expected - chrono::Duration::minutes(5) {
        tracing::warn!(
            demande = ?requested.to_std().unwrap_or_default(),
            expire = %not_after,
            "durée raccourcie par le signeur du cluster (--cluster-signing-duration)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subj(user: &str, groups: &[&str]) -> (Subject, Vec<Subject>) {
        (
            Subject::user(user).unwrap(),
            groups.iter().map(|g| Subject::group(g).unwrap()).collect(),
        )
    }

    #[test]
    fn accepte_une_demande_conforme() {
        let (user, groups) = subj("alice", &["data-team", "lecteurs"]);
        let generated = csr::generate(&user, &groups).unwrap();
        verify_csr_subject(&generated.csr_pem, &user, &groups).unwrap();
    }

    /// L'ordre des `O` dans la demande ne doit pas décider de l'acceptation : c'est un
    /// ensemble, pas une séquence.
    #[test]
    fn l_ordre_des_groupes_est_indifferent() {
        let (user, groups) = subj("alice", &["data-team", "lecteurs"]);
        let generated = csr::generate(&user, &groups).unwrap();
        let inverses: Vec<Subject> = groups.iter().rev().cloned().collect();
        verify_csr_subject(&generated.csr_pem, &user, &inverses).unwrap();
    }

    /// Le scénario qui justifie tout ce module : un utilisateur authentifié soumet une demande
    /// réclamant une autre identité.
    #[test]
    fn refuse_une_demande_qui_usurpe_un_autre_utilisateur() {
        let (attaquant, groups) = subj("mallory", &["ops"]);
        let (victime, _) = subj("alice", &[]);
        let generated = csr::generate(&victime, &groups).unwrap();

        let err = verify_csr_subject(&generated.csr_pem, &attaquant, &groups).unwrap_err();
        assert!(matches!(err, IssueError::SubjectMismatch(_)), "{err}");
    }

    #[test]
    fn refuse_une_demande_qui_reclame_un_groupe_non_accorde() {
        let (user, accordes) = subj("mallory", &["lecteurs"]);
        let (_, reclames) = subj("mallory", &["lecteurs", "admins"]);
        let generated = csr::generate(&user, &reclames).unwrap();

        let err = verify_csr_subject(&generated.csr_pem, &user, &accordes).unwrap_err();
        assert!(matches!(err, IssueError::SubjectMismatch(_)), "{err}");
    }

    /// `system:masters` ne peut pas naître d'un `Subject`, donc la demande est forgée à la
    /// main. La vérification doit tenir face à une demande qui n'est jamais passée par nos
    /// constructeurs.
    #[test]
    fn refuse_une_demande_forgee_reclamant_system_masters() {
        let forgee = forge_csr("CN=kdt:mallory,O=system:masters");
        let (user, _) = subj("mallory", &[]);

        let err = verify_csr_subject(&forgee, &user, &[]).unwrap_err();
        assert!(matches!(err, IssueError::SubjectMismatch(_)), "{err}");
    }

    #[test]
    fn refuse_une_demande_sans_prefixe() {
        let forgee = forge_csr("CN=alice");
        let (user, _) = subj("alice", &[]);

        let err = verify_csr_subject(&forgee, &user, &[]).unwrap_err();
        assert!(matches!(err, IssueError::SubjectMismatch(_)), "{err}");
    }

    #[test]
    fn refuse_un_attribut_de_sujet_inattendu() {
        let forgee = forge_csr("CN=kdt:alice,OU=finance");
        let (user, _) = subj("alice", &[]);

        let err = verify_csr_subject(&forgee, &user, &[]).unwrap_err();
        assert!(matches!(err, IssueError::SubjectMismatch(_)), "{err}");
    }

    #[test]
    fn refuse_ce_qui_n_est_pas_une_demande() {
        let (user, _) = subj("alice", &[]);
        for entree in [
            "",
            "pas du pem",
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
        ] {
            assert!(
                matches!(
                    verify_csr_subject(entree, &user, &[]),
                    Err(IssueError::Malformed(_))
                ),
                "{entree:?} aurait dû être rejeté"
            );
        }
    }

    /// Construit une demande correctement signée mais au sujet arbitraire, pour simuler un
    /// client qui n'utilise pas notre code.
    fn forge_csr(subject: &str) -> String {
        use der::{EncodePem, pem::LineEnding};
        use p256::ecdsa::{DerSignature, SigningKey};
        use p256::elliptic_curve::Generate;
        use std::str::FromStr;
        use x509_cert::builder::{Builder, RequestBuilder};
        use x509_cert::name::Name;

        let key = SigningKey::generate();
        let builder = RequestBuilder::new(Name::from_str(subject).unwrap()).unwrap();
        builder
            .build::<_, DerSignature>(&key)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap()
    }
}

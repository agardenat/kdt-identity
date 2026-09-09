//! Conversation avec un vrai annuaire.
//!
//! Ignoré par défaut : ces tests ouvrent une connexion LDAP(S) et présentent des identifiants.
//! Rien ne peut les remplacer — un annuaire bouchonné validerait la façon dont on l'a bouchonné,
//! pas le schéma d'Active Directory ni celui de FreeIPA, qui sont précisément ce qu'on cherche à
//! constater.
//!
//! Ils ne touchent pas au cluster : ils lisent l'annuaire, et rien d'autre. Les tests qui
//! écrivent des `KdtUser` vivent dans `e2e_issuance.rs`, où un cluster est déjà exigé.
//!
//! ```sh
//! export KDT_TEST_LDAP_URL=ldaps://dc01.example.com:636
//! export KDT_TEST_LDAP_PROFILE=activedirectory       # ou freeipa
//! export KDT_TEST_LDAP_BASE='OU=Users,DC=example,DC=com'
//! export KDT_TEST_LDAP_BIND_DN='CN=svc-kdt,OU=Services,DC=example,DC=com'
//! export KDT_TEST_LDAP_BIND_PASSWORD='…'
//! export KDT_TEST_LDAP_CA=/chemin/vers/ca.crt        # facultatif si CA publique
//! export KDT_TEST_LDAP_USER=alice                    # compte de test
//! export KDT_TEST_LDAP_PASSWORD='…'
//! export KDT_TEST_LDAP_GROUP_DN='CN=K8s-Admins,OU=Groups,DC=example,DC=com'
//!
//! cargo test -p kdt-identity-server --test e2e_ldap -- --ignored --nocapture
//! ```

use kdt_identity_server::config::{LdapConfig, DEFAULT_LDAP_RESYNC, DEFAULT_LDAP_TIMEOUT};
use kdt_identity_server::federation::mapping::GroupMappings;
use kdt_identity_server::federation::Source;
use kdt_identity_server::ldap::profile::LdapProfile;
use kdt_identity_server::ldap::{Directory, LdapError};
use zeroize::Zeroizing;

fn var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} doit être défini, voir l'en-tête du fichier"))
}

fn directory() -> Directory {
    kdt_identity_server::install_crypto_provider();

    // La CA est posée avant toute connexion, comme le fait `main` : `ldap3` ne sait pas en
    // recevoir une, et c'est `SSL_CERT_FILE` qui la porte.
    if let Ok(ca) = std::env::var("KDT_TEST_LDAP_CA") {
        let dir = std::env::temp_dir().join("kdt-identity-e2e-ldap");
        kdt_identity_server::ldap::trust::install(std::path::Path::new(&ca), &dir)
            .expect("magasin de confiance");
    }

    let profile: LdapProfile = var("KDT_TEST_LDAP_PROFILE").parse().expect("profil");
    let bind_dn = std::env::var("KDT_TEST_LDAP_BIND_DN").ok();
    let bind_password = std::env::var("KDT_TEST_LDAP_BIND_PASSWORD")
        .ok()
        .map(Zeroizing::new);

    let group_dn = var("KDT_TEST_LDAP_GROUP_DN");
    let mappings = GroupMappings::parse(
        &format!(
            r#"[{{"dn": {}, "group": "e2e-groupe"}}]"#,
            serde_json::to_string(&group_dn).unwrap()
        ),
        Source::Ldap,
    )
    .expect("table de correspondance");

    Directory::new(LdapConfig {
        url: var("KDT_TEST_LDAP_URL"),
        start_tls: std::env::var("KDT_TEST_LDAP_START_TLS").as_deref() == Ok("true"),
        bind_dn,
        bind_password,
        user_search_base: var("KDT_TEST_LDAP_BASE"),
        attributes: profile.attributes(),
        group_mappings: mappings,
        ca_file: std::env::var("KDT_TEST_LDAP_CA").ok(),
        timeout: DEFAULT_LDAP_TIMEOUT,
        resync: DEFAULT_LDAP_RESYNC,
    })
}

/// Le test qui valide le profil. Il constate que l'attribut de connexion du profil retenu est
/// bien celui du schéma en face : s'il ne l'était pas, la recherche ne rendrait rien et l'échec
/// serait indiscernable d'un mot de passe faux.
#[tokio::test]
#[ignore = "nécessite un annuaire : ouvre une connexion LDAP et présente des identifiants"]
async fn le_profil_retenu_trouve_la_personne() {
    let directory = directory();
    let login = var("KDT_TEST_LDAP_USER");

    let user = directory
        .lookup(&login)
        .await
        .expect("recherche")
        .expect("le compte de test doit exister dans l'annuaire");

    println!("dn           : {}", user.pin);
    println!("login        : {}", user.login);
    println!("email        : {:?}", user.email);
    println!("nom affiché  : {:?}", user.display_name);
    println!("memberOf     : {} entrées", user.member_of.len());

    assert!(
        user.email.is_some(),
        "sans adresse, aucun KdtUser ne peut être créé : vérifier userEmailAttribute"
    );
    assert!(
        !user.member_of.is_empty(),
        "aucun memberOf lu : le greffon est-il actif, et groupMemberAttribute correct ?"
    );
}

/// Le bind, c'est-à-dire tout le mode. Vérifie aussi que le mauvais mot de passe est refusé —
/// un annuaire qui accepterait n'importe quoi rendrait le portail entièrement ouvert.
#[tokio::test]
#[ignore = "nécessite un annuaire : ouvre une connexion LDAP et présente des identifiants"]
async fn le_bind_tranche_dans_les_deux_sens() {
    let directory = directory();
    let login = var("KDT_TEST_LDAP_USER");

    directory
        .authenticate(&login, &var("KDT_TEST_LDAP_PASSWORD"))
        .await
        .expect("le bon mot de passe doit être accepté");

    let refus = directory
        .authenticate(&login, "ceci-n-est-pas-le-mot-de-passe")
        .await;
    assert!(
        matches!(refus, Err(LdapError::InvalidCredentials)),
        "un mauvais mot de passe doit être refusé, obtenu : {refus:?}"
    );
}

/// Un bind avec mot de passe vide est un *bind non authentifié* : la RFC 4513 le définit comme
/// une connexion anonyme, et l'annuaire répond `success`. C'est le test le plus important du
/// fichier — sans le refus en amont, tout identifiant existant ouvrirait une session sans mot
/// de passe.
#[tokio::test]
#[ignore = "nécessite un annuaire : ouvre une connexion LDAP et présente des identifiants"]
async fn un_mot_de_passe_vide_est_refuse() {
    let refus = directory().authenticate(&var("KDT_TEST_LDAP_USER"), "").await;

    assert!(
        matches!(refus, Err(LdapError::InvalidCredentials)),
        "un mot de passe vide doit être refusé, obtenu : {refus:?}"
    );
}

/// Une saisie ne doit pas pouvoir élargir la recherche. Sur un annuaire réel, `*` rendrait la
/// première entrée venue si le filtre n'était pas échappé.
#[tokio::test]
#[ignore = "nécessite un annuaire : ouvre une connexion LDAP et présente des identifiants"]
async fn une_saisie_ne_peut_pas_elargir_la_recherche() {
    let directory = directory();

    for saisie in ["*", "x)(objectClass=*", "*)(uid=*"] {
        let trouve = directory.lookup(saisie).await.expect("recherche");
        assert!(
            trouve.is_none(),
            "{saisie:?} a rendu une entrée : le filtre n'est pas échappé"
        );
    }
}

/// La relecture par DN est ce sur quoi repose la resynchronisation. Elle doit rendre la même
/// personne que la recherche par identifiant, et distinguer une entrée absente d'une panne.
#[tokio::test]
#[ignore = "nécessite un annuaire : ouvre une connexion LDAP et présente des identifiants"]
async fn la_relecture_par_dn_retrouve_la_meme_personne() {
    let directory = directory();

    let par_login = directory
        .lookup(&var("KDT_TEST_LDAP_USER"))
        .await
        .expect("recherche")
        .expect("le compte de test doit exister");

    let par_dn = directory
        .lookup_dn(&par_login.pin)
        .await
        .expect("relecture")
        .expect("le DN qui vient d'être lu doit se relire");

    assert_eq!(par_dn, par_login);

    // Une entrée absente est un résultat, pas une panne : c'est ce qui autorise la
    // désactivation d'un compte disparu, et ce qui interdit de désactiver sur une erreur.
    let absent = directory
        .lookup_dn(&format!("CN=kdt-e2e-absent,{}", var("KDT_TEST_LDAP_BASE")))
        .await;
    assert!(
        matches!(absent, Ok(None)),
        "une entrée absente doit rendre Ok(None), obtenu : {absent:?}"
    );
}

/// La table de correspondance, contre les DN que l'annuaire rend réellement — casse et espaces
/// compris, qui ne sont jamais ceux qu'on a tapés dans les valeurs du chart.
#[tokio::test]
#[ignore = "nécessite un annuaire : ouvre une connexion LDAP et présente des identifiants"]
async fn le_groupe_declare_est_reconnu_tel_que_l_annuaire_le_rend() {
    let directory = directory();

    let user = directory
        .lookup(&var("KDT_TEST_LDAP_USER"))
        .await
        .expect("recherche")
        .expect("le compte de test doit exister");

    let groupes = directory.config().group_mappings.resolve(&user.member_of);

    assert_eq!(
        groupes,
        vec!["e2e-groupe"],
        "KDT_TEST_LDAP_GROUP_DN n'a pas été reconnu parmi {:?}",
        user.member_of
    );
}

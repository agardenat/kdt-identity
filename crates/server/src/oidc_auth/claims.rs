//! Lecture d'un jeton d'identité, et ce qu'on en tire comme personne.
//!
//! # Ce qui est vérifié
//!
//! L'émetteur, l'audience, l'expiration et le `nonce`. Ce sont les quatre qui disent que *ce*
//! jeton-ci a été émis pour *cette* connexion-ci : sans le `nonce`, un jeton obtenu ailleurs et
//! rejoué ici ferait une session ; sans l'audience, un jeton émis par le même fournisseur pour
//! une autre application en ferait une aussi.
//!
//! La signature ne l'est pas, et c'est justifié dans le module parent : le jeton arrive par un
//! échange direct avec le fournisseur, sur une connexion TLS vérifiée.
//!
//! # L'absence qui ne veut pas dire « aucun groupe »
//!
//! Un jeton Entra ID cesse de porter les groupes au-delà d'environ deux cents : le claim est
//! remplacé par un renvoi vers Microsoft Graph. Traiter cette absence comme « aucun groupe »
//! ouvrirait une session sans droits à la personne qui en a le plus, et le message d'erreur
//! qu'elle lirait plus tard parlerait de RBAC. La lecture le **signale** donc au lieu de
//! l'ignorer : l'appelant va chercher la liste chez Graph s'il en a le moyen, et refuse la
//! connexion sinon.

use super::OidcError;
use crate::config::OidcClaims;
use crate::federation::FederatedUser;
use serde_json::Value;

/// Ce à quoi le jeton doit correspondre pour être celui qu'on attend.
pub struct Expectations<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub nonce: &'a str,
    pub now: i64,
}

/// Ce qu'un jeton d'identité apprend, et ce qu'il laisse en suspens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub user: FederatedUser,
    /// Vrai quand le fournisseur a renvoyé les groupes vers son API au lieu de les inclure.
    ///
    /// `user.member_of` est alors vide, et **ne veut rien dire** : c'est à l'appelant d'aller
    /// chercher la liste, ou de refuser.
    pub groups_deferred: bool,
}

/// Vérifie un jeton d'identité et en tire une personne.
pub fn extract(
    id_token: &str,
    expected: &Expectations<'_>,
    claims: &OidcClaims,
) -> Result<Identity, OidcError> {
    let payload = payload(id_token)?;

    let issuer = string(&payload, "iss")
        .ok_or_else(|| OidcError::Unusable("le jeton ne porte pas d'émetteur".to_string()))?;
    if issuer.trim_end_matches('/') != expected.issuer.trim_end_matches('/') {
        return Err(OidcError::Unusable(format!(
            "jeton émis par {issuer:?}, {:?} attendu",
            expected.issuer
        )));
    }

    if !audience_matches(&payload, expected.audience) {
        return Err(OidcError::Unusable(format!(
            "jeton destiné à une autre application que {:?}",
            expected.audience
        )));
    }

    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| OidcError::Unusable("le jeton ne porte pas d'expiration".to_string()))?;
    if expected.now > exp + super::CLOCK_SKEW {
        return Err(OidcError::Unusable(
            "jeton expiré : vérifier l'heure du portail et celle du fournisseur".to_string(),
        ));
    }

    // Un jeton sans `nonce` est un jeton qu'on n'a pas demandé. Le tolérer reviendrait à accepter
    // n'importe quel jeton du fournisseur, y compris obtenu par une autre voie.
    match string(&payload, "nonce") {
        Some(nonce) if nonce == expected.nonce => {}
        _ => {
            return Err(OidcError::Unusable(
                "le jeton ne porte pas le nonce de cette connexion".to_string(),
            ))
        }
    }

    let pin = string(&payload, &claims.subject).ok_or_else(|| {
        OidcError::Unusable(format!(
            "le jeton ne porte pas de claim {:?}, sur lequel le compte est épinglé",
            claims.subject
        ))
    })?;

    let login = string(&payload, &claims.username).ok_or_else(|| {
        OidcError::Unusable(format!(
            "le jeton ne porte pas de claim {:?} : de quoi tirer le nom du compte manque",
            claims.username
        ))
    })?;

    // L'adresse est requise par le schéma du `KdtUser`. Chez Entra ID, le claim `email` n'est
    // présent que si la personne a une boîte : le repli sur l'identifiant, quand il en a la
    // forme, évite qu'un tenant sans messagerie ne puisse créer aucun compte.
    let email = string(&payload, &claims.email).or_else(|| login.contains('@').then(|| login.clone()));
    let (member_of, groups_deferred) = groups(&payload, &claims.groups)?;

    Ok(Identity {
        user: FederatedUser {
            pin,
            login,
            email,
            display_name: string(&payload, &claims.display),
            member_of,
        },
        groups_deferred,
    })
}

/// Charge utile d'un JWT, sans vérification de signature.
fn payload(id_token: &str) -> Result<Value, OidcError> {
    use base64::Engine;

    let mut segments = id_token.split('.');
    let (Some(_), Some(payload), Some(_), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(OidcError::Unusable(
            "le jeton d'identité n'a pas la forme d'un JWT".to_string(),
        ));
    };

    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| OidcError::Unusable(format!("charge utile du jeton illisible : {e}")))?;

    serde_json::from_slice(&raw)
        .map_err(|e| OidcError::Unusable(format!("charge utile du jeton illisible : {e}")))
}

fn string(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
}

/// `aud` est une chaîne ou un tableau, selon le fournisseur et le nombre de destinataires.
fn audience_matches(payload: &Value, expected: &str) -> bool {
    match payload.get("aud") {
        Some(Value::String(aud)) => aud == expected,
        Some(Value::Array(auds)) => auds.iter().any(|aud| aud.as_str() == Some(expected)),
        _ => false,
    }
}

/// Groupes portés par le jeton, et si le fournisseur les a déportés.
fn groups(payload: &Value, claim: &str) -> Result<(Vec<String>, bool), OidcError> {
    // Le renvoi vers Graph, sous ses deux formes : `_claim_names` désigne le claim déporté, et
    // `hasgroups` est ce qu'Entra ID met à sa place dans certains flux.
    let deporte = payload
        .get("_claim_names")
        .and_then(|names| names.get(claim))
        .is_some()
        || payload.get("hasgroups").and_then(Value::as_bool) == Some(true);

    if deporte {
        return Ok((Vec::new(), true));
    }

    Ok((match payload.get(claim) {
        // Absent : la personne n'est membre d'aucun groupe que le fournisseur émette. C'est un
        // état légitime — elle se connectera sans droits, ce que la table de correspondance
        // décrit déjà.
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        // Un fournisseur qui n'émet qu'un groupe peut le rendre nu plutôt qu'en tableau.
        Some(Value::String(value)) => vec![value.clone()],
        Some(other) => {
            return Err(OidcError::Unusable(format!(
                "le claim {claim:?} n'est ni une liste ni une chaîne : {other}"
            )))
        }
    }, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn token(payload: Value) -> String {
        use base64::Engine;
        let corps = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        format!("entete.{corps}.signature")
    }

    fn expected<'a>() -> Expectations<'a> {
        Expectations {
            issuer: "https://idp.example.com",
            audience: "kdt",
            nonce: "n-42",
            now: NOW,
        }
    }

    fn payload_valide() -> Value {
        serde_json::json!({
            "iss": "https://idp.example.com",
            "aud": "kdt",
            "exp": NOW + 300,
            "nonce": "n-42",
            "sub": "sujet-opaque",
            "preferred_username": "Alice.Martin@example.com",
            "email": "alice.martin@example.com",
            "name": "Alice Martin",
            "groups": ["8f4a1c2e-0b77-4e3b-9a21-2c5d8e7f0a11", "autre"],
        })
    }

    fn user(payload: Value) -> FederatedUser {
        extract(&token(payload), &expected(), &OidcClaims::default())
            .unwrap()
            .user
    }

    #[test]
    fn un_jeton_valide_donne_une_personne() {
        let user = user(payload_valide());

        assert_eq!(user.pin, "sujet-opaque");
        assert_eq!(user.login, "Alice.Martin@example.com");
        assert_eq!(user.email.as_deref(), Some("alice.martin@example.com"));
        assert_eq!(user.display_name.as_deref(), Some("Alice Martin"));
        assert_eq!(user.member_of.len(), 2);
    }

    /// Les quatre vérifications qui disent que ce jeton a été émis pour cette connexion.
    #[test]
    fn un_jeton_qui_ne_correspond_pas_est_refuse() {
        let cas = [
            ("iss", serde_json::json!("https://autre.example.com")),
            ("aud", serde_json::json!("une-autre-application")),
            ("exp", serde_json::json!(NOW - 3600)),
            ("nonce", serde_json::json!("n-43")),
        ];

        for (champ, valeur) in cas {
            let mut payload = payload_valide();
            payload[champ] = valeur;
            assert!(
                extract(&token(payload), &expected(), &OidcClaims::default()).is_err(),
                "{champ} accepté à tort"
            );
        }

        // Et les mêmes champs absents, qui ne valent pas mieux que faux.
        for champ in ["iss", "aud", "exp", "nonce", "sub", "preferred_username"] {
            let mut payload = payload_valide();
            payload.as_object_mut().unwrap().remove(champ);
            assert!(
                extract(&token(payload), &expected(), &OidcClaims::default()).is_err(),
                "{champ} absent accepté à tort"
            );
        }
    }

    /// Le portail et le fournisseur n'ont pas la même horloge : une expiration franchie de
    /// quelques secondes ne doit pas refuser une connexion légitime.
    #[test]
    fn un_leger_decalage_d_horloge_est_tolere() {
        let mut payload = payload_valide();
        payload["exp"] = serde_json::json!(NOW - 30);
        assert!(extract(&token(payload), &expected(), &OidcClaims::default()).is_ok());

        let mut payload = payload_valide();
        payload["exp"] = serde_json::json!(NOW - 120);
        assert!(extract(&token(payload), &expected(), &OidcClaims::default()).is_err());
    }

    /// `aud` est un tableau dès qu'il y a plusieurs destinataires, et le nôtre doit y être
    /// cherché plutôt que comparé à l'ensemble.
    #[test]
    fn une_audience_en_tableau_est_acceptee() {
        let mut payload = payload_valide();
        payload["aud"] = serde_json::json!(["autre", "kdt"]);
        assert!(extract(&token(payload), &expected(), &OidcClaims::default()).is_ok());
    }

    /// Le cas qui coûterait le plus cher en silence : la personne la mieux dotée en groupes est
    /// celle dont le jeton cesse de les porter. La lecture doit le dire, pour que l'appelant
    /// aille chercher la liste — ou refuse en connaissance de cause.
    #[test]
    fn un_claim_de_groupes_deporte_est_signale() {
        let mut payload = payload_valide();
        payload.as_object_mut().unwrap().remove("groups");
        payload["_claim_names"] = serde_json::json!({"groups": "src1"});
        payload["_claim_sources"] =
            serde_json::json!({"src1": {"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}});

        let identity = extract(&token(payload), &expected(), &OidcClaims::default()).unwrap();
        assert!(identity.groups_deferred);
        assert!(identity.user.member_of.is_empty());

        let mut payload = payload_valide();
        payload.as_object_mut().unwrap().remove("groups");
        payload["hasgroups"] = serde_json::json!(true);
        assert!(
            extract(&token(payload), &expected(), &OidcClaims::default())
                .unwrap()
                .groups_deferred
        );

        // Un jeton qui porte ses groupes ne déclenche rien : c'est le cas courant.
        assert!(
            !extract(&token(payload_valide()), &expected(), &OidcClaims::default())
                .unwrap()
                .groups_deferred
        );
    }

    /// Sans groupe émis, la personne se connecte sans droits — ce que la table de
    /// correspondance décrit déjà. C'est un état légitime, pas une erreur.
    #[test]
    fn un_jeton_sans_groupes_reste_utilisable() {
        let mut payload = payload_valide();
        payload.as_object_mut().unwrap().remove("groups");
        let identity = extract(&token(payload), &expected(), &OidcClaims::default()).unwrap();
        assert!(identity.user.member_of.is_empty());
        // Sans groupe et sans renvoi : la personne n'est membre de rien, et c'est une réponse.
        assert!(!identity.groups_deferred);

        // Et un groupe unique rendu nu plutôt qu'en tableau.
        let mut payload = payload_valide();
        payload["groups"] = serde_json::json!("seul");
        assert_eq!(user(payload).member_of, vec!["seul".to_string()]);
    }

    /// Un tenant sans messagerie ne porte pas de claim `email`, et le `KdtUser` en exige une.
    #[test]
    fn l_adresse_se_replie_sur_l_identifiant_quand_il_en_a_la_forme() {
        let mut payload = payload_valide();
        payload.as_object_mut().unwrap().remove("email");
        assert_eq!(
            user(payload).email.as_deref(),
            Some("Alice.Martin@example.com")
        );

        // Un identifiant qui n'est pas une adresse ne se déguise pas en adresse : le compte sera
        // refusé plus loin, avec un message qui nomme l'adresse manquante.
        let mut payload = payload_valide();
        payload.as_object_mut().unwrap().remove("email");
        payload["preferred_username"] = serde_json::json!("amartin");
        assert_eq!(user(payload).email, None);
    }

    /// Les claims se renomment : chez un fournisseur qui nomme `oid` ce qu'Entra ID appelle
    /// ainsi, ou `roles` ce que d'autres appellent `groups`.
    #[test]
    fn les_noms_de_claims_se_declarent() {
        let mut payload = payload_valide();
        payload["oid"] = serde_json::json!("objet-du-tenant");
        payload["roles"] = serde_json::json!(["platform-admin"]);

        let claims = OidcClaims {
            subject: "oid".to_string(),
            groups: "roles".to_string(),
            ..OidcClaims::default()
        };

        let identity = extract(&token(payload), &expected(), &claims).unwrap();
        assert_eq!(identity.user.pin, "objet-du-tenant");
        assert_eq!(identity.user.member_of, vec!["platform-admin".to_string()]);
    }

    #[test]
    fn un_jeton_qui_n_en_est_pas_un_est_refuse() {
        for brut in ["", "pas-un-jeton", "a.b", "a.b.c.d", "a.!!.c"] {
            assert!(
                extract(brut, &expected(), &OidcClaims::default()).is_err(),
                "{brut:?} accepté à tort"
            );
        }
    }
}

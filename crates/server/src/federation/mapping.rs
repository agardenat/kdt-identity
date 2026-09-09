//! Correspondance entre les groupes de la source et les `KdtGroup`.
//!
//! Elle est déclarée, jamais devinée. Dériver un nom kdt d'un DN — ou d'un identifiant de
//! groupe — demanderait de le normaliser : minuscules, caractères interdits remplacés, longueur
//! coupée. Deux groupes distincts de la source pourraient alors aboutir au même nom, donc aux
//! mêmes droits. Une table écrite à la main n'a pas ce défaut : ce qui n'y figure pas n'existe
//! pas côté cluster.

use super::Source;
use kdt_identity_api::validate_name;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
struct RawMapping {
    /// Ce que la source appelle ce groupe : un DN pour un annuaire, la valeur telle qu'elle
    /// figure dans le claim pour un fournisseur.
    ///
    /// Deux noms pour un même champ, parce que les deux tables sont écrites par des gens qui ne
    /// regardent pas la même chose : `dn` reste le nom historique, et écrire `dn` en face d'un
    /// identifiant de groupe Entra n'aurait aucun sens.
    #[serde(rename = "dn", alias = "claim")]
    key: String,
    group: String,
}

/// Table `groupe de la source` → `nom de KdtGroup`.
///
/// Les deux sens sont plusieurs-à-plusieurs, volontairement : deux groupes de la source peuvent
/// conduire au même groupe kdt, et un seul groupe de la source peut en ouvrir plusieurs.
/// Contraindre l'un ou l'autre interdirait des organisations légitimes sans rien protéger.
#[derive(Debug, Clone)]
pub struct GroupMappings {
    /// Clé normalisée, nom du groupe kdt.
    entries: Vec<(String, String)>,
    /// La source décide de ce que « la même clé » veut dire.
    source: Source,
}

impl GroupMappings {
    /// Table vide pour une source donnée : personne n'obtient de groupe.
    pub fn empty(source: Source) -> Self {
        Self {
            entries: Vec::new(),
            source,
        }
    }

    /// Lit la table telle que le chart la rend, en JSON.
    ///
    /// Chaque nom de groupe est validé ici, au démarrage. Le laisser passer produirait un
    /// `KdtGroup` que l'apiserver refuse à la première connexion, c'est-à-dire une erreur
    /// découverte par la personne qui se connecte plutôt que par celle qui a écrit la table.
    pub fn parse(raw: &str, source: Source) -> Result<Self, String> {
        let parsed: Vec<RawMapping> =
            serde_json::from_str(raw).map_err(|e| format!("table de correspondance illisible : {e}"))?;

        let mut entries = Vec::with_capacity(parsed.len());
        for mapping in parsed {
            validate_name(&mapping.group)
                .map_err(|e| format!("groupe {:?} : {e}", mapping.group))?;

            let key = normalize(&mapping.key, source);
            if key.is_empty() {
                return Err(format!(
                    "groupe {:?} : la clé de correspondance est vide",
                    mapping.group
                ));
            }
            entries.push((key, mapping.group));
        }

        Ok(Self { entries, source })
    }

    /// Groupes kdt ouverts par les groupes dont la personne est membre.
    ///
    /// Une clé sans correspondance est ignorée sans bruit : c'est le cas courant, un annuaire
    /// d'entreprise — ou un tenant — portant des centaines de groupes dont aucun ne concerne le
    /// cluster.
    pub fn resolve(&self, member_of: &[String]) -> Vec<String> {
        let keys: BTreeSet<String> = member_of
            .iter()
            .map(|key| normalize(key, self.source))
            .collect();

        self.entries
            .iter()
            .filter(|(key, _)| keys.contains(key))
            .map(|(_, group)| group.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Tous les groupes kdt que la table gère, triés.
    ///
    /// Sert à la réconciliation : un groupe cité ici doit exister, et une personne qui n'y a
    /// plus droit doit en être retirée. Sans cette liste, on saurait ajouter sans savoir
    /// enlever.
    pub fn managed_groups(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(_, group)| group.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Forme comparable d'une clé, selon ce que la source y met.
///
/// Un identifiant de groupe rendu par un fournisseur n'a pas de structure : c'est un GUID chez
/// Entra, un chemin chez Keycloak, un nom ailleurs. Seules la casse et les espaces de bordure
/// sont neutralisés — deux groupes qui ne différeraient que par la casse seraient donc
/// confondus, ce qui est le prix de la tolérance qui fait correspondre `GUID` et `guid`.
fn normalize(key: &str, source: Source) -> String {
    match source {
        Source::Ldap => normalize_dn(key),
        Source::Oidc => key.trim().to_lowercase(),
    }
}

/// Forme comparable d'un DN.
///
/// Un annuaire ne rend pas le DN tel qu'il a été écrit : la casse varie, et les espaces autour
/// des virgules aussi. Comparer les chaînes brutes ferait échouer une correspondance pourtant
/// juste — et l'échec serait silencieux, la personne se connectant simplement sans ses groupes.
///
/// La virgule échappée `\,` appartient à la valeur d'un RDN et ne sépare rien : découper
/// dessus couperait `cn=Doe\, John` en deux, et le DN ne correspondrait plus à lui-même.
pub fn normalize_dn(dn: &str) -> String {
    split_rdns(dn)
        .into_iter()
        .map(|rdn| rdn.trim().to_lowercase())
        .filter(|rdn| !rdn.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

fn split_rdns(dn: &str) -> Vec<String> {
    let mut rdns = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for c in dn.chars() {
        if escaped {
            current.push(c);
            escaped = false;
        } else if c == '\\' {
            current.push(c);
            escaped = true;
        } else if c == ',' {
            rdns.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    rdns.push(current);
    rdns
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mappings() -> GroupMappings {
        GroupMappings::parse(
            r#"[
                {"dn": "cn=k8s-admins,ou=groups,dc=example,dc=com", "group": "admins"},
                {"dn": "CN=K8s-Devs, OU=Groups, DC=example, DC=com", "group": "devs"}
            ]"#,
            Source::Ldap,
        )
        .unwrap()
    }

    #[test]
    fn seuls_les_groupes_declares_ouvrent_un_droit() {
        let member_of = vec![
            "cn=k8s-admins,ou=groups,dc=example,dc=com".to_string(),
            "cn=cantine,ou=groups,dc=example,dc=com".to_string(),
        ];
        assert_eq!(mappings().resolve(&member_of), vec!["admins"]);
    }

    /// Un annuaire ne rend pas le DN tel qu'il a été saisi. Comparer les chaînes brutes ferait
    /// échouer une correspondance juste, et la personne se connecterait sans ses groupes sans
    /// que rien ne le signale.
    #[test]
    fn la_casse_et_les_espaces_ne_changent_rien() {
        let member_of = vec!["CN=K8S-DEVS,OU=Groups,DC=Example,DC=com".to_string()];
        assert_eq!(mappings().resolve(&member_of), vec!["devs"]);
    }

    /// `cn=Doe\, John` porte une virgule dans sa valeur. La prendre pour un séparateur
    /// couperait le DN en deux et il ne correspondrait plus à lui-même.
    #[test]
    fn une_virgule_echappee_ne_separe_pas_deux_composants() {
        let table = GroupMappings::parse(
            r#"[{"dn": "cn=Doe\\, John,ou=groups,dc=example,dc=com", "group": "direction"}]"#,
            Source::Ldap,
        )
        .unwrap();

        let member_of = vec!["CN=Doe\\, John,OU=Groups,DC=example,DC=com".to_string()];
        assert_eq!(table.resolve(&member_of), vec!["direction"]);
    }

    /// Deux groupes de l'annuaire vers un même groupe kdt, et l'inverse : les deux sont des
    /// organisations légitimes, et le résultat ne doit jamais contenir de doublon.
    #[test]
    fn les_correspondances_multiples_s_unissent_sans_doublon() {
        let table = GroupMappings::parse(
            r#"[
                {"dn": "cn=a,dc=x", "group": "ops"},
                {"dn": "cn=b,dc=x", "group": "ops"},
                {"dn": "cn=a,dc=x", "group": "lecture"}
            ]"#,
            Source::Ldap,
        )
        .unwrap();

        let member_of = vec!["cn=a,dc=x".to_string(), "cn=b,dc=x".to_string()];
        assert_eq!(table.resolve(&member_of), vec!["lecture", "ops"]);
        assert_eq!(table.managed_groups(), vec!["lecture", "ops"]);
    }

    /// Un nom refusé par l'apiserver doit l'être au démarrage. Sinon l'erreur se découvre à la
    /// première connexion, du côté de la personne qui se connecte.
    #[test]
    fn un_nom_de_groupe_invalide_empeche_le_demarrage() {
        for group in ["Admins", "kdt:admins", "system:masters", "-admins", ""] {
            let raw = format!(r#"[{{"dn": "cn=g,dc=x", "group": "{group}"}}]"#);
            assert!(
                GroupMappings::parse(&raw, Source::Ldap).is_err(),
                "{group:?} accepté à tort"
            );
        }
    }

    #[test]
    fn une_table_vide_est_valide_et_n_ouvre_rien() {
        let table = GroupMappings::parse("[]", Source::Ldap).unwrap();
        assert!(table.is_empty());
        assert!(table.resolve(&["cn=a,dc=x".to_string()]).is_empty());
    }

    /// La table d'un fournisseur se déclare avec `claim`, et sa clé n'a aucune structure : un
    /// GUID Entra doit correspondre quelle que soit la casse sous laquelle il est écrit de part
    /// et d'autre.
    #[test]
    fn une_table_de_fournisseur_se_declare_avec_claim() {
        let table = GroupMappings::parse(
            r#"[
                {"claim": "8F4A1C2E-0B77-4E3B-9A21-2C5D8E7F0A11", "group": "admins"},
                {"claim": "/platform/devs", "group": "devs"}
            ]"#,
            Source::Oidc,
        )
        .unwrap();

        let member_of = vec![
            "8f4a1c2e-0b77-4e3b-9a21-2c5d8e7f0a11".to_string(),
            "/platform/devs".to_string(),
            "b7e0-inconnu".to_string(),
        ];
        assert_eq!(table.resolve(&member_of), vec!["admins", "devs"]);
    }

    /// Une clé de fournisseur n'est pas un DN : la découper sur les virgules ferait
    /// correspondre des groupes qui n'ont rien à voir.
    #[test]
    fn une_cle_de_fournisseur_n_est_pas_decoupee() {
        let table = GroupMappings::parse(
            r#"[{"claim": "equipe,plateforme", "group": "ops"}]"#,
            Source::Oidc,
        )
        .unwrap();

        assert_eq!(table.resolve(&["equipe,plateforme".to_string()]), vec!["ops"]);
        assert!(table.resolve(&["equipe".to_string()]).is_empty());
    }
}

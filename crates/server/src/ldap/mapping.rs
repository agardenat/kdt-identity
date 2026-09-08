//! Correspondance entre les groupes de l'annuaire et les `KdtGroup`.
//!
//! Elle est déclarée, jamais devinée. Dériver un nom kdt d'un DN demanderait de le normaliser —
//! minuscules, caractères interdits remplacés, longueur coupée — et deux groupes distincts de
//! l'annuaire pourraient alors aboutir au même nom, donc aux mêmes droits. Une table écrite à
//! la main n'a pas ce défaut : ce qui n'y figure pas n'existe pas côté cluster.

use kdt_identity_api::validate_name;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
struct RawMapping {
    dn: String,
    group: String,
}

/// Table `DN de l'annuaire` → `nom de KdtGroup`.
///
/// Les deux sens sont plusieurs-à-plusieurs, volontairement : deux groupes de l'annuaire
/// peuvent conduire au même groupe kdt, et un seul groupe de l'annuaire peut en ouvrir
/// plusieurs. Contraindre l'un ou l'autre interdirait des organisations légitimes sans rien
/// protéger.
#[derive(Debug, Clone, Default)]
pub struct GroupMappings {
    /// DN normalisé, nom du groupe kdt.
    entries: Vec<(String, String)>,
}

impl GroupMappings {
    /// Lit la table telle que le chart la rend, en JSON.
    ///
    /// Chaque nom de groupe est validé ici, au démarrage. Le laisser passer produirait un
    /// `KdtGroup` que l'apiserver refuse à la première connexion, c'est-à-dire une erreur
    /// découverte par la personne qui se connecte plutôt que par celle qui a écrit la table.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let parsed: Vec<RawMapping> =
            serde_json::from_str(raw).map_err(|e| format!("table de correspondance illisible : {e}"))?;

        let mut entries = Vec::with_capacity(parsed.len());
        for mapping in parsed {
            validate_name(&mapping.group)
                .map_err(|e| format!("groupe {:?} : {e}", mapping.group))?;

            let dn = normalize_dn(&mapping.dn);
            if dn.is_empty() {
                return Err(format!("groupe {:?} : DN vide", mapping.group));
            }
            entries.push((dn, mapping.group));
        }

        Ok(Self { entries })
    }

    /// Groupes kdt ouverts par les DN dont la personne est membre.
    ///
    /// Un DN sans correspondance est ignoré sans bruit : c'est le cas courant, un annuaire
    /// d'entreprise portant des centaines de groupes dont aucun ne concerne le cluster.
    pub fn resolve(&self, member_of: &[String]) -> Vec<String> {
        let dns: BTreeSet<String> = member_of.iter().map(|dn| normalize_dn(dn)).collect();

        self.entries
            .iter()
            .filter(|(dn, _)| dns.contains(dn))
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
                GroupMappings::parse(&raw).is_err(),
                "{group:?} accepté à tort"
            );
        }
    }

    #[test]
    fn une_table_vide_est_valide_et_n_ouvre_rien() {
        let table = GroupMappings::parse("[]").unwrap();
        assert!(table.is_empty());
        assert!(table.resolve(&["cn=a,dc=x".to_string()]).is_empty());
    }
}

//! Verrouillage après échecs répétés.
//!
//! Un mot de passe de douze caractères ne résiste au devinage en ligne que si le devinage en
//! ligne est lent. Ce module rend chaque échec supplémentaire plus coûteux, sans jamais
//! verrouiller définitivement — un verrou permanent déclenché à distance serait un déni de
//! service offert à quiconque connaît un nom de compte.

use chrono::{DateTime, Duration, Utc};

/// Nombre d'échecs tolérés avant que le verrouillage ne commence.
///
/// Assez haut pour absorber les fautes de frappe et un code TOTP saisi trop tard, assez bas
/// pour que le devinage devienne pénible immédiatement après.
pub const THRESHOLD: u32 = 5;

/// Attente appliquée au premier échec au-delà du seuil ; elle double ensuite.
pub const BASE_DELAY: Duration = Duration::seconds(30);

/// Plafond de l'attente.
///
/// Le doublement s'arrête ici : au-delà, le verrou ne protège plus davantage mais devient une
/// arme commode contre un utilisateur légitime.
pub const MAX_DELAY: Duration = Duration::minutes(15);

/// Compteur d'échecs d'un compte, tel qu'il est conservé entre deux tentatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lockout {
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}

impl Lockout {
    /// Vrai si le compte est verrouillé à cet instant.
    pub fn is_locked(&self, now: DateTime<Utc>) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }

    /// Temps restant avant déverrouillage, pour l'afficher à l'utilisateur.
    pub fn remaining(&self, now: DateTime<Utc>) -> Option<Duration> {
        self.locked_until
            .filter(|until| now < *until)
            .map(|until| until - now)
    }

    /// Enregistre un échec et recalcule le verrou.
    pub fn record_failure(self, now: DateTime<Utc>) -> Self {
        let failed_attempts = self.failed_attempts.saturating_add(1);

        let locked_until = match failed_attempts.checked_sub(THRESHOLD) {
            None | Some(0) => self.locked_until,
            Some(over) => Some(now + delay_for(over)),
        };

        Self {
            failed_attempts,
            locked_until,
        }
    }

    /// Efface le compteur après une authentification réussie.
    ///
    /// Sans cette remise à zéro, un compte très utilisé finirait verrouillé par accumulation
    /// de fautes de frappe étalées sur des mois.
    pub fn record_success(self) -> Self {
        Self::default()
    }
}

/// Attente pour le `n`-ième échec au-delà du seuil : 30 s, 1 min, 2 min… jusqu'au plafond.
fn delay_for(over_threshold: u32) -> Duration {
    // L'exposant est borné très en deçà de la largeur d'un `i32`. Le décalage y déborderait
    // dans le bit de signe, produisant un facteur négatif, donc une attente négative — et un
    // compte massivement attaqué se retrouverait déverrouillé, soit l'inverse exact de ce que
    // fait ce module. Le plafond étant atteint dès le sixième échec au-delà du seuil
    // (30 s × 2⁵ = 16 min), une borne à 16 ne change rien au comportement observable.
    const MAX_EXPONENT: u32 = 16;

    let exponent = over_threshold.saturating_sub(1).min(MAX_EXPONENT);
    BASE_DELAY
        .checked_mul(1i32 << exponent)
        .unwrap_or(MAX_DELAY)
        .min(MAX_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn after_failures(count: u32) -> Lockout {
        (0..count).fold(Lockout::default(), |state, _| state.record_failure(now()))
    }

    #[test]
    fn un_compte_neuf_n_est_pas_verrouille() {
        assert!(!Lockout::default().is_locked(now()));
        assert_eq!(Lockout::default().remaining(now()), None);
    }

    /// Les fautes de frappe ordinaires ne doivent gêner personne.
    #[test]
    fn les_premiers_echecs_ne_verrouillent_pas() {
        for count in 1..=THRESHOLD {
            let state = after_failures(count);
            assert!(
                !state.is_locked(now()),
                "{count} échec(s) ne devraient pas verrouiller"
            );
        }
    }

    #[test]
    fn le_verrou_s_active_au_dela_du_seuil() {
        let state = after_failures(THRESHOLD + 1);
        assert!(state.is_locked(now()));
        assert_eq!(state.remaining(now()), Some(BASE_DELAY));
    }

    /// Chaque échec supplémentaire double l'attente : le devinage devient vite impraticable.
    #[test]
    fn l_attente_double_a_chaque_echec() {
        let attendus = [
            Duration::seconds(30),
            Duration::minutes(1),
            Duration::minutes(2),
            Duration::minutes(4),
            Duration::minutes(8),
        ];
        for (i, attendu) in attendus.iter().enumerate() {
            let state = after_failures(THRESHOLD + 1 + i as u32);
            assert_eq!(
                state.remaining(now()),
                Some(*attendu),
                "après {} échecs",
                THRESHOLD + 1 + i as u32
            );
        }
    }

    /// Le plafond existe pour que le verrou reste une gêne, jamais une exclusion.
    #[test]
    fn l_attente_est_plafonnee() {
        for extra in [10, 20, 50, 1000] {
            let state = after_failures(THRESHOLD + extra);
            assert_eq!(
                state.remaining(now()),
                Some(MAX_DELAY),
                "après {extra} échecs au-delà du seuil"
            );
        }
    }

    #[test]
    fn le_verrou_expire_de_lui_meme() {
        let state = after_failures(THRESHOLD + 1);
        let apres = now() + BASE_DELAY;

        assert!(!state.is_locked(apres));
        assert_eq!(state.remaining(apres), None);
    }

    #[test]
    fn une_authentification_reussie_remet_le_compteur_a_zero() {
        let state = after_failures(THRESHOLD + 3).record_success();
        assert_eq!(state, Lockout::default());
        assert!(!state.is_locked(now()));
    }

    /// Un compteur qui déborderait ferait retomber le compte à zéro échec, donc déverrouillé.
    #[test]
    fn le_compteur_ne_deborde_pas() {
        let extreme = Lockout {
            failed_attempts: u32::MAX,
            locked_until: None,
        }
        .record_failure(now());

        assert_eq!(extreme.failed_attempts, u32::MAX);
        assert!(extreme.is_locked(now()));
    }
}

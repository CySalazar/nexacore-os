//! Thermal- and workload-aware scheduling policy (WS1-10).
//!
//! The base fairness rotation ([`crate::scheduling`], ADR-0025) is thermal- and
//! load-blind. This module layers a **thermal-aware** policy on top: as the CPU
//! warms under an AI-inference burst, the scheduler favours the
//! [`crate::scheduling::PriorityClass::AiInference`] class so the burst drains quickly (WS1-10.4),
//! while a hard **Interactive floor** guarantees the interactive class can never
//! be starved by that favouring (WS1-10.5).
//!
//! Everything here is pure (`no_std`, integer math) and host-testable: the
//! scheduler feeds it a temperature reading (WS1-10.2) and the current dominant
//! load class (WS1-10.3), and it returns the fairness cycle `pick_next` should
//! use this tick.

use crate::scheduling::{FAIRNESS_CYCLE, PriorityClass};

/// Thermal pressure band derived from the CPU temperature (WS1-10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThermalLevel {
    /// Comfortable — no thermal adjustment (the ADR-0025 baseline cycle).
    Normal,
    /// Warming — begin favouring an in-flight inference burst.
    Warm,
    /// Hot — maximally favour the inference burst (capped).
    Hot,
    /// Critical — stay at the capped favour; the Interactive floor still holds.
    Critical,
}

/// Temperature thresholds (in milli-degrees Celsius) between thermal bands.
/// Typical mobile/desktop CPU: nominal < 70 °C, throttle territory ≥ 95 °C.
const WARM_MC: u32 = 70_000;
const HOT_MC: u32 = 85_000;
const CRITICAL_MC: u32 = 95_000;

/// Classify a CPU temperature (milli-°C) into a [`ThermalLevel`] (WS1-10.2).
#[must_use]
pub const fn thermal_level(cpu_temp_millicelsius: u32) -> ThermalLevel {
    if cpu_temp_millicelsius >= CRITICAL_MC {
        ThermalLevel::Critical
    } else if cpu_temp_millicelsius >= HOT_MC {
        ThermalLevel::Hot
    } else if cpu_temp_millicelsius >= WARM_MC {
        ThermalLevel::Warm
    } else {
        ThermalLevel::Normal
    }
}

/// The minimum number of first-preference slots the Interactive class keeps in
/// **every** thermal cycle (WS1-10.5) — the anti-starvation floor.
pub const INTERACTIVE_FLOOR: usize = 2;

/// The fairness cycle `pick_next` should use under thermal `level` (WS1-10.4).
///
/// `Normal` returns the unmodified ADR-0025 `FAIRNESS_CYCLE` (so behaviour and
/// every existing scheduler test are unchanged when the CPU is cool). Warmer
/// bands convert *Background/`None`* slots into [`PriorityClass::AiInference`]
/// first-preference slots so an inference burst drains faster — **never** an
/// Interactive slot, so the [`INTERACTIVE_FLOOR`] of 2 is preserved at every
/// level. The boost is capped at `Hot` (Critical does not boost further), which
/// is the WS1-10.5 cap.
#[must_use]
pub const fn fairness_cycle_for(level: ThermalLevel) -> [Option<PriorityClass>; 8] {
    use PriorityClass::{AiInference, Interactive};
    match level {
        // Baseline: Interactive ×2, AiInference ×1, Background ×1.
        ThermalLevel::Normal => FAIRNESS_CYCLE,
        // Warm: +1 AiInference (the Background slot → AiInference). Interactive ×2.
        ThermalLevel::Warm => [
            None,
            None,
            Some(Interactive),
            None,
            Some(AiInference),
            Some(Interactive),
            None,
            Some(AiInference),
        ],
        // Hot / Critical (capped): +2 AiInference (a `None` slot also → AiInference).
        // Interactive ×2 floor still intact; Background falls back via the `None`
        // strict-order slots.
        ThermalLevel::Hot | ThermalLevel::Critical => [
            None,
            Some(AiInference),
            Some(Interactive),
            None,
            Some(AiInference),
            Some(Interactive),
            None,
            Some(AiInference),
        ],
    }
}

/// Count the first-preference slots a `class` holds in a cycle.
#[must_use]
pub fn slot_count(cycle: [Option<PriorityClass>; 8], class: PriorityClass) -> usize {
    cycle.iter().filter(|s| **s == Some(class)).count()
}

/// Whether favouring `AiInference` is warranted: an elevated thermal band
/// **and** an AI-dominated load (WS1-10.3 — the boost is workload-aware, not
/// just hot).
#[must_use]
pub const fn should_favour_ai(level: ThermalLevel, dominant_load: PriorityClass) -> bool {
    !matches!(level, ThermalLevel::Normal) && matches!(dominant_load, PriorityClass::AiInference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_map_to_bands() {
        assert_eq!(thermal_level(40_000), ThermalLevel::Normal);
        assert_eq!(thermal_level(70_000), ThermalLevel::Warm);
        assert_eq!(thermal_level(85_000), ThermalLevel::Hot);
        assert_eq!(thermal_level(99_000), ThermalLevel::Critical);
    }

    #[test]
    fn normal_cycle_is_the_baseline() {
        assert_eq!(fairness_cycle_for(ThermalLevel::Normal), FAIRNESS_CYCLE);
    }

    #[test]
    fn ai_slots_increase_then_cap_with_heat() {
        let n = slot_count(
            fairness_cycle_for(ThermalLevel::Normal),
            PriorityClass::AiInference,
        );
        let w = slot_count(
            fairness_cycle_for(ThermalLevel::Warm),
            PriorityClass::AiInference,
        );
        let h = slot_count(
            fairness_cycle_for(ThermalLevel::Hot),
            PriorityClass::AiInference,
        );
        let c = slot_count(
            fairness_cycle_for(ThermalLevel::Critical),
            PriorityClass::AiInference,
        );
        assert_eq!(n, 1);
        assert_eq!(w, 2);
        assert_eq!(h, 3);
        assert_eq!(c, h, "Critical is capped at the Hot boost");
    }

    #[test]
    fn interactive_floor_holds_at_every_level() {
        for level in [
            ThermalLevel::Normal,
            ThermalLevel::Warm,
            ThermalLevel::Hot,
            ThermalLevel::Critical,
        ] {
            let cycle = fairness_cycle_for(level);
            assert!(
                slot_count(cycle, PriorityClass::Interactive) >= INTERACTIVE_FLOOR,
                "Interactive floor violated at {level:?}"
            );
        }
    }

    #[test]
    fn favour_is_workload_aware() {
        assert!(should_favour_ai(
            ThermalLevel::Hot,
            PriorityClass::AiInference
        ));
        // Hot but the load is Interactive-dominated → do not favour AI.
        assert!(!should_favour_ai(
            ThermalLevel::Hot,
            PriorityClass::Interactive
        ));
        // AI-dominated but cool → no boost needed.
        assert!(!should_favour_ai(
            ThermalLevel::Normal,
            PriorityClass::AiInference
        ));
    }
}

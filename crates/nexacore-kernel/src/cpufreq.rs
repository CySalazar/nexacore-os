//! CPU frequency-scaling governor (WS12-06.6).
//!
//! The kernel picks a CPU operating frequency (P-state) each sample from an
//! observed load signal. The design mirrors [`crate::metrics`]: it splits into
//! pure, host-testable policy logic and a single hardware seam, so the whole
//! algorithm is exercised without touching an MSR or ACPI table.
//!
//! Three layers:
//!
//! 1. **Frequency table** ([`FrequencyTable`]) — the available P-states as an
//!    ascending list of frequencies (kHz), with `min`/`max` bounds derived
//!    from the ends. This is the discrete set the governor may select from.
//! 2. **Governor** ([`Governor`]) — computes the *target* P-state from a
//!    per-sample load reading (utilization `0..=100`). The `ondemand` policy
//!    steps the frequency **up** when load exceeds an up-threshold and **down**
//!    when it falls below a down-threshold; the gap between the two thresholds
//!    is a **hysteresis** band in which the frequency is held, so load hovering
//!    near a single threshold does not thrash the P-state. Selection is always
//!    clamped to the table bounds. `performance` pins the maximum and
//!    `powersave` pins the minimum.
//! 3. **Controller seam** ([`FreqController`]) — the actual MSR/ACPI frequency
//!    *write*. The bare-metal kernel implements this over the platform P-state
//!    interface; host tests use a recording double. The governor never writes
//!    hardware directly — it computes a target and hands it to the seam.

use alloc::vec::Vec;

// =============================================================================
// Frequency table (P-states)
// =============================================================================

/// An error building a [`FrequencyTable`] or an [`OndemandConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernorError {
    /// A frequency table was built with no P-states.
    EmptyTable,
    /// Ondemand thresholds were invalid: they must satisfy
    /// `0 <= down < up <= 100` so the hysteresis band is non-degenerate.
    InvalidThresholds,
}

/// The available CPU P-states, as an ascending, de-duplicated list of
/// frequencies in kHz.
///
/// Built from an arbitrary slice of frequencies via [`FrequencyTable::new`],
/// which sorts and de-duplicates them; the lowest is [`min_khz`](Self::min_khz)
/// and the highest [`max_khz`](Self::max_khz). The governor selects an index
/// into this table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrequencyTable {
    /// Frequencies in kHz, strictly ascending, guaranteed non-empty.
    steps: Vec<u32>,
}

impl FrequencyTable {
    /// Build a table from a slice of frequencies (kHz). The input is sorted
    /// ascending and de-duplicated, so callers may pass P-states in any order.
    ///
    /// # Errors
    ///
    /// [`GovernorError::EmptyTable`] if `steps` is empty.
    pub fn new(steps: &[u32]) -> Result<Self, GovernorError> {
        if steps.is_empty() {
            return Err(GovernorError::EmptyTable);
        }
        let mut steps: Vec<u32> = steps.to_vec();
        steps.sort_unstable();
        steps.dedup();
        Ok(Self { steps })
    }

    /// The P-states, ascending.
    #[must_use]
    pub fn steps(&self) -> &[u32] {
        &self.steps
    }

    /// The lowest available frequency (kHz).
    #[must_use]
    pub fn min_khz(&self) -> u32 {
        self.steps.first().copied().unwrap_or(0)
    }

    /// The highest available frequency (kHz).
    #[must_use]
    pub fn max_khz(&self) -> u32 {
        self.steps.last().copied().unwrap_or(0)
    }

    /// The frequency (kHz) at `index`, or `None` if out of range.
    #[must_use]
    pub fn freq_at(&self, index: usize) -> Option<u32> {
        self.steps.get(index).copied()
    }

    /// The index of the highest P-state (`len - 1`).
    #[must_use]
    fn max_index(&self) -> usize {
        self.steps.len().saturating_sub(1)
    }
}

// =============================================================================
// Policies
// =============================================================================

/// The governor policy selecting how the target frequency is derived from load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Always run at the maximum P-state, ignoring load.
    Performance,
    /// Always run at the minimum P-state, ignoring load.
    Powersave,
    /// Step up/down around load thresholds with hysteresis (the default).
    Ondemand,
}

/// The thresholds driving the [`Policy::Ondemand`] algorithm.
///
/// Load (utilization, `0..=100`) above `up_threshold` steps the frequency up;
/// below `down_threshold` steps it down; in between it is held. The band
/// `[down_threshold, up_threshold]` is the hysteresis that prevents thrashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OndemandConfig {
    /// Load above this (exclusive) steps the P-state up. In `0..=100`.
    up_threshold: u8,
    /// Load below this (exclusive) steps the P-state down. In `0..=100`.
    down_threshold: u8,
}

impl OndemandConfig {
    /// Build a config, validating that `0 <= down < up <= 100`.
    ///
    /// # Errors
    ///
    /// [`GovernorError::InvalidThresholds`] if the ordering/bounds do not hold
    /// (a degenerate band would remove the hysteresis guarantee).
    pub const fn new(up_threshold: u8, down_threshold: u8) -> Result<Self, GovernorError> {
        if up_threshold > 100 || down_threshold >= up_threshold {
            return Err(GovernorError::InvalidThresholds);
        }
        Ok(Self {
            up_threshold,
            down_threshold,
        })
    }

    /// The up-threshold (load above this steps up).
    #[must_use]
    pub const fn up_threshold(self) -> u8 {
        self.up_threshold
    }

    /// The down-threshold (load below this steps down).
    #[must_use]
    pub const fn down_threshold(self) -> u8 {
        self.down_threshold
    }
}

impl Default for OndemandConfig {
    /// The conventional ondemand defaults: up at 80%, down at 30%, giving a
    /// wide 30..=80 hysteresis band.
    fn default() -> Self {
        Self {
            up_threshold: 80,
            down_threshold: 30,
        }
    }
}

// =============================================================================
// Controller seam
// =============================================================================

/// An error writing a frequency through the hardware seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreqError {
    /// The platform rejected or failed the P-state write.
    WriteFailed,
}

/// The hardware seam: applies a selected frequency to the CPU.
///
/// The bare-metal kernel implements this over the platform P-state interface
/// (an MSR write on Intel `HWP`/`IA32_PERF_CTL`, or the ACPI `_PSS`/`_PPC`
/// method set). Host tests implement it with a recording double so the
/// governor's selection logic is verified without hardware.
pub trait FreqController {
    /// Apply `khz` as the new target CPU frequency.
    ///
    /// # Errors
    ///
    /// [`FreqError::WriteFailed`] if the platform rejects the write.
    fn write_frequency(&mut self, khz: u32) -> Result<(), FreqError>;
}

// =============================================================================
// Governor
// =============================================================================

/// The CPU frequency-scaling governor: holds the P-state table, the active
/// policy, and the current P-state index, and computes the next target from a
/// per-sample load reading.
#[derive(Clone, Debug)]
pub struct Governor {
    /// The available P-states.
    table: FrequencyTable,
    /// The active policy.
    policy: Policy,
    /// Ondemand thresholds (only consulted under [`Policy::Ondemand`]).
    ondemand: OndemandConfig,
    /// The index into `table` of the currently applied frequency.
    current: usize,
}

impl Governor {
    /// Create a governor over `table` running `policy`, starting at the minimum
    /// P-state with the default [`OndemandConfig`].
    #[must_use]
    pub fn new(table: FrequencyTable, policy: Policy) -> Self {
        Self {
            table,
            policy,
            ondemand: OndemandConfig::default(),
            current: 0,
        }
    }

    /// Builder: override the ondemand thresholds.
    #[must_use]
    pub fn with_ondemand_config(mut self, config: OndemandConfig) -> Self {
        self.ondemand = config;
        self
    }

    /// The active policy.
    #[must_use]
    pub const fn policy(&self) -> Policy {
        self.policy
    }

    /// Switch the active policy. The current P-state is unchanged until the next
    /// [`step`](Self::step).
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// The P-state table.
    #[must_use]
    pub const fn table(&self) -> &FrequencyTable {
        &self.table
    }

    /// The index of the currently applied P-state.
    #[must_use]
    pub const fn current_index(&self) -> usize {
        self.current
    }

    /// The currently applied frequency (kHz).
    #[must_use]
    pub fn current_khz(&self) -> u32 {
        self.table
            .freq_at(self.current)
            .unwrap_or_else(|| self.table.min_khz())
    }

    /// Compute the target P-state **index** for `load` under the active policy,
    /// without applying it. Pure: no hardware, no state mutation.
    ///
    /// `load` is a utilization percentage; values above 100 are treated as 100.
    /// Under [`Policy::Ondemand`] the result is one step up (load above the
    /// up-threshold), one step down (below the down-threshold), or unchanged
    /// (inside the hysteresis band), always clamped to the table bounds.
    #[must_use]
    pub fn target_index(&self, load: u8) -> usize {
        let max = self.table.max_index();
        match self.policy {
            Policy::Performance => max,
            Policy::Powersave => 0,
            Policy::Ondemand => {
                let load = load.min(100);
                if load > self.ondemand.up_threshold {
                    (self.current + 1).min(max)
                } else if load < self.ondemand.down_threshold {
                    self.current.saturating_sub(1)
                } else {
                    self.current
                }
            }
        }
    }

    /// The target frequency (kHz) for `load`, without applying it.
    #[must_use]
    pub fn target_khz(&self, load: u8) -> u32 {
        self.table
            .freq_at(self.target_index(load))
            .unwrap_or_else(|| self.current_khz())
    }

    /// Advance one governor sample: compute the target P-state for `load` and,
    /// if it differs from the current one, apply it through `controller` and
    /// commit it. Returns the frequency (kHz) in force after the step.
    ///
    /// A held P-state (inside the hysteresis band, or already at a clamp bound)
    /// issues **no** hardware write.
    ///
    /// # Errors
    ///
    /// Propagates [`FreqError`] from `controller`; on a write error the current
    /// P-state is left unchanged.
    pub fn step(
        &mut self,
        load: u8,
        controller: &mut dyn FreqController,
    ) -> Result<u32, FreqError> {
        let target = self.target_index(load);
        if target != self.current {
            let khz = self
                .table
                .freq_at(target)
                .unwrap_or_else(|| self.current_khz());
            controller.write_frequency(khz)?;
            self.current = target;
        }
        Ok(self.current_khz())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    /// A recording [`FreqController`] test double: captures every applied
    /// frequency, and can be made to fail every write.
    struct RecordingController {
        writes: Vec<u32>,
        fail: bool,
    }

    impl RecordingController {
        fn new() -> Self {
            Self {
                writes: Vec::new(),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                writes: Vec::new(),
                fail: true,
            }
        }

        fn writes(&self) -> &[u32] {
            &self.writes
        }
    }

    impl FreqController for RecordingController {
        fn write_frequency(&mut self, khz: u32) -> Result<(), FreqError> {
            if self.fail {
                return Err(FreqError::WriteFailed);
            }
            self.writes.push(khz);
            Ok(())
        }
    }

    /// A 5-state table: 800 MHz .. 2400 MHz in 400 MHz steps (kHz).
    fn table() -> FrequencyTable {
        FrequencyTable::new(&[800_000, 1_200_000, 1_600_000, 2_000_000, 2_400_000]).unwrap()
    }

    #[test]
    fn table_sorts_dedups_and_exposes_bounds() {
        let t = FrequencyTable::new(&[2_000_000, 800_000, 800_000, 1_600_000]).unwrap();
        assert_eq!(t.steps(), &[800_000, 1_600_000, 2_000_000]);
        assert_eq!(t.min_khz(), 800_000);
        assert_eq!(t.max_khz(), 2_000_000);
    }

    #[test]
    fn empty_table_is_rejected() {
        assert_eq!(FrequencyTable::new(&[]), Err(GovernorError::EmptyTable));
    }

    #[test]
    fn ondemand_config_rejects_degenerate_band() {
        assert_eq!(
            OndemandConfig::new(80, 80),
            Err(GovernorError::InvalidThresholds)
        );
        assert_eq!(
            OndemandConfig::new(101, 30),
            Err(GovernorError::InvalidThresholds)
        );
        assert!(OndemandConfig::new(80, 30).is_ok());
    }

    #[test]
    fn rising_load_steps_up_and_clamps_at_max() {
        let mut gov = Governor::new(table(), Policy::Ondemand);
        let mut ctl = RecordingController::new();
        // Start at the minimum P-state.
        assert_eq!(gov.current_khz(), 800_000);

        // Sustained high load steps up one P-state per sample.
        let f1 = gov.step(95, &mut ctl).unwrap();
        assert_eq!(f1, 1_200_000);
        let f2 = gov.step(95, &mut ctl).unwrap();
        assert_eq!(f2, 1_600_000);
        gov.step(95, &mut ctl).unwrap();
        gov.step(95, &mut ctl).unwrap();
        // Now at max (2_400_000); a further high sample must clamp, not overrun.
        let f_max = gov.step(95, &mut ctl).unwrap();
        assert_eq!(f_max, 2_400_000);
        let f_clamped = gov.step(95, &mut ctl).unwrap();
        assert_eq!(f_clamped, 2_400_000);

        // Four upward writes were applied; the clamped sample issued none.
        assert_eq!(ctl.writes(), &[1_200_000, 1_600_000, 2_000_000, 2_400_000]);
    }

    #[test]
    fn falling_load_steps_down_and_clamps_at_min() {
        let mut gov = Governor::new(table(), Policy::Ondemand);
        let mut ctl = RecordingController::new();
        // Drive up to the top first.
        for _ in 0..4 {
            gov.step(95, &mut ctl).unwrap();
        }
        assert_eq!(gov.current_khz(), 2_400_000);

        // Sustained low (idle) load steps down one P-state per sample.
        assert_eq!(gov.step(5, &mut ctl).unwrap(), 2_000_000);
        assert_eq!(gov.step(5, &mut ctl).unwrap(), 1_600_000);
        assert_eq!(gov.step(5, &mut ctl).unwrap(), 1_200_000);
        assert_eq!(gov.step(5, &mut ctl).unwrap(), 800_000);
        // At min; a further idle sample clamps.
        assert_eq!(gov.step(5, &mut ctl).unwrap(), 800_000);
    }

    #[test]
    fn hysteresis_holds_frequency_near_a_threshold() {
        // Band is 30..=80 by default. Bring the governor to a mid P-state.
        let mut gov = Governor::new(table(), Policy::Ondemand);
        let mut ctl = RecordingController::new();
        gov.step(95, &mut ctl).unwrap(); // -> 1_200_000
        gov.step(95, &mut ctl).unwrap(); // -> 1_600_000
        let base = gov.current_index();
        let base_khz = gov.current_khz();
        let writes_before = ctl.writes().len();

        // Load hovering inside the band (either side of, but not crossing, a
        // threshold) must NOT change the P-state — no thrashing.
        for load in [79, 80, 31, 30, 55, 78, 32] {
            let f = gov.step(load, &mut ctl).unwrap();
            assert_eq!(f, base_khz, "load {load} should hold");
            assert_eq!(gov.current_index(), base);
        }
        // Not a single hardware write occurred across the hovering window.
        assert_eq!(ctl.writes().len(), writes_before);
    }

    #[test]
    fn performance_pins_max_powersave_pins_min() {
        let mut ctl = RecordingController::new();

        let mut perf = Governor::new(table(), Policy::Performance);
        // Even at zero load, performance jumps straight to the top.
        assert_eq!(perf.step(0, &mut ctl).unwrap(), 2_400_000);
        assert_eq!(perf.target_index(0), 4);

        let mut save = Governor::new(table(), Policy::Powersave);
        // Drive it up under ondemand-like abuse: powersave still pins min.
        assert_eq!(save.step(100, &mut ctl).unwrap(), 800_000);
        assert_eq!(save.target_index(100), 0);
    }

    #[test]
    fn write_error_leaves_current_pstate_unchanged() {
        let mut gov = Governor::new(table(), Policy::Ondemand);
        let mut ctl = RecordingController::failing();
        assert_eq!(gov.step(95, &mut ctl), Err(FreqError::WriteFailed));
        // The failed write did not commit the step.
        assert_eq!(gov.current_index(), 0);
        assert_eq!(gov.current_khz(), 800_000);
    }

    #[test]
    fn load_above_100_is_saturated_not_wrapped() {
        let gov = Governor::new(table(), Policy::Ondemand);
        // 200 clamps to 100, which is above the up-threshold → step up.
        assert_eq!(gov.target_index(200), 1);
    }
}

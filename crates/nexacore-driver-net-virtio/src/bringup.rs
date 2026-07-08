//! Bring-up state machine — full transition table (P6.7.8.3).
//!
//! `NCIP-Driver-Net-015` § S4.1 prescribes a nine-step bring-up sequence
//! that the driver MUST execute after `DriverLoad` spawns its process and
//! the kernel mints the per-driver capability tokens. The phases below
//! mirror the state-machine view of those nine steps:
//!
//! 1. [`Phase::Reset`] — write [`device_status::RESET`] and poll back to
//!    `0x00` (§ S4.1 step 2).
//! 2. [`Phase::Acknowledge`] — write `ACKNOWLEDGE` then `ACKNOWLEDGE |
//!    DRIVER` (§ S4.1 step 3).
//! 3. [`Phase::FeatureNegotiation`] — read `device_feature`, AND with
//!    [`features::REQUIRED_FEATURES`] plus opted-in extras, write
//!    `driver_feature` and `FEATURES_OK` (§ S4.1 step 4).
//! 4. [`Phase::FeaturesLocked`] — re-read `device_status`; if
//!    `FEATURES_OK` is still set, advance. Otherwise transition to
//!    [`Phase::Failed`] (§ S4.1 step 5).
//! 5. [`Phase::VirtqueueSetup`] — `DmaMap` RX / TX virtqueues, program
//!    Common Cfg `queue_*` 64-bit addresses (§ S4.1 step 6).
//! 6. [`Phase::MacAcquired`] — read MAC from the Device Cfg, store
//!    locally for the eventual `NetEvent::MacChanged` emission
//!    (§ S4.1 step 7, NCIP-015 § S2.3 + § S3).
//! 7. [`Phase::DriverOk`] — set `DRIVER_OK`; the device is live. Post RX
//!    buffers, `IrqAttach` virtqueue IRQ vectors, register the NET
//!    service channel (§ S4.1 steps 8-9, NCIP-015 § S8 common-bringup
//!    finalizer).
//! 8. [`Phase::Failed`] — terminal error state; the driver process exits.
//!
//! The transition table is now wired end-to-end via [`BringUp`] (the
//! state-machine driver) and [`Event`] (the per-step outcome posted by
//! the actual syscall caller). The *actual* `MmioMap` / `DmaMap` /
//! `IrqAttach` invocations live in the bootable image sibling
//! `nexacore-driver-net-virtio-image` (which builds the runtime ELF the
//! kernel ingests via `DriverLoad`). This crate stays library-only and
//! host-testable.
//!
//! [`device_status::RESET`]: crate::device_status::RESET
//! [`features::REQUIRED_FEATURES`]: crate::features::REQUIRED_FEATURES

/// Ordered phases of the virtio-net bring-up state machine.
///
/// The driver advances strictly in `repr(u8)` order. Skipping a phase is
/// a kernel-detectable violation of `NCIP-Driver-Net-015` § S4.1; the
/// monotonicity is verified by the scaffold unit tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    /// § S4.1 step 2 — write `device_status::RESET`, await device clear.
    Reset = 0,
    /// § S4.1 step 3 — driver acknowledges the device.
    Acknowledge = 1,
    /// § S4.1 step 4 — feature OR/AND/write loop.
    FeatureNegotiation = 2,
    /// § S4.1 step 5 — re-read `device_status`; confirm `FEATURES_OK`.
    FeaturesLocked = 3,
    /// § S4.1 step 6 — allocate + program RX/TX virtqueues.
    VirtqueueSetup = 4,
    /// § S4.1 step 7 — read negotiated MAC from Device Cfg offset 0.
    MacAcquired = 5,
    /// § S4.1 step 8 — set `DRIVER_OK`; device is live, IRQs attached,
    /// NET service channel registered.
    DriverOk = 6,
    /// Terminal failure phase — emitted on `FEATURES_OK` not retained
    /// (§ S4.1 step 5) or on any subsequent unrecoverable error.
    Failed = 7,
}

impl Phase {
    /// Return the next phase in the bring-up sequence, or `None` if the
    /// driver is already at the terminal state ([`Phase::DriverOk`] or
    /// [`Phase::Failed`]).
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Reset => Some(Self::Acknowledge),
            Self::Acknowledge => Some(Self::FeatureNegotiation),
            Self::FeatureNegotiation => Some(Self::FeaturesLocked),
            Self::FeaturesLocked => Some(Self::VirtqueueSetup),
            Self::VirtqueueSetup => Some(Self::MacAcquired),
            Self::MacAcquired => Some(Self::DriverOk),
            Self::DriverOk | Self::Failed => None,
        }
    }

    /// Returns `true` if the phase is terminal (no further transitions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::DriverOk | Self::Failed)
    }

    /// Returns `true` if the phase represents a successful steady-state
    /// (the device is live and the driver is serving the NET channel).
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::DriverOk)
    }
}

// =============================================================================
// Bring-up driver — Event/Error/Transition (P6.7.8.3)
// =============================================================================

/// Bring-up event posted by the driver after each syscall step
/// completes (or fails). Pure data — the FSM is the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The step completed successfully; advance to the next phase.
    Advance,
    /// The step completed but the device reported a transient error
    /// the driver should retry. Caller increments the retry counter
    /// and re-invokes the syscall. After [`MAX_RETRIES`] consecutive
    /// transients the FSM forces a [`Phase::Failed`] transition.
    Retry,
    /// The step failed with an unrecoverable condition. The FSM
    /// transitions to [`Phase::Failed`] and the driver process is
    /// expected to call `TaskExit(1)`.
    Abort(BringUpError),
}

/// Errors the bring-up driver can encounter.
///
/// Distinguishing them is useful for log correlation; the kernel only
/// sees the `TaskExit` code, but the driver can post a structured event
/// on its event channel before exiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BringUpError {
    /// `device_status::FAILED` was set by the device after a write —
    /// driver / device mismatch (e.g. spec violation by either side).
    DeviceFailed,
    /// The mandatory features in [`crate::features::REQUIRED_FEATURES`]
    /// were not all offered by the device. virtio 1.0 § 3.1 mandates
    /// that we abort.
    RequiredFeaturesAbsent,
    /// After writing `FEATURES_OK` the device cleared the bit,
    /// indicating it does not accept the negotiated feature subset
    /// (§ S4.1 step 5).
    FeaturesNotAccepted,
    /// `MmioMap` returned an error — the kernel rejected the BAR
    /// mapping (capability missing, wrong region, allocator OOM).
    MmioMapFailed,
    /// `DmaMap` returned an error — the kernel could not install the
    /// IOMMU domain (or the no-IOMMU passthrough allocation failed).
    DmaMapFailed,
    /// `IrqAttach` returned an error — the kernel could not allocate a
    /// LAPIC vector or the IRQ line was already in use (shared-line
    /// rejection per § S4.1).
    IrqAttachFailed,
    /// The retry counter hit [`MAX_RETRIES`] without advancing.
    RetryBudgetExhausted,
    /// The driver attempted to advance from a terminal phase. This is
    /// always a driver bug — the FSM stays parked.
    TerminalAdvanceAttempted,
}

/// Maximum retry budget for a single phase. virtio-net devices on
/// QEMU/Proxmox typically converge on the first attempt; we cap at 3 to
/// bound bring-up latency.
pub const MAX_RETRIES: u8 = 3;

/// Bring-up state-machine driver.
///
/// Tracks the current [`Phase`] and the retry counter for the current
/// step. The actual syscall invocations are external — this struct is
/// pure host-testable logic that the bootable driver image wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BringUp {
    phase: Phase,
    retries: u8,
}

impl BringUp {
    /// Construct a fresh bring-up tracker parked at [`Phase::Reset`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: Phase::Reset,
            retries: 0,
        }
    }

    /// Current phase.
    #[must_use]
    pub const fn phase(self) -> Phase {
        self.phase
    }

    /// Retry counter for the current phase (resets on each `Advance`).
    #[must_use]
    pub const fn retries(self) -> u8 {
        self.retries
    }

    /// Apply an [`Event`] to the FSM, returning the new state. The
    /// FSM transitions are:
    ///
    /// - `Event::Advance` → `phase.next()` (resets retries). If the
    ///   current phase is terminal, the FSM forces [`Phase::Failed`]
    ///   and signals [`BringUpError::TerminalAdvanceAttempted`].
    /// - `Event::Retry` → same phase, retries + 1. When the retry
    ///   counter reaches [`MAX_RETRIES`] the FSM transitions to
    ///   [`Phase::Failed`] with [`BringUpError::RetryBudgetExhausted`].
    /// - `Event::Abort(_)` → [`Phase::Failed`].
    ///
    /// Returns `Ok(new_state)` on a clean transition, or
    /// `Err(BringUpError)` when the FSM forces a failure path. The
    /// failure variant is also reflected in `self.phase` so the caller
    /// can read it back from a single source of truth.
    ///
    /// # Errors
    ///
    /// - [`BringUpError::TerminalAdvanceAttempted`] when called on
    ///   [`Phase::DriverOk`] or [`Phase::Failed`].
    /// - [`BringUpError::RetryBudgetExhausted`] when retries reach
    ///   [`MAX_RETRIES`] on a single phase.
    /// - any [`BringUpError`] variant supplied via [`Event::Abort`].
    pub fn on_event(&mut self, event: Event) -> Result<Self, BringUpError> {
        match event {
            Event::Advance => {
                if self.phase.is_terminal() {
                    self.phase = Phase::Failed;
                    self.retries = 0;
                    return Err(BringUpError::TerminalAdvanceAttempted);
                }
                // `next()` is `Some(_)` for every non-terminal phase by
                // construction; the match above already eliminated the
                // terminal cases.
                if let Some(next) = self.phase.next() {
                    self.phase = next;
                    self.retries = 0;
                }
                Ok(*self)
            }
            Event::Retry => {
                if self.phase.is_terminal() {
                    self.phase = Phase::Failed;
                    return Err(BringUpError::TerminalAdvanceAttempted);
                }
                self.retries = self.retries.saturating_add(1);
                if self.retries >= MAX_RETRIES {
                    self.phase = Phase::Failed;
                    self.retries = 0;
                    return Err(BringUpError::RetryBudgetExhausted);
                }
                Ok(*self)
            }
            Event::Abort(err) => {
                self.phase = Phase::Failed;
                self.retries = 0;
                Err(err)
            }
        }
    }

    /// Returns the syscall the driver should issue at the current
    /// phase. Pure projection — the driver process consumes this to
    /// know which `MmioMap` / `DmaMap` / `IrqAttach` to invoke.
    #[must_use]
    pub const fn pending_step(self) -> StepKind {
        match self.phase {
            Phase::Reset => StepKind::WriteDeviceStatus(0x00),
            Phase::Acknowledge => StepKind::WriteDeviceStatus(0x03), // ACK | DRIVER
            Phase::FeatureNegotiation => StepKind::NegotiateFeatures,
            Phase::FeaturesLocked => StepKind::ReadDeviceStatus,
            Phase::VirtqueueSetup => StepKind::ConfigureVirtqueues,
            Phase::MacAcquired => StepKind::ReadMac,
            Phase::DriverOk => StepKind::SetDriverOk,
            Phase::Failed => StepKind::ParkExit,
        }
    }
}

impl Default for BringUp {
    fn default() -> Self {
        Self::new()
    }
}

/// Coarse step descriptor — the syscall family the driver issues at
/// the current phase. Carries enough information for host tests; the
/// runtime driver maps each variant to an actual syscall + arg layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// Write a literal `device_status` byte (§ S4.1 steps 2/3).
    WriteDeviceStatus(u8),
    /// Read `device_feature`, AND with `REQUIRED_FEATURES`, write
    /// `driver_feature`, then `FEATURES_OK` (§ S4.1 step 4).
    NegotiateFeatures,
    /// Re-read `device_status` to confirm `FEATURES_OK` survived
    /// (§ S4.1 step 5).
    ReadDeviceStatus,
    /// `DmaMap` RX/TX virtqueues + program Common Cfg
    /// `queue_*` registers (§ S4.1 step 6).
    ConfigureVirtqueues,
    /// Read MAC bytes from Device Cfg (§ S4.1 step 7).
    ReadMac,
    /// Write `DRIVER_OK` + `IrqAttach` + register NET channel
    /// (§ S4.1 step 8).
    SetDriverOk,
    /// Driver process should call `TaskExit(_)` and let the kernel
    /// reap the PCB. Reached only from [`Phase::Failed`].
    ParkExit,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Phase enum scaffolds (preserved from P6.7.8.2) ------------------

    #[test]
    fn variants_are_monotonic() {
        let mut cur = Phase::Reset;
        while let Some(next) = cur.next() {
            assert!(
                (next as u8) > (cur as u8),
                "Phase::next produced a non-monotonic transition: {cur:?} -> {next:?}"
            );
            cur = next;
        }
        assert_eq!(cur, Phase::DriverOk);
    }

    #[test]
    fn driver_ok_is_terminal_and_live() {
        assert!(Phase::DriverOk.is_terminal());
        assert!(Phase::DriverOk.is_live());
        assert!(Phase::DriverOk.next().is_none());
    }

    #[test]
    fn failed_is_terminal_but_not_live() {
        assert!(Phase::Failed.is_terminal());
        assert!(!Phase::Failed.is_live());
        assert!(Phase::Failed.next().is_none());
    }

    #[test]
    fn pre_terminal_phases_are_neither_terminal_nor_live() {
        for phase in [
            Phase::Reset,
            Phase::Acknowledge,
            Phase::FeatureNegotiation,
            Phase::FeaturesLocked,
            Phase::VirtqueueSetup,
            Phase::MacAcquired,
        ] {
            assert!(
                !phase.is_terminal(),
                "phase {phase:?} unexpectedly terminal"
            );
            assert!(!phase.is_live(), "phase {phase:?} unexpectedly live");
            assert!(phase.next().is_some(), "phase {phase:?} should advance");
        }
    }

    #[test]
    fn discriminants_match_ncip_step_ordering() {
        assert_eq!(Phase::Reset as u8, 0);
        assert_eq!(Phase::Acknowledge as u8, 1);
        assert_eq!(Phase::FeatureNegotiation as u8, 2);
        assert_eq!(Phase::FeaturesLocked as u8, 3);
        assert_eq!(Phase::VirtqueueSetup as u8, 4);
        assert_eq!(Phase::MacAcquired as u8, 5);
        assert_eq!(Phase::DriverOk as u8, 6);
        assert_eq!(Phase::Failed as u8, 7);
    }

    // ---- BringUp driver (P6.7.8.3) ---------------------------------------

    #[test]
    fn new_starts_at_reset_with_zero_retries() {
        let s = BringUp::new();
        assert_eq!(s.phase(), Phase::Reset);
        assert_eq!(s.retries(), 0);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(BringUp::default(), BringUp::new());
    }

    #[test]
    fn advance_traverses_every_non_terminal_phase() {
        let mut s = BringUp::new();
        let path = [
            Phase::Acknowledge,
            Phase::FeatureNegotiation,
            Phase::FeaturesLocked,
            Phase::VirtqueueSetup,
            Phase::MacAcquired,
            Phase::DriverOk,
        ];
        for expected in path {
            let next = s.on_event(Event::Advance).expect("advance ok");
            assert_eq!(next.phase(), expected);
            assert_eq!(next.retries(), 0);
            s = next;
        }
    }

    #[test]
    fn advance_from_driver_ok_marks_failed_and_reports_terminal_attempt() {
        let mut s = BringUp::new();
        for _ in 0..6 {
            s = s.on_event(Event::Advance).expect("advance ok");
        }
        assert_eq!(s.phase(), Phase::DriverOk);
        let err = s.on_event(Event::Advance).unwrap_err();
        assert_eq!(err, BringUpError::TerminalAdvanceAttempted);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn advance_from_failed_is_no_op_via_terminal_attempt() {
        let mut s = BringUp::new();
        let _ = s.on_event(Event::Abort(BringUpError::DeviceFailed));
        assert_eq!(s.phase(), Phase::Failed);
        let err = s.on_event(Event::Advance).unwrap_err();
        assert_eq!(err, BringUpError::TerminalAdvanceAttempted);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn retry_increments_counter_without_changing_phase() {
        let mut s = BringUp::new();
        let r1 = s.on_event(Event::Retry).expect("first retry ok");
        assert_eq!(r1.phase(), Phase::Reset);
        assert_eq!(r1.retries(), 1);
        s = r1;
        let r2 = s.on_event(Event::Retry).expect("second retry ok");
        assert_eq!(r2.phase(), Phase::Reset);
        assert_eq!(r2.retries(), 2);
    }

    #[test]
    fn retry_budget_exhaustion_transitions_to_failed() {
        let mut s = BringUp::new();
        // First two retries succeed; the third trips the budget.
        let _ = s.on_event(Event::Retry).expect("r1");
        let _ = s.on_event(Event::Retry).expect("r2");
        let err = s.on_event(Event::Retry).unwrap_err();
        assert_eq!(err, BringUpError::RetryBudgetExhausted);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn retry_counter_resets_after_advance() {
        let mut s = BringUp::new();
        let _ = s.on_event(Event::Retry).expect("r1");
        let _ = s.on_event(Event::Retry).expect("r2");
        assert_eq!(s.retries(), 2);
        let advanced = s.on_event(Event::Advance).expect("advance ok");
        assert_eq!(advanced.phase(), Phase::Acknowledge);
        assert_eq!(advanced.retries(), 0);
    }

    #[test]
    fn abort_carries_error_and_parks_at_failed() {
        let mut s = BringUp::new();
        let err = s
            .on_event(Event::Abort(BringUpError::MmioMapFailed))
            .unwrap_err();
        assert_eq!(err, BringUpError::MmioMapFailed);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn abort_distinguishes_every_error_variant() {
        for err in [
            BringUpError::DeviceFailed,
            BringUpError::RequiredFeaturesAbsent,
            BringUpError::FeaturesNotAccepted,
            BringUpError::MmioMapFailed,
            BringUpError::DmaMapFailed,
            BringUpError::IrqAttachFailed,
        ] {
            let mut s = BringUp::new();
            let got = s.on_event(Event::Abort(err)).unwrap_err();
            assert_eq!(got, err);
            assert_eq!(s.phase(), Phase::Failed);
        }
    }

    #[test]
    fn pending_step_matches_phase_reset() {
        let s = BringUp::new();
        assert!(matches!(s.pending_step(), StepKind::WriteDeviceStatus(0)));
    }

    #[test]
    fn pending_step_matches_phase_acknowledge() {
        let mut s = BringUp::new();
        s = s.on_event(Event::Advance).unwrap();
        assert!(matches!(
            s.pending_step(),
            StepKind::WriteDeviceStatus(0x03)
        ));
    }

    #[test]
    fn pending_step_covers_every_phase() {
        let phases = [
            Phase::Reset,
            Phase::Acknowledge,
            Phase::FeatureNegotiation,
            Phase::FeaturesLocked,
            Phase::VirtqueueSetup,
            Phase::MacAcquired,
            Phase::DriverOk,
            Phase::Failed,
        ];
        for p in phases {
            let s = BringUp {
                phase: p,
                retries: 0,
            };
            // Smoke: every variant must produce a deterministic step.
            let _ = s.pending_step();
        }
    }

    #[test]
    fn max_retries_is_three() {
        // Pin the constant — driver bring-up latency budget anchor.
        assert_eq!(MAX_RETRIES, 3);
    }

    #[test]
    fn full_happy_path_reaches_driver_ok() {
        let mut s = BringUp::new();
        for _ in 0..6 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::DriverOk);
        assert!(s.phase().is_live());
    }

    #[test]
    fn retry_then_advance_reaches_driver_ok_when_under_budget() {
        let mut s = BringUp::new();
        // Reset phase retried twice, then advance through the rest.
        let _ = s.on_event(Event::Retry).unwrap();
        let _ = s.on_event(Event::Retry).unwrap();
        for _ in 0..6 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::DriverOk);
    }

    #[test]
    fn step_kind_park_exit_only_from_failed() {
        // Only the Failed phase emits ParkExit.
        for phase in [
            Phase::Reset,
            Phase::Acknowledge,
            Phase::FeatureNegotiation,
            Phase::FeaturesLocked,
            Phase::VirtqueueSetup,
            Phase::MacAcquired,
            Phase::DriverOk,
        ] {
            let s = BringUp { phase, retries: 0 };
            assert_ne!(s.pending_step(), StepKind::ParkExit);
        }
        let failed = BringUp {
            phase: Phase::Failed,
            retries: 0,
        };
        assert_eq!(failed.pending_step(), StepKind::ParkExit);
    }
}

//! Bring-up state machine — 13-step transition table.
//!
//! [`NCIP-Driver-NVMe-014`] § S6 prescribes a 13-step bring-up sequence
//! that the driver MUST execute after `DriverLoad` spawns its process
//! and the kernel mints the per-driver capability tokens. The phases
//! below mirror the state-machine view of those 13 steps:
//!
//! 1. [`Phase::PciEnumeration`] — walk ECAM via [`NCIP-Driver-Framework-013`]
//!    § S1 `PciConfigRead` to locate the NVMe controller (§ S6 step 1).
//! 2. [`Phase::MmioMap`] — `MmioMap(BAR0, 16 KiB)` to obtain the
//!    controller register window (§ S6 step 2).
//! 3. [`Phase::ReadCap`] — read `CAP` to extract `MQES`, `DSTRD`,
//!    `MPSMIN`/`MPSMAX` (§ S6 step 3).
//! 4. [`Phase::DisableController`] — clear `CC.EN`, poll `CSTS.RDY = 0`
//!    (§ S6 step 4).
//! 5. [`Phase::SetupAdminQueues`] — `DmaMap` ASQ/ACQ pages, write
//!    `AQA`/`ASQ`/`ACQ` (§ S6 step 5).
//! 6. [`Phase::EnableController`] — write
//!    `CC.{IOSQES=6, IOCQES=4, EN=1, MPS=0, CSS=0}`; poll
//!    `CSTS.RDY = 1` (§ S6 step 6).
//! 7. [`Phase::AttachInterrupts`] — enable MSI-X via PCI config; call
//!    `IrqAttach` per vector (§ S6 step 7).
//! 8. [`Phase::IdentifyController`] — submit `Identify(Controller)`
//!    (§ S6 step 8).
//! 9. [`Phase::IdentifyActiveNsList`] — submit
//!    `Identify(ActiveNsList)`, pick the first NSID (§ S6 step 9).
//! 10. [`Phase::IdentifyNamespace`] — submit `Identify(Namespace)`,
//!     validate `LBADS = 12` (4 KiB sectors) (§ S6 step 10).
//! 11. [`Phase::CreateIoQueues`] — submit
//!     `Create IO Completion Queue` then `Create IO Submission Queue`
//!     admin commands (§ S6 step 11).
//! 12. [`Phase::RegisterBlkChannel`] — `IpcCreateChannel("nexacore.svc.blk.nvme0",
//!     queue_depth=1024, backpressure=true)` (§ S6 step 12).
//! 13. [`Phase::Ready`] — emit
//!     `[driver-nvme] ready disk0 size=N GiB sectors=M` and enter the
//!     BLK command-processing loop (§ S6 step 13).
//!
//! Terminal failure phase [`Phase::Failed`] is reached on any
//! unrecoverable error; the driver process exits with code `1` and the
//! kernel reclaims resources via the standard process-exit teardown.
//!
//! The actual `MmioMap` / `DmaMap` / `IrqAttach` invocations live in the
//! bootable image sibling `nexacore-driver-nvme-image` (P6.7.8.5). This
//! crate stays library-only and host-testable.
//!
//! [`NCIP-Driver-NVMe-014`]: ../../../ncips/ncip-driver-nvme-014.md
//! [`NCIP-Driver-Framework-013`]: ../../../ncips/ncip-driver-framework-013.md

/// Ordered phases of the NVMe bring-up state machine.
///
/// The driver advances strictly in `repr(u8)` order. Skipping a phase
/// is a kernel-detectable violation of `NCIP-Driver-NVMe-014` § S6; the
/// monotonicity is verified by the scaffold unit tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    /// § S6 step 1 — PCI enumeration via `PciConfigRead`.
    PciEnumeration = 0,
    /// § S6 step 2 — `MmioMap` the controller's BAR0.
    MmioMap = 1,
    /// § S6 step 3 — read `CAP` register.
    ReadCap = 2,
    /// § S6 step 4 — disable the controller (`CC.EN = 0`).
    DisableController = 3,
    /// § S6 step 5 — `DmaMap` and program admin queues.
    SetupAdminQueues = 4,
    /// § S6 step 6 — enable the controller (`CC.EN = 1`).
    EnableController = 5,
    /// § S6 step 7 — MSI-X enable + `IrqAttach` per vector.
    AttachInterrupts = 6,
    /// § S6 step 8 — `Identify(Controller)`.
    IdentifyController = 7,
    /// § S6 step 9 — `Identify(ActiveNsList)`.
    IdentifyActiveNsList = 8,
    /// § S6 step 10 — `Identify(Namespace)`, validate 4 KiB sectors.
    IdentifyNamespace = 9,
    /// § S6 step 11 — create IO queue pair via admin commands.
    CreateIoQueues = 10,
    /// § S6 step 12 — register the BLK service channel.
    RegisterBlkChannel = 11,
    /// § S6 step 13 — driver is live; enter the BLK command loop.
    Ready = 12,
    /// Terminal failure phase — driver process exits with code `1`.
    Failed = 13,
}

impl Phase {
    /// Return the next phase, or `None` at the terminal states
    /// ([`Phase::Ready`] / [`Phase::Failed`]).
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::PciEnumeration => Some(Self::MmioMap),
            Self::MmioMap => Some(Self::ReadCap),
            Self::ReadCap => Some(Self::DisableController),
            Self::DisableController => Some(Self::SetupAdminQueues),
            Self::SetupAdminQueues => Some(Self::EnableController),
            Self::EnableController => Some(Self::AttachInterrupts),
            Self::AttachInterrupts => Some(Self::IdentifyController),
            Self::IdentifyController => Some(Self::IdentifyActiveNsList),
            Self::IdentifyActiveNsList => Some(Self::IdentifyNamespace),
            Self::IdentifyNamespace => Some(Self::CreateIoQueues),
            Self::CreateIoQueues => Some(Self::RegisterBlkChannel),
            Self::RegisterBlkChannel => Some(Self::Ready),
            Self::Ready | Self::Failed => None,
        }
    }

    /// Returns `true` if the phase is terminal (no further transitions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ready | Self::Failed)
    }

    /// Returns `true` if the phase represents a successful steady-state
    /// (the controller is live and the BLK channel is serving).
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Ready)
    }
}

// =============================================================================
// Bring-up driver — Event / Error / Transition (P6.7.8.4)
// =============================================================================

/// Bring-up event posted by the driver after each syscall step
/// completes (or fails). Pure data — the FSM is the consumer.
///
/// Mirrors the shape of [`crate::bringup::Event`] in
/// `nexacore-driver-net-virtio` (P6.7.8.3): the contract is identical so
/// future per-driver supervisor code can drive both FSMs through the
/// same trampoline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The step completed successfully; advance to the next phase.
    Advance,
    /// The step completed but the device reported a transient error
    /// the driver should retry (e.g. `CSTS.RDY` not yet asserted).
    /// After [`MAX_RETRIES`] consecutive transients the FSM forces a
    /// [`Phase::Failed`] transition.
    Retry,
    /// The step failed with an unrecoverable condition. The FSM
    /// transitions to [`Phase::Failed`] and the driver process is
    /// expected to call `TaskExit(1)`.
    Abort(BringUpError),
}

/// Errors the bring-up driver can encounter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BringUpError {
    /// PCI enumeration found no device matching the manifest's
    /// `pci_class`. The driver cannot proceed.
    NoMatchingDevice,
    /// `MmioMap` returned an error — the kernel rejected the BAR0
    /// mapping (capability missing, wrong region, allocator OOM).
    MmioMapFailed,
    /// The controller advertised an NVMe version below 1.0, which the
    /// v0.3 driver does not support.
    UnsupportedNvmeVersion,
    /// The controller's `MPSMIN` exceeds the kernel's 4 KiB page size
    /// — the driver cannot allocate buffers small enough.
    UnsupportedPageSize,
    /// `CSTS.RDY` did not toggle within the polling budget at either
    /// step 4 (disable) or step 6 (enable).
    ControllerReadyTimeout,
    /// `CSTS.CFS` is asserted — Controller Fatal Status. The driver
    /// emits `NvmeEvent::ControllerFatal` and exits.
    ControllerFatal,
    /// `DmaMap` returned an error — the kernel could not install the
    /// IOMMU domain (or the no-IOMMU passthrough allocation failed).
    DmaMapFailed,
    /// `IrqAttach` returned an error — the kernel could not allocate a
    /// LAPIC vector or the IRQ line was already in use (shared-line
    /// rejection per NCIP-013 § S4.1).
    IrqAttachFailed,
    /// An admin command (Identify, Create IO SQ/CQ) returned a non-zero
    /// completion status.
    AdminCommandFailed,
    /// The selected namespace's `LBADS` field is not 12 (i.e. sector
    /// size is not 4 KiB). NCIP-014 § S6 step 10: the driver MUST log
    /// and reject such namespaces.
    UnsupportedSectorSize,
    /// `IpcCreateChannel` failed at step 12. Without a BLK channel
    /// the driver has no way to surface storage to clients.
    BlkChannelRegistrationFailed,
    /// Manifest queue depths fall outside the bounds in
    /// [`crate::queue_config`]. Distinct from `EINVAL` at the
    /// `DriverLoad` syscall: the driver does its own defence-in-depth
    /// check before issuing any controller writes.
    InvalidManifestQueueDepth,
    /// The retry counter hit [`MAX_RETRIES`] without advancing.
    RetryBudgetExhausted,
    /// The driver attempted to advance from a terminal phase. Always
    /// a driver bug — the FSM stays parked.
    TerminalAdvanceAttempted,
}

/// Maximum retry budget for a single phase. NVMe controllers on
/// QEMU/Proxmox typically converge on the first attempt; we cap at 3
/// to bound bring-up latency.
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
    /// Construct a fresh bring-up tracker parked at
    /// [`Phase::PciEnumeration`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: Phase::PciEnumeration,
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

    /// Apply an [`Event`] to the FSM, returning the new state.
    ///
    /// - `Event::Advance` → `phase.next()` (resets retries). If the
    ///   current phase is terminal, the FSM forces [`Phase::Failed`]
    ///   and signals [`BringUpError::TerminalAdvanceAttempted`].
    /// - `Event::Retry` → same phase, retries + 1. When the retry
    ///   counter reaches [`MAX_RETRIES`] the FSM transitions to
    ///   [`Phase::Failed`] with [`BringUpError::RetryBudgetExhausted`].
    /// - `Event::Abort(_)` → [`Phase::Failed`].
    ///
    /// # Errors
    ///
    /// - [`BringUpError::TerminalAdvanceAttempted`] when called on
    ///   [`Phase::Ready`] or [`Phase::Failed`].
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

    /// Returns the syscall family the driver should issue at the
    /// current phase. Pure projection — the driver process consumes
    /// this to know which syscall to invoke.
    #[must_use]
    pub const fn pending_step(self) -> StepKind {
        match self.phase {
            Phase::PciEnumeration => StepKind::EnumeratePci,
            Phase::MmioMap => StepKind::MapControllerRegisters,
            Phase::ReadCap => StepKind::ReadCapabilities,
            Phase::DisableController => StepKind::WriteControllerConfig(0),
            Phase::SetupAdminQueues => StepKind::AllocateAdminQueues,
            Phase::EnableController => StepKind::WriteControllerConfig(1),
            Phase::AttachInterrupts => StepKind::AttachMsiXVectors,
            Phase::IdentifyController => StepKind::SubmitIdentifyController,
            Phase::IdentifyActiveNsList => StepKind::SubmitIdentifyActiveNsList,
            Phase::IdentifyNamespace => StepKind::SubmitIdentifyNamespace,
            Phase::CreateIoQueues => StepKind::CreateIoQueuePair,
            Phase::RegisterBlkChannel => StepKind::RegisterBlkChannel,
            Phase::Ready => StepKind::EnterBlkLoop,
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
/// the current phase. The runtime driver maps each variant to an
/// actual syscall + arg layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// `PciConfigRead` walks of the ECAM space (§ S6 step 1).
    EnumeratePci,
    /// `MmioMap(BAR0, 16 KiB)` to obtain the controller register
    /// window (§ S6 step 2).
    MapControllerRegisters,
    /// MMIO read of the `CAP` register (§ S6 step 3).
    ReadCapabilities,
    /// MMIO write of `CC` with `EN` set to the embedded byte
    /// (0 = disable at step 4, 1 = enable at step 6).
    WriteControllerConfig(u8),
    /// `DmaMap` ASQ/ACQ pages + MMIO writes to `AQA`/`ASQ`/`ACQ`
    /// (§ S6 step 5).
    AllocateAdminQueues,
    /// PCI MSI-X capability enable + per-vector `IrqAttach`
    /// (§ S6 step 7).
    AttachMsiXVectors,
    /// Admin command: `Identify(Controller)` (§ S6 step 8).
    SubmitIdentifyController,
    /// Admin command: `Identify(ActiveNsList)` (§ S6 step 9).
    SubmitIdentifyActiveNsList,
    /// Admin command: `Identify(Namespace)` (§ S6 step 10).
    SubmitIdentifyNamespace,
    /// Admin commands: `Create IO Completion Queue` + `Create IO
    /// Submission Queue` (§ S6 step 11).
    CreateIoQueuePair,
    /// `IpcCreateChannel("nexacore.svc.blk.nvme0", ...)` (§ S6 step 12).
    RegisterBlkChannel,
    /// Steady-state BLK command-processing loop (§ S6 step 13).
    EnterBlkLoop,
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

    // ---- Phase enum scaffold ---------------------------------------------

    #[test]
    fn variants_are_monotonic() {
        let mut cur = Phase::PciEnumeration;
        while let Some(next) = cur.next() {
            assert!(
                (next as u8) > (cur as u8),
                "Phase::next produced a non-monotonic transition: {cur:?} -> {next:?}"
            );
            cur = next;
        }
        assert_eq!(cur, Phase::Ready);
    }

    #[test]
    fn ready_is_terminal_and_live() {
        assert!(Phase::Ready.is_terminal());
        assert!(Phase::Ready.is_live());
        assert!(Phase::Ready.next().is_none());
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
            Phase::PciEnumeration,
            Phase::MmioMap,
            Phase::ReadCap,
            Phase::DisableController,
            Phase::SetupAdminQueues,
            Phase::EnableController,
            Phase::AttachInterrupts,
            Phase::IdentifyController,
            Phase::IdentifyActiveNsList,
            Phase::IdentifyNamespace,
            Phase::CreateIoQueues,
            Phase::RegisterBlkChannel,
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
        assert_eq!(Phase::PciEnumeration as u8, 0);
        assert_eq!(Phase::MmioMap as u8, 1);
        assert_eq!(Phase::ReadCap as u8, 2);
        assert_eq!(Phase::DisableController as u8, 3);
        assert_eq!(Phase::SetupAdminQueues as u8, 4);
        assert_eq!(Phase::EnableController as u8, 5);
        assert_eq!(Phase::AttachInterrupts as u8, 6);
        assert_eq!(Phase::IdentifyController as u8, 7);
        assert_eq!(Phase::IdentifyActiveNsList as u8, 8);
        assert_eq!(Phase::IdentifyNamespace as u8, 9);
        assert_eq!(Phase::CreateIoQueues as u8, 10);
        assert_eq!(Phase::RegisterBlkChannel as u8, 11);
        assert_eq!(Phase::Ready as u8, 12);
        assert_eq!(Phase::Failed as u8, 13);
    }

    // ---- BringUp driver --------------------------------------------------

    #[test]
    fn new_starts_at_pci_enumeration_with_zero_retries() {
        let s = BringUp::new();
        assert_eq!(s.phase(), Phase::PciEnumeration);
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
            Phase::MmioMap,
            Phase::ReadCap,
            Phase::DisableController,
            Phase::SetupAdminQueues,
            Phase::EnableController,
            Phase::AttachInterrupts,
            Phase::IdentifyController,
            Phase::IdentifyActiveNsList,
            Phase::IdentifyNamespace,
            Phase::CreateIoQueues,
            Phase::RegisterBlkChannel,
            Phase::Ready,
        ];
        for expected in path {
            let next = s.on_event(Event::Advance).expect("advance ok");
            assert_eq!(next.phase(), expected);
            assert_eq!(next.retries(), 0);
            s = next;
        }
    }

    #[test]
    fn advance_from_ready_marks_failed_and_reports_terminal_attempt() {
        let mut s = BringUp::new();
        for _ in 0..12 {
            s = s.on_event(Event::Advance).expect("advance ok");
        }
        assert_eq!(s.phase(), Phase::Ready);
        let err = s.on_event(Event::Advance).unwrap_err();
        assert_eq!(err, BringUpError::TerminalAdvanceAttempted);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn advance_from_failed_is_no_op_via_terminal_attempt() {
        let mut s = BringUp::new();
        let _ = s.on_event(Event::Abort(BringUpError::MmioMapFailed));
        assert_eq!(s.phase(), Phase::Failed);
        let err = s.on_event(Event::Advance).unwrap_err();
        assert_eq!(err, BringUpError::TerminalAdvanceAttempted);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn retry_increments_counter_without_changing_phase() {
        let mut s = BringUp::new();
        let r1 = s.on_event(Event::Retry).expect("first retry ok");
        assert_eq!(r1.phase(), Phase::PciEnumeration);
        assert_eq!(r1.retries(), 1);
        s = r1;
        let r2 = s.on_event(Event::Retry).expect("second retry ok");
        assert_eq!(r2.phase(), Phase::PciEnumeration);
        assert_eq!(r2.retries(), 2);
    }

    #[test]
    fn retry_budget_exhaustion_transitions_to_failed() {
        let mut s = BringUp::new();
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
        assert_eq!(advanced.phase(), Phase::MmioMap);
        assert_eq!(advanced.retries(), 0);
    }

    #[test]
    fn abort_carries_error_and_parks_at_failed() {
        let mut s = BringUp::new();
        let err = s
            .on_event(Event::Abort(BringUpError::ControllerReadyTimeout))
            .unwrap_err();
        assert_eq!(err, BringUpError::ControllerReadyTimeout);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn abort_distinguishes_every_error_variant() {
        for err in [
            BringUpError::NoMatchingDevice,
            BringUpError::MmioMapFailed,
            BringUpError::UnsupportedNvmeVersion,
            BringUpError::UnsupportedPageSize,
            BringUpError::ControllerReadyTimeout,
            BringUpError::ControllerFatal,
            BringUpError::DmaMapFailed,
            BringUpError::IrqAttachFailed,
            BringUpError::AdminCommandFailed,
            BringUpError::UnsupportedSectorSize,
            BringUpError::BlkChannelRegistrationFailed,
            BringUpError::InvalidManifestQueueDepth,
        ] {
            let mut s = BringUp::new();
            let got = s.on_event(Event::Abort(err)).unwrap_err();
            assert_eq!(got, err);
            assert_eq!(s.phase(), Phase::Failed);
        }
    }

    // ---- StepKind projection --------------------------------------------

    #[test]
    fn pending_step_matches_phase_pci_enumeration() {
        let s = BringUp::new();
        assert_eq!(s.pending_step(), StepKind::EnumeratePci);
    }

    #[test]
    fn pending_step_disable_controller_carries_zero() {
        let mut s = BringUp::new();
        for _ in 0..3 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::DisableController);
        assert_eq!(s.pending_step(), StepKind::WriteControllerConfig(0));
    }

    #[test]
    fn pending_step_enable_controller_carries_one() {
        let mut s = BringUp::new();
        for _ in 0..5 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::EnableController);
        assert_eq!(s.pending_step(), StepKind::WriteControllerConfig(1));
    }

    #[test]
    fn pending_step_covers_every_phase() {
        let phases = [
            Phase::PciEnumeration,
            Phase::MmioMap,
            Phase::ReadCap,
            Phase::DisableController,
            Phase::SetupAdminQueues,
            Phase::EnableController,
            Phase::AttachInterrupts,
            Phase::IdentifyController,
            Phase::IdentifyActiveNsList,
            Phase::IdentifyNamespace,
            Phase::CreateIoQueues,
            Phase::RegisterBlkChannel,
            Phase::Ready,
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
    fn step_kind_park_exit_only_from_failed() {
        for phase in [
            Phase::PciEnumeration,
            Phase::MmioMap,
            Phase::ReadCap,
            Phase::DisableController,
            Phase::SetupAdminQueues,
            Phase::EnableController,
            Phase::AttachInterrupts,
            Phase::IdentifyController,
            Phase::IdentifyActiveNsList,
            Phase::IdentifyNamespace,
            Phase::CreateIoQueues,
            Phase::RegisterBlkChannel,
            Phase::Ready,
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

    #[test]
    fn step_kind_enter_blk_loop_only_at_ready() {
        for phase in [
            Phase::PciEnumeration,
            Phase::MmioMap,
            Phase::ReadCap,
            Phase::DisableController,
            Phase::SetupAdminQueues,
            Phase::EnableController,
            Phase::AttachInterrupts,
            Phase::IdentifyController,
            Phase::IdentifyActiveNsList,
            Phase::IdentifyNamespace,
            Phase::CreateIoQueues,
            Phase::RegisterBlkChannel,
            Phase::Failed,
        ] {
            let s = BringUp { phase, retries: 0 };
            assert_ne!(s.pending_step(), StepKind::EnterBlkLoop);
        }
        let ready = BringUp {
            phase: Phase::Ready,
            retries: 0,
        };
        assert_eq!(ready.pending_step(), StepKind::EnterBlkLoop);
    }

    #[test]
    fn max_retries_is_three() {
        // Pin the constant — driver bring-up latency budget anchor;
        // matches the virtio-net driver to keep both FSMs in sync.
        assert_eq!(MAX_RETRIES, 3);
    }

    #[test]
    fn full_happy_path_reaches_ready() {
        let mut s = BringUp::new();
        for _ in 0..12 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::Ready);
        assert!(s.phase().is_live());
    }

    #[test]
    fn retry_then_advance_reaches_ready_when_under_budget() {
        let mut s = BringUp::new();
        // PciEnumeration retried twice (e.g. ECAM scan slow), then
        // advance through the rest.
        let _ = s.on_event(Event::Retry).unwrap();
        let _ = s.on_event(Event::Retry).unwrap();
        for _ in 0..12 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::Ready);
    }
}

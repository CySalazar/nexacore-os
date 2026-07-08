//! Bring-up state machine — 13-step transition table.
//!
//! [`NCIP-Driver-Net-015`] § S5.1 prescribes an 11-step hardware bring-up
//! sequence; § S8 layers two common post-bring-up steps on top (register
//! the NET service channel + emit the `[driver-net] ready ...` line),
//! yielding a 13-phase FSM. The phases below mirror the state-machine
//! view of those 13 steps:
//!
//! 1.  [`Phase::PciEnumeration`] — walk ECAM via
//!     [`NCIP-Driver-Framework-013`] § S1 `PciConfigRead` to locate the
//!     e1000e controller matching the manifest's `pci_vendor_device`
//!     table (§ S5.1 step 1 prerequisite).
//! 2.  [`Phase::MmioMap`] — `MmioMap(BAR0, 128 KiB)` to obtain the CSR
//!     register window (§ S5.1 step 1).
//! 3.  [`Phase::DisableInterrupts`] — write `0xFFFFFFFF` to `IMC`
//!     (§ S5.1 step 2).
//! 4.  [`Phase::GlobalReset`] — set `CTRL.RST`, wait 1 ms, poll back to 0
//!     (§ S5.1 step 3).
//! 5.  [`Phase::ReadMac`] — read `RAL[0]` / `RAH[0]`, verify
//!     `RAH[0].AV` (§ S5.1 step 4).
//! 6.  [`Phase::PhyInit`] — MDIO-issue `MII_CTRL` read, trigger
//!     auto-negotiation if needed (§ S5.1 step 5).
//! 7.  [`Phase::SetupRxRing`] — `DmaMap` RX descriptor ring, write
//!     `RDBAL` / `RDBAH` / `RDLEN`, init `RDH` / `RDT` (§ S5.1 step 6).
//! 8.  [`Phase::PostRxBuffers`] — pre-post `rx_buffer_count` 2 KiB
//!     buffers, advance `RDT` (§ S5.1 step 7).
//! 9.  [`Phase::SetupTxRing`] — `DmaMap` TX descriptor ring, write
//!     `TDBAL` / `TDBAH` / `TDLEN` (§ S5.1 step 8).
//! 10. [`Phase::ConfigureRxTx`] — write `RCTL` + `TCTL` (§ S5.1 step 9).
//! 11. [`Phase::EnableInterrupts`] — write `IMS = RXT0 | TXDW | LSC`
//!     (§ S5.1 step 10).
//! 12. [`Phase::AttachIrq`] — `IrqAttach` the single MSI-X vector
//!     (§ S5.1 step 11).
//! 13. [`Phase::RegisterNetChannel`] — `IpcCreateChannel`
//!     `nexacore.svc.net.eth<N>` + companion event channel (§ S8 steps 1-4).
//! 14. [`Phase::Ready`] — emit `[driver-net] ready eth<N> mac=<mac>
//!     link=<up|down> mtu=<mtu>` (§ S8 step 5) and enter the steady-state
//!     RX/TX loop.
//!
//! Terminal failure phase [`Phase::Failed`] is reached on any
//! unrecoverable error; the driver process exits with code `1` and the
//! kernel reclaims resources via the standard process-exit teardown.
//!
//! The actual `MmioMap` / `DmaMap` / `IrqAttach` invocations live in the
//! bootable image sibling `nexacore-driver-e1000e-image` (P6.7.8.7). This
//! crate stays library-only and host-testable.
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md
//! [`NCIP-Driver-Framework-013`]: ../../../ncips/ncip-driver-framework-013.md

/// Ordered phases of the e1000e bring-up state machine.
///
/// The driver advances strictly in `repr(u8)` order. Skipping a phase
/// is a kernel-detectable violation of `NCIP-Driver-Net-015` § S5.1; the
/// monotonicity is verified by the scaffold unit tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    /// § S5.1 prereq — PCI enumeration via `PciConfigRead`.
    PciEnumeration = 0,
    /// § S5.1 step 1 — `MmioMap(BAR0, 128 KiB)`.
    MmioMap = 1,
    /// § S5.1 step 2 — `IMC = 0xFFFFFFFF`.
    DisableInterrupts = 2,
    /// § S5.1 step 3 — `CTRL.RST = 1`, poll until cleared.
    GlobalReset = 3,
    /// § S5.1 step 4 — read MAC from `RAL[0]` / `RAH[0]`.
    ReadMac = 4,
    /// § S5.1 step 5 — MDIO `MII_CTRL` + auto-negotiation kick.
    PhyInit = 5,
    /// § S5.1 step 6 — RX descriptor ring + base/length registers.
    SetupRxRing = 6,
    /// § S5.1 step 7 — pre-post RX buffers.
    PostRxBuffers = 7,
    /// § S5.1 step 8 — TX descriptor ring + base/length registers.
    SetupTxRing = 8,
    /// § S5.1 step 9 — `RCTL` + `TCTL` configuration.
    ConfigureRxTx = 9,
    /// § S5.1 step 10 — `IMS = RXT0 | TXDW | LSC`.
    EnableInterrupts = 10,
    /// § S5.1 step 11 — `IrqAttach` MSI-X vector.
    AttachIrq = 11,
    /// § S8 steps 1-4 — register `nexacore.svc.net.eth<N>` + event channel
    /// + emit initial `MacChanged` / `LinkStateChange` events.
    RegisterNetChannel = 12,
    /// § S8 step 5 — `[driver-net] ready ...` line; enter the RX/TX
    /// steady-state loop.
    Ready = 13,
    /// Terminal failure phase — driver process exits with code `1`.
    Failed = 14,
}

impl Phase {
    /// Return the next phase, or `None` at the terminal states
    /// ([`Phase::Ready`] / [`Phase::Failed`]).
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::PciEnumeration => Some(Self::MmioMap),
            Self::MmioMap => Some(Self::DisableInterrupts),
            Self::DisableInterrupts => Some(Self::GlobalReset),
            Self::GlobalReset => Some(Self::ReadMac),
            Self::ReadMac => Some(Self::PhyInit),
            Self::PhyInit => Some(Self::SetupRxRing),
            Self::SetupRxRing => Some(Self::PostRxBuffers),
            Self::PostRxBuffers => Some(Self::SetupTxRing),
            Self::SetupTxRing => Some(Self::ConfigureRxTx),
            Self::ConfigureRxTx => Some(Self::EnableInterrupts),
            Self::EnableInterrupts => Some(Self::AttachIrq),
            Self::AttachIrq => Some(Self::RegisterNetChannel),
            Self::RegisterNetChannel => Some(Self::Ready),
            Self::Ready | Self::Failed => None,
        }
    }

    /// Returns `true` if the phase is terminal (no further transitions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ready | Self::Failed)
    }

    /// Returns `true` if the phase represents a successful steady-state
    /// (the controller is live and the NET channel is serving).
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Ready)
    }
}

// =============================================================================
// Bring-up driver — Event / Error / Transition (P6.7.8.6)
// =============================================================================

/// Bring-up event posted by the driver after each syscall step
/// completes (or fails). Pure data — the FSM is the consumer.
///
/// Mirrors the shape of `Event` in `nexacore-driver-net-virtio` (P6.7.8.3)
/// and `nexacore-driver-nvme` (P6.7.8.4): the contract is identical so a
/// future per-driver supervisor can drive every FSM through the same
/// trampoline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The step completed successfully; advance to the next phase.
    Advance,
    /// The step completed but the device reported a transient error
    /// the driver should retry (e.g. `CTRL.RST` not yet cleared, MDIC
    /// busy bit still pinned). After [`MAX_RETRIES`] consecutive
    /// transients the FSM forces a [`Phase::Failed`] transition.
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
    /// `pci_vendor_device` table. The driver cannot proceed.
    NoMatchingDevice,
    /// `MmioMap` returned an error — the kernel rejected the BAR0
    /// mapping (capability missing, wrong region, allocator OOM).
    MmioMapFailed,
    /// `CTRL.RST` did not self-clear within the polling budget
    /// (§ S5.1 step 3 mandates a 1 ms wait + poll).
    ResetTimeout,
    /// `RAH[0].AV` is clear after the global reset — the EEPROM has
    /// not loaded the MAC; the driver cannot proceed without an
    /// EEPROM-backed MAC (synthesising a locally-administered MAC is
    /// disallowed by NCIP-015 § S2.3).
    InvalidMac,
    /// PHY auto-negotiation failed to converge within the polling
    /// budget. The driver still surfaces the channel but with
    /// `link=down`; the FSM treats this as a hard error in v0.3.
    PhyInitFailed,
    /// `DmaMap` returned an error — the kernel could not install the
    /// IOMMU domain (or the no-IOMMU passthrough allocation failed).
    DmaMapFailed,
    /// `IrqAttach` returned an error — the kernel could not allocate a
    /// LAPIC vector or the IRQ line was already in use (shared-line
    /// rejection per NCIP-013 § S4.1).
    IrqAttachFailed,
    /// `IpcCreateChannel` failed at step 12. Without a NET channel
    /// the driver has no way to surface network access to clients.
    NetChannelRegistrationFailed,
    /// Manifest ring depth or RX buffer count fall outside the bounds
    /// in [`crate::ring_config`]. Distinct from `EINVAL` at the
    /// `DriverLoad` syscall: the driver does its own defence-in-depth
    /// check before issuing any controller writes.
    InvalidRingDepth,
    /// The retry counter hit [`MAX_RETRIES`] without advancing.
    RetryBudgetExhausted,
    /// The driver attempted to advance from a terminal phase. Always
    /// a driver bug — the FSM stays parked.
    TerminalAdvanceAttempted,
}

/// Maximum retry budget for a single phase.
///
/// e1000e controllers on QEMU/Proxmox typically converge on the first
/// attempt; we cap at 3 to bound bring-up latency. Same precedent as
/// `nexacore-driver-net-virtio::MAX_RETRIES` (P6.7.8.3) and
/// `nexacore-driver-nvme::MAX_RETRIES` (P6.7.8.4).
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
            Phase::DisableInterrupts => StepKind::WriteImcMaskAll,
            Phase::GlobalReset => StepKind::TriggerCtrlReset,
            Phase::ReadMac => StepKind::ReadReceiveAddress,
            Phase::PhyInit => StepKind::IssueMdioAutonegotiate,
            Phase::SetupRxRing => StepKind::AllocateRxRing,
            Phase::PostRxBuffers => StepKind::PrepostRxBuffers,
            Phase::SetupTxRing => StepKind::AllocateTxRing,
            Phase::ConfigureRxTx => StepKind::WriteRctlTctl,
            Phase::EnableInterrupts => StepKind::WriteImsEnabled,
            Phase::AttachIrq => StepKind::AttachMsiXVector,
            Phase::RegisterNetChannel => StepKind::RegisterNetChannel,
            Phase::Ready => StepKind::EnterRxTxLoop,
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
    /// `PciConfigRead` walks of the ECAM space (§ S5.1 prereq).
    EnumeratePci,
    /// `MmioMap(BAR0, 128 KiB)` (§ S5.1 step 1).
    MapControllerRegisters,
    /// MMIO write `IMC = 0xFFFFFFFF` (§ S5.1 step 2).
    WriteImcMaskAll,
    /// MMIO write `CTRL.RST = 1`, poll back to 0 (§ S5.1 step 3).
    TriggerCtrlReset,
    /// MMIO read `RAL[0]` / `RAH[0]`, verify `AV` (§ S5.1 step 4).
    ReadReceiveAddress,
    /// MDIO transaction to `MII_CTRL` + auto-negotiation kick
    /// (§ S5.1 step 5).
    IssueMdioAutonegotiate,
    /// `DmaMap` RX descriptor ring + MMIO writes to
    /// `RDBAL`/`RDBAH`/`RDLEN` (§ S5.1 step 6).
    AllocateRxRing,
    /// Pre-post `rx_buffer_count` × 2 KiB buffers, advance `RDT`
    /// (§ S5.1 step 7).
    PrepostRxBuffers,
    /// `DmaMap` TX descriptor ring + MMIO writes to
    /// `TDBAL`/`TDBAH`/`TDLEN` (§ S5.1 step 8).
    AllocateTxRing,
    /// MMIO writes to `RCTL` (enable, broadcast accept, strip CRC) +
    /// `TCTL` (enable, pad, CT/COLD defaults) (§ S5.1 step 9).
    WriteRctlTctl,
    /// MMIO write `IMS = RXT0 | TXDW | LSC` (§ S5.1 step 10).
    WriteImsEnabled,
    /// `IrqAttach` the single MSI-X vector (§ S5.1 step 11).
    AttachMsiXVector,
    /// `IpcCreateChannel` `nexacore.svc.net.eth<N>` + companion event
    /// channel; emit initial `MacChanged` / `LinkStateChange`
    /// (§ S8 steps 1-4).
    RegisterNetChannel,
    /// Steady-state RX/TX loop (§ S8 step 5).
    EnterRxTxLoop,
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
            Phase::DisableInterrupts,
            Phase::GlobalReset,
            Phase::ReadMac,
            Phase::PhyInit,
            Phase::SetupRxRing,
            Phase::PostRxBuffers,
            Phase::SetupTxRing,
            Phase::ConfigureRxTx,
            Phase::EnableInterrupts,
            Phase::AttachIrq,
            Phase::RegisterNetChannel,
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
        assert_eq!(Phase::DisableInterrupts as u8, 2);
        assert_eq!(Phase::GlobalReset as u8, 3);
        assert_eq!(Phase::ReadMac as u8, 4);
        assert_eq!(Phase::PhyInit as u8, 5);
        assert_eq!(Phase::SetupRxRing as u8, 6);
        assert_eq!(Phase::PostRxBuffers as u8, 7);
        assert_eq!(Phase::SetupTxRing as u8, 8);
        assert_eq!(Phase::ConfigureRxTx as u8, 9);
        assert_eq!(Phase::EnableInterrupts as u8, 10);
        assert_eq!(Phase::AttachIrq as u8, 11);
        assert_eq!(Phase::RegisterNetChannel as u8, 12);
        assert_eq!(Phase::Ready as u8, 13);
        assert_eq!(Phase::Failed as u8, 14);
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
            Phase::DisableInterrupts,
            Phase::GlobalReset,
            Phase::ReadMac,
            Phase::PhyInit,
            Phase::SetupRxRing,
            Phase::PostRxBuffers,
            Phase::SetupTxRing,
            Phase::ConfigureRxTx,
            Phase::EnableInterrupts,
            Phase::AttachIrq,
            Phase::RegisterNetChannel,
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
        for _ in 0..13 {
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
            .on_event(Event::Abort(BringUpError::ResetTimeout))
            .unwrap_err();
        assert_eq!(err, BringUpError::ResetTimeout);
        assert_eq!(s.phase(), Phase::Failed);
    }

    #[test]
    fn abort_distinguishes_every_error_variant() {
        for err in [
            BringUpError::NoMatchingDevice,
            BringUpError::MmioMapFailed,
            BringUpError::ResetTimeout,
            BringUpError::InvalidMac,
            BringUpError::PhyInitFailed,
            BringUpError::DmaMapFailed,
            BringUpError::IrqAttachFailed,
            BringUpError::NetChannelRegistrationFailed,
            BringUpError::InvalidRingDepth,
        ] {
            let mut s = BringUp::new();
            let got = s.on_event(Event::Abort(err)).unwrap_err();
            assert_eq!(got, err);
            assert_eq!(s.phase(), Phase::Failed);
        }
    }

    #[test]
    fn pending_step_matches_phase_pci_enumeration() {
        let s = BringUp::new();
        assert_eq!(s.pending_step(), StepKind::EnumeratePci);
    }

    #[test]
    fn pending_step_matches_phase_mmio_map() {
        let mut s = BringUp::new();
        s = s.on_event(Event::Advance).unwrap();
        assert_eq!(s.pending_step(), StepKind::MapControllerRegisters);
    }

    #[test]
    fn pending_step_covers_every_phase() {
        for phase in [
            Phase::PciEnumeration,
            Phase::MmioMap,
            Phase::DisableInterrupts,
            Phase::GlobalReset,
            Phase::ReadMac,
            Phase::PhyInit,
            Phase::SetupRxRing,
            Phase::PostRxBuffers,
            Phase::SetupTxRing,
            Phase::ConfigureRxTx,
            Phase::EnableInterrupts,
            Phase::AttachIrq,
            Phase::RegisterNetChannel,
            Phase::Ready,
            Phase::Failed,
        ] {
            let s = BringUp { phase, retries: 0 };
            // Smoke: every variant must produce a deterministic step.
            let _ = s.pending_step();
        }
    }

    #[test]
    fn max_retries_is_three() {
        assert_eq!(MAX_RETRIES, 3);
    }

    #[test]
    fn full_happy_path_reaches_ready() {
        let mut s = BringUp::new();
        for _ in 0..13 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::Ready);
        assert!(s.phase().is_live());
    }

    #[test]
    fn retry_then_advance_reaches_ready_when_under_budget() {
        let mut s = BringUp::new();
        // PciEnumeration phase retried twice, then advance through the
        // rest.
        let _ = s.on_event(Event::Retry).unwrap();
        let _ = s.on_event(Event::Retry).unwrap();
        for _ in 0..13 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::Ready);
    }

    #[test]
    fn step_kind_park_exit_only_from_failed() {
        for phase in [
            Phase::PciEnumeration,
            Phase::MmioMap,
            Phase::DisableInterrupts,
            Phase::GlobalReset,
            Phase::ReadMac,
            Phase::PhyInit,
            Phase::SetupRxRing,
            Phase::PostRxBuffers,
            Phase::SetupTxRing,
            Phase::ConfigureRxTx,
            Phase::EnableInterrupts,
            Phase::AttachIrq,
            Phase::RegisterNetChannel,
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

    // ---- Live transition tests (P6.7.9.c) -----------------------------------

    #[test]
    fn live_mmio_phase_advances_from_disable_interrupts_to_global_reset() {
        let mut s = BringUp::new();
        // Advance to DisableInterrupts (phase 2)
        s = s.on_event(Event::Advance).unwrap(); // → MmioMap
        s = s.on_event(Event::Advance).unwrap(); // → DisableInterrupts
        assert_eq!(s.phase(), Phase::DisableInterrupts);
        assert_eq!(s.pending_step(), StepKind::WriteImcMaskAll);
        // After MMIO write completes, advance to GlobalReset
        s = s.on_event(Event::Advance).unwrap();
        assert_eq!(s.phase(), Phase::GlobalReset);
        assert_eq!(s.pending_step(), StepKind::TriggerCtrlReset);
    }

    #[test]
    fn live_read_mac_phase_returns_correct_step_kind() {
        let mut s = BringUp::new();
        for _ in 0..4 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::ReadMac);
        assert_eq!(s.pending_step(), StepKind::ReadReceiveAddress);
    }

    #[test]
    fn live_phy_init_retry_then_advance_preserves_phase_order() {
        let mut s = BringUp::new();
        // Advance to PhyInit
        for _ in 0..5 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::PhyInit);
        // Simulate a transient MDIC busy — retry once
        s = s.on_event(Event::Retry).unwrap();
        assert_eq!(s.phase(), Phase::PhyInit);
        assert_eq!(s.retries(), 1);
        // Then advance on success
        s = s.on_event(Event::Advance).unwrap();
        assert_eq!(s.phase(), Phase::SetupRxRing);
        assert_eq!(s.retries(), 0);
    }

    #[test]
    fn live_setup_rings_sequence_is_rx_then_post_then_tx() {
        let mut s = BringUp::new();
        for _ in 0..6 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::SetupRxRing);
        assert_eq!(s.pending_step(), StepKind::AllocateRxRing);
        s = s.on_event(Event::Advance).unwrap();
        assert_eq!(s.phase(), Phase::PostRxBuffers);
        assert_eq!(s.pending_step(), StepKind::PrepostRxBuffers);
        s = s.on_event(Event::Advance).unwrap();
        assert_eq!(s.phase(), Phase::SetupTxRing);
        assert_eq!(s.pending_step(), StepKind::AllocateTxRing);
    }

    #[test]
    fn live_configure_then_enable_interrupts_then_attach_irq() {
        let mut s = BringUp::new();
        for _ in 0..9 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::ConfigureRxTx);
        assert_eq!(s.pending_step(), StepKind::WriteRctlTctl);
        s = s.on_event(Event::Advance).unwrap();
        assert_eq!(s.phase(), Phase::EnableInterrupts);
        assert_eq!(s.pending_step(), StepKind::WriteImsEnabled);
        s = s.on_event(Event::Advance).unwrap();
        assert_eq!(s.phase(), Phase::AttachIrq);
        assert_eq!(s.pending_step(), StepKind::AttachMsiXVector);
    }

    #[test]
    fn live_abort_at_global_reset_reports_reset_timeout() {
        let mut s = BringUp::new();
        // Advance to GlobalReset
        for _ in 0..3 {
            s = s.on_event(Event::Advance).unwrap();
        }
        assert_eq!(s.phase(), Phase::GlobalReset);
        // Simulate hardware never clearing CTRL.RST
        let err = s
            .on_event(Event::Abort(BringUpError::ResetTimeout))
            .unwrap_err();
        assert_eq!(err, BringUpError::ResetTimeout);
        assert_eq!(s.phase(), Phase::Failed);
        assert_eq!(s.pending_step(), StepKind::ParkExit);
    }
}

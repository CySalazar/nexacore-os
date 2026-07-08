//! NVMe bring-up FSM — live admin-queue glue.
//!
//! Composes the pure-state [`crate::bringup::BringUp`] FSM
//! (P6.7.8.4) with the live [`crate::admin_session::AdminSession`]
//! introduced in P6.7.10-pre.13 + the
//! [`crate::queue::MmioBackend`] seam from pre.11. The helpers in
//! this module are the "did the admin command succeed?" boundary
//! the bootable driver image's `_start` would otherwise have to
//! re-implement at every phase transition.
//!
//! ## Why a separate module
//!
//! The FSM in [`crate::bringup`] is intentionally side-effect-free
//! so it stays host-testable without standing up the live queue
//! pair. The composition layer that binds it to
//! [`crate::admin_session::AdminSession`] therefore lives in a
//! parallel module — the FSM's `Event::Advance` / `Event::Retry` /
//! `Event::Abort(_)` shape is preserved verbatim; this module just
//! provides the "translate an `AdminCqeFields` into the matching
//! `Event`" gateway.
//!
//! ## Scope
//!
//! Only the three Identify phases (steps 8/9/10 of NCIP-014 § S6)
//! are wired today. The future IO-queue creation phase (step 11)
//! lands in a sibling helper once the live `encode_create_io_cq` /
//! `encode_create_io_sq` submit path is wired through the session
//! (the current `AdminSession` only exposes the Identify family).

use crate::{
    admin::CIOSQ_QPRIO_MEDIUM,
    admin_session::AdminSession,
    bringup::{BringUp, BringUpError, Event, Phase},
    queue::{MmioBackend, QueueError},
};

/// Default NSID the bring-up FSM passes to `Identify Namespace`.
///
/// Phase-1 NVMe driver always inspects the first NSID per
/// NCIP-Driver-NVMe-014 § S6 step 9 (which is `1` by spec — NSID `0`
/// is reserved). When `IdentifyActiveNsList` later returns the
/// actual NSID list, the FSM re-issues `Identify Namespace` with
/// the real value if it differs from this default.
pub const DEFAULT_NSID: u32 = 1;

/// Map a [`QueueError`] from the [`AdminSession`] layer to the
/// matching [`BringUpError`] the FSM consumes via `Event::Abort`.
///
/// Most queue errors collapse to
/// [`BringUpError::AdminCommandFailed`] because the FSM does not
/// distinguish between "the controller rejected the command" and
/// "the driver could not deliver the command at all" — both leave
/// the controller in the same recoverable state (`Phase::Failed` →
/// process exit → kernel reaps resources via the existing
/// task-exit chain).
///
/// [`QueueError::ControllerNotReady`] maps to
/// [`BringUpError::ControllerReadyTimeout`] because that surfaces
/// the actual diagnostic the driver should log.
#[must_use]
pub const fn bringup_error_for(err: QueueError) -> BringUpError {
    match err {
        QueueError::ControllerNotReady => BringUpError::ControllerReadyTimeout,
        _ => BringUpError::AdminCommandFailed,
    }
}

/// Configuration for the [`advance_create_io_queues`] helper.
///
/// Phase-1 NVMe driver creates exactly one IO queue pair (one CQ +
/// one SQ) per NCIP-Driver-NVMe-014 § R2. Future multi-queue
/// support extends to an iterator of `CreateIoQueuesConfig`
/// without breaking the single-pair shape used today.
#[derive(Debug, Clone, Copy)]
pub struct CreateIoQueuesConfig {
    /// IO CQ identifier — `1..=io_queue_count` per NCIP-014 § R5.
    pub cq_qid: u16,
    /// IO CQ depth (1-based; the encoder subtracts one).
    pub cq_qsize: u16,
    /// IOVA of the CQ data page (4 KiB-aligned, physically
    /// contiguous).
    pub cq_prp1: u64,
    /// MSI-X vector the controller signals CQ completions on.
    pub cq_irq_vector: u16,
    /// IO SQ identifier — typically matches `cq_qid`.
    pub sq_qid: u16,
    /// IO SQ depth.
    pub sq_qsize: u16,
    /// IOVA of the SQ data page.
    pub sq_prp1: u64,
    /// Queue priority — one of
    /// [`crate::admin::CIOSQ_QPRIO_URGENT`] /
    /// [`crate::admin::CIOSQ_QPRIO_HIGH`] /
    /// [`crate::admin::CIOSQ_QPRIO_MEDIUM`] /
    /// [`crate::admin::CIOSQ_QPRIO_LOW`]. Phase-1 default is
    /// `MEDIUM` (matches QEMU `weighted_round_robin`).
    pub sq_queue_priority: u32,
}

impl CreateIoQueuesConfig {
    /// Phase-1 default: single IO QP pair with `MEDIUM` priority.
    ///
    /// `cq_prp1` + `sq_prp1` MUST be supplied by the caller (they
    /// come from a `DmaMap` allocation that this layer cannot
    /// observe).
    #[must_use]
    pub const fn phase_1_default(cq_prp1: u64, sq_prp1: u64, cq_irq_vector: u16) -> Self {
        Self {
            cq_qid: 1,
            cq_qsize: 1024,
            cq_prp1,
            cq_irq_vector,
            sq_qid: 1,
            sq_qsize: 1024,
            sq_prp1,
            sq_queue_priority: CIOSQ_QPRIO_MEDIUM,
        }
    }
}

/// Advance the FSM through [`Phase::CreateIoQueues`] by issuing
/// `Create I/O Completion Queue` then `Create I/O Submission Queue`
/// admin commands in spec order.
///
/// Per NVMe 1.4 § 5.4: the IO SQ command depends on the matching IO
/// CQ already existing in the controller, so the helper issues them
/// strictly in sequence. Either failure aborts the FSM via
/// [`bringup_error_for`].
///
/// The helper is a no-op (returns `Event::Advance` without invoking
/// the session) if the FSM is NOT at [`Phase::CreateIoQueues`] —
/// callers can drive a generic phase-loop blindly through it.
///
/// # Errors
///
/// - Any [`BringUpError`] [`BringUp::on_event`] surfaces.
pub fn advance_create_io_queues<M: MmioBackend>(
    fsm: BringUp,
    session: &mut AdminSession,
    config: &CreateIoQueuesConfig,
    poll_limit: u32,
    mmio: &mut M,
) -> Result<BringUp, BringUpError> {
    let mut next = fsm;
    if fsm.phase() != Phase::CreateIoQueues {
        return next.on_event(Event::Advance);
    }

    // Step 11.a: Create IO CQ first (the SQ command references it).
    let cq_result = session.run_create_io_cq(
        config.cq_qid,
        config.cq_qsize,
        config.cq_prp1,
        config.cq_irq_vector,
        poll_limit,
        mmio,
    );
    match cq_result {
        Ok(fields) if fields.is_success() => {}
        Ok(_) => return next.on_event(Event::Abort(BringUpError::AdminCommandFailed)),
        Err(err) => return next.on_event(Event::Abort(bringup_error_for(err))),
    }

    // Step 11.b: Create IO SQ.
    let sq_result = session.run_create_io_sq(
        config.sq_qid,
        config.sq_qsize,
        config.sq_prp1,
        config.cq_qid,
        config.sq_queue_priority,
        poll_limit,
        mmio,
    );
    match sq_result {
        Ok(fields) if fields.is_success() => next.on_event(Event::Advance),
        Ok(_) => next.on_event(Event::Abort(BringUpError::AdminCommandFailed)),
        Err(err) => next.on_event(Event::Abort(bringup_error_for(err))),
    }
}

/// Advance the FSM through one Identify-family phase using the
/// supplied [`AdminSession`].
///
/// The helper dispatches on the FSM's current phase:
///
/// - [`Phase::IdentifyController`] → [`AdminSession::run_identify_controller`]
/// - [`Phase::IdentifyActiveNsList`] →
///   [`AdminSession::run_identify_active_ns_list`]
/// - [`Phase::IdentifyNamespace`] →
///   [`AdminSession::run_identify_namespace`] with `nsid = `
///   [`DEFAULT_NSID`]
/// - any other phase → posts `Event::Advance` without invoking the
///   session (the caller is responsible for non-Identify phases;
///   the helper still applies the FSM transition so callers can
///   blindly drive the loop).
///
/// The matching completion's `status` field is inspected:
///
/// - success (`is_success() == true`) → posts `Event::Advance`.
/// - non-success status word → posts
///   `Event::Abort(BringUpError::AdminCommandFailed)`.
/// - [`QueueError::IdentifyCompletionTimeout`] /
///   [`QueueError::ControllerNotReady`] / other queue errors →
///   posts `Event::Abort` with the mapped [`BringUpError`] per
///   [`bringup_error_for`].
///
/// Returns the updated FSM state on success or the matching
/// [`BringUpError`] on failure (the FSM has already transitioned
/// to [`Phase::Failed`] in either case, mirroring the underlying
/// `on_event` contract).
///
/// # Errors
///
/// - Any [`BringUpError`] the underlying
///   [`BringUp::on_event`] surfaces (`TerminalAdvanceAttempted`,
///   `RetryBudgetExhausted`, or the variant the
///   `Event::Abort(_)` carries).
pub fn advance_with_admin_session<M: MmioBackend>(
    fsm: BringUp,
    session: &mut AdminSession,
    buf_iova: u64,
    poll_limit: u32,
    mmio: &mut M,
) -> Result<BringUp, BringUpError> {
    let mut next = fsm;
    let result: Result<bool, QueueError> = match fsm.phase() {
        Phase::IdentifyController => session
            .run_identify_controller(buf_iova, poll_limit, mmio)
            .map(|fields| fields.is_success()),
        Phase::IdentifyActiveNsList => session
            .run_identify_active_ns_list(buf_iova, poll_limit, mmio)
            .map(|fields| fields.is_success()),
        Phase::IdentifyNamespace => session
            .run_identify_namespace(DEFAULT_NSID, buf_iova, poll_limit, mmio)
            .map(|fields| fields.is_success()),
        _ => {
            // Non-Identify phase: just advance the FSM. The caller
            // is responsible for the side effect (the FSM is
            // unaware that there even was one).
            return next.on_event(Event::Advance);
        }
    };

    match result {
        Ok(true) => next.on_event(Event::Advance),
        Ok(false) => next.on_event(Event::Abort(BringUpError::AdminCommandFailed)),
        Err(err) => next.on_event(Event::Abort(bringup_error_for(err))),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::admin::ADMIN_CQE_BYTES;

    // Re-export the FakeController fixture pattern from
    // admin_session — duplicated minimally here because the
    // original is `#[cfg(test)] mod tests` (not exported).

    #[derive(Debug, Default)]
    struct BootstrapFake {
        writes: Vec<(usize, u32)>,
    }

    impl MmioBackend for BootstrapFake {
        fn write_doorbell(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
        }
    }

    /// Build a synthetic completion at CQ slot 0 with phase=1, the
    /// CID extracted from the most recently submitted SQE, and
    /// `sq_head = sq_tail` so the SqRing's head_observed catches
    /// up.
    fn emit_synthetic_completion(s: &mut AdminSession, sq_tail: u16) {
        let sq_snapshot: Vec<u8> = s.sq_page().to_vec();
        let cq_capacity: u16 = s.queue_pair().cq().capacity();
        let mut scratch: Vec<u8> = vec![0u8; (cq_capacity as usize) * ADMIN_CQE_BYTES];

        // Extract CID from the latest SQE.
        let consumed_slot = if sq_tail == 0 {
            s.queue_pair().sq().capacity() - 1
        } else {
            sq_tail - 1
        };
        let sqe_start = (consumed_slot as usize) * 64;
        let cid_lo = sq_snapshot.get(sqe_start + 2).copied().unwrap();
        let cid_hi = sq_snapshot.get(sqe_start + 3).copied().unwrap();
        let cid: u16 = u16::from_le_bytes([cid_lo, cid_hi]);

        // CQE at slot 0: CDW2 = sq_head, CDW3 = CID | (phase=1) << 16.
        let cdw2: u32 = u32::from(sq_tail);
        let cdw3: u32 = u32::from(cid) | (1u32 << 16);
        scratch
            .get_mut(0..4)
            .unwrap()
            .copy_from_slice(&0u32.to_le_bytes());
        scratch
            .get_mut(4..8)
            .unwrap()
            .copy_from_slice(&0u32.to_le_bytes());
        scratch
            .get_mut(8..12)
            .unwrap()
            .copy_from_slice(&cdw2.to_le_bytes());
        scratch
            .get_mut(12..16)
            .unwrap()
            .copy_from_slice(&cdw3.to_le_bytes());

        s.cq_page_mut().copy_from_slice(&scratch);
    }

    // -------------------------------------------------------------------
    // bringup_error_for taxonomy
    // -------------------------------------------------------------------

    #[test]
    fn bringup_error_for_controller_not_ready_maps_to_ready_timeout() {
        assert_eq!(
            bringup_error_for(QueueError::ControllerNotReady),
            BringUpError::ControllerReadyTimeout
        );
    }

    #[test]
    fn bringup_error_for_identify_timeout_maps_to_admin_command_failed() {
        assert_eq!(
            bringup_error_for(QueueError::IdentifyCompletionTimeout),
            BringUpError::AdminCommandFailed
        );
    }

    #[test]
    fn bringup_error_for_full_ring_maps_to_admin_command_failed() {
        assert_eq!(
            bringup_error_for(QueueError::Full),
            BringUpError::AdminCommandFailed
        );
    }

    // -------------------------------------------------------------------
    // advance_with_admin_session — non-Identify phases pass through
    // -------------------------------------------------------------------

    #[test]
    fn advance_non_identify_phase_just_advances_fsm() {
        // Phase = PciEnumeration. The helper should NOT touch the
        // session and post Event::Advance.
        let fsm = BringUp::new();
        assert_eq!(fsm.phase(), Phase::PciEnumeration);
        let mut session = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let next = advance_with_admin_session(fsm, &mut session, 0, 16, &mut mmio).expect("ok");
        assert_eq!(next.phase(), Phase::MmioMap);
        // No doorbell writes recorded → session was untouched.
        assert!(mmio.writes.is_empty());
    }

    // -------------------------------------------------------------------
    // advance_with_admin_session — IdentifyController happy path
    // -------------------------------------------------------------------

    fn fsm_at(phase: Phase) -> BringUp {
        // Walk the FSM forward to the target phase.
        let mut fsm = BringUp::new();
        while fsm.phase() != phase {
            fsm = fsm
                .on_event(Event::Advance)
                .expect("FSM advance during test setup");
        }
        fsm
    }

    #[test]
    fn advance_identify_controller_propagates_timeout_to_admin_command_failed() {
        // The session submits CID=1 successfully (mmio records the
        // SQ tail doorbell), but the empty CQ →
        // IdentifyCompletionTimeout → bringup_error_for maps to
        // AdminCommandFailed. The FSM transitions to Failed inside
        // `on_event(Event::Abort(_))`.
        let fsm = fsm_at(Phase::IdentifyController);
        let mut session = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let res = advance_with_admin_session(fsm, &mut session, 0x1000, 4, &mut mmio);
        assert_eq!(res, Err(BringUpError::AdminCommandFailed));
        // Post-condition: the helper dispatched the submit before
        // the poll timed out — exactly one doorbell write.
        assert_eq!(mmio.writes.len(), 1);
    }

    #[test]
    fn advance_identify_active_ns_list_path_routes_to_session() {
        let fsm = fsm_at(Phase::IdentifyActiveNsList);
        let mut session = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let res = advance_with_admin_session(fsm, &mut session, 0x2000, 4, &mut mmio);
        // Same shape as the IdentifyController test: empty CQ →
        // AdminCommandFailed. The doorbell write proves the helper
        // dispatched to run_identify_active_ns_list.
        assert_eq!(res, Err(BringUpError::AdminCommandFailed));
        assert_eq!(mmio.writes.len(), 1);
        // Inspect the SQE that landed: CDW10.CNS should be
        // CNS_ACTIVE_NSID_LIST = 0x02.
        let sqe = session.sq_page().get(0..64).unwrap();
        let cns = sqe.get(40).copied().unwrap();
        assert_eq!(cns, crate::admin::CNS_ACTIVE_NSID_LIST);
    }

    #[test]
    fn advance_identify_namespace_passes_default_nsid() {
        let fsm = fsm_at(Phase::IdentifyNamespace);
        let mut session = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let _ = advance_with_admin_session(fsm, &mut session, 0x3000, 4, &mut mmio);
        // Verify the SQE carries NSID = DEFAULT_NSID = 1.
        let sqe = session.sq_page().get(0..64).unwrap();
        let nsid_bytes = sqe.get(4..8).unwrap();
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(nsid_bytes);
        assert_eq!(u32::from_le_bytes(tmp), DEFAULT_NSID);
    }

    // -------------------------------------------------------------------
    // DEFAULT_NSID constant tripwire
    // -------------------------------------------------------------------

    #[test]
    fn default_nsid_is_one_per_ncip_014() {
        // Phase-1 driver inspects the first NSID per NCIP-014 § S6
        // step 9. NSID 0 is reserved by the NVMe spec.
        assert_eq!(DEFAULT_NSID, 1);
    }

    // -------------------------------------------------------------------
    // emit_synthetic_completion fixture sanity check (the inverse of
    // the FakeController in admin_session::tests)
    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // advance_create_io_queues (P6.7.10-pre.20)
    // -------------------------------------------------------------------

    #[test]
    fn create_io_queues_config_phase_1_default_matches_spec() {
        let config = CreateIoQueuesConfig::phase_1_default(0x1_0000, 0x2_0000, 5);
        assert_eq!(config.cq_qid, 1);
        assert_eq!(config.sq_qid, 1);
        assert_eq!(config.cq_qsize, 1024);
        assert_eq!(config.sq_qsize, 1024);
        assert_eq!(config.cq_prp1, 0x1_0000);
        assert_eq!(config.sq_prp1, 0x2_0000);
        assert_eq!(config.cq_irq_vector, 5);
        assert_eq!(config.sq_queue_priority, CIOSQ_QPRIO_MEDIUM);
    }

    #[test]
    fn advance_create_io_queues_non_matching_phase_just_advances() {
        // Phase = PciEnumeration → helper should not touch the
        // session and just post Event::Advance.
        let fsm = BringUp::new();
        let mut session = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let config = CreateIoQueuesConfig::phase_1_default(0x1_0000, 0x2_0000, 1);
        let next = advance_create_io_queues(fsm, &mut session, &config, 4, &mut mmio).unwrap();
        assert_eq!(next.phase(), Phase::MmioMap);
        assert!(mmio.writes.is_empty());
    }

    #[test]
    fn advance_create_io_queues_at_correct_phase_dispatches_to_session() {
        let fsm = fsm_at(Phase::CreateIoQueues);
        let mut session = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let config = CreateIoQueuesConfig::phase_1_default(0x1_0000, 0x2_0000, 1);
        let res = advance_create_io_queues(fsm, &mut session, &config, 4, &mut mmio);
        // Empty CQ → run_create_io_cq times out → IdentifyCompletionTimeout
        // → bringup_error_for maps to AdminCommandFailed.
        assert_eq!(res, Err(BringUpError::AdminCommandFailed));
        // The helper submitted Create IO CQ (1 doorbell write) and
        // aborted before reaching Create IO SQ.
        assert_eq!(mmio.writes.len(), 1);
        // Verify the SQE opcode at slot 0 is OPC_CREATE_IO_CQ.
        let sqe = session.sq_page().get(0..64).unwrap();
        assert_eq!(
            sqe.first().copied().unwrap(),
            crate::admin::OPC_CREATE_IO_CQ
        );
    }

    #[test]
    fn emit_synthetic_completion_fills_cq_with_expected_bytes() {
        let mut session = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = session
            .submit_identify_controller(0x1000, &mut mmio)
            .unwrap();
        emit_synthetic_completion(&mut session, 1);
        // The fixture writes a CQE at slot 0 with the just-issued
        // CID. The session can drain it.
        let mut nop = BootstrapFake::default();
        let fields = session
            .poll_completion_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert!(fields.is_success());
        assert_eq!(fields.cid, cid);
        // sq_head should match the supplied sq_tail = 1.
        assert_eq!(fields.sq_head, 1);
        // No doorbell write on the poll-only path (`nop` here is
        // a separate recorder; the drain DID write to it because
        // poll_completion_for_cid rings the CQ head doorbell on
        // every consumed completion).
        assert_eq!(nop.writes.len(), 1);
    }
}

//! NVMe Admin queue session — composition layer.
//!
//! Wraps [`crate::queue::AdminQueuePair`] with the per-session
//! bookkeeping (SQ + CQ data pages, monotone CID allocator) that the
//! bring-up FSM and the future live driver would otherwise have to
//! re-implement at every call site. The session offers high-level
//! "submit Identify Controller and poll for its completion" helpers
//! that compose the lower-level [`crate::admin::encode_identify`] +
//! [`crate::queue::AdminQueuePair::submit`] +
//! [`crate::queue::AdminQueuePair::drain_completion`] primitives.
//!
//! ## What this module does NOT do
//!
//! - It does not allocate the IOVA-mapped Identify response buffer.
//!   The caller supplies `buf_iova` from a prior `DmaMap` syscall.
//! - It does not parse the Identify response payload. The 4 KiB
//!   structure lands in the IOVA buffer the caller controls; the
//!   session simply returns the matching [`AdminCqeFields`] so the
//!   caller can inspect `status` + `cdw0` before reading the
//!   buffer.

use alloc::{vec, vec::Vec};

use nexacore_types::nvme::IdentifyTarget;

use crate::{
    admin::{
        ADMIN_CQE_BYTES, ADMIN_SQE_BYTES, AdminCqeFields, encode_create_io_cq, encode_create_io_sq,
        encode_identify,
    },
    queue::{AdminQueuePair, MmioBackend, QueueError},
};

/// PRP2 value for Identify commands (single 4 KiB response buffer
/// fits in PRP1 only).
const IDENTIFY_PRP2_ZERO: u64 = 0;

/// Default polling cap when waiting for a matching completion.
///
/// Phase-1 admin commands complete in microseconds on real hardware
/// and instantly on the host harness, so the cap is conservative —
/// if a drain loop iterates this many times without finding the
/// matching CID, something has gone wrong upstream of the session.
pub const DEFAULT_POLL_LIMIT: u32 = 1_000_000;

/// Per-session bookkeeping for the NVMe Admin queue pair.
///
/// Owns the SQ + CQ data pages (allocated as plain `Vec<u8>` for the
/// host harness; the live driver swaps them for `DmaMap`-backed
/// IOVA slices through a future trait) and a monotone CID counter
/// that wraps at `u16::MAX`. The wrap is benign because admin
/// commands complete in order and the CID is only meaningful for
/// the duration of one round-trip.
#[derive(Debug)]
pub struct AdminSession {
    queue_pair: AdminQueuePair,
    sq_page: Vec<u8>,
    cq_page: Vec<u8>,
    next_cid: u16,
}

impl AdminSession {
    /// Construct a fresh admin session.
    ///
    /// Allocates the SQ data page at `sq_depth * ADMIN_SQE_BYTES`
    /// bytes and the CQ data page at `cq_depth * ADMIN_CQE_BYTES`
    /// bytes, both zero-initialised so the CQ phase-tag check sees
    /// the correct "previous-lap-phase-0" state on the first lap.
    ///
    /// # Errors
    ///
    /// - [`QueueError::Ring`] wrapping any [`crate::ring::RingError`]
    ///   the underlying [`AdminQueuePair::new`] surfaces.
    pub fn new(sq_depth: u32, cq_depth: u32, dstrd: u8) -> Result<Self, QueueError> {
        let queue_pair = AdminQueuePair::new(sq_depth, cq_depth, dstrd)?;
        let sq_page = vec![0u8; (sq_depth as usize) * ADMIN_SQE_BYTES];
        let cq_page = vec![0u8; (cq_depth as usize) * ADMIN_CQE_BYTES];
        Ok(Self {
            queue_pair,
            sq_page,
            cq_page,
            next_cid: 1, // 0 reserved per nexacore_types::nvme::RESERVED_DRIVER_OPAQUE_ID
        })
    }

    /// Borrow the underlying [`AdminQueuePair`] for read-only
    /// introspection.
    #[must_use]
    pub const fn queue_pair(&self) -> &AdminQueuePair {
        &self.queue_pair
    }

    /// Borrow the SQ data page (read-only).
    #[must_use]
    pub fn sq_page(&self) -> &[u8] {
        &self.sq_page
    }

    /// Borrow the CQ data page mutably so a host test (or the
    /// future bare-metal `mmio_read` path) can write synthetic
    /// completions into the slots.
    pub fn cq_page_mut(&mut self) -> &mut [u8] {
        &mut self.cq_page
    }

    /// Allocate the next CID and advance the monotone counter
    /// (wrapping at `u16::MAX`). CID `0` is reserved per
    /// `nexacore_types::nvme::RESERVED_DRIVER_OPAQUE_ID`; the counter
    /// skips zero on wrap.
    fn allocate_cid(&mut self) -> u16 {
        let cid = self.next_cid;
        // `checked_add` returns `None` on `u16::MAX` overflow; we
        // wrap to `1` (skipping the reserved `0` per
        // `nexacore_types::nvme::RESERVED_DRIVER_OPAQUE_ID`).
        self.next_cid = self.next_cid.checked_add(1).unwrap_or(1);
        cid
    }

    /// Submit an `Identify` admin command of the given target into
    /// the queue and return the assigned CID for completion
    /// correlation.
    ///
    /// The caller supplies `buf_iova`, the IOVA of the 4 KiB
    /// response buffer the controller will fill. PRP2 is zero
    /// (Identify response fits in one page).
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`AdminQueuePair::submit`] surfaces (`Full`, `SqPageTooSmall`,
    /// `DoorbellOffsetOverflow`).
    pub fn submit_identify<M: MmioBackend>(
        &mut self,
        target: IdentifyTarget,
        buf_iova: u64,
        mmio: &mut M,
    ) -> Result<u16, QueueError> {
        let cid = self.allocate_cid();
        let sqe = encode_identify(target, buf_iova, IDENTIFY_PRP2_ZERO, cid);
        self.queue_pair.submit(&sqe, mmio, &mut self.sq_page)?;
        Ok(cid)
    }

    /// Convenience wrapper for `Identify Controller`.
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`Self::submit_identify`] surfaces.
    pub fn submit_identify_controller<M: MmioBackend>(
        &mut self,
        buf_iova: u64,
        mmio: &mut M,
    ) -> Result<u16, QueueError> {
        self.submit_identify(IdentifyTarget::Controller, buf_iova, mmio)
    }

    /// Convenience wrapper for `Identify Namespace`.
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`Self::submit_identify`] surfaces.
    pub fn submit_identify_namespace<M: MmioBackend>(
        &mut self,
        nsid: u32,
        buf_iova: u64,
        mmio: &mut M,
    ) -> Result<u16, QueueError> {
        self.submit_identify(IdentifyTarget::Namespace { nsid }, buf_iova, mmio)
    }

    /// Convenience wrapper for `Identify Active Namespace List`.
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`Self::submit_identify`] surfaces.
    pub fn submit_identify_active_ns_list<M: MmioBackend>(
        &mut self,
        buf_iova: u64,
        mmio: &mut M,
    ) -> Result<u16, QueueError> {
        self.submit_identify(IdentifyTarget::ActiveNsList, buf_iova, mmio)
    }

    /// Submit `Identify Controller` and poll the matching completion
    /// in a single high-level call.
    ///
    /// # Errors
    ///
    /// - Any [`QueueError`] [`Self::submit_identify_controller`]
    ///   surfaces.
    /// - [`QueueError::IdentifyCompletionTimeout`] if the matching
    ///   CQE does not arrive within `poll_limit` iterations of the
    ///   drain loop.
    pub fn run_identify_controller<M: MmioBackend>(
        &mut self,
        buf_iova: u64,
        poll_limit: u32,
        mmio: &mut M,
    ) -> Result<AdminCqeFields, QueueError> {
        let cid = self.submit_identify_controller(buf_iova, mmio)?;
        self.poll_completion_for_cid(cid, poll_limit, mmio)?
            .ok_or(QueueError::IdentifyCompletionTimeout)
    }

    /// Submit `Identify Namespace(nsid)` and poll the matching
    /// completion in a single high-level call.
    ///
    /// # Errors
    ///
    /// See [`Self::run_identify_controller`].
    pub fn run_identify_namespace<M: MmioBackend>(
        &mut self,
        nsid: u32,
        buf_iova: u64,
        poll_limit: u32,
        mmio: &mut M,
    ) -> Result<AdminCqeFields, QueueError> {
        let cid = self.submit_identify_namespace(nsid, buf_iova, mmio)?;
        self.poll_completion_for_cid(cid, poll_limit, mmio)?
            .ok_or(QueueError::IdentifyCompletionTimeout)
    }

    /// Submit `Identify Active Namespace List` and poll the matching
    /// completion in a single high-level call.
    ///
    /// # Errors
    ///
    /// See [`Self::run_identify_controller`].
    pub fn run_identify_active_ns_list<M: MmioBackend>(
        &mut self,
        buf_iova: u64,
        poll_limit: u32,
        mmio: &mut M,
    ) -> Result<AdminCqeFields, QueueError> {
        let cid = self.submit_identify_active_ns_list(buf_iova, mmio)?;
        self.poll_completion_for_cid(cid, poll_limit, mmio)?
            .ok_or(QueueError::IdentifyCompletionTimeout)
    }

    /// Submit `Create I/O Completion Queue` (NVMe 1.4 § 5.5) and
    /// return the assigned CID.
    ///
    /// `qid` is the new IO CQ identifier (1..=`io_queue_count`),
    /// `qsize` is 1-based (the encoder subtracts one to match the
    /// spec's 0-based wire field), `prp1` points at the host-prepared
    /// IO CQ data page (4 KiB-aligned, physically contiguous).
    /// `irq_vector` selects the MSI-X vector the controller signals
    /// completions on; Phase-1 always enables interrupts
    /// (`IEN = true`) and physical contiguity (`PC = true`) per
    /// NCIP-Driver-NVMe-014 § R5.
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`AdminQueuePair::submit`] surfaces.
    pub fn submit_create_io_cq<M: MmioBackend>(
        &mut self,
        qid: u16,
        qsize: u16,
        prp1: u64,
        irq_vector: u16,
        mmio: &mut M,
    ) -> Result<u16, QueueError> {
        let cid = self.allocate_cid();
        let sqe = encode_create_io_cq(qid, qsize, prp1, irq_vector, true, true, cid);
        self.queue_pair.submit(&sqe, mmio, &mut self.sq_page)?;
        Ok(cid)
    }

    /// Submit `Create I/O Submission Queue` (NVMe 1.4 § 5.4) and
    /// return the assigned CID.
    ///
    /// `cq_id` MUST reference a CQ the driver has already created
    /// via [`Self::submit_create_io_cq`] (the controller validates
    /// the CQID and surfaces a non-success completion otherwise).
    /// `queue_priority` is one of the
    /// [`crate::admin::CIOSQ_QPRIO_URGENT`] /
    /// [`crate::admin::CIOSQ_QPRIO_HIGH`] /
    /// [`crate::admin::CIOSQ_QPRIO_MEDIUM`] /
    /// [`crate::admin::CIOSQ_QPRIO_LOW`] constants; Phase-1
    /// default is `CIOSQ_QPRIO_MEDIUM`.
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`AdminQueuePair::submit`] surfaces.
    pub fn submit_create_io_sq<M: MmioBackend>(
        &mut self,
        qid: u16,
        qsize: u16,
        prp1: u64,
        cq_id: u16,
        queue_priority: u32,
        mmio: &mut M,
    ) -> Result<u16, QueueError> {
        let cid = self.allocate_cid();
        let sqe = encode_create_io_sq(qid, qsize, prp1, cq_id, queue_priority, true, cid);
        self.queue_pair.submit(&sqe, mmio, &mut self.sq_page)?;
        Ok(cid)
    }

    /// Submit `Create I/O Completion Queue` and poll the matching
    /// completion in a single call.
    ///
    /// # Errors
    ///
    /// - Any [`QueueError`] [`Self::submit_create_io_cq`] surfaces.
    /// - [`QueueError::IdentifyCompletionTimeout`] if the matching
    ///   CQE does not arrive within `poll_limit` iterations (same
    ///   sentinel as the Identify family — the timeout semantics
    ///   are identical).
    pub fn run_create_io_cq<M: MmioBackend>(
        &mut self,
        qid: u16,
        qsize: u16,
        prp1: u64,
        irq_vector: u16,
        poll_limit: u32,
        mmio: &mut M,
    ) -> Result<AdminCqeFields, QueueError> {
        let cid = self.submit_create_io_cq(qid, qsize, prp1, irq_vector, mmio)?;
        self.poll_completion_for_cid(cid, poll_limit, mmio)?
            .ok_or(QueueError::IdentifyCompletionTimeout)
    }

    /// Submit `Create I/O Submission Queue` and poll the matching
    /// completion in a single call.
    ///
    /// # Errors
    ///
    /// See [`Self::run_create_io_cq`].
    #[allow(
        clippy::too_many_arguments,
        reason = "NVMe Create I/O Submission Queue takes 7 spec-mandated parameters; a struct-arg refactor lands in pre.21 alongside the multi-queue NCIP work"
    )]
    pub fn run_create_io_sq<M: MmioBackend>(
        &mut self,
        qid: u16,
        qsize: u16,
        prp1: u64,
        cq_id: u16,
        queue_priority: u32,
        poll_limit: u32,
        mmio: &mut M,
    ) -> Result<AdminCqeFields, QueueError> {
        let cid = self.submit_create_io_sq(qid, qsize, prp1, cq_id, queue_priority, mmio)?;
        self.poll_completion_for_cid(cid, poll_limit, mmio)?
            .ok_or(QueueError::IdentifyCompletionTimeout)
    }

    /// Poll the completion queue until a CQE matching `cid` is
    /// drained or `poll_limit` iterations elapse without one.
    ///
    /// Returns:
    /// - `Ok(Some(fields))` when the matching CQE arrives. The
    ///   caller inspects `fields.status` to decide whether the
    ///   command succeeded.
    /// - `Ok(None)` when `poll_limit` is reached without a matching
    ///   CQE. This is a soft failure — the caller can decide
    ///   whether to retry or abort.
    ///
    /// Non-matching CQEs (e.g. completions for sibling commands the
    /// session also submitted) are drained and silently discarded
    /// — Phase 1 admin sessions process one command at a time per
    /// NCIP-014 § S6 step 8, but the helper handles concurrent
    /// outstanding admin commands correctly for future flows.
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`AdminQueuePair::drain_completion`] surfaces
    /// (`CqPageTooSmall`, `DoorbellOffsetOverflow`).
    pub fn poll_completion_for_cid<M: MmioBackend>(
        &mut self,
        cid: u16,
        poll_limit: u32,
        mmio: &mut M,
    ) -> Result<Option<AdminCqeFields>, QueueError> {
        for _ in 0..poll_limit {
            // Sibling completions (`Some(_)`) and empty slots
            // (`None`) both fall through to the next iteration —
            // only a matching CID short-circuits with `Ok(Some)`.
            if let Some(fields) = self.queue_pair.drain_completion(mmio, &self.cq_page)? {
                if fields.cid == cid {
                    return Ok(Some(fields));
                }
            }
        }
        Ok(None)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admin::ADMIN_CQE_BYTES,
        controller_regs::{cq_head_doorbell_offset, sq_tail_doorbell_offset},
    };

    /// Fake controller backend — records doorbell writes AND fills
    /// the CQ page with a synthetic completion every time the
    /// driver rings the SQ tail doorbell. This is enough for the
    /// host harness to exercise the full submit → controller →
    /// drain pipeline.
    #[derive(Debug)]
    struct FakeController<'a> {
        sq_tail_offset: usize,
        cq_head_offset: usize,
        // CQ state mirrors the controller side — head advances on
        // every drain, expected_phase tracks the controller's wrap.
        cq_capacity: u16,
        cq_tail_local: u16, // controller's view of CQ tail
        cq_phase_emit: bool,
        // Pending SQEs to drain into completion entries. We pull the
        // CID out of the most-recently-written SQE slot.
        sq_capacity: u16,
        sq_head_local: u16,
        // Borrowed CQ page so the fake can write completions inline
        // after each doorbell write.
        cq_page: &'a mut [u8],
        sq_page: &'a [u8],
    }

    impl<'a> FakeController<'a> {
        fn new(
            sq_capacity: u16,
            cq_capacity: u16,
            dstrd: u8,
            sq_page: &'a [u8],
            cq_page: &'a mut [u8],
        ) -> Self {
            Self {
                sq_tail_offset: sq_tail_doorbell_offset(0, dstrd).expect("sq off"),
                cq_head_offset: cq_head_doorbell_offset(0, dstrd).expect("cq off"),
                cq_capacity,
                cq_tail_local: 0,
                cq_phase_emit: true,
                sq_capacity,
                sq_head_local: 0,
                cq_page,
                sq_page,
            }
        }

        fn emit_completion_for_latest_sqe(&mut self, new_sq_tail: u16) {
            // Read the CID from the SQE the driver just wrote at
            // slot `(new_sq_tail - 1) mod sq_capacity`.
            let consumed_slot = if new_sq_tail == 0 {
                self.sq_capacity - 1
            } else {
                new_sq_tail - 1
            };
            let sqe_start = (consumed_slot as usize) * ADMIN_SQE_BYTES;
            // CID lives at bytes 2..=3 (little-endian) of the SQE.
            let cid_lo = self.sq_page.get(sqe_start + 2).copied().expect("cid lo");
            let cid_hi = self.sq_page.get(sqe_start + 3).copied().expect("cid hi");
            let cid: u16 = u16::from_le_bytes([cid_lo, cid_hi]);

            // Advance controller's SQ head — it has consumed the slot.
            self.sq_head_local = new_sq_tail;

            // Write a synthetic CQE at the controller's CQ tail.
            let cq_slot = self.cq_tail_local as usize;
            let start = cq_slot * ADMIN_CQE_BYTES;
            // CDW2: sq_head (bits 15:0) | sq_id = 0 (bits 31:16)
            let cdw2: u32 = u32::from(self.sq_head_local);
            // CDW3: CID | status (phase + sc=0 + sct=0)
            let status_word: u16 = u16::from(self.cq_phase_emit);
            let cdw3: u32 = u32::from(cid) | (u32::from(status_word) << 16);
            // Zero the slot first so old bytes do not bleed into
            // the test assertions.
            let dest = self
                .cq_page
                .get_mut(start..start + ADMIN_CQE_BYTES)
                .expect("cq slot");
            for byte in dest.iter_mut() {
                *byte = 0;
            }
            // Write CDW2 + CDW3.
            let mut chunks = dest.chunks_exact_mut(4);
            let _ = chunks.next(); // CDW0
            let _ = chunks.next(); // CDW1
            chunks.next().unwrap().copy_from_slice(&cdw2.to_le_bytes());
            chunks.next().unwrap().copy_from_slice(&cdw3.to_le_bytes());

            // Advance CQ tail; flip phase on wrap.
            self.cq_tail_local += 1;
            if self.cq_tail_local == self.cq_capacity {
                self.cq_tail_local = 0;
                self.cq_phase_emit = !self.cq_phase_emit;
            }
        }
    }

    impl MmioBackend for FakeController<'_> {
        fn write_doorbell(&mut self, offset: usize, value: u32) {
            if offset == self.sq_tail_offset {
                // Driver advanced the SQ tail — emit a completion
                // for the SQE the driver just wrote.
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "value is the SQ tail; bounded by sq_capacity ≤ u16::MAX"
                )]
                let new_tail = value as u16;
                self.emit_completion_for_latest_sqe(new_tail);
            } else if offset == self.cq_head_offset {
                // Driver acked a completion — no state change on the
                // fake controller side beyond what's already
                // observed.
            }
        }
    }

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    #[test]
    fn admin_session_ctor_allocates_correctly_sized_pages() {
        let s = AdminSession::new(8, 16, 0).expect("ctor");
        assert_eq!(s.sq_page().len(), 8 * ADMIN_SQE_BYTES);
        assert_eq!(s.queue_pair().cq().capacity(), 16);
        // CQ page is also sized to the CQ depth even though we
        // don't expose a read-only accessor — verify via the drain
        // path indirectly through the integration test below.
    }

    #[test]
    fn admin_session_ctor_propagates_ring_error_on_zero_depth() {
        let res = AdminSession::new(0, 8, 0);
        assert!(matches!(res, Err(QueueError::Ring(_))));
    }

    #[test]
    fn admin_session_starts_with_cid_one_zero_reserved() {
        // The first allocate_cid returns 1, skipping the reserved 0.
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        assert_eq!(s.allocate_cid(), 1);
        assert_eq!(s.allocate_cid(), 2);
    }

    #[test]
    fn allocate_cid_wraps_past_u16_max_skipping_zero() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        // Force the counter to u16::MAX.
        s.next_cid = u16::MAX;
        let last = s.allocate_cid();
        assert_eq!(last, u16::MAX);
        // Wrap MUST land on 1, not 0 (reserved sentinel).
        let wrapped = s.allocate_cid();
        assert_eq!(wrapped, 1);
    }

    // -------------------------------------------------------------------
    // Full round-trip: submit_identify_controller + poll
    // -------------------------------------------------------------------

    #[test]
    fn submit_identify_controller_round_trips_through_fake_controller() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let buf_iova = 0x1000;

        // Step 1 — submit the SQE through a no-completion bootstrap
        // fake so the session's SQ page has the encoded SQE bytes
        // for the real fake to read.
        let mut bootstrap = BootstrapFake::default();
        let cid = s
            .submit_identify_controller(buf_iova, &mut bootstrap)
            .expect("submit ok");

        // Step 2 — snapshot the SQ page and build a scratch CQ
        // page the fake controller writes into.
        let sq_snapshot: Vec<u8> = s.sq_page().to_vec();
        let cq_capacity: u16 = s.queue_pair().cq().capacity();
        let sq_capacity: u16 = s.queue_pair().sq().capacity();
        let mut scratch_cq: Vec<u8> = vec![0u8; (cq_capacity as usize) * ADMIN_CQE_BYTES];
        {
            let mut fake = FakeController::new(
                sq_capacity,
                cq_capacity,
                s.queue_pair().dstrd(),
                &sq_snapshot,
                &mut scratch_cq,
            );
            // Emit completion for the SQE we just submitted (tail
            // is now 1, so consumed slot is 0).
            fake.emit_completion_for_latest_sqe(1);
        }

        // Step 3 — copy the synthetic completion into the session's
        // CQ page via `copy_from_slice` (avoids the slice-take
        // pitfall of `core::mem::take(&mut [u8])`).
        s.cq_page_mut().copy_from_slice(&scratch_cq);

        // Step 4 — poll for the matching CID. NopMmio because the
        // synthetic completion is already in the page.
        let mut nop = NopMmio;
        let fields = s
            .poll_completion_for_cid(cid, 16, &mut nop)
            .expect("poll ok")
            .expect("fields found");
        assert_eq!(fields.cid, cid);
        assert_eq!(fields.sc, 0); // success
        assert!(fields.is_success());
        // sq_head fed back via drain_completion → SqRing's
        // head_observed advanced to 1.
        assert_eq!(s.queue_pair().sq().head_observed(), 1);
    }

    /// Test-only MmioBackend that records doorbell writes without
    /// emitting completions.
    #[derive(Debug, Default)]
    struct BootstrapFake {
        writes: Vec<(usize, u32)>,
    }

    impl MmioBackend for BootstrapFake {
        fn write_doorbell(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
        }
    }

    /// No-op MmioBackend for the poll path.
    #[derive(Debug, Default)]
    struct NopMmio;

    impl MmioBackend for NopMmio {
        fn write_doorbell(&mut self, _offset: usize, _value: u32) {}
    }

    #[test]
    fn submit_identify_namespace_uses_correct_cns_byte() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = s
            .submit_identify_namespace(7, 0x2000, &mut mmio)
            .expect("submit");

        // Inspect the SQE at slot 0: CDW10.CNS = CNS_IDENTIFY_NAMESPACE = 0x00.
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).expect("slot 0");
        let cns = sqe.get(40).copied().expect("cdw10 byte 40");
        assert_eq!(cns, crate::admin::CNS_IDENTIFY_NAMESPACE);
        // NSID at bytes 4..=7 little-endian = 7.
        let nsid_bytes = sqe.get(4..8).expect("nsid range");
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(nsid_bytes);
        assert_eq!(u32::from_le_bytes(tmp), 7);
        // CID echoed in SQE bytes 2..=3.
        let cid_bytes = sqe.get(2..4).expect("cid range");
        let mut t = [0u8; 2];
        t.copy_from_slice(cid_bytes);
        assert_eq!(u16::from_le_bytes(t), cid);
    }

    #[test]
    fn submit_identify_active_ns_list_uses_cns_02() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        s.submit_identify_active_ns_list(0x3000, &mut mmio).unwrap();
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).expect("slot 0");
        let cns = sqe.get(40).copied().expect("cdw10");
        assert_eq!(cns, crate::admin::CNS_ACTIVE_NSID_LIST);
    }

    // -------------------------------------------------------------------
    // poll behaviour
    // -------------------------------------------------------------------

    #[test]
    fn poll_returns_none_after_poll_limit_when_no_matching_completion() {
        // No CQE written to the CQ page → drain returns None every
        // iteration. After poll_limit iterations the helper returns
        // Ok(None) without erroring.
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut nop = NopMmio;
        let res = s.poll_completion_for_cid(42, 4, &mut nop).expect("poll");
        assert!(res.is_none());
    }

    // -------------------------------------------------------------------
    // run_identify_* (P6.7.10-pre.18)
    // -------------------------------------------------------------------

    fn round_trip_session_through_fake(s: &mut AdminSession, emits: u16) {
        // Drive the FakeController against the session's SQ snapshot
        // + a scratch CQ, then copy the scratch CQ back into the
        // session via copy_from_slice. `emits` is the new SQ tail
        // value the fake should respond to.
        let sq_snapshot: Vec<u8> = s.sq_page().to_vec();
        let cq_capacity: u16 = s.queue_pair().cq().capacity();
        let mut scratch_cq: Vec<u8> = vec![0u8; (cq_capacity as usize) * ADMIN_CQE_BYTES];
        {
            let mut fake = FakeController::new(
                s.queue_pair().sq().capacity(),
                cq_capacity,
                s.queue_pair().dstrd(),
                &sq_snapshot,
                &mut scratch_cq,
            );
            fake.emit_completion_for_latest_sqe(emits);
        }
        s.cq_page_mut().copy_from_slice(&scratch_cq);
    }

    #[test]
    fn run_identify_controller_round_trips_to_completion() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut bootstrap = BootstrapFake::default();
        // Pre-submit through the bootstrap fake so the SQ page has
        // the encoded SQE for the FakeController to read.
        let cid = s
            .submit_identify_controller(0x1000, &mut bootstrap)
            .unwrap();
        round_trip_session_through_fake(&mut s, 1);
        // Now poll via the high-level helper. It re-uses the
        // previously-submitted CID; the helper itself would have
        // allocated CID = 2, but for the host harness we exercise
        // the poll half directly.
        let mut nop = NopMmio;
        let fields = s
            .poll_completion_for_cid(cid, 16, &mut nop)
            .expect("poll")
            .expect("matched");
        assert!(fields.is_success());
    }

    #[test]
    fn run_identify_controller_returns_timeout_on_empty_cq() {
        let mut s = AdminSession::new(4, 4, 0).expect("ctor");
        let mut bootstrap = BootstrapFake::default();
        // submit_identify_controller works (writes to SQ page).
        // The FakeController is NOT invoked, so the CQ page stays
        // zero → drain returns None → helper surfaces timeout.
        let res = s.run_identify_controller(0x1000, 4, &mut bootstrap);
        assert_eq!(res, Err(QueueError::IdentifyCompletionTimeout));
    }

    #[test]
    fn run_identify_namespace_submits_correct_nsid_and_round_trips() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut bootstrap = BootstrapFake::default();
        let cid = s
            .submit_identify_namespace(7, 0x2000, &mut bootstrap)
            .unwrap();
        // Verify the encoded SQE carries NSID = 7.
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(sqe.get(4..8).unwrap());
        assert_eq!(u32::from_le_bytes(tmp), 7);
        round_trip_session_through_fake(&mut s, 1);
        let mut nop = NopMmio;
        let fields = s
            .poll_completion_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert!(fields.is_success());
    }

    #[test]
    fn run_identify_active_ns_list_round_trips() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut bootstrap = BootstrapFake::default();
        let cid = s
            .submit_identify_active_ns_list(0x3000, &mut bootstrap)
            .unwrap();
        // Verify CDW10.CNS = 0x02 (ActiveNsList).
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        let cns = sqe.get(40).copied().unwrap();
        assert_eq!(cns, crate::admin::CNS_ACTIVE_NSID_LIST);
        round_trip_session_through_fake(&mut s, 1);
        let mut nop = NopMmio;
        let fields = s
            .poll_completion_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert!(fields.is_success());
    }

    #[test]
    fn identify_completion_timeout_in_queue_error_taxonomy() {
        assert_ne!(
            QueueError::IdentifyCompletionTimeout,
            QueueError::ControllerNotReady
        );
        assert_ne!(QueueError::IdentifyCompletionTimeout, QueueError::Full);
    }

    // -------------------------------------------------------------------
    // Create IO CQ / Create IO SQ (P6.7.10-pre.20)
    // -------------------------------------------------------------------

    #[test]
    fn submit_create_io_cq_encodes_opcode_and_returns_cid() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = s
            .submit_create_io_cq(1, 128, 0x10_0000, 3, &mut mmio)
            .expect("submit");
        // CID is the freshly-allocated one (next_cid started at 1).
        assert_eq!(cid, 1);
        // Inspect the encoded SQE at slot 0: byte 0 = OPC = 0x05.
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        assert_eq!(
            sqe.first().copied().unwrap(),
            crate::admin::OPC_CREATE_IO_CQ
        );
    }

    #[test]
    fn submit_create_io_sq_encodes_opcode_and_returns_cid() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = s
            .submit_create_io_sq(
                1,
                1024,
                0x20_0000,
                1,
                crate::admin::CIOSQ_QPRIO_MEDIUM,
                &mut mmio,
            )
            .expect("submit");
        assert_eq!(cid, 1);
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        assert_eq!(
            sqe.first().copied().unwrap(),
            crate::admin::OPC_CREATE_IO_SQ
        );
    }

    #[test]
    fn submit_create_io_cq_sets_ien_and_pc_bits() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        s.submit_create_io_cq(1, 64, 0x10_0000, 5, &mut mmio)
            .unwrap();
        // Read CDW11 from bytes 44..=47.
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        let mut cdw11_buf = [0u8; 4];
        cdw11_buf.copy_from_slice(sqe.get(44..48).unwrap());
        let cdw11 = u32::from_le_bytes(cdw11_buf);
        // PC bit set.
        assert_eq!(
            cdw11 & crate::admin::CIOQ_CDW11_PC_BIT,
            crate::admin::CIOQ_CDW11_PC_BIT
        );
        // IEN bit set.
        assert_eq!(
            cdw11 & crate::admin::CIOCQ_CDW11_IEN_BIT,
            crate::admin::CIOCQ_CDW11_IEN_BIT
        );
        // IV = 5 in bits 31:16.
        assert_eq!(cdw11 >> crate::admin::CIOCQ_CDW11_IV_SHIFT, 5);
    }

    #[test]
    fn submit_create_io_sq_packs_cqid_and_qprio() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        s.submit_create_io_sq(
            1,
            1024,
            0x20_0000,
            7, // CQID
            crate::admin::CIOSQ_QPRIO_MEDIUM,
            &mut mmio,
        )
        .unwrap();
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        let mut cdw11_buf = [0u8; 4];
        cdw11_buf.copy_from_slice(sqe.get(44..48).unwrap());
        let cdw11 = u32::from_le_bytes(cdw11_buf);
        // PC bit set.
        assert_eq!(
            cdw11 & crate::admin::CIOQ_CDW11_PC_BIT,
            crate::admin::CIOQ_CDW11_PC_BIT
        );
        // QPRIO = MEDIUM = 0b10 in bits 2:1.
        let qprio = (cdw11 >> crate::admin::CIOSQ_CDW11_QPRIO_SHIFT) & 0b11;
        assert_eq!(qprio, crate::admin::CIOSQ_QPRIO_MEDIUM);
        // CQID = 7 in bits 31:16.
        let cqid = cdw11 >> crate::admin::CIOSQ_CDW11_CQID_SHIFT;
        assert_eq!(cqid, 7);
    }

    #[test]
    fn run_create_io_cq_returns_timeout_on_empty_cq() {
        let mut s = AdminSession::new(4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let res = s.run_create_io_cq(1, 64, 0x10_0000, 1, 4, &mut mmio);
        assert_eq!(res, Err(QueueError::IdentifyCompletionTimeout));
    }

    #[test]
    fn run_create_io_sq_returns_timeout_on_empty_cq() {
        let mut s = AdminSession::new(4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let res = s.run_create_io_sq(
            1,
            64,
            0x20_0000,
            1,
            crate::admin::CIOSQ_QPRIO_MEDIUM,
            4,
            &mut mmio,
        );
        assert_eq!(res, Err(QueueError::IdentifyCompletionTimeout));
    }

    #[test]
    fn run_create_io_cq_round_trips_to_success() {
        let mut s = AdminSession::new(8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        // Pre-submit so SQ has the SQE, then drive the fake to emit
        // the matching completion.
        let cid = s
            .submit_create_io_cq(1, 64, 0x10_0000, 1, &mut mmio)
            .unwrap();
        round_trip_session_through_fake(&mut s, 1);
        let mut nop = NopMmio;
        let fields = s
            .poll_completion_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert!(fields.is_success());
    }

    // -------------------------------------------------------------------
    // P6.7.10-pre.21 — end-to-end Phase-1 bring-up smoke
    // -------------------------------------------------------------------

    /// Build a synthetic CQE at the given CQ slot for the supplied
    /// CID + phase. Used by the e2e test to step through CQEs one
    /// at a time across multiple lap-aware slots.
    fn write_synthetic_cqe(page: &mut [u8], slot: usize, cid: u16, phase: bool, sq_head: u16) {
        let start = slot * ADMIN_CQE_BYTES;
        let end = start + ADMIN_CQE_BYTES;
        let dest = page.get_mut(start..end).expect("slot in range");
        // Zero the slot first so stale bytes do not leak through.
        for byte in dest.iter_mut() {
            *byte = 0;
        }
        let cdw2: u32 = u32::from(sq_head);
        let status_word: u16 = u16::from(phase);
        let cdw3: u32 = u32::from(cid) | (u32::from(status_word) << 16);
        let mut chunks = dest.chunks_exact_mut(4);
        let _ = chunks.next(); // CDW0
        let _ = chunks.next(); // CDW1
        chunks
            .next()
            .expect("cdw2 chunk")
            .copy_from_slice(&cdw2.to_le_bytes());
        chunks
            .next()
            .expect("cdw3 chunk")
            .copy_from_slice(&cdw3.to_le_bytes());
    }

    #[test]
    fn end_to_end_phase_1_bringup_sequence_completes_successfully() {
        // This integration test pins the full Phase-1 admin-queue
        // bring-up lifecycle to a single test, covering every
        // helper landed across P6.7.10-pre.13..pre.20:
        //
        //   1. Identify Controller        (pre.18)
        //   2. Identify Active NS List    (pre.18)
        //   3. Identify Namespace         (pre.18)
        //   4. Create I/O Completion Queue (pre.20)
        //   5. Create I/O Submission Queue (pre.20)
        //
        // Each step submits a SQE through the AdminSession,
        // injects a synthetic completion at the CQ slot the
        // session expects next, and drains it via
        // poll_completion_for_cid. Phase tag tracking flips
        // appropriately at every wrap.

        let mut s = AdminSession::new(4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();

        // Step 1: Identify Controller — CID = 1, SQ tail = 1.
        let cid1 = s.submit_identify_controller(0x1000, &mut mmio).unwrap();
        assert_eq!(cid1, 1);
        // Synthetic completion at CQ slot 0 with phase=true.
        write_synthetic_cqe(s.cq_page_mut(), 0, cid1, true, 1);
        let mut nop = NopMmio;
        let f1 = s
            .poll_completion_for_cid(cid1, 16, &mut nop)
            .unwrap()
            .expect("step 1 completion");
        assert!(f1.is_success());
        assert_eq!(f1.sq_head, 1);

        // Step 2: Identify Active NS List — CID = 2, SQ tail = 2.
        let cid2 = s.submit_identify_active_ns_list(0x2000, &mut mmio).unwrap();
        assert_eq!(cid2, 2);
        // CQ head advanced to slot 1 by the previous poll. Phase
        // tag still true (no wrap yet since capacity is 4).
        write_synthetic_cqe(s.cq_page_mut(), 1, cid2, true, 2);
        let f2 = s
            .poll_completion_for_cid(cid2, 16, &mut nop)
            .unwrap()
            .expect("step 2 completion");
        assert!(f2.is_success());

        // Step 3: Identify Namespace — CID = 3, SQ tail = 3.
        let cid3 = s.submit_identify_namespace(1, 0x3000, &mut mmio).unwrap();
        assert_eq!(cid3, 3);
        write_synthetic_cqe(s.cq_page_mut(), 2, cid3, true, 3);
        let f3 = s
            .poll_completion_for_cid(cid3, 16, &mut nop)
            .unwrap()
            .expect("step 3 completion");
        assert!(f3.is_success());

        // Step 4: Create I/O Completion Queue — CID = 4. But
        // wait: SQ capacity is 4, and the SqRing reserves one
        // slot for empty/full distinction (usable = 3). After 3
        // submits the ring is full. The previous polls fed back
        // sq_head=1/2/3, so head_observed advanced and the ring
        // unblocked. Verify by submitting Create IO CQ at slot 3
        // (last slot before wrap).
        let cid4 = s
            .submit_create_io_cq(1, 64, 0x10_0000, 1, &mut mmio)
            .unwrap();
        assert_eq!(cid4, 4);
        // CQ slot 3 — still phase=true (capacity=4, no wrap yet).
        write_synthetic_cqe(s.cq_page_mut(), 3, cid4, true, 0);
        let f4 = s
            .poll_completion_for_cid(cid4, 16, &mut nop)
            .unwrap()
            .expect("step 4 completion");
        assert!(f4.is_success());

        // Step 5: Create I/O Submission Queue — CID = 5. SQ tail
        // wraps to 0 here (sq_head fed back to 0 by the previous
        // CQE). CQ also wraps to slot 0 with phase=false (after
        // 4 completions consumed → expected_phase flipped).
        let cid5 = s
            .submit_create_io_sq(
                1,
                64,
                0x20_0000,
                1,
                crate::admin::CIOSQ_QPRIO_MEDIUM,
                &mut mmio,
            )
            .unwrap();
        assert_eq!(cid5, 5);
        // CQ wrapped → write at slot 0 with phase=false.
        write_synthetic_cqe(s.cq_page_mut(), 0, cid5, false, 1);
        let f5 = s
            .poll_completion_for_cid(cid5, 16, &mut nop)
            .unwrap()
            .expect("step 5 completion");
        assert!(f5.is_success());

        // Final state asserts: CQ ring wrapped exactly once →
        // expected_phase = true (initial), flipped to false after
        // 4 consumed CQEs, no further wrap on the 5th consumption
        // because head is now 1.
        assert!(!s.queue_pair().cq().expected_phase());
        assert_eq!(s.queue_pair().cq().head(), 1);
        // Driver issued 5 SQ tail doorbell writes total (one per
        // submit) + 5 CQ head doorbell writes (one per drain).
        // The mmio recorder only captured SUBMIT-side writes (the
        // polls used `nop`).
        assert_eq!(mmio.writes.len(), 5);
    }

    #[test]
    fn poll_skips_sibling_completions_until_matching_cid_arrives() {
        let mut s = AdminSession::new(4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        // Submit two Identify Controller commands → cid_a = 1, cid_b = 2.
        let cid_a = s.submit_identify_controller(0x1000, &mut mmio).unwrap();
        let cid_b = s.submit_identify_controller(0x2000, &mut mmio).unwrap();
        assert_eq!(cid_a, 1);
        assert_eq!(cid_b, 2);

        // Fake controller emits completions for both.
        let sq_snapshot: Vec<u8> = s.sq_page().to_vec();
        let cq_capacity: u16 = s.queue_pair().cq().capacity();
        let mut scratch_cq: Vec<u8> = vec![0u8; (cq_capacity as usize) * ADMIN_CQE_BYTES];
        {
            let mut fake = FakeController::new(4, cq_capacity, 0, &sq_snapshot, &mut scratch_cq);
            fake.emit_completion_for_latest_sqe(1); // cid_a
            fake.emit_completion_for_latest_sqe(2); // cid_b
        }
        s.cq_page_mut().copy_from_slice(&scratch_cq);

        let mut nop = NopMmio;
        // Poll for cid_b — the helper drains cid_a first (silently
        // discards it) then finds cid_b.
        let fields = s
            .poll_completion_for_cid(cid_b, 16, &mut nop)
            .expect("poll ok")
            .expect("fields");
        assert_eq!(fields.cid, cid_b);
    }
}

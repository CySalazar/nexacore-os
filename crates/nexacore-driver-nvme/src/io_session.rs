//! NVMe IO Queue Pair session — BLK ↔ NVMe glue.
//!
//! Composes [`crate::queue::AdminQueuePair`] (re-purposed for a
//! non-admin queue id via [`AdminQueuePair::new_for_qid`]) with the
//! BLK ↔ NVMe gateway from [`crate::blk_gateway`] so the
//! file-system service consumes a high-level
//! [`BlkRequest`] → [`BlkResponse`] surface without ever touching
//! the NVMe wire format directly.
//!
//! ## Phase-1 scope
//!
//! Phase-1 driver allocates exactly one IO queue pair (qid = 1)
//! per NCIP-Driver-NVMe-014 § R2. Multi-queue support (qid `2..=4`
//! per § R5) lands as a future NCIP without breaking the session
//! shape used today — the constructor accepts an arbitrary qid.
//!
//! ## What this module does NOT do
//!
//! - It does not validate `lba` against namespace size or `count`
//!   against [`nexacore_types::blk::MAX_BLOCK_COUNT_PER_REQUEST`].
//!   Those checks happen at the BLK channel boundary; the
//!   session trusts the caller.
//! - It does not own the PRP-list buffer for multi-page transfers
//!   (`block_count > 2` per
//!   [`crate::transfer_model::prp_layout`]). The caller composes
//!   the PRP layout via [`crate::transfer_model`] helpers and
//!   passes the resulting `prp1` / `prp2` pair to
//!   [`IoSession::submit_blk_request`].

use alloc::{vec, vec::Vec};

use nexacore_types::blk::{BlkRequest, BlkResponse};

use crate::{
    admin::{ADMIN_CQE_BYTES, ADMIN_SQE_BYTES},
    blk_gateway::{cqe_to_blk_response, encode_blk_request},
    queue::{AdminQueuePair, MmioBackend, QueueError},
    transfer_model::{PrpDeriveError, derive_prp_pair_for_blocks},
};

/// Phase-1 IO queue identifier (single queue per NCIP-014 § R2).
pub const PHASE_1_IO_QID: u16 = 1;

/// Errors the high-level [`IoSession::submit_blk_request_auto`]
/// path can surface.
///
/// Wraps the underlying [`QueueError`] + [`PrpDeriveError`] families
/// so the BLK channel server can translate each failure to the
/// matching `nexacore_types::blk::BlkResponse` variant without needing
/// to know which layer the error came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IoSubmitError {
    /// The PRP-pair derivation rejected the request shape (zero
    /// count, misaligned IOVA, count above
    /// [`crate::transfer_model::MAX_BLOCK_COUNT_PER_COMMAND`], or
    /// missing/misaligned PRP-list page).
    PrpDerive(PrpDeriveError),
    /// The underlying queue submission failed
    /// ([`QueueError::Full`], [`QueueError::SqPageTooSmall`],
    /// [`QueueError::DoorbellOffsetOverflow`], etc.).
    Queue(QueueError),
    /// The request is `BlkRequest::Discard`. The Dataset Management
    /// command requires PRP1 to point at a caller-prepared Range
    /// Descriptor buffer (built via
    /// [`crate::discard::write_single_discard_range`]); the
    /// auto-derivation path cannot synthesise that buffer. The
    /// caller MUST invoke [`IoSession::submit_blk_request`]
    /// directly with the prepared IOVA.
    DiscardRequiresExplicitPrp,
    /// The request is an unknown `#[non_exhaustive]` future
    /// variant the encoder does not recognise — the caller MUST
    /// emit `BlkResponse::NotSupported` upstream.
    UnsupportedRequest,
}

/// Per-session bookkeeping for the NVMe IO queue pair.
///
/// Mirrors the [`crate::admin_session::AdminSession`] pattern:
/// owns the SQ + CQ data pages (allocated as `Vec<u8>` for the
/// host harness; the live driver swaps them for `DmaMap`-backed
/// IOVA slices through a future trait) and a monotone CID counter
/// that wraps at `u16::MAX` skipping zero (reserved per
/// `nexacore_types::nvme::RESERVED_DRIVER_OPAQUE_ID`).
#[derive(Debug)]
pub struct IoSession {
    queue_pair: AdminQueuePair,
    sq_page: Vec<u8>,
    cq_page: Vec<u8>,
    next_cid: u16,
    nsid: u32,
}

impl IoSession {
    /// Construct a fresh IO session bound to the supplied qid +
    /// namespace.
    ///
    /// Phase-1 callers should pass `qid = PHASE_1_IO_QID` (1) and
    /// `nsid = 1` (the single active namespace).
    ///
    /// # Errors
    ///
    /// - [`QueueError::Ring`] wrapping any underlying
    ///   [`crate::ring::RingError`] (capacity zero or > `u16::MAX`).
    pub fn new(
        qid: u16,
        nsid: u32,
        sq_depth: u32,
        cq_depth: u32,
        dstrd: u8,
    ) -> Result<Self, QueueError> {
        let queue_pair = AdminQueuePair::new_for_qid(qid, sq_depth, cq_depth, dstrd)?;
        let sq_page = vec![0u8; (sq_depth as usize) * ADMIN_SQE_BYTES];
        let cq_page = vec![0u8; (cq_depth as usize) * ADMIN_CQE_BYTES];
        Ok(Self {
            queue_pair,
            sq_page,
            cq_page,
            next_cid: 1,
            nsid,
        })
    }

    /// Borrow the underlying queue pair for read-only
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

    /// Borrow the CQ data page mutably (host tests inject
    /// synthetic completions through this accessor).
    pub fn cq_page_mut(&mut self) -> &mut [u8] {
        &mut self.cq_page
    }

    /// Returns the namespace the session targets.
    #[must_use]
    pub const fn nsid(&self) -> u32 {
        self.nsid
    }

    /// Allocate the next CID and advance the monotone counter
    /// (wrapping at `u16::MAX`, skipping the reserved zero).
    fn allocate_cid(&mut self) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.checked_add(1).unwrap_or(1);
        cid
    }

    /// Encode + submit a [`BlkRequest`] onto the IO submission
    /// queue. Returns the assigned CID for the matching
    /// completion.
    ///
    /// The caller derives `prp1` / `prp2` from the request's
    /// `buf_iova` via [`crate::transfer_model::prp_layout`] +
    /// [`crate::transfer_model::prp1_for`] +
    /// [`crate::transfer_model::prp2_for`]. The session does not
    /// own the PRP-list page (caller-supplied for
    /// `block_count > 2`).
    ///
    /// Returns `None` when [`encode_blk_request`] rejects the
    /// request (currently only `#[non_exhaustive]` future
    /// variants); the caller MUST then emit
    /// `BlkResponse::NotSupported` to the BLK channel client.
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`AdminQueuePair::submit`] surfaces (`Full`,
    /// `SqPageTooSmall`, `DoorbellOffsetOverflow`).
    pub fn submit_blk_request<M: MmioBackend>(
        &mut self,
        req: BlkRequest,
        prp1: u64,
        prp2: u64,
        mmio: &mut M,
    ) -> Result<Option<u16>, QueueError> {
        let cid = self.allocate_cid();
        let Some(sqe) = encode_blk_request(req, cid, self.nsid, prp1, prp2) else {
            return Ok(None);
        };
        self.queue_pair.submit(&sqe, mmio, &mut self.sq_page)?;
        Ok(Some(cid))
    }

    /// Submit a [`BlkRequest`] with automatic PRP derivation.
    ///
    /// This is the high-level entry point the BLK channel server
    /// uses: it dispatches on the request variant, derives the
    /// `(prp1, prp2)` pair for data-transfer commands via
    /// [`derive_prp_pair_for_blocks`] (P6.7.10-pre.28), then
    /// routes through [`Self::submit_blk_request`].
    ///
    /// Per-variant behaviour:
    /// - [`BlkRequest::Read`] / [`BlkRequest::Write`] —
    ///   `(prp1, prp2)` derived from `(buf_iova, count,
    ///   list_page_iova)` per [`derive_prp_pair_for_blocks`].
    /// - [`BlkRequest::Flush`] — PRPs are unused (`prp1 = prp2 =
    ///   0`); `list_page_iova` is ignored.
    /// - [`BlkRequest::Discard`] — REJECTED with
    ///   [`IoSubmitError::DiscardRequiresExplicitPrp`]. The
    ///   Dataset Management command requires PRP1 to point at a
    ///   caller-prepared Range Descriptor buffer (built via
    ///   [`crate::discard::write_single_discard_range`]); the
    ///   auto-derivation path cannot synthesise that buffer. The
    ///   caller MUST invoke [`Self::submit_blk_request`] directly
    ///   for Discard, passing the prepared Range Descriptor IOVA
    ///   as `prp1`.
    /// - any future `#[non_exhaustive]` variant — REJECTED with
    ///   [`IoSubmitError::UnsupportedRequest`].
    ///
    /// # Errors
    ///
    /// - [`IoSubmitError::PrpDerive`] wrapping any
    ///   [`PrpDeriveError`] [`derive_prp_pair_for_blocks`]
    ///   surfaces (`BufferMisaligned`, `ZeroBlockCount`,
    ///   `TooManyBlocks`, `PrpListPageMissing`,
    ///   `PrpListPageMisaligned`).
    /// - [`IoSubmitError::Queue`] wrapping any [`QueueError`] the
    ///   underlying [`AdminQueuePair::submit`] surfaces.
    /// - [`IoSubmitError::DiscardRequiresExplicitPrp`] when the
    ///   request is `BlkRequest::Discard`.
    /// - [`IoSubmitError::UnsupportedRequest`] when the request
    ///   is an unknown `#[non_exhaustive]` variant the encoder
    ///   does not recognise.
    pub fn submit_blk_request_auto<M: MmioBackend>(
        &mut self,
        req: BlkRequest,
        list_page_iova: u64,
        mmio: &mut M,
    ) -> Result<u16, IoSubmitError> {
        match req {
            BlkRequest::Read {
                lba: _,
                count,
                buf_iova,
            }
            | BlkRequest::Write {
                lba: _,
                count,
                buf_iova,
            } => {
                let (_, prp1, prp2) = derive_prp_pair_for_blocks(buf_iova, count, list_page_iova)
                    .map_err(IoSubmitError::PrpDerive)?;
                self.submit_blk_request(req, prp1, prp2, mmio)
                    .map_err(IoSubmitError::Queue)?
                    .ok_or(IoSubmitError::UnsupportedRequest)
            }
            BlkRequest::Flush => self
                .submit_blk_request(req, 0, 0, mmio)
                .map_err(IoSubmitError::Queue)?
                .ok_or(IoSubmitError::UnsupportedRequest),
            BlkRequest::Discard { .. } => Err(IoSubmitError::DiscardRequiresExplicitPrp),
            // `#[non_exhaustive]` catch-all per NCIP-Serde-004.
            _ => Err(IoSubmitError::UnsupportedRequest),
        }
    }

    /// Drain the CQ for the matching `cid` and translate the
    /// completion to a [`BlkResponse`].
    ///
    /// Sibling completions for other in-flight CIDs are silently
    /// discarded. The poll loop terminates after `poll_limit`
    /// drained CQEs without a match — at which point the helper
    /// returns `Ok(None)`, mirroring
    /// [`crate::admin_session::AdminSession::poll_completion_for_cid`].
    ///
    /// # Errors
    ///
    /// Propagates any [`QueueError`] the underlying
    /// [`AdminQueuePair::drain_completion`] surfaces.
    pub fn poll_blk_response_for_cid<M: MmioBackend>(
        &mut self,
        cid: u16,
        poll_limit: u32,
        mmio: &mut M,
    ) -> Result<Option<BlkResponse>, QueueError> {
        for _ in 0..poll_limit {
            if let Some(fields) = self.queue_pair.drain_completion(mmio, &self.cq_page)? {
                if fields.cid == cid {
                    return Ok(Some(cqe_to_blk_response(&fields)));
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
        admin::AdminCqeFields,
        controller_regs::{cq_head_doorbell_offset, sq_tail_doorbell_offset},
    };

    #[derive(Debug, Default)]
    struct BootstrapFake {
        writes: Vec<(usize, u32)>,
    }

    impl MmioBackend for BootstrapFake {
        fn write_doorbell(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
        }
    }

    /// Write a synthetic CQE at slot `slot` carrying the supplied
    /// CID + phase + status. The default status (0,0) means
    /// success.
    fn write_synthetic_cqe(page: &mut [u8], slot: usize, cid: u16, phase: bool, sct: u8, sc: u8) {
        let start = slot * ADMIN_CQE_BYTES;
        let end = start + ADMIN_CQE_BYTES;
        let dest = page.get_mut(start..end).expect("slot in range");
        for byte in dest.iter_mut() {
            *byte = 0;
        }
        // CDW3 = CID | status_word << 16 where status_word's bit 0
        // is the phase tag, bits 1..=8 are SC, bits 9..=11 are SCT.
        let status_word: u16 =
            u16::from(phase) | (u16::from(sc) << 1) | (u16::from(sct & 0b111) << 9);
        let cdw3: u32 = u32::from(cid) | (u32::from(status_word) << 16);
        let mut chunks = dest.chunks_exact_mut(4);
        let _ = chunks.next(); // CDW0
        let _ = chunks.next(); // CDW1
        let _ = chunks.next(); // CDW2
        chunks
            .next()
            .expect("cdw3")
            .copy_from_slice(&cdw3.to_le_bytes());
    }

    // -------------------------------------------------------------------
    // Construction & routing
    // -------------------------------------------------------------------

    #[test]
    fn phase_1_io_qid_constant_is_one() {
        // Tripwire per NCIP-NVMe-014 § R2 (Phase-1 single IO queue
        // lives at qid = 1; qid = 0 is reserved for the admin
        // queue per § 3.1.21).
        assert_eq!(PHASE_1_IO_QID, 1);
    }

    #[test]
    fn io_session_new_records_qid_and_nsid() {
        let s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        assert_eq!(s.queue_pair().qid(), 1);
        assert_eq!(s.nsid(), 1);
    }

    #[test]
    fn io_session_doorbell_routes_to_io_qid() {
        // Submit one BlkRequest::Flush so the recorder captures
        // the SQ tail doorbell offset. The offset MUST match the
        // qid=1 SQ doorbell, NOT the qid=0 admin doorbell.
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        s.submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap();
        let (off, _) = mmio.writes.first().copied().expect("doorbell written");
        let io_sq_offset = sq_tail_doorbell_offset(PHASE_1_IO_QID, 0).unwrap();
        let admin_sq_offset = sq_tail_doorbell_offset(0, 0).unwrap();
        assert_eq!(off, io_sq_offset);
        assert_ne!(off, admin_sq_offset, "MUST route to IO doorbell, not admin");
    }

    // -------------------------------------------------------------------
    // submit_blk_request — full round-trip
    // -------------------------------------------------------------------

    #[test]
    fn submit_blk_request_returns_assigned_cid() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid_opt = s
            .submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap();
        assert_eq!(cid_opt, Some(1));
    }

    #[test]
    fn submit_blk_request_encodes_nsid_into_sqe() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 7, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        s.submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap();
        // NSID at SQE bytes 4..=7 (little-endian).
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(sqe.get(4..8).unwrap());
        assert_eq!(u32::from_le_bytes(tmp), 7);
    }

    #[test]
    fn submit_blk_request_read_encodes_nvm_read_opcode() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let req = BlkRequest::Read {
            lba: 0x100,
            count: 4,
            buf_iova: 0x1_0000,
        };
        s.submit_blk_request(req, 0x1_0000, 0, &mut mmio).unwrap();
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        assert_eq!(sqe.first().copied().unwrap(), crate::io::OPC_NVM_READ);
    }

    // -------------------------------------------------------------------
    // poll_blk_response_for_cid — translation
    // -------------------------------------------------------------------

    #[test]
    fn poll_blk_response_returns_ok_on_successful_cqe() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = s
            .submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap()
            .unwrap();
        // Inject a successful CQE at slot 0 with phase=true.
        write_synthetic_cqe(s.cq_page_mut(), 0, cid, true, 0, 0);
        let mut nop = BootstrapFake::default();
        let resp = s
            .poll_blk_response_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp, BlkResponse::Ok);
        // The drain rang the IO CQ head doorbell (not the admin).
        let (off, _) = nop.writes.first().copied().unwrap();
        let io_cq_offset = cq_head_doorbell_offset(PHASE_1_IO_QID, 0).unwrap();
        assert_eq!(off, io_cq_offset);
    }

    #[test]
    fn poll_blk_response_returns_invalid_argument_on_sc_02() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = s
            .submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap()
            .unwrap();
        // SCT=0, SC=0x02 → Invalid Field in Command.
        write_synthetic_cqe(s.cq_page_mut(), 0, cid, true, 0, 0x02);
        let mut nop = BootstrapFake::default();
        let resp = s
            .poll_blk_response_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp, BlkResponse::InvalidArgument);
    }

    #[test]
    fn poll_blk_response_returns_out_of_range_on_sc_80() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = s
            .submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap()
            .unwrap();
        // SCT=0, SC=0x80 → LBA Out of Range.
        write_synthetic_cqe(s.cq_page_mut(), 0, cid, true, 0, 0x80);
        let mut nop = BootstrapFake::default();
        let resp = s
            .poll_blk_response_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp, BlkResponse::OutOfRange);
    }

    #[test]
    fn poll_blk_response_returns_device_error_on_other_status() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let cid = s
            .submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap()
            .unwrap();
        // SCT=2 (Command-Specific), SC=0x82.
        write_synthetic_cqe(s.cq_page_mut(), 0, cid, true, 2, 0x82);
        let mut nop = BootstrapFake::default();
        let resp = s
            .poll_blk_response_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        match resp {
            BlkResponse::DeviceError(status) => {
                // Packed: (SCT << 8) | SC = (2 << 8) | 0x82 = 0x0282.
                assert_eq!(status, 0x0282);
            }
            _ => panic!("expected DeviceError, got {resp:?}"),
        }
    }

    #[test]
    fn poll_blk_response_returns_none_when_no_matching_completion() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 4, 4, 0).expect("ctor");
        let mmio = BootstrapFake::default();
        // No completion injected → drain returns None each
        // iteration → helper returns Ok(None) after exhausting
        // poll budget.
        let mut nop = BootstrapFake::default();
        let resp = s.poll_blk_response_for_cid(99, 4, &mut nop).unwrap();
        assert!(resp.is_none());
        let _ = mmio;
    }

    // -------------------------------------------------------------------
    // End-to-end: submit BLK Read → synthetic completion → poll
    // -------------------------------------------------------------------

    #[test]
    fn submit_then_poll_round_trips_blk_read_to_ok() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 4, 4, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let req = BlkRequest::Read {
            lba: 0x100,
            count: 1,
            buf_iova: 0x1_0000,
        };
        let cid = s
            .submit_blk_request(req, 0x1_0000, 0, &mut mmio)
            .unwrap()
            .unwrap();
        // Synthetic successful CQE.
        write_synthetic_cqe(s.cq_page_mut(), 0, cid, true, 0, 0);
        let mut nop = BootstrapFake::default();
        let resp = s
            .poll_blk_response_for_cid(cid, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp, BlkResponse::Ok);
        // sq_head feedback advanced the IO SqRing's head_observed.
        // Synthetic CQE carried sq_head=0 (default), so it didn't
        // actually advance — but the drain still consumed the
        // slot and rang the CQ head doorbell.
        assert_eq!(s.queue_pair().sq().tail(), 1);
    }

    #[test]
    fn cid_allocator_starts_at_one_and_advances() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        for expected_cid in 1..=3 {
            let cid = s
                .submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
                .unwrap()
                .unwrap();
            assert_eq!(cid, expected_cid);
        }
    }

    #[test]
    fn ctor_propagates_ring_error_on_zero_depth() {
        let res = IoSession::new(PHASE_1_IO_QID, 1, 0, 8, 0);
        assert!(matches!(res, Err(QueueError::Ring(_))));
    }

    // Suppress dead-code lint for the AdminCqeFields helper if
    // the imports above don't get exercised; keeping the use
    // visible for future tests that compose this fixture with
    // the cqe_to_blk_response surface directly.
    #[allow(dead_code)]
    fn _unused_admin_cqe_fields_ref(_f: AdminCqeFields) {}

    // -------------------------------------------------------------------
    // P6.7.10-pre.24 — IO queue pair end-to-end smoke (all 4
    // BlkRequest variants in sequence)
    // -------------------------------------------------------------------

    #[test]
    fn end_to_end_io_session_all_blk_request_variants_round_trip() {
        // Pins the BLK channel ABI to one auditable test:
        //   1. Read    -> CID=1, slot 0
        //   2. Write   -> CID=2, slot 1
        //   3. Flush   -> CID=3, slot 2
        //   4. Discard -> CID=4, slot 3
        //
        // Each step submits one BlkRequest, injects a synthetic
        // successful CQE at the next CQ slot, polls for the
        // matching CID, and asserts BlkResponse::Ok. Final
        // assertions verify CID monotone allocation, IO queue
        // doorbell routing, and the SQ ring's head_observed
        // feedback from each completion's sq_head field.

        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();

        // Step 1: Read
        let read_req = BlkRequest::Read {
            lba: 0x100,
            count: 1,
            buf_iova: 0x1_0000,
        };
        let cid1 = s
            .submit_blk_request(read_req, 0x1_0000, 0, &mut mmio)
            .unwrap()
            .unwrap();
        assert_eq!(cid1, 1);
        write_synthetic_cqe(s.cq_page_mut(), 0, cid1, true, 0, 0);
        let mut nop = BootstrapFake::default();
        let resp1 = s
            .poll_blk_response_for_cid(cid1, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp1, BlkResponse::Ok);

        // Step 2: Write
        let write_req = BlkRequest::Write {
            lba: 0x200,
            count: 2,
            buf_iova: 0x2_0000,
        };
        let cid2 = s
            .submit_blk_request(write_req, 0x2_0000, 0x2_1000, &mut mmio)
            .unwrap()
            .unwrap();
        assert_eq!(cid2, 2);
        write_synthetic_cqe(s.cq_page_mut(), 1, cid2, true, 0, 0);
        let resp2 = s
            .poll_blk_response_for_cid(cid2, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp2, BlkResponse::Ok);

        // Step 3: Flush
        let cid3 = s
            .submit_blk_request(BlkRequest::Flush, 0, 0, &mut mmio)
            .unwrap()
            .unwrap();
        assert_eq!(cid3, 3);
        write_synthetic_cqe(s.cq_page_mut(), 2, cid3, true, 0, 0);
        let resp3 = s
            .poll_blk_response_for_cid(cid3, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp3, BlkResponse::Ok);

        // Step 4: Discard
        let discard_req = BlkRequest::Discard {
            lba: 0x300,
            count: 4,
        };
        let cid4 = s
            .submit_blk_request(discard_req, 0x3_0000, 0, &mut mmio)
            .unwrap()
            .unwrap();
        assert_eq!(cid4, 4);
        write_synthetic_cqe(s.cq_page_mut(), 3, cid4, true, 0, 0);
        let resp4 = s
            .poll_blk_response_for_cid(cid4, 16, &mut nop)
            .unwrap()
            .unwrap();
        assert_eq!(resp4, BlkResponse::Ok);

        // Final assertions: 4 distinct CIDs (1..=4), 4 SQ tail
        // doorbell writes (one per submit) all to the IO queue
        // offset, 4 CQ head doorbell writes (one per drain), CQ
        // head advanced to 4.
        let io_sq_offset = sq_tail_doorbell_offset(PHASE_1_IO_QID, 0).unwrap();
        let io_cq_offset = cq_head_doorbell_offset(PHASE_1_IO_QID, 0).unwrap();
        assert_eq!(mmio.writes.len(), 4, "4 SQ tail doorbells (one per submit)");
        for (i, &(off, _)) in mmio.writes.iter().enumerate() {
            assert_eq!(
                off, io_sq_offset,
                "submit {i} doorbell must route to the IO SQ tail offset"
            );
        }
        assert_eq!(nop.writes.len(), 4, "4 CQ head doorbells (one per drain)");
        for (i, &(off, _)) in nop.writes.iter().enumerate() {
            assert_eq!(
                off, io_cq_offset,
                "drain {i} doorbell must route to the IO CQ head offset"
            );
        }
        // CQ ring head advanced through all 4 slots.
        assert_eq!(s.queue_pair().cq().head(), 4);
        // SQ tail advanced through all 4 submissions.
        assert_eq!(s.queue_pair().sq().tail(), 4);
    }

    // -------------------------------------------------------------------
    // submit_blk_request_auto (P6.7.10-pre.29)
    // -------------------------------------------------------------------

    #[test]
    fn auto_submit_read_derives_single_page_prps() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let req = BlkRequest::Read {
            lba: 0x100,
            count: 1,
            buf_iova: 0x1_0000,
        };
        let cid = s.submit_blk_request_auto(req, 0, &mut mmio).unwrap();
        assert_eq!(cid, 1);
        // SQE byte 0 = OPC_NVM_READ; PRP1 (bytes 24..=31) = buf_iova;
        // PRP2 (bytes 32..=39) = 0 (single-page transfer).
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        assert_eq!(sqe.first().copied().unwrap(), crate::io::OPC_NVM_READ);
        let mut prp1_buf = [0u8; 8];
        prp1_buf.copy_from_slice(sqe.get(24..32).unwrap());
        assert_eq!(u64::from_le_bytes(prp1_buf), 0x1_0000);
        let mut prp2_buf = [0u8; 8];
        prp2_buf.copy_from_slice(sqe.get(32..40).unwrap());
        assert_eq!(u64::from_le_bytes(prp2_buf), 0);
    }

    #[test]
    fn auto_submit_write_two_blocks_derives_two_pages_prps() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let req = BlkRequest::Write {
            lba: 0x200,
            count: 2,
            buf_iova: 0x2_0000,
        };
        s.submit_blk_request_auto(req, 0, &mut mmio).unwrap();
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        assert_eq!(sqe.first().copied().unwrap(), crate::io::OPC_NVM_WRITE);
        // PRP1 = buf; PRP2 = buf + 4096 (TwoPages layout).
        let mut prp2_buf = [0u8; 8];
        prp2_buf.copy_from_slice(sqe.get(32..40).unwrap());
        assert_eq!(u64::from_le_bytes(prp2_buf), 0x2_0000 + 4096);
    }

    #[test]
    fn auto_submit_read_three_blocks_uses_list_page_iova() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let req = BlkRequest::Read {
            lba: 0x300,
            count: 3,
            buf_iova: 0x3_0000,
        };
        // PRP-list page at 0x10_0000.
        s.submit_blk_request_auto(req, 0x10_0000, &mut mmio)
            .unwrap();
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        // PRP2 = list_page_iova (PrpList layout).
        let mut prp2_buf = [0u8; 8];
        prp2_buf.copy_from_slice(sqe.get(32..40).unwrap());
        assert_eq!(u64::from_le_bytes(prp2_buf), 0x10_0000);
    }

    #[test]
    fn auto_submit_flush_uses_zero_prps_and_ignores_list_page_iova() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        // Garbage list_page_iova — Flush must ignore it.
        s.submit_blk_request_auto(BlkRequest::Flush, 0xDEAD_BEEF, &mut mmio)
            .unwrap();
        let sqe = s.sq_page().get(0..ADMIN_SQE_BYTES).unwrap();
        assert_eq!(sqe.first().copied().unwrap(), crate::io::OPC_NVM_FLUSH);
        let mut prp1_buf = [0u8; 8];
        prp1_buf.copy_from_slice(sqe.get(24..32).unwrap());
        assert_eq!(u64::from_le_bytes(prp1_buf), 0);
        let mut prp2_buf = [0u8; 8];
        prp2_buf.copy_from_slice(sqe.get(32..40).unwrap());
        assert_eq!(u64::from_le_bytes(prp2_buf), 0);
    }

    #[test]
    fn auto_submit_discard_rejects_with_explicit_prp_required() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let request = BlkRequest::Discard {
            lba: 0x100,
            count: 4,
        };
        let outcome = s.submit_blk_request_auto(request, 0x10_0000, &mut mmio);
        assert_eq!(outcome, Err(IoSubmitError::DiscardRequiresExplicitPrp));
        // No SQE written, no doorbell rung.
        assert!(mmio.writes.is_empty());
    }

    #[test]
    fn auto_submit_propagates_prp_derive_error_for_zero_count() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let request = BlkRequest::Read {
            lba: 0,
            count: 0,
            buf_iova: 0x1_0000,
        };
        let outcome = s.submit_blk_request_auto(request, 0, &mut mmio);
        assert_eq!(
            outcome,
            Err(IoSubmitError::PrpDerive(PrpDeriveError::ZeroBlockCount))
        );
        assert!(mmio.writes.is_empty());
    }

    #[test]
    fn auto_submit_propagates_prp_derive_error_for_misaligned_buf() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        let request = BlkRequest::Write {
            lba: 0,
            count: 1,
            buf_iova: 0x1_0001, // not 4 KiB-aligned
        };
        let outcome = s.submit_blk_request_auto(request, 0, &mut mmio);
        assert_eq!(
            outcome,
            Err(IoSubmitError::PrpDerive(PrpDeriveError::BufferMisaligned))
        );
    }

    #[test]
    fn auto_submit_propagates_prp_derive_error_for_missing_list_page() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 8, 8, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        // 3 blocks but list_page_iova = 0 → PrpListPageMissing.
        let request = BlkRequest::Read {
            lba: 0,
            count: 3,
            buf_iova: 0x1_0000,
        };
        let outcome = s.submit_blk_request_auto(request, 0, &mut mmio);
        assert_eq!(
            outcome,
            Err(IoSubmitError::PrpDerive(PrpDeriveError::PrpListPageMissing))
        );
    }

    #[test]
    fn auto_submit_advances_cid_monotonically_across_variants() {
        let mut s = IoSession::new(PHASE_1_IO_QID, 1, 16, 16, 0).expect("ctor");
        let mut mmio = BootstrapFake::default();
        // Read → CID=1
        let c1 = s
            .submit_blk_request_auto(
                BlkRequest::Read {
                    lba: 0,
                    count: 1,
                    buf_iova: 0x1_0000,
                },
                0,
                &mut mmio,
            )
            .unwrap();
        // Write → CID=2
        let c2 = s
            .submit_blk_request_auto(
                BlkRequest::Write {
                    lba: 0,
                    count: 1,
                    buf_iova: 0x2_0000,
                },
                0,
                &mut mmio,
            )
            .unwrap();
        // Flush → CID=3
        let c3 = s
            .submit_blk_request_auto(BlkRequest::Flush, 0, &mut mmio)
            .unwrap();
        assert_eq!((c1, c2, c3), (1, 2, 3));
    }

    #[test]
    fn io_submit_error_taxonomy_is_distinguishable() {
        let a = IoSubmitError::DiscardRequiresExplicitPrp;
        let b = IoSubmitError::UnsupportedRequest;
        let c = IoSubmitError::PrpDerive(PrpDeriveError::ZeroBlockCount);
        let d = IoSubmitError::Queue(QueueError::Full);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(c, d);
        assert_ne!(a, d);
        assert_eq!(a, IoSubmitError::DiscardRequiresExplicitPrp);
    }
}

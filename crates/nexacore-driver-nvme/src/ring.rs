//! NVMe Submission Queue / Completion Queue ring-buffer scaffolds.
//!
//! Pinned by NVMe 1.4 base spec § 4.1 ("Submission and Completion
//! Queues") + § 4.6 (CQE phase-tag wrap semantics). The user-space
//! NVMe driver maintains one [`SqRing`] + one [`CqRing`] per queue
//! pair the controller hosts: one pair for the Admin queue (Phase 1
//! single-queue), one or more pairs for IO traffic.
//!
//! ## Why a pure-state scaffold module
//!
//! The live admin / IO queue driver is a multi-stage state machine —
//! `submit(sqe)` writes the SQE into a ring slot then bumps the SQ
//! tail doorbell; `drain_completions()` reads CQE slots until the
//! phase tag toggles, ack-ing each entry through the CQ head
//! doorbell. The MMIO half of that machine cannot be unit-tested
//! host-side without standing up a controller. The ring-buffer
//! bookkeeping, however, is pure state — slot index arithmetic,
//! wrap-around at `capacity`, phase-tag flipping on every CQ wrap.
//! Putting the pure-state bookkeeping here (separate from the future
//! MMIO half) lets host tests prove the wrap math is correct without
//! waiting for the live driver to land.
//!
//! ## What this module does NOT do
//!
//! - It does not write SQ doorbells. The caller invokes
//!   [`SqRing::submit`] to claim a slot index, then writes the SQE
//!   into the queue page at that index and rings the SQ tail
//!   doorbell. The ring tracks the new tail so a future capacity
//!   check sees the right occupancy.
//! - It does not parse CQE bytes. The caller passes the
//!   [`crate::admin::AdminCqe`] view of the next CQ slot to
//!   [`CqRing::try_take`]; the ring decides whether the slot
//!   belongs to the current lap (by matching the parsed phase bit
//!   against the expected value) and the caller drains the CQE
//!   payload through [`crate::admin::parse_admin_cqe`].
//! - It does not allocate the queue pages. Page allocation is the
//!   caller's responsibility (`MmioMap` for the doorbell array;
//!   `DmaMap` for the SQ + CQ data pages). The ring holds only
//!   pointers / indices into those pages, never the bytes
//!   themselves.

use crate::admin::{AdminCqe, AdminCqeFields, parse_admin_cqe};

// =============================================================================
// Errors
// =============================================================================

/// Reason a ring-buffer helper could not complete.
///
/// All variants are observable through the future IO ring-buffer
/// driver's `BlkResponse::InvalidArgument` / `BackpressureFull`
/// surface; the ring maps each variant deterministically without
/// touching MMIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RingError {
    /// The ring was constructed with `capacity = 0`. NVMe 1.4 § 5.1
    /// requires `1..=4096` (admin) or `1..=65536` (IO); landing here
    /// indicates a manifest validation regression upstream.
    CapacityZero,
    /// The ring's capacity exceeded `u16::MAX` (= 65535). NVMe 1.4
    /// § 5.5 encodes the IO submission-queue size in a 16-bit CDW10
    /// field; capacities beyond that range would silently wrap to
    /// the controller, so the constructor rejects them at type-level
    /// here.
    CapacityTooLarge,
}

// =============================================================================
// SqRing — submission queue ring
// =============================================================================

/// Submission Queue ring-buffer bookkeeping.
///
/// Tracks the local tail (the next slot the driver will write) and
/// the most-recently-observed head (the controller's view of the
/// queue, sampled from the matching CQE's SQ Head Pointer field per
/// NVMe 1.4 § 4.6). Capacity-checking is `tail - head_observed`
/// modulo `capacity`, which is the standard MPSC-style empty/full
/// distinction the NVMe spec mandates.
///
/// The ring is full when `tail` would catch up to `head_observed` —
/// i.e. when the next [`Self::submit`] would advance `tail` to equal
/// `head_observed`. To distinguish full from empty the standard
/// trick is to leave one slot unused; [`Self::capacity`] therefore
/// reports the underlying physical size, while
/// [`Self::usable_capacity`] reports the effective slot count
/// (`capacity - 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqRing {
    capacity: u16,
    tail: u16,
    head_observed: u16,
}

impl SqRing {
    /// Construct an empty SQ ring of the given physical capacity.
    ///
    /// # Errors
    ///
    /// - [`RingError::CapacityZero`] when `capacity == 0`.
    /// - [`RingError::CapacityTooLarge`] when `capacity > u16::MAX`.
    ///   The signature accepts `u32` to mirror the
    ///   [`crate::queue_config`] depth-validation API; the constructor
    ///   downcasts after the bound check.
    pub const fn new(capacity: u32) -> Result<Self, RingError> {
        if capacity == 0 {
            return Err(RingError::CapacityZero);
        }
        // `u16::MAX as u32` is the only widening `const fn` path —
        // `u32::from(u16::MAX)` is not yet `const` on stable. The
        // operation is lossless by construction (`u16::MAX` fits in
        // `u32`).
        #[allow(
            clippy::cast_lossless,
            reason = "u32::from is not yet const; this widen is lossless by construction"
        )]
        let max = u16::MAX as u32;
        if capacity > max {
            return Err(RingError::CapacityTooLarge);
        }
        // u32 → u16 cast is bounded by the check above; explicit
        // `as` is the only way in a `const fn` (`TryFrom` is not
        // `const` yet).
        #[allow(
            clippy::cast_possible_truncation,
            reason = "guarded by the capacity bound check above"
        )]
        Ok(Self {
            capacity: capacity as u16,
            tail: 0,
            head_observed: 0,
        })
    }

    /// Physical capacity of the ring (number of allocated SQE slots).
    #[must_use]
    pub const fn capacity(self) -> u16 {
        self.capacity
    }

    /// Effective capacity (number of slots the driver may have
    /// outstanding at once). One slot is reserved to distinguish
    /// "empty" from "full" — see the type-level documentation.
    #[must_use]
    pub const fn usable_capacity(self) -> u16 {
        // capacity >= 1 by construction; subtraction does not wrap.
        self.capacity - 1
    }

    /// Current local tail (the slot index the next [`Self::submit`]
    /// would write to).
    #[must_use]
    pub const fn tail(self) -> u16 {
        self.tail
    }

    /// Most-recently-observed head (the controller's view of the
    /// queue).
    #[must_use]
    pub const fn head_observed(self) -> u16 {
        self.head_observed
    }

    /// Returns `true` iff the ring is full and a [`Self::submit`]
    /// call would refuse the request.
    #[must_use]
    pub const fn is_full(self) -> bool {
        // Full when the next tail wrap would hit head_observed.
        let next_tail = if self.tail + 1 == self.capacity {
            0
        } else {
            self.tail + 1
        };
        next_tail == self.head_observed
    }

    /// Returns `true` iff the ring has no outstanding commands.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.tail == self.head_observed
    }

    /// Claim the next submission slot and advance the local tail.
    ///
    /// Returns the slot index the caller must write the SQE into
    /// (the caller then rings the SQ tail doorbell with the new
    /// `tail` value).
    ///
    /// Returns `None` if the ring is full (the caller MUST drain
    /// completions via [`CqRing::try_take`] + a doorbell write
    /// before retrying).
    pub fn submit(&mut self) -> Option<u16> {
        if self.is_full() {
            return None;
        }
        let slot = self.tail;
        let next_tail = if self.tail + 1 == self.capacity {
            0
        } else {
            self.tail + 1
        };
        self.tail = next_tail;
        Some(slot)
    }

    /// Update the local view of the controller's head pointer.
    ///
    /// Called from the CQE drain loop with the `sq_head` field
    /// parsed from a matching [`AdminCqeFields`] — the controller
    /// reports its current SQ head every time it completes a
    /// command, which is how the driver knows it can re-use the
    /// freed-up slot.
    ///
    /// `head` MUST be `< capacity`. Out-of-range values are silently
    /// clamped via modulo for defence-in-depth — the live driver
    /// upstream of this call validates the doorbell stride at
    /// bring-up, so the modulo is a tripwire rather than a regular
    /// code path.
    pub fn update_head(&mut self, head: u16) {
        self.head_observed = head % self.capacity;
    }
}

// =============================================================================
// CqRing — completion queue ring
// =============================================================================

/// Completion Queue ring-buffer bookkeeping with phase-tag tracking.
///
/// NVMe 1.4 § 4.6 specifies that the controller toggles the phase
/// tag bit on every CQ ring wrap; the driver MUST compare the parsed
/// phase bit of each CQE against the locally-expected value to
/// distinguish "this slot has been filled this lap" from "this slot
/// is leftover from a previous lap".
///
/// Initial state per the spec: head = 0, `expected_phase` = `true`
/// (logical `1`). On every consumed CQE the head advances by one
/// modulo `capacity`; on every wrap the `expected_phase` flips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CqRing {
    capacity: u16,
    head: u16,
    expected_phase: bool,
}

impl CqRing {
    /// Construct an empty CQ ring of the given physical capacity.
    ///
    /// # Errors
    ///
    /// - [`RingError::CapacityZero`] when `capacity == 0`.
    /// - [`RingError::CapacityTooLarge`] when `capacity > u16::MAX`.
    pub const fn new(capacity: u32) -> Result<Self, RingError> {
        if capacity == 0 {
            return Err(RingError::CapacityZero);
        }
        #[allow(
            clippy::cast_lossless,
            reason = "u32::from is not yet const; this widen is lossless by construction"
        )]
        let max = u16::MAX as u32;
        if capacity > max {
            return Err(RingError::CapacityTooLarge);
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "guarded by the capacity bound check above"
        )]
        Ok(Self {
            capacity: capacity as u16,
            head: 0,
            expected_phase: true,
        })
    }

    /// Physical capacity of the ring (number of allocated CQE slots).
    #[must_use]
    pub const fn capacity(self) -> u16 {
        self.capacity
    }

    /// Current local head (the next slot to inspect).
    #[must_use]
    pub const fn head(self) -> u16 {
        self.head
    }

    /// Currently expected phase-tag bit. Flips on every ring wrap.
    #[must_use]
    pub const fn expected_phase(self) -> bool {
        self.expected_phase
    }

    /// Attempt to consume the CQE at the current head slot.
    ///
    /// The caller passes the [`AdminCqe`] read from the queue page at
    /// the slot index [`Self::head`]; the ring decides whether the
    /// slot belongs to the current lap:
    ///
    /// - If the parsed phase bit matches [`Self::expected_phase`]
    ///   the slot is consumed: the head advances by one modulo
    ///   `capacity`, the `expected_phase` flips on wrap, and the
    ///   parsed [`AdminCqeFields`] is returned.
    /// - If the phase bit does not match, the slot belongs to a
    ///   previous lap (the controller has not filled it yet); the
    ///   ring leaves head + `expected_phase` unchanged and returns
    ///   `None`.
    ///
    /// The caller MUST then ring the CQ head doorbell with the new
    /// `head` value on every `Some` return so the controller knows
    /// the slot is free to re-use.
    pub fn try_take(&mut self, slot: &AdminCqe) -> Option<AdminCqeFields> {
        let fields = parse_admin_cqe(slot);
        if fields.phase != self.expected_phase {
            return None;
        }
        // Slot belongs to the current lap — advance head and flip
        // phase on wrap.
        let next_head = if self.head + 1 == self.capacity {
            self.expected_phase = !self.expected_phase;
            0
        } else {
            self.head + 1
        };
        self.head = next_head;
        Some(fields)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::ADMIN_CQE_BYTES;

    fn make_cqe(phase: bool, cid: u16) -> AdminCqe {
        // Build a minimal CQE where only the phase bit and CID are
        // meaningful; the rest of the bytes stay zero.
        let mut raw = [0u8; ADMIN_CQE_BYTES];
        let cdw3: u32 = u32::from(cid) | (if phase { 1u32 << 16 } else { 0 });
        let cdw3_bytes = cdw3.to_le_bytes();
        let mut chunks = raw.chunks_exact_mut(4);
        let _ = chunks.next(); // CDW0
        let _ = chunks.next(); // CDW1
        let _ = chunks.next(); // CDW2
        chunks
            .next()
            .expect("cdw3 chunk in raw")
            .copy_from_slice(&cdw3_bytes);
        AdminCqe::from_bytes(raw)
    }

    // -------------------------------------------------------------------
    // Construction & invariants
    // -------------------------------------------------------------------

    #[test]
    fn sq_ring_rejects_zero_capacity() {
        assert_eq!(SqRing::new(0), Err(RingError::CapacityZero));
    }

    #[test]
    fn sq_ring_rejects_oversized_capacity() {
        assert_eq!(
            SqRing::new(u32::from(u16::MAX) + 1),
            Err(RingError::CapacityTooLarge)
        );
    }

    #[test]
    fn sq_ring_accepts_capacity_at_u16_max() {
        let r = SqRing::new(u32::from(u16::MAX)).expect("ok");
        assert_eq!(r.capacity(), u16::MAX);
    }

    #[test]
    fn cq_ring_rejects_zero_capacity() {
        assert_eq!(CqRing::new(0), Err(RingError::CapacityZero));
    }

    #[test]
    fn cq_ring_rejects_oversized_capacity() {
        assert_eq!(
            CqRing::new(u32::from(u16::MAX) + 1),
            Err(RingError::CapacityTooLarge)
        );
    }

    #[test]
    fn cq_ring_initial_expected_phase_is_true() {
        let r = CqRing::new(64).expect("ok");
        assert!(r.expected_phase());
        assert_eq!(r.head(), 0);
    }

    #[test]
    fn sq_ring_initial_state_is_empty() {
        let r = SqRing::new(64).expect("ok");
        assert!(r.is_empty());
        assert!(!r.is_full());
        assert_eq!(r.tail(), 0);
        assert_eq!(r.head_observed(), 0);
        // Effective usable capacity = capacity - 1 (one slot reserved).
        assert_eq!(r.usable_capacity(), 63);
    }

    // -------------------------------------------------------------------
    // SqRing — submit + update_head
    // -------------------------------------------------------------------

    #[test]
    fn sq_submit_advances_tail() {
        let mut r = SqRing::new(8).expect("ok");
        assert_eq!(r.submit(), Some(0));
        assert_eq!(r.tail(), 1);
        assert_eq!(r.submit(), Some(1));
        assert_eq!(r.tail(), 2);
    }

    #[test]
    fn sq_submit_wraps_tail_to_zero() {
        let mut r = SqRing::new(4).expect("ok");
        // Default head_observed = 0; submit 3 items fills the ring
        // to capacity-1 (slot reserved for empty/full distinction).
        // tail moves 0 → 1 → 2 → 3.
        assert_eq!(r.submit(), Some(0));
        assert_eq!(r.submit(), Some(1));
        assert_eq!(r.submit(), Some(2));
        assert_eq!(r.tail(), 3);
        assert!(r.is_full(), "ring full at tail=3 head=0");
        // Controller consumes slot 0 → reports head = 1; ring frees
        // one slot.
        r.update_head(1);
        // Next submit lands at slot 3; tail wraps to 0.
        assert_eq!(r.submit(), Some(3));
        assert_eq!(r.tail(), 0, "tail wrapped after slot 3");
    }

    #[test]
    fn sq_full_returns_none() {
        let mut r = SqRing::new(4).expect("ok");
        // capacity=4 ⇒ usable=3. Submit 3 SQEs.
        assert_eq!(r.submit(), Some(0));
        assert_eq!(r.submit(), Some(1));
        assert_eq!(r.submit(), Some(2));
        // Ring is now full (next tail=3 equals head_observed=0 wrap).
        // Wait — tail=3, head_observed=0; (3+1) % 4 = 0 = head_observed ⇒
        // is_full true. Confirm.
        assert!(r.is_full());
        assert_eq!(r.submit(), None);
        assert_eq!(r.tail(), 3, "failed submit must not advance tail");
    }

    #[test]
    fn sq_drain_unblocks_submit() {
        let mut r = SqRing::new(4).expect("ok");
        r.submit().expect("0");
        r.submit().expect("1");
        r.submit().expect("2");
        assert!(r.is_full());
        // Controller completed slot 0 — its SQ head pointer is now 1.
        r.update_head(1);
        assert!(!r.is_full());
        assert_eq!(r.submit(), Some(3));
    }

    #[test]
    fn sq_update_head_clamps_via_modulo() {
        let mut r = SqRing::new(4).expect("ok");
        r.update_head(5); // out-of-range -> 5 % 4 = 1
        assert_eq!(r.head_observed(), 1);
    }

    // -------------------------------------------------------------------
    // CqRing — try_take + phase-tag wrap
    // -------------------------------------------------------------------

    #[test]
    fn cq_take_with_matching_phase_advances_head() {
        let mut r = CqRing::new(4).expect("ok");
        let cqe = make_cqe(true, 42); // phase = 1 matches expected
        let f = r.try_take(&cqe).expect("phase matched");
        assert_eq!(f.cid, 42);
        assert_eq!(r.head(), 1);
        assert!(r.expected_phase(), "no wrap yet");
    }

    #[test]
    fn cq_take_with_mismatched_phase_returns_none() {
        let mut r = CqRing::new(4).expect("ok");
        let cqe = make_cqe(false, 0); // phase = 0 mismatches initial expected = true
        assert!(r.try_take(&cqe).is_none());
        assert_eq!(r.head(), 0);
        assert!(r.expected_phase());
    }

    #[test]
    fn cq_phase_flips_on_ring_wrap() {
        let mut r = CqRing::new(2).expect("ok");
        // Consume slots 0 and 1 with phase = true.
        r.try_take(&make_cqe(true, 1)).expect("slot 0");
        assert_eq!(r.head(), 1);
        assert!(r.expected_phase(), "still lap 0");
        r.try_take(&make_cqe(true, 2)).expect("slot 1");
        assert_eq!(r.head(), 0, "wrapped to 0");
        assert!(!r.expected_phase(), "phase flipped on wrap");
        // Next slot 0 with phase=true is stale → reject.
        assert!(r.try_take(&make_cqe(true, 999)).is_none());
        // Slot 0 with phase=false (the new expected) → consume.
        let f = r.try_take(&make_cqe(false, 100)).expect("new lap");
        assert_eq!(f.cid, 100);
        assert_eq!(r.head(), 1);
    }

    #[test]
    fn cq_two_full_laps_restore_phase() {
        let mut r = CqRing::new(2).expect("ok");
        // Lap 0: phase=true for both slots.
        r.try_take(&make_cqe(true, 0)).expect("L0 S0");
        r.try_take(&make_cqe(true, 1)).expect("L0 S1");
        assert!(!r.expected_phase());
        // Lap 1: phase=false for both slots.
        r.try_take(&make_cqe(false, 2)).expect("L1 S0");
        r.try_take(&make_cqe(false, 3)).expect("L1 S1");
        assert!(r.expected_phase(), "phase restored after second wrap");
        assert_eq!(r.head(), 0);
    }

    #[test]
    fn cq_capacity_one_wraps_every_take() {
        // Degenerate ring with a single CQE slot — phase flips on
        // every take.
        let mut r = CqRing::new(1).expect("ok");
        let initial_phase = r.expected_phase();
        r.try_take(&make_cqe(initial_phase, 1)).expect("take 0");
        assert_eq!(r.head(), 0);
        assert_eq!(r.expected_phase(), !initial_phase);
    }

    // -------------------------------------------------------------------
    // Cross-ring invariants
    // -------------------------------------------------------------------

    #[test]
    fn ring_error_variants_are_distinguishable() {
        // Tripwire on the `#[non_exhaustive]` taxonomy — verifies the
        // two error variants pin to distinct discriminants.
        assert_ne!(RingError::CapacityZero, RingError::CapacityTooLarge);
    }
}

//! xHCI ring-buffer state machines: Command, Event, and Transfer rings.
//!
//! All three ring types are **pure state** — they track pointer indices and
//! cycle bits but do not allocate memory, perform DMA, or touch MMIO.
//! The image crate owns the backing DMA pages and provides them by reference
//! when calling the produce / consume methods.
//!
//! ## Cycle bit semantics (xHCI § 4.9.2)
//!
//! The xHCI cycle bit is the mechanism by which producer and consumer
//! distinguish "this TRB has been filled this lap" from "this slot was
//! filled on a previous lap":
//!
//! - **Command ring / Transfer ring (driver-produced)**: the driver writes TRBs
//!   with the current Producer Cycle State (PCS). The last slot is always a Link
//!   TRB with `TC=1` (Toggle Cycle); when the producer wraps through it the PCS
//!   flips and the Link TRB itself carries the pre-flip cycle bit.
//!
//! - **Event ring (device-produced)**: the driver reads TRBs from the ring and
//!   accepts only those whose cycle bit matches the Consumer Cycle State (CCS).
//!   When the dequeue pointer wraps, the CCS flips. This is mechanically
//!   identical to the NVMe CQ phase-tag pattern in `nexacore-driver-nvme::ring`.
//!
//! ## Capacity
//!
//! For Command and Transfer rings: one slot is permanently occupied by the
//! Link TRB, so `usable_capacity = capacity - 1`.
//!
//! For Event rings: every slot is usable (the Event Ring Segment Table (ERST)
//! is managed separately by the image crate); the full `capacity` slots are
//! available for device-written events.

use crate::trb::{Trb, link_trb};

// =============================================================================
// RingError
// =============================================================================

/// Reason a ring helper could not complete an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RingError {
    /// The ring was constructed with `capacity = 0` or `capacity = 1`.
    ///
    /// A capacity-1 ring can hold no usable TRBs (the only slot is the Link
    /// TRB). The minimum useful capacity for Command / Transfer rings is 2.
    CapacityTooSmall,
    /// The requested capacity exceeds 2^16 - 1.
    ///
    /// The xHCI spec does not impose a hard limit here, but the ring indices
    /// are tracked as `u16` for compactness; values beyond `u16::MAX` would
    /// silently overflow.
    CapacityTooLarge,
}

// =============================================================================
// CommandRing — driver-produced, device-consumed
// =============================================================================

/// Command Ring bookkeeping (xHCI § 4.9.2, driver-produced).
///
/// The driver enqueues command TRBs into the ring and notifies the controller
/// by writing the Command Ring doorbell (slot 0). The last physical slot is
/// always a Link TRB that points back to slot 0 and has `TC=1` (Toggle
/// Cycle), causing the Producer Cycle State to flip on wrap.
///
/// `capacity` includes the Link TRB slot; `usable_capacity = capacity - 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandRing {
    /// Total number of TRB slots, including the Link TRB.
    capacity: u16,
    /// Index of the next slot the driver will write into (0-based).
    ///
    /// Invariant: `enqueue_ptr < capacity`. Slot `capacity - 1` is the Link
    /// TRB; `enqueue_ptr` advances to 0 (with a PCS flip) when it reaches
    /// the Link slot.
    enqueue_ptr: u16,
    /// Current Producer Cycle State.
    ///
    /// All TRBs written to the ring (including the Link TRB) carry this bit.
    /// Flips whenever the enqueue pointer wraps through the Link TRB.
    producer_cycle: bool,
}

impl CommandRing {
    /// Construct an empty Command Ring with `capacity` total slots.
    ///
    /// `capacity` must be `>= 2` (one usable slot + one Link slot) and
    /// `<= u16::MAX`.
    ///
    /// The initial Producer Cycle State is `true` (1), matching the `RCS`
    /// bit that the driver programs into `CRCR.RCS` at bring-up.
    ///
    /// # Errors
    ///
    /// - [`RingError::CapacityTooSmall`] when `capacity < 2`.
    /// - [`RingError::CapacityTooLarge`] when `capacity > u16::MAX`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::ring::CommandRing;
    ///
    /// let r = CommandRing::new(64).unwrap();
    /// assert_eq!(r.usable_capacity(), 63);
    /// assert!(r.producer_cycle());
    /// ```
    pub const fn new(capacity: u32) -> Result<Self, RingError> {
        if capacity < 2 {
            return Err(RingError::CapacityTooSmall);
        }
        #[allow(
            clippy::cast_lossless,
            reason = "u32::from(u16::MAX) is not yet const; this widen is lossless"
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
            enqueue_ptr: 0,
            producer_cycle: true,
        })
    }

    /// Physical capacity (total TRB slots, including the Link TRB).
    #[must_use]
    pub const fn capacity(self) -> u16 {
        self.capacity
    }

    /// Usable capacity (slots available for commands, excluding Link TRB).
    #[must_use]
    pub const fn usable_capacity(self) -> u16 {
        // capacity >= 2 by construction; subtraction does not wrap.
        self.capacity - 1
    }

    /// Current enqueue pointer (index of the next slot to write).
    #[must_use]
    pub const fn enqueue_ptr(self) -> u16 {
        self.enqueue_ptr
    }

    /// Current Producer Cycle State.
    #[must_use]
    pub const fn producer_cycle(self) -> bool {
        self.producer_cycle
    }

    /// Claim the next command slot and return its index.
    ///
    /// The caller MUST:
    /// 1. Write the command TRB into the DMA page at `slot_index * 16`, with
    ///    the cycle bit set to [`Self::producer_cycle`].
    /// 2. Ensure the last physical slot (`capacity - 1`) contains the Link TRB
    ///    constructed by [`Self::build_link_trb`] (this is set once at ring
    ///    initialisation and refreshed on every wrap).
    /// 3. Ring the command ring doorbell (slot 0) with `0` (the doorbell DB
    ///    Target field for the command ring is `0` per xHCI § 6.3).
    ///
    /// The image crate is responsible for tracking outstanding commands and not
    /// submitting more than `usable_capacity` at once without draining events.
    pub fn enqueue(&mut self) -> u16 {
        // The Link TRB occupies the last slot; the enqueue pointer must not
        // land there (the driver writes through it automatically on wrap).
        let link_slot = self.capacity - 1;
        if self.enqueue_ptr == link_slot {
            // The pointer reached the Link TRB slot — wrap to 0, flip PCS.
            self.producer_cycle = !self.producer_cycle;
            self.enqueue_ptr = 0;
        }
        let slot = self.enqueue_ptr;
        let next = if slot + 1 == link_slot {
            // Next slot would be the Link — wrap will occur on the next call.
            slot + 1
        } else if slot + 1 >= self.capacity {
            0
        } else {
            slot + 1
        };
        self.enqueue_ptr = next;
        slot
    }

    /// Build the Link TRB that must occupy slot `capacity - 1`.
    ///
    /// `ring_base_ptr` is the 64-bit IOVA of slot 0 of this ring. The Link
    /// TRB wraps the pointer back to `ring_base_ptr` and has `TC = 1` so the
    /// controller toggles the cycle bit on wrap.
    ///
    /// The Link TRB carries the **current** `producer_cycle` bit so the
    /// controller recognises it as belonging to the current lap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::{ring::CommandRing, trb::TRB_TYPE_LINK};
    ///
    /// let r = CommandRing::new(8).unwrap();
    /// let link = r.build_link_trb(0x0010_0000);
    /// assert_eq!(link.trb_type(), TRB_TYPE_LINK);
    /// ```
    #[must_use]
    pub fn build_link_trb(self, ring_base_ptr: u64) -> Trb {
        link_trb(ring_base_ptr, true, self.producer_cycle)
    }
}

// =============================================================================
// TransferRing — driver-produced, device-consumed (per endpoint)
// =============================================================================

/// Transfer Ring bookkeeping (xHCI § 4.9.2, driver-produced, per-endpoint).
///
/// Mechanically identical to [`CommandRing`] but used for data transfers on
/// a specific endpoint. Each endpoint has its own transfer ring; the image
/// crate maintains one `TransferRing` per active endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRing {
    capacity: u16,
    enqueue_ptr: u16,
    producer_cycle: bool,
}

impl TransferRing {
    /// Construct an empty Transfer Ring.
    ///
    /// Same capacity constraints as [`CommandRing::new`].
    ///
    /// # Errors
    ///
    /// - [`RingError::CapacityTooSmall`] when `capacity < 2`.
    /// - [`RingError::CapacityTooLarge`] when `capacity > u16::MAX`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::ring::TransferRing;
    ///
    /// let r = TransferRing::new(64).unwrap();
    /// assert_eq!(r.usable_capacity(), 63);
    /// ```
    pub const fn new(capacity: u32) -> Result<Self, RingError> {
        if capacity < 2 {
            return Err(RingError::CapacityTooSmall);
        }
        #[allow(clippy::cast_lossless, reason = "lossless widen for const context")]
        let max = u16::MAX as u32;
        if capacity > max {
            return Err(RingError::CapacityTooLarge);
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "guarded by capacity bound check"
        )]
        Ok(Self {
            capacity: capacity as u16,
            enqueue_ptr: 0,
            producer_cycle: true,
        })
    }

    /// Physical capacity (including the Link TRB slot).
    #[must_use]
    pub const fn capacity(self) -> u16 {
        self.capacity
    }

    /// Usable capacity (excluding the Link TRB slot).
    #[must_use]
    pub const fn usable_capacity(self) -> u16 {
        self.capacity - 1
    }

    /// Current enqueue pointer.
    #[must_use]
    pub const fn enqueue_ptr(self) -> u16 {
        self.enqueue_ptr
    }

    /// Current Producer Cycle State.
    #[must_use]
    pub const fn producer_cycle(self) -> bool {
        self.producer_cycle
    }

    /// Claim the next transfer slot and return its index.
    ///
    /// The image crate must not submit more than `usable_capacity` TRBs
    /// without draining completions. Semantics identical to
    /// [`CommandRing::enqueue`].
    pub fn enqueue(&mut self) -> u16 {
        let link_slot = self.capacity - 1;
        if self.enqueue_ptr == link_slot {
            self.producer_cycle = !self.producer_cycle;
            self.enqueue_ptr = 0;
        }
        let slot = self.enqueue_ptr;
        let next = if slot + 1 == link_slot {
            slot + 1
        } else if slot + 1 >= self.capacity {
            0
        } else {
            slot + 1
        };
        self.enqueue_ptr = next;
        slot
    }

    /// Build the Link TRB for slot `capacity - 1`.
    #[must_use]
    pub fn build_link_trb(self, ring_base_ptr: u64) -> Trb {
        link_trb(ring_base_ptr, true, self.producer_cycle)
    }

    /// Dequeue pointer value (IOVA) for the Endpoint Context `tr_dequeue_ptr`
    /// field, combining `ring_base_ptr` (the IOVA of slot 0) with the current
    /// `producer_cycle` bit packed into bit 0, as required by xHCI § 6.2.3.
    ///
    /// The address is already 16-byte aligned (TRBs are 16 bytes); bit 0 of
    /// the address carries the DCS (Dequeue Cycle State) bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::ring::TransferRing;
    ///
    /// let r = TransferRing::new(64).unwrap();
    /// let dcs_ptr = r.dequeue_ptr_with_dcs(0x0040_0000);
    /// // Bit 0 set because initial producer_cycle = true.
    /// assert_eq!(dcs_ptr & 0x1, 1);
    /// assert_eq!(dcs_ptr & !0xF, 0x0040_0000);
    /// ```
    #[must_use]
    pub fn dequeue_ptr_with_dcs(self, ring_base_ptr: u64) -> u64 {
        let base = ring_base_ptr & !0xF; // 16-byte aligned
        if self.producer_cycle {
            base | 0x1
        } else {
            base
        }
    }
}

// =============================================================================
// EventRing — device-produced, driver-consumed
// =============================================================================

/// Event Ring bookkeeping (xHCI § 4.9.4, device-produced, driver-consumed).
///
/// The xHC writes events into the ring with the current producer cycle bit;
/// the driver reads them when the cycle bit matches the Consumer Cycle State
/// (CCS). On every segment wrap the CCS flips — identical to NVMe's CQ
/// phase-tag mechanism.
///
/// TASK-26 uses a single-segment event ring. The image crate sets up the
/// Event Ring Segment Table (ERST) with one entry pointing to the DMA page,
/// and programs `ERSTSZ = 1`, `ERSTBA`, and the initial `ERDP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventRing {
    /// Total number of TRB slots in the segment.
    capacity: u16,
    /// Index of the next slot the driver will inspect.
    dequeue_ptr: u16,
    /// Current Consumer Cycle State. The driver only accepts TRBs whose
    /// cycle bit matches this value.
    consumer_cycle: bool,
}

impl EventRing {
    /// Construct an empty Event Ring with `capacity` slots.
    ///
    /// `capacity` must be `>= 1` and `<= u16::MAX`.
    ///
    /// The initial Consumer Cycle State is `true` (1), matching the initial
    /// cycle state the xHC uses when it first fills the ring.
    ///
    /// # Errors
    ///
    /// - [`RingError::CapacityTooSmall`] when `capacity == 0`.
    /// - [`RingError::CapacityTooLarge`] when `capacity > u16::MAX`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::ring::EventRing;
    ///
    /// let r = EventRing::new(128).unwrap();
    /// assert_eq!(r.dequeue_ptr(), 0);
    /// assert!(r.consumer_cycle());
    /// ```
    pub const fn new(capacity: u32) -> Result<Self, RingError> {
        if capacity == 0 {
            return Err(RingError::CapacityTooSmall);
        }
        #[allow(clippy::cast_lossless, reason = "lossless widen for const context")]
        let max = u16::MAX as u32;
        if capacity > max {
            return Err(RingError::CapacityTooLarge);
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "guarded by capacity bound check"
        )]
        Ok(Self {
            capacity: capacity as u16,
            dequeue_ptr: 0,
            consumer_cycle: true,
        })
    }

    /// Physical capacity.
    #[must_use]
    pub const fn capacity(self) -> u16 {
        self.capacity
    }

    /// Current dequeue pointer (index of the next slot to inspect).
    #[must_use]
    pub const fn dequeue_ptr(self) -> u16 {
        self.dequeue_ptr
    }

    /// Current Consumer Cycle State.
    #[must_use]
    pub const fn consumer_cycle(self) -> bool {
        self.consumer_cycle
    }

    /// Attempt to dequeue the next event TRB.
    ///
    /// The caller passes the `Trb` read from the DMA page at
    /// `dequeue_ptr * 16`. The ring inspects the cycle bit:
    ///
    /// - If `trb.cycle_bit() == consumer_cycle`, the TRB belongs to the
    ///   current lap: advance the dequeue pointer (flipping `consumer_cycle`
    ///   on segment wrap) and return `Some(trb)`.
    /// - Otherwise the slot belongs to a previous lap and the controller has
    ///   not yet written a new event here: return `None` without mutating state.
    ///
    /// The caller MUST write back the new `ERDP` (using
    /// [`Self::erdp_value`]) after each successful dequeue so the controller
    /// knows the slot is free.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::{
    ///     ring::EventRing,
    ///     trb::{TRB_TYPE_COMMAND_COMPLETION_EVENT, Trb},
    /// };
    ///
    /// let mut ring = EventRing::new(4).unwrap();
    /// // Slot 0 with cycle=true (matches initial CCS=true).
    /// let dw3: u32 = ((TRB_TYPE_COMMAND_COMPLETION_EVENT as u32) << 10) | 0x1;
    /// let trb = Trb::from_dwords([0, 0, 0, dw3]);
    /// let consumed = ring.try_dequeue(trb);
    /// assert!(consumed.is_some());
    /// assert_eq!(ring.dequeue_ptr(), 1);
    /// ```
    pub fn try_dequeue(&mut self, trb: Trb) -> Option<Trb> {
        if trb.cycle_bit() != self.consumer_cycle {
            return None;
        }
        // Advance dequeue pointer; flip CCS on wrap.
        let next = self.dequeue_ptr + 1;
        if next >= self.capacity {
            self.consumer_cycle = !self.consumer_cycle;
            self.dequeue_ptr = 0;
        } else {
            self.dequeue_ptr = next;
        }
        Some(trb)
    }

    /// Compute the `ERDP` value to write after consuming events.
    ///
    /// `ring_base_iova` is the IOVA of the first slot of the event ring
    /// segment. The `ERDP` value is `ring_base_iova + dequeue_ptr * 16`,
    /// with the `EHB` bit (bit 3) set to clear the Event Handler Busy flag
    /// per xHCI § 5.5.2.5.
    ///
    /// Returns `None` on overflow (defence-in-depth — the product of
    /// `u16::MAX * 16` fits in `u64`; the checked path costs nothing).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::{regs::ERDP_EHB, ring::EventRing};
    ///
    /// let r = EventRing::new(128).unwrap();
    /// let base: u64 = 0x0050_0000;
    /// // dequeue_ptr = 0 at construction → ERDP = base | EHB.
    /// let erdp = r.erdp_value(base).unwrap();
    /// assert!((erdp & ERDP_EHB) != 0, "EHB bit must be set");
    /// // Strip EHB to recover the base pointer.
    /// assert_eq!(erdp & !ERDP_EHB, base);
    /// ```
    #[must_use]
    pub fn erdp_value(self, ring_base_iova: u64) -> Option<u64> {
        let offset = u64::from(self.dequeue_ptr).checked_mul(16)?;
        let ptr = ring_base_iova.checked_add(offset)?;
        // Set EHB (bit 3) to signal that the event handler is no longer busy.
        Some(ptr | crate::regs::ERDP_EHB)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trb::{TRB_TYPE_COMMAND_COMPLETION_EVENT, TRB_TYPE_ENABLE_SLOT};

    // Helper: build a TRB with a given cycle bit and type.
    fn make_trb(cycle: bool, trb_type: u8) -> Trb {
        let mut dw3: u32 = (u32::from(trb_type) & 0x3F) << 10;
        if cycle {
            dw3 |= 0x1;
        }
        Trb::from_dwords([0, 0, 0, dw3])
    }

    // =========================================================================
    // CommandRing
    // =========================================================================

    #[test]
    fn command_ring_rejects_capacity_zero() {
        assert_eq!(CommandRing::new(0), Err(RingError::CapacityTooSmall));
    }

    #[test]
    fn command_ring_rejects_capacity_one() {
        assert_eq!(CommandRing::new(1), Err(RingError::CapacityTooSmall));
    }

    #[test]
    fn command_ring_rejects_capacity_too_large() {
        assert_eq!(
            CommandRing::new(u32::from(u16::MAX) + 1),
            Err(RingError::CapacityTooLarge)
        );
    }

    #[test]
    fn command_ring_usable_capacity() {
        let r = CommandRing::new(64).unwrap();
        assert_eq!(r.usable_capacity(), 63);
        assert_eq!(r.capacity(), 64);
    }

    #[test]
    fn command_ring_initial_state() {
        let r = CommandRing::new(8).unwrap();
        assert_eq!(r.enqueue_ptr(), 0);
        assert!(r.producer_cycle(), "initial PCS = true");
    }

    #[test]
    fn command_ring_enqueue_advances_ptr() {
        let mut r = CommandRing::new(8).unwrap();
        assert_eq!(r.enqueue(), 0);
        assert_eq!(r.enqueue_ptr(), 1);
        assert_eq!(r.enqueue(), 1);
        assert_eq!(r.enqueue_ptr(), 2);
    }

    #[test]
    fn command_ring_wraps_through_link_trb_and_flips_cycle() {
        // capacity = 4 → slots 0,1,2 usable, slot 3 = Link TRB.
        let mut r = CommandRing::new(4).unwrap();
        // Enqueue slots 0, 1, 2.
        assert_eq!(r.enqueue(), 0);
        assert_eq!(r.enqueue(), 1);
        assert_eq!(r.enqueue(), 2);
        // enqueue_ptr is now at slot 3 (the Link TRB slot).
        assert_eq!(r.enqueue_ptr(), 3);
        // PCS is still true before the wrap.
        assert!(r.producer_cycle());
        // Next enqueue should wrap through slot 3 → back to 0 and flip PCS.
        let slot = r.enqueue();
        assert_eq!(slot, 0, "wrapped back to slot 0");
        assert!(!r.producer_cycle(), "PCS flipped after Link TRB wrap");
    }

    #[test]
    fn command_ring_double_wrap_restores_pcs() {
        // capacity = 3 → 2 usable + 1 Link.
        let mut r = CommandRing::new(3).unwrap();
        // First wrap.
        r.enqueue(); // slot 0
        r.enqueue(); // slot 1 = Link slot; next call wraps
        r.enqueue(); // wraps → slot 0, PCS=false
        assert!(!r.producer_cycle());
        // Second wrap.
        r.enqueue(); // slot 1 = Link slot again
        r.enqueue(); // wraps → slot 0, PCS=true
        assert!(r.producer_cycle(), "PCS restored after second wrap");
    }

    #[test]
    fn command_ring_build_link_trb() {
        use crate::trb::TRB_TYPE_LINK;
        let r = CommandRing::new(8).unwrap();
        let link = r.build_link_trb(0x0010_0000);
        assert_eq!(link.trb_type(), TRB_TYPE_LINK);
        // Initial PCS = true → Link TRB cycle bit = true.
        assert!(link.cycle_bit());
        // TC bit (bit 1 of DWord 3) must be set.
        assert!((link.dwords()[3] >> 1) & 1 != 0, "TC bit must be set");
    }

    // =========================================================================
    // TransferRing
    // =========================================================================

    #[test]
    fn transfer_ring_rejects_capacity_too_small() {
        assert_eq!(TransferRing::new(0), Err(RingError::CapacityTooSmall));
        assert_eq!(TransferRing::new(1), Err(RingError::CapacityTooSmall));
    }

    #[test]
    fn transfer_ring_usable_capacity() {
        let r = TransferRing::new(64).unwrap();
        assert_eq!(r.usable_capacity(), 63);
    }

    #[test]
    fn transfer_ring_enqueue_wraps_and_flips_cycle() {
        let mut r = TransferRing::new(3).unwrap();
        assert_eq!(r.enqueue(), 0);
        // enqueue_ptr is now 1; next call hits the Link TRB slot (2).
        // Actually with capacity 3: usable = 2, Link at slot 2.
        // After slot 0 is enqueued, ptr advances to 1.
        assert_eq!(r.enqueue(), 1);
        // Now enqueue_ptr = 2 (Link slot). Next call wraps.
        assert!(r.producer_cycle());
        let slot = r.enqueue();
        assert_eq!(slot, 0);
        assert!(!r.producer_cycle(), "PCS flipped on wrap");
    }

    #[test]
    fn transfer_ring_dequeue_ptr_with_dcs() {
        let r = TransferRing::new(64).unwrap();
        let base: u64 = 0x0040_0000;
        let dcs_ptr = r.dequeue_ptr_with_dcs(base);
        // Initial PCS = true → DCS bit = 1.
        assert_eq!(dcs_ptr & 0x1, 1);
        assert_eq!(dcs_ptr & !0xF, base);
    }

    // =========================================================================
    // EventRing
    // =========================================================================

    #[test]
    fn event_ring_rejects_capacity_zero() {
        assert_eq!(EventRing::new(0), Err(RingError::CapacityTooSmall));
    }

    #[test]
    fn event_ring_initial_state() {
        let r = EventRing::new(128).unwrap();
        assert_eq!(r.dequeue_ptr(), 0);
        assert!(r.consumer_cycle(), "initial CCS = true");
    }

    #[test]
    fn event_ring_try_dequeue_matching_cycle_advances_ptr() {
        let mut r = EventRing::new(4).unwrap();
        let trb = make_trb(true, TRB_TYPE_COMMAND_COMPLETION_EVENT);
        let consumed = r.try_dequeue(trb);
        assert!(consumed.is_some());
        assert_eq!(r.dequeue_ptr(), 1);
        assert!(r.consumer_cycle(), "no wrap yet");
    }

    #[test]
    fn event_ring_try_dequeue_mismatched_cycle_returns_none() {
        let mut r = EventRing::new(4).unwrap();
        // Initial CCS = true; TRB with cycle = false → mismatch.
        let trb = make_trb(false, TRB_TYPE_COMMAND_COMPLETION_EVENT);
        assert!(r.try_dequeue(trb).is_none());
        // State must not change.
        assert_eq!(r.dequeue_ptr(), 0);
        assert!(r.consumer_cycle());
    }

    #[test]
    fn event_ring_wraps_and_flips_consumer_cycle() {
        let mut r = EventRing::new(2).unwrap();
        // Consume slot 0 (cycle=true).
        r.try_dequeue(make_trb(true, TRB_TYPE_ENABLE_SLOT)).unwrap();
        assert_eq!(r.dequeue_ptr(), 1);
        assert!(r.consumer_cycle(), "lap 0 still");
        // Consume slot 1 (cycle=true) → wraps to 0, CCS flips.
        r.try_dequeue(make_trb(true, TRB_TYPE_ENABLE_SLOT)).unwrap();
        assert_eq!(r.dequeue_ptr(), 0, "wrapped to 0");
        assert!(!r.consumer_cycle(), "CCS flipped on wrap");
        // Slot 0 with old cycle (true) is now stale.
        assert!(
            r.try_dequeue(make_trb(true, TRB_TYPE_ENABLE_SLOT))
                .is_none()
        );
        // Slot 0 with new cycle (false) is fresh.
        r.try_dequeue(make_trb(false, TRB_TYPE_ENABLE_SLOT))
            .unwrap();
    }

    #[test]
    fn event_ring_two_laps_restores_ccs() {
        let mut r = EventRing::new(2).unwrap();
        // Lap 0: cycle = true.
        r.try_dequeue(make_trb(true, TRB_TYPE_ENABLE_SLOT)).unwrap();
        r.try_dequeue(make_trb(true, TRB_TYPE_ENABLE_SLOT)).unwrap();
        assert!(!r.consumer_cycle());
        // Lap 1: cycle = false.
        r.try_dequeue(make_trb(false, TRB_TYPE_ENABLE_SLOT))
            .unwrap();
        r.try_dequeue(make_trb(false, TRB_TYPE_ENABLE_SLOT))
            .unwrap();
        assert!(r.consumer_cycle(), "CCS restored after two laps");
        assert_eq!(r.dequeue_ptr(), 0);
    }

    #[test]
    fn event_ring_erdp_value_includes_ehb() {
        let r = EventRing::new(128).unwrap();
        let base: u64 = 0x0050_0000;
        let erdp = r.erdp_value(base).unwrap();
        // EHB is bit 3; base is 16-byte aligned so bits 3:0 are normally 0.
        assert!((erdp & crate::regs::ERDP_EHB) != 0, "EHB must be set");
        assert_eq!(erdp & !0xF, base);
    }

    #[test]
    fn event_ring_capacity_one_wraps_every_dequeue() {
        let mut r = EventRing::new(1).unwrap();
        r.try_dequeue(make_trb(true, TRB_TYPE_ENABLE_SLOT)).unwrap();
        assert_eq!(r.dequeue_ptr(), 0, "wrapped back to 0");
        assert!(!r.consumer_cycle(), "CCS flipped");
    }

    #[test]
    fn ring_error_variants_distinguishable() {
        assert_ne!(RingError::CapacityTooSmall, RingError::CapacityTooLarge);
    }
}

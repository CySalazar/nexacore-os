//! Domain identifier allocator shared by both vendor backends.
//!
//! ## Scope
//!
//! Both VT-d (16-bit `DOMAIN_ID` in the second-level context entry)
//! and AMD-Vi (16-bit `DomainID` in the device-table entry) require
//! the kernel to assign one identifier per driver process and recycle
//! identifiers when the driver exits. This module provides the
//! vendor-neutral accounting layer.
//!
//! The allocator is a fixed-capacity bitmap; the capacity is chosen
//! at construction time and may not exceed [`HARD_CAP_DOMAINS`] =
//! 65 536 (the full 16-bit ID space). The first identifier returned
//! is always `0`, which is the conventional **passthrough domain**
//! used during bring-up; callers that want to reserve it differently
//! can call [`DomainAllocator::reserve`] before any [`alloc`] call.
//!
//! ## Why a bitmap and not a free-list
//!
//! - The 16-bit ID space fits in 8 KiB of bits — trivially `Vec`-able
//!   on the bare-metal `BumpHeap`.
//! - A bitmap gives O(1) `free`/`is_allocated` and bounded O(N/64)
//!   `alloc` — the existing `nexacore-kernel` style favours bounded loops
//!   over linked structures (see ADR-0007 *Heap-pressure budget*).
//! - The hint-cursor amortises typical alloc cost to O(1).

extern crate alloc;

use alloc::vec::Vec;

use super::DomainId;

/// Hard upper bound on the allocator capacity (full 16-bit ID space).
pub const HARD_CAP_DOMAINS: usize = 65_536;

/// Default capacity used when [`DomainAllocator::new`] is called without an explicit cap.
///
/// 1 024 covers any Phase 1 deployment (driver-per-PCI-device + a few service
/// domains) without dragging 8 KiB of bitmap into the allocator at boot.
pub const DEFAULT_CAPACITY: u16 = 1024;

/// Reasons [`DomainAllocator`] methods can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// No free slots remain.
    Exhausted,
    /// [`DomainAllocator::free`] was called on an identifier that was
    /// already free. Defensive — surfaces double-free bugs.
    AlreadyFree,
    /// The identifier exceeds the allocator's capacity.
    OutOfRange,
}

/// Fixed-capacity bitmap allocator over 16-bit domain identifiers.
#[derive(Debug, Clone)]
pub struct DomainAllocator {
    /// One bit per identifier; LSB-first within each byte.
    bitmap: Vec<u8>,
    /// Capacity in identifiers (not bytes).
    capacity: u16,
    /// Number of currently-allocated identifiers (for O(1)
    /// `allocated_count`).
    allocated: usize,
    /// Hint for the next linear scan; amortises typical alloc to O(1).
    hint: u16,
}

impl DomainAllocator {
    /// Build an allocator that hands out at most `capacity`
    /// identifiers.
    ///
    /// `capacity` is clamped to `[1, HARD_CAP_DOMAINS]`. The allocator
    /// is initialised with every slot free.
    #[must_use]
    pub fn new(capacity: u16) -> Self {
        let cap = capacity.max(1);
        let byte_count = (cap as usize).div_ceil(8);
        Self {
            bitmap: alloc::vec![0u8; byte_count],
            capacity: cap,
            allocated: 0,
            hint: 0,
        }
    }

    /// Convenience constructor with [`DEFAULT_CAPACITY`].
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Capacity in identifiers.
    #[must_use]
    pub fn capacity(&self) -> u16 {
        self.capacity
    }

    /// Number of currently-allocated identifiers.
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.allocated
    }

    /// `true` iff every slot is consumed.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.allocated >= self.capacity as usize
    }

    /// `true` iff `id` is currently allocated.
    #[must_use]
    pub fn is_allocated(&self, id: DomainId) -> bool {
        let raw = id.raw();
        if raw >= self.capacity {
            return false;
        }
        #[allow(
            clippy::integer_division,
            reason = "u16 / 8 is the canonical bitmap byte index; no precision loss possible on integer operands"
        )]
        let byte_idx = (raw / 8) as usize;
        let bit_idx = raw % 8;
        self.bitmap
            .get(byte_idx)
            .is_some_and(|byte| (byte >> bit_idx) & 0x1 == 1)
    }

    /// Allocate the lowest free identifier.
    ///
    /// # Errors
    ///
    /// [`AllocError::Exhausted`] when no free slot remains.
    pub fn alloc(&mut self) -> Result<DomainId, AllocError> {
        if self.is_exhausted() {
            return Err(AllocError::Exhausted);
        }
        // Search from `hint` to capacity, then wrap to 0 to cover any
        // slots freed below the hint.
        let cap = self.capacity;
        let hint = self.hint;
        for raw in hint..cap {
            if !self.is_allocated(DomainId::new(raw)) {
                self.set_bit(raw, true);
                self.allocated += 1;
                self.hint = raw.saturating_add(1);
                return Ok(DomainId::new(raw));
            }
        }
        for raw in 0..hint {
            if !self.is_allocated(DomainId::new(raw)) {
                self.set_bit(raw, true);
                self.allocated += 1;
                self.hint = raw.saturating_add(1);
                return Ok(DomainId::new(raw));
            }
        }
        // Defensive: bookkeeping disagreed with the bitmap walk.
        Err(AllocError::Exhausted)
    }

    /// Mark `id` as allocated without going through [`alloc`].
    ///
    /// Used for boot-time reservation (e.g. domain `0` for
    /// passthrough). Returns `Ok(())` if the slot was free and is now
    /// taken; `Err(AllocError::AlreadyFree)` is reused for the
    /// double-reserve case to keep the error taxonomy compact.
    ///
    /// # Errors
    ///
    /// - [`AllocError::OutOfRange`] when `id` exceeds capacity.
    /// - [`AllocError::AlreadyFree`] when `id` was already allocated
    ///   (i.e. "tried to reserve a taken slot" — reuses the variant
    ///   because the underlying invariant is the same: caller and
    ///   allocator disagree on whether the slot is free).
    pub fn reserve(&mut self, id: DomainId) -> Result<(), AllocError> {
        let raw = id.raw();
        if raw >= self.capacity {
            return Err(AllocError::OutOfRange);
        }
        if self.is_allocated(id) {
            return Err(AllocError::AlreadyFree);
        }
        self.set_bit(raw, true);
        self.allocated += 1;
        Ok(())
    }

    /// Return `id` to the free pool.
    ///
    /// # Errors
    ///
    /// - [`AllocError::OutOfRange`] when `id` exceeds capacity.
    /// - [`AllocError::AlreadyFree`] when `id` was not allocated.
    pub fn free(&mut self, id: DomainId) -> Result<(), AllocError> {
        let raw = id.raw();
        if raw >= self.capacity {
            return Err(AllocError::OutOfRange);
        }
        if !self.is_allocated(id) {
            return Err(AllocError::AlreadyFree);
        }
        self.set_bit(raw, false);
        self.allocated = self.allocated.saturating_sub(1);
        // Lower the hint so the next `alloc` reclaims the slot fast.
        if raw < self.hint {
            self.hint = raw;
        }
        Ok(())
    }

    fn set_bit(&mut self, raw: u16, value: bool) {
        #[allow(
            clippy::integer_division,
            reason = "u16 / 8 is the canonical bitmap byte index; no precision loss possible on integer operands"
        )]
        let byte_idx = (raw / 8) as usize;
        let bit_idx = raw % 8;
        if let Some(byte) = self.bitmap.get_mut(byte_idx) {
            let mask = 1u8 << bit_idx;
            if value {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
        }
    }
}

impl Default for DomainAllocator {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::{AllocError, DEFAULT_CAPACITY, DomainAllocator, HARD_CAP_DOMAINS};
    use crate::bare_metal::iommu::DomainId;

    #[test]
    fn new_starts_empty() {
        let alloc = DomainAllocator::new(64);
        assert_eq!(alloc.allocated_count(), 0);
        assert_eq!(alloc.capacity(), 64);
        assert!(!alloc.is_exhausted());
        assert!(!alloc.is_allocated(DomainId::new(0)));
        assert!(!alloc.is_allocated(DomainId::new(63)));
    }

    #[test]
    fn default_uses_default_capacity() {
        let alloc = DomainAllocator::default();
        assert_eq!(alloc.capacity(), DEFAULT_CAPACITY);
    }

    #[test]
    fn alloc_returns_zero_then_one_then_two() {
        let mut alloc = DomainAllocator::new(16);
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(0));
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(1));
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(2));
        assert_eq!(alloc.allocated_count(), 3);
        assert!(alloc.is_allocated(DomainId::new(0)));
        assert!(alloc.is_allocated(DomainId::new(1)));
        assert!(alloc.is_allocated(DomainId::new(2)));
        assert!(!alloc.is_allocated(DomainId::new(3)));
    }

    #[test]
    fn alloc_to_exhaustion() {
        let mut alloc = DomainAllocator::new(4);
        for expected in 0..4u16 {
            assert_eq!(alloc.alloc().unwrap(), DomainId::new(expected));
        }
        assert!(alloc.is_exhausted());
        assert_eq!(alloc.alloc(), Err(AllocError::Exhausted));
    }

    #[test]
    fn free_then_realloc_returns_lowest_free() {
        let mut alloc = DomainAllocator::new(8);
        let a = alloc.alloc().unwrap();
        let b = alloc.alloc().unwrap();
        let c = alloc.alloc().unwrap();
        assert_eq!(
            (a, b, c),
            (DomainId::new(0), DomainId::new(1), DomainId::new(2))
        );
        alloc.free(b).unwrap();
        assert_eq!(alloc.allocated_count(), 2);
        // The freed slot is now reclaimed first.
        let d = alloc.alloc().unwrap();
        assert_eq!(d, DomainId::new(1));
    }

    #[test]
    fn free_unallocated_returns_already_free() {
        let mut alloc = DomainAllocator::new(8);
        assert_eq!(alloc.free(DomainId::new(0)), Err(AllocError::AlreadyFree));
        // After alloc + free, double-free surfaces the same error.
        let id = alloc.alloc().unwrap();
        alloc.free(id).unwrap();
        assert_eq!(alloc.free(id), Err(AllocError::AlreadyFree));
    }

    #[test]
    fn free_out_of_range_returns_out_of_range() {
        let mut alloc = DomainAllocator::new(8);
        assert_eq!(alloc.free(DomainId::new(8)), Err(AllocError::OutOfRange));
        assert_eq!(
            alloc.free(DomainId::new(0xFFFF)),
            Err(AllocError::OutOfRange)
        );
    }

    #[test]
    fn reserve_marks_id_as_allocated() {
        let mut alloc = DomainAllocator::new(8);
        alloc.reserve(DomainId::new(3)).unwrap();
        assert!(alloc.is_allocated(DomainId::new(3)));
        assert_eq!(alloc.allocated_count(), 1);
        // Next alloc skips the reserved slot.
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(0));
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(1));
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(2));
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(4));
    }

    #[test]
    fn reserve_already_allocated_returns_already_free() {
        let mut alloc = DomainAllocator::new(8);
        alloc.reserve(DomainId::new(3)).unwrap();
        assert_eq!(
            alloc.reserve(DomainId::new(3)),
            Err(AllocError::AlreadyFree)
        );
    }

    #[test]
    fn reserve_out_of_range_returns_out_of_range() {
        let mut alloc = DomainAllocator::new(8);
        assert_eq!(alloc.reserve(DomainId::new(8)), Err(AllocError::OutOfRange));
    }

    #[test]
    fn capacity_zero_is_clamped_to_one() {
        let mut alloc = DomainAllocator::new(0);
        assert_eq!(alloc.capacity(), 1);
        assert_eq!(alloc.alloc().unwrap(), DomainId::new(0));
        assert_eq!(alloc.alloc(), Err(AllocError::Exhausted));
    }

    #[test]
    fn hint_wraps_to_zero_on_low_free() {
        // Allocate the first three, free slot 0, then verify the next
        // alloc finds it (wraparound path of the linear scan).
        let mut alloc = DomainAllocator::new(8);
        let a = alloc.alloc().unwrap();
        let _ = alloc.alloc().unwrap();
        let _ = alloc.alloc().unwrap();
        alloc.free(a).unwrap();
        let next = alloc.alloc().unwrap();
        assert_eq!(next, DomainId::new(0));
    }

    #[test]
    fn allocator_round_trip_under_pressure() {
        // Cycle through 32 alloc + free pairs over a 16-slot table.
        // Validates the allocated count and hint do not drift.
        let mut alloc = DomainAllocator::new(16);
        for _ in 0..32 {
            let id = alloc.alloc().unwrap();
            alloc.free(id).unwrap();
            assert_eq!(alloc.allocated_count(), 0);
        }
    }

    #[test]
    fn hard_cap_constant_matches_u16_space() {
        // Sanity check: HARD_CAP must equal 2^16 so the doc claim
        // about full 16-bit ID space holds.
        assert_eq!(HARD_CAP_DOMAINS, 1 << 16);
    }

    #[test]
    fn is_allocated_oob_returns_false() {
        let alloc = DomainAllocator::new(8);
        assert!(!alloc.is_allocated(DomainId::new(8)));
        assert!(!alloc.is_allocated(DomainId::new(0xFFFF)));
    }
}

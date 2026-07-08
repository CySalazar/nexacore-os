//! Per-process user-mode stack VA allocator (MB11, ADR-0004 § 5).
//!
//! Mirror of MB10's kernel stack pattern but in low VA with `PTE_USER`.
//! Each process owns a private bump allocator that hands out 16 KiB
//! stack slots from the range `[USER_STACK_VA_BASE, USER_STACK_VA_END)`,
//! with a 16 KiB guard page below each writable slot.
//!
//! Layout per slot:
//!
//! ```text
//!    addr (VA)                       contenuto                   mapping
//!    ────────────────────────────────────────────────────────────────────
//!    BASE + N * STRIDE                                            (none)        ┐
//!    BASE + N * STRIDE + 0x3FFF      <guard page — NOT mapped>    (none)        │ 16 KiB guard
//!    BASE + N * STRIDE + 0x4000      ↑ stack grows downward       PRESENT|WR|U  ┐
//!    BASE + N * STRIDE + 0x7FFF      stack top - 1                PRESENT|WR|U  ┘ 16 KiB stack
//! ```
//!
//! The slot allocator is **per-process** (lives inside
//! `ProcessControlBlock`), not global like MB10. This way each process
//! enumerates slots independently and process IDs are decoupled from
//! the user-stack range walk.

use super::{
    address_space::AddressSpace,
    paging::{PTE_NO_EXEC, PTE_PRESENT, PTE_USER, PTE_WRITABLE, PageMapper},
};
use crate::memory::{BitmapFrameAllocator, PhysAddr, VirtAddr};

/// Base of the per-process user-stack VA range (low half).
pub const USER_STACK_VA_BASE: u64 = 0x0000_0040_0000_0000;

/// Exclusive upper bound of the user-stack VA range — 2 GiB (≈ 64 K
/// process slots × 32 KiB stride). Plenty for Phase 1.
pub const USER_STACK_VA_END: u64 = 0x0000_0040_8000_0000;

/// Writable user-stack size per process, in bytes (16 KiB = 4 pages).
pub const USER_STACK_SIZE: u64 = 0x4000;

/// Address-space stride per slot: 16 KiB guard + 16 KiB stack = 32 KiB.
pub const USER_STACK_STRIDE: u64 = 0x8000;

/// Compute the writable-base VA of slot `n`. Returns `None` if `n` does
/// not fit inside `[USER_STACK_VA_BASE, USER_STACK_VA_END)`.
#[must_use]
pub fn slot_writable_base(n: u64) -> Option<u64> {
    let slot_base = USER_STACK_VA_BASE.checked_add(n.checked_mul(USER_STACK_STRIDE)?)?;
    let writable_base = slot_base.checked_add(USER_STACK_SIZE)?;
    let writable_top = writable_base.checked_add(USER_STACK_SIZE)?;
    if writable_top > USER_STACK_VA_END {
        return None;
    }
    Some(writable_base)
}

/// Allocate the next user-stack slot, map the writable 16 KiB into the
/// given address space, and return the **top** of the writable region
/// (the value to load as the initial RSP).
///
/// The 16 KiB guard page below the writable region is intentionally
/// not mapped, so a stack overflow generates `#PF` with `CR2` pointing
/// into the guard. The kernel's #PF handler can then deliver a fatal
/// signal to the offending process instead of corrupting another's
/// address space.
///
/// `next_slot` is the per-process counter; the caller increments it on
/// success. Returns `None` if either the bump range is exhausted, the
/// physical frame allocator runs out, or the mapping fails (which is
/// possible only if the VA range was already populated — a bug).
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "AddressSpace is the conceptual subject; pass-by-ref for callsite ergonomics"
)]
pub fn allocate_user_stack<const N: usize>(
    next_slot: &mut usize,
    address_space: &AddressSpace,
    mapper: &mut PageMapper,
    alloc: &mut BitmapFrameAllocator<N>,
) -> Option<u64> {
    let slot = *next_slot as u64;
    let writable_base = slot_writable_base(slot)?;

    // Map the 4 frames covering the writable region.
    #[allow(
        clippy::integer_division,
        reason = "USER_STACK_SIZE = 16 KiB / 4 KiB = 4 frames exactly"
    )]
    let num_pages = USER_STACK_SIZE / 4096;
    for page_i in 0..num_pages {
        let virt = VirtAddr(writable_base + page_i * 4096);
        let frame: PhysAddr = alloc.alloc_frame()?;
        let flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXEC;
        if !address_space.map_user_4k(mapper, virt, frame, flags, alloc) {
            return None;
        }
    }

    *next_slot = next_slot.checked_add(1)?;
    // RSP is decremented before writes, so the initial value points
    // ONE past the last writable byte (stack top, exclusive).
    Some(writable_base + USER_STACK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_slot_starts_after_guard_page() {
        let base = slot_writable_base(0).expect("slot 0");
        assert_eq!(base, USER_STACK_VA_BASE + USER_STACK_SIZE);
    }

    #[test]
    fn stride_matches_size_plus_guard() {
        assert_eq!(USER_STACK_STRIDE, 2 * USER_STACK_SIZE);
    }

    #[test]
    fn consecutive_slots_advance_by_stride() {
        let a = slot_writable_base(0).expect("slot 0");
        let b = slot_writable_base(1).expect("slot 1");
        assert_eq!(b - a, USER_STACK_STRIDE);
    }

    #[test]
    fn range_constants_fit_invariants() {
        assert_eq!(USER_STACK_VA_END - USER_STACK_VA_BASE, 2u64 << 30); // 2 GiB
        assert_eq!(USER_STACK_SIZE, 0x4000);
        assert_eq!(USER_STACK_STRIDE, 0x8000);
    }

    #[test]
    fn out_of_range_slot_returns_none() {
        #[allow(
            clippy::integer_division,
            reason = "STRIDE divides range evenly by construction"
        )]
        let max_slots = (USER_STACK_VA_END - USER_STACK_VA_BASE) / USER_STACK_STRIDE;
        assert!(slot_writable_base(max_slots).is_none());
    }
}

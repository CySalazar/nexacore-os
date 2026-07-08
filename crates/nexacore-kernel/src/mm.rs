//! Kernel memory-management façade (MB14.d).
//!
//! Thin re-export layer that groups the cross-cutting MM primitives the
//! rest of the kernel reaches for: today only TLB-range invalidation
//! (BSP-side `invlpg` + cross-CPU broadcast on vector
//! `bare_metal::tlb_shootdown::TLB_SHOOTDOWN_VECTOR`); MB14.e will add
//! per-CPU run-queue allocation helpers and MB14.f the x2APIC migration
//! surface.
//!
//! Keeping the call-site spelling `mm::flush_tlb_range(...)` lets the
//! kernel house style stay close to Linux/seL4 idioms even while the
//! implementation lives under `bare_metal`.
//!
//! [`bare_metal`]: crate::bare_metal

/// Re-export of `bare_metal::tlb_shootdown::flush_tlb_range` so callers
/// can say `mm::flush_tlb_range(va, len)` without reaching into the
/// `bare_metal` sub-tree.
#[cfg(feature = "bare-metal")]
pub use crate::bare_metal::tlb_shootdown::{
    SHOOTDOWN_FULL_FLUSH, SHOOTDOWN_MAX_PAGES, ShootdownReport, TLB_SHOOTDOWN_VECTOR,
    flush_tlb_range, invalidate_local,
};

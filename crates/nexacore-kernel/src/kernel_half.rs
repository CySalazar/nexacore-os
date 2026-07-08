//! WS1-11 — MP kernel-half aliasing hardening (ADR-0004 Alt B).
//!
//! ## The hazard
//!
//! ADR-0004 § "Alternativa 3" gives every process its own PML4 frame whose
//! kernel half (PML4 indices `256..512`) is **memcpy-cloned by reference**
//! from the boot CR3 — see `bare_metal::address_space::AddressSpace::new_with_kernel_half`.
//! Each per-process PML4 therefore owns a *private copy of the 256 kernel-half
//! entry words*, while the PDPT / PD / PT sub-tables those words point at are
//! **shared** across all processes.
//!
//! While a single CPU schedules (Phase 1) the kernel half is static post-boot,
//! so the by-reference clone is sound. Once more than one Application Processor
//! schedules actively (WS1-11.4 / MB14.h), a kernel-half *mutation* becomes a
//! concurrency hazard. Two cases:
//!
//! 1. **Sub-table mutation** — a `vmap` that installs a leaf PTE (or a PD/PDPT
//!    entry) inside a sub-table whose PML4 slot is *already present*. Because
//!    the sub-table is shared, the new mapping is visible to **every** CPU's
//!    active CR3 the instant the 8-byte entry is written; only stale TLB
//!    entries must be invalidated. This is **safe** given a barrier — the
//!    existing `bare_metal::tlb_shootdown::flush_tlb_range` broadcast.
//!
//! 2. **PML4-level mutation** — a mapping that needs a *previously-empty*
//!    kernel-half PML4 slot to start pointing at a freshly-allocated sub-table.
//!    The boot PML4 would gain the entry, but the per-process PML4 clones —
//!    frozen at clone time — would **not**. A CPU running such a process then
//!    resolves the new kernel VA differently from (or faults where) a CPU on
//!    the boot/another address space does. This is **dangerous aliasing**:
//!    divergent kernel-half translations across CPUs.
//!
//! ## The decision (WS1-11.1): shared-immutable
//!
//! We adopt `KernelHalfStrategy::SharedImmutable`. The kernel-half PML4
//! entries are treated as **frozen at boot**: every kernel-half PML4 slot the
//! kernel will ever use is populated *before* the first AP is started, each
//! pointing at a pre-allocated sub-table. After the freeze:
//!
//! * No kernel mapping ever changes a PML4-level kernel-half entry — case (2)
//!   is *structurally impossible*. The chokepoint `plan_kernel_map` rejects
//!   any request that would require it (`AliasingViolation::Pml4Divergence`).
//! * All kernel mappings touch only the shared sub-tables — case (1) — and are
//!   made coherent by a mandatory TLB-shootdown barrier
//!   (`MapPlan::requires_shootdown`).
//!
//! The discarded alternative, `KernelHalfStrategy::FullClone`, would instead
//! re-sync every live PML4 on each kernel-half mutation (O(processes) per map,
//! itself needing a cross-CPU barrier to avoid a torn copy). It buys nothing
//! over shared-immutable for a statically-partitioned kernel half and costs a
//! full PML4 walk per `vmap`; ADR-0004 already rejected per-process kernel
//! clones for the same reason (§ "Alternativa 2").
//!
//! ## What this module provides
//!
//! * `KernelHalfSnapshot` — the frozen 256-entry kernel-half image, captured
//!   from the boot PML4 and verifiable against any per-process PML4
//!   (`KernelHalfSnapshot::matches_pml4`). Equality of every process PML4's
//!   kernel half against this snapshot **is** the "no dangerous aliasing"
//!   invariant.
//! * `classify_va` / `plan_kernel_map` — the mutation chokepoint that
//!   identifies the AP-mutation points (WS1-11.2) and enforces the strategy
//!   (WS1-11.3).
//! * `MpKernelHalfModel` — a host-testable model of N CPUs sharing the
//!   kernel half, used by the WS1-11.5 model test to prove the invariant holds
//!   under concurrent sub-table mutation and is violated only by the rejected
//!   PML4-level path.

#![allow(
    clippy::doc_markdown,
    reason = "module references PML4, CR3, PDPT, TLB, VA without backticks in prose"
)]
#![allow(
    unsafe_code,
    reason = "PML4 kernel-half capture/verify reads table entries via the direct map; SAFETY per fn"
)]

use crate::memory::{PhysAddr, VirtAddr};

/// First PML4 index belonging to the kernel half on x86_64 long mode.
///
/// The canonical 256/256 split maps the lower 128 TiB to user space and the
/// upper 128 TiB (indices `256..512`) to the kernel. Mirrors the constant in
/// `bare_metal::address_space` so the two agree on the boundary.
pub const KERNEL_PML4_START: usize = 256;

/// Number of `u64` entries in a PML4 (4 KiB / 8 bytes).
pub const PML4_ENTRIES: usize = 512;

/// Number of kernel-half entries (`512 - 256`).
pub const KERNEL_HALF_LEN: usize = PML4_ENTRIES - KERNEL_PML4_START;

/// PTE present bit — an entry is "populated" iff bit 0 is set.
const PTE_PRESENT: u64 = 1 << 0;

/// Lowest kernel-half virtual address (PML4 index 256, all lower bits zero),
/// sign-extended to the canonical higher half.
pub const KERNEL_HALF_VA_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Strategy for keeping the by-reference kernel half coherent once more than
/// one CPU schedules actively. See the module docs for the rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelHalfStrategy {
    /// Re-clone the kernel-half PML4 entries into every live process PML4 on
    /// each kernel-half mutation. O(processes) per map; needs a cross-CPU
    /// barrier to avoid a torn copy. **Rejected** — see module docs.
    FullClone,
    /// Freeze the kernel-half PML4 entries at boot; all post-boot kernel
    /// mappings touch only the shared sub-tables and are made coherent by the
    /// TLB-shootdown barrier. **Chosen.**
    SharedImmutable,
}

/// The strategy this kernel uses (WS1-11.1).
pub const KERNEL_HALF_STRATEGY: KernelHalfStrategy = KernelHalfStrategy::SharedImmutable;

/// Where a virtual address falls relative to the kernel half, for the
/// mutation chokepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaClass {
    /// User half (PML4 index `0..256`). Never the kernel's concern here.
    UserHalf,
    /// Kernel half, and the covering PML4 slot is already present in the
    /// frozen snapshot — a mapping here touches only the shared sub-table.
    KernelShared,
    /// Kernel half, but the covering PML4 slot is *absent* in the frozen
    /// snapshot — installing it would diverge the per-process PML4 clones.
    KernelPml4Gap,
}

/// PML4 index covering a virtual address (bits 47..39).
#[must_use]
pub const fn pml4_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}

/// A mapping the chokepoint refused because it would violate the
/// shared-immutable invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasingViolation {
    /// The VA is in the user half — not routable through the kernel-half
    /// chokepoint at all.
    NotKernelHalf,
    /// The VA needs a previously-empty kernel-half PML4 slot. Honouring it
    /// post-freeze would make the boot PML4 diverge from the per-process
    /// clones (dangerous aliasing). The kernel half must be fully
    /// pre-populated at boot instead.
    Pml4Divergence,
}

/// An accepted kernel-half mapping plan produced by [`plan_kernel_map`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapPlan {
    /// PML4 index the mapping resolves through (always a present, frozen
    /// kernel-half slot).
    pub pml4_index: usize,
    /// Whether the caller must issue a TLB-shootdown barrier after writing
    /// the leaf entry. Always `true` for kernel-half mutations under MP: the
    /// shared sub-table is visible to every CPU, so every CPU may hold a stale
    /// TLB entry for the range.
    pub requires_shootdown: bool,
}

/// Frozen image of the kernel-half PML4 entries (indices `256..512`).
///
/// Captured once at boot from the boot PML4, *after* every kernel-half slot is
/// populated and *before* the first AP starts scheduling. Thereafter it is the
/// reference every per-process PML4 must match; [`Self::matches_pml4`] is the
/// concrete "no dangerous aliasing" check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelHalfSnapshot {
    entries: [u64; KERNEL_HALF_LEN],
}

impl KernelHalfSnapshot {
    /// Construct directly from the 256 kernel-half entry words (host tests +
    /// the MP model). Bare-metal callers use [`Self::capture`].
    #[must_use]
    pub const fn from_entries(entries: &[u64; KERNEL_HALF_LEN]) -> Self {
        Self { entries: *entries }
    }

    /// Borrow the captured kernel-half entries.
    #[must_use]
    pub const fn entries(&self) -> &[u64; KERNEL_HALF_LEN] {
        &self.entries
    }

    /// `true` iff the kernel-half PML4 slot covering `va` is present in the
    /// snapshot (i.e. mapping `va` touches only a shared sub-table).
    #[must_use]
    pub fn covers(&self, va: u64) -> bool {
        let idx = pml4_index(va);
        if idx < KERNEL_PML4_START {
            return false;
        }
        // `idx - 256` is in `0..256`; `.get()` keeps it panic-free for clippy.
        self.entries
            .get(idx - KERNEL_PML4_START)
            .is_some_and(|e| e & PTE_PRESENT != 0)
    }

    /// Capture the kernel-half entries from a live PML4 via the direct map.
    ///
    /// `pml4_phys` is the PML4 physical base; `phys_offset` the bootloader
    /// direct-map offset (`phys → virt`). Read-only.
    ///
    /// # Safety
    ///
    /// `pml4_phys` must be a valid PML4 frame and `phys_offset` the live
    /// direct-map offset, so that `phys_offset + pml4_phys` is a readable
    /// mapping of the table for the duration of the call.
    #[must_use]
    pub unsafe fn capture(pml4_phys: PhysAddr, phys_offset: u64) -> Self {
        let mut entries = [0u64; KERNEL_HALF_LEN];
        // SAFETY: contract delegated to the caller — `pml4_phys` is a mapped
        // PML4 frame; we read 256 aligned `u64`s from its kernel half.
        unsafe {
            let base = phys_offset.wrapping_add(pml4_phys.0) as *const u64;
            for (i, slot) in entries.iter_mut().enumerate() {
                *slot = core::ptr::read(base.add(KERNEL_PML4_START + i));
            }
        }
        Self { entries }
    }

    /// Verify a per-process PML4's kernel half matches this snapshot
    /// byte-for-byte. A mismatch means the process would observe a divergent
    /// kernel-half translation — the dangerous-aliasing condition.
    ///
    /// Returns the first diverging kernel-half index (`256..512`) on
    /// mismatch, or `Ok(())` when identical.
    ///
    /// # Errors
    ///
    /// Returns `Err(idx)` with the first kernel-half PML4 index whose entry in
    /// the inspected PML4 differs from the snapshot — the process would alias
    /// the kernel half there.
    ///
    /// # Safety
    ///
    /// Same contract as [`Self::capture`] for `pml4_phys` / `phys_offset`.
    pub unsafe fn matches_pml4(&self, pml4_phys: PhysAddr, phys_offset: u64) -> Result<(), usize> {
        // SAFETY: caller guarantees the PML4 frame is mapped at
        // `phys_offset + pml4_phys`.
        unsafe {
            let base = phys_offset.wrapping_add(pml4_phys.0) as *const u64;
            for (i, expected) in self.entries.iter().enumerate() {
                let got = core::ptr::read(base.add(KERNEL_PML4_START + i));
                if got != *expected {
                    return Err(KERNEL_PML4_START + i);
                }
            }
        }
        Ok(())
    }

    /// Classify where `va` falls relative to this frozen kernel half.
    #[must_use]
    pub fn classify(&self, va: u64) -> VaClass {
        if pml4_index(va) < KERNEL_PML4_START {
            VaClass::UserHalf
        } else if self.covers(va) {
            VaClass::KernelShared
        } else {
            VaClass::KernelPml4Gap
        }
    }
}

/// Stateless VA classification against the canonical kernel-half boundary,
/// for callers that only need user-vs-kernel without a snapshot.
#[must_use]
pub fn classify_va(va: u64) -> VaClass {
    if pml4_index(va) < KERNEL_PML4_START {
        VaClass::UserHalf
    } else {
        // Without a snapshot we cannot tell shared from gap; assume the
        // pessimistic "needs verification" — callers with a snapshot use
        // [`KernelHalfSnapshot::classify`].
        VaClass::KernelPml4Gap
    }
}

/// The kernel-half mutation chokepoint (WS1-11.2 / .3).
///
/// Every kernel-side mapping under MP must route through here. Given the
/// frozen [`KernelHalfSnapshot`] and the target VA it either returns a
/// [`MapPlan`] (the mapping touches a shared sub-table; write the leaf then
/// issue the shootdown barrier) or an [`AliasingViolation`] (the mapping would
/// diverge the per-process PML4 clones and must not proceed).
///
/// This is the single point where the shared-immutable invariant is enforced:
/// it is *impossible* to install a kernel mapping that would alias across CPUs
/// without `plan_kernel_map` rejecting it first.
///
/// # Errors
///
/// - [`AliasingViolation::NotKernelHalf`] — `va` is in the user half and must
///   not be routed through the kernel-half chokepoint.
/// - [`AliasingViolation::Pml4Divergence`] — `va` needs a previously-empty
///   kernel-half PML4 slot; honouring it post-freeze would alias across CPUs.
pub fn plan_kernel_map(
    snapshot: &KernelHalfSnapshot,
    va: VirtAddr,
) -> Result<MapPlan, AliasingViolation> {
    match snapshot.classify(va.0) {
        VaClass::UserHalf => Err(AliasingViolation::NotKernelHalf),
        VaClass::KernelPml4Gap => Err(AliasingViolation::Pml4Divergence),
        VaClass::KernelShared => Ok(MapPlan {
            pml4_index: pml4_index(va.0),
            // Shared sub-table mutation is visible to every CPU's CR3 at once;
            // every CPU may hold a stale TLB entry → barrier is mandatory.
            requires_shootdown: true,
        }),
    }
}

// =============================================================================
// Host-testable MP model (WS1-11.5)
// =============================================================================

#[cfg(test)]
mod model {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::{KERNEL_HALF_LEN, KERNEL_PML4_START, PTE_PRESENT, pml4_index};

    /// A single shared kernel-half sub-table (PDPT level), modelled as the
    /// leaf VA→frame mappings it resolves. In the real kernel this is the
    /// physical PDPT/PD/PT chain hung off one PML4 slot; the model collapses
    /// the chain to its observable behaviour (which leaf VAs resolve to which
    /// frames) because that is exactly what "aliasing" is about.
    #[derive(Debug, Default, Clone)]
    struct SharedSubTable {
        /// `(va, frame)` leaf mappings installed in this sub-table.
        leaves: Vec<(u64, u64)>,
    }

    impl SharedSubTable {
        fn resolve(&self, va: u64) -> Option<u64> {
            self.leaves.iter().find(|(v, _)| *v == va).map(|(_, f)| *f)
        }

        fn install(&mut self, va: u64, frame: u64) {
            if let Some(slot) = self.leaves.iter_mut().find(|(v, _)| *v == va) {
                slot.1 = frame;
            } else {
                self.leaves.push((va, frame));
            }
        }
    }

    /// One CPU running a process: its private copy of the 256 kernel-half PML4
    /// entry words. Each present word is an index into the model's shared
    /// sub-table arena (mirroring "the entry points at a shared PDPT").
    #[derive(Debug, Clone)]
    struct CpuView {
        kernel_half: [u64; KERNEL_HALF_LEN],
    }

    impl CpuView {
        /// Resolve a kernel-half VA exactly as the MMU would: PML4 entry
        /// (this CPU's private copy) → shared sub-table → leaf.
        fn resolve(&self, va: u64, arena: &[SharedSubTable]) -> Option<u64> {
            let idx = pml4_index(va);
            if idx < KERNEL_PML4_START {
                return None;
            }
            let entry = self.kernel_half[idx - KERNEL_PML4_START];
            if entry & PTE_PRESENT == 0 {
                return None;
            }
            // The entry's upper bits encode the shared sub-table id.
            let sub_id = (entry >> 12) as usize;
            arena.get(sub_id).and_then(|st| st.resolve(va))
        }
    }

    /// Model of N CPUs sharing a by-reference kernel half under the
    /// shared-immutable strategy.
    pub(super) struct MpKernelHalfModel {
        boot: [u64; KERNEL_HALF_LEN],
        cpus: Vec<CpuView>,
        arena: Vec<SharedSubTable>,
        frozen: bool,
    }

    impl MpKernelHalfModel {
        /// Build a boot PML4 whose kernel half has `present_slots` populated
        /// (each pointing at a fresh shared sub-table). No CPUs cloned yet.
        #[must_use]
        pub(super) fn new(present_slots: &[usize]) -> Self {
            let mut boot = [0u64; KERNEL_HALF_LEN];
            let mut arena = Vec::new();
            for &slot in present_slots {
                assert!(
                    (KERNEL_PML4_START..512).contains(&slot),
                    "slot {slot} is not a kernel-half index"
                );
                let sub_id = arena.len() as u64;
                arena.push(SharedSubTable::default());
                // entry = PRESENT | (sub_id << 12)
                boot[slot - KERNEL_PML4_START] = PTE_PRESENT | (sub_id << 12);
            }
            Self {
                boot,
                cpus: Vec::new(),
                arena,
                frozen: false,
            }
        }

        /// Freeze the kernel half: no further PML4-level slots may be added.
        pub(super) fn freeze(&mut self) {
            self.frozen = true;
        }

        /// Clone a new per-process PML4 (a new CPU's view) from the boot PML4,
        /// exactly as `AddressSpace::new_with_kernel_half` memcpy-clones the
        /// kernel half. Returns the CPU index.
        pub(super) fn clone_process(&mut self) -> usize {
            self.cpus.push(CpuView {
                kernel_half: self.boot,
            });
            self.cpus.len() - 1
        }

        /// Install a leaf mapping in the shared sub-table covering `va`. This
        /// is the safe case-(1) path: it mutates only the shared arena, so
        /// every CPU observes it without touching any PML4. Returns `false`
        /// if `va`'s PML4 slot is not a present (frozen) kernel-half slot —
        /// i.e. the chokepoint would have rejected it.
        pub(super) fn map_shared(&mut self, va: u64, frame: u64) -> bool {
            let idx = pml4_index(va);
            if idx < KERNEL_PML4_START {
                return false;
            }
            let entry = self.boot[idx - KERNEL_PML4_START];
            if entry & PTE_PRESENT == 0 {
                return false;
            }
            let sub_id = (entry >> 12) as usize;
            self.arena[sub_id].install(va, frame);
            true
        }

        /// Attempt the dangerous case-(2) PML4-level mutation: point a
        /// previously-empty kernel-half slot at a new sub-table on the **boot
        /// PML4 only** (as a naive `vmap` would). Rejected post-freeze. This
        /// models exactly what the [`super::plan_kernel_map`] chokepoint
        /// forbids; the test asserts the rejection and, in a separate "unsafe"
        /// variant, that *bypassing* it produces observable aliasing.
        pub(super) fn attempt_pml4_mutation(&mut self, slot: usize) -> bool {
            if self.frozen {
                return false;
            }
            if !(KERNEL_PML4_START..512).contains(&slot) {
                return false;
            }
            let sub_id = self.arena.len() as u64;
            self.arena.push(SharedSubTable::default());
            self.boot[slot - KERNEL_PML4_START] = PTE_PRESENT | (sub_id << 12);
            true
        }

        /// Deliberately bypass the freeze to demonstrate the hazard: install a
        /// new PML4 slot on the boot PML4 *after* CPUs were cloned, without
        /// re-syncing them. Used only by the negative test.
        pub(super) fn force_pml4_mutation_bypassing_freeze(
            &mut self,
            slot: usize,
            va: u64,
            frame: u64,
        ) {
            let sub_id = self.arena.len() as u64;
            let mut st = SharedSubTable::default();
            st.install(va, frame);
            self.arena.push(st);
            self.boot[slot - KERNEL_PML4_START] = PTE_PRESENT | (sub_id << 12);
        }

        /// Resolve `va` on every CPU; return the set of distinct outcomes.
        /// One element ⇒ all CPUs agree (no aliasing). More than one ⇒
        /// dangerous aliasing.
        fn outcomes(&self, va: u64) -> Vec<Option<u64>> {
            let mut seen: Vec<Option<u64>> = Vec::new();
            for cpu in &self.cpus {
                let r = cpu.resolve(va, &self.arena);
                if !seen.contains(&r) {
                    seen.push(r);
                }
            }
            seen
        }

        /// The core invariant: every CPU resolves `va` identically.
        #[must_use]
        pub(super) fn all_cpus_agree(&self, va: u64) -> bool {
            self.outcomes(va).len() <= 1
        }

        /// The structural invariant behind it: every CPU's kernel-half PML4
        /// copy is byte-identical to the boot snapshot taken at freeze time.
        #[must_use]
        pub(super) fn no_pml4_divergence(&self, frozen_boot: &[u64; KERNEL_HALF_LEN]) -> bool {
            self.cpus.iter().all(|c| &c.kernel_half == frozen_boot)
        }

        /// Snapshot the current boot kernel half (taken at freeze time).
        #[must_use]
        pub(super) fn boot_snapshot(&self) -> [u64; KERNEL_HALF_LEN] {
            self.boot
        }
    }
}

#[cfg(test)]
use model::MpKernelHalfModel;

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with_present(slots: &[usize]) -> KernelHalfSnapshot {
        let mut e = [0u64; KERNEL_HALF_LEN];
        for &s in slots {
            e[s - KERNEL_PML4_START] = PTE_PRESENT | ((s as u64) << 12);
        }
        KernelHalfSnapshot::from_entries(&e)
    }

    #[test]
    fn strategy_is_shared_immutable() {
        assert_eq!(KERNEL_HALF_STRATEGY, KernelHalfStrategy::SharedImmutable);
    }

    #[test]
    fn pml4_index_extracts_bits_47_39() {
        assert_eq!(pml4_index(0), 0);
        assert_eq!(pml4_index(KERNEL_HALF_VA_BASE), 256);
        // index 511 = top of the address space.
        assert_eq!(pml4_index(0xFFFF_FF80_0000_0000), 511);
    }

    #[test]
    fn classify_va_splits_user_and_kernel_half() {
        assert_eq!(classify_va(0x0000_0000_4000_0000), VaClass::UserHalf);
        assert_eq!(classify_va(0x0000_7FFF_FFFF_F000), VaClass::UserHalf);
        // First kernel-half VA → without a snapshot, pessimistic gap.
        assert_eq!(classify_va(KERNEL_HALF_VA_BASE), VaClass::KernelPml4Gap);
    }

    #[test]
    fn snapshot_covers_only_present_slots() {
        let snap = snapshot_with_present(&[256, 300]);
        assert!(snap.covers(KERNEL_HALF_VA_BASE)); // index 256
        // index 300 VA = 300 << 39, sign-extended.
        let va_300 = 0xFFFF_8000_0000_0000 | ((300u64 - 256) << 39);
        assert!(snap.covers(va_300));
        // index 257 absent.
        let va_257 = 0xFFFF_8000_0000_0000 | (1u64 << 39);
        assert!(!snap.covers(va_257));
    }

    #[test]
    fn plan_kernel_map_accepts_shared_slot_and_demands_shootdown() {
        let snap = snapshot_with_present(&[256]);
        let plan = plan_kernel_map(&snap, VirtAddr(KERNEL_HALF_VA_BASE + 0x1000))
            .expect("present kernel-half slot must be mappable");
        assert_eq!(plan.pml4_index, 256);
        assert!(
            plan.requires_shootdown,
            "kernel-half mutation must force a TLB-shootdown barrier under MP"
        );
    }

    #[test]
    fn plan_kernel_map_rejects_user_half() {
        let snap = snapshot_with_present(&[256]);
        let err = plan_kernel_map(&snap, VirtAddr(0x0000_0000_4000_0000)).unwrap_err();
        assert_eq!(err, AliasingViolation::NotKernelHalf);
    }

    #[test]
    fn plan_kernel_map_rejects_pml4_gap() {
        // Slot 256 present, 257 absent → a map into 257 would need a new
        // PML4 entry, which would diverge the per-process clones.
        let snap = snapshot_with_present(&[256]);
        let va_257 = 0xFFFF_8000_0000_0000 | (1u64 << 39);
        let err = plan_kernel_map(&snap, VirtAddr(va_257)).unwrap_err();
        assert_eq!(err, AliasingViolation::Pml4Divergence);
    }

    // ----- MP model tests (WS1-11.5) -----

    #[test]
    fn shared_subtable_mutation_is_seen_by_all_cpus_without_aliasing() {
        // Boot kernel half has slots 256 and 384 present. Freeze, clone 4
        // process PML4s (4 CPUs), then install a leaf in the shared sub-table
        // for an existing slot. Every CPU must resolve it identically.
        let mut m = MpKernelHalfModel::new(&[256, 384]);
        m.freeze();
        let frozen = m.boot_snapshot();
        for _ in 0..4 {
            m.clone_process();
        }
        let va = KERNEL_HALF_VA_BASE + 0x2000; // covered by slot 256
        assert!(m.map_shared(va, 0xDEAD_0000), "slot 256 is present → safe");
        assert!(
            m.all_cpus_agree(va),
            "shared sub-table mutation must be visible to every CPU identically"
        );
        assert!(
            m.no_pml4_divergence(&frozen),
            "no CPU's PML4 kernel half may diverge from the frozen snapshot"
        );
    }

    #[test]
    fn frozen_model_rejects_pml4_level_mutation() {
        let mut m = MpKernelHalfModel::new(&[256]);
        m.freeze();
        m.clone_process();
        m.clone_process();
        // Slot 257 was never populated; post-freeze it cannot be added.
        assert!(
            !m.attempt_pml4_mutation(257),
            "the chokepoint must refuse a post-freeze PML4-level kernel mapping"
        );
    }

    #[test]
    fn bypassing_the_freeze_produces_observable_aliasing() {
        // Negative control: prove the hazard is real. If we bypass the freeze
        // and add a PML4 slot on the boot PML4 only (after cloning), the new
        // CPU view (cloned *after*) sees it but the old views do not.
        let mut m = MpKernelHalfModel::new(&[256]);
        let cpu_a = m.clone_process(); // cloned before the mutation
        let va_257 = 0xFFFF_8000_0000_0000 | (1u64 << 39);
        m.force_pml4_mutation_bypassing_freeze(257, va_257, 0xBEEF_0000);
        let cpu_b = m.clone_process(); // cloned after the mutation
        assert_ne!(cpu_a, cpu_b);
        assert!(
            !m.all_cpus_agree(va_257),
            "without the shared-immutable freeze, a PML4-level mutation aliases across CPUs"
        );
    }

    #[test]
    fn capture_and_matches_round_trip_via_arena() {
        // Exercise the real direct-map capture/verify path against a host
        // arena standing in for two PML4 frames with identical kernel halves.
        use core::alloc::Layout;
        let layout = Layout::from_size_align(2 * 4096, 4096).unwrap();
        // SAFETY: non-zero layout; freed below.
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!base.is_null());
        let phys_offset = base as u64; // pretend phys 0 maps to `base`.
        let boot = PhysAddr(0);
        let proc_pml4 = PhysAddr(4096);

        // SAFETY: arena memory we own; write kernel-half sentinels into both
        // frames identically. Pointers are derived via integer arithmetic on
        // the 4 KiB-aligned arena base (not a `*u8 → *u64` reinterpret) so the
        // u64 accesses stay aligned.
        unsafe {
            let b = phys_offset.wrapping_add(boot.0) as *mut u64;
            let p = phys_offset.wrapping_add(proc_pml4.0) as *mut u64;
            for i in KERNEL_PML4_START..PML4_ENTRIES {
                let v = PTE_PRESENT | ((i as u64) << 12);
                core::ptr::write(b.add(i), v);
                core::ptr::write(p.add(i), v);
            }
        }

        // SAFETY: `boot`/`proc_pml4` map into the arena at `phys_offset`.
        let snap = unsafe { KernelHalfSnapshot::capture(boot, phys_offset) };
        // SAFETY: same.
        let ok = unsafe { snap.matches_pml4(proc_pml4, phys_offset) };
        assert_eq!(ok, Ok(()), "identical kernel halves must verify clean");

        // Now diverge the process PML4 at index 300 and expect a mismatch.
        // SAFETY: arena memory; aligned integer-derived pointer.
        unsafe {
            let p = phys_offset.wrapping_add(proc_pml4.0) as *mut u64;
            core::ptr::write(p.add(300), 0);
        }
        // SAFETY: same.
        let bad = unsafe { snap.matches_pml4(proc_pml4, phys_offset) };
        assert_eq!(bad, Err(300), "the diverging kernel-half index is reported");

        // SAFETY: same layout used in alloc.
        unsafe { std::alloc::dealloc(base, layout) };
    }
}

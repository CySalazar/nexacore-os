//! Per-domain IOMMU page-table root allocator (P6.7.9-pre.9).
//!
//! ## Scope
//!
//! Both vendor backends (`vtd::VtdBackend`, `amdvi::AmdViBackend`)
//! consume a 4-KiB-aligned **per-domain root page** when binding a PCI
//! device through their respective `install_device_entry` MMIO paths
//! (`slpt_phys` for VT-d, `iopt_phys` for AMD-Vi). Until this slice the
//! root was a parameter the caller had to supply; nothing in the kernel
//! actually allocated one, which made the device-entry install
//! unreachable from the live `DriverLoad (73)` path.
//!
//! This module closes that gap with two pieces:
//!
//! 1. A vendor-neutral [`FrameSource`] trait that abstracts the frame
//!    provider. The bare-metal kernel feeds in a thin wrapper around
//!    `BitmapFrameAllocator` + the bootloader direct-map offset (so the
//!    returned frame can be zero-filled before the IOMMU reads it). Host
//!    tests use `MockFrameSource` (a `cfg(test)`-only helper at the
//!    bottom of this module) which hands out fake frames from a
//!    deterministic counter and tracks `(alloc, free)` calls.
//!
//! 2. A [`DomainPageTables`] registry held inside each vendor backend.
//!    It maps `DomainId → root_phys` with O(N) lookup over a small
//!    `Vec`; Phase 1 driver counts are bounded by the per-process IOMMU
//!    domain budget (one domain per driver process; tens at most) so
//!    the bounded linear scan is preferable to a `BTreeMap` (avoids
//!    dragging in `alloc::collections` for a registry that lives behind
//!    a `spin::Mutex` already).
//!
//! ## What is and isn't allocated
//!
//! - **Allocated:** exactly one 4-KiB frame per provisioned domain, used
//!   as the root of the per-domain second-level (VT-d) / I/O (AMD-Vi)
//!   page table. The intermediate levels are faulted in on demand by the
//!   WI-7a second-level page-table builder ([`super::vtd::map_4k_slpt`])
//!   which pulls additional frames from the same [`FrameSource`] and
//!   reads/writes their entries via [`FrameSource::read_entry`] /
//!   [`FrameSource::write_entry`]. (The builder is host-tested but not
//!   yet wired into the live `dma_map` path — that wiring plus the
//!   `GCMD.TE` flip is WI-7b.)
//! - **Not allocated:** the kernel-wide root-table (one per VT-d unit)
//!   and the per-bus context tables — those are already allocated by
//!   the activation code in `kmain` and lives orthogonally to the
//!   per-domain page-table root provided here.
//!
//! ## Security posture
//!
//! - The allocator NEVER hands out a frame the caller has not zero-
//!   filled. The trait contract states that
//!   [`FrameSource::alloc_zeroed_frame`] returns a 4-KiB-aligned
//!   physical address whose page is freshly zeroed via the bootloader
//!   direct map. A non-zero return value (`0` is reserved as "alloc
//!   failed") that violates alignment is rejected by [`DomainPageTables::provision`].
//! - The registry rejects double-provisioning to surface caller bugs
//!   ([`DomainPtError::AlreadyProvisioned`]) instead of silently
//!   leaking a frame.
//! - Release is **idempotent on the registry side but NOT on the
//!   `FrameSource` side** — releasing a domain twice is rejected with
//!   [`DomainPtError::NotProvisioned`], so the caller cannot accidentally
//!   double-free the underlying frame.
//!
//! ## References
//!
//! - NCIP-Driver-Framework-013 § S3.3 — IOMMU per-driver domain.
//! - Intel VT-d spec rev 4.1 § 3.5 (second-level translation root).
//! - AMD I/O Virtualization Technology spec rev 3.10 § 5.4 (I/O page
//!   table root).

extern crate alloc;

use alloc::vec::Vec;

use super::DomainId;

/// Size of one IOMMU page-table page in bytes.
///
/// Both VT-d and AMD-Vi use 4-KiB pages at every level of the second-
/// level / I/O page-table tree (large-page support is a
/// performance-only optimisation deferred to Phase 2+). Exposed as a
/// `pub const` so the `KernelFrameSource` wrapper in the bare-metal
/// crate can sanity-check the frame size it asks the bitmap allocator
/// for.
pub const PT_PAGE_BYTES: usize = 4096;

/// Errors returned by [`DomainPageTables`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainPtError {
    /// The supplied [`FrameSource::alloc_zeroed_frame`] returned `None`
    /// (out of physical RAM, bitmap exhausted, etc.).
    FrameAllocFailed,
    /// The supplied [`FrameSource::alloc_zeroed_frame`] returned a
    /// non-zero physical address that is not 4-KiB-aligned. Defensive
    /// — surfaces a broken frame allocator before the IOMMU reads the
    /// page.
    Misaligned,
    /// `provision` was called for a domain that already has a root
    /// frame. Callers must `release` first to recycle the previous
    /// frame.
    AlreadyProvisioned,
    /// `release` / `root_phys_strict` was called for a domain with no
    /// recorded root frame.
    NotProvisioned,
}

/// Vendor-neutral frame provider for [`DomainPageTables`].
///
/// The trait is intentionally minimal: one allocation entry point that
/// returns a zero-filled 4-KiB-aligned physical frame, and one free
/// entry point. Implementations OWN the zero-fill — the registry never
/// touches the underlying frame, so the security invariant (no stale
/// data leaks across domains) is enforced at the source.
pub trait FrameSource {
    /// Allocate a fresh 4-KiB physical frame, zero-fill it, and return
    /// its physical address.
    ///
    /// Returns `None` when no frame can be allocated (RAM exhaustion,
    /// fragmentation, allocator wedged). The returned address MUST be
    /// non-zero (the `0` sentinel is reserved) and 4-KiB-aligned —
    /// [`DomainPageTables::provision`] rejects misaligned returns
    /// defensively.
    fn alloc_zeroed_frame(&mut self) -> Option<u64>;

    /// Return `phys` to the underlying pool.
    ///
    /// The registry calls this exactly once per `release` invocation on
    /// a provisioned domain. `phys` is guaranteed to be a 4-KiB-aligned
    /// address that was previously returned by
    /// [`Self::alloc_zeroed_frame`] (the registry validates the
    /// alignment on allocation).
    fn free_frame(&mut self, phys: u64);

    /// Read the 64-bit page-table entry at `index` within the 4-KiB
    /// page-table frame at physical address `table_phys`.
    ///
    /// `index` is in `0..512` (a 4-KiB frame holds 512 eight-byte
    /// entries). Used by the second-level page-table walker (WI-7a,
    /// `vtd::map_4k_slpt`) to test whether an intermediate entry is
    /// already present before allocating a child table. Implementations
    /// read through the same backing the zero-fill uses — the bootloader
    /// direct map on bare-metal, a deterministic store in host tests.
    /// An entry in a freshly [`Self::alloc_zeroed_frame`]'d frame reads
    /// back as `0` (not present).
    fn read_entry(&self, table_phys: u64, index: usize) -> u64;

    /// Write `value` to the 64-bit page-table entry at `index` within
    /// the frame at `table_phys`. Counterpart of [`Self::read_entry`];
    /// same `index` domain and backing contract.
    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64);
}

/// Number of 8-byte entries in one 4-KiB IOMMU page-table frame.
///
/// `4096 / 8 = 512` — the per-level fan-out of every VT-d second-level
/// and AMD-Vi I/O page table. Exposed so the walker and host tests share
/// one definition.
#[allow(
    clippy::integer_division,
    reason = "PT_PAGE_BYTES (4096) is an exact multiple of the 8-byte entry size; constant fold"
)]
pub const PTES_PER_TABLE: usize = PT_PAGE_BYTES / 8;

/// One `(domain, root_phys)` entry tracked by [`DomainPageTables`].
///
/// Pure data — exposed primarily for the bare-metal driver framework
/// to iterate the registry (e.g. on process teardown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainPtEntry {
    /// Domain the root frame belongs to.
    pub domain: DomainId,
    /// 4-KiB-aligned physical address of the page-table root.
    pub root_phys: u64,
}

/// Vendor-neutral registry mapping `DomainId → root_phys`.
///
/// Embedded inside each vendor backend (`VtdBackend::domain_pts`,
/// `AmdViBackend::domain_pts`) so the per-domain root frame travels
/// with the backend that owns the live MMIO tables. The registry is
/// `Default` + `Clone` so the backends can keep their existing `const
/// fn new()` constructors.
///
/// Lookup is O(N) in the entry count; the worst-case Phase 1 entry
/// count (≤ tens) keeps the constant factor lower than a B-tree's
/// allocation overhead.
#[derive(Debug, Clone, Default)]
pub struct DomainPageTables {
    entries: Vec<DomainPtEntry>,
}

impl DomainPageTables {
    /// Construct an empty registry.
    ///
    /// `const` so the host-test default-constructible backend types can
    /// keep their `const fn new()` initialisers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of currently provisioned domains.
    #[must_use]
    pub fn provisioned_count(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff `domain` currently has a recorded root frame.
    #[must_use]
    pub fn is_provisioned(&self, domain: DomainId) -> bool {
        self.entries.iter().any(|e| e.domain == domain)
    }

    /// Recorded root physical address for `domain`, or `None` if the
    /// domain has not been provisioned via [`Self::provision`].
    #[must_use]
    pub fn root_phys(&self, domain: DomainId) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.domain == domain)
            .map(|e| e.root_phys)
    }

    /// Snapshot of the recorded entries (insertion order). Exposed so
    /// the driver framework's teardown path can iterate every active
    /// domain without paying for a clone of the underlying `Vec`.
    #[must_use]
    pub fn entries(&self) -> &[DomainPtEntry] {
        &self.entries
    }

    /// Allocate a fresh root frame for `domain` via `src`, record the
    /// `(domain, root_phys)` binding, and return the new physical
    /// address.
    ///
    /// # Errors
    ///
    /// - [`DomainPtError::AlreadyProvisioned`] when `domain` already
    ///   has a recorded root frame. Callers must
    ///   [`Self::release`] first.
    /// - [`DomainPtError::FrameAllocFailed`] when the supplied
    ///   [`FrameSource`] returned `None`.
    /// - [`DomainPtError::Misaligned`] when the [`FrameSource`]
    ///   returned a non-`None`, non-4-KiB-aligned physical address.
    ///   Defensive — surfaces a broken allocator instead of letting the
    ///   IOMMU read a misaligned root.
    pub fn provision(
        &mut self,
        domain: DomainId,
        src: &mut dyn FrameSource,
    ) -> Result<u64, DomainPtError> {
        if self.is_provisioned(domain) {
            return Err(DomainPtError::AlreadyProvisioned);
        }
        let root_phys = src
            .alloc_zeroed_frame()
            .ok_or(DomainPtError::FrameAllocFailed)?;
        if root_phys & 0xFFF != 0 {
            // Defensive: the allocator returned a misaligned frame.
            // Return it to the pool before surfacing the error so we do
            // not leak the frame even though the registry rejects it.
            src.free_frame(root_phys);
            return Err(DomainPtError::Misaligned);
        }
        self.entries.push(DomainPtEntry { domain, root_phys });
        Ok(root_phys)
    }

    /// Drop the binding for `domain` and return the underlying root
    /// frame to `src` via [`FrameSource::free_frame`].
    ///
    /// # Errors
    ///
    /// [`DomainPtError::NotProvisioned`] when `domain` has no recorded
    /// root frame.
    pub fn release(
        &mut self,
        domain: DomainId,
        src: &mut dyn FrameSource,
    ) -> Result<(), DomainPtError> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.domain == domain)
            .ok_or(DomainPtError::NotProvisioned)?;
        let removed = self.entries.swap_remove(pos);
        src.free_frame(removed.root_phys);
        Ok(())
    }
}

// =============================================================================
// MockFrameSource — host-only deterministic allocator for tests.
// =============================================================================

/// Deterministic [`FrameSource`] implementation for host tests.
///
/// Hands out 4-KiB-aligned physical addresses starting at `BASE` and
/// striding by [`PT_PAGE_BYTES`]; tracks the `(alloc, free)` call count
/// so tests can assert the registry actually drove the underlying
/// allocator (catches `provision` paths that record without allocating
/// or `release` paths that drop the entry without freeing).
///
/// `BASE` is chosen well above the q35 firmware reserved regions so
/// the returned addresses cannot collide with any real frame in the
/// bare-metal build — the type is `cfg(test)`-only anyway, but the
/// constant keeps the host-test invariants self-documenting.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct MockFrameSource {
    /// Next physical address to hand out.
    next_phys: u64,
    /// Total successful `alloc_zeroed_frame` calls.
    pub alloc_calls: usize,
    /// Total `free_frame` calls.
    pub free_calls: usize,
    /// Set to `true` to make `alloc_zeroed_frame` return `None`.
    pub force_alloc_fail: bool,
    /// When non-`None`, override the next allocation with this raw
    /// physical address (used to exercise the misalignment defensive
    /// path).
    pub force_next_phys: Option<u64>,
    /// Recorded list of physical addresses returned to `free_frame`,
    /// in call order, so tests can assert the registry hands the right
    /// frame back.
    pub freed: Vec<u64>,
    /// Backing store for [`FrameSource::read_entry`] /
    /// [`FrameSource::write_entry`]: `frame_phys → 512 entries`. A frame
    /// not present here reads back as all-zero, mirroring the zero-fill
    /// contract of [`FrameSource::alloc_zeroed_frame`]. Boxed array keeps
    /// the map node small and the page contiguous.
    pages: alloc::collections::BTreeMap<u64, alloc::boxed::Box<[u64; PTES_PER_TABLE]>>,
}

#[cfg(test)]
impl MockFrameSource {
    /// Build a fresh mock that starts handing out frames from `0x1_0000_0000`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_phys: 0x1_0000_0000,
            alloc_calls: 0,
            free_calls: 0,
            force_alloc_fail: false,
            force_next_phys: None,
            freed: Vec::new(),
            pages: alloc::collections::BTreeMap::new(),
        }
    }
}

#[cfg(test)]
impl Default for MockFrameSource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl FrameSource for MockFrameSource {
    fn alloc_zeroed_frame(&mut self) -> Option<u64> {
        if self.force_alloc_fail {
            return None;
        }
        let phys = if let Some(override_phys) = self.force_next_phys.take() {
            override_phys
        } else {
            let p = self.next_phys;
            self.next_phys = self.next_phys.wrapping_add(PT_PAGE_BYTES as u64);
            p
        };
        self.alloc_calls += 1;
        Some(phys)
    }

    fn free_frame(&mut self, phys: u64) {
        self.free_calls += 1;
        self.freed.push(phys);
        // Drop the page contents so a later alloc handing out the same
        // address (the bitmap allocator's first-fit reuse) starts zeroed.
        self.pages.remove(&phys);
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> u64 {
        assert!(index < PTES_PER_TABLE, "PTE index out of range");
        self.pages.get(&table_phys).map_or(0, |page| page[index])
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) {
        assert!(index < PTES_PER_TABLE, "PTE index out of range");
        let page = self
            .pages
            .entry(table_phys)
            .or_insert_with(|| alloc::boxed::Box::new([0u64; PTES_PER_TABLE]));
        page[index] = value;
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainId, DomainPageTables, DomainPtError, MockFrameSource, PT_PAGE_BYTES};

    #[test]
    fn new_registry_is_empty() {
        let pts = DomainPageTables::new();
        assert_eq!(pts.provisioned_count(), 0);
        assert!(!pts.is_provisioned(DomainId::new(0)));
        assert_eq!(pts.root_phys(DomainId::new(7)), None);
        assert!(pts.entries().is_empty());
    }

    #[test]
    fn provision_allocates_and_records() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let root = pts.provision(DomainId::new(3), &mut src).unwrap();
        assert_eq!(root & 0xFFF, 0, "root must be 4-KiB-aligned");
        assert_eq!(src.alloc_calls, 1);
        assert_eq!(src.free_calls, 0);
        assert_eq!(pts.provisioned_count(), 1);
        assert!(pts.is_provisioned(DomainId::new(3)));
        assert_eq!(pts.root_phys(DomainId::new(3)), Some(root));
    }

    #[test]
    fn provision_returns_distinct_roots_per_domain() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let root_a = pts.provision(DomainId::new(1), &mut src).unwrap();
        let root_b = pts.provision(DomainId::new(2), &mut src).unwrap();
        let root_c = pts.provision(DomainId::new(3), &mut src).unwrap();
        assert_ne!(root_a, root_b);
        assert_ne!(root_b, root_c);
        assert_ne!(root_a, root_c);
        assert_eq!(src.alloc_calls, 3);
        assert_eq!(pts.provisioned_count(), 3);
    }

    #[test]
    fn provision_rejects_double_provision() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let _ = pts.provision(DomainId::new(7), &mut src).unwrap();
        let err = pts.provision(DomainId::new(7), &mut src).unwrap_err();
        assert_eq!(err, DomainPtError::AlreadyProvisioned);
        // The failed re-provision must NOT have called alloc again —
        // the registry checks for an existing binding before touching
        // the source.
        assert_eq!(src.alloc_calls, 1);
    }

    #[test]
    fn provision_surfaces_frame_alloc_failure() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        src.force_alloc_fail = true;
        let err = pts.provision(DomainId::new(0), &mut src).unwrap_err();
        assert_eq!(err, DomainPtError::FrameAllocFailed);
        // No entry recorded.
        assert!(!pts.is_provisioned(DomainId::new(0)));
    }

    #[test]
    fn provision_rejects_misaligned_frame_and_returns_it() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        // Force the allocator to hand out a misaligned address; the
        // registry must reject and return the frame to the pool.
        src.force_next_phys = Some(0xCAFE_1001);
        let err = pts.provision(DomainId::new(0), &mut src).unwrap_err();
        assert_eq!(err, DomainPtError::Misaligned);
        // The misaligned frame must have been returned via free_frame.
        assert_eq!(src.free_calls, 1);
        assert_eq!(src.freed.as_slice(), &[0xCAFE_1001]);
        // No entry recorded.
        assert!(!pts.is_provisioned(DomainId::new(0)));
    }

    #[test]
    fn release_drops_entry_and_frees_frame() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let root = pts.provision(DomainId::new(9), &mut src).unwrap();
        assert!(pts.is_provisioned(DomainId::new(9)));
        pts.release(DomainId::new(9), &mut src).unwrap();
        assert!(!pts.is_provisioned(DomainId::new(9)));
        assert_eq!(src.free_calls, 1);
        assert_eq!(src.freed.as_slice(), &[root]);
    }

    #[test]
    fn release_unknown_domain_returns_not_provisioned() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let err = pts.release(DomainId::new(42), &mut src).unwrap_err();
        assert_eq!(err, DomainPtError::NotProvisioned);
        assert_eq!(src.free_calls, 0);
    }

    #[test]
    fn release_does_not_free_other_domain_root() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let _ = pts.provision(DomainId::new(1), &mut src).unwrap();
        let root_b = pts.provision(DomainId::new(2), &mut src).unwrap();
        pts.release(DomainId::new(1), &mut src).unwrap();
        // Domain 2's binding is intact and the frame was not freed.
        assert!(pts.is_provisioned(DomainId::new(2)));
        assert_eq!(pts.root_phys(DomainId::new(2)), Some(root_b));
        assert_eq!(src.free_calls, 1);
        // Domain 1's root was the one freed, not domain 2's.
        let freed_first = src.freed.first().copied().expect("one freed root");
        assert_ne!(freed_first, root_b);
    }

    #[test]
    fn reprovision_after_release_returns_new_root() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let root_a = pts.provision(DomainId::new(5), &mut src).unwrap();
        pts.release(DomainId::new(5), &mut src).unwrap();
        let root_b = pts.provision(DomainId::new(5), &mut src).unwrap();
        // The mock hands out monotonically increasing addresses; the
        // re-provisioned root must therefore differ from the original.
        assert_ne!(root_a, root_b);
        assert_eq!(pts.root_phys(DomainId::new(5)), Some(root_b));
    }

    #[test]
    fn entries_preserves_insertion_order_until_release() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        let _ = pts.provision(DomainId::new(10), &mut src).unwrap();
        let _ = pts.provision(DomainId::new(20), &mut src).unwrap();
        let _ = pts.provision(DomainId::new(30), &mut src).unwrap();
        let snapshot: Vec<DomainId> = pts.entries().iter().map(|e| e.domain).collect();
        assert_eq!(
            snapshot,
            vec![DomainId::new(10), DomainId::new(20), DomainId::new(30)]
        );
    }

    #[test]
    fn pt_page_bytes_is_4096() {
        // Pin the constant — both VT-d and AMD-Vi require 4-KiB pages.
        assert_eq!(PT_PAGE_BYTES, 4096);
    }

    #[test]
    fn provisioned_count_tracks_alloc_and_release() {
        let mut pts = DomainPageTables::new();
        let mut src = MockFrameSource::new();
        assert_eq!(pts.provisioned_count(), 0);
        let _ = pts.provision(DomainId::new(1), &mut src).unwrap();
        assert_eq!(pts.provisioned_count(), 1);
        let _ = pts.provision(DomainId::new(2), &mut src).unwrap();
        assert_eq!(pts.provisioned_count(), 2);
        pts.release(DomainId::new(1), &mut src).unwrap();
        assert_eq!(pts.provisioned_count(), 1);
        pts.release(DomainId::new(2), &mut src).unwrap();
        assert_eq!(pts.provisioned_count(), 0);
    }
}

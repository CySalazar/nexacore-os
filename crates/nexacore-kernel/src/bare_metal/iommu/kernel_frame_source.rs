//! Kernel-side [`FrameSource`] adapter — P6.7.9-pre.10 (PT wire DriverLoad).
//!
//! Bridges the vendor-neutral [`FrameSource`] contract used by
//! [`super::pt_alloc::DomainPageTables`] to the kernel-wide
//! [`BitmapFrameAllocator`] initialised at boot. The adapter owns no state
//! of its own — it captures a short-lived `&mut BitmapFrameAllocator<N>`
//! plus the bootloader direct-map offset so the freshly allocated frame
//! can be zero-filled before the IOMMU reads its content.
//!
//! ## Why a separate adapter
//!
//! The pure-data [`super::pt_alloc`] module deliberately knows nothing about
//! the kernel frame allocator (it must stay host-testable and dep-free).
//! The IOMMU dispatch helpers ([`super::iommu_provision_domain_pt`] /
//! [`super::iommu_release_domain_pt`]) therefore accept any
//! `&mut dyn FrameSource`. This adapter is what the `DriverLoad (73)`
//! syscall handler (and `tear_down_pci_bindings` teardown helper)
//! instantiates inside the `SAFETY: single-CPU; FRAME_ALLOC not aliased`
//! block so the same call site can drive any vendor backend (passthrough
//! no-ops; VT-d / AMD-Vi consume one root frame per domain).
//!
//! ## Zero-fill contract
//!
//! [`FrameSource::alloc_zeroed_frame`] requires that the returned page be
//! freshly zeroed. On bare-metal builds the adapter performs a 4-KiB
//! `core::ptr::write_bytes` through the bootloader direct map immediately
//! after the [`BitmapFrameAllocator::alloc_frame`] call. On host builds
//! (`cfg(target_os != "none")`) the zero-fill step is elided because no
//! direct-map exists and the returned address is never dereferenced (host
//! tests only inspect the bookkeeping side of the contract).
//!
//! ## Security posture
//!
//! - The adapter NEVER hands out a frame the caller has not zero-filled on
//!   bare-metal. The host-test `cfg` elision is harmless because tests never
//!   dereference the returned address.
//! - [`super::pt_alloc::DomainPageTables::provision`] enforces 4-KiB
//!   alignment on the returned address — the [`BitmapFrameAllocator`]
//!   always returns 4-KiB-aligned frames so the defensive misalignment
//!   check is a belt-and-braces safety net rather than a routine path.
//! - The wrapper holds no `unsafe` aliasing — the caller passes in
//!   exclusively borrowed references; lifetime erasure prevents the
//!   adapter from outliving the borrow.
//!
//! ## References
//!
//! - [`FrameSource`] — the trait contract this adapter implements.
//! - NCIP-Driver-Framework-013 § S3.3 — per-driver IOMMU domain semantics.
//! - Intel VT-d spec rev 4.1 § 3.5 — second-level translation root frame.
//! - AMD I/O Virtualization Technology spec rev 3.10 § 5.4 — I/O page-table
//!   root frame.

use super::pt_alloc::{FrameSource, PT_PAGE_BYTES};
use crate::memory::{BitmapFrameAllocator, PhysAddr};

/// Adapter exposing a `&mut BitmapFrameAllocator<N>` as a vendor-neutral
/// [`FrameSource`].
///
/// Construct one inside the syscall handler that owns the `FRAME_ALLOC`
/// borrow; pass it by `&mut` to [`super::iommu_provision_domain_pt`] /
/// [`super::iommu_release_domain_pt`].
///
/// The wrapper is `repr(Rust)` and intentionally NOT `Send`/`Sync` (the
/// kernel single-CPU syscall path is the only legitimate caller; an MP
/// caller must take the kernel mutex first).
pub struct KernelFrameSource<'a, const N: usize> {
    alloc: &'a mut BitmapFrameAllocator<N>,
    phys_offset: u64,
}

impl<'a, const N: usize> KernelFrameSource<'a, N> {
    /// Wrap `alloc` so it can be consumed as a [`FrameSource`].
    ///
    /// `phys_offset` MUST be the live bootloader direct-map offset
    /// (`bare_metal::phys_offset()` on bare-metal; ignored on host
    /// builds). The wrapper performs no aliasing tricks; the caller
    /// must already hold the `&mut BitmapFrameAllocator<N>` borrow
    /// under whatever locking discipline the kernel uses.
    #[must_use]
    pub fn new(alloc: &'a mut BitmapFrameAllocator<N>, phys_offset: u64) -> Self {
        Self { alloc, phys_offset }
    }

    /// Live count of free frames in the wrapped allocator.
    ///
    /// Exposed for host tests + boot-time logging so the caller can
    /// assert the adapter actually drove the underlying allocator
    /// (catches `provision` paths that record without allocating).
    #[must_use]
    pub fn free_frames(&self) -> u64 {
        self.alloc.free_frames()
    }
}

impl<const N: usize> FrameSource for KernelFrameSource<'_, N> {
    fn alloc_zeroed_frame(&mut self) -> Option<u64> {
        let phys = self.alloc.alloc_frame()?.0;
        // The bitmap allocator's `alloc_frame` returns a 4-KiB-aligned
        // address by construction (it walks the bitmap one bit per
        // frame). The defensive check here surfaces a future regression
        // in the allocator before the IOMMU reads the misaligned page.
        if phys & (PT_PAGE_BYTES as u64 - 1) != 0 {
            // Defensive: return the misaligned frame to the pool and
            // surface the failure as `None` so `DomainPageTables::provision`
            // maps it onto `DomainPtError::FrameAllocFailed` and the
            // caller's best-effort flow keeps going.
            let _ = self.alloc.free_frame(PhysAddr(phys));
            return None;
        }
        // SAFETY: bare-metal kernel context only. `phys` is a 4-KiB-aligned
        // address inside the `FRAME_ALLOC`-tracked usable region, which the
        // bootloader has direct-mapped at `phys_offset`. The
        // `write_bytes(va, 0, PT_PAGE_BYTES)` writes exactly 4096 bytes
        // starting at the aligned direct-map VA — i.e. into a single
        // frame the caller has just claimed exclusive ownership of.
        #[cfg(target_os = "none")]
        {
            let va = self.phys_offset.wrapping_add(phys) as *mut u8;
            #[allow(
                unsafe_code,
                reason = "single-CPU bare-metal kernel; frame just claimed; direct map established at boot"
            )]
            unsafe {
                core::ptr::write_bytes(va, 0u8, PT_PAGE_BYTES);
            }
        }
        #[cfg(not(target_os = "none"))]
        {
            // Host tests never dereference the returned address; the
            // zero-fill step is meaningless without a direct map.
            let _ = self.phys_offset;
        }
        Some(phys)
    }

    fn free_frame(&mut self, phys: u64) {
        // The bitmap allocator's `free_frame` validates alignment and
        // bounds internally and returns `false` on bogus input. The
        // [`FrameSource`] contract states `phys` is a previously-handed-out
        // 4-KiB-aligned address, so the `false` return is a noisy assert
        // (no-op in release builds, swallowed silently here per the
        // teardown best-effort policy).
        let _ = self.alloc.free_frame(PhysAddr(phys));
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> u64 {
        debug_assert!(index < super::pt_alloc::PTES_PER_TABLE);
        #[cfg(target_os = "none")]
        {
            // SAFETY: bare-metal kernel only. `table_phys` is a 4-KiB
            // page-table frame inside the `FRAME_ALLOC`-tracked usable
            // region the bootloader direct-mapped at `phys_offset`;
            // `index < 512` keeps the access inside that frame. The read
            // is volatile because the IOMMU hardware also reads this
            // memory (the page table is shared kernel↔device state).
            let va = self
                .phys_offset
                .wrapping_add(table_phys)
                .wrapping_add((index as u64) * 8) as *const u64;
            #[allow(
                unsafe_code,
                reason = "single-CPU bare-metal kernel; direct-mapped page-table frame; index bounded < 512"
            )]
            unsafe {
                core::ptr::read_volatile(va)
            }
        }
        #[cfg(not(target_os = "none"))]
        {
            // Host build: no direct map. The live SLPT walker is
            // `cfg(target_os = "none")`-gated and never calls this on
            // host; the SLPT builder's host tests use `MockFrameSource`.
            let _ = (table_phys, index);
            0
        }
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) {
        debug_assert!(index < super::pt_alloc::PTES_PER_TABLE);
        #[cfg(target_os = "none")]
        {
            // SAFETY: same invariants as `read_entry`. The write is
            // volatile so the compiler cannot elide or reorder the
            // device-visible page-table update.
            let va = self
                .phys_offset
                .wrapping_add(table_phys)
                .wrapping_add((index as u64) * 8) as *mut u64;
            #[allow(
                unsafe_code,
                reason = "single-CPU bare-metal kernel; direct-mapped page-table frame; index bounded < 512"
            )]
            unsafe {
                core::ptr::write_volatile(va, value);
            }
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (table_phys, index, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BitmapFrameAllocator, FrameSource, KernelFrameSource, PT_PAGE_BYTES, PhysAddr};
    use crate::bare_metal::iommu::{
        DomainId,
        pt_alloc::{DomainPageTables, DomainPtError},
    };

    /// Build a small allocator with two free frames starting at `base`.
    fn make_alloc(base: u64) -> BitmapFrameAllocator<1> {
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(base));
        // Mark two 4-KiB frames free starting at `base`.
        alloc.mark_range_free(PhysAddr(base), (PT_PAGE_BYTES as u64) * 2);
        alloc
    }

    #[test]
    fn alloc_returns_aligned_frame_from_pool() {
        let base = 0x0010_0000_u64;
        let mut alloc = make_alloc(base);
        let initial_free = alloc.free_frames();
        let mut src = KernelFrameSource::new(&mut alloc, 0);
        let phys = src.alloc_zeroed_frame().expect("frame available");
        assert_eq!(phys & 0xFFF, 0, "frame must be 4-KiB-aligned");
        assert!(phys >= base, "frame within allocator range");
        assert_eq!(src.free_frames(), initial_free - 1);
    }

    #[test]
    fn alloc_exhausts_pool_then_returns_none() {
        let base = 0x0020_0000_u64;
        let mut alloc = make_alloc(base);
        let mut src = KernelFrameSource::new(&mut alloc, 0);
        let _a = src.alloc_zeroed_frame().expect("first alloc ok");
        let _b = src.alloc_zeroed_frame().expect("second alloc ok");
        assert_eq!(src.alloc_zeroed_frame(), None, "pool exhausted");
    }

    #[test]
    fn free_returns_frame_to_pool_for_reuse() {
        let base = 0x0030_0000_u64;
        let mut alloc = make_alloc(base);
        let mut src = KernelFrameSource::new(&mut alloc, 0);
        let phys = src.alloc_zeroed_frame().expect("first alloc ok");
        let free_before = src.free_frames();
        src.free_frame(phys);
        assert_eq!(src.free_frames(), free_before + 1);
        // After free we can allocate again — the bitmap allocator
        // re-uses the bit we just cleared.
        let phys2 = src.alloc_zeroed_frame().expect("realloc ok");
        assert_eq!(phys, phys2, "first-fit re-uses the freed slot");
    }

    #[test]
    fn provision_through_domain_page_tables_round_trips() {
        // End-to-end: hand the adapter to `DomainPageTables::provision` and
        // assert the registry records the frame the adapter actually
        // returned from the bitmap. Mirrors the live `DriverLoad` flow.
        let base = 0x0040_0000_u64;
        let mut alloc = make_alloc(base);
        let mut pts = DomainPageTables::new();
        let mut src = KernelFrameSource::new(&mut alloc, 0);
        let root = pts
            .provision(DomainId::new(7), &mut src)
            .expect("provision ok");
        assert!(root >= base, "root within allocator range");
        assert_eq!(root & 0xFFF, 0, "root 4-KiB-aligned");
        assert_eq!(pts.root_phys(DomainId::new(7)), Some(root));
        // Release returns the frame.
        pts.release(DomainId::new(7), &mut src).expect("release ok");
        assert!(!pts.is_provisioned(DomainId::new(7)));
    }

    #[test]
    fn provision_surfaces_pool_exhaustion_as_frame_alloc_failed() {
        // Empty allocator → adapter returns None → provision surfaces
        // `DomainPtError::FrameAllocFailed`.
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(0));
        let mut pts = DomainPageTables::new();
        let mut src = KernelFrameSource::new(&mut alloc, 0);
        let err = pts
            .provision(DomainId::new(0), &mut src)
            .expect_err("alloc should fail");
        assert_eq!(err, DomainPtError::FrameAllocFailed);
        assert!(!pts.is_provisioned(DomainId::new(0)));
    }

    #[test]
    fn release_then_reprovision_distinct_domain_reuses_pool() {
        // Provision → release → provision a *different* domain. The
        // adapter must hand out the freed frame again (first-fit
        // semantics inherited from `BitmapFrameAllocator`).
        let base = 0x0050_0000_u64;
        let mut alloc = make_alloc(base);
        let mut pts = DomainPageTables::new();
        let mut src = KernelFrameSource::new(&mut alloc, 0);
        let first = pts.provision(DomainId::new(1), &mut src).expect("first ok");
        pts.release(DomainId::new(1), &mut src).expect("release ok");
        let second = pts
            .provision(DomainId::new(2), &mut src)
            .expect("second ok");
        assert_eq!(first, second, "freed frame reused by next provision");
    }
}

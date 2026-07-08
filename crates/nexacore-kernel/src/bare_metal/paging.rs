//! `x86_64` 4-level page-table walker (Track B, MB2).
//!
//! Provides read access to the bootloader-installed page tables and a
//! `map_4k` / `unmap_4k` interface for adding kernel mappings in the
//! direct-mapped physical window. Does **not** write to CR3 — the
//! bootloader page tables remain the active tables; this module adds
//! new mappings within the identity map that the bootloader already
//! installed.
//!
//! ## Direct-map convention
//!
//! `bootloader 0.11` with `Mapping::Dynamic` maps all physical memory
//! at a virtual offset `physical_memory_offset` (from `BootInfo`).
//! Every physical address `p` is accessible at virtual address
//! `p + phys_offset`. `PageMapper` uses this window to traverse and
//! mutate page-table structures without a recursive mapping.
//!
//! ## Huge-page handling
//!
//! `translate` follows huge-page entries (PS=1) at both PDPT (1 GiB)
//! and PD (2 MiB) levels and returns the correct physical address using
//! the appropriate page offset (30 bits for 1 GiB, 21 bits for 2 MiB).
//! This is required because `bootloader 0.11` installs the linear
//! direct-map of physical memory using 1 GiB / 2 MiB pages; without
//! huge-page traversal, `translate` would report most of physical RAM
//! as unmapped even though the CPU resolves it correctly.
//!
//! `map_4k` operates only on 4 KiB entries: it does not currently split
//! a huge-page mapping that already covers the target address. Callers
//! that need to override a huge-page-backed region must split it
//! externally (out of scope for MB9).

#![allow(
    unsafe_code,
    reason = "page-table walker reads/writes raw frame pointers; SAFETY per fn"
)]

use crate::memory::{BitmapFrameAllocator, PhysAddr, VirtAddr};

// -----------------------------------------------------------------------
// PTE flag constants
// -----------------------------------------------------------------------

/// Page is present in memory.
pub const PTE_PRESENT: u64 = 1 << 0;
/// Page is writable.
pub const PTE_WRITABLE: u64 = 1 << 1;
/// Page is accessible from user mode (ring 3).
pub const PTE_USER: u64 = 1 << 2;
/// Page size: at PD level marks a 2 MiB page, at PDPT level marks a 1 GiB page.
///
/// Reserved (must be 0) in PML4E and PTE; ignored by hardware when set there.
pub const PTE_HUGE: u64 = 1 << 7;
/// Execute-disable bit (requires `IA32_EFER.NXE` to be set).
pub const PTE_NO_EXEC: u64 = 1 << 63;

// -----------------------------------------------------------------------
// Huge-page frame masks
//
// PS=1 entries encode the frame at coarser-than-4K granularity:
//   PDPTE 1 GiB → bits [51:30] are the 1 GiB-aligned physical frame.
//   PDE    2 MiB → bits [51:21] are the 2 MiB-aligned physical frame.
// These constants isolate those frame bits; the corresponding offset is
// the low (30 or 21) bits of the virtual address.
// -----------------------------------------------------------------------

/// Frame mask for a PDPTE with PS=1 (1 GiB page): bits \[51:30\].
const HUGE_1G_FRAME_MASK: u64 = 0x000F_FFFF_C000_0000;
/// Offset mask within a 1 GiB page: bits \[29:0\].
const HUGE_1G_OFFSET_MASK: u64 = 0x0000_0000_3FFF_FFFF;
/// Frame mask for a PDE with PS=1 (2 MiB page): bits \[51:21\].
const HUGE_2M_FRAME_MASK: u64 = 0x000F_FFFF_FFE0_0000;
/// Offset mask within a 2 MiB page: bits \[20:0\].
const HUGE_2M_OFFSET_MASK: u64 = 0x0000_0000_001F_FFFF;

// -----------------------------------------------------------------------
// PageTableEntry
// -----------------------------------------------------------------------

/// A single `x86_64` page-table entry (8 bytes).
///
/// Bits \[11:0\] are flags; bits \[51:12\] are the physical frame address
/// (4 KiB-aligned); bit 63 is the NX flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Returns `true` if the PRESENT bit (bit 0) is set.
    #[inline]
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.0 & PTE_PRESENT != 0
    }

    /// Extracts the physical frame address (bits \[51:12\]).
    ///
    /// The low 12 flag bits and high reserved bits are masked out.
    #[inline]
    #[must_use]
    pub const fn phys_addr(self) -> PhysAddr {
        PhysAddr(self.0 & 0x000F_FFFF_FFFF_F000)
    }

    /// Sets this entry to `frame | flags`. `frame` must be 4 KiB-aligned;
    /// excess low bits are masked away before writing.
    #[inline]
    pub fn set_frame(&mut self, frame: PhysAddr, flags: u64) {
        self.0 = (frame.0 & 0x000F_FFFF_FFFF_F000) | flags;
    }

    /// Clears the entry (marks as not-present, zeroes all bits).
    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

// -----------------------------------------------------------------------
// RawPageTable
// -----------------------------------------------------------------------

/// A 512-entry `x86_64` page table (PML4, PDPT, PD, or PT level).
///
/// Aligned to 4 KiB so a single instance fits exactly in one physical
/// frame. `repr(C)` ensures a predictable field layout with no padding.
#[repr(C, align(4096))]
pub struct RawPageTable {
    entries: [PageTableEntry; 512],
}

impl RawPageTable {
    /// Returns a zeroed (all-not-present) page table.
    pub const fn empty() -> Self {
        Self {
            entries: [PageTableEntry(0); 512],
        }
    }

    /// Returns the entry at `idx` by value.
    #[inline]
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "idx is always 0..512, produced by virt_index()"
    )]
    pub fn entry(&self, idx: usize) -> PageTableEntry {
        self.entries[idx]
    }

    /// Returns a mutable reference to the entry at `idx`.
    #[inline]
    #[allow(
        clippy::indexing_slicing,
        reason = "idx is always 0..512, produced by virt_index()"
    )]
    pub fn entry_mut(&mut self, idx: usize) -> &mut PageTableEntry {
        &mut self.entries[idx]
    }
}

// -----------------------------------------------------------------------
// PageLevel
// -----------------------------------------------------------------------

/// The four `x86_64` paging levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageLevel {
    /// Level 4: Page Map Level 4.
    Pml4,
    /// Level 3: Page Directory Pointer Table.
    Pdpt,
    /// Level 2: Page Directory.
    Pd,
    /// Level 1: Page Table (leaf level for 4 KiB pages).
    Pt,
}

/// Extracts the 9-bit index into the page table at `level` from `virt`.
///
/// | Level | Bits    | Shift |
/// |-------|---------|-------|
/// | PML4  | \[47:39\] | 39    |
/// | PDPT  | \[38:30\] | 30    |
/// | PD    | \[29:21\] | 21    |
/// | PT    | \[20:12\] | 12    |
#[inline]
#[must_use]
pub const fn virt_index(virt: VirtAddr, level: PageLevel) -> usize {
    let shift = match level {
        PageLevel::Pml4 => 39u64,
        PageLevel::Pdpt => 30u64,
        PageLevel::Pd => 21u64,
        PageLevel::Pt => 12u64,
    };
    ((virt.0 >> shift) & 0x1FF) as usize
}

// -----------------------------------------------------------------------
// PageMapper
// -----------------------------------------------------------------------

/// Page-table mapper backed by the bootloader's direct physical-memory map.
///
/// `phys_offset` is `BootInfo.physical_memory_offset` — the virtual address
/// at which the entire physical address space is mapped linearly. Physical
/// address `p` is accessible at `phys_offset + p`. `root_phys` is the
/// physical address of the PML4 table read from CR3.
///
/// ## Safety invariant
///
/// The caller must ensure `phys_offset` correctly describes the direct map
/// and that `root_phys` is the physical address of the active PML4 table.
/// Using incorrect values will dereference arbitrary virtual memory.
pub struct PageMapper {
    phys_offset: u64,
    /// Physical address of the PML4 root table (from CR3).
    pub root_phys: PhysAddr,
}

impl PageMapper {
    /// Constructs a mapper from the bootloader's direct-map offset and
    /// the physical address of the PML4 (from CR3, low 12 bits masked).
    #[must_use]
    pub fn new(phys_offset: u64, root_phys: PhysAddr) -> Self {
        Self {
            phys_offset,
            root_phys,
        }
    }

    /// Direct-map offset (`BootInfo.physical_memory_offset`). Used by
    /// `super::address_space::AddressSpace` to read/write raw page-table
    /// frames through the bootloader's direct map.
    #[must_use]
    pub const fn phys_offset(&self) -> u64 {
        self.phys_offset
    }

    /// Translates a virtual address to a physical address by walking the
    /// active 4-level page tables.
    ///
    /// Follows PS=1 entries at PDPT (1 GiB) and PD (2 MiB) levels and
    /// returns the physical address with the appropriate page offset.
    /// Returns `None` only if any traversed entry is not-present.
    #[must_use]
    #[allow(
        clippy::similar_names,
        reason = "page-table level variable names are intentionally terse"
    )]
    /// Translate a VA using an explicit page-table root (e.g. a per-process PML4).
    pub fn translate_in(&self, root: PhysAddr, virt: VirtAddr) -> Option<PhysAddr> {
        let pml4 = self.table_ptr(root);
        let pml4e = unsafe { (*pml4).entry(virt_index(virt, PageLevel::Pml4)) };
        if !pml4e.is_present() {
            return None;
        }
        let pdpt = self.table_ptr(pml4e.phys_addr());
        let pdpte = unsafe { (*pdpt).entry(virt_index(virt, PageLevel::Pdpt)) };
        if !pdpte.is_present() {
            return None;
        }
        if pdpte.0 & PTE_HUGE != 0 {
            return Some(PhysAddr(
                (pdpte.0 & HUGE_1G_FRAME_MASK) + (virt.0 & HUGE_1G_OFFSET_MASK),
            ));
        }
        let pd = self.table_ptr(pdpte.phys_addr());
        let pde = unsafe { (*pd).entry(virt_index(virt, PageLevel::Pd)) };
        if !pde.is_present() {
            return None;
        }
        if pde.0 & PTE_HUGE != 0 {
            return Some(PhysAddr(
                (pde.0 & HUGE_2M_FRAME_MASK) + (virt.0 & HUGE_2M_OFFSET_MASK),
            ));
        }
        let pt = self.table_ptr(pde.phys_addr());
        let pte = unsafe { (*pt).entry(virt_index(virt, PageLevel::Pt)) };
        if !pte.is_present() {
            return None;
        }
        Some(PhysAddr(pte.phys_addr().0 + (virt.0 & 0xFFF)))
    }

    /// Translate a VA through the mapper's own root page table.
    // justification: pml4e/pdpte/pde/pte are the canonical x86_64 page-table
    // entry names from the Intel SDM Vol.3A Table 4-1; renaming hurts auditability.
    #[allow(clippy::similar_names)]
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let pml4 = self.table_ptr(self.root_phys);
        let pml4e = unsafe { (*pml4).entry(virt_index(virt, PageLevel::Pml4)) };
        if !pml4e.is_present() {
            return None;
        }

        let pdpt = self.table_ptr(pml4e.phys_addr());
        let pdpte = unsafe { (*pdpt).entry(virt_index(virt, PageLevel::Pdpt)) };
        if !pdpte.is_present() {
            return None;
        }
        if pdpte.0 & PTE_HUGE != 0 {
            // 1 GiB page: frame is bits [51:30], offset is the low 30 bits of virt.
            let frame = pdpte.0 & HUGE_1G_FRAME_MASK;
            let offset = virt.0 & HUGE_1G_OFFSET_MASK;
            return Some(PhysAddr(frame + offset));
        }

        let pd = self.table_ptr(pdpte.phys_addr());
        let pde = unsafe { (*pd).entry(virt_index(virt, PageLevel::Pd)) };
        if !pde.is_present() {
            return None;
        }
        if pde.0 & PTE_HUGE != 0 {
            // 2 MiB page: frame is bits [51:21], offset is the low 21 bits of virt.
            let frame = pde.0 & HUGE_2M_FRAME_MASK;
            let offset = virt.0 & HUGE_2M_OFFSET_MASK;
            return Some(PhysAddr(frame + offset));
        }

        let pt = self.table_ptr(pde.phys_addr());
        let pte = unsafe { (*pt).entry(virt_index(virt, PageLevel::Pt)) };
        if !pte.is_present() {
            return None;
        }

        let page_offset = virt.0 & 0xFFF;
        Some(PhysAddr(pte.phys_addr().0 + page_offset))
    }

    /// Effective access for `virt` in the page tables rooted at `root`.
    ///
    /// Returns `None` if any level of the walk is not present (the page is
    /// unmapped), otherwise `Some(writable)` where `writable` is the AND of the
    /// `PTE_WRITABLE` bit across every level traversed — the effective
    /// supervisor write permission when `CR0.WP` is set (which it is). Huge
    /// pages terminate the walk early at their mapping level.
    // pml4e/pdpte/pde/pte are the canonical x86_64 PTE names (Intel SDM 3A);
    // renaming hurts auditability — same rationale as `translate`.
    #[allow(clippy::similar_names)]
    fn page_access_in(&self, root: PhysAddr, virt: VirtAddr) -> Option<bool> {
        let mut writable = true;
        let pml4 = self.table_ptr(root);
        let pml4e = unsafe { (*pml4).entry(virt_index(virt, PageLevel::Pml4)) };
        if !pml4e.is_present() {
            return None;
        }
        writable &= pml4e.0 & PTE_WRITABLE != 0;

        let pdpt = self.table_ptr(pml4e.phys_addr());
        let pdpte = unsafe { (*pdpt).entry(virt_index(virt, PageLevel::Pdpt)) };
        if !pdpte.is_present() {
            return None;
        }
        writable &= pdpte.0 & PTE_WRITABLE != 0;
        if pdpte.0 & PTE_HUGE != 0 {
            return Some(writable);
        }

        let pd = self.table_ptr(pdpte.phys_addr());
        let pde = unsafe { (*pd).entry(virt_index(virt, PageLevel::Pd)) };
        if !pde.is_present() {
            return None;
        }
        writable &= pde.0 & PTE_WRITABLE != 0;
        if pde.0 & PTE_HUGE != 0 {
            return Some(writable);
        }

        let pt = self.table_ptr(pde.phys_addr());
        let pte = unsafe { (*pt).entry(virt_index(virt, PageLevel::Pt)) };
        if !pte.is_present() {
            return None;
        }
        writable &= pte.0 & PTE_WRITABLE != 0;
        Some(writable)
    }

    /// Whether every 4 KiB page spanning `[virt, virt + len)` is present in the
    /// tables rooted at `root` and, when `write` is set, writable.
    ///
    /// The syscall user-copy layer ([`super::uaccess`]) calls this to turn a
    /// bad user pointer into an `EFAULT` *before* it dereferences it, rather
    /// than `#PF`-ing the kernel mid-copy (NCIP-026 WI-4b §32 — probe variant;
    /// the exception path is panic-only, so we prevent the fault instead of
    /// recovering from it). `len == 0` is trivially accessible. Returns `false`
    /// on address overflow.
    #[must_use]
    pub fn range_accessible_in(
        &self,
        root: PhysAddr,
        virt: VirtAddr,
        len: usize,
        write: bool,
    ) -> bool {
        if len == 0 {
            return true;
        }
        let Some(end) = virt.0.checked_add(len as u64) else {
            return false;
        };
        let mut page = virt.0 & !0xFFF;
        while page < end {
            match self.page_access_in(root, VirtAddr(page)) {
                Some(writable) if !write || writable => {}
                _ => return false,
            }
            page = match page.checked_add(0x1000) {
                Some(next) => next,
                None => return false,
            };
        }
        true
    }

    /// Maps the 4 KiB page at `virt` to physical frame `phys` with `flags`,
    /// using `self.root_phys` as the root PML4. Thin wrapper around
    /// [`Self::map_4k_into`] for the common case of mapping into the
    /// active address space.
    pub fn map_4k<const N: usize>(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: u64,
        alloc: &mut BitmapFrameAllocator<N>,
    ) -> bool {
        let root = self.root_phys;
        self.map_4k_into(root, virt, phys, flags, alloc)
    }

    /// Maps the 4 KiB page at `virt` to physical frame `phys` with `flags`
    /// in the page-table tree rooted at `root_phys`.
    ///
    /// MB11: required by [`super::address_space::AddressSpace`] to map
    /// pages into per-process PML4s without mutating `self.root_phys`.
    ///
    /// Intermediate page-table frames (PDPT, PD, PT) are allocated from
    /// `alloc` as needed; they are always mapped with PRESENT | WRITABLE.
    ///
    /// Returns `false` if:
    /// - the allocator could not provide a frame for a missing table,
    /// - the target page was already mapped.
    #[allow(
        clippy::similar_names,
        reason = "page-table level variable names are intentionally terse"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "the explicit 4-level walk (kept verbose for auditability) plus \
                  the WS1-09 huge-page split branch exceed the 100-line lint by a few lines"
    )]
    pub fn map_4k_into<const N: usize>(
        &mut self,
        root_phys: PhysAddr,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: u64,
        alloc: &mut BitmapFrameAllocator<N>,
    ) -> bool {
        let pml4_idx = virt_index(virt, PageLevel::Pml4);
        let pdpt_idx = virt_index(virt, PageLevel::Pdpt);
        let pd_idx = virt_index(virt, PageLevel::Pd);
        let pt_idx = virt_index(virt, PageLevel::Pt);

        // Intermediate page-table entries (PML4E, PDPTE, PDE) must carry
        // PTE_USER when the leaf PTE is user-accessible, otherwise the CPU
        // raises #PF on any Ring 3 access regardless of the leaf flags.
        let intermediate_flags = if flags & PTE_USER != 0 {
            PTE_PRESENT | PTE_WRITABLE | PTE_USER
        } else {
            PTE_PRESENT | PTE_WRITABLE
        };

        // PML4 → PDPT
        let pml4 = self.table_ptr_mut(root_phys);
        let pdpt_phys = {
            let e = unsafe { (*pml4).entry(pml4_idx) };
            if e.is_present() {
                // If the entry exists but lacks USER and we need it, upgrade.
                if flags & PTE_USER != 0 && e.0 & PTE_USER == 0 {
                    unsafe {
                        (*pml4)
                            .entry_mut(pml4_idx)
                            .set_frame(e.phys_addr(), intermediate_flags);
                    }
                }
                e.phys_addr()
            } else {
                let Some(f) = alloc.alloc_frame() else {
                    return false;
                };
                unsafe {
                    self.zero_table(f);
                }
                unsafe {
                    (*pml4).entry_mut(pml4_idx).set_frame(f, intermediate_flags);
                }
                f
            }
        };

        // PDPT → PD
        let pdpt = self.table_ptr_mut(pdpt_phys);
        let pd_phys = {
            let e = unsafe { (*pdpt).entry(pdpt_idx) };
            if e.is_present() {
                if e.0 & PTE_HUGE != 0 {
                    // A 1 GiB huge page is mapped here. Split it into a fresh PD
                    // of 512 × 2 MiB huge entries reproducing the same range with
                    // the parent's flags (WS1-09.3). The 2 MiB entry covering the
                    // target is split again into 4 KiB at the PD→PT step below.
                    let Some(new_pd) = self.split_1g_pdpte(e, alloc) else {
                        return false;
                    };
                    let mut pdpte_flags = intermediate_flags;
                    if e.0 & PTE_USER != 0 {
                        pdpte_flags |= PTE_USER;
                    }
                    unsafe {
                        (*pdpt).entry_mut(pdpt_idx).set_frame(new_pd, pdpte_flags);
                    }
                    new_pd
                } else {
                    if flags & PTE_USER != 0 && e.0 & PTE_USER == 0 {
                        unsafe {
                            (*pdpt)
                                .entry_mut(pdpt_idx)
                                .set_frame(e.phys_addr(), intermediate_flags);
                        }
                    }
                    e.phys_addr()
                }
            } else {
                let Some(f) = alloc.alloc_frame() else {
                    return false;
                };
                unsafe {
                    self.zero_table(f);
                }
                unsafe {
                    (*pdpt).entry_mut(pdpt_idx).set_frame(f, intermediate_flags);
                }
                f
            }
        };

        // PD → PT
        let pd = self.table_ptr_mut(pd_phys);
        let pt_phys = {
            let e = unsafe { (*pd).entry(pd_idx) };
            if e.is_present() {
                if e.0 & PTE_HUGE != 0 {
                    // A 2 MiB huge page is mapped here. Split it into a fresh
                    // page table of 512 × 4 KiB entries that reproduce the same
                    // physical range with the parent's flags (WS1-09.2/.4),
                    // leaving the target slot free so the new leaf mapping below
                    // installs into it. The caller is responsible for the TLB
                    // flush, exactly as for `unmap_4k`.
                    let Some(new_pt) = self.split_2m_pde(e, pt_idx, alloc) else {
                        return false;
                    };
                    // The PDE now points at a page table, not a 2 MiB frame:
                    // present + writable, carrying USER if either the parent
                    // huge page or the incoming mapping is user-accessible.
                    let mut pde_flags = intermediate_flags;
                    if e.0 & PTE_USER != 0 {
                        pde_flags |= PTE_USER;
                    }
                    unsafe {
                        (*pd).entry_mut(pd_idx).set_frame(new_pt, pde_flags);
                    }
                    new_pt
                } else {
                    if flags & PTE_USER != 0 && e.0 & PTE_USER == 0 {
                        unsafe {
                            (*pd)
                                .entry_mut(pd_idx)
                                .set_frame(e.phys_addr(), intermediate_flags);
                        }
                    }
                    e.phys_addr()
                }
            } else {
                let Some(f) = alloc.alloc_frame() else {
                    return false;
                };
                unsafe {
                    self.zero_table(f);
                }
                unsafe {
                    (*pd).entry_mut(pd_idx).set_frame(f, intermediate_flags);
                }
                f
            }
        };

        // Leaf PT entry
        let pt = self.table_ptr_mut(pt_phys);
        let existing = unsafe { (*pt).entry(pt_idx) };
        if existing.is_present() {
            return false;
        } // already mapped
        unsafe { (*pt).entry_mut(pt_idx).set_frame(phys, flags | PTE_PRESENT) };
        true
    }

    /// Split the 2 MiB huge page described by `pde` into a fresh page table of
    /// 512 × 4 KiB entries that reproduce the same physical range, preserving
    /// the parent's access flags, and return the new PT's physical frame
    /// (WS1-09.2/.4). The entry at `skip_idx` is left **not-present** so the
    /// caller can install a fresh leaf mapping there (the sub-page being
    /// remapped).
    ///
    /// Flag handling: child PTEs inherit the parent's low flag bits — minus
    /// `PTE_HUGE` (bit 7), which at PT level is the PAT bit, not a page-size
    /// bit — plus the parent's NX. Clearing bit 7 leaves PAT=0 (write-back),
    /// which is exact for every current kernel huge page (the bootloader
    /// direct map is write-back); a future non-WB huge page would need the
    /// 2 MiB-PAT (bit 12) → 4 KiB-PAT (bit 7) translation added here.
    ///
    /// Returns `None` if the allocator cannot provide a frame for the new PT.
    fn split_2m_pde<const N: usize>(
        &self,
        pde: PageTableEntry,
        skip_idx: usize,
        alloc: &mut BitmapFrameAllocator<N>,
    ) -> Option<PhysAddr> {
        debug_assert!(pde.0 & PTE_HUGE != 0, "split_2m_pde requires a PS=1 PDE");
        let huge_frame = pde.0 & HUGE_2M_FRAME_MASK;
        // Parent low flags (bits [11:0]) minus PS, plus the parent NX bit.
        let child_flags = (pde.0 & 0xFFF & !PTE_HUGE) | (pde.0 & PTE_NO_EXEC) | PTE_PRESENT;
        let pt_frame = alloc.alloc_frame()?;
        // SAFETY: `pt_frame` is a freshly allocated, exclusively-owned frame;
        // zero it before publishing any entries.
        unsafe {
            self.zero_table(pt_frame);
        }
        let pt = self.table_ptr_mut(pt_frame);
        let mut k: usize = 0;
        while k < 512 {
            if k != skip_idx {
                // Each child covers one 4 KiB slice of the 2 MiB frame.
                let child_phys = PhysAddr(huge_frame + (k as u64) * 0x1000);
                // SAFETY: `pt` points at the just-zeroed PT in the direct map;
                // `k < 512` is in bounds for the 512-entry table.
                unsafe {
                    (*pt).entry_mut(k).set_frame(child_phys, child_flags);
                }
            }
            k += 1;
        }
        Some(pt_frame)
    }

    /// Split the 1 GiB huge page described by `pdpte` into a fresh page
    /// directory of 512 × 2 MiB **huge** entries that reproduce the same
    /// physical range, preserving the parent's flags, and return the new PD's
    /// physical frame (WS1-09.3/.4).
    ///
    /// Every child stays a 2 MiB huge page (PS=1): no slot is skipped, because
    /// the 2 MiB entry covering the remap target is itself split into 4 KiB by
    /// [`Self::split_2m_pde`] when `map_4k_into` continues to the PD→PT level.
    /// Child flags are the parent's low bits (which already include PS) plus
    /// NX; the PAT bit (bit 12) has the same position in 1 GiB and 2 MiB
    /// entries, and is 0 (write-back) for every current kernel huge page.
    ///
    /// Returns `None` if the allocator cannot provide a frame for the new PD.
    fn split_1g_pdpte<const N: usize>(
        &self,
        pdpte: PageTableEntry,
        alloc: &mut BitmapFrameAllocator<N>,
    ) -> Option<PhysAddr> {
        debug_assert!(
            pdpte.0 & PTE_HUGE != 0,
            "split_1g_pdpte requires a PS=1 PDPTE"
        );
        let huge_frame = pdpte.0 & HUGE_1G_FRAME_MASK;
        // Parent low flags (bits [11:0], already including PS) plus NX. Each
        // child remains a 2 MiB huge page, so PS is kept (unlike the 2M→4K split).
        let child_flags = (pdpte.0 & 0xFFF) | (pdpte.0 & PTE_NO_EXEC) | PTE_PRESENT | PTE_HUGE;
        let pd_frame = alloc.alloc_frame()?;
        // SAFETY: `pd_frame` is a freshly allocated, exclusively-owned frame;
        // zero it before publishing any entries.
        unsafe {
            self.zero_table(pd_frame);
        }
        let pd = self.table_ptr_mut(pd_frame);
        let mut k: usize = 0;
        while k < 512 {
            // Each child covers one 2 MiB slice of the 1 GiB frame.
            let child_phys = PhysAddr(huge_frame + (k as u64) * 0x20_0000);
            // SAFETY: `pd` points at the just-zeroed PD in the direct map;
            // `k < 512` is in bounds for the 512-entry table.
            unsafe {
                (*pd).entry_mut(k).set_frame(child_phys, child_flags);
            }
            k += 1;
        }
        Some(pd_frame)
    }

    /// Unmaps the 4 KiB page at `virt` and invalidates the TLB entry.
    ///
    /// Returns `false` if the page was not present (no-op).
    #[allow(
        clippy::similar_names,
        reason = "page-table level variable names are intentionally terse"
    )]
    #[allow(
        clippy::needless_pass_by_ref_mut,
        reason = "mutation occurs through raw pointers in the direct-map window"
    )]
    pub fn unmap_4k(&mut self, virt: VirtAddr) -> bool {
        let pml4 = self.table_ptr(self.root_phys);
        let pml4e = unsafe { (*pml4).entry(virt_index(virt, PageLevel::Pml4)) };
        if !pml4e.is_present() {
            return false;
        }

        let pdpt = self.table_ptr(pml4e.phys_addr());
        let pdpte = unsafe { (*pdpt).entry(virt_index(virt, PageLevel::Pdpt)) };
        if !pdpte.is_present() {
            return false;
        }

        let pd = self.table_ptr(pdpte.phys_addr());
        let pde = unsafe { (*pd).entry(virt_index(virt, PageLevel::Pd)) };
        if !pde.is_present() {
            return false;
        }

        let pt = self.table_ptr_mut(pde.phys_addr());
        let pte = unsafe { (*pt).entry(virt_index(virt, PageLevel::Pt)) };
        if !pte.is_present() {
            return false;
        }

        unsafe {
            (*pt).entry_mut(virt_index(virt, PageLevel::Pt)).clear();
        }
        // Invalidate TLB — only meaningful on bare-metal; no-op on non-x86 hosts.
        #[cfg(all(target_arch = "x86_64", not(test)))]
        unsafe {
            super::arch::invlpg(virt.0);
        }
        true
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Converts a physical address to a `*const RawPageTable` via the
    /// direct-map window: `phys_offset + p`.
    #[inline]
    fn table_ptr(&self, phys: PhysAddr) -> *const RawPageTable {
        self.phys_offset.wrapping_add(phys.0) as *const RawPageTable
    }

    /// Mutable variant of [`table_ptr`](Self::table_ptr).
    #[inline]
    fn table_ptr_mut(&self, phys: PhysAddr) -> *mut RawPageTable {
        self.phys_offset.wrapping_add(phys.0) as *mut RawPageTable
    }

    /// Zeroes all 4 096 bytes of the page-table frame at `phys`.
    ///
    /// # Safety
    ///
    /// Caller must ensure `phys` is a freshly-allocated, non-aliased frame
    /// within the direct-map window.
    unsafe fn zero_table(&self, phys: PhysAddr) {
        let ptr = self.table_ptr_mut(phys).cast::<u8>();
        unsafe { core::ptr::write_bytes(ptr, 0, 4096) };
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BitmapFrameAllocator;

    // 64 frames of fake physical memory (256 KiB).
    // Using heap allocation to guarantee 4096-byte alignment.
    const ARENA_FRAMES: u64 = 64;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "64 fits usize on every supported target"
    )]
    const ARENA_SIZE: usize = ARENA_FRAMES as usize * 4096;
    const PHYS_BASE: u64 = 0x0100_0000; // 16 MiB — arbitrary "physical" base

    /// Per-test arena: a single heap allocation that stands in for physical
    /// RAM in unit tests.
    ///
    /// Each call to [`TestArena::new`] produces an independent, zero-filled
    /// allocation aligned to 4 096 bytes. Because every `TestArena` owns its
    /// own backing buffer there is **no shared global state** between test
    /// instances; tests can run in parallel without any synchronisation.
    ///
    /// The `phys_offset` method returns the value to pass as
    /// [`PageMapper::new`]'s first argument so that `phys + phys_offset`
    /// resolves to the correct virtual address within the arena buffer.
    struct TestArena {
        ptr: *mut u8,
        layout: std::alloc::Layout,
    }

    // SAFETY: `TestArena` owns the heap allocation exclusively. `ptr` is never
    // aliased — no other `TestArena` or code holds a reference to the same
    // allocation. It is therefore safe to transfer ownership of a `TestArena`
    // to another thread: the owning thread's `Drop` will run exactly once, and
    // until then the pointer is valid and unaliased.
    unsafe impl Send for TestArena {}

    impl TestArena {
        /// Allocates a fresh, zero-filled arena of [`ARENA_SIZE`] bytes
        /// aligned to 4 096 bytes.
        ///
        /// Panics if the global allocator cannot satisfy the request (only
        /// possible if the test runner is memory-constrained, not a code bug).
        fn new() -> Self {
            let layout = std::alloc::Layout::from_size_align(ARENA_SIZE, 4096)
                .expect("ARENA_SIZE and alignment are compile-time constants and always valid");
            // SAFETY: `layout` has non-zero size (ARENA_SIZE = 64 * 4096) and
            // power-of-two alignment (4096). The returned pointer is checked
            // for null immediately below.
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null(), "test arena allocation failed");
            Self { ptr, layout }
        }

        /// Returns the `phys_offset` value for [`PageMapper::new`]: the
        /// difference `arena_base_virt - PHYS_BASE`, so that the mapper's
        /// `phys + phys_offset` arithmetic resolves to the correct byte inside
        /// this arena buffer.
        fn phys_offset(&self) -> u64 {
            (self.ptr as u64).wrapping_sub(PHYS_BASE)
        }
    }

    impl Drop for TestArena {
        fn drop(&mut self) {
            // SAFETY: `self.ptr` was obtained from `alloc_zeroed` with
            // `self.layout` in `new()`, and this `Drop` impl runs exactly
            // once per `TestArena`.
            unsafe { std::alloc::dealloc(self.ptr, self.layout) };
        }
    }

    /// Creates a ready-to-use mapper backed by a fresh, independently
    /// allocated [`TestArena`].
    ///
    /// The returned tuple keeps the arena alive for the duration of the test:
    /// the caller must bind it (e.g. `let (_arena, mapper, alloc) = ...`);
    /// dropping `_arena` before using `mapper` would be a use-after-free.
    ///
    /// Because every call allocates a new arena on the heap, multiple calls
    /// within the same test — or across concurrent tests — produce completely
    /// independent memory regions with no aliasing.
    fn make_mapper() -> (TestArena, PageMapper, BitmapFrameAllocator<1>) {
        let arena = TestArena::new();
        let phys_offset = arena.phys_offset();

        // Frame 0 at PHYS_BASE is the PML4.  Mark the rest free.
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(PHYS_BASE));
        alloc.mark_range_free(PhysAddr(PHYS_BASE), ARENA_FRAMES * 4096);
        alloc.mark_range_used(PhysAddr(PHYS_BASE), 4096); // PML4 is pre-allocated

        let mapper = PageMapper::new(phys_offset, PhysAddr(PHYS_BASE));
        (arena, mapper, alloc)
    }

    // -------------------------------------------------------------------
    // virt_index tests
    // -------------------------------------------------------------------

    #[test]
    fn virt_index_zero_address() {
        let v = VirtAddr(0x0000_0000_0000_0000);
        assert_eq!(virt_index(v, PageLevel::Pml4), 0);
        assert_eq!(virt_index(v, PageLevel::Pdpt), 0);
        assert_eq!(virt_index(v, PageLevel::Pd), 0);
        assert_eq!(virt_index(v, PageLevel::Pt), 0);
    }

    #[test]
    fn virt_index_known_values() {
        // Pack indices 1,2,3,4 into the 4 levels.
        let virt = VirtAddr((1u64 << 39) | (2u64 << 30) | (3u64 << 21) | (4u64 << 12));
        assert_eq!(virt_index(virt, PageLevel::Pml4), 1);
        assert_eq!(virt_index(virt, PageLevel::Pdpt), 2);
        assert_eq!(virt_index(virt, PageLevel::Pd), 3);
        assert_eq!(virt_index(virt, PageLevel::Pt), 4);
    }

    #[test]
    fn virt_index_max_indices() {
        // All indices = 511 (0x1FF).
        let virt =
            VirtAddr((0x1FFu64 << 39) | (0x1FFu64 << 30) | (0x1FFu64 << 21) | (0x1FFu64 << 12));
        assert_eq!(virt_index(virt, PageLevel::Pml4), 511);
        assert_eq!(virt_index(virt, PageLevel::Pdpt), 511);
        assert_eq!(virt_index(virt, PageLevel::Pd), 511);
        assert_eq!(virt_index(virt, PageLevel::Pt), 511);
    }

    // -------------------------------------------------------------------
    // PageTableEntry tests
    // -------------------------------------------------------------------

    #[test]
    fn entry_default_not_present() {
        let e = PageTableEntry::default();
        assert!(!e.is_present());
        assert_eq!(e.phys_addr(), PhysAddr(0));
    }

    #[test]
    fn entry_set_and_read_frame() {
        let mut e = PageTableEntry(0);
        e.set_frame(PhysAddr(0x0000_DEAD_0000_0000), PTE_PRESENT | PTE_WRITABLE);
        assert!(e.is_present());
        assert_eq!(e.phys_addr(), PhysAddr(0x0000_DEAD_0000_0000));
    }

    #[test]
    fn entry_low_flag_bits_not_in_phys_addr() {
        let e = PageTableEntry(0x0000_DEAD_0000_0FFF);
        assert_eq!(e.phys_addr(), PhysAddr(0x0000_DEAD_0000_0000));
    }

    #[test]
    fn entry_clear_zeroes_all() {
        let mut e = PageTableEntry(0xFFFF_FFFF_FFFF_FFFF);
        e.clear();
        assert_eq!(e, PageTableEntry(0));
        assert!(!e.is_present());
    }

    // -------------------------------------------------------------------
    // PageMapper tests
    // -------------------------------------------------------------------

    #[test]
    fn translate_unmapped_is_none() {
        let (_arena, mapper, _alloc) = make_mapper();
        assert!(mapper.translate(VirtAddr(0x0000_0000_1234_5000)).is_none());
    }

    #[test]
    fn map_and_translate_round_trip() {
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let virt = VirtAddr(0x0000_0001_0000_0000);
        let phys = PhysAddr(0x0000_0002_0000_0000);
        assert!(mapper.map_4k(virt, phys, PTE_WRITABLE, &mut alloc));
        assert_eq!(mapper.translate(virt), Some(phys));
    }

    #[test]
    fn translate_preserves_page_offset() {
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let phys_base = PhysAddr(0x0000_0003_0000_0000);
        let virt_page = VirtAddr(0x0000_0001_8000_0000);
        assert!(mapper.map_4k(virt_page, phys_base, 0, &mut alloc));
        // Address within the page — offset should be added to phys_base.
        assert_eq!(
            mapper.translate(VirtAddr(virt_page.0 + 0xA00)),
            Some(PhysAddr(phys_base.0 + 0xA00)),
        );
    }

    #[test]
    fn range_accessible_in_reflects_presence_and_writability() {
        // NCIP-026 WI-4b §32 (probe): the user-copy layer relies on this to
        // reject unmapped / read-only user pointers before dereferencing them.
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let root = mapper.root_phys;
        let va = VirtAddr(0x0000_0001_8000_0000);
        let phys = PhysAddr(0x0000_0003_0000_0000);

        // Unmapped: any non-empty access is rejected; zero length is trivial.
        assert!(!mapper.range_accessible_in(root, va, 0x1000, false));
        assert!(mapper.range_accessible_in(root, va, 0, true));

        // Writable mapping: both read and write probes pass, including a
        // sub-page tail within the same page.
        assert!(mapper.map_4k(va, phys, PTE_WRITABLE | PTE_USER, &mut alloc));
        assert!(mapper.range_accessible_in(root, va, 0x1000, false));
        assert!(mapper.range_accessible_in(root, va, 0x1000, true));
        assert!(mapper.range_accessible_in(root, VirtAddr(va.0 + 0xFFF), 1, true));

        // A range that crosses into the next (unmapped) page is rejected.
        assert!(!mapper.range_accessible_in(root, va, 0x1001, false));

        // Read-only mapping: the read probe passes, the write probe is rejected.
        let ro_va = VirtAddr(va.0 + 0x3000);
        let ro_phys = PhysAddr(phys.0 + 0x3000);
        assert!(mapper.map_4k(ro_va, ro_phys, PTE_USER, &mut alloc));
        assert!(mapper.range_accessible_in(root, ro_va, 0x1000, false));
        assert!(!mapper.range_accessible_in(root, ro_va, 0x1000, true));
    }

    #[test]
    fn unmap_not_present_returns_false() {
        let (_arena, mut mapper, _alloc) = make_mapper();
        assert!(!mapper.unmap_4k(VirtAddr(0x0000_DEAD_BEEF_0000)));
    }

    #[test]
    fn map_then_unmap_then_translate_is_none() {
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let virt = VirtAddr(0x0000_0000_8000_0000);
        let phys = PhysAddr(0x0000_0001_0000_0000);
        assert!(mapper.map_4k(virt, phys, 0, &mut alloc));
        assert_eq!(mapper.translate(virt), Some(phys));
        assert!(mapper.unmap_4k(virt));
        assert!(mapper.translate(virt).is_none());
    }

    #[test]
    fn double_map_returns_false() {
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let virt = VirtAddr(0x0000_0000_4000_0000);
        let phys = PhysAddr(0x0000_0004_0000_0000);
        assert!(mapper.map_4k(virt, phys, 0, &mut alloc));
        assert!(!mapper.map_4k(virt, phys, 0, &mut alloc));
    }

    #[test]
    fn double_unmap_returns_false() {
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let virt = VirtAddr(0x0000_0000_2000_0000);
        let phys = PhysAddr(0x0000_0005_0000_0000);
        assert!(mapper.map_4k(virt, phys, 0, &mut alloc));
        assert!(mapper.unmap_4k(virt));
        assert!(!mapper.unmap_4k(virt));
    }

    #[test]
    fn adjacent_pages_share_intermediate_tables() {
        let (_arena, mut mapper, mut alloc) = make_mapper();
        // Two pages in the same PT (differ only in PT index).
        let virt1 = VirtAddr(0x0000_0000_1000_0000); // PT idx 0
        let virt2 = VirtAddr(0x0000_0000_1000_1000); // PT idx 1
        let phys1 = PhysAddr(0x0000_0010_0000_0000);
        let phys2 = PhysAddr(0x0000_0011_0000_0000);

        let frames_before = alloc.free_frames();
        assert!(mapper.map_4k(virt1, phys1, 0, &mut alloc));
        let frames_after_first = alloc.free_frames();
        // First map allocates 3 intermediate frames (PDPT, PD, PT).
        assert_eq!(frames_before - frames_after_first, 3);

        assert!(mapper.map_4k(virt2, phys2, 0, &mut alloc));
        let frames_after_second = alloc.free_frames();
        // Second map reuses all 3 existing tables — 0 new frames.
        assert_eq!(frames_after_first - frames_after_second, 0);

        assert_eq!(mapper.translate(virt1), Some(phys1));
        assert_eq!(mapper.translate(virt2), Some(phys2));
    }

    #[test]
    fn out_of_frames_returns_false() {
        let (_arena, mut mapper, mut alloc) = make_mapper();
        // Exhaust all free frames.
        while alloc.alloc_frame().is_some() {}
        // With no frames left, map_4k must fail.
        let result = mapper.map_4k(
            VirtAddr(0x0000_0000_F000_0000),
            PhysAddr(0x0000_0006_0000_0000),
            0,
            &mut alloc,
        );
        assert!(!result);
    }

    // -------------------------------------------------------------------
    // Huge-page translate tests (MB9)
    // -------------------------------------------------------------------

    /// Writes a 1 GiB huge-page PDPTE at `pdpt_idx` pointing to `huge_frame`,
    /// installing a PML4E that references a fresh PDPT in the arena at
    /// `pdpt_phys`. Returns nothing — the mapper observes the change via the
    /// direct-map window.
    fn install_1g_huge(
        mapper: &mut PageMapper,
        pdpt_phys: PhysAddr,
        pml4_idx: usize,
        pdpt_idx: usize,
        huge_frame: u64,
    ) {
        let pml4 = mapper.table_ptr_mut(mapper.root_phys);
        unsafe {
            (*pml4)
                .entry_mut(pml4_idx)
                .set_frame(pdpt_phys, PTE_PRESENT | PTE_WRITABLE);
            let pdpt = mapper.table_ptr_mut(pdpt_phys);
            (*pdpt).entry_mut(pdpt_idx).0 = huge_frame | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE;
        }
    }

    /// Same as `install_1g_huge` but at PD level — installs PML4→PDPT→PD chain
    /// and writes a 2 MiB huge-page PDE at `pd_idx` pointing to `huge_frame`.
    fn install_2m_huge(
        mapper: &mut PageMapper,
        pdpt_phys: PhysAddr,
        pd_phys: PhysAddr,
        pml4_idx: usize,
        pdpt_idx: usize,
        pd_idx: usize,
        huge_frame: u64,
    ) {
        let pml4 = mapper.table_ptr_mut(mapper.root_phys);
        unsafe {
            (*pml4)
                .entry_mut(pml4_idx)
                .set_frame(pdpt_phys, PTE_PRESENT | PTE_WRITABLE);
            let pdpt = mapper.table_ptr_mut(pdpt_phys);
            (*pdpt)
                .entry_mut(pdpt_idx)
                .set_frame(pd_phys, PTE_PRESENT | PTE_WRITABLE);
            let pd = mapper.table_ptr_mut(pd_phys);
            (*pd).entry_mut(pd_idx).0 = huge_frame | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE;
        }
    }

    #[test]
    fn translate_follows_1gib_huge_page_at_start() {
        let (_arena, mut mapper, _alloc) = make_mapper();
        let pdpt_phys = PhysAddr(PHYS_BASE + 4096);
        let huge_frame = 0x0000_0001_8000_0000u64; // 6 GiB, 1 GiB-aligned
        install_1g_huge(
            &mut mapper,
            pdpt_phys,
            /*pml4=*/ 0,
            /*pdpt=*/ 1,
            huge_frame,
        );
        // virt = PML4=0, PDPT=1 → (1 << 30) = 0x4000_0000
        assert_eq!(
            mapper.translate(VirtAddr(1u64 << 30)),
            Some(PhysAddr(huge_frame)),
        );
    }

    #[test]
    fn translate_follows_1gib_huge_page_middle_offset() {
        let (_arena, mut mapper, _alloc) = make_mapper();
        let pdpt_phys = PhysAddr(PHYS_BASE + 4096);
        let huge_frame = 0x0000_0001_8000_0000u64;
        install_1g_huge(&mut mapper, pdpt_phys, 0, 1, huge_frame);
        let virt = (1u64 << 30) + 0x1234_5678;
        assert_eq!(
            mapper.translate(VirtAddr(virt)),
            Some(PhysAddr(huge_frame + 0x1234_5678)),
        );
    }

    #[test]
    fn translate_follows_1gib_huge_page_last_byte() {
        let (_arena, mut mapper, _alloc) = make_mapper();
        let pdpt_phys = PhysAddr(PHYS_BASE + 4096);
        let huge_frame = 0x0000_0001_8000_0000u64;
        install_1g_huge(&mut mapper, pdpt_phys, 0, 1, huge_frame);
        let virt = (1u64 << 30) + 0x3FFF_FFFF; // last byte in the 1 GiB region
        assert_eq!(
            mapper.translate(VirtAddr(virt)),
            Some(PhysAddr(huge_frame + 0x3FFF_FFFF)),
        );
    }

    #[test]
    fn translate_follows_2mib_huge_page_at_start() {
        let (_arena, mut mapper, _alloc) = make_mapper();
        let pdpt_phys = PhysAddr(PHYS_BASE + 4096);
        let pd_phys = PhysAddr(PHYS_BASE + 8192);
        let huge_frame = 0x0000_0002_0040_0000u64; // 2 MiB-aligned (low 21 bits = 0)
        install_2m_huge(&mut mapper, pdpt_phys, pd_phys, 0, 0, 2, huge_frame);
        // virt = PD=2 → (2 << 21) = 0x40_0000
        assert_eq!(
            mapper.translate(VirtAddr(2u64 << 21)),
            Some(PhysAddr(huge_frame)),
        );
    }

    #[test]
    fn translate_follows_2mib_huge_page_middle_offset() {
        let (_arena, mut mapper, _alloc) = make_mapper();
        let pdpt_phys = PhysAddr(PHYS_BASE + 4096);
        let pd_phys = PhysAddr(PHYS_BASE + 8192);
        let huge_frame = 0x0000_0002_0040_0000u64;
        install_2m_huge(&mut mapper, pdpt_phys, pd_phys, 0, 0, 2, huge_frame);
        let virt = (2u64 << 21) + 0x10_0000; // 1 MiB into the 2 MiB page
        assert_eq!(
            mapper.translate(VirtAddr(virt)),
            Some(PhysAddr(huge_frame + 0x10_0000)),
        );
    }

    #[test]
    fn translate_follows_2mib_huge_page_last_byte() {
        let (_arena, mut mapper, _alloc) = make_mapper();
        let pdpt_phys = PhysAddr(PHYS_BASE + 4096);
        let pd_phys = PhysAddr(PHYS_BASE + 8192);
        let huge_frame = 0x0000_0002_0040_0000u64;
        install_2m_huge(&mut mapper, pdpt_phys, pd_phys, 0, 0, 2, huge_frame);
        let virt = (2u64 << 21) + 0x1F_FFFF; // last byte in the 2 MiB region
        assert_eq!(
            mapper.translate(VirtAddr(virt)),
            Some(PhysAddr(huge_frame + 0x1F_FFFF)),
        );
    }

    // -------------------------------------------------------------------
    // WS1-09.2: 2 MiB → 4 KiB split on sub-page remap
    // -------------------------------------------------------------------

    #[test]
    fn map_4k_inside_2mib_huge_splits_and_preserves_siblings() {
        // Remapping a 4 KiB sub-page of a 2 MiB huge page must split the PDE
        // into a 512-entry PT: the target sub-page takes the new mapping while
        // every sibling keeps resolving to the original 2 MiB frame's slice.
        let (_arena, mut mapper, mut alloc) = make_mapper();
        // Allocate the intermediate tables from the allocator so the split's
        // own frame allocation cannot alias them.
        let pdpt_phys = alloc.alloc_frame().expect("pdpt frame");
        let pd_phys = alloc.alloc_frame().expect("pd frame");
        let huge_frame = 0x0000_0002_0000_0000u64; // 8 GiB, 2 MiB-aligned
        // PML4=0, PDPT=0, PD=2 → VA base = 2 << 21 = 0x40_0000.
        install_2m_huge(&mut mapper, pdpt_phys, pd_phys, 0, 0, 2, huge_frame);
        let base = 2u64 << 21;

        // Pre-split sanity: the whole 2 MiB resolves into the huge frame.
        assert_eq!(mapper.translate(VirtAddr(base)), Some(PhysAddr(huge_frame)));
        assert_eq!(
            mapper.translate(VirtAddr(base + 0x5000)),
            Some(PhysAddr(huge_frame + 0x5000))
        );

        // Remap the 4 KiB sub-page at index 3 (base + 0x3000) to a new frame.
        let new_phys = PhysAddr(0x0000_0000_8000_0000); // distinct, 4 KiB-aligned
        let target = VirtAddr(base + 0x3000);
        assert!(mapper.map_4k(target, new_phys, PTE_PRESENT | PTE_WRITABLE, &mut alloc));

        // The remapped sub-page now points at the new frame …
        assert_eq!(mapper.translate(target), Some(new_phys));
        // … and every sibling still resolves to the original frame's slice.
        assert_eq!(mapper.translate(VirtAddr(base)), Some(PhysAddr(huge_frame))); // idx 0
        assert_eq!(
            mapper.translate(VirtAddr(base + 0x2000)),
            Some(PhysAddr(huge_frame + 0x2000)) // idx 2, just before target
        );
        assert_eq!(
            mapper.translate(VirtAddr(base + 0x4000)),
            Some(PhysAddr(huge_frame + 0x4000)) // idx 4, just after target
        );
        assert_eq!(
            mapper.translate(VirtAddr(base + 0x1F_F000)),
            Some(PhysAddr(huge_frame + 0x1F_F000)) // idx 511, last 4 KiB
        );

        // Flag flow (WS1-09.4, light check): the parent was writable, so both a
        // preserved sibling and the freshly installed leaf are writable.
        assert_eq!(
            mapper.page_access_in(mapper.root_phys, VirtAddr(base)),
            Some(true)
        );
        assert_eq!(mapper.page_access_in(mapper.root_phys, target), Some(true));
    }

    #[test]
    fn map_4k_in_2mib_splits_once_then_pt_is_reused() {
        // WS1-09.5: mapping a 4 KiB page inside a 2 MiB huge region splits the
        // PDE exactly once. After the split the other sub-pages are real,
        // present 4 KiB pages, so map_4k honours its no-clobber contract on
        // them; unmapping one and re-mapping it reuses the page table without a
        // second split (zero further frames).
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let pdpt_phys = alloc.alloc_frame().expect("pdpt");
        let pd_phys = alloc.alloc_frame().expect("pd");
        let huge_frame = 0x0000_0002_0000_0000u64;
        install_2m_huge(&mut mapper, pdpt_phys, pd_phys, 0, 0, 2, huge_frame);
        let base = 2u64 << 21;

        // Mapping sub-page idx 0 splits the 2 MiB: exactly one new page table.
        let p0 = PhysAddr(0x0000_0000_8000_0000);
        let before = alloc.free_frames();
        assert!(mapper.map_4k(VirtAddr(base), p0, PTE_PRESENT | PTE_WRITABLE, &mut alloc));
        assert_eq!(
            before - alloc.free_frames(),
            1,
            "split allocates exactly one PT"
        );
        assert_eq!(mapper.translate(VirtAddr(base)), Some(p0));

        // Every other sub-page is now a present 4 KiB page; map_4k refuses to
        // silently overwrite one (its no-clobber contract) and allocates nothing.
        let after_split = alloc.free_frames();
        let last = VirtAddr(base + 0x1F_F000); // idx 511, a preserved sibling
        assert!(
            !mapper.map_4k(
                last,
                PhysAddr(0x9000_0000),
                PTE_PRESENT | PTE_WRITABLE,
                &mut alloc
            ),
            "a preserved sibling is not silently overwritten"
        );
        assert_eq!(
            after_split,
            alloc.free_frames(),
            "the refused map allocates nothing"
        );

        // Unmapping that sibling and re-mapping it succeeds and reuses the PT
        // (the region is no longer huge) — no further page-table frames.
        assert!(mapper.unmap_4k(last));
        let p511 = PhysAddr(0x0000_0000_9000_0000);
        assert!(mapper.map_4k(last, p511, PTE_PRESENT | PTE_WRITABLE, &mut alloc));
        assert_eq!(
            after_split,
            alloc.free_frames(),
            "unmap+remap reuses the PT"
        );
        assert_eq!(mapper.translate(last), Some(p511));

        // A still-untouched middle sibling keeps the original frame's slice.
        assert_eq!(
            mapper.translate(VirtAddr(base + 0x10_0000)), // idx 256
            Some(PhysAddr(huge_frame + 0x10_0000))
        );
    }

    /// Walk to and return the 4 KiB leaf PTE for `virt`, or `None` if the walk
    /// hits a not-present or still-huge entry. Test-only inspector used to
    /// assert the exact flag bits preserved across a split (WS1-09.4).
    fn read_leaf_pte(mapper: &PageMapper, virt: VirtAddr) -> Option<PageTableEntry> {
        let pml4 = mapper.table_ptr(mapper.root_phys);
        let pml4e = unsafe { (*pml4).entry(virt_index(virt, PageLevel::Pml4)) };
        if !pml4e.is_present() {
            return None;
        }
        let pdpt = mapper.table_ptr(pml4e.phys_addr());
        let pdpte = unsafe { (*pdpt).entry(virt_index(virt, PageLevel::Pdpt)) };
        if !pdpte.is_present() || pdpte.0 & PTE_HUGE != 0 {
            return None;
        }
        let pd = mapper.table_ptr(pdpte.phys_addr());
        let pde = unsafe { (*pd).entry(virt_index(virt, PageLevel::Pd)) };
        if !pde.is_present() || pde.0 & PTE_HUGE != 0 {
            return None;
        }
        let pt = mapper.table_ptr(pde.phys_addr());
        Some(unsafe { (*pt).entry(virt_index(virt, PageLevel::Pt)) })
    }

    #[test]
    fn split_2m_preserves_parent_ro_user_nx_flags() {
        // A read-only, user-accessible, no-execute 2 MiB page, split by a new
        // sub-page mapping, must hand those exact flags to every preserved
        // sibling — while the freshly installed leaf carries only its own flags.
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let pdpt_phys = alloc.alloc_frame().expect("pdpt");
        let pd_phys = alloc.alloc_frame().expect("pd");
        let huge_frame = 0x0000_0002_0000_0000u64;
        install_2m_huge(&mut mapper, pdpt_phys, pd_phys, 0, 0, 2, huge_frame);
        let base = 2u64 << 21;
        // Re-stamp the PDE as RO (no WRITABLE) + USER + NX, still a 2 MiB huge.
        unsafe {
            let pd = mapper.table_ptr_mut(pd_phys);
            (*pd).entry_mut(2).0 = huge_frame | PTE_PRESENT | PTE_USER | PTE_NO_EXEC | PTE_HUGE;
        }

        // Map a fresh 4 KiB sub-page (writable, supervisor, executable).
        let target = VirtAddr(base + 0x3000);
        assert!(mapper.map_4k(
            target,
            PhysAddr(0x0000_0000_8000_0000),
            PTE_PRESENT | PTE_WRITABLE,
            &mut alloc
        ));

        // A preserved sibling keeps the parent's RO + USER + NX.
        let sib = read_leaf_pte(&mapper, VirtAddr(base + 0x5000)).expect("sibling leaf");
        assert_eq!(sib.0 & PTE_WRITABLE, 0, "sibling stays read-only");
        assert_ne!(sib.0 & PTE_USER, 0, "sibling keeps USER");
        assert_ne!(sib.0 & PTE_NO_EXEC, 0, "sibling keeps NX");

        // The new leaf carries only what the caller asked for.
        let leaf = read_leaf_pte(&mapper, target).expect("target leaf");
        assert_ne!(leaf.0 & PTE_WRITABLE, 0, "new leaf is writable");
        assert_eq!(leaf.0 & PTE_USER, 0, "new leaf is supervisor-only");
        assert_eq!(leaf.0 & PTE_NO_EXEC, 0, "new leaf is executable");
    }

    #[test]
    fn split_1g_preserves_parent_ro_user_nx_flags() {
        // Same matrix one level up: a RO + USER + NX 1 GiB page. After a 4 KiB
        // remap, a 4 KiB sibling (in the split 2 MiB) keeps RO/USER/NX, and a
        // sibling in another 2 MiB range stays a read-only huge page.
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let pdpt_phys = alloc.alloc_frame().expect("pdpt");
        let huge_frame = 0x0000_0004_0000_0000u64;
        install_1g_huge(&mut mapper, pdpt_phys, 0, 1, huge_frame);
        let base = 1u64 << 30;
        // Re-stamp the PDPTE as RO + USER + NX, still a 1 GiB huge.
        unsafe {
            let pdpt = mapper.table_ptr_mut(pdpt_phys);
            (*pdpt).entry_mut(1).0 = huge_frame | PTE_PRESENT | PTE_USER | PTE_NO_EXEC | PTE_HUGE;
        }

        let target = VirtAddr(base + 0x20_3000); // 2 MiB idx 1, 4 KiB idx 3
        assert!(mapper.map_4k(
            target,
            PhysAddr(0x0000_0000_C000_0000),
            PTE_PRESENT | PTE_WRITABLE,
            &mut alloc
        ));

        // 4 KiB sibling in the split 2 MiB keeps RO + USER + NX.
        let sib = read_leaf_pte(&mapper, VirtAddr(base + 0x20_5000)).expect("sibling leaf");
        assert_eq!(sib.0 & PTE_WRITABLE, 0, "4K sibling stays read-only");
        assert_ne!(sib.0 & PTE_USER, 0, "4K sibling keeps USER");
        assert_ne!(sib.0 & PTE_NO_EXEC, 0, "4K sibling keeps NX");

        // A sibling in another 2 MiB range is still a read-only huge page
        // (write permission is the AND across levels; it must be false).
        assert_eq!(
            mapper.page_access_in(mapper.root_phys, VirtAddr(base)),
            Some(false),
            "2 MiB sibling stays read-only"
        );
    }

    #[test]
    fn map_4k_inside_1gib_huge_double_splits_and_preserves() {
        // Remapping a 4 KiB sub-page of a 1 GiB huge page splits twice:
        // 1 GiB → 512×2 MiB (PDPT→PD), then the covering 2 MiB → 512×4 KiB.
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let pdpt_phys = alloc.alloc_frame().expect("pdpt frame");
        let huge_frame = 0x0000_0004_0000_0000u64; // 16 GiB, 1 GiB-aligned
        // PML4=0, PDPT=1 → VA base = 1 << 30 = 0x4000_0000.
        install_1g_huge(&mut mapper, pdpt_phys, 0, 1, huge_frame);
        let base = 1u64 << 30;

        // Pre-split sanity: the whole 1 GiB resolves into the huge frame.
        assert_eq!(mapper.translate(VirtAddr(base)), Some(PhysAddr(huge_frame)));

        // Remap a 4 KiB sub-page at offset 0x20_3000 → 2 MiB index 1, 4 KiB
        // index 3 (exercises a non-zero 2 MiB child of the 1 GiB).
        let off = 0x20_3000u64;
        let new_phys = PhysAddr(0x0000_0000_C000_0000); // distinct, 4 KiB-aligned
        let target = VirtAddr(base + off);
        assert!(mapper.map_4k(target, new_phys, PTE_PRESENT | PTE_WRITABLE, &mut alloc));

        // Target now points to the new frame …
        assert_eq!(mapper.translate(target), Some(new_phys));
        // … a 4 KiB sibling in the SAME (now-split) 2 MiB keeps the original slice …
        assert_eq!(
            mapper.translate(VirtAddr(base + 0x20_0000)),
            Some(PhysAddr(huge_frame + 0x20_0000))
        );
        // … a sibling in a DIFFERENT 2 MiB (still a 2 MiB huge page) is preserved …
        assert_eq!(mapper.translate(VirtAddr(base)), Some(PhysAddr(huge_frame)));
        // … and so is one near the top of the 1 GiB region.
        assert_eq!(
            mapper.translate(VirtAddr(base + 0x3FF0_0000)),
            Some(PhysAddr(huge_frame + 0x3FF0_0000))
        );
        // Write permission survives the double split.
        assert_eq!(mapper.page_access_in(mapper.root_phys, target), Some(true));
        assert_eq!(
            mapper.page_access_in(mapper.root_phys, VirtAddr(base)),
            Some(true)
        );
    }

    #[test]
    fn translate_1gib_huge_does_not_dereference_pd() {
        // Regression: when PDPTE has PS=1, the walker must not load the next
        // level's table pointer (the PDPTE frame field is the leaf, not a
        // pointer to a PD). Catches a future bug where the walker would
        // dereference a bogus table pointer.
        let (_arena, mut mapper, _alloc) = make_mapper();
        // Point the PDPTE to an unmapped "phys" address (would fault if walked).
        let pdpt_phys = PhysAddr(PHYS_BASE + 4096);
        // The huge_frame field of the PDPTE is set to something that, if
        // treated as a PD pointer, would index outside the arena.
        let huge_frame = 0x0000_00FF_C000_0000u64;
        install_1g_huge(&mut mapper, pdpt_phys, 0, 1, huge_frame);
        // Translation must succeed without panicking / segfaulting on the
        // test harness.
        assert_eq!(
            mapper.translate(VirtAddr(1u64 << 30)),
            Some(PhysAddr(huge_frame)),
        );
    }

    #[test]
    fn translate_4kib_path_still_works_after_huge_page_support() {
        // Regression for the 4 KiB code path after the huge-page changes.
        let (_arena, mut mapper, mut alloc) = make_mapper();
        let virt = VirtAddr(0x0000_0007_0000_0000);
        let phys = PhysAddr(0x0000_0008_0000_0000);
        assert!(mapper.map_4k(virt, phys, PTE_WRITABLE, &mut alloc));
        assert_eq!(mapper.translate(virt), Some(phys));
        assert_eq!(
            mapper.translate(VirtAddr(virt.0 + 0xABC)),
            Some(PhysAddr(phys.0 + 0xABC)),
        );
    }

    // -------------------------------------------------------------------
    // Concurrent-access safety tests (TASK-012)
    //
    // These four tests prove that independent `TestArena` instances are
    // completely isolated from one another under concurrent use. Because
    // each arena is a distinct heap allocation there is no shared mutable
    // state; the tests pass with the default thread count.
    // -------------------------------------------------------------------

    /// Spawn 4 threads, each writing a distinct byte pattern to a disjoint
    /// region of a *shared* arena (disjoint regions, no overlap).
    ///
    /// Verifies that concurrent writes to non-overlapping memory do not
    /// corrupt each other and that all written values are readable after all
    /// threads complete.
    ///
    /// The arena base pointer is transmitted as a plain `usize` (an integer,
    /// not a raw pointer), which is `Send`. Each thread receives its own
    /// disjoint slice base address and writes only within that region. All
    /// threads are joined before the main thread reads any bytes, establishing
    /// the required happens-before relationship.
    #[test]
    fn arena_concurrent_disjoint_writes() {
        use std::sync::{Arc, Barrier};

        // Declared before `let` statements (clippy::items_after_statements).
        const THREADS: usize = 4;
        // ARENA_SIZE is an exact multiple of THREADS (64 * 4096 / 4 = 16384).
        #[allow(
            clippy::integer_division,
            reason = "ARENA_SIZE is an exact multiple of THREADS; truncation is intentional"
        )]
        const CHUNK: usize = ARENA_SIZE / THREADS;

        let arena = TestArena::new();
        // Transmit the base address as a plain integer so the closure is `Send`.
        // The raw pointer is reconstructed inside the thread from this integer.
        let base_addr: usize = arena.ptr as usize;
        let barrier = Arc::new(Barrier::new(THREADS));

        let handles: Vec<_> = (0..THREADS)
            .map(|id| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let offset = id * CHUNK;
                    // id is in 0..THREADS (= 4), so the low byte is exact.
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "id is in 0..THREADS (= 4); fits in u8 exactly"
                    )]
                    let byte_value = (id as u8).wrapping_add(1); // 1, 2, 3, 4
                    // SAFETY:
                    // - `base_addr` is the start of the arena, which remains live
                    //   on the main thread until after all handles are joined
                    //   (enforced by the sequential join loop below).
                    // - Each thread operates on the disjoint byte range
                    //   `[offset, offset+CHUNK)`. No two threads alias the same
                    //   byte because `id` is unique per thread.
                    unsafe {
                        let base = (base_addr + offset) as *mut u8;
                        core::ptr::write_bytes(base, byte_value, CHUNK);
                    }
                    (offset, byte_value)
                })
            })
            .collect();

        // Join all threads before reading — establishes happens-before.
        for handle in handles {
            let (offset, expected) = handle.join().expect("thread panicked");
            for i in 0..CHUNK {
                // SAFETY: `offset + i < ARENA_SIZE`, arena is live.
                let actual = unsafe { *arena.ptr.add(offset + i) };
                assert_eq!(
                    actual, expected,
                    "byte corruption at {offset}+{i}: expected {expected:#x}, got {actual:#x}"
                );
            }
        }
        // `arena` dropped here — all threads are already joined.
    }

    /// Spawn 4 threads, each creating its **own** `TestArena` and verifying
    /// that writes to one arena do not affect any other.
    ///
    /// This is the primary regression test for the original SIGSEGV: if a
    /// shared `static mut` backing buffer existed, concurrent zeroing followed
    /// by writes would race. With per-instance heap allocation each thread
    /// operates on completely independent memory.
    #[test]
    fn arena_concurrent_independent_instances() {
        use std::sync::{Arc, Barrier};

        let barrier = Arc::new(Barrier::new(4));
        let handles: Vec<_> = (0..4u8)
            .map(|id| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    // Each thread allocates its own arena — completely independent.
                    let arena = TestArena::new();
                    barrier.wait();
                    // Fill this thread's arena with a distinctive byte.
                    let fill = id.wrapping_add(0xA0);
                    // SAFETY: we own `arena` exclusively; no other thread
                    // references this allocation.
                    unsafe {
                        core::ptr::write_bytes(arena.ptr, fill, ARENA_SIZE);
                    }
                    // Verify the fill survived intact before dropping.
                    for i in 0..ARENA_SIZE {
                        // SAFETY: i < ARENA_SIZE, arena is live.
                        let actual = unsafe { *arena.ptr.add(i) };
                        assert_eq!(
                            actual, fill,
                            "corruption in thread {id} at byte {i}: expected {fill:#x}, got {actual:#x}"
                        );
                    }
                    // `arena` is dropped here — its allocation is freed.
                    // Other threads' arenas are unaffected.
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }

    /// Two threads each create independent arenas, build mappers, and perform
    /// `map_4k` + `translate` operations concurrently.
    ///
    /// Verifies that page-table operations on separate arenas do not interfere
    /// with each other's mappings even when executing simultaneously.
    #[test]
    fn arena_parallel_map_operations() {
        use std::sync::{Arc, Barrier};

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2u64)
            .map(|id| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let (arena, mut mapper, mut alloc) = make_mapper();
                    barrier.wait(); // start both threads simultaneously
                    // Use different virtual and physical addresses per thread
                    // to keep them logically independent (they are already
                    // physically independent due to separate arenas).
                    let virt = VirtAddr(0x0000_0009_0000_0000 + id * 0x1000_0000);
                    let phys = PhysAddr(0x0000_0010_0000_0000 + id * 0x1000_0000);
                    assert!(
                        mapper.map_4k(virt, phys, PTE_WRITABLE, &mut alloc),
                        "map_4k failed in thread {id}"
                    );
                    assert_eq!(
                        mapper.translate(virt),
                        Some(phys),
                        "translate mismatch in thread {id}"
                    );
                    // arena kept alive until end of closure.
                    drop(arena);
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }

    /// Dropping one `TestArena` must not corrupt an arena owned by a different
    /// thread (or a different scope in the same thread).
    ///
    /// Creates two arenas, writes a sentinel pattern to the first, drops the
    /// second, and verifies the first is unaffected — then does the same with
    /// two arenas on separate threads.
    #[test]
    fn arena_no_use_after_drop() {
        const SENTINEL: u8 = 0xCD;

        // --- Case A: fill arena_a, drop arena_b, verify arena_a is intact ---
        let arena_a = TestArena::new();
        let arena_b = TestArena::new();

        // Fill arena_a with the sentinel byte.
        // SAFETY: we have exclusive ownership; arena_a is live.
        unsafe { core::ptr::write_bytes(arena_a.ptr, SENTINEL, ARENA_SIZE) };

        // Dropping arena_b must not touch arena_a's memory (they are distinct
        // heap allocations).
        drop(arena_b);

        for i in 0..ARENA_SIZE {
            // SAFETY: i < ARENA_SIZE, arena_a is live.
            let actual = unsafe { *arena_a.ptr.add(i) };
            assert_eq!(
                actual, SENTINEL,
                "arena_a corrupted after arena_b drop at byte {i}: expected {SENTINEL:#x}, got {actual:#x}"
            );
        }

        // --- Case B: same test with arenas created in separate threads ---
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        let (tx_done, rx_done) = std::sync::mpsc::channel::<()>();

        // Thread B: allocate an arena, signal readiness, wait for the drop
        // signal, then exit (dropping its arena).
        let handle_b = std::thread::spawn(move || {
            let _arena_b2 = TestArena::new();
            tx_ready.send(()).expect("send failed");
            // Wait until main thread signals us to proceed (by dropping rx_done).
            rx_done.recv().ok();
            // `_arena_b2` dropped here.
        });

        // Wait for B to have its arena live, then build and fill our own.
        rx_ready.recv().expect("recv failed");
        let arena_c = TestArena::new();
        // SAFETY: we have exclusive ownership of arena_c.
        unsafe { core::ptr::write_bytes(arena_c.ptr, SENTINEL, ARENA_SIZE) };
        // Signal B to drop its arena, then join.
        drop(tx_done);
        handle_b.join().expect("thread B panicked");

        // After B's arena is dropped, arena_c must still be intact.
        for i in 0..ARENA_SIZE {
            // SAFETY: i < ARENA_SIZE, arena_c is live.
            let actual = unsafe { *arena_c.ptr.add(i) };
            assert_eq!(
                actual, SENTINEL,
                "arena_c corrupted after thread B dropped its arena at byte {i}"
            );
        }
    }
}

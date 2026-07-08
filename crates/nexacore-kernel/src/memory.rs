//! Memory management: virtual memory, page tables, allocators.
//!
//! ## Status
//!
//! P6.3 scaffold. The trait surface and helper types are defined; the
//! concrete `x86_64` page-table machinery lands when the bootloader
//! hand-off is operational (P6.2).
//!
//! ## Design rationale
//!
//! - **Single allocator interface.** The kernel exposes one
//!   [`Allocator`] trait; concrete impls include a bump allocator (used
//!   during early boot), a slab allocator (mature kernel state), and a
//!   per-task region allocator (per-process address spaces).
//! - **Page-table abstractions are arch-specific.** The trait surface in
//!   [`PageTable`] is arch-neutral, but the impls live in arch-gated
//!   modules. `x86_64` lands first.
//! - **Capabilities gate every allocation.** A caller must present a
//!   capability authorizing the requested allocation class; the kernel
//!   refuses ambient allocation entirely.

#![allow(
    clippy::missing_errors_doc,
    reason = "trait scaffold methods return NotYetImplemented until P6.3 activates allocator"
)]

use crate::{KernelResult, bitflags_simple};

// -----------------------------------------------------------------------------
// Address types
// -----------------------------------------------------------------------------

/// A physical address. 64-bit; the upper bits are reserved by the
/// hardware in the v1 platform support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

/// A virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VirtAddr(pub u64);

impl PhysAddr {
    /// Convenience: returns the address as a raw `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl VirtAddr {
    /// Convenience: returns the address as a raw `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

// -----------------------------------------------------------------------------
// Page size
// -----------------------------------------------------------------------------

/// Page sizes supported by the kernel.
///
/// The v1 kernel supports 4 KiB and 2 MiB pages on `x86_64`. 1 GiB pages
/// are a roadmap item (P6.3) once the page-table walker is mature; the
/// variant exists in the enum to make adding the impl a non-breaking
/// change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageSize {
    /// 4 KiB — standard page.
    Page4Kib,
    /// 2 MiB — large page.
    Page2Mib,
    /// 1 GiB — huge page (reserved for v1.x).
    Page1Gib,
}

impl PageSize {
    /// Returns the page size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Page4Kib => 4 * 1024,
            Self::Page2Mib => 2 * 1024 * 1024,
            Self::Page1Gib => 1024 * 1024 * 1024,
        }
    }
}

// -----------------------------------------------------------------------------
// Page table flags
// -----------------------------------------------------------------------------

bitflags_simple! {
    /// Page-table entry flags. Mapped to the architecture's bit positions
    /// inside the arch-specific page-table walker.
    ///
    /// (We use a hand-rolled bitflags-like macro to avoid the `bitflags`
    /// crate dependency at this layer; the kernel deliberately keeps its
    /// dep graph minimal.)
    pub struct PageFlags: u32 {
        /// The page is present in memory.
        const PRESENT     = 0b0000_0001;
        /// The page is writable.
        const WRITABLE    = 0b0000_0010;
        /// The page is accessible from user mode.
        const USER        = 0b0000_0100;
        /// The page is executable.
        const EXECUTABLE  = 0b0000_1000;
        /// The page is cacheable.
        const CACHEABLE   = 0b0001_0000;
        /// The page is global (TLB persists across address-space switches).
        const GLOBAL      = 0b0010_0000;
    }
}

// -----------------------------------------------------------------------------
// Allocator trait
// -----------------------------------------------------------------------------

/// A kernel allocator.
///
/// All allocations require a capability per the kernel security model.
/// The capability is validated by the syscall layer; allocators only see
/// already-authorized calls.
pub trait Allocator {
    /// Allocates `count` contiguous pages of `size` and returns the
    /// physical address of the first page.
    ///
    /// # Errors
    ///
    /// - [`crate::KernelError::ResourceExhausted`] if no contiguous region
    ///   is available.
    fn allocate(&mut self, size: PageSize, count: usize) -> KernelResult<PhysAddr>;

    /// Releases a previously-allocated region.
    fn free(&mut self, addr: PhysAddr, size: PageSize, count: usize) -> KernelResult<()>;

    /// Returns the total number of bytes currently allocated.
    fn allocated_bytes(&self) -> u64;
}

// -----------------------------------------------------------------------------
// PageTable trait
// -----------------------------------------------------------------------------

/// A page-table walker. Arch-specific implementations live in
/// `nexacore-kernel-arch-x86_64` (P6.3+) and similar.
pub trait PageTable {
    /// Maps `virt` to `phys` with the given flags.
    fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        size: PageSize,
        flags: PageFlags,
    ) -> KernelResult<()>;

    /// Unmaps `virt`. Returns the previously-mapped physical address.
    fn unmap(&mut self, virt: VirtAddr) -> KernelResult<PhysAddr>;

    /// Returns the physical address `virt` maps to, or `None`.
    fn translate(&self, virt: VirtAddr) -> Option<PhysAddr>;

    /// Flushes the TLB entry for `virt`. Architecture-specific.
    fn flush(&mut self, virt: VirtAddr);
}

// -----------------------------------------------------------------------------
// Internal bitflags-like macro
// -----------------------------------------------------------------------------

/// Tiny replacement for the `bitflags` crate. Sufficient for the small
/// number of bitflag types in the kernel; eliminates an external dep.
#[macro_export]
macro_rules! bitflags_simple {
    (
        $(#[$meta:meta])*
        pub struct $name:ident: $repr:ty {
            $($(#[$bit_meta:meta])* const $bit:ident = $value:expr;)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub $repr);

        impl $name {
            $($(#[$bit_meta])* pub const $bit: Self = Self($value);)*

            /// Returns the underlying bit representation.
            #[must_use]
            pub const fn bits(self) -> $repr { self.0 }

            /// Returns `true` if all bits in `other` are set.
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }
    };
}

// -----------------------------------------------------------------------------
// BitmapFrameAllocator — physical frame allocator (Track B, MB1)
// -----------------------------------------------------------------------------

/// Physical frame allocator backed by a flat bitmap.
///
/// Each bit tracks one 4 KiB physical frame: `0` = free, `1` = used.
/// The bitmap covers `N × 64` frames starting at `base`. With the
/// default `N = 16384` the allocator manages up to 1 048 576 frames
/// (4 GiB of addressable RAM). The backing array is stack- or
/// static-allocated — no heap required, safe to use before the global
/// allocator is initialised.
///
/// ## Initialisation order
///
/// 1. Construct via [`BitmapFrameAllocator::new`] (all frames start **used**).
/// 2. For every bootloader-reported *Usable* region, call
///    [`mark_range_free`][Self::mark_range_free].
/// 3. Optionally, call [`mark_range_used`][Self::mark_range_used] on the
///    kernel image / heap region to prevent re-allocation.
/// 4. Call [`alloc_frame`][Self::alloc_frame] / [`free_frame`][Self::free_frame].
///
/// Frames whose addresses fall outside `[base, base + N × 64 × 4096)` are
/// silently ignored by every method.
pub struct BitmapFrameAllocator<const N: usize> {
    /// Flat bitmap: bit `i` of word `i/64` tracks frame `i`. 0 = free, 1 = used.
    bitmap: [u64; N],
    /// Physical base address of frame 0.
    base: PhysAddr,
    /// Count of frames ever marked usable (free + currently allocated).
    total_frames: u64,
    /// Count of frames currently available for allocation.
    free_frames: u64,
}

impl<const N: usize> BitmapFrameAllocator<N> {
    const FRAME_BYTES: u64 = 4096;
    const FRAMES_PER_WORD: u64 = 64;
    /// Maximum frames this instance can track.
    const CAPACITY: u64 = N as u64 * Self::FRAMES_PER_WORD;

    /// Constructs a new allocator anchored at `base`.
    ///
    /// All frames start marked **used**; call [`mark_range_free`][Self::mark_range_free]
    /// to register usable physical regions from the bootloader memory map.
    #[must_use]
    pub const fn new(base: PhysAddr) -> Self {
        Self {
            bitmap: [u64::MAX; N],
            base,
            total_frames: 0,
            free_frames: 0,
        }
    }

    /// Marks the physical range `[start, start + size)` as free.
    ///
    /// `start` is rounded down to a 4 KiB boundary. The `size` is
    /// truncated to a whole number of frames. Previously-used frames
    /// increment both `total_frames` and `free_frames`.
    pub fn mark_range_free(&mut self, start: PhysAddr, size: u64) {
        let aligned = start.0 & !(Self::FRAME_BYTES - 1);
        let first = self.frame_idx(aligned);
        #[allow(
            clippy::integer_division,
            reason = "truncation to whole frames is intentional"
        )]
        let count = size / Self::FRAME_BYTES;
        for i in first..first.saturating_add(count) {
            if i >= Self::CAPACITY {
                break;
            }
            let (w, b) = Self::word_bit(i);
            #[allow(clippy::indexing_slicing, reason = "i < CAPACITY guarantees w < N")]
            if self.bitmap[w] & (1u64 << b) != 0 {
                self.bitmap[w] &= !(1u64 << b);
                self.total_frames += 1;
                self.free_frames += 1;
            }
        }
    }

    /// Marks the physical range `[start, start + size)` as used.
    ///
    /// `start` is rounded down to a 4 KiB boundary; `size` is rounded
    /// *up* so the entire containing frame is reserved. Decrements
    /// `free_frames` for each previously-free frame; `total_frames` is
    /// unchanged (frames remain registered usable RAM, just in use).
    pub fn mark_range_used(&mut self, start: PhysAddr, size: u64) {
        let aligned = start.0 & !(Self::FRAME_BYTES - 1);
        let first = self.frame_idx(aligned);
        let count = size.div_ceil(Self::FRAME_BYTES);
        for i in first..first.saturating_add(count) {
            if i >= Self::CAPACITY {
                break;
            }
            let (w, b) = Self::word_bit(i);
            #[allow(clippy::indexing_slicing, reason = "i < CAPACITY guarantees w < N")]
            if self.bitmap[w] & (1u64 << b) == 0 {
                self.bitmap[w] |= 1u64 << b;
                self.free_frames = self.free_frames.saturating_sub(1);
            }
        }
    }

    /// Allocates one free 4 KiB frame using a first-fit linear scan.
    ///
    /// Returns `None` when no free frame exists.
    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        for (wi, word) in self.bitmap.iter_mut().enumerate() {
            if *word == u64::MAX {
                continue;
            }
            let bit = u64::from(word.trailing_ones());
            *word |= 1u64 << bit;
            self.free_frames = self.free_frames.saturating_sub(1);
            let frame_idx = wi as u64 * Self::FRAMES_PER_WORD + bit;
            return Some(PhysAddr(self.base.0 + frame_idx * Self::FRAME_BYTES));
        }
        None
    }

    /// Frees a previously-allocated 4 KiB frame.
    ///
    /// Returns `false` if:
    /// - `addr` is not 4 KiB-aligned,
    /// - `addr` is out of this allocator's range, or
    /// - the frame was already free (double-free guard).
    pub fn free_frame(&mut self, addr: PhysAddr) -> bool {
        if addr.0 % Self::FRAME_BYTES != 0 {
            return false;
        }
        let idx = self.frame_idx(addr.0);
        if idx >= Self::CAPACITY {
            return false;
        }
        let (w, b) = Self::word_bit(idx);
        #[allow(clippy::indexing_slicing, reason = "idx < CAPACITY guarantees w < N")]
        if self.bitmap[w] & (1u64 << b) == 0 {
            return false; // double-free guard
        }
        #[allow(clippy::indexing_slicing, reason = "idx < CAPACITY guarantees w < N")]
        {
            self.bitmap[w] &= !(1u64 << b);
        }
        self.free_frames += 1;
        true
    }

    /// Total frames registered as usable physical RAM (free + allocated).
    #[must_use]
    pub fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// Frames currently available for allocation.
    #[must_use]
    pub fn free_frames(&self) -> u64 {
        self.free_frames
    }

    /// Total usable physical bytes (`total_frames × 4096`).
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_frames * Self::FRAME_BYTES
    }

    /// Free physical bytes currently available (`free_frames × 4096`).
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        self.free_frames * Self::FRAME_BYTES
    }

    /// Converts an absolute physical address to a frame index relative to `base`.
    #[inline]
    #[allow(
        clippy::integer_division,
        reason = "frame index calculation requires truncating division"
    )]
    fn frame_idx(&self, phys: u64) -> u64 {
        phys.saturating_sub(self.base.0) / Self::FRAME_BYTES
    }

    /// Decomposes a frame index into `(word_index, bit_position)`.
    #[inline]
    #[allow(
        clippy::integer_division,
        reason = "bitmap word/bit decomposition requires truncating division"
    )]
    const fn word_bit(frame_idx: u64) -> (usize, u64) {
        (
            (frame_idx / Self::FRAMES_PER_WORD) as usize,
            frame_idx % Self::FRAMES_PER_WORD,
        )
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_bytes_correct() {
        assert_eq!(PageSize::Page4Kib.bytes(), 4096);
        assert_eq!(PageSize::Page2Mib.bytes(), 2 * 1024 * 1024);
        assert_eq!(PageSize::Page1Gib.bytes(), 1024 * 1024 * 1024);
    }

    #[test]
    fn page_flags_combine() {
        let combined = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER;
        assert!(combined.contains(PageFlags::PRESENT));
        assert!(combined.contains(PageFlags::WRITABLE));
        assert!(combined.contains(PageFlags::USER));
        assert!(!combined.contains(PageFlags::EXECUTABLE));
    }

    #[test]
    fn addr_types_round_trip() {
        let p = PhysAddr(0xDEAD_BEEFu64);
        let v = VirtAddr(0xCAFE_F00Du64);
        assert_eq!(p.as_u64(), 0xDEAD_BEEFu64);
        assert_eq!(v.as_u64(), 0xCAFE_F00Du64);
    }
}

#[cfg(test)]
mod bitmap_alloc_tests {
    use super::*;

    /// Small allocator: 4 words × 64 bits = 256 frames = 1 MiB at base 1 MiB.
    type SmallAlloc = BitmapFrameAllocator<4>;
    const BASE: PhysAddr = PhysAddr(0x10_0000); // 1 MiB

    #[test]
    fn alloc_first_frame_returns_base() {
        let mut a = SmallAlloc::new(BASE);
        a.mark_range_free(BASE, 4096 * 64);
        let f = a.alloc_frame().expect("should allocate from freed region");
        assert_eq!(f, BASE);
    }

    #[test]
    fn alloc_until_full_then_none() {
        let mut a = SmallAlloc::new(BASE);
        a.mark_range_free(BASE, 4096 * 256);
        let mut count = 0usize;
        while a.alloc_frame().is_some() {
            count += 1;
        }
        assert_eq!(count, 256, "should allocate exactly 256 frames");
        assert!(
            a.alloc_frame().is_none(),
            "exhausted allocator must return None"
        );
    }

    #[test]
    fn free_and_reallocate_same_frame() {
        let mut a = SmallAlloc::new(BASE);
        a.mark_range_free(BASE, 4096 * 64);
        let f1 = a.alloc_frame().unwrap();
        assert!(a.free_frame(f1), "free should succeed");
        let f2 = a.alloc_frame().unwrap();
        assert_eq!(f1, f2, "first-fit must reuse the freed frame");
    }

    #[test]
    fn mark_range_used_prevents_allocation() {
        let mut a = SmallAlloc::new(BASE);
        a.mark_range_free(BASE, 4096 * 64);
        a.mark_range_used(BASE, 4096); // re-mark first frame used
        let f = a.alloc_frame().unwrap();
        assert_ne!(f, BASE, "first frame should be skipped");
        assert_eq!(f, PhysAddr(BASE.0 + 4096));
    }

    #[test]
    fn free_misaligned_address_returns_false() {
        let mut a = SmallAlloc::new(BASE);
        a.mark_range_free(BASE, 4096 * 64);
        let f = a.alloc_frame().unwrap();
        assert!(
            !a.free_frame(PhysAddr(f.0 + 1)),
            "misaligned free must fail"
        );
    }

    #[test]
    fn stats_track_alloc_and_free() {
        let mut a = SmallAlloc::new(BASE);
        a.mark_range_free(BASE, 4096 * 10);
        assert_eq!(a.total_frames(), 10);
        assert_eq!(a.free_frames(), 10);
        assert_eq!(a.total_bytes(), 4096 * 10);
        a.alloc_frame().unwrap();
        assert_eq!(a.total_frames(), 10, "total must not change on alloc");
        assert_eq!(a.free_frames(), 9);
        assert_eq!(a.free_bytes(), 4096 * 9);
    }
}

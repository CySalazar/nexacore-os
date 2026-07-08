//! Guest physical memory layout planning and a host-side backing buffer.
//!
//! See `NCIP-Container-006` § 1. A micro-VM's guest physical address space is
//! not contiguous: on x86-64 a *MMIO gap* is reserved below the 4 GiB boundary
//! for memory-mapped device windows (virtio-mmio, the local APIC, the IO-APIC,
//! …), so any guest RAM that would land inside the gap is relocated above
//! 4 GiB. [`GuestMemoryLayout`] computes the resulting RAM regions (each maps
//! to one `KVM_SET_USER_MEMORY_REGION` slot) and the matching **e820** map that
//! the guest firmware/kernel reads to discover usable RAM.
//!
//! This module is **platform-independent and fully host-testable**: it computes
//! addresses and byte tables, not ioctls. The real
//! [`crate::hypervisor::Hypervisor::set_memory`] call consumes
//! [`GuestMemoryLayout::regions`] to register each slot; the
//! byte-exact [`GuestMemoryLayout::e820`] table is copied into the boot
//! parameters by [`crate::boot`].
//!
//! [`GuestRam`] is a contiguous host buffer addressed from guest physical
//! address `0`, with **bounds-checked** little-endian accessors. It models the
//! low RAM region (where virtqueues and boot structures live) so the virtqueue
//! processing in [`crate::virtio::queue`] can be exercised without a real
//! hypervisor.

// Address arithmetic and the byte-table encoders perform deliberate integer
// truncation (e.g. `usize as u64`, slicing a `u64` into LE bytes) and integer
// division by the constant page size. These are correct by construction and
// bounds-checked; the module-level allows keep the strict workspace clippy
// profile from flagging every arithmetic site.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::integer_division
)]

/// Page size on x86-64 (4 KiB). Guest RAM sizes and slot boundaries MUST be a
/// multiple of this value.
pub const PAGE_SIZE: u64 = 4096;

/// First guest physical address past the 32-bit boundary (4 GiB).
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;

/// Size of the 32-bit MMIO gap reserved below 4 GiB for device windows
/// (768 MiB — the Firecracker/Cloud-Hypervisor convention).
pub const MMIO_GAP_SIZE: u64 = 768 << 20;

/// Start of the MMIO gap (`= 4 GiB − 768 MiB = 0xD000_0000`). Guest RAM never
/// occupies `[MMIO_GAP_START, MMIO_GAP_END)`.
pub const MMIO_GAP_START: u64 = FIRST_ADDR_PAST_32BITS - MMIO_GAP_SIZE;

/// End of the MMIO gap (`= 4 GiB`). RAM that would exceed [`MMIO_GAP_START`] is
/// relocated to begin here.
pub const MMIO_GAP_END: u64 = FIRST_ADDR_PAST_32BITS;

/// Guest physical address at which the 64-bit kernel is loaded (1 MiB). Below
/// this the real-mode IVT, BDA, and the EBDA / VGA window live.
pub const HIGH_RAM_START: u64 = 0x0010_0000;

/// e820 memory-range type, matching the Linux `boot_e820_entry::type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum E820Kind {
    /// Usable RAM (`E820_TYPE_RAM`).
    Ram = 1,
    /// Reserved — not usable by the OS (`E820_TYPE_RESERVED`).
    Reserved = 2,
}

/// A single e820 entry: a `[addr, addr+size)` range of a given kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E820Entry {
    /// Start guest physical address of the range.
    pub addr: u64,
    /// Length of the range in bytes.
    pub size: u64,
    /// Range classification.
    pub kind: E820Kind,
}

impl E820Entry {
    /// Serialize into the 20-byte `boot_e820_entry` wire layout
    /// (`addr: u64 LE, size: u64 LE, type: u32 LE`).
    #[must_use]
    pub fn to_bytes(self) -> [u8; 20] {
        let mut out = [0u8; 20];
        out[0..8].copy_from_slice(&self.addr.to_le_bytes());
        out[8..16].copy_from_slice(&self.size.to_le_bytes());
        out[16..20].copy_from_slice(&(self.kind as u32).to_le_bytes());
        out
    }
}

/// One guest RAM region, corresponding to a single KVM memory slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    /// KVM slot index (0-based).
    pub slot: u32,
    /// Guest physical base address of the region.
    pub guest_addr: u64,
    /// Region length in bytes.
    pub size: u64,
}

/// Error returned when a requested guest RAM size is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LayoutError {
    /// The size is zero.
    #[error("guest RAM size must be non-zero")]
    ZeroSize,
    /// The size is not a multiple of [`PAGE_SIZE`].
    #[error("guest RAM size must be page-aligned (multiple of 4096)")]
    Misaligned,
}

/// Computes the guest physical memory layout for a requested RAM size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMemoryLayout {
    ram_size: u64,
}

impl GuestMemoryLayout {
    /// Construct a layout for `ram_size` bytes of guest RAM.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutError`] if `ram_size` is zero or not page-aligned.
    pub fn new(ram_size: u64) -> Result<Self, LayoutError> {
        if ram_size == 0 {
            return Err(LayoutError::ZeroSize);
        }
        if ram_size % PAGE_SIZE != 0 {
            return Err(LayoutError::Misaligned);
        }
        Ok(Self { ram_size })
    }

    /// Total guest RAM in bytes.
    #[must_use]
    pub fn ram_size(self) -> u64 {
        self.ram_size
    }

    /// The RAM regions, one per KVM memory slot.
    ///
    /// If the RAM fits below [`MMIO_GAP_START`] a single slot is returned;
    /// otherwise the RAM is split into a low slot `[0, MMIO_GAP_START)` and a
    /// high slot beginning at [`MMIO_GAP_END`].
    #[must_use]
    pub fn regions(self) -> Vec<MemRegion> {
        let mut regions = Vec::new();
        if self.ram_size <= MMIO_GAP_START {
            regions.push(MemRegion {
                slot: 0,
                guest_addr: 0,
                size: self.ram_size,
            });
        } else {
            regions.push(MemRegion {
                slot: 0,
                guest_addr: 0,
                size: MMIO_GAP_START,
            });
            regions.push(MemRegion {
                slot: 1,
                guest_addr: MMIO_GAP_END,
                size: self.ram_size - MMIO_GAP_START,
            });
        }
        regions
    }

    /// The e820 map presented to the guest.
    ///
    /// The legacy `[0, 640 KiB)` conventional memory and the
    /// `[1 MiB, …)` extended memory are reported as usable RAM; the
    /// `[640 KiB, 1 MiB)` legacy device window (VGA / option-ROM / BIOS) is
    /// reported reserved, matching what real firmware presents.
    #[must_use]
    pub fn e820(self) -> Vec<E820Entry> {
        const CONVENTIONAL_END: u64 = 0x0009_FC00; // 639 KiB (EBDA-safe).
        let mut map = Vec::new();
        // Conventional memory below the legacy device hole.
        map.push(E820Entry {
            addr: 0,
            size: CONVENTIONAL_END,
            kind: E820Kind::Ram,
        });
        // Legacy device window [639 KiB, 1 MiB) — reserved.
        map.push(E820Entry {
            addr: CONVENTIONAL_END,
            size: HIGH_RAM_START - CONVENTIONAL_END,
            kind: E820Kind::Reserved,
        });
        // Extended RAM regions (everything reported by `regions`, clamped to
        // begin at 1 MiB for the low region).
        for region in self.regions() {
            let start = region.guest_addr.max(HIGH_RAM_START);
            let end = region.guest_addr + region.size;
            if end > start {
                map.push(E820Entry {
                    addr: start,
                    size: end - start,
                    kind: E820Kind::Ram,
                });
            }
        }
        map
    }
}

/// A contiguous host buffer modelling guest RAM addressed from guest physical
/// address `0`, with bounds-checked little-endian accessors.
///
/// Used to host-test virtqueue processing ([`crate::virtio::queue`]) and boot
/// structure placement ([`crate::boot`]) without a real hypervisor. Every
/// accessor returns `None` on an out-of-range access — no panics, no `unsafe`.
#[derive(Debug, Clone)]
pub struct GuestRam {
    bytes: Vec<u8>,
}

impl GuestRam {
    /// Allocate `len` bytes of zeroed guest RAM.
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len],
        }
    }

    /// Length of the backing region in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the region is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow `len` bytes at guest physical address `gpa`, or `None` if the
    /// range is out of bounds.
    #[must_use]
    pub fn read_slice(&self, gpa: u64, len: usize) -> Option<&[u8]> {
        let start = usize::try_from(gpa).ok()?;
        let end = start.checked_add(len)?;
        self.bytes.get(start..end)
    }

    /// Copy `src` into guest RAM at `gpa`. Returns `None` if the write would go
    /// out of bounds (nothing is written in that case).
    #[must_use]
    pub fn write_slice(&mut self, gpa: u64, src: &[u8]) -> Option<()> {
        let start = usize::try_from(gpa).ok()?;
        let end = start.checked_add(src.len())?;
        let dst = self.bytes.get_mut(start..end)?;
        dst.copy_from_slice(src);
        Some(())
    }

    /// Read a little-endian `u16` at `gpa`.
    #[must_use]
    pub fn read_u16(&self, gpa: u64) -> Option<u16> {
        let b: [u8; 2] = self.read_slice(gpa, 2)?.try_into().ok()?;
        Some(u16::from_le_bytes(b))
    }

    /// Read a little-endian `u32` at `gpa`.
    #[must_use]
    pub fn read_u32(&self, gpa: u64) -> Option<u32> {
        let b: [u8; 4] = self.read_slice(gpa, 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    }

    /// Read a little-endian `u64` at `gpa`.
    #[must_use]
    pub fn read_u64(&self, gpa: u64) -> Option<u64> {
        let b = self.read_slice(gpa, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_le_bytes(a))
    }

    /// Write a little-endian `u16` at `gpa`.
    #[must_use]
    pub fn write_u16(&mut self, gpa: u64, v: u16) -> Option<()> {
        self.write_slice(gpa, &v.to_le_bytes())
    }

    /// Write a little-endian `u32` at `gpa`.
    #[must_use]
    pub fn write_u32(&mut self, gpa: u64, v: u32) -> Option<()> {
        self.write_slice(gpa, &v.to_le_bytes())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_and_misaligned() {
        assert_eq!(GuestMemoryLayout::new(0), Err(LayoutError::ZeroSize));
        assert_eq!(GuestMemoryLayout::new(4097), Err(LayoutError::Misaligned));
        assert!(GuestMemoryLayout::new(PAGE_SIZE).is_ok());
    }

    #[test]
    fn small_ram_is_single_slot() {
        let layout = GuestMemoryLayout::new(64 << 20).expect("64 MiB");
        let regions = layout.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].slot, 0);
        assert_eq!(regions[0].guest_addr, 0);
        assert_eq!(regions[0].size, 64 << 20);
    }

    #[test]
    fn large_ram_splits_across_mmio_gap() {
        // 5 GiB of RAM: 3.25 GiB below the gap, the remaining 1.75 GiB above.
        let total = 5u64 << 30;
        let layout = GuestMemoryLayout::new(total).expect("5 GiB");
        let regions = layout.regions();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].guest_addr, 0);
        assert_eq!(regions[0].size, MMIO_GAP_START);
        assert_eq!(regions[1].guest_addr, MMIO_GAP_END);
        assert_eq!(regions[1].size, total - MMIO_GAP_START);
        // No region overlaps the MMIO gap.
        for r in &regions {
            let end = r.guest_addr + r.size;
            assert!(end <= MMIO_GAP_START || r.guest_addr >= MMIO_GAP_END);
        }
    }

    #[test]
    fn e820_marks_legacy_hole_reserved() {
        let layout = GuestMemoryLayout::new(128 << 20).expect("128 MiB");
        let map = layout.e820();
        // First entry usable RAM from 0, second entry reserved legacy hole.
        assert_eq!(map[0].kind, E820Kind::Ram);
        assert_eq!(map[0].addr, 0);
        assert_eq!(map[1].kind, E820Kind::Reserved);
        assert_eq!(map[1].addr + map[1].size, HIGH_RAM_START);
        // Extended RAM begins at 1 MiB.
        assert!(
            map.iter()
                .any(|e| e.addr == HIGH_RAM_START && e.kind == E820Kind::Ram)
        );
    }

    #[test]
    fn e820_entry_serializes_byte_exact() {
        let e = E820Entry {
            addr: 0x0010_0000,
            size: 0x0400_0000,
            kind: E820Kind::Ram,
        };
        let b = e.to_bytes();
        assert_eq!(&b[0..8], &0x0010_0000u64.to_le_bytes());
        assert_eq!(&b[8..16], &0x0400_0000u64.to_le_bytes());
        assert_eq!(&b[16..20], &1u32.to_le_bytes());
    }

    #[test]
    fn guest_ram_bounds_checked() {
        let mut ram = GuestRam::new(4096);
        assert_eq!(ram.len(), 4096);
        assert!(!ram.is_empty());
        // In-bounds round trip.
        assert!(ram.write_u32(0x10, 0xDEAD_BEEF).is_some());
        assert_eq!(ram.read_u32(0x10), Some(0xDEAD_BEEF));
        // Out-of-bounds returns None, never panics.
        assert!(ram.read_u32(4094).is_none());
        assert!(ram.write_slice(4090, &[0u8; 16]).is_none());
        // The failed write left memory untouched.
        assert_eq!(ram.read_slice(4090, 6), Some(&[0u8; 6][..]));
    }

    #[test]
    fn guest_ram_le_accessors_round_trip() {
        let mut ram = GuestRam::new(64);
        ram.write_u16(0, 0x1234).expect("u16");
        ram.write_slice(8, &0x0123_4567_89AB_CDEFu64.to_le_bytes())
            .expect("u64");
        assert_eq!(ram.read_u16(0), Some(0x1234));
        assert_eq!(ram.read_u64(8), Some(0x0123_4567_89AB_CDEF));
    }
}

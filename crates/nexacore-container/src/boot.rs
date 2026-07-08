//! Linux/x86-64 guest boot-parameter construction (the "zero page").
//!
//! See `NCIP-Container-006` § 2. To boot a Stichting-signed Linux guest the
//! host loads the kernel and (optional) initrd into guest RAM, writes the
//! kernel command line, and hands the vCPU a populated `boot_params` structure
//! (the 4 KiB "zero page" at a fixed guest physical address). This module
//! builds that structure **byte-exactly** per the Linux x86 boot protocol, and
//! provides helpers to place the command line, kernel image, and initrd into a
//! [`crate::memory::GuestRam`] backing buffer.
//!
//! Everything here is platform-independent: it computes byte tables and copies
//! into a host buffer. The real `KVM_SET_REGS` / `KVM_SET_SREGS` that point a
//! vCPU at the kernel entry are issued by the (Linux-only) KVM backend; the
//! addresses and the zero page they consume are produced here and are fully
//! host-testable.

// The boot protocol is defined in terms of fixed little-endian field widths;
// writing `u64`/`u32` addresses into the page and casting `usize` lengths to
// the protocol's `u32` fields is correct by construction and bounds-checked.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

use crate::memory::{E820Entry, GuestMemoryLayout, GuestRam};

/// Size of the `boot_params` zero page (one 4 KiB page).
pub const BOOT_PARAMS_SIZE: usize = 4096;

/// `setup_header.header` magic — ASCII `"HdrS"`, little-endian `0x5372_6448`.
pub const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;

/// Boot-sector trailer magic at offset `0x1FE` (`0xAA55`).
pub const BOOT_FLAG_MAGIC: u16 = 0xAA55;

/// `type_of_loader` value for a loader without an assigned id ("undefined").
pub const LOADER_TYPE_UNDEFINED: u8 = 0xFF;

/// `loadflags` bit 0: the protected-mode kernel is loaded high (at 1 MiB).
pub const LOADFLAGS_LOADED_HIGH: u8 = 0x01;

/// `loadflags` bit 7: a heap is present and `heap_end_ptr` is valid.
pub const LOADFLAGS_CAN_USE_HEAP: u8 = 0x80;

// --- Field offsets within `boot_params` (Linux x86 boot protocol) ----------
const OFF_E820_ENTRIES: usize = 0x1E8;
const OFF_SETUP_SECTS: usize = 0x1F1;
const OFF_BOOT_FLAG: usize = 0x1FE;
const OFF_HEADER: usize = 0x202;
const OFF_VERSION: usize = 0x206;
const OFF_TYPE_OF_LOADER: usize = 0x210;
const OFF_LOADFLAGS: usize = 0x211;
const OFF_RAMDISK_IMAGE: usize = 0x218;
const OFF_RAMDISK_SIZE: usize = 0x21C;
const OFF_HEAP_END_PTR: usize = 0x224;
const OFF_CMD_LINE_PTR: usize = 0x228;
const OFF_KERNEL_ALIGNMENT: usize = 0x230;
const OFF_E820_TABLE: usize = 0x2D0;

/// Max e820 entries the `boot_params::e820_table` array can hold.
pub const E820_MAX_ENTRIES: usize = 128;

/// Conventional load addresses inside the guest physical address space.
pub mod addr {
    /// Where the populated `boot_params` zero page is placed.
    pub const ZERO_PAGE: u64 = 0x0000_7000;
    /// Where the NUL-terminated kernel command line is placed.
    pub const CMDLINE: u64 = 0x0002_0000;
    /// Where the protected-mode kernel image is loaded (1 MiB).
    pub const KERNEL: u64 = 0x0010_0000;
    /// Where the initrd is loaded (high, just under the MMIO gap by default).
    pub const INITRD_DEFAULT: u64 = 0x0F00_0000;
}

/// Fields parsed from a bzImage `setup_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupHeader {
    /// Number of 512-byte setup sectors (`setup_sects`; `0` means `4`).
    pub setup_sects: u8,
    /// Boot-protocol version (`major << 8 | minor`).
    pub version: u16,
    /// `loadflags` byte.
    pub loadflags: u8,
}

impl SetupHeader {
    /// Parse the `setup_header` from the first sectors of a bzImage.
    ///
    /// Returns `None` if `kernel` is too short or the `HdrS` magic at `0x202`
    /// is absent (i.e. the image is not a Linux bzImage).
    #[must_use]
    pub fn parse(kernel: &[u8]) -> Option<Self> {
        let magic: [u8; 4] = kernel.get(OFF_HEADER..OFF_HEADER + 4)?.try_into().ok()?;
        if u32::from_le_bytes(magic) != KERNEL_HDR_MAGIC {
            return None;
        }
        let setup_sects = *kernel.get(OFF_SETUP_SECTS)?;
        let ver: [u8; 2] = kernel.get(OFF_VERSION..OFF_VERSION + 2)?.try_into().ok()?;
        let load = *kernel.get(OFF_LOADFLAGS)?;
        Some(Self {
            // Per the protocol, a `setup_sects` of 0 means 4.
            setup_sects: if setup_sects == 0 { 4 } else { setup_sects },
            version: u16::from_le_bytes(ver),
            loadflags: load,
        })
    }

    /// Byte offset of the protected-mode kernel within the bzImage
    /// (`(setup_sects + 1) * 512`).
    #[must_use]
    pub fn protected_mode_offset(self) -> usize {
        (self.setup_sects as usize + 1) * 512
    }
}

/// Builder for the guest `boot_params` zero page.
#[derive(Debug, Clone, Copy)]
pub struct BootParamsBuilder {
    cmdline_addr: u64,
    initrd: Option<(u64, u64)>,
}

impl Default for BootParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BootParamsBuilder {
    /// Start a new builder with the conventional command-line address and no
    /// initrd.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cmdline_addr: addr::CMDLINE,
            initrd: None,
        }
    }

    /// Set the guest physical address of the NUL-terminated command line.
    #[must_use]
    pub fn cmdline_addr(mut self, addr: u64) -> Self {
        self.cmdline_addr = addr;
        self
    }

    /// Set the initrd image address and size (in bytes).
    #[must_use]
    pub fn initrd(mut self, addr: u64, size: u64) -> Self {
        self.initrd = Some((addr, size));
        self
    }

    /// Produce the 4 KiB zero page for the given memory layout.
    ///
    /// The e820 table is taken from [`GuestMemoryLayout::e820`], truncated to
    /// [`E820_MAX_ENTRIES`] (the protocol's fixed array size).
    #[must_use]
    pub fn build(&self, layout: GuestMemoryLayout) -> [u8; BOOT_PARAMS_SIZE] {
        let mut page = [0u8; BOOT_PARAMS_SIZE];

        // setup_header magic + boot flag identify the page to the kernel.
        write_u32(&mut page, OFF_HEADER, KERNEL_HDR_MAGIC);
        write_u16(&mut page, OFF_BOOT_FLAG, BOOT_FLAG_MAGIC);
        // Boot protocol 2.15.
        write_u16(&mut page, OFF_VERSION, 0x020F);
        // We are an "undefined" boot loader; kernel loaded high; heap present.
        write_u8(&mut page, OFF_TYPE_OF_LOADER, LOADER_TYPE_UNDEFINED);
        write_u8(
            &mut page,
            OFF_LOADFLAGS,
            LOADFLAGS_LOADED_HIGH | LOADFLAGS_CAN_USE_HEAP,
        );
        write_u8(&mut page, OFF_SETUP_SECTS, 0);
        write_u32(&mut page, OFF_KERNEL_ALIGNMENT, 0x0100_0000);
        write_u16(&mut page, OFF_HEAP_END_PTR, 0xFE00);

        // Command line.
        write_u32(&mut page, OFF_CMD_LINE_PTR, self.cmdline_addr as u32);

        // initrd.
        if let Some((addr, size)) = self.initrd {
            write_u32(&mut page, OFF_RAMDISK_IMAGE, addr as u32);
            write_u32(&mut page, OFF_RAMDISK_SIZE, size as u32);
        }

        // e820 map.
        let map = layout.e820();
        let count = map.len().min(E820_MAX_ENTRIES);
        write_u8(&mut page, OFF_E820_ENTRIES, count as u8);
        write_e820_table(&mut page, &map);

        page
    }
}

/// Copy the e820 entries into the `boot_params::e820_table` array region.
fn write_e820_table(page: &mut [u8; BOOT_PARAMS_SIZE], map: &[E820Entry]) {
    for (i, entry) in map.iter().take(E820_MAX_ENTRIES).enumerate() {
        let base = OFF_E820_TABLE + i * 20;
        if let Some(dst) = page.get_mut(base..base + 20) {
            dst.copy_from_slice(&entry.to_bytes());
        }
    }
}

// Small bounds-checked little-endian field writers (no panics, no indexing).
fn write_u8(page: &mut [u8; BOOT_PARAMS_SIZE], off: usize, v: u8) {
    if let Some(b) = page.get_mut(off) {
        *b = v;
    }
}
fn write_u16(page: &mut [u8; BOOT_PARAMS_SIZE], off: usize, v: u16) {
    if let Some(dst) = page.get_mut(off..off + 2) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u32(page: &mut [u8; BOOT_PARAMS_SIZE], off: usize, v: u32) {
    if let Some(dst) = page.get_mut(off..off + 4) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

/// Errors from placing boot artifacts into guest RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BootLoadError {
    /// A copy would have exceeded the guest RAM backing buffer.
    #[error("boot artifact does not fit in guest RAM at the requested address")]
    OutOfBounds,
}

/// Write the NUL-terminated kernel command line into guest RAM.
///
/// # Errors
///
/// Returns [`BootLoadError::OutOfBounds`] if the string + terminator does not
/// fit at `addr`.
pub fn place_cmdline(ram: &mut GuestRam, addr: u64, cmdline: &str) -> Result<(), BootLoadError> {
    let mut bytes = cmdline.as_bytes().to_vec();
    bytes.push(0); // NUL terminator.
    ram.write_slice(addr, &bytes)
        .ok_or(BootLoadError::OutOfBounds)
}

/// Copy a blob (kernel protected-mode image or initrd) into guest RAM.
///
/// # Errors
///
/// Returns [`BootLoadError::OutOfBounds`] if the blob does not fit at `addr`.
pub fn place_blob(ram: &mut GuestRam, addr: u64, blob: &[u8]) -> Result<(), BootLoadError> {
    ram.write_slice(addr, blob)
        .ok_or(BootLoadError::OutOfBounds)
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

    fn layout() -> GuestMemoryLayout {
        GuestMemoryLayout::new(256 << 20).expect("256 MiB")
    }

    #[test]
    fn zero_page_has_magics() {
        let page = BootParamsBuilder::new().build(layout());
        assert_eq!(
            u32::from_le_bytes(page[OFF_HEADER..OFF_HEADER + 4].try_into().unwrap()),
            KERNEL_HDR_MAGIC
        );
        assert_eq!(
            u16::from_le_bytes(page[OFF_BOOT_FLAG..OFF_BOOT_FLAG + 2].try_into().unwrap()),
            BOOT_FLAG_MAGIC
        );
        assert_eq!(page[OFF_TYPE_OF_LOADER], LOADER_TYPE_UNDEFINED);
        assert_eq!(
            page[OFF_LOADFLAGS],
            LOADFLAGS_LOADED_HIGH | LOADFLAGS_CAN_USE_HEAP
        );
    }

    #[test]
    fn zero_page_records_cmdline_and_initrd() {
        let page = BootParamsBuilder::new()
            .cmdline_addr(addr::CMDLINE)
            .initrd(addr::INITRD_DEFAULT, 0x1234)
            .build(layout());
        assert_eq!(
            u32::from_le_bytes(
                page[OFF_CMD_LINE_PTR..OFF_CMD_LINE_PTR + 4]
                    .try_into()
                    .unwrap()
            ),
            addr::CMDLINE as u32
        );
        assert_eq!(
            u32::from_le_bytes(
                page[OFF_RAMDISK_IMAGE..OFF_RAMDISK_IMAGE + 4]
                    .try_into()
                    .unwrap()
            ),
            addr::INITRD_DEFAULT as u32
        );
        assert_eq!(
            u32::from_le_bytes(
                page[OFF_RAMDISK_SIZE..OFF_RAMDISK_SIZE + 4]
                    .try_into()
                    .unwrap()
            ),
            0x1234
        );
    }

    #[test]
    fn zero_page_embeds_e820_table() {
        let l = layout();
        let page = BootParamsBuilder::new().build(l);
        let count = page[OFF_E820_ENTRIES] as usize;
        assert_eq!(count, l.e820().len());
        // First table entry matches the first e820 entry byte-for-byte.
        let first = &page[OFF_E820_TABLE..OFF_E820_TABLE + 20];
        assert_eq!(first, &l.e820()[0].to_bytes());
    }

    #[test]
    fn setup_header_parses_synthetic_bzimage() {
        // Build a minimal fake bzImage: zeros + HdrS magic + fields.
        let mut img = vec![0u8; 1024];
        img[OFF_SETUP_SECTS] = 0; // → interpreted as 4.
        img[OFF_HEADER..OFF_HEADER + 4].copy_from_slice(&KERNEL_HDR_MAGIC.to_le_bytes());
        img[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&0x020Fu16.to_le_bytes());
        img[OFF_LOADFLAGS] = LOADFLAGS_LOADED_HIGH;
        let hdr = SetupHeader::parse(&img).expect("valid header");
        assert_eq!(hdr.setup_sects, 4);
        assert_eq!(hdr.version, 0x020F);
        assert_eq!(hdr.loadflags, LOADFLAGS_LOADED_HIGH);
        // (4 setup sectors + 1 boot sector) * 512.
        assert_eq!(hdr.protected_mode_offset(), 5 * 512);
    }

    #[test]
    fn setup_header_rejects_non_bzimage() {
        assert!(SetupHeader::parse(&[0u8; 1024]).is_none());
        assert!(SetupHeader::parse(&[0u8; 4]).is_none());
    }

    #[test]
    fn place_cmdline_writes_nul_terminated() {
        let mut ram = GuestRam::new(0x21000);
        place_cmdline(&mut ram, addr::CMDLINE, "console=ttyS0").expect("fits");
        let read = ram.read_slice(addr::CMDLINE, 14).unwrap();
        assert_eq!(&read[..13], b"console=ttyS0");
        assert_eq!(read[13], 0);
    }

    #[test]
    fn place_blob_out_of_bounds_is_error() {
        let mut ram = GuestRam::new(16);
        assert_eq!(
            place_blob(&mut ram, 8, &[1u8; 32]),
            Err(BootLoadError::OutOfBounds)
        );
    }
}

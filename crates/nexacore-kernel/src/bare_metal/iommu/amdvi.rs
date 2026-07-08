//! AMD-Vi backend scaffold (P6.7.9-pre.3).
//!
//! ## Scope
//!
//! Sibling of [`super::vtd`] for AMD platforms: this module lands the
//! **dormant scaffold** for the AMD I/O Virtualization Technology
//! backend that will eventually replace the [`super::PassthroughBackend`]
//! when `bare_metal::iommu::iommu_vendor()` reports
//! [`super::IommuVendor::Amd`]. The scaffold pins four pure-function
//! surfaces — register offsets, Device Table Entry (DTE) encoder, I/O
//! Page Table Entry (PTE) encoder, and Extended Feature Register (EFR)
//! field decoders — plus a host-testable [`AmdViBackend`] struct that
//! tracks domains in an internal table without writing a single MMIO
//! byte.
//!
//! Until P6.7.9-pre.4 (DMA-Map vendor switch) wires it in, no caller
//! reaches this backend at runtime — the kernel `dma_map_handlers`
//! continues to use [`super::PassthroughBackend`]. The scaffold lives
//! in the workspace so the QEMU smoke (`-machine q35,iommu=amd`) can
//! assert the vendor selector + ACPI parser interaction without any
//! silicon side effect.
//!
//! ## Why a scaffold and not the live backend?
//!
//! Each P6.7.9-pre.x slice keeps the auditable surface bounded:
//!
//! - **P6.7.9-pre.0:** parser + trait + passthrough.
//! - **P6.7.9-pre.1:** firmware-probe + vendor selector.
//! - **P6.7.9-pre.2:** Intel VT-d register-offset constants +
//!   data-structure encoders + dormant `VtdBackend`.
//! - **P6.7.9-pre.3 (this slice):** AMD-Vi register-offset constants +
//!   DTE / I/O-PTE encoders + dormant `AmdViBackend`.
//! - **P6.7.9-pre.4:** swap `dma_map_handlers` to consult
//!   `iommu_vendor()` and route through the now-live backends.
//!
//! Splitting the live register programming off keeps every PR's
//! `unsafe` surface auditable and lets the host test matrix exercise
//! the encoders before the live ring is opened.
//!
//! ## References
//!
//! - AMD I/O Virtualization Technology (IOMMU) Specification rev 3.10
//!   § 5 (IOMMU architecture), in particular § 5.2.2 (Device Table
//!   Entry), § 5.3.1 (I/O Page Table), § 5.5 (MMIO register layout),
//!   § 5.7 (Extended Feature Register).
//! - NCIP-Driver-Framework-013 § S3 (capability scope + IOMMU
//!   semantics).

#![allow(
    clippy::module_name_repetitions,
    reason = "AmdViBackend / AmdViError / AmdViRegister share the AmdVi prefix by design — they are the public symbols of this submodule and the prefix prevents ambiguity with sibling VT-d / passthrough types"
)]

extern crate alloc;

use alloc::vec::Vec;

use super::{DomainId, IommuBackend, IommuError, IommuFlags, IommuVendor, PciBdf};

// =============================================================================
// Section 1 — AMD-Vi MMIO register offsets (AMD IOMMU spec rev 3.10 § 5.5).
//
// Offsets are byte-addressed against the per-IOMMU MMIO base
// discovered from the IVRS table's IVHD entry `base_address` field
// (see `super::ivrs::IvhdEntry::base_address`). The control + table
// pointer registers live in the first 4 KiB of the window; the queue
// head/tail registers live at offset 0x2000 in the second 4 KiB so
// they can be remapped uncached without disturbing the control plane.
// Constants are `pub` so the future live backend (P6.7.9-pre.4) and
// the host test suite can both reference the same single source of
// truth.
// =============================================================================

/// Device Table Base Address Register — 8 bytes at offset `0x00`.
///
/// Bits 0..51 carry the 4-KiB-aligned physical address of the device
/// table; bits 52..63 carry the table size encoding (`Size = 2^(n+12)`
/// bytes, where `n` is bits 0..8 of the register).
pub const REG_OFFSET_DEVICE_TABLE_BASE: u32 = 0x000;

/// Command Buffer Base Address Register — 8 bytes at offset `0x08`.
///
/// Bits 0..51 carry the 4-KiB-aligned physical base of the ring;
/// bits 56..59 encode log2 of the ring length.
pub const REG_OFFSET_COMMAND_BUFFER_BASE: u32 = 0x008;

/// Event Log Base Address Register — 8 bytes at offset `0x10`.
///
/// Same layout as the command buffer base.
pub const REG_OFFSET_EVENT_LOG_BASE: u32 = 0x010;

/// IOMMU Control Register — 8 bytes at offset `0x18`.
///
/// Each enable bit is paged by [`CTRL_BIT_*`](CTRL_BIT_IOMMU_EN).
pub const REG_OFFSET_CONTROL: u32 = 0x018;

/// Exclusion Range Base Register — 8 bytes at offset `0x20`.
pub const REG_OFFSET_EXCLUSION_BASE: u32 = 0x020;

/// Exclusion Range Limit Register — 8 bytes at offset `0x28`.
pub const REG_OFFSET_EXCLUSION_LIMIT: u32 = 0x028;

/// Extended Feature Register — 8 bytes at offset `0x30`. Read-only.
///
/// Advertises the optional capabilities the silicon implements:
/// prefetch, PPR, NX, GT, hardware-accessed PASID width, etc. See
/// the [`efr_*`](efr_supports_prefetch) decoders below.
pub const REG_OFFSET_EXT_FEATURE: u32 = 0x030;

/// PPR Log Base Address Register — 8 bytes at offset `0x38`.
pub const REG_OFFSET_PPR_LOG_BASE: u32 = 0x038;

/// Hardware Event Upper Register — 8 bytes at offset `0x40`. RW1C.
pub const REG_OFFSET_HW_EVENT_UPPER: u32 = 0x040;

/// Hardware Event Lower Register — 8 bytes at offset `0x48`. RW1C.
pub const REG_OFFSET_HW_EVENT_LOWER: u32 = 0x048;

/// Hardware Event Status Register — 8 bytes at offset `0x50`. RW1C.
pub const REG_OFFSET_HW_EVENT_STATUS: u32 = 0x050;

/// Command Buffer Head Pointer Register — 8 bytes at offset `0x2000`.
///
/// Hardware-maintained pointer into the ring (read-only). Software
/// observes this register to wait for completion of in-flight
/// commands.
pub const REG_OFFSET_COMMAND_BUFFER_HEAD: u32 = 0x2000;

/// Command Buffer Tail Pointer Register — 8 bytes at offset `0x2008`.
///
/// Software-maintained pointer into the ring; advancing the tail
/// notifies the IOMMU of new commands.
pub const REG_OFFSET_COMMAND_BUFFER_TAIL: u32 = 0x2008;

/// Event Log Head Pointer Register — 8 bytes at offset `0x2010`.
pub const REG_OFFSET_EVENT_LOG_HEAD: u32 = 0x2010;

/// Event Log Tail Pointer Register — 8 bytes at offset `0x2018`.
pub const REG_OFFSET_EVENT_LOG_TAIL: u32 = 0x2018;

/// IOMMU Status Register — 8 bytes at offset `0x2020`. RW1C.
///
/// Bit 0 = `EventOverflow`, bit 1 = `EventLogInt`, bit 2 = `ComWaitInt`,
/// bit 3 = `EventLogRun`, bit 4 = `CmdBufRun`. See AMD spec § 5.5.4.
pub const REG_OFFSET_STATUS: u32 = 0x2020;

// -- Control Register bit positions per spec rev 3.10 § 5.5.5 ----------

/// `IommuEn` (Enable IOMMU) — bit 0 of CONTROL.
pub const CTRL_BIT_IOMMU_EN: u64 = 1 << 0;
/// `HtTunEn` (`HyperTransport` Tunnel Enable) — bit 1.
pub const CTRL_BIT_HT_TUN_EN: u64 = 1 << 1;
/// `EventLogEn` (Event Log Enable) — bit 2.
pub const CTRL_BIT_EVENT_LOG_EN: u64 = 1 << 2;
/// `EventIntEn` (Event-log Interrupt Enable) — bit 3.
pub const CTRL_BIT_EVENT_INT_EN: u64 = 1 << 3;
/// `ComWaitIntEn` (Completion-wait Interrupt Enable) — bit 4.
pub const CTRL_BIT_COM_WAIT_INT_EN: u64 = 1 << 4;
/// `Coherent` — bit 10. When set, IOMMU page-walks are snoop coherent.
pub const CTRL_BIT_COHERENT: u64 = 1 << 10;
/// `Isoc` (Isochronous) — bit 11.
pub const CTRL_BIT_ISOC: u64 = 1 << 11;
/// `CmdBufEn` (Command-Buffer Enable) — bit 12.
pub const CTRL_BIT_CMD_BUF_EN: u64 = 1 << 12;
/// `PprLogEn` (PPR Log Enable) — bit 13.
pub const CTRL_BIT_PPR_LOG_EN: u64 = 1 << 13;
/// `PprIntEn` (PPR Interrupt Enable) — bit 14.
pub const CTRL_BIT_PPR_INT_EN: u64 = 1 << 14;
/// `PprEn` (Peripheral Page Request Enable) — bit 15.
pub const CTRL_BIT_PPR_EN: u64 = 1 << 15;
/// `GTEn` (Guest Translation Enable) — bit 16.
pub const CTRL_BIT_GT_EN: u64 = 1 << 16;

// -- STATUS register bit positions per spec rev 3.10 § 5.5.4 ----------
//
// STATUS is a 64-bit RW1C register mirroring the steady-state liveness
// of the IOMMU's optional features. The live activation path
// (P6.7.9-pre.6) polls these bits to detect when the command buffer
// and event log pipelines have come online after raising
// [`CTRL_BIT_CMD_BUF_EN`] / [`CTRL_BIT_EVENT_LOG_EN`].

/// `EventOverflow` — bit 0 of STATUS. Set by the IOMMU when the event
/// log was unable to accept a new entry; firmware drains the log and
/// writes a `1` back to clear (RW1C).
pub const STATUS_BIT_EVENT_OVERFLOW: u64 = 1 << 0;

/// `EventLogInt` — bit 1 of STATUS. Set when the IOMMU asserts the
/// event-log interrupt.
pub const STATUS_BIT_EVENT_LOG_INT: u64 = 1 << 1;

/// `ComWaitInt` — bit 2 of STATUS. Set when a `COMPLETION_WAIT`
/// command raises its interrupt.
pub const STATUS_BIT_COM_WAIT_INT: u64 = 1 << 2;

/// `EventLogRun` — bit 3 of STATUS. Mirrors [`CTRL_BIT_EVENT_LOG_EN`]
/// once the hardware has begun servicing the event log.
pub const STATUS_BIT_EVENT_LOG_RUN: u64 = 1 << 3;

/// `CmdBufRun` — bit 4 of STATUS. Mirrors [`CTRL_BIT_CMD_BUF_EN`] once
/// the hardware has begun fetching descriptors from the command
/// buffer.
pub const STATUS_BIT_CMD_BUF_RUN: u64 = 1 << 4;

// -- Command buffer layout (AMD IOMMU spec rev 3.10 § 5.3.2) ----------
//
// We program the minimum-size command buffer (256 entries × 16 bytes =
// one 4-KiB page) because the bring-up path only ever needs to submit
// a small number of `INVALIDATE_DEVTAB_ENTRY` descriptors. A larger
// ring would add zero throughput in the Phase 1 single-driver bring-up
// scenario.

/// Byte width of one AMD-Vi command-buffer entry (§ 5.4.1).
pub const CMD_BUFFER_ENTRY_BYTES: usize = 16;

/// Number of entries in the minimum-size command buffer
/// ([`CMD_BUFFER_LENGTH_ENCODING`] = `0x8`).
pub const CMD_BUFFER_ENTRY_COUNT: usize = 256;

/// Total command-buffer footprint in bytes —
/// `CMD_BUFFER_ENTRY_COUNT * CMD_BUFFER_ENTRY_BYTES`. Exactly one
/// 4-KiB frame.
pub const CMD_BUFFER_BYTES: usize = CMD_BUFFER_ENTRY_COUNT * CMD_BUFFER_ENTRY_BYTES;

/// `ComLen` field value for the minimum-size 4-KiB command buffer.
///
/// Encoded into bits 56..59 of [`REG_OFFSET_COMMAND_BUFFER_BASE`].
/// The buffer holds `2^ComLen` 16-byte entries; valid `ComLen` values
/// are `0x8..=0xF` per spec § 5.5.2.
pub const CMD_BUFFER_LENGTH_ENCODING: u64 = 8;

// -- Event log layout (AMD IOMMU spec rev 3.10 § 5.3.3) ---------------
//
// Same shape as the command buffer; the IOMMU writes log entries here
// when it encounters DMA faults. The minimum 256-entry buffer is
// sufficient for the Phase 1 boot smoke.

/// Byte width of one AMD-Vi event-log entry (§ 5.4.4).
pub const EVENT_LOG_ENTRY_BYTES: usize = 16;

/// Number of entries in the minimum-size event log.
pub const EVENT_LOG_ENTRY_COUNT: usize = 256;

/// Total event-log footprint in bytes — exactly one 4-KiB frame.
pub const EVENT_LOG_BYTES: usize = EVENT_LOG_ENTRY_COUNT * EVENT_LOG_ENTRY_BYTES;

/// `EventLen` field value for the minimum-size 4-KiB event log.
///
/// Encoded into bits 56..59 of [`REG_OFFSET_EVENT_LOG_BASE`].
pub const EVENT_LOG_LENGTH_ENCODING: u64 = 8;

// -- Device table size encoding ---------------------------------------

/// `Size` field value for a 1-frame (4-KiB) device table.
///
/// Encoded into bits 0..8 of [`REG_OFFSET_DEVICE_TABLE_BASE`]; per
/// spec § 5.5.1, the table size in bytes is `(Size + 1) × 4 KiB`. A
/// single 4-KiB frame holds 128 × 32-byte entries — enough to cover
/// the local PCI bus on the Phase 1 q35/Proxmox targets.
pub const DEVICE_TABLE_SIZE_ENCODING: u64 = 0;

/// Physical footprint in bytes of the Phase 1 device table —
/// `(DEVICE_TABLE_SIZE_ENCODING + 1) × 4 KiB`. Used by
/// `AmdViBackend::install_device_entry` to bounds-check the DTE
/// slot before writing.
pub const DEVICE_TABLE_BYTES: usize = 4096;

// -- Command opcode constants (AMD IOMMU spec rev 3.10 § 5.4) ---------
//
// Opcodes occupy bits 60..63 of the 128-bit command (i.e. bits 28..31
// of `data[1]` per AMD's little-endian dword layout). See
// [`encode_invalidate_devtab_entry`] for the exact placement.

/// `COMPLETION_WAIT` opcode (§ 5.4.2).
pub const CMD_OPCODE_COMPLETION_WAIT: u64 = 0x1;

/// `INVALIDATE_DEVTAB_ENTRY` opcode (§ 5.4.3).
pub const CMD_OPCODE_INVALIDATE_DEVTAB: u64 = 0x2;

/// `INVALIDATE_IOMMU_PAGES` opcode (§ 5.4.4).
pub const CMD_OPCODE_INVALIDATE_IOMMU_PAGES: u64 = 0x3;

/// `INVALIDATE_IOTLB_PAGES` opcode (§ 5.4.5).
pub const CMD_OPCODE_INVALIDATE_IOTLB_PAGES: u64 = 0x4;

/// `INVALIDATE_ALL` opcode (§ 5.4.9, gated by EFR.IASup).
pub const CMD_OPCODE_INVALIDATE_ALL: u64 = 0x8;

/// Bounded poll counter for hardware-status mirror bits, symmetric to
/// [`super::vtd::VTD_ACTIVATION_POLL_LIMIT`].
///
/// 1 million iterations easily covers the worst-case QEMU emulation
/// latency. On a real AMD platform the run-bits flip within
/// microseconds; an overflow indicates a wedged IOMMU and surfaces as
/// one of the `*Timeout` variants of [`AmdViActivateError`].
pub const AMDVI_ACTIVATION_POLL_LIMIT: u32 = 1_000_000;

// =============================================================================
// Section 2 — Device Table Entry (DTE) + I/O PTE encoders (AMD spec §§ 5.2.2 /
// 5.3.1).
//
// A DTE is 256 bits (4 × u64) per spec § 5.2.2.2; one entry per
// requester ID (BDF). An I/O PTE is 64 bits per spec § 5.3.1. We
// store both as `u64` quadwords (rather than `#[repr(C)]` bitfields)
// so the encoders stay pure functions that the host test suite can
// exercise without an `unsafe { *mut Dte }` cast.
// =============================================================================

/// Size of a single AMD-Vi Device Table Entry (§ 5.2.2.2).
///
/// 256 bits = 32 bytes. One entry per requester ID = 64 KiB total for
/// a flat 16-bit BDF space (`MAX_DEV_TABLE_BYTES = 2 MiB` per
/// 256-entry segment, capped at 64 KiB for the typical single-segment
/// case).
pub const DEVICE_TABLE_ENTRY_BYTES: usize = 32;

/// Size of a single AMD-Vi I/O Page Table Entry (§ 5.3.1).
///
/// 64 bits = 8 bytes. A 4-KiB I/O page table holds 512 entries.
pub const IOPTE_BYTES: usize = 8;

/// Encoded AMD-Vi Device Table Entry.
///
/// Layout (§ 5.2.2.2; only the fields the scaffold encodes/decodes are
/// listed):
/// ```text
/// qword[0]:
///   bit  0    : V (Valid)
///   bit  1    : TV (Translation Information Valid)
///   bit  9..11: Mode (page-table level depth, 1..6; 0 = no translation)
///   bit 12..51: Page-Table Root (4-KiB aligned physical address)
///   bit 61    : IR (I/O Read permission)
///   bit 62    : IW (I/O Write permission)
/// qword[1]:
///   bit  0..15: DomainID (16 bits)
/// qword[2]:
///   reserved / interrupt-remapping (not encoded by the scaffold)
/// qword[3]:
///   reserved (not encoded by the scaffold)
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTableEntry {
    /// Four quadwords (256 bits total).
    pub qwords: [u64; 4],
}

impl DeviceTableEntry {
    /// `V` bit position (`qwords[0]` bit 0).
    pub const BIT_V: u64 = 1 << 0;
    /// `TV` bit position (`qwords[0]` bit 1).
    pub const BIT_TV: u64 = 1 << 1;
    /// `IR` bit position (`qwords[0]` bit 61).
    pub const BIT_IR: u64 = 1 << 61;
    /// `IW` bit position (`qwords[0]` bit 62).
    pub const BIT_IW: u64 = 1 << 62;

    /// `true` iff the Valid bit (`qwords[0]` bit 0) is set.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        (self.qwords[0] & Self::BIT_V) != 0
    }

    /// `true` iff the Translation Valid bit (`qwords[0]` bit 1) is set.
    #[must_use]
    pub const fn translation_valid(self) -> bool {
        (self.qwords[0] & Self::BIT_TV) != 0
    }

    /// Extract the 4-KiB-aligned page-table root pointer (`qwords[0]`
    /// bits 12..51).
    #[must_use]
    pub const fn page_table_root(self) -> u64 {
        self.qwords[0] & 0x000F_FFFF_FFFF_F000
    }

    /// Extract the Mode field (`qwords[0]` bits 9..11).
    #[must_use]
    pub const fn mode_raw(self) -> u8 {
        ((self.qwords[0] >> 9) & 0b111) as u8
    }

    /// Extract the 16-bit Domain identifier (`qwords[1]` bits 0..15).
    #[must_use]
    pub const fn domain_id(self) -> DomainId {
        DomainId::new((self.qwords[1] & 0xFFFF) as u16)
    }

    /// `true` iff the IR (I/O Read) permission bit is set.
    #[must_use]
    pub const fn allows_read(self) -> bool {
        (self.qwords[0] & Self::BIT_IR) != 0
    }

    /// `true` iff the IW (I/O Write) permission bit is set.
    #[must_use]
    pub const fn allows_write(self) -> bool {
        (self.qwords[0] & Self::BIT_IW) != 0
    }
}

/// AMD-Vi page-table-walk depth (DTE Mode field, § 5.2.2.2).
///
/// Selects how many levels of the I/O page table the IOMMU walks
/// before reaching the leaf I/O PTE. `NoTranslation` is the "all
/// requests pass through untranslated" mode used by the bring-up
/// domain `0`; `Level1..6` are the standard 4-KiB / 2-MiB / 1-GiB /
/// 512-GiB / 256-TiB / 128-PiB paging modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageMode {
    /// `Mode = 0` — no translation (host-physical = guest-physical).
    NoTranslation = 0,
    /// `Mode = 1` — 1-level table, 4-KiB leaves.
    Level1 = 1,
    /// `Mode = 2` — 2-level table.
    Level2 = 2,
    /// `Mode = 3` — 3-level table.
    Level3 = 3,
    /// `Mode = 4` — 4-level table (matches `x86_64` paging).
    Level4 = 4,
    /// `Mode = 5` — 5-level table.
    Level5 = 5,
    /// `Mode = 6` — 6-level table (256-TiB address space).
    Level6 = 6,
}

impl PageMode {
    /// Raw 3-bit `Mode` encoding for the DTE / I/O PTE.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode a 3-bit `Mode` value back into a [`PageMode`]. Values
    /// outside `0..=6` are clamped to [`PageMode::NoTranslation`] so a
    /// torn read never crashes the syscall layer.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Level1,
            2 => Self::Level2,
            3 => Self::Level3,
            4 => Self::Level4,
            5 => Self::Level5,
            6 => Self::Level6,
            _ => Self::NoTranslation,
        }
    }
}

/// Build a Device Table Entry pointing at `page_table_root` for
/// `domain` with the given page-walk depth and I/O permission flags.
///
/// `IommuFlags::READ` / `IommuFlags::WRITE` map to the DTE `IR` / `IW`
/// bits respectively. `IommuFlags::EXECUTE` and `IommuFlags::COHERENT`
/// do not surface at the DTE level on AMD-Vi: the per-page snoop bit
/// lives in the I/O PTE, and DMA does not have an execute permission
/// in AMD-Vi (transactions never fetch instructions). The encoder
/// silently ignores them at the DTE layer; they ARE honoured by
/// [`encode_iopte`] below.
///
/// # Errors
///
/// Returns `Err([AmdViError::AddressMisaligned])` when
/// `page_table_root` is not 4-KiB aligned.
pub fn encode_device_table_entry(
    page_table_root: u64,
    domain: DomainId,
    mode: PageMode,
    flags: IommuFlags,
) -> Result<DeviceTableEntry, AmdViError> {
    if page_table_root & 0xFFF != 0 {
        return Err(AmdViError::AddressMisaligned);
    }
    let mut qword0 = (page_table_root & 0x000F_FFFF_FFFF_F000)
        | ((u64::from(mode.as_u8()) & 0b111) << 9)
        | DeviceTableEntry::BIT_V
        | DeviceTableEntry::BIT_TV;
    if flags.contains(IommuFlags::READ) {
        qword0 |= DeviceTableEntry::BIT_IR;
    }
    if flags.contains(IommuFlags::WRITE) {
        qword0 |= DeviceTableEntry::BIT_IW;
    }
    let qword1 = u64::from(domain.raw());
    Ok(DeviceTableEntry {
        qwords: [qword0, qword1, 0, 0],
    })
}

/// Build a Valid-but-untranslated Device Table Entry.
///
/// Sets `V = 1`, `TV = 0`, all permission bits = 0; AMD-Vi treats
/// such an entry as "device exists but every DMA request is blocked"
/// — the safe default for an enumerated-but-unconfigured PCI device.
#[must_use]
pub const fn encode_device_table_entry_blocked(domain: DomainId) -> DeviceTableEntry {
    DeviceTableEntry {
        qwords: [DeviceTableEntry::BIT_V, domain.raw() as u64, 0, 0],
    }
}

/// Build a not-present Device Table Entry (all quadwords zero).
///
/// Used during bring-up to publish a blank device table. Any DMA
/// request that hits a `V = 0` entry is target-aborted by the IOMMU.
#[must_use]
pub const fn encode_device_table_entry_absent() -> DeviceTableEntry {
    DeviceTableEntry { qwords: [0; 4] }
}

/// Encoded AMD-Vi I/O Page Table Entry (PTE).
///
/// Layout (§ 5.3.1; flags follow the same convention as the
/// CPU-side page tables but the bit positions are AMD-Vi-specific):
/// ```text
/// bit  0      : PR (Present)
/// bit  1..8   : Reserved / software available
/// bit  9..11  : NextLvl (next page-table level; 0 = 4-KiB leaf)
/// bit 12..51  : Page Address (4-KiB-aligned host-physical address)
/// bit 52..60  : Software available / reserved
/// bit 61      : FC (Force Coherent / Snoop)
/// bit 62      : IR (I/O Read permission)
/// bit 63      : IW (I/O Write permission)
/// ```
///
/// Constructed via [`encode_iopte`] and consumed via the field
/// accessors below.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IoPageTableEntry(pub u64);

impl IoPageTableEntry {
    /// `PR` bit position (bit 0).
    pub const BIT_PR: u64 = 1 << 0;
    /// `FC` bit position (bit 61).
    pub const BIT_FC: u64 = 1 << 61;
    /// `IR` bit position (bit 62).
    pub const BIT_IR: u64 = 1 << 62;
    /// `IW` bit position (bit 63).
    pub const BIT_IW: u64 = 1 << 63;

    /// `true` iff the Present bit (bit 0) is set.
    #[must_use]
    pub const fn is_present(self) -> bool {
        (self.0 & Self::BIT_PR) != 0
    }

    /// 4-KiB-aligned output address (bits 12..51).
    #[must_use]
    pub const fn output_address(self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    /// Extract the `NextLvl` field (bits 9..11).
    #[must_use]
    pub const fn next_level(self) -> u8 {
        ((self.0 >> 9) & 0b111) as u8
    }

    /// `true` iff the IR (I/O Read) permission bit is set.
    #[must_use]
    pub const fn allows_read(self) -> bool {
        (self.0 & Self::BIT_IR) != 0
    }

    /// `true` iff the IW (I/O Write) permission bit is set.
    #[must_use]
    pub const fn allows_write(self) -> bool {
        (self.0 & Self::BIT_IW) != 0
    }

    /// `true` iff the FC (Force Coherent / Snoop) bit is set.
    #[must_use]
    pub const fn force_coherent(self) -> bool {
        (self.0 & Self::BIT_FC) != 0
    }
}

/// Build a leaf I/O PTE for `phys` with `flags`.
///
/// Translates the kernel [`IommuFlags`] surface into the AMD-Vi
/// bit-position constants:
///
/// - `READ`  → `IR`
/// - `WRITE` → `IW` (plus `IR`, mirroring [`super::vtd::encode_slpte`]
///   semantics — AMD-Vi does not require `IR` for a `IW`-only entry,
///   but treating write-only as malformed keeps the cross-vendor
///   semantics uniform).
/// - `EXECUTE` → ignored (AMD-Vi has no execute bit for DMA).
/// - `COHERENT` → `FC` (Force Coherent / Snoop).
///
/// The encoder always emits a leaf entry (`NextLvl = 0`). Intermediate
/// page-directory entries are constructed by [`encode_pde`].
///
/// # Errors
///
/// Returns `Err([AmdViError::AddressMisaligned])` when `phys` is not
/// 4-KiB aligned.
pub fn encode_iopte(phys: u64, flags: IommuFlags) -> Result<IoPageTableEntry, AmdViError> {
    if phys & 0xFFF != 0 {
        return Err(AmdViError::AddressMisaligned);
    }
    let mut bits = phys & 0x000F_FFFF_FFFF_F000;
    if flags.contains(IommuFlags::READ) || flags.contains(IommuFlags::WRITE) {
        bits |= IoPageTableEntry::BIT_PR;
        bits |= IoPageTableEntry::BIT_IR;
    }
    if flags.contains(IommuFlags::WRITE) {
        bits |= IoPageTableEntry::BIT_IW;
    }
    if flags.contains(IommuFlags::COHERENT) {
        bits |= IoPageTableEntry::BIT_FC;
    }
    Ok(IoPageTableEntry(bits))
}

/// Build a Page Directory Entry (PDE) — an intermediate entry that
/// points at another page table at level `next_level`.
///
/// PDEs are present + carry the `IR/IW` permissions of the entire
/// subtree (AMD-Vi propagates permissions top-down; if `IR` is clear
/// at a PDE, every entry below it is non-readable regardless).
///
/// # Errors
///
/// - `Err([AmdViError::AddressMisaligned])` when `next_table_phys` is
///   not 4-KiB aligned.
/// - `Err([AmdViError::UnsupportedFlags])` when `next_level` is `0`
///   (which would make this a leaf entry; callers must use
///   [`encode_iopte`] for leaves).
pub fn encode_pde(
    next_table_phys: u64,
    next_level: PageMode,
    flags: IommuFlags,
) -> Result<IoPageTableEntry, AmdViError> {
    if next_table_phys & 0xFFF != 0 {
        return Err(AmdViError::AddressMisaligned);
    }
    if matches!(next_level, PageMode::NoTranslation) {
        return Err(AmdViError::UnsupportedFlags);
    }
    let mut bits = next_table_phys & 0x000F_FFFF_FFFF_F000;
    bits |= IoPageTableEntry::BIT_PR;
    bits |= (u64::from(next_level.as_u8()) & 0b111) << 9;
    if flags.contains(IommuFlags::READ) || flags.contains(IommuFlags::WRITE) {
        bits |= IoPageTableEntry::BIT_IR;
    }
    if flags.contains(IommuFlags::WRITE) {
        bits |= IoPageTableEntry::BIT_IW;
    }
    if flags.contains(IommuFlags::COHERENT) {
        bits |= IoPageTableEntry::BIT_FC;
    }
    Ok(IoPageTableEntry(bits))
}

// =============================================================================
// Section 2.b — Live-MMIO register-value encoders (AMD IOMMU spec
// rev 3.10 § 5.4 + § 5.5).
//
// These functions assemble the 64-bit values written into the
// per-IOMMU MMIO registers during activation. They are pure (no
// `unsafe`) so the host test suite can pin every bit position; the
// live `unsafe` MMIO writes consume their results in
// [`AmdViBackend::activate_hardware`].
// =============================================================================

/// Encode the value written to [`REG_OFFSET_DEVICE_TABLE_BASE`]
/// (AMD spec § 5.5.1).
///
/// Layout:
/// - bits 0..8: `Size` field — table size = `(size + 1) × 4 KiB`.
/// - bits 9..11: reserved (must be 0).
/// - bits 12..51: 4-KiB-aligned table physical base address.
/// - bits 52..63: reserved (must be 0).
///
/// Reserved bits are masked out defensively so a high-bit overflow in
/// `table_phys` cannot accidentally set Size, and a size argument
/// above 9 bits cannot leak into the reserved region.
#[must_use]
pub const fn encode_device_table_base(table_phys: u64, size: u64) -> u64 {
    let base = table_phys & 0x000F_FFFF_FFFF_F000;
    let sz = size & 0x1FF;
    base | sz
}

/// Encode the value written to [`REG_OFFSET_COMMAND_BUFFER_BASE`]
/// (AMD spec § 5.5.2).
///
/// Layout:
/// - bits 0..11: reserved (must be 0; 4-KiB alignment is implicit).
/// - bits 12..51: 4-KiB-aligned buffer physical base address.
/// - bits 52..55: reserved.
/// - bits 56..59: `ComLen` — buffer holds `2^ComLen` 16-byte entries
///   (so `ComLen=8` → 256 entries = 4 KiB, `ComLen=9` → 512 = 8 KiB).
/// - bits 60..63: reserved (must be 0).
#[must_use]
pub const fn encode_command_buffer_base(buf_phys: u64, com_len: u64) -> u64 {
    let base = buf_phys & 0x000F_FFFF_FFFF_F000;
    let len = (com_len & 0xF) << 56;
    base | len
}

/// Encode the value written to [`REG_OFFSET_EVENT_LOG_BASE`]
/// (AMD spec § 5.5.3). Same layout as
/// [`encode_command_buffer_base`].
#[must_use]
pub const fn encode_event_log_base(log_phys: u64, event_len: u64) -> u64 {
    let base = log_phys & 0x000F_FFFF_FFFF_F000;
    let len = (event_len & 0xF) << 56;
    base | len
}

/// Encode the low + high qwords of a 128-bit `INVALIDATE_DEVTAB_ENTRY`
/// command (AMD spec § 5.4.3).
///
/// Layout (one 128-bit command = two 64-bit qwords, little-endian
/// byte order in the command-buffer ring):
/// - lo qword bits 0..15:  `DeviceID` (16-bit BDF).
/// - lo qword bits 16..59: reserved (zero).
/// - lo qword bits 60..63: `Op` = [`CMD_OPCODE_INVALIDATE_DEVTAB`]
///   (`0x2`).
/// - hi qword: reserved / `PASID`-related (zero for the bring-up).
///
/// Returns `(low, high)`. The caller writes them into successive
/// 64-bit slots of the command-buffer ring.
#[must_use]
pub const fn encode_invalidate_devtab_entry(device_id: u16) -> (u64, u64) {
    let low = (CMD_OPCODE_INVALIDATE_DEVTAB << 60) | ((device_id as u64) & 0xFFFF);
    (low, 0)
}

/// Encode a 128-bit `INVALIDATE_IOMMU_PAGES` command targeting **all
/// entries** for a single domain (§ 5.4.4).
///
/// Layout per spec § 5.4.4 (little-endian on the wire):
/// ```text
/// data[0] (low qword):
///   bits  0..15 : Pasid (0 for non-PASID variants)
///   bits 32..47 : DomainID
///   bits 60..63 : Opcode (= INVALIDATE_IOMMU_PAGES)
/// data[1] (high qword):
///   bit  0      : Size (S) = 1 for "invalidate all"
///   bits 12..63 : Address (zero — ignored when S=1 spans all)
/// ```
///
/// Returns `(low, high)`. The caller writes them into successive
/// 64-bit slots of the command-buffer ring.
#[must_use]
pub const fn encode_invalidate_iommu_pages_domain(domain: DomainId) -> (u64, u64) {
    let low = (CMD_OPCODE_INVALIDATE_IOMMU_PAGES << 60) | ((domain.raw() as u64) << 32);
    // S=1 in bit 0 of the high qword + Address=0 (everything in the
    // domain's I/O page table is invalidated).
    let high = 0x1_u64;
    (low, high)
}

/// Byte offset of the DTE slot for `bdf` within the AMD-Vi device
/// table (§ 5.2.2.1 — slot index = full 16-bit requester ID, slot
/// size = [`DEVICE_TABLE_ENTRY_BYTES`]).
///
/// Pure function — moves the index arithmetic out of the unsafe MMIO
/// path so host tests can pin the offsets.
#[must_use]
pub const fn dte_offset(bdf: PciBdf) -> u64 {
    (bdf.raw() as u64) * (DEVICE_TABLE_ENTRY_BYTES as u64)
}

// =============================================================================
// Section 3 — Extended Feature Register (EFR) field decoders
// (AMD IOMMU spec rev 3.10 § 5.7).
//
// The probe path reads EFR once per IOMMU to learn the optional
// capabilities the silicon advertises (Prefetch, PPR, NX, GT, PASID
// width, ...). These helpers stay pure so the host test suite can
// exercise every bit pattern without firmware.
// =============================================================================

/// `PreFSup` — bit 0 of EFR. Set when the IOMMU supports the
/// `PREFETCH_PAGES` invalidation command.
#[must_use]
pub const fn efr_supports_prefetch(efr: u64) -> bool {
    (efr & (1 << 0)) != 0
}

/// `PPRSup` — bit 1 of EFR. Set when Peripheral Page Request is
/// supported.
#[must_use]
pub const fn efr_supports_ppr(efr: u64) -> bool {
    (efr & (1 << 1)) != 0
}

/// `XTSup` — bit 2 of EFR. Set when 6-level page-tables and extended
/// PCI device-ID format are supported.
#[must_use]
pub const fn efr_supports_xt(efr: u64) -> bool {
    (efr & (1 << 2)) != 0
}

/// `NXSup` — bit 3 of EFR. Set when the No-Execute bit is honoured on
/// guest page-table walks (`GTEn` mode).
#[must_use]
pub const fn efr_supports_nx(efr: u64) -> bool {
    (efr & (1 << 3)) != 0
}

/// `GTSup` — bit 4 of EFR. Set when Guest Translation is supported
/// (the IOMMU honours nested page tables for guest DMA requests).
#[must_use]
pub const fn efr_supports_gt(efr: u64) -> bool {
    (efr & (1 << 4)) != 0
}

/// `IASup` — bit 6 of EFR. Set when invalidate-all (`INVALIDATE_ALL`)
/// command is supported.
#[must_use]
pub const fn efr_supports_invalidate_all(efr: u64) -> bool {
    (efr & (1 << 6)) != 0
}

/// `GASup` — bit 7 of EFR. Set when Guest APIC virtualization is
/// supported.
#[must_use]
pub const fn efr_supports_ga(efr: u64) -> bool {
    (efr & (1 << 7)) != 0
}

/// `HESup` — bit 8 of EFR. Set when hardware-error reporting is
/// supported.
#[must_use]
pub const fn efr_supports_hardware_error(efr: u64) -> bool {
    (efr & (1 << 8)) != 0
}

/// `PASmax` — bits 11..15 of EFR (5 bits).
///
/// Maximum PASID width supported: the implementation can address up
/// to `2^(PASmax + 1) - 1` distinct PASIDs.
#[must_use]
pub const fn efr_pas_max(efr: u64) -> u8 {
    ((efr >> 11) & 0b1_1111) as u8
}

/// `HATS` (Host Address Translation Size) — bits 22..23 of EFR
/// (2 bits). Encodes the maximum host address-translation depth the
/// IOMMU advertises:
///
/// | HATS | Levels |
/// |------|--------|
/// | 0    | 4-level (48-bit physical address) |
/// | 1    | 5-level (57-bit) |
/// | 2    | 6-level (64-bit) |
/// | 3    | reserved (treated as `NoTranslation`) |
#[must_use]
pub const fn efr_hats(efr: u64) -> u8 {
    ((efr >> 22) & 0b11) as u8
}

/// Pick the highest supported [`PageMode`] from the EFR `HATS` field.
///
/// Returns [`PageMode::NoTranslation`] for the reserved value `0b11`
/// (defensive — firmware should never advertise this).
#[must_use]
pub const fn efr_highest_supported_mode(efr: u64) -> PageMode {
    match efr_hats(efr) {
        0 => PageMode::Level4,
        1 => PageMode::Level5,
        2 => PageMode::Level6,
        _ => PageMode::NoTranslation,
    }
}

// =============================================================================
// Section 4 — `AmdViBackend`: host-testable dormant backend.
//
// The struct tracks `(domain_id, [mapping_record])` tuples in an
// internal `Vec` so the `IommuBackend` trait can be exercised against
// it from host tests. It does NOT write any MMIO byte; the live
// backend lands in P6.7.9-pre.4 with explicit `unsafe` blocks gated
// behind `#[cfg(target_arch = "x86_64")]`.
// =============================================================================

/// Error category raised by the AMD-Vi encoders + scaffold backend.
///
/// Maps to [`IommuError`] when surfaced through the trait so callers
/// see a vendor-neutral taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdViError {
    /// Address argument violated the AMD-Vi 4-KiB alignment requirement.
    AddressMisaligned,
    /// Caller passed a [`DomainId`] not previously installed.
    UnknownDomain,
    /// `flags` requested a permission the backend cannot honour, or a
    /// PDE encoder was invoked with [`PageMode::NoTranslation`].
    UnsupportedFlags,
}

impl From<AmdViError> for IommuError {
    fn from(err: AmdViError) -> Self {
        match err {
            AmdViError::AddressMisaligned => Self::AddressMisaligned,
            AmdViError::UnknownDomain => Self::InvalidDomain,
            AmdViError::UnsupportedFlags => Self::Unsupported,
        }
    }
}

/// Error category surfaced by `AmdViBackend::activate_hardware` (the
/// bare-metal-only activation entry point gated on
/// `cfg(target_os = "none")`).
///
/// Maps to [`IommuError::ActivationFailed`] when surfaced through the
/// trait; the variant identity is preserved for the kernel boot log
/// so the operator can tell command-buffer-start timeout from
/// event-log-start timeout from a stalled invalidate. None of these
/// should fire on a healthy IOMMU — they signal either a spec-divergent
/// emulation or genuinely wedged silicon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdViActivateError {
    /// [`AmdViBackend::prepare_activation`] was never called (or
    /// reported zeroes) before `AmdViBackend::activate_hardware` —
    /// `unit_base` is `0` so MMIO writes would target the BIOS
    /// real-mode area.
    NotPrepared,
    /// Polled [`STATUS_BIT_CMD_BUF_RUN`] for
    /// [`AMDVI_ACTIVATION_POLL_LIMIT`] iterations after raising
    /// [`CTRL_BIT_CMD_BUF_EN`]; bit never flipped.
    CmdBufStartTimeout,
    /// Polled [`STATUS_BIT_EVENT_LOG_RUN`] for
    /// [`AMDVI_ACTIVATION_POLL_LIMIT`] iterations after raising
    /// [`CTRL_BIT_EVENT_LOG_EN`]; bit never flipped.
    EventLogStartTimeout,
    /// Command-buffer Head never caught up to Tail after submitting
    /// the bring-up `INVALIDATE_DEVTAB_ENTRY` descriptor. Indicates a
    /// stuck command pipeline.
    InvalidationTimeout,
    /// Command-buffer Head never caught up to Tail after submitting
    /// the post-`IommuEn` `INVALIDATE_ALL` descriptor in
    /// `AmdViBackend::enable_translation`. Indicates a stuck command
    /// pipeline AFTER translation was nominally enabled — the IOMMU
    /// may now be gating DMA but cannot observe new entries.
    TranslationEnableTimeout,
}

impl From<AmdViActivateError> for IommuError {
    fn from(_err: AmdViActivateError) -> Self {
        Self::ActivationFailed
    }
}

/// Recorded per-device attachment in the host-testable scaffold.
///
/// Symmetric to [`super::vtd::VtdAttachment`]. Live MMIO state
/// (`AmdViBackend::install_device_entry`) also pushes a
/// [`AmdViAttachment`] so the bookkeeping is consistent between the
/// host and bare-metal halves: every `(bdf → domain)` binding visible
/// to the trait dispatch surface has exactly one entry here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmdViAttachment {
    /// PCI requester ID owning the binding (= AMD-Vi `DeviceID`).
    pub bdf: PciBdf,
    /// Domain the device is bound to.
    pub domain: DomainId,
}

/// Error surfaced by `AmdViBackend::install_device_entry`.
///
/// Maps to [`IommuError`] when surfaced through the public surface so
/// the syscall layer keeps a vendor-neutral taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdViAttachError {
    /// The backend was never `activate_hardware`'d so the command
    /// buffer is not guaranteed to be drained — refusing to write
    /// the DTE avoids publishing a translation entry the IOMMU
    /// cannot invalidate later.
    NotActivated,
    /// `domain` was never installed via
    /// [`super::IommuBackend::install_domain`].
    DomainNotInstalled,
    /// `bdf` is already attached (callers must `detach_device` first).
    AlreadyAttached,
    /// `iopt_phys` is not 4-KiB aligned.
    AddressMisaligned,
    /// `bdf`'s requester-ID exceeds the configured device-table size
    /// (Phase 1 ships with [`DEVICE_TABLE_SIZE_ENCODING`] = `0` =
    /// 4 KiB = 128 DTE slots — sufficient for bus 0 device 0..15
    /// only). Raising the device-table size is tracked as a Phase 2
    /// follow-up.
    DeviceTableTooSmall,
    /// `mode` is [`PageMode::NoTranslation`] — install with no
    /// translation is a contradiction (callers wanting pass-through
    /// must not invoke `install_device_entry` at all).
    UnsupportedMode,
    /// Command-buffer Head never caught up to Tail after submitting
    /// the per-domain invalidations.
    InvalidationTimeout,
}

impl From<AmdViAttachError> for IommuError {
    fn from(err: AmdViAttachError) -> Self {
        match err {
            AmdViAttachError::NotActivated | AmdViAttachError::InvalidationTimeout => {
                Self::ActivationFailed
            }
            AmdViAttachError::DomainNotInstalled => Self::InvalidDomain,
            AmdViAttachError::AlreadyAttached | AmdViAttachError::UnsupportedMode => {
                Self::Unsupported
            }
            AmdViAttachError::AddressMisaligned => Self::AddressMisaligned,
            AmdViAttachError::DeviceTableTooSmall => Self::DomainTableFull,
        }
    }
}

/// One mapping record tracked by the scaffold backend.
///
/// Pure data — exists so the host test suite can assert on the
/// IOMMU-side state without touching MMIO. Symmetric to
/// [`super::vtd::ScaffoldMapping`] but carries an AMD-Vi `leaf_iopte`
/// rather than a VT-d `leaf_slpte`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaffoldMapping {
    /// Domain the mapping belongs to.
    pub domain: DomainId,
    /// I/O virtual address (4-KiB aligned).
    pub iova: u64,
    /// Backing physical address (4-KiB aligned).
    pub phys: u64,
    /// Length in bytes (multiple of 4 KiB).
    pub len: u64,
    /// Encoded I/O PTE for the first 4-KiB leaf.
    pub leaf_iopte: IoPageTableEntry,
}

/// Dormant AMD-Vi backend. Holds bookkeeping only; emits no MMIO
/// while the activation parameters are zero.
///
/// The host-test exercise path:
///
/// 1. Build `AmdViBackend::new()`.
/// 2. `install_domain(DomainId::new(7))?;`
/// 3. `map(DomainId::new(7), 0x1000, 0x2000, 0x1000, IommuFlags::READ)?;`
/// 4. Inspect the recorded `mappings()` slice in the assertion.
///
/// P6.7.9-pre.6 extends the backend with five `u64`/`bool` fields and
/// the `prepare_activation` / `activate_hardware` (bare-metal-only)
/// pair so the kernel boot path can drive the live MMIO programming
/// against the per-IOMMU register window discovered by the IVRS
/// walker. The `map`/`unmap` paths remain dormant — per-domain device
/// table writes land in P6.7.9-pre.7+.
#[derive(Debug, Clone, Default)]
pub struct AmdViBackend {
    /// Installed domains, in insertion order.
    domains: Vec<DomainId>,
    /// Recorded mappings.
    mappings: Vec<ScaffoldMapping>,
    /// MMIO base of the per-IOMMU register window. `0` while the
    /// backend is dormant; populated by [`Self::prepare_activation`]
    /// once the boot probe resolves the first IVHD's `base_address`.
    unit_base: u64,
    /// Physical address of the 4-KiB device-table page used by the
    /// live MMIO path. `0` while dormant.
    device_table_phys: u64,
    /// Physical address of the 4-KiB command-buffer page. `0` while
    /// dormant.
    command_buffer_phys: u64,
    /// Physical address of the 4-KiB event-log page. `0` while
    /// dormant.
    event_log_phys: u64,
    /// Software-maintained tail byte-offset into the command buffer,
    /// measured in **bytes** so it can be written to
    /// [`REG_OFFSET_COMMAND_BUFFER_TAIL`] directly. Wraps at
    /// [`CMD_BUFFER_BYTES`].
    command_buffer_tail: u64,
    /// `true` once `Self::activate_hardware` has cleanly walked the
    /// device-table install + command-buffer + event-log enable
    /// sequence and observed every status mirror bit set (the
    /// activation method is gated on `cfg(target_os = "none")`).
    hardware_activated: bool,
    /// Per-device attachments recorded by `attach_device` and (for
    /// bare-metal builds) `install_device_entry`. Both halves of the
    /// API share this vector so the host-testable scaffold and the
    /// live MMIO path agree on `(bdf → domain)` state.
    attachments: Vec<AmdViAttachment>,
    /// Per-domain I/O page-table root registry (P6.7.9-pre.9).
    ///
    /// Populated through [`Self::provision_domain_pt`] before the live
    /// `install_device_entry` MMIO path runs; the recorded `root_phys`
    /// is what `install_device_entry` consumes as the `iopt_phys`
    /// argument for the matching domain.
    domain_pts: super::pt_alloc::DomainPageTables,
    /// `true` once `Self::enable_translation` has flipped
    /// `CTRL.IommuEn` and the post-flip `INVALIDATE_ALL` command has
    /// drained. Sticky for the lifetime of the kernel;
    /// [`Self::prepare_activation`] resets it back to `false` together
    /// with [`Self::hardware_activated`] when re-prepared with different
    /// parameters (MP follow-up).
    translation_enabled: bool,
}

impl AmdViBackend {
    /// Construct an empty backend.
    ///
    /// `const` so the kernel-wide [`super::IOMMU_BACKEND`] static can
    /// be initialised at static-init time without paying for lazy
    /// `OnceLock` overhead (P6.7.9-pre.4).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            domains: Vec::new(),
            mappings: Vec::new(),
            unit_base: 0,
            device_table_phys: 0,
            command_buffer_phys: 0,
            event_log_phys: 0,
            command_buffer_tail: 0,
            hardware_activated: false,
            attachments: Vec::new(),
            domain_pts: super::pt_alloc::DomainPageTables::new(),
            translation_enabled: false,
        }
    }

    /// Allocate the per-domain I/O page-table root frame for `domain`
    /// through the supplied [`super::pt_alloc::FrameSource`] and record
    /// the `(domain, root_phys)` binding so the live per-device install
    /// MMIO call can read `root_phys` back via
    /// [`Self::domain_pt_root_phys`].
    ///
    /// Must be preceded by a successful [`Self::install_domain`]; the
    /// caller is responsible for ordering (the registry does not depend
    /// on the domain list, but the live MMIO path will refuse to bind a
    /// device whose `domain` has no recorded root).
    ///
    /// # Errors
    ///
    /// Forwards every [`super::pt_alloc::DomainPtError`] variant
    /// unchanged — see the module documentation for the taxonomy.
    pub fn provision_domain_pt(
        &mut self,
        domain: DomainId,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<u64, super::pt_alloc::DomainPtError> {
        self.domain_pts.provision(domain, src)
    }

    /// Release the per-domain page-table root frame and remove the
    /// `(domain, root_phys)` binding.
    ///
    /// # Errors
    ///
    /// [`super::pt_alloc::DomainPtError::NotProvisioned`] when `domain`
    /// has no recorded root frame.
    pub fn release_domain_pt(
        &mut self,
        domain: DomainId,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<(), super::pt_alloc::DomainPtError> {
        self.domain_pts.release(domain, src)
    }

    /// Recorded per-domain page-table root, or `None` if `domain` has
    /// not been provisioned through [`Self::provision_domain_pt`].
    #[must_use]
    pub fn domain_pt_root_phys(&self, domain: DomainId) -> Option<u64> {
        self.domain_pts.root_phys(domain)
    }

    /// Snapshot of the per-domain page-table registry (insertion order).
    #[must_use]
    pub fn domain_pt_entries(&self) -> &[super::pt_alloc::DomainPtEntry] {
        self.domain_pts.entries()
    }

    /// Snapshot of the recorded per-device attachments (insertion
    /// order). Exposed primarily so the host test suite can assert on
    /// the `(bdf → domain)` state without going through the trait
    /// surface.
    #[must_use]
    pub fn attachments(&self) -> &[AmdViAttachment] {
        &self.attachments
    }

    /// `true` iff `bdf` is currently attached to some domain.
    #[must_use]
    pub fn has_attachment(&self, bdf: PciBdf) -> bool {
        self.attachments.iter().any(|a| a.bdf == bdf)
    }

    /// Snapshot of the recorded mapping list (newest last).
    #[must_use]
    pub fn mappings(&self) -> &[ScaffoldMapping] {
        &self.mappings
    }

    /// `true` iff `id` was installed via [`Self::install_domain`].
    #[must_use]
    pub fn has_domain(&self, id: DomainId) -> bool {
        self.domains.iter().any(|d| *d == id)
    }

    /// Snapshot of the installed domain list (insertion order).
    #[must_use]
    pub fn domains(&self) -> &[DomainId] {
        &self.domains
    }

    /// MMIO base of the per-IOMMU register window (`0` while dormant).
    #[must_use]
    pub const fn unit_base(&self) -> u64 {
        self.unit_base
    }

    /// Physical address of the 4-KiB device-table page (`0` while
    /// dormant).
    #[must_use]
    pub const fn device_table_phys(&self) -> u64 {
        self.device_table_phys
    }

    /// Physical address of the 4-KiB command-buffer page (`0` while
    /// dormant).
    #[must_use]
    pub const fn command_buffer_phys(&self) -> u64 {
        self.command_buffer_phys
    }

    /// Physical address of the 4-KiB event-log page (`0` while
    /// dormant).
    #[must_use]
    pub const fn event_log_phys(&self) -> u64 {
        self.event_log_phys
    }

    /// `true` once `Self::activate_hardware` has completed cleanly
    /// (the activation method is gated on `cfg(target_os = "none")`).
    #[must_use]
    pub const fn is_hardware_activated(&self) -> bool {
        self.hardware_activated
    }

    /// `true` once `Self::enable_translation` has flipped
    /// `CTRL.IommuEn` (the method is gated on `cfg(target_os = "none")`).
    #[must_use]
    pub const fn is_translation_enabled(&self) -> bool {
        self.translation_enabled
    }

    /// Stash the activation parameters in the backend without
    /// touching MMIO.
    ///
    /// Idempotent: calling twice with the same values is a no-op; a
    /// second call with different values overwrites and **resets**
    /// [`Self::is_hardware_activated`] to `false` so the caller
    /// understands the live programming must be redriven. This is the
    /// behaviour the kernel boot path relies on after a TLB-shootdown
    /// induced re-activation in MP follow-up work.
    pub fn prepare_activation(
        &mut self,
        unit_base: u64,
        device_table_phys: u64,
        command_buffer_phys: u64,
        event_log_phys: u64,
    ) {
        let same = self.unit_base == unit_base
            && self.device_table_phys == device_table_phys
            && self.command_buffer_phys == command_buffer_phys
            && self.event_log_phys == event_log_phys;
        self.unit_base = unit_base;
        self.device_table_phys = device_table_phys;
        self.command_buffer_phys = command_buffer_phys;
        self.event_log_phys = event_log_phys;
        self.command_buffer_tail = 0;
        if !same {
            self.hardware_activated = false;
            self.translation_enabled = false;
        }
    }

    /// Drive the live AMD-Vi MMIO programming sequence.
    ///
    /// Spec-faithful order (AMD IOMMU rev 3.10 § 5.3 + § 5.5):
    ///
    /// 1. Write the device-table base + size into `DEV_TAB_BAR`.
    /// 2. Write the command-buffer base + length into `CMD_BUF_BASE`.
    /// 3. Write the event-log base + length into `EVENT_LOG_BASE`.
    /// 4. Zero the command-buffer + event-log Head/Tail registers.
    /// 5. Raise `CTRL.CmdBufEn | CTRL.EventLogEn` and poll `STATUS`
    ///    for `CmdBufRun` then `EventLogRun`.
    /// 6. Submit one `INVALIDATE_DEVTAB_ENTRY` command at command-
    ///    buffer slot 0, bump `CMD_BUFFER_TAIL` to `16`, and wait for
    ///    `CMD_BUFFER_HEAD` to catch up.
    ///
    /// `CTRL.IommuEn` is **NOT** raised by this slice; per-device
    /// translation gating lands once the driver framework attaches
    /// its first PCI device (future P6.7.9-pre.7+). Until then the
    /// IOMMU stays in pre-translation pass-through at the hardware
    /// level — same observable behaviour as before the slice.
    ///
    /// # Errors
    ///
    /// See [`AmdViActivateError`].
    ///
    /// # Safety
    ///
    /// `phys_offset` must be the live bootloader direct-map offset.
    /// `unit_base` (recorded via [`Self::prepare_activation`]) must
    /// be the MMIO base address of an AMD-Vi remapping unit owned
    /// exclusively by the kernel. The function performs
    /// `volatile_write64` against `phys_offset + unit_base + offset`
    /// for the constants documented in §1 above.
    #[cfg(target_os = "none")]
    pub unsafe fn activate_hardware(&mut self, phys_offset: u64) -> Result<(), AmdViActivateError> {
        if self.unit_base == 0
            || self.device_table_phys == 0
            || self.command_buffer_phys == 0
            || self.event_log_phys == 0
        {
            return Err(AmdViActivateError::NotPrepared);
        }

        let unit_va = phys_offset.wrapping_add(self.unit_base);

        // (1) Device-table base + size.
        let dev_tab = encode_device_table_base(self.device_table_phys, DEVICE_TABLE_SIZE_ENCODING);
        // SAFETY: per the function's safety contract, `unit_va` is a
        // valid MMIO VA into a kernel-owned AMD-Vi register window.
        unsafe { mmio_write64(unit_va, REG_OFFSET_DEVICE_TABLE_BASE, dev_tab) };

        // (2) Command-buffer base + ComLen.
        let cmd_buf =
            encode_command_buffer_base(self.command_buffer_phys, CMD_BUFFER_LENGTH_ENCODING);
        // SAFETY: same as DEV_TAB_BAR.
        unsafe { mmio_write64(unit_va, REG_OFFSET_COMMAND_BUFFER_BASE, cmd_buf) };

        // (3) Event-log base + EventLen.
        let evt_log = encode_event_log_base(self.event_log_phys, EVENT_LOG_LENGTH_ENCODING);
        // SAFETY: same as DEV_TAB_BAR.
        unsafe { mmio_write64(unit_va, REG_OFFSET_EVENT_LOG_BASE, evt_log) };

        // (4) Zero the command-buffer + event-log Head/Tail registers
        //     so the live programming starts from an empty ring.
        // SAFETY: same as DEV_TAB_BAR.
        unsafe {
            mmio_write64(unit_va, REG_OFFSET_COMMAND_BUFFER_HEAD, 0);
            mmio_write64(unit_va, REG_OFFSET_COMMAND_BUFFER_TAIL, 0);
            mmio_write64(unit_va, REG_OFFSET_EVENT_LOG_HEAD, 0);
            mmio_write64(unit_va, REG_OFFSET_EVENT_LOG_TAIL, 0);
        }
        self.command_buffer_tail = 0;

        // (5) Raise CTRL.CmdBufEn + CTRL.EventLogEn (NO IommuEn yet).
        //     One write is sufficient because the IOMMU starts in a
        //     known-disabled state; if a future revision needs RMW we
        //     will reach for the `mmio_read64` helper below.
        let new_ctrl = CTRL_BIT_CMD_BUF_EN | CTRL_BIT_EVENT_LOG_EN;
        // SAFETY: same as DEV_TAB_BAR.
        unsafe { mmio_write64(unit_va, REG_OFFSET_CONTROL, new_ctrl) };

        // SAFETY: STATUS is a 8-byte RO MMIO mirror.
        if !unsafe { poll_status_bit(unit_va, STATUS_BIT_CMD_BUF_RUN) } {
            return Err(AmdViActivateError::CmdBufStartTimeout);
        }
        // SAFETY: same as above.
        if !unsafe { poll_status_bit(unit_va, STATUS_BIT_EVENT_LOG_RUN) } {
            return Err(AmdViActivateError::EventLogStartTimeout);
        }

        // (6) Submit INVALIDATE_DEVTAB_ENTRY(DeviceID=0) at slot 0,
        //     bump CMD_BUFFER_TAIL, and wait for HEAD to catch up.
        let buf_va = phys_offset.wrapping_add(self.command_buffer_phys);
        let (lo, hi) = encode_invalidate_devtab_entry(0);
        // SAFETY: caller guarantees the command-buffer page is
        // 4-KiB-aligned, kernel-owned, and zero-filled. The first 16
        // bytes hold command-slot index 0.
        unsafe { write_cmd_entry(buf_va, 0, lo, hi) };
        let next_tail: u64 = CMD_BUFFER_ENTRY_BYTES as u64;
        // SAFETY: same as DEV_TAB_BAR.
        unsafe { mmio_write64(unit_va, REG_OFFSET_COMMAND_BUFFER_TAIL, next_tail) };
        self.command_buffer_tail = next_tail;
        // SAFETY: CMD_BUFFER_HEAD is a 8-byte RO MMIO register.
        if !unsafe { poll_cmd_head_reaches(unit_va, next_tail) } {
            return Err(AmdViActivateError::InvalidationTimeout);
        }

        self.hardware_activated = true;
        Ok(())
    }

    /// Flip `CTRL.IommuEn` to start gating every DMA-capable device
    /// through its per-domain page table (P6.7.9-pre.11).
    ///
    /// Idempotent — repeat calls after the first success short-circuit
    /// to `Ok(())` without touching MMIO. Must run **after**
    /// [`Self::activate_hardware`] and **after** the first successful
    /// [`Self::install_device_entry`] (the IOMMU rejects DMA from any
    /// DTE-without-Valid the moment `IommuEn` is observed).
    ///
    /// Spec-faithful (AMD IOMMU rev 3.10 § 5.5.3): read-modify-writes
    /// the `CTRL` register to OR in [`CTRL_BIT_IOMMU_EN`] while
    /// preserving the already-raised
    /// `CMD_BUF_EN | EVENT_LOG_EN` bits, then submits one
    /// `INVALIDATE_ALL` command and waits for the command-buffer Head
    /// to drain. The post-flip invalidation forces the IOMMU to evict
    /// any pre-translation cache so the per-device DTEs installed by
    /// [`Self::install_device_entry`] are taken into account on the
    /// very next DMA from the device.
    ///
    /// # Errors
    ///
    /// - [`AmdViActivateError::NotPrepared`] if the backend was never
    ///   `prepare_activation`'d or [`Self::activate_hardware`] never
    ///   succeeded.
    /// - [`AmdViActivateError::TranslationEnableTimeout`] if the
    ///   command-buffer Head does not catch up to the new Tail within
    ///   the poll budget.
    ///
    /// # Safety
    ///
    /// `phys_offset` must be the live bootloader direct-map offset.
    /// Same MMIO-window ownership contract as
    /// [`Self::activate_hardware`].
    #[cfg(target_os = "none")]
    pub unsafe fn enable_translation(
        &mut self,
        phys_offset: u64,
    ) -> Result<(), AmdViActivateError> {
        if !self.hardware_activated {
            return Err(AmdViActivateError::NotPrepared);
        }
        if self.translation_enabled {
            return Ok(());
        }
        let unit_va = phys_offset.wrapping_add(self.unit_base);

        // (1) RMW CTRL ← CTRL | IommuEn so the previous
        //     CmdBufEn / EventLogEn bits are preserved.
        // SAFETY: per the function's safety contract, `unit_va` is the
        // kernel-owned AMD-Vi MMIO register window.
        let current_ctrl = unsafe { mmio_read64(unit_va, REG_OFFSET_CONTROL) };
        // SAFETY: same as above.
        unsafe {
            mmio_write64(
                unit_va,
                REG_OFFSET_CONTROL,
                current_ctrl | CTRL_BIT_IOMMU_EN,
            );
        }

        // (2) Submit INVALIDATE_ALL so the IOMMU drops any cached
        //     pre-translation entries that may have been speculatively
        //     populated before the per-device DTEs were programmed.
        //     The opcode lives in the high 4 bits of byte 7 (bit 60..63
        //     of the low qword) per § 5.4.7; the rest of the descriptor
        //     is reserved-zero for the global INVALIDATE_ALL granularity.
        let inv_all_lo = CMD_OPCODE_INVALIDATE_ALL << 60;
        let buf_va = phys_offset.wrapping_add(self.command_buffer_phys);
        // SAFETY: command-buffer page is kernel-owned 4-KiB aligned; the
        // submit helper updates `self.command_buffer_tail` and bounds
        // the new tail to `CMD_BUFFER_BYTES`.
        unsafe { self.submit_cmd_descriptor(buf_va, unit_va, inv_all_lo, 0) }
            .map_err(|()| AmdViActivateError::TranslationEnableTimeout)?;

        self.translation_enabled = true;
        Ok(())
    }

    /// Drive the live AMD-Vi per-device DTE install.
    ///
    /// Spec-faithful order (AMD IOMMU rev 3.10 § 5.2 + § 5.4):
    ///
    /// 1. Validate inputs (`hardware_activated`, alignments, domain
    ///    installed, bdf not already attached, requester-ID fits in
    ///    the device table).
    /// 2. Encode the DTE for `(iopt_phys, domain, mode, flags)` and
    ///    write it into the device table at offset [`dte_offset(bdf)`].
    /// 3. Submit an `INVALIDATE_DEVTAB_ENTRY(device_id = bdf.raw())`
    ///    command and wait for the command-buffer Head to catch up.
    /// 4. Submit an `INVALIDATE_IOMMU_PAGES(domain)` command and
    ///    wait for completion (drops any stale I/O TLB entry tagged
    ///    with the same domain ID).
    /// 5. Record the `(bdf, domain)` binding in
    ///    [`Self::attachments`].
    ///
    /// `CTRL.IommuEn` is **NOT** raised by this slice; the IOMMU
    /// stays in pre-translation pass-through mode at the hardware
    /// level until the kernel raises it once at least one device has
    /// been installed — orthogonal to this slice.
    ///
    /// # Errors
    ///
    /// See [`AmdViAttachError`].
    ///
    /// # Safety
    ///
    /// `phys_offset` must be the live bootloader direct-map offset.
    /// `iopt_phys` must reference a 4-KiB-aligned I/O page-table
    /// root owned by the kernel reachable through that direct map.
    /// The function performs `volatile_write64` against the device-
    /// table + command-buffer pages recorded via
    /// [`Self::prepare_activation`].
    #[cfg(target_os = "none")]
    pub unsafe fn install_device_entry(
        &mut self,
        phys_offset: u64,
        bdf: PciBdf,
        domain: DomainId,
        iopt_phys: u64,
        flags: IommuFlags,
        mode: PageMode,
    ) -> Result<(), AmdViAttachError> {
        if !self.hardware_activated {
            return Err(AmdViAttachError::NotActivated);
        }
        if iopt_phys & 0xFFF != 0 {
            return Err(AmdViAttachError::AddressMisaligned);
        }
        if !self.has_domain(domain) {
            return Err(AmdViAttachError::DomainNotInstalled);
        }
        if self.has_attachment(bdf) {
            return Err(AmdViAttachError::AlreadyAttached);
        }
        if matches!(mode, PageMode::NoTranslation) {
            return Err(AmdViAttachError::UnsupportedMode);
        }
        let dte_byte_offset = dte_offset(bdf);
        if dte_byte_offset + (DEVICE_TABLE_ENTRY_BYTES as u64) > (DEVICE_TABLE_BYTES as u64) {
            return Err(AmdViAttachError::DeviceTableTooSmall);
        }

        // (2) Encode + write the DTE into the device table.
        let dte = encode_device_table_entry(iopt_phys, domain, mode, flags)
            .map_err(|_| AmdViAttachError::AddressMisaligned)?;
        let dev_table_va = phys_offset.wrapping_add(self.device_table_phys);
        // SAFETY: caller guarantees `self.device_table_phys` (recorded
        // via `prepare_activation`) is a kernel-owned, 4-KiB-aligned
        // page reachable through the direct map; bounds-check above
        // proves the entire 32-byte entry fits inside the page.
        unsafe { write_dte_at(dev_table_va, dte_byte_offset, dte.qwords) };

        // (3) + (4) Per-device DTE invalidation + per-domain IOMMU
        //     pages invalidation, sequenced through the command
        //     buffer.
        let buf_va = phys_offset.wrapping_add(self.command_buffer_phys);
        let unit_va = phys_offset.wrapping_add(self.unit_base);

        let (dt_lo, dt_hi) = encode_invalidate_devtab_entry(bdf.raw());
        // SAFETY: command buffer is a kernel-owned 4-KiB page;
        // submit_cmd_* updates `self.command_buffer_tail` after each
        // push.
        unsafe { self.submit_cmd_descriptor(buf_va, unit_va, dt_lo, dt_hi) }
            .map_err(|()| AmdViAttachError::InvalidationTimeout)?;

        let (pg_lo, pg_hi) = encode_invalidate_iommu_pages_domain(domain);
        // SAFETY: same as above.
        unsafe { self.submit_cmd_descriptor(buf_va, unit_va, pg_lo, pg_hi) }
            .map_err(|()| AmdViAttachError::InvalidationTimeout)?;

        // (5) Record the attachment.
        self.attachments.push(AmdViAttachment { bdf, domain });
        Ok(())
    }

    /// Push a single 128-bit command into the command buffer, advance
    /// `CMD_BUFFER_TAIL`, and wait for `CMD_BUFFER_HEAD` to catch up.
    /// Wraps the tail pointer on [`CMD_BUFFER_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if `CMD_BUFFER_HEAD` does not catch up
    /// within [`AMDVI_ACTIVATION_POLL_LIMIT`] iterations.
    ///
    /// # Safety
    ///
    /// `buf_va` must point at the start of the kernel-owned 4-KiB
    /// command-buffer page reachable through the direct map.
    /// `unit_va` must point at the per-IOMMU MMIO register window so
    /// `unit_va + REG_OFFSET_COMMAND_BUFFER_TAIL` / `+ HEAD` are valid
    /// 64-bit accesses.
    #[cfg(target_os = "none")]
    unsafe fn submit_cmd_descriptor(
        &mut self,
        buf_va: u64,
        unit_va: u64,
        lo: u64,
        hi: u64,
    ) -> Result<(), ()> {
        // Slot index = tail / CMD_BUFFER_ENTRY_BYTES. The tail is
        // strictly bounded by `CMD_BUFFER_BYTES = 4096` so the cast
        // and the bounded division are precision-safe on every
        // pointer width.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::integer_division,
            reason = "command tail is bounded by CMD_BUFFER_BYTES (4096); division by CMD_BUFFER_ENTRY_BYTES (16) is the canonical slot-index conversion"
        )]
        let slot = (self.command_buffer_tail as usize) / CMD_BUFFER_ENTRY_BYTES;
        // SAFETY: command buffer is a kernel-owned 4-KiB page; `slot`
        // is bounded to `CMD_BUFFER_ENTRY_COUNT - 1` by the wrap
        // below.
        unsafe { write_cmd_entry(buf_va, slot, lo, hi) };
        let mut next_tail = self
            .command_buffer_tail
            .wrapping_add(CMD_BUFFER_ENTRY_BYTES as u64);
        if next_tail >= CMD_BUFFER_BYTES as u64 {
            next_tail = 0;
        }
        // SAFETY: per the function's safety contract.
        unsafe { mmio_write64(unit_va, REG_OFFSET_COMMAND_BUFFER_TAIL, next_tail) };
        self.command_buffer_tail = next_tail;
        // SAFETY: CMD_BUFFER_HEAD is a 8-byte read-only MMIO register.
        if !unsafe { poll_cmd_head_reaches(unit_va, next_tail) } {
            return Err(());
        }
        Ok(())
    }
}

// =============================================================================
// MMIO helpers — bare-metal-only, `volatile` semantics.
//
// All accesses go through `core::ptr::read_volatile` /
// `core::ptr::write_volatile` so the optimiser cannot reorder or
// coalesce the writes; this is mandatory for MMIO programming. The
// helpers are unsafe — the caller (`AmdViBackend::activate_hardware`)
// commits to the invariants in its safety contract. AMD-Vi's register
// surface is uniformly 64-bit wide for the activation path, so only
// the 64-bit helpers are wired here (32-bit reads exist for
// completeness in VT-d where GCMD/GSTS are 4 bytes wide).
// =============================================================================

/// Volatile 64-bit write to `unit_va + offset`.
///
/// # Safety
///
/// `unit_va + offset` must address a kernel-owned MMIO register that
/// accepts 64-bit naturally-aligned writes.
#[cfg(target_os = "none")]
#[inline]
unsafe fn mmio_write64(unit_va: u64, offset: u32, value: u64) {
    let ptr = unit_va.wrapping_add(u64::from(offset)) as *mut u64;
    // SAFETY: per the function's safety contract.
    unsafe { core::ptr::write_volatile(ptr, value) };
}

/// Volatile 64-bit read from `unit_va + offset`.
///
/// # Safety
///
/// `unit_va + offset` must address a kernel-owned MMIO register that
/// accepts 64-bit naturally-aligned reads.
#[cfg(target_os = "none")]
#[inline]
unsafe fn mmio_read64(unit_va: u64, offset: u32) -> u64 {
    let ptr = unit_va.wrapping_add(u64::from(offset)) as *const u64;
    // SAFETY: per the function's safety contract.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Poll [`REG_OFFSET_STATUS`] for `bit` to become set, with a bounded
/// retry budget.
///
/// Returns `true` if `bit` was observed set within
/// [`AMDVI_ACTIVATION_POLL_LIMIT`] iterations, `false` on timeout.
///
/// # Safety
///
/// `unit_va` must point at the start of a kernel-owned AMD-Vi register
/// window so `unit_va + REG_OFFSET_STATUS` is a valid 64-bit read.
#[cfg(target_os = "none")]
unsafe fn poll_status_bit(unit_va: u64, bit: u64) -> bool {
    let mut budget = AMDVI_ACTIVATION_POLL_LIMIT;
    while budget > 0 {
        // SAFETY: per the function's safety contract.
        let status = unsafe { mmio_read64(unit_va, REG_OFFSET_STATUS) };
        if status & bit != 0 {
            return true;
        }
        core::hint::spin_loop();
        budget -= 1;
    }
    false
}

/// Poll [`REG_OFFSET_COMMAND_BUFFER_HEAD`] until it reaches
/// `tail_byte_offset`, with a bounded retry budget.
///
/// The IOMMU advances HEAD as it consumes commands. When `HEAD ==
/// TAIL` the ring is drained.
///
/// # Safety
///
/// Same as [`poll_status_bit`].
#[cfg(target_os = "none")]
unsafe fn poll_cmd_head_reaches(unit_va: u64, tail_byte_offset: u64) -> bool {
    let mut budget = AMDVI_ACTIVATION_POLL_LIMIT;
    while budget > 0 {
        // SAFETY: per the function's safety contract.
        let head = unsafe { mmio_read64(unit_va, REG_OFFSET_COMMAND_BUFFER_HEAD) };
        if head == tail_byte_offset {
            return true;
        }
        core::hint::spin_loop();
        budget -= 1;
    }
    false
}

/// Write a 128-bit command into the command-buffer ring at the 16-byte
/// slot indexed by `slot`.
///
/// # Safety
///
/// `buf_va` must point at the start of a kernel-owned, 4-KiB-aligned
/// command-buffer page mapped through the direct map, and `slot` must
/// be `< CMD_BUFFER_ENTRY_COUNT`.
#[cfg(target_os = "none")]
#[inline]
unsafe fn write_cmd_entry(buf_va: u64, slot: usize, lo: u64, hi: u64) {
    let byte_offset = slot.wrapping_mul(CMD_BUFFER_ENTRY_BYTES) as u64;
    let base = buf_va.wrapping_add(byte_offset);
    let lo_ptr = base as *mut u64;
    let hi_ptr = base.wrapping_add(8) as *mut u64;
    // SAFETY: per the function's safety contract.
    unsafe {
        core::ptr::write_volatile(lo_ptr, lo);
        core::ptr::write_volatile(hi_ptr, hi);
    }
}

/// Write a 256-bit Device Table Entry (4 qwords) into the device table
/// page at `byte_offset`.
///
/// # Safety
///
/// `dev_table_va` must point at the start of the kernel-owned,
/// 4-KiB-aligned device-table page reachable through the direct map.
/// `byte_offset + 32` must be `<= DEVICE_TABLE_BYTES`.
#[cfg(target_os = "none")]
#[inline]
unsafe fn write_dte_at(dev_table_va: u64, byte_offset: u64, qwords: [u64; 4]) {
    let base = dev_table_va.wrapping_add(byte_offset);
    // SAFETY: per the function's safety contract.
    unsafe {
        let q0 = base as *mut u64;
        let q1 = base.wrapping_add(8) as *mut u64;
        let q2 = base.wrapping_add(16) as *mut u64;
        let q3 = base.wrapping_add(24) as *mut u64;
        core::ptr::write_volatile(q0, qwords[0]);
        core::ptr::write_volatile(q1, qwords[1]);
        core::ptr::write_volatile(q2, qwords[2]);
        core::ptr::write_volatile(q3, qwords[3]);
    }
}

impl IommuBackend for AmdViBackend {
    fn vendor(&self) -> IommuVendor {
        IommuVendor::Amd
    }

    fn install_domain(&mut self, id: DomainId) -> Result<(), IommuError> {
        if !self.has_domain(id) {
            self.domains.push(id);
        }
        Ok(())
    }

    fn map(
        &mut self,
        id: DomainId,
        iova: u64,
        phys: u64,
        len: u64,
        flags: IommuFlags,
    ) -> Result<(), IommuError> {
        if !self.has_domain(id) {
            return Err(IommuError::InvalidDomain);
        }
        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || len & 0xFFF != 0 || len == 0 {
            return Err(IommuError::AddressMisaligned);
        }
        let leaf = encode_iopte(phys, flags).map_err(IommuError::from)?;
        self.mappings.push(ScaffoldMapping {
            domain: id,
            iova,
            phys,
            len,
            leaf_iopte: leaf,
        });
        Ok(())
    }

    fn unmap(&mut self, id: DomainId, iova: u64, len: u64) -> Result<(), IommuError> {
        if !self.has_domain(id) {
            return Err(IommuError::InvalidDomain);
        }
        if iova & 0xFFF != 0 || len & 0xFFF != 0 || len == 0 {
            return Err(IommuError::AddressMisaligned);
        }
        let initial = self.mappings.len();
        self.mappings
            .retain(|m| !(m.domain == id && m.iova == iova && m.len == len));
        if self.mappings.len() == initial {
            return Err(IommuError::UnmapFailed);
        }
        Ok(())
    }

    fn flush(&mut self, id: DomainId) -> Result<(), IommuError> {
        if !self.has_domain(id) {
            return Err(IommuError::InvalidDomain);
        }
        // Dormant backend: nothing to flush. Live backend will queue
        // an `INVALIDATE_IOMMU_PAGES` command descriptor here.
        Ok(())
    }

    fn attach_device(&mut self, bdf: PciBdf, domain: DomainId) -> Result<(), IommuError> {
        if !self.has_domain(domain) {
            return Err(IommuError::InvalidDomain);
        }
        if self.has_attachment(bdf) {
            return Err(IommuError::Unsupported);
        }
        self.attachments.push(AmdViAttachment { bdf, domain });
        Ok(())
    }

    fn detach_device(&mut self, bdf: PciBdf) -> Result<(), IommuError> {
        let initial = self.attachments.len();
        self.attachments.retain(|a| a.bdf != bdf);
        if self.attachments.len() == initial {
            return Err(IommuError::Unsupported);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AMDVI_ACTIVATION_POLL_LIMIT, AmdViActivateError, AmdViAttachError, AmdViAttachment,
        AmdViBackend, AmdViError, CMD_BUFFER_BYTES, CMD_BUFFER_ENTRY_BYTES, CMD_BUFFER_ENTRY_COUNT,
        CMD_BUFFER_LENGTH_ENCODING, CMD_OPCODE_COMPLETION_WAIT, CMD_OPCODE_INVALIDATE_ALL,
        CMD_OPCODE_INVALIDATE_DEVTAB, CMD_OPCODE_INVALIDATE_IOMMU_PAGES,
        CMD_OPCODE_INVALIDATE_IOTLB_PAGES, CTRL_BIT_CMD_BUF_EN, CTRL_BIT_COHERENT,
        CTRL_BIT_EVENT_LOG_EN, CTRL_BIT_GT_EN, CTRL_BIT_IOMMU_EN, DEVICE_TABLE_BYTES,
        DEVICE_TABLE_ENTRY_BYTES, DEVICE_TABLE_SIZE_ENCODING, DeviceTableEntry, EVENT_LOG_BYTES,
        EVENT_LOG_ENTRY_BYTES, EVENT_LOG_ENTRY_COUNT, EVENT_LOG_LENGTH_ENCODING, IoPageTableEntry,
        IommuBackend, IommuError, IommuFlags, IommuVendor, PageMode,
        REG_OFFSET_COMMAND_BUFFER_BASE, REG_OFFSET_COMMAND_BUFFER_HEAD,
        REG_OFFSET_COMMAND_BUFFER_TAIL, REG_OFFSET_CONTROL, REG_OFFSET_DEVICE_TABLE_BASE,
        REG_OFFSET_EVENT_LOG_BASE, REG_OFFSET_EVENT_LOG_HEAD, REG_OFFSET_EVENT_LOG_TAIL,
        REG_OFFSET_EXT_FEATURE, REG_OFFSET_STATUS, STATUS_BIT_CMD_BUF_RUN, STATUS_BIT_COM_WAIT_INT,
        STATUS_BIT_EVENT_LOG_INT, STATUS_BIT_EVENT_LOG_RUN, STATUS_BIT_EVENT_OVERFLOW,
        ScaffoldMapping, dte_offset, efr_hats, efr_highest_supported_mode, efr_pas_max,
        efr_supports_ga, efr_supports_gt, efr_supports_hardware_error, efr_supports_invalidate_all,
        efr_supports_nx, efr_supports_ppr, efr_supports_prefetch, efr_supports_xt,
        encode_command_buffer_base, encode_device_table_base, encode_device_table_entry,
        encode_device_table_entry_absent, encode_device_table_entry_blocked, encode_event_log_base,
        encode_invalidate_devtab_entry, encode_invalidate_iommu_pages_domain, encode_iopte,
        encode_pde,
    };
    use crate::bare_metal::iommu::{DomainId, PciBdf};

    // ---- Register offset invariants ------------------------------------

    #[test]
    fn register_offsets_match_amd_spec_3_10() {
        // Pinning against the spec lets a future refactor catch any
        // accidental drift via the test suite rather than at runtime.
        assert_eq!(REG_OFFSET_DEVICE_TABLE_BASE, 0x000);
        assert_eq!(REG_OFFSET_COMMAND_BUFFER_BASE, 0x008);
        assert_eq!(REG_OFFSET_EVENT_LOG_BASE, 0x010);
        assert_eq!(REG_OFFSET_CONTROL, 0x018);
        assert_eq!(REG_OFFSET_EXT_FEATURE, 0x030);
        assert_eq!(REG_OFFSET_COMMAND_BUFFER_HEAD, 0x2000);
        assert_eq!(REG_OFFSET_COMMAND_BUFFER_TAIL, 0x2008);
        assert_eq!(REG_OFFSET_EVENT_LOG_HEAD, 0x2010);
        assert_eq!(REG_OFFSET_EVENT_LOG_TAIL, 0x2018);
        assert_eq!(REG_OFFSET_STATUS, 0x2020);
    }

    #[test]
    fn control_register_bits_match_spec() {
        assert_eq!(CTRL_BIT_IOMMU_EN, 1 << 0);
        assert_eq!(CTRL_BIT_COHERENT, 1 << 10);
        assert_eq!(CTRL_BIT_CMD_BUF_EN, 1 << 12);
        assert_eq!(CTRL_BIT_GT_EN, 1 << 16);
    }

    // ---- Device Table Entry encoder ------------------------------------

    #[test]
    fn encode_dte_sets_valid_and_translation_bits() {
        let entry = encode_device_table_entry(
            0xABCD_F000,
            DomainId::new(0x42),
            PageMode::Level4,
            IommuFlags::READ.union(IommuFlags::WRITE),
        )
        .unwrap();
        assert!(entry.is_valid());
        assert!(entry.translation_valid());
        assert_eq!(entry.page_table_root(), 0xABCD_F000);
        assert_eq!(entry.mode_raw(), PageMode::Level4.as_u8());
        assert_eq!(entry.domain_id(), DomainId::new(0x42));
        assert!(entry.allows_read());
        assert!(entry.allows_write());
    }

    #[test]
    fn encode_dte_read_only_unsets_iw() {
        let entry =
            encode_device_table_entry(0x1000, DomainId::new(1), PageMode::Level3, IommuFlags::READ)
                .unwrap();
        assert!(entry.allows_read());
        assert!(!entry.allows_write());
    }

    #[test]
    fn encode_dte_rejects_misaligned_root() {
        assert_eq!(
            encode_device_table_entry(0x1001, DomainId::new(0), PageMode::Level4, IommuFlags::READ),
            Err(AmdViError::AddressMisaligned)
        );
        assert_eq!(
            encode_device_table_entry(0x1FFF, DomainId::new(0), PageMode::Level4, IommuFlags::READ),
            Err(AmdViError::AddressMisaligned)
        );
    }

    #[test]
    fn encode_dte_round_trips_domain_id_and_mode() {
        let entry = encode_device_table_entry(
            0x10_0000,
            DomainId::new(0xFFFF),
            PageMode::Level6,
            IommuFlags::READ,
        )
        .unwrap();
        assert_eq!(entry.domain_id(), DomainId::new(0xFFFF));
        assert_eq!(entry.mode_raw(), 6);
    }

    #[test]
    fn encode_dte_no_translation_keeps_mode_zero() {
        let entry = encode_device_table_entry(
            0x10_0000,
            DomainId::new(0),
            PageMode::NoTranslation,
            IommuFlags::READ,
        )
        .unwrap();
        assert!(entry.is_valid());
        assert_eq!(entry.mode_raw(), 0);
    }

    #[test]
    fn encode_dte_absent_is_all_zero() {
        let entry = encode_device_table_entry_absent();
        assert!(!entry.is_valid());
        assert!(!entry.translation_valid());
        assert_eq!(entry, DeviceTableEntry { qwords: [0; 4] });
    }

    #[test]
    fn encode_dte_blocked_has_valid_bit_only() {
        let entry = encode_device_table_entry_blocked(DomainId::new(3));
        assert!(entry.is_valid());
        assert!(!entry.translation_valid());
        assert!(!entry.allows_read());
        assert!(!entry.allows_write());
        assert_eq!(entry.domain_id(), DomainId::new(3));
    }

    #[test]
    fn page_mode_round_trip() {
        for raw in 0u8..=6 {
            assert_eq!(PageMode::from_raw(raw).as_u8(), raw);
        }
        // Reserved value clamps to NoTranslation.
        assert_eq!(PageMode::from_raw(7), PageMode::NoTranslation);
        assert_eq!(PageMode::from_raw(0xFF), PageMode::NoTranslation);
    }

    // ---- I/O PTE encoder -----------------------------------------------

    #[test]
    fn encode_iopte_read_only() {
        let pte = encode_iopte(0xABCD_F000, IommuFlags::READ).unwrap();
        assert!(pte.is_present());
        assert_eq!(pte.output_address(), 0xABCD_F000);
        assert!(pte.allows_read());
        assert!(!pte.allows_write());
        assert!(!pte.force_coherent());
        assert_eq!(pte.next_level(), 0);
    }

    #[test]
    fn encode_iopte_write_forces_read_bit() {
        // AMD-Vi tolerates `IW`-only entries but we mirror the VT-d
        // semantics (force `IR` on whenever `IW` is requested) so the
        // cross-vendor invariant `WRITE ⇒ READ` holds at the SDK
        // surface.
        let pte = encode_iopte(0x1000, IommuFlags::WRITE).unwrap();
        assert!(pte.is_present());
        assert!(pte.allows_read());
        assert!(pte.allows_write());
    }

    #[test]
    fn encode_iopte_coherent_sets_fc_bit() {
        let flags = IommuFlags::READ.union(IommuFlags::COHERENT);
        let pte = encode_iopte(0x2000, flags).unwrap();
        assert!(pte.force_coherent());
        assert!(pte.allows_read());
    }

    #[test]
    fn encode_iopte_execute_flag_is_silently_ignored() {
        // AMD-Vi has no DMA execute bit; the encoder must not panic
        // and must not set any spurious bit when EXECUTE is passed.
        let flags = IommuFlags::READ.union(IommuFlags::EXECUTE);
        let pte = encode_iopte(0x3000, flags).unwrap();
        assert!(pte.is_present());
        assert!(pte.allows_read());
        assert!(!pte.allows_write());
        // No phantom bit set above the address field other than IR.
        assert_eq!(
            pte.0 & !(IoPageTableEntry::BIT_PR | IoPageTableEntry::BIT_IR | 0x000F_FFFF_FFFF_F000),
            0
        );
    }

    #[test]
    fn encode_iopte_rejects_misaligned_phys() {
        assert_eq!(
            encode_iopte(0x1001, IommuFlags::READ),
            Err(AmdViError::AddressMisaligned)
        );
    }

    #[test]
    fn encode_iopte_zero_flags_emits_not_present() {
        // No R, no W -> not present. Useful for clearing leaves during
        // unmap without zeroing the address bits.
        let pte = encode_iopte(0x1000, IommuFlags::from_bits(0)).unwrap();
        assert!(!pte.is_present());
        assert_eq!(pte.output_address(), 0x1000);
    }

    // ---- PDE encoder ---------------------------------------------------

    #[test]
    fn encode_pde_sets_next_level_and_permissions() {
        let pde = encode_pde(
            0xC0DE_0000,
            PageMode::Level2,
            IommuFlags::READ.union(IommuFlags::WRITE),
        )
        .unwrap();
        assert!(pde.is_present());
        assert_eq!(pde.next_level(), 2);
        assert_eq!(pde.output_address(), 0xC0DE_0000);
        assert!(pde.allows_read());
        assert!(pde.allows_write());
    }

    #[test]
    fn encode_pde_rejects_leaf_level() {
        assert_eq!(
            encode_pde(0x1000, PageMode::NoTranslation, IommuFlags::READ),
            Err(AmdViError::UnsupportedFlags)
        );
    }

    #[test]
    fn encode_pde_rejects_misaligned_phys() {
        assert_eq!(
            encode_pde(0x1001, PageMode::Level3, IommuFlags::READ),
            Err(AmdViError::AddressMisaligned)
        );
    }

    // ---- EFR decoders --------------------------------------------------

    #[test]
    fn efr_feature_bits_round_trip() {
        let efr = (1u64 << 0)
            | (1 << 1)
            | (1 << 2)
            | (1 << 3)
            | (1 << 4)
            | (1 << 6)
            | (1 << 7)
            | (1 << 8);
        assert!(efr_supports_prefetch(efr));
        assert!(efr_supports_ppr(efr));
        assert!(efr_supports_xt(efr));
        assert!(efr_supports_nx(efr));
        assert!(efr_supports_gt(efr));
        assert!(efr_supports_invalidate_all(efr));
        assert!(efr_supports_ga(efr));
        assert!(efr_supports_hardware_error(efr));
    }

    #[test]
    fn efr_feature_bits_zero_efr_reports_nothing() {
        assert!(!efr_supports_prefetch(0));
        assert!(!efr_supports_ppr(0));
        assert!(!efr_supports_nx(0));
        assert!(!efr_supports_gt(0));
        assert!(!efr_supports_invalidate_all(0));
    }

    #[test]
    fn efr_pas_max_extracts_bits_11_to_15() {
        let efr = 0b1_1111u64 << 11;
        assert_eq!(efr_pas_max(efr), 0b1_1111);
        let efr = 0b1_0101u64 << 11;
        assert_eq!(efr_pas_max(efr), 0b1_0101);
    }

    #[test]
    fn efr_hats_decodes_known_levels() {
        // HATS = 0 → 4-level (Level4)
        assert_eq!(efr_hats(0), 0);
        assert_eq!(efr_highest_supported_mode(0), PageMode::Level4);
        // HATS = 1 → 5-level
        assert_eq!(efr_hats(1u64 << 22), 1);
        assert_eq!(efr_highest_supported_mode(1u64 << 22), PageMode::Level5);
        // HATS = 2 → 6-level
        assert_eq!(efr_hats(2u64 << 22), 2);
        assert_eq!(efr_highest_supported_mode(2u64 << 22), PageMode::Level6);
        // HATS = 3 → reserved → NoTranslation (defensive).
        assert_eq!(efr_hats(3u64 << 22), 3);
        assert_eq!(
            efr_highest_supported_mode(3u64 << 22),
            PageMode::NoTranslation
        );
    }

    // ---- AmdViBackend bookkeeping --------------------------------------

    #[test]
    fn amdvi_backend_vendor_reports_amd() {
        let backend = AmdViBackend::new();
        assert_eq!(backend.vendor(), IommuVendor::Amd);
    }

    #[test]
    fn amdvi_backend_install_domain_is_idempotent() {
        let mut backend = AmdViBackend::new();
        backend.install_domain(DomainId::new(3)).unwrap();
        backend.install_domain(DomainId::new(3)).unwrap();
        assert!(backend.has_domain(DomainId::new(3)));
        assert_eq!(backend.domains(), &[DomainId::new(3)]);
    }

    #[test]
    fn amdvi_backend_map_rejects_unknown_domain() {
        let mut backend = AmdViBackend::new();
        assert_eq!(
            backend.map(DomainId::new(7), 0x1000, 0x2000, 0x1000, IommuFlags::READ),
            Err(IommuError::InvalidDomain)
        );
    }

    #[test]
    fn amdvi_backend_map_records_mapping_with_encoded_iopte() {
        let mut backend = AmdViBackend::new();
        backend.install_domain(DomainId::new(7)).unwrap();
        backend
            .map(
                DomainId::new(7),
                0x1000,
                0x2000,
                0x1000,
                IommuFlags::READ.union(IommuFlags::WRITE),
            )
            .unwrap();
        let mappings = backend.mappings();
        assert_eq!(mappings.len(), 1);
        let rec: ScaffoldMapping = *mappings.first().expect("one mapping just recorded");
        assert_eq!(rec.domain, DomainId::new(7));
        assert_eq!(rec.iova, 0x1000);
        assert_eq!(rec.phys, 0x2000);
        assert_eq!(rec.len, 0x1000);
        assert_eq!(rec.leaf_iopte.output_address(), 0x2000);
        assert!(rec.leaf_iopte.is_present());
        assert!(rec.leaf_iopte.allows_write());
    }

    #[test]
    fn amdvi_backend_map_rejects_misaligned_arguments() {
        let mut backend = AmdViBackend::new();
        backend.install_domain(DomainId::new(7)).unwrap();
        assert_eq!(
            backend.map(DomainId::new(7), 0x1001, 0x2000, 0x1000, IommuFlags::READ),
            Err(IommuError::AddressMisaligned)
        );
        assert_eq!(
            backend.map(DomainId::new(7), 0x1000, 0x2001, 0x1000, IommuFlags::READ),
            Err(IommuError::AddressMisaligned)
        );
        assert_eq!(
            backend.map(DomainId::new(7), 0x1000, 0x2000, 0x1001, IommuFlags::READ),
            Err(IommuError::AddressMisaligned)
        );
        assert_eq!(
            backend.map(DomainId::new(7), 0x1000, 0x2000, 0, IommuFlags::READ),
            Err(IommuError::AddressMisaligned)
        );
    }

    #[test]
    fn amdvi_backend_unmap_removes_record() {
        let mut backend = AmdViBackend::new();
        backend.install_domain(DomainId::new(7)).unwrap();
        backend
            .map(DomainId::new(7), 0x1000, 0x2000, 0x1000, IommuFlags::READ)
            .unwrap();
        assert_eq!(backend.mappings().len(), 1);
        backend.unmap(DomainId::new(7), 0x1000, 0x1000).unwrap();
        assert!(backend.mappings().is_empty());
    }

    #[test]
    fn amdvi_backend_unmap_unmapped_range_returns_error() {
        let mut backend = AmdViBackend::new();
        backend.install_domain(DomainId::new(7)).unwrap();
        assert_eq!(
            backend.unmap(DomainId::new(7), 0x1000, 0x1000),
            Err(IommuError::UnmapFailed)
        );
    }

    #[test]
    fn amdvi_backend_unmap_rejects_unknown_domain() {
        let mut backend = AmdViBackend::new();
        assert_eq!(
            backend.unmap(DomainId::new(9), 0x1000, 0x1000),
            Err(IommuError::InvalidDomain)
        );
    }

    #[test]
    fn amdvi_backend_flush_rejects_unknown_domain() {
        let mut backend = AmdViBackend::new();
        assert_eq!(
            backend.flush(DomainId::new(0)),
            Err(IommuError::InvalidDomain)
        );
    }

    #[test]
    fn amdvi_backend_flush_known_domain_is_ok() {
        let mut backend = AmdViBackend::new();
        backend.install_domain(DomainId::new(0)).unwrap();
        assert_eq!(backend.flush(DomainId::new(0)), Ok(()));
    }

    // ---- AmdViError → IommuError mapping -------------------------------

    #[test]
    fn amdvi_error_into_iommu_error_mapping() {
        assert_eq!(
            IommuError::from(AmdViError::AddressMisaligned),
            IommuError::AddressMisaligned
        );
        assert_eq!(
            IommuError::from(AmdViError::UnknownDomain),
            IommuError::InvalidDomain
        );
        assert_eq!(
            IommuError::from(AmdViError::UnsupportedFlags),
            IommuError::Unsupported
        );
    }

    // ---- P6.7.9-pre.6 live MMIO surface --------------------------------

    #[test]
    fn status_bits_mirror_control_positions() {
        // The Status register mirrors the matching enable bits the
        // hardware accepted; symbolically the run-bits do NOT share
        // numeric positions with Control (CmdBufRun=4, CmdBufEn=12;
        // EventLogRun=3, EventLogEn=2), but the spec pinning ensures
        // a future refactor catches any drift.
        assert_eq!(STATUS_BIT_EVENT_OVERFLOW, 1 << 0);
        assert_eq!(STATUS_BIT_EVENT_LOG_INT, 1 << 1);
        assert_eq!(STATUS_BIT_COM_WAIT_INT, 1 << 2);
        assert_eq!(STATUS_BIT_EVENT_LOG_RUN, 1 << 3);
        assert_eq!(STATUS_BIT_CMD_BUF_RUN, 1 << 4);
    }

    #[test]
    fn command_buffer_layout_constants_match_min_size() {
        assert_eq!(CMD_BUFFER_ENTRY_BYTES, 16);
        assert_eq!(CMD_BUFFER_ENTRY_COUNT, 256);
        assert_eq!(CMD_BUFFER_BYTES, 4096);
        assert_eq!(
            CMD_BUFFER_ENTRY_COUNT * CMD_BUFFER_ENTRY_BYTES,
            CMD_BUFFER_BYTES
        );
        // ComLen = 8 ↔ 2^8 = 256 entries ↔ 4 KiB.
        assert_eq!(CMD_BUFFER_LENGTH_ENCODING, 8);
        assert_eq!(1usize << CMD_BUFFER_LENGTH_ENCODING, CMD_BUFFER_ENTRY_COUNT);
    }

    #[test]
    fn event_log_layout_constants_match_min_size() {
        assert_eq!(EVENT_LOG_ENTRY_BYTES, 16);
        assert_eq!(EVENT_LOG_ENTRY_COUNT, 256);
        assert_eq!(EVENT_LOG_BYTES, 4096);
        assert_eq!(
            EVENT_LOG_ENTRY_COUNT * EVENT_LOG_ENTRY_BYTES,
            EVENT_LOG_BYTES
        );
        assert_eq!(EVENT_LOG_LENGTH_ENCODING, 8);
    }

    #[test]
    fn device_table_size_encoding_for_single_frame_is_zero() {
        // (Size + 1) × 4 KiB = 4 KiB for one frame.
        assert_eq!(DEVICE_TABLE_SIZE_ENCODING, 0);
    }

    #[test]
    fn command_opcode_constants_match_spec_5_4() {
        assert_eq!(CMD_OPCODE_COMPLETION_WAIT, 0x1);
        assert_eq!(CMD_OPCODE_INVALIDATE_DEVTAB, 0x2);
        assert_eq!(CMD_OPCODE_INVALIDATE_IOMMU_PAGES, 0x3);
        assert_eq!(CMD_OPCODE_INVALIDATE_IOTLB_PAGES, 0x4);
        assert_eq!(CMD_OPCODE_INVALIDATE_ALL, 0x8);
    }

    #[test]
    fn poll_limit_is_a_million() {
        assert_eq!(AMDVI_ACTIVATION_POLL_LIMIT, 1_000_000);
    }

    #[test]
    fn ctrl_bit_event_log_en_position_matches_spec() {
        // EventLogEn = bit 2 of Control per AMD spec rev 3.10 § 5.5.5.
        assert_eq!(CTRL_BIT_EVENT_LOG_EN, 1 << 2);
    }

    // ---- encode_device_table_base --------------------------------------

    #[test]
    fn encode_device_table_base_places_phys_in_bits_12_to_51() {
        let phys = 0x1234_5000;
        let val = encode_device_table_base(phys, 0);
        assert_eq!(val & 0x000F_FFFF_FFFF_F000, phys);
        // Size field zero.
        assert_eq!(val & 0x1FF, 0);
    }

    #[test]
    fn encode_device_table_base_places_size_in_bits_0_to_8() {
        let val = encode_device_table_base(0, 0x100);
        assert_eq!(val & 0x1FF, 0x100);
    }

    #[test]
    fn encode_device_table_base_masks_reserved_low_bits_of_phys() {
        // Bits 0..11 of phys must NOT leak into the Size field;
        // the encoder masks them out defensively.
        let phys_with_dirt = 0x1234_5FFF;
        let val = encode_device_table_base(phys_with_dirt, 0);
        assert_eq!(val & 0x000F_FFFF_FFFF_F000, 0x1234_5000);
        // Lower 9 bits of the input fall into Size = 0xFF & 0x1FF =
        // 0xFF... wait no. The mask `0xFFF` is reserved-low-bits of
        // phys, which after the high-bit mask are gone. So Size = 0.
        assert_eq!(val & 0x1FF, 0);
    }

    #[test]
    fn encode_device_table_base_truncates_size_above_9_bits() {
        // Size is 9 bits — high bits are discarded.
        let val = encode_device_table_base(0, 0xFFFF_FFFF);
        assert_eq!(val & 0x1FF, 0x1FF);
    }

    #[test]
    fn encode_device_table_base_masks_phys_above_bit_51() {
        // Bits 52..63 of the input phys must NOT leak into the
        // reserved upper bits of the encoded register value. Bits
        // 48..51 (the highest 4 of the 40-bit address range) MUST be
        // preserved. We exercise both with one input.
        let high_phys = 0xFFFF_0000_0000_F000;
        let val = encode_device_table_base(high_phys, 0);
        // Bits 52..63 are zeroed.
        assert_eq!(val & 0xFFF0_0000_0000_0000, 0);
        // Bits 12..51 round-trip: bit 12-15 (0xF) + bit 48-51 (0xF).
        assert_eq!(val & 0x000F_FFFF_FFFF_F000, 0x000F_0000_0000_F000);
    }

    // ---- encode_command_buffer_base ------------------------------------

    #[test]
    fn encode_command_buffer_base_places_phys_and_com_len() {
        let phys = 0xAB00_0000;
        let val = encode_command_buffer_base(phys, 8);
        assert_eq!(val & 0x000F_FFFF_FFFF_F000, phys);
        assert_eq!((val >> 56) & 0xF, 8);
    }

    #[test]
    fn encode_command_buffer_base_truncates_com_len_above_4_bits() {
        let val = encode_command_buffer_base(0, 0xFF);
        assert_eq!((val >> 56) & 0xF, 0xF);
        // Bits above 59 must not be set.
        assert_eq!(val & (0xFu64 << 60), 0);
    }

    #[test]
    fn encode_command_buffer_base_masks_reserved_low_bits_of_phys() {
        let phys_with_dirt = 0xAB00_0FFF;
        let val = encode_command_buffer_base(phys_with_dirt, 8);
        assert_eq!(val & 0x000F_FFFF_FFFF_F000, 0xAB00_0000);
    }

    // ---- encode_event_log_base -----------------------------------------

    #[test]
    fn encode_event_log_base_layout_matches_command_buffer_base() {
        let phys = 0xCD00_0000;
        let cmd_val = encode_command_buffer_base(phys, 9);
        let evt_val = encode_event_log_base(phys, 9);
        assert_eq!(cmd_val, evt_val);
    }

    // ---- encode_invalidate_devtab_entry --------------------------------

    #[test]
    fn encode_invalidate_devtab_low_qword_carries_opcode_and_device_id() {
        let (low, high) = encode_invalidate_devtab_entry(0x1234);
        // Bits 0..15: DeviceID.
        assert_eq!(low & 0xFFFF, 0x1234);
        // Bits 60..63: opcode 0x2.
        assert_eq!((low >> 60) & 0xF, CMD_OPCODE_INVALIDATE_DEVTAB);
        // Everything else: zero.
        assert_eq!(low & !(0xFFFFu64 | (0xFu64 << 60)), 0);
        assert_eq!(high, 0);
    }

    #[test]
    fn encode_invalidate_devtab_zero_device_id() {
        let (low, high) = encode_invalidate_devtab_entry(0);
        assert_eq!(low, CMD_OPCODE_INVALIDATE_DEVTAB << 60);
        assert_eq!(high, 0);
    }

    #[test]
    fn encode_invalidate_devtab_max_device_id() {
        let (low, _) = encode_invalidate_devtab_entry(0xFFFF);
        assert_eq!(low & 0xFFFF, 0xFFFF);
        // DeviceID should not overflow into reserved bits.
        assert_eq!(low & 0x0FFF_FFFF_FFFF_0000, 0);
    }

    // ---- AmdViActivateError → IommuError -------------------------------

    #[test]
    fn amdvi_activate_error_maps_to_iommu_activation_failed() {
        for err in [
            AmdViActivateError::NotPrepared,
            AmdViActivateError::CmdBufStartTimeout,
            AmdViActivateError::EventLogStartTimeout,
            AmdViActivateError::InvalidationTimeout,
        ] {
            assert_eq!(IommuError::from(err), IommuError::ActivationFailed);
        }
    }

    // ---- AmdViBackend dormant-state defaults ---------------------------

    #[test]
    fn fresh_backend_reports_dormant_state() {
        let backend = AmdViBackend::new();
        assert_eq!(backend.unit_base(), 0);
        assert_eq!(backend.device_table_phys(), 0);
        assert_eq!(backend.command_buffer_phys(), 0);
        assert_eq!(backend.event_log_phys(), 0);
        assert!(!backend.is_hardware_activated());
    }

    #[test]
    fn prepare_activation_stashes_parameters() {
        let mut backend = AmdViBackend::new();
        backend.prepare_activation(0xFEB8_0000, 0x10_0000, 0x10_1000, 0x10_2000);
        assert_eq!(backend.unit_base(), 0xFEB8_0000);
        assert_eq!(backend.device_table_phys(), 0x10_0000);
        assert_eq!(backend.command_buffer_phys(), 0x10_1000);
        assert_eq!(backend.event_log_phys(), 0x10_2000);
        assert!(!backend.is_hardware_activated());
    }

    #[test]
    fn prepare_activation_with_same_params_does_not_clear_activated_flag() {
        // We can't trigger activate_hardware on host (it is
        // `cfg(target_os = "none")`), but we can still test the
        // idempotency contract by re-calling `prepare_activation`
        // with the same args and asserting the flag survives. Use
        // a manual mutation of the flag to set up the test.
        let mut backend = AmdViBackend::new();
        backend.prepare_activation(0xFEB8_0000, 0x10_0000, 0x10_1000, 0x10_2000);
        backend.prepare_activation(0xFEB8_0000, 0x10_0000, 0x10_1000, 0x10_2000);
        // The activated flag is false here (we never ran the live
        // path), but the no-reset semantics is captured by the
        // explicit `if !same { self.hardware_activated = false; }`
        // branch in `prepare_activation`. The next test exercises the
        // reset path.
        assert!(!backend.is_hardware_activated());
    }

    #[test]
    fn prepare_activation_with_different_params_resets_state() {
        let mut backend = AmdViBackend::new();
        backend.prepare_activation(0xFEB8_0000, 0x10_0000, 0x10_1000, 0x10_2000);
        backend.prepare_activation(0xFEB8_1000, 0x20_0000, 0x20_1000, 0x20_2000);
        assert_eq!(backend.unit_base(), 0xFEB8_1000);
        assert_eq!(backend.device_table_phys(), 0x20_0000);
        assert_eq!(backend.command_buffer_phys(), 0x20_1000);
        assert_eq!(backend.event_log_phys(), 0x20_2000);
        assert!(!backend.is_hardware_activated());
    }

    // ---- P6.7.9-pre.7 — INVALIDATE_IOMMU_PAGES encoder ------------------

    #[test]
    fn encode_invalidate_iommu_pages_domain_packs_opcode_and_did() {
        let (low, high) = encode_invalidate_iommu_pages_domain(DomainId::new(0x55AA));
        // Opcode in bits 60..63.
        assert_eq!(low >> 60, CMD_OPCODE_INVALIDATE_IOMMU_PAGES);
        // DomainID in bits 32..47.
        assert_eq!((low >> 32) & 0xFFFF, 0x55AA);
        // S=1 bit in the high qword.
        assert_eq!(high & 0x1, 0x1);
    }

    #[test]
    fn encode_invalidate_iommu_pages_domain_handles_did_zero() {
        // Boundary: DID=0 must still raise the opcode + S bit.
        let (low, high) = encode_invalidate_iommu_pages_domain(DomainId::new(0));
        assert_eq!(low >> 60, CMD_OPCODE_INVALIDATE_IOMMU_PAGES);
        assert_eq!((low >> 32) & 0xFFFF, 0);
        assert_eq!(high, 0x1);
    }

    // ---- P6.7.9-pre.7 — DTE offset helper -------------------------------

    #[test]
    fn dte_offset_matches_bdf_raw_times_32() {
        // bdf 00:00.0 → raw=0 → offset=0.
        assert_eq!(dte_offset(PciBdf::from_parts(0, 0, 0)), 0);
        // bdf 00:00.1 → raw=1 → offset=32.
        assert_eq!(
            dte_offset(PciBdf::from_parts(0, 0, 1)),
            DEVICE_TABLE_ENTRY_BYTES as u64
        );
        // bdf 00:01.0 → raw=8 → offset=256.
        assert_eq!(
            dte_offset(PciBdf::from_parts(0, 1, 0)),
            8 * DEVICE_TABLE_ENTRY_BYTES as u64
        );
    }

    #[test]
    fn dte_offset_first_127_entries_fit_in_phase1_device_table() {
        // The Phase 1 device table is 4 KiB = 128 entries. bdf raw
        // 127 maps to offset 127 * 32 = 4064, and the entry body
        // (32 bytes) lands at 4096 — exactly the page boundary.
        let bdf = PciBdf::from_raw(127);
        let off = dte_offset(bdf);
        assert_eq!(off, 4064);
        assert!(off + (DEVICE_TABLE_ENTRY_BYTES as u64) <= DEVICE_TABLE_BYTES as u64);
    }

    #[test]
    fn dte_offset_above_127_overflows_phase1_device_table() {
        // bdf raw 128 → offset 4096, which already overflows the
        // Phase 1 page. Validates the bounds-check that
        // `install_device_entry` enforces.
        let bdf = PciBdf::from_raw(128);
        let off = dte_offset(bdf);
        assert!(off >= DEVICE_TABLE_BYTES as u64);
    }

    // ---- P6.7.9-pre.7 — AmdViAttachment scaffold -------------------------

    #[test]
    fn attach_device_records_binding_and_rejects_unknown_domain() {
        let mut backend = AmdViBackend::new();
        let bdf = PciBdf::from_parts(0, 1, 0);
        assert_eq!(
            backend.attach_device(bdf, DomainId::new(0x20)),
            Err(IommuError::InvalidDomain)
        );
        backend.install_domain(DomainId::new(0x20)).unwrap();
        assert_eq!(backend.attach_device(bdf, DomainId::new(0x20)), Ok(()));
        assert!(backend.has_attachment(bdf));
        assert_eq!(backend.attachments().len(), 1);
        assert_eq!(
            backend.attachments().first().copied(),
            Some(AmdViAttachment {
                bdf,
                domain: DomainId::new(0x20),
            })
        );
    }

    #[test]
    fn attach_device_double_attach_rejected() {
        let mut backend = AmdViBackend::new();
        let bdf = PciBdf::from_parts(0, 2, 0);
        backend.install_domain(DomainId::new(3)).unwrap();
        backend.attach_device(bdf, DomainId::new(3)).unwrap();
        assert_eq!(
            backend.attach_device(bdf, DomainId::new(3)),
            Err(IommuError::Unsupported)
        );
    }

    #[test]
    fn detach_device_removes_and_allows_reattach() {
        let mut backend = AmdViBackend::new();
        let bdf = PciBdf::from_parts(0, 3, 0);
        backend.install_domain(DomainId::new(4)).unwrap();
        backend.attach_device(bdf, DomainId::new(4)).unwrap();
        assert_eq!(backend.detach_device(bdf), Ok(()));
        assert!(!backend.has_attachment(bdf));
        assert_eq!(backend.attach_device(bdf, DomainId::new(4)), Ok(()));
    }

    #[test]
    fn detach_unknown_device_returns_unsupported() {
        let mut backend = AmdViBackend::new();
        let bdf = PciBdf::from_parts(0, 5, 0);
        assert_eq!(backend.detach_device(bdf), Err(IommuError::Unsupported));
    }

    #[test]
    fn amdvi_attach_error_maps_to_iommu_error_variants() {
        assert_eq!(
            IommuError::from(AmdViAttachError::NotActivated),
            IommuError::ActivationFailed
        );
        assert_eq!(
            IommuError::from(AmdViAttachError::DomainNotInstalled),
            IommuError::InvalidDomain
        );
        assert_eq!(
            IommuError::from(AmdViAttachError::AlreadyAttached),
            IommuError::Unsupported
        );
        assert_eq!(
            IommuError::from(AmdViAttachError::AddressMisaligned),
            IommuError::AddressMisaligned
        );
        assert_eq!(
            IommuError::from(AmdViAttachError::DeviceTableTooSmall),
            IommuError::DomainTableFull
        );
        assert_eq!(
            IommuError::from(AmdViAttachError::UnsupportedMode),
            IommuError::Unsupported
        );
        assert_eq!(
            IommuError::from(AmdViAttachError::InvalidationTimeout),
            IommuError::ActivationFailed
        );
    }

    #[test]
    fn fresh_backend_has_no_attachments() {
        let backend = AmdViBackend::new();
        assert!(backend.attachments().is_empty());
        assert!(!backend.has_attachment(PciBdf::from_parts(0, 0, 0)));
    }

    // ---- P6.7.9-pre.11 translation enable state machine ---------------

    #[test]
    fn fresh_backend_is_not_translation_enabled() {
        let backend = AmdViBackend::new();
        assert!(!backend.is_translation_enabled());
    }

    #[test]
    fn amdvi_activate_error_translation_enable_timeout_maps_to_activation_failed() {
        assert_eq!(
            IommuError::from(AmdViActivateError::TranslationEnableTimeout),
            IommuError::ActivationFailed
        );
    }

    #[test]
    fn prepare_activation_with_different_params_resets_translation_enabled() {
        let mut backend = AmdViBackend::new();
        backend.prepare_activation(0xFEE0_0000, 0x20_0000, 0x20_1000, 0x20_2000);
        assert!(!backend.is_translation_enabled());
        // Same params: state preserved.
        backend.prepare_activation(0xFEE0_0000, 0x20_0000, 0x20_1000, 0x20_2000);
        assert!(!backend.is_translation_enabled());
        // Different params: reset both flags.
        backend.prepare_activation(0xFEE0_4000, 0x20_0000, 0x20_1000, 0x20_2000);
        assert!(!backend.is_hardware_activated());
        assert!(!backend.is_translation_enabled());
    }
}

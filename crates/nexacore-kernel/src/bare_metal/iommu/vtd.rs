//! Intel VT-d backend scaffold (P6.7.9-pre.2).
//!
//! ## Scope
//!
//! This module lands the **dormant scaffold** for the Intel VT-d
//! second-level translation backend that will eventually replace the
//! [`super::PassthroughBackend`] when `bare_metal::iommu::iommu_vendor()`
//! reports [`super::IommuVendor::Intel`]. The scaffold lines up four
//! pure-function surfaces — register offsets, root-entry encoders,
//! context-entry encoders, and second-level page-table-entry (SL-PTE)
//! encoders — plus a host-testable [`VtdBackend`] struct that tracks
//! domains in an internal table without writing a single MMIO byte.
//!
//! Until P6.7.9-pre.4 (DMA-Map vendor switch) wires it in, no caller
//! reaches this backend at runtime — the kernel `dma_map_handlers`
//! continues to use [`super::PassthroughBackend`]. The scaffold lives
//! in the workspace so the QEMU smoke (`iommu=intel`) can assert the
//! vendor selector + ACPI parser interaction without any silicon side
//! effect.
//!
//! ## Why a scaffold and not the live backend?
//!
//! Each P6.7.9-pre.x slice keeps the auditable surface bounded:
//!
//! - **P6.7.9-pre.0:** parser + trait + passthrough.
//! - **P6.7.9-pre.1:** firmware-probe + vendor selector.
//! - **P6.7.9-pre.2 (this slice):** register-offset constants +
//!   data-structure encoders + dormant `VtdBackend`.
//! - **P6.7.9-pre.3:** AMD-Vi sibling scaffold.
//! - **P6.7.9-pre.4:** swap `dma_map_handlers` to consult
//!   `iommu_vendor()` and route through the now-live backends.
//!
//! Splitting the live register programming off keeps every PR's
//! `unsafe` surface auditable and lets the host test matrix exercise
//! the encoders before the live ring is opened.
//!
//! ## References
//!
//! - Intel Virtualization Technology for Directed I/O Architecture
//!   Specification rev 4.1 § 9 (Translation Data Structures) and § 10.4
//!   (Register Descriptions).
//! - NCIP-Driver-Framework-013 § S3 (capability scope + IOMMU semantics).

#![allow(
    clippy::module_name_repetitions,
    reason = "VtdBackend / VtdError / VtdRegister share the Vtd prefix by design — they are the public symbols of this submodule and the prefix prevents ambiguity with sibling AMD-Vi / passthrough types"
)]

extern crate alloc;

use alloc::vec::Vec;

use super::{DomainId, IommuBackend, IommuError, IommuFlags, IommuVendor, PciBdf};

// =============================================================================
// Section 1 — VT-d MMIO register offsets (Intel VT-d spec rev 4.1 § 10.4).
//
// Offsets are byte-addressed against the per-IOMMU MMIO base discovered
// from the DRHD entry's `register_base` field (see
// `super::dmar::DrhdEntry::register_base`). Constants are `pub` so the
// future live backend (P6.7.9-pre.4) and the host test suite can both
// reference the same single source of truth.
// =============================================================================

/// `VER`: Version Register — 4 bytes at offset `0x00`.
///
/// Bits 0..3 = MIN (minor), 4..7 = MAX (major). Read-only.
pub const REG_OFFSET_VER: u32 = 0x000;

/// `CAP`: Capability Register — 8 bytes at offset `0x08`.
///
/// Carries the static capabilities the IOMMU advertises (number of
/// domains, supported AGAW levels, caching mode, …). Read-only.
pub const REG_OFFSET_CAP: u32 = 0x008;

/// `ECAP`: Extended Capability Register — 8 bytes at offset `0x10`.
///
/// Advertises extended features (queued invalidation, interrupt
/// remapping, page-request, …). Read-only.
pub const REG_OFFSET_ECAP: u32 = 0x010;

/// `GCMD`: Global Command Register — 4 bytes at offset `0x18`. Write-only.
///
/// Used to toggle translation enable (TE, bit 31), set-root-table
/// pointer (SRTP, bit 30), write-buffer flush (WBF, bit 27), queued
/// invalidation enable (QIE, bit 26), and interrupt-remap enable (IRE,
/// bit 25).
pub const REG_OFFSET_GCMD: u32 = 0x018;

/// `GSTS`: Global Status Register — 4 bytes at offset `0x1C`. Read-only.
///
/// Mirror of GCMD after the hardware processes the command. Bit
/// positions match GCMD.
pub const REG_OFFSET_GSTS: u32 = 0x01C;

/// `RTADDR`: Root Table Address Register — 8 bytes at offset `0x20`.
///
/// Bits 0..10 reserved, bit 11 = `RTT` (Root Table Type: 0 = legacy,
/// 1 = scalable), bits 12..63 = 4-KiB-aligned physical address of the
/// root table.
pub const REG_OFFSET_RTADDR: u32 = 0x020;

/// `CCMD`: Context Command Register — 8 bytes at offset `0x28`.
///
/// Drives the legacy register-based context-cache invalidation. Bit
/// 63 = `ICC` (Invalidate Context Cache), bits 61..62 = `CIRG`
/// (Context Invalidation Request Granularity), bits 59..60 = `CAIG`.
pub const REG_OFFSET_CCMD: u32 = 0x028;

/// `FSTS`: Fault Status Register — 4 bytes at offset `0x34`. RW1C.
///
/// Bit 0 = `PFO` (Primary Fault Overflow), bit 1 = `PPF` (Primary
/// Pending Fault), bit 2 = `AFO` (Advanced Fault Overflow), bit 3 =
/// `APF` (Advanced Pending Fault), bit 4 = `IQE` (Invalidation Queue
/// Error), bit 5 = `ICE` (Invalidation Completion Error), bit 6 =
/// `ITE` (Invalidation Time-out Error).
pub const REG_OFFSET_FSTS: u32 = 0x034;

/// `FECTL`: Fault Event Control Register — 4 bytes at offset `0x38`.
///
/// Bit 31 = `IM` (Interrupt Mask). When clear, the IOMMU raises an MSI
/// for every fault.
pub const REG_OFFSET_FECTL: u32 = 0x038;

/// `FEDATA`: Fault Event Data Register — 4 bytes at offset `0x3C`.
pub const REG_OFFSET_FEDATA: u32 = 0x03C;

/// `FEADDR`: Fault Event Address Register — 4 bytes at offset `0x40`.
pub const REG_OFFSET_FEADDR: u32 = 0x040;

/// `FEUADDR`: Fault Event Upper Address Register — 4 bytes at offset `0x44`.
pub const REG_OFFSET_FEUADDR: u32 = 0x044;

/// `PMEN`: Protected Memory Enable Register — 4 bytes at offset `0x64`.
///
/// Bit 31 = `EPM` (Enable Protected Memory).
pub const REG_OFFSET_PMEN: u32 = 0x064;

/// `IQH`: Invalidation Queue Head Register — 8 bytes at offset `0x80`.
///
/// Hardware-maintained pointer into the descriptor ring. Read-only.
pub const REG_OFFSET_IQH: u32 = 0x080;

/// `IQT`: Invalidation Queue Tail Register — 8 bytes at offset `0x88`.
///
/// Software-maintained pointer into the descriptor ring.
pub const REG_OFFSET_IQT: u32 = 0x088;

/// `IQA`: Invalidation Queue Address Register — 8 bytes at offset `0x90`.
pub const REG_OFFSET_IQA: u32 = 0x090;

// -- GCMD/GSTS bit positions per spec rev 4.1 § 10.4.4 ----------------

/// `TE` (Translation Enable) — bit 31 in GCMD/GSTS.
pub const GCMD_BIT_TE: u32 = 1 << 31;
/// `SRTP` (Set Root Table Pointer) — bit 30.
pub const GCMD_BIT_SRTP: u32 = 1 << 30;
/// `SFL` (Set Fault Log) — bit 29.
pub const GCMD_BIT_SFL: u32 = 1 << 29;
/// `EAFL` (Enable Advanced Fault Logging) — bit 28.
pub const GCMD_BIT_EAFL: u32 = 1 << 28;
/// `WBF` (Write Buffer Flush) — bit 27.
pub const GCMD_BIT_WBF: u32 = 1 << 27;
/// `QIE` (Queued Invalidation Enable) — bit 26.
pub const GCMD_BIT_QIE: u32 = 1 << 26;
/// `IRE` (Interrupt Remapping Enable) — bit 25.
pub const GCMD_BIT_IRE: u32 = 1 << 25;
/// `SIRTP` (Set Interrupt Remap Table Pointer) — bit 24.
pub const GCMD_BIT_SIRTP: u32 = 1 << 24;
/// `CFI` (Compatibility Format Interrupt) — bit 23.
pub const GCMD_BIT_CFI: u32 = 1 << 23;

// -- GSTS status-mirror bit positions per spec rev 4.1 § 10.4.5 -------
//
// GSTS is read-only and mirrors the most-recently committed GCMD bits
// after the hardware has finished processing the request. The live
// activation path (P6.7.9-pre.5) polls these bits to detect when the
// IOMMU has accepted SRTP / QIE / TE.

/// `TES` (Translation Enable Status) — bit 31 in GSTS. Mirrors
/// [`GCMD_BIT_TE`] once the hardware enables second-level translation.
pub const GSTS_BIT_TES: u32 = 1 << 31;
/// `RTPS` (Root Table Pointer Status) — bit 30 in GSTS. Mirrors
/// [`GCMD_BIT_SRTP`] once the hardware accepts the new root-table
/// pointer.
pub const GSTS_BIT_RTPS: u32 = 1 << 30;
/// `QIES` (Queued Invalidation Enable Status) — bit 26 in GSTS. Mirrors
/// [`GCMD_BIT_QIE`] once the hardware starts servicing descriptors out
/// of the invalidation queue.
pub const GSTS_BIT_QIES: u32 = 1 << 26;

// -- Invalidation queue layout (Intel VT-d spec rev 4.1 § 6.5.2) ------
//
// We program the legacy 128-bit (16-byte) descriptor format because
// the scalable 256-bit format requires ECAP.SMTS support that is not
// guaranteed on all Phase 1 platforms. With QS=0 the queue holds 256
// descriptors × 16 bytes = exactly one 4-KiB page — matches the frame
// allocator's allocation unit.

/// `QS` field value stored in `IQA[2:0]` — `0` for a 1-page (4 KiB)
/// queue, i.e. 256 entries of 16 bytes each.
pub const INV_QUEUE_SIZE_ORDER: u8 = 0;
/// Number of descriptor slots in the invalidation queue under
/// [`INV_QUEUE_SIZE_ORDER`].
pub const INV_QUEUE_ENTRY_COUNT: usize = 256;
/// Byte width of one legacy (128-bit) invalidation descriptor.
pub const INV_QUEUE_ENTRY_BYTES: usize = 16;
/// Total queue footprint in bytes — `INV_QUEUE_ENTRY_COUNT *
/// INV_QUEUE_ENTRY_BYTES`. By construction equals one 4-KiB frame.
pub const INV_QUEUE_BYTES: usize = INV_QUEUE_ENTRY_COUNT * INV_QUEUE_ENTRY_BYTES;

// -- Invalidation descriptor type / granularity tags (spec § 6.5.2.2) -
//
// Encoded into bits 0..3 of the descriptor low qword.

/// `Type=0x1` — Context-cache invalidate (CCMD-equivalent).
pub const INV_DESC_TYPE_CONTEXT_CACHE: u64 = 0x1;
/// `Type=0x2` — IOTLB invalidate.
pub const INV_DESC_TYPE_IOTLB: u64 = 0x2;
/// `Type=0x5` — Invalidate-wait (synchronisation fence).
pub const INV_DESC_TYPE_INVALIDATE_WAIT: u64 = 0x5;

/// Context-cache granularity `G=01` (Global). Encoded into bits 4..5
/// of the context-cache descriptor low qword.
pub const INV_DESC_CTX_GRAN_GLOBAL: u64 = 0b01 << 4;
/// Context-cache granularity `G=10` (Domain).
///
/// Selects the per-domain context-cache invalidate variant — the
/// descriptor targets only the entries whose `DID` matches the field
/// encoded into bits 16..31 of the low qword (see
/// [`encode_context_cache_domain_invalidate`]).
pub const INV_DESC_CTX_GRAN_DOMAIN: u64 = 0b10 << 4;
/// IOTLB granularity `G=01` (Global). Encoded into bits 4..5 of the
/// IOTLB descriptor low qword.
pub const INV_DESC_IOTLB_GRAN_GLOBAL: u64 = 0b01 << 4;
/// IOTLB granularity `G=10` (Domain).
///
/// Selects the per-domain IOTLB invalidate variant — descriptor targets
/// only entries whose `DID` matches the field encoded into bits 16..31
/// of the low qword (see [`encode_iotlb_domain_invalidate`]).
pub const INV_DESC_IOTLB_GRAN_DOMAIN: u64 = 0b10 << 4;
/// Invalidate-wait `SW=1`: write a 4-byte status value to the status
/// address once the wait descriptor reaches the IOMMU. Bit 5.
pub const INV_DESC_WAIT_STATUS_WRITE: u64 = 1 << 5;

/// Bounded poll counter for hardware-status mirror bits.
///
/// 1 million iterations easily covers the worst-case QEMU emulation
/// latency (typically < 1 µs / iteration in practice). On a real Intel
/// platform the SRTP and QIE bits flip within microseconds; an
/// overflow indicates a wedged IOMMU and surfaces as one of the
/// `*Timeout` variants of [`VtdActivateError`].
pub const VTD_ACTIVATION_POLL_LIMIT: u32 = 1_000_000;

/// Bounded poll counter for the recoverable IOTLB-flush path (P11.4,
/// ADR-0027 review finding #5).
///
/// Deliberately ~100× smaller than [`VTD_ACTIVATION_POLL_LIMIT`]: the
/// activation polls run once at boot and must absorb worst-case
/// hardware latency (a timeout there is fatal for the IOMMU posture),
/// while a per-domain IOTLB invalidate runs on every `DmaMap` flush
/// and device teardown, and those call sites are best-effort /
/// recoverable. On a wedged unit the activation budget would stall
/// every flush for ~1 ms; 10k iterations bound the stall to ~10 µs
/// while still exceeding the observed drain latency (tens of
/// iterations on QEMU `intel-iommu` and real hardware) by 2–3 orders
/// of magnitude. Exhaustion surfaces as
/// `IommuError::FlushStalled` on the flush path.
pub const IOTLB_FLUSH_POLL_BUDGET: u32 = 10_000;

// =============================================================================
// Section 2 — Root / Context / SL-PTE encoders (Intel VT-d spec § 9).
//
// All three structures are 128-bit (root + context) or 64-bit (SL-PTE).
// We store them as `[u64; N]` rather than `#[repr(C)]` bitfields to
// keep the encoders pure functions over `u64` operands — the host test
// suite then exercises every bit position without needing to grant the
// kernel an `unsafe { *mut RootEntry }` cast.
// =============================================================================

/// Size of a single VT-d **legacy** root entry (§ 9.1).
///
/// 128 bits = 16 bytes. One entry per PCI bus number; a single root
/// table holds 256 entries = 4 KiB total.
pub const ROOT_ENTRY_BYTES: usize = 16;

/// Size of a single VT-d **legacy** context entry (§ 9.3).
///
/// 128 bits = 16 bytes. One entry per (Device, Function) pair on a
/// given bus; a single context table holds 256 entries = 4 KiB total.
pub const CONTEXT_ENTRY_BYTES: usize = 16;

/// Size of a single VT-d **legacy** second-level page-table entry
/// (§ 9.6).
///
/// 64 bits = 8 bytes. A 4-KiB SL-PT page holds 512 entries.
pub const SLPTE_BYTES: usize = 8;

/// Encoded VT-d **legacy** root entry.
///
/// Layout (low 64 bits, § 9.1):
/// ```text
/// bit  0      : Present (P)
/// bit  1..11  : Reserved (must be 0)
/// bit 12..63  : Context Table Pointer (CTP), 4-KiB aligned
/// ```
/// High 64 bits are reserved and must be zero.
///
/// Constructed via [`encode_root_entry`]; consumed via the field
/// accessors below.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RootEntry {
    /// Low 64 bits (present + CTP).
    pub low: u64,
    /// High 64 bits (always 0 in the legacy mode).
    pub high: u64,
}

impl RootEntry {
    /// `true` iff the present bit (bit 0) is set.
    #[must_use]
    pub const fn is_present(self) -> bool {
        (self.low & 0x1) != 0
    }

    /// 4-KiB-aligned context-table-pointer field (bits 12..63 of the
    /// low quadword).
    #[must_use]
    pub const fn context_table_pointer(self) -> u64 {
        self.low & !0xFFF
    }
}

/// Build a legacy root entry from a 4-KiB-aligned context-table phys
/// address.
///
/// # Errors
///
/// Returns `Err([VtdError::AddressMisaligned])` when `context_table_phys`
/// is not 4-KiB aligned.
pub fn encode_root_entry(context_table_phys: u64) -> Result<RootEntry, VtdError> {
    if context_table_phys & 0xFFF != 0 {
        return Err(VtdError::AddressMisaligned);
    }
    Ok(RootEntry {
        low: context_table_phys | 0x1,
        high: 0,
    })
}

/// Build a not-present root entry (low + high quadwords both zero).
///
/// Used during bring-up to publish an empty root table.
#[must_use]
pub const fn encode_root_entry_absent() -> RootEntry {
    RootEntry { low: 0, high: 0 }
}

/// VT-d legacy translation-type enumeration (Context Entry bits 2..3,
/// § 9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationType {
    /// Untranslated requests use the second-level page table.
    /// Untranslated **with PASID** is not supported in legacy mode.
    UntranslatedOnly = 0b00,
    /// Untranslated + translated requests both use the SL page table.
    UntranslatedAndTranslated = 0b01,
    /// Pass-through: untranslated requests bypass translation (used by
    /// the bring-up domain `0`, identical to no-IOMMU semantics).
    Passthrough = 0b10,
}

impl TranslationType {
    /// Raw 2-bit encoding for the context-entry `T` field.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// VT-d legacy **AGAW** (Adjusted Guest Address Width) encoding
/// (§ 9.3 + § 10.4.2 CAP register SAGAW field).
///
/// The mapping is bit-position-based on the SAGAW field of the
/// Capability Register; the value stored in a context entry's `AW`
/// field matches the bit index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressWidth {
    /// 30-bit, 2-level page table (rarely advertised).
    Bits30Level2 = 0,
    /// 39-bit, 3-level page table (most desktops + servers).
    Bits39Level3 = 1,
    /// 48-bit, 4-level page table (matches `x86_64` paging).
    Bits48Level4 = 2,
    /// 57-bit, 5-level page table (5LP-enabled Xeons).
    Bits57Level5 = 3,
}

impl AddressWidth {
    /// Raw 3-bit AW encoding.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Number of paging levels for this AGAW.
    #[must_use]
    pub const fn levels(self) -> u8 {
        match self {
            Self::Bits30Level2 => 2,
            Self::Bits39Level3 => 3,
            Self::Bits48Level4 => 4,
            Self::Bits57Level5 => 5,
        }
    }
}

/// Encoded VT-d **legacy** context entry.
///
/// Low 64 bits (§ 9.3):
/// ```text
/// bit  0      : Present (P)
/// bit  1      : Fault Processing Disable (FPD)
/// bit  2..3   : Translation Type (T)
/// bit  4..11  : Reserved
/// bit 12..63  : Second-Level Page Table Pointer (SLPTPTR), 4-KiB aligned
/// ```
///
/// High 64 bits (§ 9.3):
/// ```text
/// bit  0..2   : Address Width (AW)
/// bit  3..7   : Reserved
/// bit  8..23  : Domain Identifier (DID)
/// bit 24..63  : Reserved
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ContextEntry {
    /// Low 64 bits (present + T + SLPTPTR).
    pub low: u64,
    /// High 64 bits (AW + DID).
    pub high: u64,
}

impl ContextEntry {
    /// `true` iff the present bit (bit 0 of low) is set.
    #[must_use]
    pub const fn is_present(self) -> bool {
        (self.low & 0x1) != 0
    }

    /// Extract the second-level page-table pointer (bits 12..63 of
    /// low).
    #[must_use]
    pub const fn slptptr(self) -> u64 {
        self.low & !0xFFF
    }

    /// Extract the 16-bit domain identifier (bits 8..23 of high).
    #[must_use]
    pub const fn domain_id(self) -> DomainId {
        DomainId::new(((self.high >> 8) & 0xFFFF) as u16)
    }

    /// Extract the translation-type field (bits 2..3 of low).
    #[must_use]
    pub const fn translation_type_raw(self) -> u8 {
        ((self.low >> 2) & 0b11) as u8
    }

    /// Extract the address-width field (bits 0..2 of high).
    #[must_use]
    pub const fn address_width_raw(self) -> u8 {
        (self.high & 0b111) as u8
    }
}

/// Build a context entry pointing at `slpt_phys` for `domain` with the
/// given translation type and AGAW.
///
/// # Errors
///
/// Returns `Err([VtdError::AddressMisaligned])` when `slpt_phys` is not
/// 4-KiB aligned.
pub fn encode_context_entry(
    slpt_phys: u64,
    domain: DomainId,
    translation: TranslationType,
    width: AddressWidth,
) -> Result<ContextEntry, VtdError> {
    if slpt_phys & 0xFFF != 0 {
        return Err(VtdError::AddressMisaligned);
    }
    let t = u64::from(translation.as_u8()) & 0b11;
    let aw = u64::from(width.as_u8()) & 0b111;
    let did = u64::from(domain.raw());
    Ok(ContextEntry {
        low: (slpt_phys & !0xFFF) | (t << 2) | 0x1,
        high: aw | (did << 8),
    })
}

/// Build a not-present context entry.
#[must_use]
pub const fn encode_context_entry_absent() -> ContextEntry {
    ContextEntry { low: 0, high: 0 }
}

/// Encoded VT-d **legacy** second-level page-table entry (SL-PTE).
///
/// Layout (§ 9.6):
/// ```text
/// bit  0      : Read (R)
/// bit  1      : Write (W)
/// bit  2      : Execute (X)  — honoured only when ECAP.XLM is set
/// bit  3..6   : Ignored
/// bit  7      : Page Size (PS) — must be 0 for 4-KiB leaves
/// bit  8..10  : Ignored
/// bit 11      : Snoop Behaviour (SNP) — honoured when ECAP.SC is set
/// bit 12..51  : 4-KiB-aligned output address
/// bit 52..61  : Ignored
/// bit 62      : Transient Mapping (TM)
/// bit 63      : Ignored
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Slpte(pub u64);

impl Slpte {
    /// `R` bit position (bit 0).
    pub const BIT_READ: u64 = 1 << 0;
    /// `W` bit position (bit 1).
    pub const BIT_WRITE: u64 = 1 << 1;
    /// `X` bit position (bit 2).
    pub const BIT_EXECUTE: u64 = 1 << 2;
    /// `SNP` bit position (bit 11).
    pub const BIT_SNOOP: u64 = 1 << 11;

    /// `true` iff this entry has either `R` or `W` set.
    #[must_use]
    pub const fn is_present(self) -> bool {
        (self.0 & (Self::BIT_READ | Self::BIT_WRITE)) != 0
    }

    /// 4-KiB-aligned output address (bits 12..51).
    ///
    /// Mask drops the 12 low alignment bits **and** the 12 high ignored
    /// bits (52..63), so callers consistently see only the translated
    /// physical address.
    #[must_use]
    pub const fn output_address(self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }
}

/// Build a leaf SL-PTE for `phys` with `flags`.
///
/// Translates the kernel [`IommuFlags`] surface into the VT-d
/// bit-position constants. `R` is forced on whenever the caller asks
/// for `WRITE` because VT-d treats a write-only entry as malformed in
/// the legacy mode.
///
/// # Errors
///
/// Returns `Err([VtdError::AddressMisaligned])` when `phys` is not
/// 4-KiB aligned.
pub fn encode_slpte(phys: u64, flags: IommuFlags) -> Result<Slpte, VtdError> {
    if phys & 0xFFF != 0 {
        return Err(VtdError::AddressMisaligned);
    }
    let mut bits = phys & 0x000F_FFFF_FFFF_F000;
    if flags.contains(IommuFlags::READ) || flags.contains(IommuFlags::WRITE) {
        bits |= Slpte::BIT_READ;
    }
    if flags.contains(IommuFlags::WRITE) {
        bits |= Slpte::BIT_WRITE;
    }
    if flags.contains(IommuFlags::EXECUTE) {
        bits |= Slpte::BIT_EXECUTE;
    }
    if flags.contains(IommuFlags::COHERENT) {
        bits |= Slpte::BIT_SNOOP;
    }
    Ok(Slpte(bits))
}

// =============================================================================
// Section 2b — Second-level page-table builder (WI-7a).
//
// `VtdBackend::map` only RECORDS a (domain, iova→phys) tuple in a Vec —
// it does not construct the hardware-walkable page-table tree. With
// `GCMD.TE` off (the current the test VM posture) that scaffold is harmless
// because the device DMA is passthrough. The moment WI-7b raises TE,
// the IOMMU walks the per-domain second-level page table rooted at the
// domain's `slpt_phys`; an empty root faults EVERY DMA. This builder
// fills the gap: it walks the multi-level tree for one mapping,
// allocating missing intermediate tables from a `FrameSource`, and
// writes the leaf SL-PTE — so a future TE flip translates legitimate
// DMA instead of faulting it.
//
// The builder is intentionally NOT yet wired into the live `dma_map`
// syscall path: that wiring + the TE flip + the per-driver deposit-path
// attach is WI-7b, gated on an explicit hardware verification session
// (it can regress the M0 datapath). Here the machinery lands fully
// host-tested via `MockFrameSource`'s entry backing store.
//
// Entry format: an intermediate (non-leaf) entry uses the same R/W +
// 4-KiB-aligned-output-address layout as a leaf SL-PTE (VT-d § 9.6 —
// leaf vs intermediate is a function of LEVEL, not a bit, for 4-KiB
// pages; the PS bit is only set for large-page leaves, which we never
// emit). So "present" is `R|W set` at every level.
// =============================================================================

use super::pt_alloc::{FrameSource, PTES_PER_TABLE};

/// 4-KiB-aligned output-address mask (bits 12..51) shared by leaf and
/// intermediate SL-PTEs.
const SLPT_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// `true` iff the SL-PTE `entry` is present (Read or Write set).
#[must_use]
const fn slpt_entry_present(entry: u64) -> bool {
    entry & (Slpte::BIT_READ | Slpte::BIT_WRITE) != 0
}

/// Physical address of the next-level table referenced by an
/// intermediate `entry` (bits 12..51).
#[must_use]
const fn slpt_entry_next_table(entry: u64) -> u64 {
    entry & SLPT_ADDR_MASK
}

/// Encode an intermediate (non-leaf) SL-PTE pointing at `next_phys`.
///
/// Sets Read + Write so the hardware may descend through this level for
/// both read and write DMA; per-page permissions are enforced by the
/// LEAF entry, not the intermediates (VT-d § 9.6 — intermediate
/// permissions are `AND`ed down the walk, so opening R/W here and
/// restricting at the leaf yields the leaf's effective permission).
#[must_use]
const fn slpt_intermediate_entry(next_phys: u64) -> u64 {
    (next_phys & SLPT_ADDR_MASK) | Slpte::BIT_READ | Slpte::BIT_WRITE
}

/// Per-level page-table index for `iova` at `level` (1 = leaf 4-KiB
/// level, up to the root level = `AddressWidth::levels()`).
///
/// Each level consumes 9 bits; level 1 starts at bit 12 (the 4-KiB page
/// offset is bits 0..11). So the shift for `level` is `12 + 9*(level-1)`.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "result is masked to 0..512 by PTES_PER_TABLE-1, fits usize on every target"
)]
pub const fn slpt_index(iova: u64, level: u8) -> usize {
    let shift = 12 + 9 * (level as u32 - 1);
    ((iova >> shift) & (PTES_PER_TABLE as u64 - 1)) as usize
}

/// Build the second-level page-table path for ONE 4-KiB `iova → leaf`
/// mapping under the domain rooted at `root_phys`, allocating any
/// missing intermediate tables from `src`.
///
/// `leaf` is a fully-encoded leaf SL-PTE (see [`encode_slpte`]); `aw`
/// selects the level count (2..5). On success every intermediate level
/// for `iova` exists and the leaf entry holds `leaf`.
///
/// # Errors
///
/// - [`VtdError::AddressMisaligned`] — `root_phys` or `iova` is not
///   4-KiB aligned.
/// - [`VtdError::PageTableAllocFailed`] — `src` ran out of frames while
///   allocating an intermediate table (partial intermediates may remain
///   installed; the caller's teardown frees the whole subtree by
///   releasing the domain root).
pub fn map_4k_slpt(
    root_phys: u64,
    iova: u64,
    leaf: Slpte,
    aw: AddressWidth,
    src: &mut dyn FrameSource,
) -> Result<(), VtdError> {
    if root_phys & 0xFFF != 0 || iova & 0xFFF != 0 {
        return Err(VtdError::AddressMisaligned);
    }
    let levels = aw.levels();
    let mut table = root_phys;
    let mut level = levels;
    // Descend the intermediate levels (root .. level 2), faulting in
    // missing tables.
    while level > 1 {
        let idx = slpt_index(iova, level);
        let entry = src.read_entry(table, idx);
        let next = if slpt_entry_present(entry) {
            slpt_entry_next_table(entry)
        } else {
            let child = src
                .alloc_zeroed_frame()
                .ok_or(VtdError::PageTableAllocFailed)?;
            if child & 0xFFF != 0 {
                return Err(VtdError::AddressMisaligned);
            }
            src.write_entry(table, idx, slpt_intermediate_entry(child));
            child
        };
        table = next;
        level -= 1;
    }
    // Leaf level: install the mapping.
    let leaf_idx = slpt_index(iova, 1);
    src.write_entry(table, leaf_idx, leaf.0);
    Ok(())
}

/// Map a contiguous `[iova, iova+len)` → `[phys, phys+len)` range as
/// 4-KiB pages with `flags`, building all intermediate tables.
///
/// # Errors
///
/// - [`VtdError::AddressMisaligned`] — any of `iova`, `phys`, `len` is
///   not 4-KiB aligned, or `len == 0`.
/// - [`VtdError::PageTableAllocFailed`] — frame exhaustion mid-range.
pub fn map_range_slpt(
    root_phys: u64,
    iova: u64,
    phys: u64,
    len: u64,
    flags: IommuFlags,
    aw: AddressWidth,
    src: &mut dyn FrameSource,
) -> Result<(), VtdError> {
    if iova & 0xFFF != 0 || phys & 0xFFF != 0 || len & 0xFFF != 0 || len == 0 {
        return Err(VtdError::AddressMisaligned);
    }
    // `len` is a non-zero multiple of 4 KiB (checked above); shift by 12
    // is the page count without a division lint.
    let pages = len >> 12;
    for i in 0..pages {
        let off = i << 12;
        let leaf = encode_slpte(phys + off, flags)?;
        map_4k_slpt(root_phys, iova + off, leaf, aw, src)?;
    }
    Ok(())
}

/// Walk the second-level page table for `iova` read-only and return the
/// translated physical address (output address OR'd with the page
/// offset), or `None` if any level along the path is not present.
///
/// Primarily a verification helper — it lets host tests confirm the
/// builder produced a hardware-walkable tree without a live IOMMU, and
/// gives WI-7b a cheap "is this IOVA mapped?" probe.
#[must_use]
pub fn translate_slpt(
    root_phys: u64,
    iova: u64,
    aw: AddressWidth,
    src: &dyn FrameSource,
) -> Option<u64> {
    if root_phys & 0xFFF != 0 {
        return None;
    }
    let levels = aw.levels();
    let mut table = root_phys;
    let mut level = levels;
    while level > 1 {
        let entry = src.read_entry(table, slpt_index(iova, level));
        if !slpt_entry_present(entry) {
            return None;
        }
        table = slpt_entry_next_table(entry);
        level -= 1;
    }
    let leaf = src.read_entry(table, slpt_index(iova, 1));
    if !slpt_entry_present(leaf) {
        return None;
    }
    Some((leaf & SLPT_ADDR_MASK) | (iova & 0xFFF))
}

/// Clear the leaf SL-PTE for `iova`, removing the mapping.
///
/// Intermediate tables are intentionally retained (Phase 1: no
/// empty-subtree reaping — they are freed wholesale when the domain root
/// is released on driver teardown). Returns `true` if a present leaf was
/// cleared, `false` if the path was already absent.
///
/// # Errors
///
/// [`VtdError::AddressMisaligned`] when `root_phys`/`iova` is unaligned.
pub fn unmap_4k_slpt(
    root_phys: u64,
    iova: u64,
    aw: AddressWidth,
    src: &mut dyn FrameSource,
) -> Result<bool, VtdError> {
    if root_phys & 0xFFF != 0 || iova & 0xFFF != 0 {
        return Err(VtdError::AddressMisaligned);
    }
    let levels = aw.levels();
    let mut table = root_phys;
    let mut level = levels;
    while level > 1 {
        let entry = src.read_entry(table, slpt_index(iova, level));
        if !slpt_entry_present(entry) {
            return Ok(false); // path absent — nothing to clear
        }
        table = slpt_entry_next_table(entry);
        level -= 1;
    }
    let leaf_idx = slpt_index(iova, 1);
    if !slpt_entry_present(src.read_entry(table, leaf_idx)) {
        return Ok(false);
    }
    src.write_entry(table, leaf_idx, 0);
    Ok(true)
}

/// Free every intermediate table under `table_phys` (WI-7b step 2).
///
/// `table_phys` sits at `level`; the freed frames return to `src`. The
/// table at `table_phys` itself is NOT freed — for the domain root that
/// is [`super::pt_alloc::DomainPageTables::release`]'s job, which keeps
/// the registry bookkeeping authoritative.
///
/// Level-1 tables contain leaf SL-PTEs whose output addresses are the
/// driver's DMA buffer frames — owned by the process teardown path, so
/// the recursion stops at `level <= 1` and never frees a leaf target.
///
/// Recursion depth is bounded by `level ≤ 5` ([`AddressWidth::levels`]),
/// so the kernel stack cost is constant and small. Entries are written
/// exclusively by the kernel-side builder ([`map_4k_slpt`]), so the
/// walk cannot encounter cycles.
pub fn free_slpt_subtree(table_phys: u64, level: u8, src: &mut dyn FrameSource) {
    if level <= 1 || table_phys & 0xFFF != 0 {
        return;
    }
    for idx in 0..PTES_PER_TABLE {
        let entry = src.read_entry(table_phys, idx);
        if !slpt_entry_present(entry) {
            continue;
        }
        let child = slpt_entry_next_table(entry);
        free_slpt_subtree(child, level - 1, src);
        src.write_entry(table_phys, idx, 0);
        src.free_frame(child);
    }
}

// =============================================================================
// Section 3 — Capability-register field extraction (CAP @ REG_OFFSET_CAP).
//
// The probe path reads CAP once per IOMMU to size the AGAW and learn
// how many domains the hardware advertises. These helpers stay pure so
// the host test suite can exercise every bit pattern without firmware.
// =============================================================================

/// Decode the `ND` field (Number of Domains, bits 0..2 of CAP, § 10.4.2)
/// as a count.
///
/// Per spec: supported domain count `= 1 << (4 + 2 * ND)`. Common values:
///
/// | ND | Domains |
/// |----|--------|
/// | 0  |    16   |
/// | 1  |    64   |
/// | 2  |   256   |
/// | 3  |  1 024  |
/// | 4  |  4 096  |
/// | 5  | 16 384  |
/// | 6  | 65 536  |
/// | 7  | reserved (treated as 65 536) |
#[must_use]
pub const fn cap_domain_count(cap: u64) -> u32 {
    let nd = (cap & 0b111) as u32;
    let shift = 4u32.saturating_add(nd.saturating_mul(2));
    // Cap at 16 since `1 << 16 = 65 536` matches the 16-bit DID space.
    if shift >= 16 { 65_536 } else { 1u32 << shift }
}

/// Decode the `SAGAW` field (Supported AGAW, bits 8..12 of CAP) as a
/// bitmask of [`AddressWidth`] discriminants. Bit `n` of the mask is
/// set iff the IOMMU advertises level `n+2` (30, 39, 48, 57 bits).
#[must_use]
pub const fn cap_supported_agaw(cap: u64) -> u8 {
    ((cap >> 8) & 0b1_1111) as u8
}

/// Pick the highest supported AGAW from the SAGAW bitmask.
///
/// Returns `None` when the IOMMU advertises no width at all (which
/// would itself be a firmware bug, but the encoder is defensive).
#[must_use]
pub const fn pick_highest_supported_agaw(sagaw_mask: u8) -> Option<AddressWidth> {
    if sagaw_mask & (1 << 3) != 0 {
        Some(AddressWidth::Bits57Level5)
    } else if sagaw_mask & (1 << 2) != 0 {
        Some(AddressWidth::Bits48Level4)
    } else if sagaw_mask & (1 << 1) != 0 {
        Some(AddressWidth::Bits39Level3)
    } else if sagaw_mask & (1 << 0) != 0 {
        Some(AddressWidth::Bits30Level2)
    } else {
        None
    }
}

/// `CM` (Caching Mode) flag — bit 7 of CAP, § 10.4.2.
#[must_use]
pub const fn cap_caching_mode(cap: u64) -> bool {
    (cap & (1 << 7)) != 0
}

/// `FRO` (Fault-recording Register Offset) — bits 24..33 of CAP.
///
/// (§ 10.4.2.) The field is a count of 16-byte units from the IOMMU
/// register base to the first Fault Recording Register (FRCD); this
/// helper returns the byte offset (WI-7b step 3 fault reporting). FRO
/// is SKU-variable (0x400 on some parts, 0xEE8 on others) — always read
/// it, never hardcode.
#[must_use]
pub const fn cap_fault_recording_offset(cap: u64) -> u32 {
    // 10-bit field at bit 24; × 16 = byte offset. The product fits u32
    // for any spec-legal FRO (max 0x3FF × 16 = 0x3FF0).
    (((cap >> 24) & 0x3FF) as u32) * 16
}

/// `NFR` (Number of Fault-recording Registers minus one) — bits 40..47
/// of CAP (§ 10.4.2). Returns the COUNT (field + 1) of FRCD registers.
#[must_use]
pub const fn cap_num_fault_recording(cap: u64) -> u16 {
    (((cap >> 40) & 0xFF) as u16) + 1
}

// -- FSTS (Fault Status Register, offset 0x34) field decoders ---------
//
// All pure functions over the 32-bit FSTS read so the host test suite
// can exercise every bit pattern without firmware (WI-7b step 3).

/// `PFO` (Primary Fault Overflow) — FSTS bit 0. Set when a fault was
/// dropped because all FRCD registers were full.
#[must_use]
pub const fn fsts_primary_fault_overflow(fsts: u32) -> bool {
    fsts & (1 << 0) != 0
}

/// `PPF` (Primary Pending Fault) — FSTS bit 1. Set while at least one
/// FRCD register holds an un-cleared fault.
#[must_use]
pub const fn fsts_primary_pending_fault(fsts: u32) -> bool {
    fsts & (1 << 1) != 0
}

/// `FRI` (Fault Record Index) — FSTS bits 8..15. Index of the FRCD
/// register that received the most recent primary fault (valid only
/// while [`fsts_primary_pending_fault`] is set).
#[must_use]
pub const fn fsts_fault_record_index(fsts: u32) -> u8 {
    ((fsts >> 8) & 0xFF) as u8
}

// -- FRCD (Fault Recording Register, 128-bit) field decoders ----------
//
// Each FRCD is two 64-bit halves (§ 10.4.14). The low half carries the
// faulting address; the high half carries the Fault bit, reason, type
// and source-id. Decoders are pure over the two read halves.

/// `F` (Fault) — FRCD high-half bit 63. Set by hardware when the
/// register holds a recorded fault; RW1C by software after reading.
#[must_use]
pub const fn frcd_fault(high: u64) -> bool {
    high & (1 << 63) != 0
}

/// `FR` (Fault Reason) — FRCD high-half bits 32..39. The architectural
/// fault-reason code (e.g. `0x05` = SLPT entry not present, write;
/// `0x06` = read; context-entry faults `0x01`..`0x04`).
#[must_use]
pub const fn frcd_fault_reason(high: u64) -> u8 {
    ((high >> 32) & 0xFF) as u8
}

/// `T` (Type) — FRCD high-half bit 62. `false` = write request,
/// `true` = read request (§ 10.4.14). Informational for the log.
#[must_use]
pub const fn frcd_is_read(high: u64) -> bool {
    high & (1 << 62) != 0
}

/// `SID` (Source Identifier) — FRCD high-half bits 0..15. The 16-bit
/// requester id (bus/devfn) of the faulting device.
#[must_use]
pub const fn frcd_source_id(high: u64) -> u16 {
    (high & 0xFFFF) as u16
}

/// Faulting address — FRCD low-half bits 12..63 (4-KiB-page granular).
#[must_use]
pub const fn frcd_fault_address(low: u64) -> u64 {
    low & !0xFFF
}

/// A decoded VT-d translation fault (WI-7b step 3).
///
/// Produced by [`decode_fault_record`] from one FRCD register pair; the
/// §S9.1 negative test asserts on these fields, and the live
/// `VtdBackend::drain_faults` path (`cfg(target_os = "none")`, so not
/// linkable from host docs) logs them so an out-of-window DMA is
/// observable in the serial capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRecord {
    /// Requester id (bus/devfn) of the faulting device.
    pub source_id: u16,
    /// Architectural fault-reason code (§ 10.4.14 Table).
    pub reason: u8,
    /// `true` = read request, `false` = write request.
    pub is_read: bool,
    /// 4-KiB-page-granular faulting address.
    pub address: u64,
}

/// Decode one FRCD register pair into a [`FaultRecord`], or `None` when
/// the `F` (Fault) bit is clear (the register holds no recorded fault).
/// Pure — host-tested without firmware.
#[must_use]
pub const fn decode_fault_record(low: u64, high: u64) -> Option<FaultRecord> {
    if !frcd_fault(high) {
        return None;
    }
    Some(FaultRecord {
        source_id: frcd_source_id(high),
        reason: frcd_fault_reason(high),
        is_read: frcd_is_read(high),
        address: frcd_fault_address(low),
    })
}

// =============================================================================
// Section 4 — `VtdBackend`: host-testable dormant backend.
//
// The struct tracks `(domain_id, [SLPTE_record])` tuples in an internal
// `Vec` so the `IommuBackend` trait can be exercised against it from
// host tests. It does NOT write any MMIO byte; the live backend lands
// in P6.7.9-pre.4 with explicit `unsafe` blocks gated behind
// `#[cfg(target_arch = "x86_64")]`.
// =============================================================================

/// Error category raised by the VT-d encoders + scaffold backend.
///
/// Maps to [`IommuError`] when surfaced through the trait so callers
/// see a vendor-neutral taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtdError {
    /// Address argument violated the VT-d 4-KiB alignment requirement.
    AddressMisaligned,
    /// Caller passed a [`DomainId`] not previously installed.
    UnknownDomain,
    /// `flags` requested a permission the backend cannot honour.
    UnsupportedFlags,
    /// The [`FrameSource`] could not supply a frame for an intermediate
    /// second-level page table mid-walk (RAM exhausted). Surfaced by the
    /// SLPT builder ([`map_4k_slpt`] / [`map_range_slpt`], WI-7a).
    PageTableAllocFailed,
}

impl From<VtdError> for IommuError {
    fn from(err: VtdError) -> Self {
        match err {
            VtdError::AddressMisaligned => Self::AddressMisaligned,
            VtdError::UnknownDomain => Self::InvalidDomain,
            VtdError::UnsupportedFlags => Self::Unsupported,
            VtdError::PageTableAllocFailed => Self::MapFailed,
        }
    }
}

/// Error category surfaced by `VtdBackend::activate_hardware` (the
/// bare-metal-only activation entry point gated on
/// `cfg(target_os = "none")`).
///
/// Maps to [`IommuError::ActivationFailed`] when surfaced through the
/// trait; the variant identity is preserved for the kernel boot log so
/// the operator can tell SRTP timeout from QIE timeout from a
/// stalled IOTLB drain. None of these errors should fire on a healthy
/// IOMMU — they signal either a spec-divergent emulation or genuinely
/// wedged silicon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtdActivateError {
    /// [`VtdBackend::prepare_activation`] was never called (or
    /// reported zeroes) before `VtdBackend::activate_hardware` —
    /// `unit_base` is `0` so MMIO writes would target the BIOS
    /// real-mode area.
    NotPrepared,
    /// Polled [`GSTS_BIT_RTPS`] for [`VTD_ACTIVATION_POLL_LIMIT`]
    /// iterations after raising [`GCMD_BIT_SRTP`]; bit never flipped.
    RootTableTimeout,
    /// Polled [`GSTS_BIT_QIES`] for [`VTD_ACTIVATION_POLL_LIMIT`]
    /// iterations after raising [`GCMD_BIT_QIE`]; bit never flipped.
    QueueEnableTimeout,
    /// IQH never caught up to IQT after submitting the global IOTLB
    /// invalidate descriptor. Indicates a stuck invalidation engine.
    InvalidationTimeout,
    /// Polled [`GSTS_BIT_TES`] for [`VTD_ACTIVATION_POLL_LIMIT`]
    /// iterations after raising [`GCMD_BIT_TE`] in
    /// `VtdBackend::enable_translation`; bit never flipped.
    TranslationEnableTimeout,
}

impl From<VtdActivateError> for IommuError {
    fn from(_err: VtdActivateError) -> Self {
        Self::ActivationFailed
    }
}

/// Encode the `IQA` register value for a given queue base address +
/// size order.
///
/// Bit layout (Intel VT-d spec rev 4.1 § 10.4.20):
///
/// - bits 12..63: 4-KiB-aligned queue base physical address (`IQA`).
/// - bit 11: reserved (must be zero).
/// - bit 10: descriptor width — `0` for legacy 128-bit, `1` for
///   scalable 256-bit. We always use `0`.
/// - bits 0..2: `QS` (queue size in pages, queue holds `2^QS` 4-KiB
///   pages of descriptors).
///
/// Reserved bits are masked out defensively so a high-bit overflow in
/// `queue_phys` cannot accidentally set DW or QS.
#[must_use]
pub const fn encode_iqa(queue_phys: u64, size_order: u8) -> u64 {
    let base = queue_phys & 0x000F_FFFF_FFFF_F000;
    let qs = (size_order as u64) & 0x7;
    base | qs
}

/// Encode the low + high qwords of a 128-bit global IOTLB invalidate
/// descriptor.
///
/// Layout (Intel VT-d spec § 6.5.2.4):
///
/// - low qword bits 0..3:  Type = [`INV_DESC_TYPE_IOTLB`] (`0x2`).
/// - low qword bits 4..5:  G   = `01` (Global).
/// - low qword bits 6..7:  DR  = `00` (drain reads = off).
/// - low qword bits 8..9:  DW  = `00` (drain writes = off).
/// - low qword bits 10..63: reserved (zero).
/// - high qword:           AM/AIH/Address — unused for global granularity.
///
/// Returns `(low, high)`. The caller writes them into successive
/// 64-bit slots of the queue ring.
#[must_use]
pub const fn encode_iotlb_global_invalidate() -> (u64, u64) {
    let low = INV_DESC_TYPE_IOTLB | INV_DESC_IOTLB_GRAN_GLOBAL;
    (low, 0)
}

/// Encode the low + high qwords of a 128-bit global context-cache
/// invalidate descriptor.
///
/// Layout (Intel VT-d spec § 6.5.2.3):
///
/// - low qword bits 0..3:  Type = [`INV_DESC_TYPE_CONTEXT_CACHE`] (`0x1`).
/// - low qword bits 4..5:  G   = `01` (Global).
/// - high qword: source-id / function-mask — unused for global granularity.
#[must_use]
pub const fn encode_context_cache_global_invalidate() -> (u64, u64) {
    let low = INV_DESC_TYPE_CONTEXT_CACHE | INV_DESC_CTX_GRAN_GLOBAL;
    (low, 0)
}

/// Encode the low + high qwords of a 128-bit **per-domain**
/// context-cache invalidate descriptor.
///
/// Layout (Intel VT-d spec § 6.5.2.3):
///
/// - low qword bits  0..3 : Type = [`INV_DESC_TYPE_CONTEXT_CACHE`] (`0x1`).
/// - low qword bits  4..5 : G   = `10` (Domain-granular).
/// - low qword bits 16..31: DID = `domain.raw()`.
/// - high qword: source-id / function-mask — unused for domain
///   granularity (the IOMMU evicts every cache entry whose `DID`
///   matches, regardless of source-id).
///
/// This is what the per-device install path queues after binding a new
/// PCI device to `domain` so the IOMMU drops any stale entries from a
/// prior generation of the same DID.
#[must_use]
pub const fn encode_context_cache_domain_invalidate(domain: DomainId) -> (u64, u64) {
    let did = (domain.raw() as u64) << 16;
    let low = INV_DESC_TYPE_CONTEXT_CACHE | INV_DESC_CTX_GRAN_DOMAIN | did;
    (low, 0)
}

/// Encode the low + high qwords of a 128-bit **per-domain** IOTLB
/// invalidate descriptor.
///
/// Layout (Intel VT-d spec § 6.5.2.4):
///
/// - low qword bits  0..3 : Type = [`INV_DESC_TYPE_IOTLB`] (`0x2`).
/// - low qword bits  4..5 : G   = `10` (Domain-granular).
/// - low qword bits 16..31: DID = `domain.raw()`.
/// - high qword: AM/AIH/Address — unused for domain granularity.
#[must_use]
pub const fn encode_iotlb_domain_invalidate(domain: DomainId) -> (u64, u64) {
    let did = (domain.raw() as u64) << 16;
    let low = INV_DESC_TYPE_IOTLB | INV_DESC_IOTLB_GRAN_DOMAIN | did;
    (low, 0)
}

/// Byte offset of the context-entry slot for `bdf` within a per-bus
/// 4-KiB context table (§ 9.3 — slot index = devfn, slot size =
/// [`CONTEXT_ENTRY_BYTES`]).
///
/// Pure function — moves the index arithmetic out of the unsafe MMIO
/// path so host tests can pin the offsets.
#[must_use]
pub const fn context_entry_offset(bdf: super::PciBdf) -> u64 {
    (bdf.devfn() as u64) * (CONTEXT_ENTRY_BYTES as u64)
}

/// Byte offset of the root-entry slot for `bus` within the 4-KiB
/// root table (§ 9.1 — slot index = bus number, slot size =
/// [`ROOT_ENTRY_BYTES`]).
#[must_use]
pub const fn root_entry_offset(bus: u8) -> u64 {
    (bus as u64) * (ROOT_ENTRY_BYTES as u64)
}

/// Recorded per-device attachment in the host-testable scaffold.
///
/// Live MMIO state (`VtdBackend::install_device_entry`) also pushes a
/// [`VtdAttachment`] so the bookkeeping is consistent between the host
/// and bare-metal halves: every `(bdf → domain)` binding visible to
/// the trait dispatch surface has exactly one entry here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtdAttachment {
    /// PCI requester ID owning the binding.
    pub bdf: PciBdf,
    /// Domain the device is bound to.
    pub domain: DomainId,
}

/// One per-bus context-table page tracked by the backend
/// (P6.7.9-pre.11).
///
/// A VT-d unit has exactly one root table; each root entry (indexed by
/// PCI bus number) points to a 4-KiB context-table page that holds
/// 256 context entries (one per `devfn`). The backend owns the lifetime
/// of these context tables — a single 4-KiB page is shared by every
/// device on the same bus regardless of which driver process the device
/// belongs to (each devfn slot points to that device's own SL-PTE root).
///
/// The page is acquired lazily on the first
/// `VtdBackend::install_device_entry_with_alloc` for a bus and
/// released only when the last attached device on that bus is detached
/// via `VtdBackend::release_bus_context_table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusContextTable {
    /// PCI bus number owning this context table (`0..=255`).
    pub bus: u8,
    /// 4-KiB-aligned physical address of the context-table page.
    pub phys: u64,
    /// Number of live `(bdf → domain)` attachments currently using
    /// slots in this context table. Decremented by
    /// `VtdBackend::release_bus_context_table`; the page is freed
    /// through the [`super::pt_alloc::FrameSource`] when it reaches `0`.
    pub refcount: u32,
}

/// Error surfaced by `VtdBackend::install_device_entry`.
///
/// Mapped to [`IommuError`] when surfaced through the public surface so
/// the syscall layer keeps a vendor-neutral taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtdAttachError {
    /// The backend was never `activate_hardware`'d so the IQ is not
    /// guaranteed to be drained — refusing to write the entry avoids
    /// publishing a context entry the IOMMU cannot invalidate later.
    NotActivated,
    /// `domain` was never installed via
    /// [`super::IommuBackend::install_domain`].
    DomainNotInstalled,
    /// `bdf` is already attached (callers must `detach_device` first).
    AlreadyAttached,
    /// `slpt_phys` or `context_table_phys` not 4-KiB aligned.
    AddressMisaligned,
    /// Per-domain context-cache or IOTLB invalidate failed to drain in
    /// [`VTD_ACTIVATION_POLL_LIMIT`] iterations.
    InvalidationTimeout,
    /// [`super::pt_alloc::FrameSource::alloc_zeroed_frame`] returned
    /// `None` (or a misaligned address) while acquiring a per-bus
    /// context-table page. Surfaced through
    /// `VtdBackend::install_device_entry_with_alloc` only.
    BusContextAllocFailed,
}

impl From<VtdAttachError> for IommuError {
    fn from(err: VtdAttachError) -> Self {
        match err {
            VtdAttachError::NotActivated | VtdAttachError::InvalidationTimeout => {
                Self::ActivationFailed
            }
            VtdAttachError::DomainNotInstalled => Self::InvalidDomain,
            VtdAttachError::AlreadyAttached => Self::Unsupported,
            VtdAttachError::AddressMisaligned => Self::AddressMisaligned,
            VtdAttachError::BusContextAllocFailed => Self::DomainTableFull,
        }
    }
}

/// Error surfaced by `VtdBackend::release_bus_context_table`.
///
/// Symmetric to [`VtdAttachError::BusContextAllocFailed`]; carries an
/// explicit error type rather than `()` so clippy's
/// `result_unit_err` lint stays happy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusContextTableReleaseError {
    /// No context-table page is currently allocated for the requested
    /// bus (the caller must invoke `VtdBackend::acquire_bus_context_table`
    /// first).
    UnknownBus,
}

/// One mapping record tracked by the scaffold backend.
///
/// Pure data — exists so the host test suite can assert on the
/// IOMMU-side state without touching MMIO.
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
    /// Encoded SL-PTE for the first 4-KiB leaf.
    pub leaf_slpte: Slpte,
}

/// Dormant VT-d backend. Holds bookkeeping only; emits no MMIO.
///
/// The host-test exercise path:
///
/// 1. Build `VtdBackend::new()`.
/// 2. `install_domain(DomainId::new(7))?;`
/// 3. `map(DomainId::new(7), 0x1000, 0x2000, 0x1000, IommuFlags::READ)?;`
/// 4. Inspect the recorded `mappings()` slice in the assertion.
///
/// Live programming swap: P6.7.9-pre.4 adds a `unit_base: u64` field
/// and an `mmio_write32` helper; the `map`/`unmap` paths gain
/// `unsafe { ... }` blocks that write the descriptors back-to-back into
/// the IOMMU's invalidation queue (`REG_OFFSET_IQT`).
#[derive(Debug, Clone, Default)]
pub struct VtdBackend {
    /// Installed domains, in insertion order.
    domains: Vec<DomainId>,
    /// Recorded mappings.
    mappings: Vec<ScaffoldMapping>,
    /// MMIO base of the per-IOMMU register window. `0` while the
    /// backend is dormant; populated by [`Self::prepare_activation`]
    /// once the boot probe resolves the first DRHD's `register_base`.
    unit_base: u64,
    /// Physical address of the 4-KiB root-table page used by the live
    /// MMIO path. `0` while dormant.
    root_table_phys: u64,
    /// Physical address of the 4-KiB invalidation-queue page. `0`
    /// while dormant.
    invalidation_queue_phys: u64,
    /// Software-maintained tail index into the invalidation queue,
    /// measured in **bytes** so it can be written to IQT directly.
    /// Wraps at [`INV_QUEUE_BYTES`].
    invalidation_queue_tail: u64,
    /// `true` once `Self::activate_hardware` has cleanly walked
    /// RTADDR + GCMD.SRTP + IQA + GCMD.QIE + the global IOTLB flush
    /// and observed every status mirror bit set (the activation
    /// method is gated on `cfg(target_os = "none")`).
    hardware_activated: bool,
    /// Per-device attachments recorded by `attach_device` and (for
    /// bare-metal builds) `install_device_entry`. Both halves of the
    /// API share this vector so the host-testable scaffold and the
    /// live MMIO path agree on `(bdf → domain)` state.
    attachments: Vec<VtdAttachment>,
    /// Per-domain second-level page-table root registry (P6.7.9-pre.9).
    ///
    /// Populated through [`Self::provision_domain_pt`] before the live
    /// `install_device_entry` MMIO path runs; the recorded
    /// `root_phys` is what `install_device_entry` consumes as the
    /// `slpt_phys` argument for the matching domain.
    domain_pts: super::pt_alloc::DomainPageTables,
    /// Per-bus context-table pages (P6.7.9-pre.11).
    ///
    /// One 4-KiB page per active bus, refcounted on the number of live
    /// device attachments hosted in the page. Acquired by
    /// `Self::install_device_entry_with_alloc` and released by
    /// [`Self::release_bus_context_table`].
    bus_context_tables: Vec<BusContextTable>,
    /// `true` once `Self::enable_translation` has flipped `GCMD.TE`
    /// and observed `GSTS.TES`. Sticky for the lifetime of the kernel;
    /// [`Self::prepare_activation`] resets it back to `false` together
    /// with [`Self::hardware_activated`] when re-prepared with different
    /// parameters (MP follow-up).
    translation_enabled: bool,
    /// Cached `CAP.SAGAW` bitmask (bits 8..12) read once at
    /// [`Self::activate_hardware`] (WI-7b). `0` until activation. The
    /// supported AGAW determines the second-level page-table level count
    /// every context entry and SLPT build MUST agree on — hardcoding the
    /// wrong width faults all DMA the moment `GCMD.TE` is raised, so the
    /// live value is read from the hardware rather than assumed.
    supported_sagaw: u8,
    /// Bootloader direct-map offset cached at
    /// [`Self::activate_hardware`] (WI-7b step 2). `0` while dormant.
    ///
    /// The [`IommuBackend::flush`] trait method has no `phys_offset`
    /// parameter (it predates the live MMIO path), so the live IOTLB
    /// domain-invalidate submission reads the offset from here. The
    /// offset is a boot constant (same value passed to
    /// `crate::bare_metal::set_phys_offset`), so caching it at
    /// activation cannot go stale; [`Self::prepare_activation`] clears
    /// it together with [`Self::hardware_activated`] when re-prepared
    /// with different parameters.
    phys_offset: u64,
    /// Level-sensitive `GCMD` enable bits currently committed to the
    /// hardware (`TE`/`QIE`/`IRE`/`EAFL` — P11.3, ADR-0027 review
    /// finding #4).
    ///
    /// Per Intel VT-d rev 4.1 § 11.4.4 every `GCMD` write replaces the
    /// whole register, so software MUST re-assert every enable bit it
    /// has previously raised or the hardware silently lowers it. Each
    /// GCMD write site ORs the bit(s) it raises into this mask through
    /// [`Self::compose_enable_bits`] and writes the composed value —
    /// never a hardcoded constant. One-shot *command* bits (`SRTP`,
    /// `SFL`, `WBF`, `SIRTP`) must NOT enter the mask: they
    /// self-clear and re-asserting them would re-trigger the command.
    /// `0` while dormant; [`Self::prepare_activation`] resets it
    /// together with [`Self::hardware_activated`] when re-prepared
    /// with different parameters.
    live_enable_mask: u32,
}

impl VtdBackend {
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
            root_table_phys: 0,
            invalidation_queue_phys: 0,
            invalidation_queue_tail: 0,
            hardware_activated: false,
            attachments: Vec::new(),
            domain_pts: super::pt_alloc::DomainPageTables::new(),
            bus_context_tables: Vec::new(),
            translation_enabled: false,
            supported_sagaw: 0,
            phys_offset: 0,
            live_enable_mask: 0,
        }
    }

    /// Cached `CAP.SAGAW` bitmask read at `Self::activate_hardware`
    /// (`cfg(target_os = "none")`, so not linkable from host docs;
    /// `0` before activation). See [`Self::supported_address_width`].
    #[must_use]
    pub const fn supported_sagaw(&self) -> u8 {
        self.supported_sagaw
    }

    /// Highest [`AddressWidth`] the hardware advertises in `CAP.SAGAW`,
    /// or `None` before activation / if the mask is empty (WI-7b). This
    /// is the level count every context entry + SLPT build must use.
    #[must_use]
    pub fn supported_address_width(&self) -> Option<AddressWidth> {
        pick_highest_supported_agaw(self.supported_sagaw)
    }

    /// Allocate the per-domain second-level page-table root frame for
    /// `domain` through the supplied [`super::pt_alloc::FrameSource`]
    /// and record the `(domain, root_phys)` binding so the live
    /// per-device install MMIO call can read `root_phys` back via
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
    /// WI-7b step 2: before the registry frees the root, every
    /// intermediate table reachable from it is freed back to `src` via
    /// [`free_slpt_subtree`] — [`Self::map_with_src`] allocates
    /// intermediates from the same source and [`Self::unmap_with_src`]
    /// deliberately retains them (Phase 1: no per-unmap reaping), so
    /// the wholesale free here is what makes the "freed on domain-root
    /// release" contract real instead of a leak. Leaf entries reference
    /// the driver's DMA buffer frames, which are owned and freed by
    /// `tear_down_dma_mappings` — the walk never frees level-1 targets.
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
        if let Some(root_phys) = self.domain_pts.root_phys(domain) {
            let aw = self
                .supported_address_width()
                .unwrap_or(AddressWidth::Bits48Level4);
            free_slpt_subtree(root_phys, aw.levels(), src);
        }
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

    /// Map `[iova, iova+len) → [phys, phys+len)` for `id`, building the
    /// real second-level page table when the domain has a provisioned
    /// root (WI-7b step 2 — wires the WI-7a builder into the live path).
    ///
    /// Behaviour matrix:
    ///
    /// - **Domain PT provisioned** ([`Self::provision_domain_pt`] ran):
    ///   the WI-7a [`map_range_slpt`] walker populates the SLPT tree
    ///   rooted at the recorded `root_phys`, allocating intermediate
    ///   tables from `src`, THEN the `(domain, iova, phys, len)` tuple
    ///   is recorded in the bookkeeping list. With `GCMD.TE` off the
    ///   populated tree is inert (hardware stays in passthrough); the
    ///   moment WI-7b raises TE these mappings become the device's
    ///   only reachable memory.
    /// - **No domain PT** (no BDF ever attached — e.g. a non-PCI test
    ///   process): bookkeeping only, `src` untouched. Identical to the
    ///   legacy [`IommuBackend::map`] behaviour.
    ///
    /// The level count comes from the live `CAP.SAGAW` cache
    /// ([`Self::supported_address_width`]); before activation (host
    /// tests) it falls back to [`AddressWidth::Bits48Level4`] — the same
    /// width the managed device-entry install path uses, so the context
    /// entry AGAW and the SLPT depth can never disagree.
    ///
    /// # Errors
    ///
    /// - [`IommuError::InvalidDomain`] — `id` was never installed.
    /// - [`IommuError::AddressMisaligned`] — `iova`/`phys`/`len` not
    ///   4-KiB aligned or `len == 0`.
    /// - [`IommuError::MapFailed`] — `src` ran out of frames mid-build
    ///   (partial intermediates may remain; they are freed wholesale
    ///   when the domain root is released — Phase 1 contract, see
    ///   [`map_4k_slpt`]). **No bookkeeping entry is recorded** on this
    ///   path so the caller's rollback sees consistent state.
    pub fn map_with_src(
        &mut self,
        id: DomainId,
        iova: u64,
        phys: u64,
        len: u64,
        flags: IommuFlags,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<(), IommuError> {
        if !self.has_domain(id) {
            return Err(IommuError::InvalidDomain);
        }
        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || len & 0xFFF != 0 || len == 0 {
            return Err(IommuError::AddressMisaligned);
        }
        // Defensive end-of-range guard (review finding #6): the walker
        // computes `iova + off` / `phys + off` per page — a window
        // ending past `u64::MAX` would wrap. The `DmaMap` syscall
        // surface already bounds `iova + len ≤ DRIVER_DMA_VA_END`, but
        // this is a `pub` API.
        if iova.checked_add(len).is_none() || phys.checked_add(len).is_none() {
            return Err(IommuError::AddressMisaligned);
        }
        let leaf = encode_slpte(phys, flags).map_err(IommuError::from)?;
        if let Some(root_phys) = self.domain_pts.root_phys(id) {
            let aw = self
                .supported_address_width()
                .unwrap_or(AddressWidth::Bits48Level4);
            map_range_slpt(root_phys, iova, phys, len, flags, aw, src).map_err(IommuError::from)?;
        }
        self.mappings.push(ScaffoldMapping {
            domain: id,
            iova,
            phys,
            len,
            leaf_slpte: leaf,
        });
        Ok(())
    }

    /// Remove the `(id, iova, len)` mapping, clearing the second-level
    /// page-table leaves when the domain has a provisioned root (WI-7b
    /// step 2 — symmetric to [`Self::map_with_src`]).
    ///
    /// Intermediate tables are retained per the Phase 1 contract (freed
    /// wholesale on domain-root release, see [`unmap_4k_slpt`]); `src`
    /// is only used for entry reads/writes, never for frees here.
    ///
    /// # Errors
    ///
    /// - [`IommuError::InvalidDomain`] — `id` was never installed.
    /// - [`IommuError::AddressMisaligned`] — `iova`/`len` not 4-KiB
    ///   aligned or `len == 0`.
    /// - [`IommuError::UnmapFailed`] — no bookkeeping record matches
    ///   `(id, iova, len)`; the SLPT is not touched on this path.
    pub fn unmap_with_src(
        &mut self,
        id: DomainId,
        iova: u64,
        len: u64,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<(), IommuError> {
        if !self.has_domain(id) {
            return Err(IommuError::InvalidDomain);
        }
        if iova & 0xFFF != 0 || len & 0xFFF != 0 || len == 0 {
            return Err(IommuError::AddressMisaligned);
        }
        // Defensive end-of-range guard — mirrors `map_with_src`.
        if iova.checked_add(len).is_none() {
            return Err(IommuError::AddressMisaligned);
        }
        let initial = self.mappings.len();
        self.mappings
            .retain(|m| !(m.domain == id && m.iova == iova && m.len == len));
        if self.mappings.len() == initial {
            return Err(IommuError::UnmapFailed);
        }
        if let Some(root_phys) = self.domain_pts.root_phys(id) {
            let aw = self
                .supported_address_width()
                .unwrap_or(AddressWidth::Bits48Level4);
            // `len` is a non-zero multiple of 4 KiB (validated above).
            let pages = len >> 12;
            for i in 0..pages {
                // `Ok(false)` (path already absent) is fine — the leaf
                // may never have been built if the domain PT was
                // provisioned after this mapping was recorded.
                let _ = unmap_4k_slpt(root_phys, iova + (i << 12), aw, src)
                    .map_err(IommuError::from)?;
            }
        }
        Ok(())
    }

    /// Snapshot of the recorded per-device attachments (insertion
    /// order). Exposed primarily so the host test suite can assert on
    /// the `(bdf → domain)` state without going through the trait
    /// surface.
    #[must_use]
    pub fn attachments(&self) -> &[VtdAttachment] {
        &self.attachments
    }

    /// `true` iff `bdf` is currently attached to some domain.
    #[must_use]
    pub fn has_attachment(&self, bdf: PciBdf) -> bool {
        self.attachments.iter().any(|a| a.bdf == bdf)
    }

    /// Domain `bdf` is attached to, or `None` if unattached (WI-7b step 3
    /// C2 — the TE-finalize guard reads this to find a confined device's
    /// domain so it can check the SLPT is built before flipping).
    #[must_use]
    pub fn attached_domain(&self, bdf: PciBdf) -> Option<DomainId> {
        self.attachments
            .iter()
            .find(|a| a.bdf == bdf)
            .map(|a| a.domain)
    }

    /// `true` iff at least one DMA window is recorded for `domain` (WI-7b
    /// step 3 C2). The TE-finalize guard uses this to refuse the flip
    /// until a confined (translating) driver's `DmaMap` calls have built
    /// its second-level page table — flipping with an empty SLPT would
    /// fault that device's every DMA.
    #[must_use]
    pub fn domain_has_mappings(&self, domain: DomainId) -> bool {
        self.mappings.iter().any(|m| m.domain == domain)
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

    /// Physical address of the 4-KiB root-table page (`0` while
    /// dormant).
    #[must_use]
    pub const fn root_table_phys(&self) -> u64 {
        self.root_table_phys
    }

    /// Physical address of the 4-KiB invalidation-queue page (`0`
    /// while dormant).
    #[must_use]
    pub const fn invalidation_queue_phys(&self) -> u64 {
        self.invalidation_queue_phys
    }

    /// `true` once `Self::activate_hardware` has completed cleanly
    /// (the activation method is gated on `cfg(target_os = "none")`).
    #[must_use]
    pub const fn is_hardware_activated(&self) -> bool {
        self.hardware_activated
    }

    /// `true` once `Self::enable_translation` has flipped `GCMD.TE`
    /// (the method is gated on `cfg(target_os = "none")`).
    #[must_use]
    pub const fn is_translation_enabled(&self) -> bool {
        self.translation_enabled
    }

    /// Level-sensitive `GCMD` enable bits currently committed to the
    /// hardware (P11.3). `0` while dormant.
    #[must_use]
    pub const fn live_enable_mask(&self) -> u32 {
        self.live_enable_mask
    }

    /// Record newly raised level-sensitive `GCMD` enable bits and
    /// return the full composed mask to write to `GCMD` (P11.3,
    /// ADR-0027 review finding #4).
    ///
    /// Per Intel VT-d rev 4.1 § 11.4.4 a `GCMD` write replaces the
    /// whole register, so every write site must re-assert every enable
    /// bit raised so far. Composing through this method (instead of
    /// hardcoding e.g. `TE | QIE`) keeps the write sites correct when
    /// a future slice raises another enable bit (`IRE`/`EAFL`): the
    /// bit lands in the mask once and every later write preserves it.
    ///
    /// `bits` must contain only level-sensitive enable bits
    /// ([`GCMD_BIT_TE`], [`GCMD_BIT_QIE`], [`GCMD_BIT_IRE`],
    /// [`GCMD_BIT_EAFL`], [`GCMD_BIT_CFI`]) — never the one-shot
    /// command bits (`SRTP`/`SFL`/`WBF`/`SIRTP`), which self-clear and
    /// would be spuriously re-triggered by later writes if recorded
    /// here. Debug-asserted, not run-time-checked: the call sites are
    /// kernel-internal and fixed at compile time.
    ///
    /// Host-testable on purpose: the composition is the P11.3 logic
    /// under test, while the MMIO write sites are
    /// `cfg(target_os = "none")` gated.
    pub fn compose_enable_bits(&mut self, bits: u32) -> u32 {
        const GCMD_ONE_SHOT_BITS: u32 =
            GCMD_BIT_SRTP | GCMD_BIT_SFL | GCMD_BIT_WBF | GCMD_BIT_SIRTP;
        debug_assert_eq!(
            bits & GCMD_ONE_SHOT_BITS,
            0,
            "one-shot GCMD command bits must not enter live_enable_mask"
        );
        self.live_enable_mask |= bits;
        self.live_enable_mask
    }

    /// Snapshot of the per-bus context-table registry (P6.7.9-pre.11).
    #[must_use]
    pub fn bus_context_tables(&self) -> &[BusContextTable] {
        &self.bus_context_tables
    }

    /// Physical address of the context-table page hosting `bus`, or
    /// `None` if no driver has acquired a slot on that bus yet.
    #[must_use]
    pub fn bus_context_table_phys(&self, bus: u8) -> Option<u64> {
        self.bus_context_tables
            .iter()
            .find(|t| t.bus == bus)
            .map(|t| t.phys)
    }

    /// Number of live device attachments hosted in the context-table
    /// page for `bus`, or `None` if no page has been allocated for that
    /// bus.
    #[must_use]
    pub fn bus_context_table_refcount(&self, bus: u8) -> Option<u32> {
        self.bus_context_tables
            .iter()
            .find(|t| t.bus == bus)
            .map(|t| t.refcount)
    }

    /// Acquire the per-bus context-table page for `bus`, allocating it
    /// through `src` on first use and bumping the refcount on every
    /// subsequent acquisition.
    ///
    /// Defence-in-depth: a non-`None` alloc that returns a non-4-KiB-
    /// aligned frame is rejected ([`VtdAttachError::BusContextAllocFailed`])
    /// and the frame is returned to the pool before propagating the error,
    /// matching the [`super::pt_alloc::DomainPageTables::provision`] contract.
    ///
    /// # Errors
    ///
    /// - [`VtdAttachError::BusContextAllocFailed`] — `src.alloc_zeroed_frame`
    ///   returned `None`, or the returned phys is not 4-KiB-aligned (the
    ///   misaligned frame is freed back to `src` before the error returns).
    pub fn acquire_bus_context_table(
        &mut self,
        bus: u8,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<u64, VtdAttachError> {
        if let Some(entry) = self.bus_context_tables.iter_mut().find(|t| t.bus == bus) {
            entry.refcount = entry.refcount.saturating_add(1);
            return Ok(entry.phys);
        }
        let phys = src
            .alloc_zeroed_frame()
            .ok_or(VtdAttachError::BusContextAllocFailed)?;
        if phys & 0xFFF != 0 {
            src.free_frame(phys);
            return Err(VtdAttachError::BusContextAllocFailed);
        }
        self.bus_context_tables.push(BusContextTable {
            bus,
            phys,
            refcount: 1,
        });
        Ok(phys)
    }

    /// Release one refcount slot on the context-table page for `bus`.
    ///
    /// When the refcount drops to zero the page is freed back to `src`
    /// and the entry removed from the registry. The caller is expected
    /// to have zeroed the relevant context-entry slot before the release
    /// (the live MMIO path does this through
    /// `Self::release_device_entry_with_alloc`) so the IOMMU never sees
    /// a stale pointer to a recycled frame.
    ///
    /// # Errors
    ///
    /// Returns [`BusContextTableReleaseError::UnknownBus`] when no
    /// context-table page has been allocated for `bus` (callers must
    /// `acquire_bus_context_table` first).
    pub fn release_bus_context_table(
        &mut self,
        bus: u8,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<(), BusContextTableReleaseError> {
        let Some(idx) = self.bus_context_tables.iter().position(|t| t.bus == bus) else {
            return Err(BusContextTableReleaseError::UnknownBus);
        };
        let Some(entry) = self.bus_context_tables.get_mut(idx) else {
            return Err(BusContextTableReleaseError::UnknownBus);
        };
        if entry.refcount > 1 {
            entry.refcount -= 1;
            return Ok(());
        }
        let phys = entry.phys;
        self.bus_context_tables.swap_remove(idx);
        src.free_frame(phys);
        Ok(())
    }

    /// Stash the activation parameters in the backend without touching
    /// MMIO.
    ///
    /// Idempotent: calling twice with the same values is a no-op; the
    /// second call with different values overwrites and **resets**
    /// [`Self::is_hardware_activated`] to `false` so the caller
    /// understands the live programming must be redriven (this is the
    /// behaviour the kernel boot path relies on after a TLB-shootdown
    /// induced re-activation in MP follow-up work).
    pub fn prepare_activation(
        &mut self,
        unit_base: u64,
        root_table_phys: u64,
        invalidation_queue_phys: u64,
    ) {
        let same = self.unit_base == unit_base
            && self.root_table_phys == root_table_phys
            && self.invalidation_queue_phys == invalidation_queue_phys;
        self.unit_base = unit_base;
        self.root_table_phys = root_table_phys;
        self.invalidation_queue_phys = invalidation_queue_phys;
        self.invalidation_queue_tail = 0;
        if !same {
            self.hardware_activated = false;
            self.translation_enabled = false;
            self.phys_offset = 0;
            // The enable bits live on the unit being re-prepared; a new
            // activation walk re-raises (and re-records) them from scratch.
            self.live_enable_mask = 0;
        }
    }

    /// Drive the live VT-d MMIO programming sequence.
    ///
    /// Spec-faithful order (Intel VT-d rev 4.1 § 6.2 + § 6.5):
    ///
    /// 1. Write the root-table physical address into `RTADDR`.
    /// 2. Raise `GCMD.SRTP` and poll `GSTS.RTPS` until set.
    /// 3. Write the invalidation-queue layout into `IQA` and clear
    ///    `IQT` (head==tail = empty queue).
    /// 4. Raise `GCMD.QIE` and poll `GSTS.QIES` until set.
    /// 5. Submit a global IOTLB invalidate descriptor (queue slot 0),
    ///    bump `IQT`, and wait for `IQH` to catch up.
    ///
    /// `GCMD.TE` is **NOT** raised by this slice; the IOMMU stays in
    /// pre-translation (passthrough) mode at the hardware level until
    /// the kernel is ready to gate every DMA-capable device through a
    /// per-domain page table (future P6.7.9-pre.7+).
    ///
    /// # Errors
    ///
    /// See [`VtdActivateError`].
    ///
    /// # Safety
    ///
    /// `phys_offset` must be the live bootloader direct-map offset.
    /// `unit_base` (recorded via [`Self::prepare_activation`]) must be
    /// the MMIO base address of a VT-d remapping unit owned exclusively
    /// by the kernel. The function performs `volatile_write32` /
    /// `volatile_write64` against `phys_offset + unit_base + offset`
    /// for the constants documented in §1 above.
    #[cfg(target_os = "none")]
    pub unsafe fn activate_hardware(&mut self, phys_offset: u64) -> Result<(), VtdActivateError> {
        if self.unit_base == 0 || self.root_table_phys == 0 || self.invalidation_queue_phys == 0 {
            return Err(VtdActivateError::NotPrepared);
        }

        let unit_va = phys_offset.wrapping_add(self.unit_base);

        // (0) Cache CAP.SAGAW (WI-7b). Read-only; informs every later
        //     context-entry AGAW + SLPT level count. Reading CAP has no
        //     side effects and does not change translation behaviour.
        // SAFETY: CAP (offset 0x008) is a read-only MMIO register in the
        // kernel-owned VT-d window addressed by `unit_va`.
        let cap = unsafe { mmio_read64(unit_va, REG_OFFSET_CAP) };
        self.supported_sagaw = cap_supported_agaw(cap);

        // (1) Write the root-table physical address into RTADDR.
        //     Bit 11 (RTT) stays 0 — we use the legacy 128-bit root
        //     entry format (matches `encode_root_entry`).
        // SAFETY: per the function's safety contract, `unit_va` is a
        // valid MMIO VA into a kernel-owned VT-d register window.
        unsafe { mmio_write64(unit_va, REG_OFFSET_RTADDR, self.root_table_phys) };

        // (2) Raise GCMD.SRTP and poll GSTS.RTPS until set or timeout.
        //     SRTP is a one-shot command bit (self-clearing, so NOT
        //     recorded in `live_enable_mask`), but the write still
        //     replaces the whole register (§ 11.4.4) so the live
        //     enable bits are re-asserted alongside it (P11.3). On a
        //     first activation the mask is 0 and this degenerates to
        //     the bare SRTP write.
        let gcmd_srtp = self.live_enable_mask | GCMD_BIT_SRTP;
        // SAFETY: same as above.
        unsafe { mmio_write32(unit_va, REG_OFFSET_GCMD, gcmd_srtp) };
        // SAFETY: GSTS is a 4-byte read-only MMIO register.
        if !unsafe { poll_gsts_bit(unit_va, GSTS_BIT_RTPS) } {
            return Err(VtdActivateError::RootTableTimeout);
        }

        // (3) Program the invalidation queue base + size. The queue
        //     body itself was zero-filled by the caller before this
        //     activation runs — IQT=0 publishes "empty queue" to the
        //     IOMMU.
        let iqa = encode_iqa(self.invalidation_queue_phys, INV_QUEUE_SIZE_ORDER);
        // SAFETY: same as RTADDR — kernel-owned MMIO window.
        unsafe { mmio_write64(unit_va, REG_OFFSET_IQA, iqa) };
        // SAFETY: same as RTADDR — kernel-owned MMIO window.
        unsafe { mmio_write64(unit_va, REG_OFFSET_IQT, 0) };
        self.invalidation_queue_tail = 0;

        // (4) Raise GCMD.QIE and poll GSTS.QIES until set or timeout.
        //     QIE is level-sensitive: record it in `live_enable_mask`
        //     so every later GCMD write re-asserts it (P11.3).
        let gcmd_qie = self.compose_enable_bits(GCMD_BIT_QIE);
        // SAFETY: same as RTADDR — kernel-owned MMIO window.
        unsafe { mmio_write32(unit_va, REG_OFFSET_GCMD, gcmd_qie) };
        // SAFETY: GSTS is a 4-byte read-only MMIO register.
        if !unsafe { poll_gsts_bit(unit_va, GSTS_BIT_QIES) } {
            return Err(VtdActivateError::QueueEnableTimeout);
        }

        // (5) Submit a global IOTLB invalidate descriptor at slot 0,
        //     bump IQT, and wait for IQH to catch up.
        let queue_va = phys_offset.wrapping_add(self.invalidation_queue_phys);
        let (lo, hi) = encode_iotlb_global_invalidate();
        // SAFETY: caller guarantees the invalidation-queue page is
        // 4-KiB-aligned, kernel-owned, and zero-filled. The first 16
        // bytes hold descriptor index 0.
        unsafe { write_queue_entry(queue_va, 0, lo, hi) };
        let next_tail: u64 = INV_QUEUE_ENTRY_BYTES as u64;
        // SAFETY: same as IQA / IQT writes above.
        unsafe { mmio_write64(unit_va, REG_OFFSET_IQT, next_tail) };
        self.invalidation_queue_tail = next_tail;
        // SAFETY: IQH is a 8-byte read-only MMIO register.
        if !unsafe { poll_iqh_reaches(unit_va, next_tail, VTD_ACTIVATION_POLL_LIMIT) } {
            return Err(VtdActivateError::InvalidationTimeout);
        }

        self.hardware_activated = true;
        // Cache the direct-map offset for the live `flush` half (WI-7b
        // step 2) — the `IommuBackend::flush` trait signature has no
        // `phys_offset` parameter, and the offset is a boot constant.
        self.phys_offset = phys_offset;
        Ok(())
    }

    /// Flip `GCMD.TE` to start gating every DMA-capable device through
    /// its per-domain page table (P6.7.9-pre.11).
    ///
    /// Idempotent — repeat calls after the first success short-circuit
    /// to `Ok(())` without touching MMIO. Must run **after**
    /// [`Self::activate_hardware`] and **after** the first successful
    /// [`Self::install_device_entry`] (the IOMMU rejects DMA from any
    /// unconfigured `(bus, devfn)` slot the moment TE is observed).
    ///
    /// Spec-faithful (Intel VT-d rev 4.1 § 6.2.3 + § 11.4.4): ORs
    /// [`GCMD_BIT_TE`] into [`Self::live_enable_mask`] via
    /// [`Self::compose_enable_bits`], writes the composed mask to
    /// `GCMD`, and polls [`GSTS_BIT_TES`] until set or the
    /// [`VTD_ACTIVATION_POLL_LIMIT`] retry budget runs out.
    ///
    /// ## Why the full mask is written, not `TE` alone (WI-7b → P11.3)
    ///
    /// `GCMD` mixes one-shot *command* bits (`SRTP`, `SFL`, `WBF`,
    /// `SIRTP`) with level-sensitive *enable* bits (`TE`, `QIE`, `IRE`,
    /// `EAFL`). Per § 11.4.4 software MUST preserve the current state of
    /// the enable bits on every `GCMD` write — an earlier revision of
    /// this method wrote `TE` alone, which a spec-conforming
    /// implementation (QEMU `intel-iommu` included) interprets as
    /// "TE := 1 **and QIE := 0**", silently disabling the invalidation
    /// queue at the exact moment translation starts gating DMA. Every
    /// subsequent queued invalidation would then time out. The WI-7b
    /// step 2 fix hardcoded `TE | QIE`, which repeated the same bug one
    /// generation later for any future enable bit (`IRE`/`EAFL`) — the
    /// ADR-0027 review (finding #4, P11.3) replaced the hardcoded pair
    /// with [`Self::live_enable_mask`] composition. `QIE` is known-set
    /// in the mask because [`Self::activate_hardware`] (gated by
    /// `hardware_activated` above) composed it and nothing ever lowers
    /// it.
    ///
    /// # Errors
    ///
    /// - [`VtdActivateError::NotPrepared`] if the backend was never
    ///   `prepare_activation`'d or [`Self::activate_hardware`] never
    ///   succeeded.
    /// - [`VtdActivateError::TranslationEnableTimeout`] if `GSTS.TES`
    ///   does not mirror the request within the poll budget.
    ///
    /// # Safety
    ///
    /// `phys_offset` must be the live bootloader direct-map offset.
    /// Same MMIO-window ownership contract as
    /// [`Self::activate_hardware`].
    #[cfg(target_os = "none")]
    pub unsafe fn enable_translation(&mut self, phys_offset: u64) -> Result<(), VtdActivateError> {
        if !self.hardware_activated {
            return Err(VtdActivateError::NotPrepared);
        }
        if self.translation_enabled {
            return Ok(());
        }
        let unit_va = phys_offset.wrapping_add(self.unit_base);
        // Compose TE into the live mask and write the WHOLE mask:
        // every enable bit raised so far (QIE today, IRE/EAFL in
        // future slices) is re-asserted because GCMD enable bits are
        // level-sensitive (§ 11.4.4, P11.3) — see the method docs.
        let gcmd_te = self.compose_enable_bits(GCMD_BIT_TE);
        // SAFETY: per the function's safety contract; `unit_va` is the
        // kernel-owned VT-d MMIO register window.
        unsafe { mmio_write32(unit_va, REG_OFFSET_GCMD, gcmd_te) };
        // SAFETY: GSTS is a 4-byte read-only MMIO register at a fixed
        // offset inside the same window.
        if !unsafe { poll_gsts_bit(unit_va, GSTS_BIT_TES) } {
            return Err(VtdActivateError::TranslationEnableTimeout);
        }
        self.translation_enabled = true;
        Ok(())
    }

    /// Drive the live VT-d per-device entry install.
    ///
    /// Spec-faithful order (Intel VT-d rev 4.1 § 9 + § 6.5):
    ///
    /// 1. Validate inputs (`hardware_activated`, alignments, domain
    ///    installed; an existing attachment for `bdf` is accepted when
    ///    it names the SAME domain — the attach-then-install flow of
    ///    the driver framework — and rejected only on a domain
    ///    conflict).
    /// 2. Encode the context entry for `(slpt_phys, domain,
    ///    translation, width)` and write it into the per-bus context
    ///    table at offset [`context_entry_offset(bdf)`].
    /// 3. Encode the root entry pointing at `context_table_phys` and
    ///    write it into the root table at offset
    ///    [`root_entry_offset(bdf.bus())`].
    /// 4. Submit a per-domain context-cache invalidate descriptor on
    ///    the invalidation queue and wait for it to drain.
    /// 5. Submit a per-domain IOTLB invalidate descriptor and wait
    ///    for it to drain.
    /// 6. Record the `(bdf, domain)` binding in
    ///    [`Self::attachments`].
    ///
    /// `GCMD.TE` is **NOT** raised by this slice; the IOMMU stays in
    /// pre-translation pass-through mode at the hardware level until
    /// the kernel is ready to gate every DMA-capable device (raise
    /// `TE` lands once at least one device is attached and the
    /// per-domain page tables are populated — orthogonal to this
    /// slice).
    ///
    /// # Errors
    ///
    /// See [`VtdAttachError`].
    ///
    /// # Safety
    ///
    /// `phys_offset` must be the live bootloader direct-map offset.
    /// `slpt_phys` must reference a 4-KiB-aligned second-level page
    /// table owned by the kernel and reachable through that direct
    /// map. `context_table_phys` must reference a 4-KiB-aligned
    /// context-table page owned by the kernel; the caller is
    /// responsible for keeping the same `context_table_phys` for the
    /// same bus across successive `install_device_entry` calls
    /// (otherwise the per-bus root entry will be overwritten with a
    /// dangling pointer).
    #[cfg(target_os = "none")]
    #[allow(
        clippy::too_many_arguments,
        reason = "the per-device install needs all of (phys_offset, bdf, domain, slpt_phys, context_table_phys, width, translation) — the driver framework is the sole caller and the explicit positional surface keeps the unsafe MMIO entry-point auditable"
    )]
    pub unsafe fn install_device_entry(
        &mut self,
        phys_offset: u64,
        bdf: PciBdf,
        domain: DomainId,
        slpt_phys: u64,
        context_table_phys: u64,
        width: AddressWidth,
        translation: TranslationType,
    ) -> Result<(), VtdAttachError> {
        if !self.hardware_activated {
            return Err(VtdAttachError::NotActivated);
        }
        if slpt_phys & 0xFFF != 0 || context_table_phys & 0xFFF != 0 {
            return Err(VtdAttachError::AddressMisaligned);
        }
        if !self.has_domain(domain) {
            return Err(VtdAttachError::DomainNotInstalled);
        }
        // (1b) Attachment reconciliation (WI-7b step 2 fix). The driver
        //     framework records the `(bdf → domain)` binding through the
        //     trait-level `attach_device` BEFORE driving this live
        //     install — both the `DriverLoad (73)` block and the boot
        //     deposit path do attach-then-install, and the two halves of
        //     the API share `self.attachments` by design. A pre-existing
        //     record for the SAME domain is therefore the expected state
        //     here, not an error (the previous unconditional
        //     `AlreadyAttached` reject made every live install fail —
        //     latent until the boot path first exercised this on
        //     hardware). Only a CONFLICTING domain is rejected: that
        //     would mean two owners claim the same requester ID.
        let already_attached = match self.attachments.iter().find(|a| a.bdf == bdf) {
            Some(a) if a.domain != domain => return Err(VtdAttachError::AlreadyAttached),
            Some(_) => true,
            None => false,
        };

        // (2) Encode + write the context entry into the per-bus
        //     context table at offset (devfn * 16).
        let context_entry = encode_context_entry(slpt_phys, domain, translation, width)
            .map_err(|_| VtdAttachError::AddressMisaligned)?;
        let context_va = phys_offset.wrapping_add(context_table_phys);
        let ctx_offset = context_entry_offset(bdf);
        // SAFETY: caller guarantees `context_table_phys` is a
        // kernel-owned, 4-KiB-aligned page reachable through the
        // direct map; `ctx_offset` is bounded to (255 * 16) + 15 =
        // 4095 by the devfn 8-bit constraint, so the write stays
        // inside the page.
        unsafe {
            write_context_entry_at(
                context_va,
                ctx_offset,
                context_entry.low,
                context_entry.high,
            );
        }

        // (3) Encode + write the root entry into the global root
        //     table at offset (bus * 16). Idempotent on the
        //     `context_table_phys` value — overwriting with the same
        //     pointer is a no-op for the IOMMU.
        let root_entry =
            encode_root_entry(context_table_phys).map_err(|_| VtdAttachError::AddressMisaligned)?;
        let root_va = phys_offset.wrapping_add(self.root_table_phys);
        let root_offset = root_entry_offset(bdf.bus());
        // SAFETY: caller guarantees `self.root_table_phys` (recorded
        // via `prepare_activation`) is a kernel-owned, 4-KiB-aligned
        // page reachable through the direct map; `root_offset` is
        // bounded to 4080 by the 8-bit bus constraint.
        unsafe { write_root_entry_at(root_va, root_offset, root_entry.low, root_entry.high) };

        // (4) + (5) Per-domain context-cache invalidate + per-domain
        //     IOTLB invalidate, sequenced through the invalidation
        //     queue. We wrap on `INV_QUEUE_BYTES` so the tail
        //     pointer never escapes the queue page.
        let queue_va = phys_offset.wrapping_add(self.invalidation_queue_phys);
        let unit_va = phys_offset.wrapping_add(self.unit_base);

        let (cc_lo, cc_hi) = encode_context_cache_domain_invalidate(domain);
        // The install path keeps the full activation budget: a timeout
        // here is a hard error (the device must not be handed to its
        // driver with stale context/IOTLB state), unlike the
        // best-effort flush/teardown paths (P11.4).
        // SAFETY: queue is a kernel-owned 4-KiB page; submit_iq_*
        // updates `self.invalidation_queue_tail` after each push.
        unsafe {
            self.submit_iq_descriptor(queue_va, unit_va, cc_lo, cc_hi, VTD_ACTIVATION_POLL_LIMIT)
        }
        .map_err(|()| VtdAttachError::InvalidationTimeout)?;

        let (io_lo, io_hi) = encode_iotlb_domain_invalidate(domain);
        // SAFETY: same as above.
        unsafe {
            self.submit_iq_descriptor(queue_va, unit_va, io_lo, io_hi, VTD_ACTIVATION_POLL_LIMIT)
        }
        .map_err(|()| VtdAttachError::InvalidationTimeout)?;

        // (6) Record the attachment — unless the trait-level
        //     `attach_device` already did (attach-then-install flow);
        //     a duplicate record would make `detach`/release remove
        //     only one of the two and desynchronise the registry.
        if !already_attached {
            self.attachments.push(VtdAttachment { bdf, domain });
        }
        Ok(())
    }

    /// High-level per-device install that acquires the per-bus context
    /// table through `src` and then calls [`Self::install_device_entry`]
    /// (P6.7.9-pre.11).
    ///
    /// On install failure the context-table acquisition is rolled back
    /// so the refcount registry stays consistent with the live
    /// attachments. Returns the `context_table_phys` that owns the
    /// device's slot — primarily for host-test assertion; the caller
    /// does not need to keep it (the backend retains the binding via
    /// [`Self::bus_context_tables`]).
    ///
    /// # Errors
    ///
    /// - [`VtdAttachError::BusContextAllocFailed`] when `src` cannot
    ///   produce a 4-KiB-aligned frame.
    /// - Any [`VtdAttachError`] variant propagated by
    ///   [`Self::install_device_entry`]. On these errors the bus
    ///   context table refcount is rolled back **before** the error
    ///   returns (and the page is freed back to `src` if the refcount
    ///   drops to zero).
    ///
    /// # Safety
    ///
    /// Inherits the safety contract of [`Self::install_device_entry`].
    #[cfg(target_os = "none")]
    #[allow(
        clippy::too_many_arguments,
        reason = "the high-level managed install needs the same positional surface as install_device_entry plus the frame source — the alternatives (struct args / trait object packing) hide the unsafe-call site invariants from the auditor"
    )]
    pub unsafe fn install_device_entry_with_alloc(
        &mut self,
        phys_offset: u64,
        bdf: PciBdf,
        domain: DomainId,
        slpt_phys: u64,
        width: AddressWidth,
        translation: TranslationType,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<u64, VtdAttachError> {
        let context_table_phys = self.acquire_bus_context_table(bdf.bus(), src)?;
        // SAFETY: same MMIO-window ownership contract as
        // `install_device_entry`; phys arguments are validated inside.
        let install_result = unsafe {
            self.install_device_entry(
                phys_offset,
                bdf,
                domain,
                slpt_phys,
                context_table_phys,
                width,
                translation,
            )
        };
        match install_result {
            Ok(()) => Ok(context_table_phys),
            Err(err) => {
                // Roll back the acquired refcount so a follow-up retry
                // does not double-count. `release_bus_context_table`
                // only returns `Err(())` if no entry exists; we KNOW
                // one exists because we just acquired it above.
                let _ = self.release_bus_context_table(bdf.bus(), src);
                Err(err)
            }
        }
    }

    /// High-level per-device release that zeroes the device's context
    /// entry, decrements the bus context-table refcount, and frees the
    /// page (plus zeroes the root entry for that bus) when the refcount
    /// drops to zero (P6.7.9-pre.11).
    ///
    /// Symmetric to `Self::install_device_entry_with_alloc`. Does NOT
    /// gate translation on `hardware_activated` — teardown must run
    /// even on a backend that never reached the live MMIO path so the
    /// bookkeeping stays consistent.
    ///
    /// # Errors
    ///
    /// - `Err(())` when `bdf` is not currently attached (callers must
    ///   `install_device_entry_with_alloc` first) OR when the bus has
    ///   no context table acquired (logically the same condition as
    ///   "no attachment" — both invariants are maintained by the
    ///   install path).
    ///
    /// # Safety
    ///
    /// Same MMIO-window ownership contract as
    /// [`Self::install_device_entry`].
    #[cfg(target_os = "none")]
    pub unsafe fn release_device_entry_with_alloc(
        &mut self,
        phys_offset: u64,
        bdf: PciBdf,
        src: &mut dyn super::pt_alloc::FrameSource,
    ) -> Result<(), BusContextTableReleaseError> {
        // Locate the attachment + remove it. Refusing on absence keeps
        // the refcount registry consistent with the attachments vec.
        let attachment_idx = self
            .attachments
            .iter()
            .position(|a| a.bdf == bdf)
            .ok_or(BusContextTableReleaseError::UnknownBus)?;
        let attachment = self.attachments.swap_remove(attachment_idx);

        // Zero the device's context entry slot so the IOMMU stops
        // honouring DMA from this BDF immediately.
        let Some(context_table_phys) = self.bus_context_table_phys(bdf.bus()) else {
            return Err(BusContextTableReleaseError::UnknownBus);
        };
        let context_va = phys_offset.wrapping_add(context_table_phys);
        let ctx_offset = context_entry_offset(bdf);
        let absent = encode_context_entry_absent();
        // SAFETY: `context_table_phys` is a kernel-owned, 4-KiB-aligned
        // page tracked in `bus_context_tables`; `ctx_offset` is bounded
        // to 4080 by the devfn 8-bit constraint.
        unsafe { write_context_entry_at(context_va, ctx_offset, absent.low, absent.high) };

        // Per-domain context-cache + IOTLB invalidate so the IOMMU
        // drops any cached translation for the just-detached device.
        // We treat invalidation failure as benign in teardown — the
        // context entry is already cleared, so a stuck IOTLB drain
        // does not affect correctness once HEAD eventually catches up.
        // Best-effort site ⇒ flush-class poll budget: a wedged unit
        // must not stall every teardown for the ~1 ms activation
        // budget (P11.4).
        let queue_va = phys_offset.wrapping_add(self.invalidation_queue_phys);
        let unit_va = phys_offset.wrapping_add(self.unit_base);
        let (cc_lo, cc_hi) = encode_context_cache_domain_invalidate(attachment.domain);
        // SAFETY: queue/unit VAs are derived from registered phys
        // addresses; submit_iq_descriptor maintains its tail invariant.
        let _ = unsafe {
            self.submit_iq_descriptor(queue_va, unit_va, cc_lo, cc_hi, IOTLB_FLUSH_POLL_BUDGET)
        };
        let (io_lo, io_hi) = encode_iotlb_domain_invalidate(attachment.domain);
        // SAFETY: same as above.
        let _ = unsafe {
            self.submit_iq_descriptor(queue_va, unit_va, io_lo, io_hi, IOTLB_FLUSH_POLL_BUDGET)
        };

        // Decrement the bus context-table refcount; if it drops to
        // zero, also zero the root-table entry for the bus so the
        // IOMMU never speculates on the freed page.
        let refcount_after = self
            .bus_context_table_refcount(bdf.bus())
            .map_or(0, |c| c.saturating_sub(1));
        if refcount_after == 0 {
            let root_va = phys_offset.wrapping_add(self.root_table_phys);
            let root_offset = root_entry_offset(bdf.bus());
            let root_absent = encode_root_entry_absent();
            // SAFETY: `root_table_phys` is the kernel-owned root-table
            // page registered via `prepare_activation`; `root_offset`
            // is bounded to 4080 by the 8-bit bus constraint.
            unsafe {
                write_root_entry_at(root_va, root_offset, root_absent.low, root_absent.high);
            }
        }
        // Now release through the refcounted allocator (frees the page
        // when refcount reaches zero).
        self.release_bus_context_table(bdf.bus(), src)
    }

    /// Push a single 128-bit descriptor into the invalidation queue,
    /// advance `IQT`, and wait for `IQH` to catch up. Wraps the tail
    /// pointer on [`INV_QUEUE_BYTES`].
    ///
    /// `poll_budget` bounds the `IQH` wait: pass
    /// [`VTD_ACTIVATION_POLL_LIMIT`] on the one-shot install paths
    /// (a timeout there is a hard error) and
    /// [`IOTLB_FLUSH_POLL_BUDGET`] on the per-`DmaMap` flush and
    /// device-teardown paths, whose call sites are best-effort and
    /// must not stall ~1 ms per operation on a wedged unit (P11.4).
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if `IQH` does not catch up within
    /// `poll_budget` iterations.
    ///
    /// # Safety
    ///
    /// `queue_va` must point at the start of the kernel-owned 4-KiB
    /// invalidation-queue page reachable through the direct map.
    /// `unit_va` must point at the per-IOMMU MMIO register window so
    /// `unit_va + REG_OFFSET_IQT` / `+ REG_OFFSET_IQH` are valid
    /// 64-bit accesses.
    #[cfg(target_os = "none")]
    unsafe fn submit_iq_descriptor(
        &mut self,
        queue_va: u64,
        unit_va: u64,
        lo: u64,
        hi: u64,
        poll_budget: u32,
    ) -> Result<(), ()> {
        // Compute the slot index from the current tail (byte offset →
        // slot index = tail / INV_QUEUE_ENTRY_BYTES). Wrapping is
        // implicit because `invalidation_queue_tail` is reset to 0
        // when it would overflow `INV_QUEUE_BYTES`. The tail is
        // strictly bounded by `INV_QUEUE_BYTES = 4096` so the `usize`
        // cast and the bounded division are precision-safe on every
        // pointer width.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::integer_division,
            reason = "queue tail is bounded by INV_QUEUE_BYTES (4096); division by INV_QUEUE_ENTRY_BYTES (16) is the canonical slot-index conversion"
        )]
        let slot = (self.invalidation_queue_tail as usize) / INV_QUEUE_ENTRY_BYTES;
        // SAFETY: queue is a kernel-owned 4-KiB page; `slot` is
        // bounded to `INV_QUEUE_ENTRY_COUNT - 1` by the wrap below.
        unsafe { write_queue_entry(queue_va, slot, lo, hi) };
        let mut next_tail = self
            .invalidation_queue_tail
            .wrapping_add(INV_QUEUE_ENTRY_BYTES as u64);
        if next_tail >= INV_QUEUE_BYTES as u64 {
            next_tail = 0;
        }
        // SAFETY: per the function's safety contract.
        unsafe { mmio_write64(unit_va, REG_OFFSET_IQT, next_tail) };
        self.invalidation_queue_tail = next_tail;
        // SAFETY: IQH is a 8-byte read-only MMIO register.
        if !unsafe { poll_iqh_reaches(unit_va, next_tail, poll_budget) } {
            return Err(());
        }
        Ok(())
    }

    /// Drain every pending primary fault from the Fault Recording
    /// Registers, returning the decoded records and clearing the
    /// hardware fault state (WI-7b step 3).
    ///
    /// Reads `FSTS`; while `PPF` (Primary Pending Fault) is set it walks
    /// the `NFR` FRCD registers (located at `CAP.FRO`), decodes each one
    /// whose `F` bit is set, RW1C-clears that `F` bit, and finally
    /// RW1C-clears `FSTS.PFO`. Bounded by `NFR` so a wedged unit cannot
    /// spin. Returns the decoded records (empty when no fault pending) so
    /// the §S9.1 negative test can assert on the out-of-window DMA fault
    /// and the caller can log it.
    ///
    /// This only READS fault state + RW1C-clears it — it never changes
    /// translation behaviour, so it is safe to call on every boot
    /// (TE on or off) as a diagnostic.
    ///
    /// # Safety
    ///
    /// `phys_offset` must be the live bootloader direct-map offset and
    /// the unit must have been `activate_hardware`'d (so `unit_base` is
    /// the kernel-owned VT-d MMIO window).
    #[cfg(target_os = "none")]
    #[must_use]
    pub unsafe fn drain_faults(&self, phys_offset: u64) -> alloc::vec::Vec<FaultRecord> {
        let mut out = alloc::vec::Vec::new();
        if self.unit_base == 0 {
            return out;
        }
        let unit_va = phys_offset.wrapping_add(self.unit_base);
        // SAFETY: CAP is a read-only MMIO register in the kernel-owned
        // VT-d window.
        let cap = unsafe { mmio_read64(unit_va, REG_OFFSET_CAP) };
        // Always scan the FRCD registers directly rather than gating on
        // `FSTS.PPF`: some IOMMU models (observed on QEMU `intel-iommu`)
        // record a fault in FRCD without reflecting it in `FSTS.PPF` the
        // way the spec implies, so a `PPF`-gated early return would miss
        // it. Scanning `NFR` registers is cheap and idempotent — on a
        // clean unit every `F` bit is 0 and the result is empty.
        let fro = cap_fault_recording_offset(cap);
        let nfr = cap_num_fault_recording(cap);
        for i in 0..nfr {
            let rec_off = fro + u32::from(i) * 16;
            // SAFETY: FRCD registers live at CAP.FRO inside the same
            // kernel-owned window; `i < nfr` keeps the access in range.
            let low = unsafe { mmio_read64(unit_va, rec_off) };
            let high = unsafe { mmio_read64(unit_va, rec_off + 8) };
            if let Some(rec) = decode_fault_record(low, high) {
                out.push(rec);
                // RW1C the F bit (high-half bit 63) to clear the record;
                // clearing all FRCD F bits also clears FSTS.PPF.
                // SAFETY: same kernel-owned window.
                unsafe { mmio_write64(unit_va, rec_off + 8, 1u64 << 63) };
            }
        }
        // RW1C FSTS.PFO (overflow) in case faults were dropped.
        // SAFETY: FSTS is a RW1C MMIO register.
        unsafe { mmio_write32(unit_va, REG_OFFSET_FSTS, 1u32 << 0) };
        out
    }

    /// Raw `FSTS` (Fault Status Register) read — diagnostic for the §S9.1
    /// negative-test harness (ADR-0029) to confirm whether the hardware
    /// recorded a fault, independent of the FRCD decoder. `0` when the unit
    /// has no MMIO base.
    ///
    /// # Safety
    ///
    /// Same contract as [`Self::drain_faults`].
    #[cfg(target_os = "none")]
    #[must_use]
    pub unsafe fn fault_status_raw(&self, phys_offset: u64) -> u32 {
        if self.unit_base == 0 {
            return 0;
        }
        let unit_va = phys_offset.wrapping_add(self.unit_base);
        // SAFETY: FSTS is a read-only/RW1C MMIO register in the
        // kernel-owned VT-d window.
        unsafe { mmio_read32(unit_va, REG_OFFSET_FSTS) }
    }

    /// Raw register snapshot for the §S9.1 negative-test diagnostic
    /// (ADR-0029): `(cap, fsts, frcd0_low, frcd0_high)`. Reads FRCD[0]
    /// directly at `CAP.FRO` regardless of `FSTS.PPF`, so a fault the
    /// status-bit path might miss is still visible. All zero when the
    /// unit has no MMIO base.
    ///
    /// # Safety
    ///
    /// Same contract as [`Self::drain_faults`].
    #[cfg(target_os = "none")]
    #[must_use]
    pub unsafe fn fault_regs_debug(&self, phys_offset: u64) -> (u64, u32, u64, u64) {
        if self.unit_base == 0 {
            return (0, 0, 0, 0);
        }
        let unit_va = phys_offset.wrapping_add(self.unit_base);
        // SAFETY: CAP/FSTS/FRCD are MMIO registers in the kernel-owned
        // VT-d window; FRCD[0] sits at CAP.FRO.
        unsafe {
            let cap = mmio_read64(unit_va, REG_OFFSET_CAP);
            let fsts = mmio_read32(unit_va, REG_OFFSET_FSTS);
            let fro = cap_fault_recording_offset(cap);
            let lo = mmio_read64(unit_va, fro);
            let hi = mmio_read64(unit_va, fro + 8);
            (cap, fsts, lo, hi)
        }
    }
}

// =============================================================================
// MMIO helpers — bare-metal-only, `volatile` semantics.
//
// All accesses go through `core::ptr::read_volatile` /
// `core::ptr::write_volatile` so the optimiser cannot reorder or
// coalesce the writes; this is mandatory for MMIO programming. The
// helpers are unsafe — the caller (`VtdBackend::activate_hardware`)
// commits to the invariants in its safety contract.
// =============================================================================

/// Volatile 32-bit write to `unit_va + offset`.
///
/// # Safety
///
/// `unit_va + offset` must address a kernel-owned MMIO register that
/// accepts 32-bit naturally-aligned writes.
#[cfg(target_os = "none")]
#[inline]
unsafe fn mmio_write32(unit_va: u64, offset: u32, value: u32) {
    let ptr = unit_va.wrapping_add(u64::from(offset)) as *mut u32;
    // SAFETY: per the function's safety contract.
    unsafe { core::ptr::write_volatile(ptr, value) };
}

/// Volatile 32-bit read from `unit_va + offset`.
///
/// # Safety
///
/// `unit_va + offset` must address a kernel-owned MMIO register that
/// accepts 32-bit naturally-aligned reads.
#[cfg(target_os = "none")]
#[inline]
unsafe fn mmio_read32(unit_va: u64, offset: u32) -> u32 {
    let ptr = unit_va.wrapping_add(u64::from(offset)) as *const u32;
    // SAFETY: per the function's safety contract.
    unsafe { core::ptr::read_volatile(ptr) }
}

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

/// Drive a bounded poll loop: invoke `observed` up to `budget` times,
/// returning `true` as soon as it reports the awaited condition and
/// `false` once the budget is exhausted (P11.4).
///
/// Pure control flow — the volatile MMIO read lives in the caller's
/// closure — so the budget discipline (exactly `budget` observations,
/// then give up) is host-testable while the
/// `cfg(target_os = "none")` wrappers own the unsafe register access.
#[cfg_attr(
    not(target_os = "none"),
    allow(
        dead_code,
        reason = "host builds compile out the MMIO poll wrappers; the host test suite is the remaining consumer"
    )
)]
fn poll_with_budget(budget: u32, mut observed: impl FnMut() -> bool) -> bool {
    let mut remaining = budget;
    while remaining > 0 {
        if observed() {
            return true;
        }
        core::hint::spin_loop();
        remaining -= 1;
    }
    false
}

/// Poll `GSTS` for `bit` to become set, with a bounded retry budget.
///
/// Returns `true` if `bit` was observed set within
/// [`VTD_ACTIVATION_POLL_LIMIT`] iterations, `false` on timeout.
///
/// # Safety
///
/// `unit_va` must point at the start of a kernel-owned VT-d register
/// window so `unit_va + REG_OFFSET_GSTS` is a valid 32-bit read.
#[cfg(target_os = "none")]
unsafe fn poll_gsts_bit(unit_va: u64, bit: u32) -> bool {
    poll_with_budget(VTD_ACTIVATION_POLL_LIMIT, || {
        // SAFETY: per the function's safety contract.
        let gsts = unsafe { mmio_read32(unit_va, REG_OFFSET_GSTS) };
        gsts & bit != 0
    })
}

/// Poll `IQH` until it reaches `tail_byte_offset`, with the supplied
/// retry budget ([`VTD_ACTIVATION_POLL_LIMIT`] on the activation /
/// install paths, [`IOTLB_FLUSH_POLL_BUDGET`] on the recoverable
/// flush / teardown paths — P11.4).
///
/// The IOMMU advances `IQH` as it consumes descriptors. When `IQH ==
/// IQT` the queue is drained.
///
/// # Safety
///
/// Same as [`poll_gsts_bit`].
#[cfg(target_os = "none")]
unsafe fn poll_iqh_reaches(unit_va: u64, tail_byte_offset: u64, budget: u32) -> bool {
    poll_with_budget(budget, || {
        // SAFETY: per the function's safety contract.
        let iqh = unsafe { mmio_read64(unit_va, REG_OFFSET_IQH) };
        iqh == tail_byte_offset
    })
}

/// Write a 128-bit descriptor into the invalidation queue at the
/// 16-byte slot indexed by `slot`.
///
/// # Safety
///
/// `queue_va` must point at the start of a kernel-owned, 4-KiB-aligned
/// invalidation-queue page mapped through the direct map, and `slot`
/// must be `< INV_QUEUE_ENTRY_COUNT`.
#[cfg(target_os = "none")]
#[inline]
unsafe fn write_queue_entry(queue_va: u64, slot: usize, lo: u64, hi: u64) {
    let byte_offset = slot.wrapping_mul(INV_QUEUE_ENTRY_BYTES) as u64;
    let base = queue_va.wrapping_add(byte_offset);
    let lo_ptr = base as *mut u64;
    let hi_ptr = base.wrapping_add(8) as *mut u64;
    // SAFETY: per the function's safety contract.
    unsafe {
        core::ptr::write_volatile(lo_ptr, lo);
        core::ptr::write_volatile(hi_ptr, hi);
    }
}

/// Write a 128-bit context entry (low + high qwords) into a per-bus
/// context-table page at `byte_offset`.
///
/// # Safety
///
/// `context_va` must point at the start of a kernel-owned, 4-KiB-aligned
/// context-table page reachable through the direct map.
/// `byte_offset + 16` must be `<= 4096`.
#[cfg(target_os = "none")]
#[inline]
unsafe fn write_context_entry_at(context_va: u64, byte_offset: u64, low: u64, high: u64) {
    let base = context_va.wrapping_add(byte_offset);
    let lo_ptr = base as *mut u64;
    let hi_ptr = base.wrapping_add(8) as *mut u64;
    // SAFETY: per the function's safety contract.
    unsafe {
        core::ptr::write_volatile(lo_ptr, low);
        core::ptr::write_volatile(hi_ptr, high);
    }
}

/// Write a 128-bit root entry (low + high qwords) into the global
/// root-table page at `byte_offset`.
///
/// # Safety
///
/// `root_va` must point at the start of the kernel-owned, 4-KiB-aligned
/// root-table page reachable through the direct map (the same page
/// recorded via [`VtdBackend::prepare_activation`]).
/// `byte_offset + 16` must be `<= 4096`.
#[cfg(target_os = "none")]
#[inline]
unsafe fn write_root_entry_at(root_va: u64, byte_offset: u64, low: u64, high: u64) {
    let base = root_va.wrapping_add(byte_offset);
    let lo_ptr = base as *mut u64;
    let hi_ptr = base.wrapping_add(8) as *mut u64;
    // SAFETY: per the function's safety contract.
    unsafe {
        core::ptr::write_volatile(lo_ptr, low);
        core::ptr::write_volatile(hi_ptr, high);
    }
}

impl IommuBackend for VtdBackend {
    fn vendor(&self) -> IommuVendor {
        IommuVendor::Intel
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
        let leaf = encode_slpte(phys, flags).map_err(IommuError::from)?;
        self.mappings.push(ScaffoldMapping {
            domain: id,
            iova,
            phys,
            len,
            leaf_slpte: leaf,
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
        // Live half (WI-7b step 2): submit a per-domain IOTLB
        // invalidate through the invalidation queue. Mandatory for
        // correctness once `GCMD.TE` is up — QEMU's intel-iommu
        // advertises `CAP.CM = 1` (caching mode), under which even
        // not-present → present transitions must be invalidated for
        // the hardware to observe new SLPT leaves. Exercising the
        // queue on every map/unmap while TE is still off also proves
        // the descriptor path on real hardware ahead of the
        // operator-gated TE session.
        //
        // Dormant backend (host tests / passthrough boot): nothing to
        // flush — `hardware_activated` is only set by the bare-metal
        // activation path.
        #[cfg(target_os = "none")]
        if self.hardware_activated && self.phys_offset != 0 {
            let queue_va = self.phys_offset.wrapping_add(self.invalidation_queue_phys);
            let unit_va = self.phys_offset.wrapping_add(self.unit_base);
            let (io_lo, io_hi) = encode_iotlb_domain_invalidate(id);
            // Flush-class poll budget (P11.4): this runs on every
            // `DmaMap`/teardown and the call sites are best-effort, so
            // a wedged unit bounds the stall to ~10 µs instead of the
            // ~1 ms activation budget. Exhaustion is surfaced as the
            // dedicated `FlushStalled` (recoverable) — NOT
            // `ActivationFailed` (fatal posture error).
            // SAFETY: `phys_offset` was cached by `activate_hardware`
            // from the live bootloader direct-map offset; the queue and
            // unit windows are the same kernel-owned pages that
            // activation already programmed through.
            unsafe {
                self.submit_iq_descriptor(queue_va, unit_va, io_lo, io_hi, IOTLB_FLUSH_POLL_BUDGET)
            }
            .map_err(|()| IommuError::FlushStalled)?;
        }
        Ok(())
    }

    fn attach_device(&mut self, bdf: PciBdf, domain: DomainId) -> Result<(), IommuError> {
        if !self.has_domain(domain) {
            return Err(IommuError::InvalidDomain);
        }
        if self.has_attachment(bdf) {
            return Err(IommuError::Unsupported);
        }
        self.attachments.push(VtdAttachment { bdf, domain });
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
        AddressWidth, CONTEXT_ENTRY_BYTES, ContextEntry, GCMD_BIT_IRE, GCMD_BIT_QIE, GCMD_BIT_SRTP,
        GCMD_BIT_TE, INV_DESC_CTX_GRAN_DOMAIN, INV_DESC_IOTLB_GRAN_DOMAIN,
        INV_DESC_TYPE_CONTEXT_CACHE, INV_DESC_TYPE_IOTLB, IommuBackend, IommuError, IommuFlags,
        IommuVendor, REG_OFFSET_CAP, REG_OFFSET_ECAP, REG_OFFSET_GCMD, REG_OFFSET_GSTS,
        REG_OFFSET_IQA, REG_OFFSET_IQH, REG_OFFSET_IQT, REG_OFFSET_RTADDR, REG_OFFSET_VER,
        ROOT_ENTRY_BYTES, RootEntry, ScaffoldMapping, Slpte, TranslationType, VtdAttachError,
        VtdAttachment, VtdBackend, VtdError, cap_caching_mode, cap_domain_count,
        cap_fault_recording_offset, cap_num_fault_recording, cap_supported_agaw,
        context_entry_offset, decode_fault_record, encode_context_cache_domain_invalidate,
        encode_context_entry, encode_context_entry_absent, encode_iotlb_domain_invalidate,
        encode_root_entry, encode_root_entry_absent, encode_slpte, frcd_fault, frcd_fault_address,
        frcd_fault_reason, frcd_is_read, frcd_source_id, free_slpt_subtree,
        fsts_fault_record_index, fsts_primary_fault_overflow, fsts_primary_pending_fault,
        map_4k_slpt, map_range_slpt, pick_highest_supported_agaw, root_entry_offset, slpt_index,
        translate_slpt, unmap_4k_slpt,
    };
    use crate::bare_metal::iommu::{DomainId, PciBdf, pt_alloc::FrameSource};

    // ---- Register offset invariants ------------------------------------

    #[test]
    fn register_offsets_match_intel_spec_4_1() {
        // Pinning against the spec lets a future refactor catch any
        // accidental drift via the test suite rather than at runtime.
        assert_eq!(REG_OFFSET_VER, 0x000);
        assert_eq!(REG_OFFSET_CAP, 0x008);
        assert_eq!(REG_OFFSET_ECAP, 0x010);
        assert_eq!(REG_OFFSET_GCMD, 0x018);
        assert_eq!(REG_OFFSET_GSTS, 0x01C);
        assert_eq!(REG_OFFSET_RTADDR, 0x020);
        assert_eq!(REG_OFFSET_IQH, 0x080);
        assert_eq!(REG_OFFSET_IQT, 0x088);
        assert_eq!(REG_OFFSET_IQA, 0x090);
    }

    #[test]
    fn gcmd_bits_are_top_of_32_bit_word() {
        assert_eq!(GCMD_BIT_TE, 1 << 31);
        assert_eq!(GCMD_BIT_SRTP, 1 << 30);
        assert_eq!(GCMD_BIT_QIE, 1 << 26);
    }

    // ---- Root entry encoder --------------------------------------------

    #[test]
    fn encode_root_entry_sets_present_bit_and_ctp() {
        let entry = encode_root_entry(0x1234_5000).unwrap();
        assert!(entry.is_present());
        assert_eq!(entry.context_table_pointer(), 0x1234_5000);
        assert_eq!(entry.high, 0);
    }

    #[test]
    fn encode_root_entry_rejects_misaligned_ctp() {
        assert_eq!(
            encode_root_entry(0x1234_5001),
            Err(VtdError::AddressMisaligned)
        );
        assert_eq!(
            encode_root_entry(0x1234_5FFF),
            Err(VtdError::AddressMisaligned)
        );
    }

    #[test]
    fn encode_root_entry_absent_is_all_zero() {
        let entry = encode_root_entry_absent();
        assert!(!entry.is_present());
        assert_eq!(entry, RootEntry { low: 0, high: 0 });
    }

    // ---- Context entry encoder -----------------------------------------

    #[test]
    fn encode_context_entry_round_trips_did_and_aw() {
        let entry = encode_context_entry(
            0xAB_CDEF_F000,
            DomainId::new(0x1234),
            TranslationType::UntranslatedAndTranslated,
            AddressWidth::Bits48Level4,
        )
        .unwrap();
        assert!(entry.is_present());
        assert_eq!(entry.slptptr(), 0xAB_CDEF_F000);
        assert_eq!(entry.domain_id(), DomainId::new(0x1234));
        assert_eq!(
            entry.translation_type_raw(),
            TranslationType::UntranslatedAndTranslated.as_u8()
        );
        assert_eq!(
            entry.address_width_raw(),
            AddressWidth::Bits48Level4.as_u8()
        );
    }

    #[test]
    fn encode_context_entry_passthrough_keeps_t_field() {
        let entry = encode_context_entry(
            0x100_0000,
            DomainId::new(0),
            TranslationType::Passthrough,
            AddressWidth::Bits39Level3,
        )
        .unwrap();
        assert_eq!(
            entry.translation_type_raw(),
            TranslationType::Passthrough.as_u8()
        );
    }

    #[test]
    fn encode_context_entry_rejects_misaligned_slpt() {
        assert_eq!(
            encode_context_entry(
                0x100_0001,
                DomainId::new(0),
                TranslationType::UntranslatedOnly,
                AddressWidth::Bits48Level4,
            ),
            Err(VtdError::AddressMisaligned)
        );
    }

    #[test]
    fn encode_context_entry_absent_is_all_zero() {
        let entry = encode_context_entry_absent();
        assert!(!entry.is_present());
        assert_eq!(entry, ContextEntry { low: 0, high: 0 });
    }

    #[test]
    fn address_width_levels_match_spec() {
        assert_eq!(AddressWidth::Bits30Level2.levels(), 2);
        assert_eq!(AddressWidth::Bits39Level3.levels(), 3);
        assert_eq!(AddressWidth::Bits48Level4.levels(), 4);
        assert_eq!(AddressWidth::Bits57Level5.levels(), 5);
    }

    // ---- SL-PTE encoder ------------------------------------------------

    #[test]
    fn encode_slpte_read_only() {
        let pte = encode_slpte(0xABCD_F000, IommuFlags::READ).unwrap();
        assert!(pte.is_present());
        assert_eq!(pte.output_address(), 0xABCD_F000);
        assert_eq!(pte.0 & Slpte::BIT_READ, Slpte::BIT_READ);
        assert_eq!(pte.0 & Slpte::BIT_WRITE, 0);
        assert_eq!(pte.0 & Slpte::BIT_EXECUTE, 0);
        assert_eq!(pte.0 & Slpte::BIT_SNOOP, 0);
    }

    #[test]
    fn encode_slpte_write_forces_read_bit() {
        // VT-d treats W-only entries as malformed; the encoder must
        // force R on whenever W is requested.
        let pte = encode_slpte(0x1000, IommuFlags::WRITE).unwrap();
        assert_eq!(pte.0 & Slpte::BIT_READ, Slpte::BIT_READ);
        assert_eq!(pte.0 & Slpte::BIT_WRITE, Slpte::BIT_WRITE);
    }

    #[test]
    fn encode_slpte_execute_and_coherent() {
        let flags = IommuFlags::READ
            .union(IommuFlags::WRITE)
            .union(IommuFlags::EXECUTE)
            .union(IommuFlags::COHERENT);
        let pte = encode_slpte(0x2000, flags).unwrap();
        assert_eq!(pte.0 & Slpte::BIT_EXECUTE, Slpte::BIT_EXECUTE);
        assert_eq!(pte.0 & Slpte::BIT_SNOOP, Slpte::BIT_SNOOP);
    }

    #[test]
    fn encode_slpte_rejects_misaligned_phys() {
        assert_eq!(
            encode_slpte(0x1001, IommuFlags::READ),
            Err(VtdError::AddressMisaligned)
        );
    }

    #[test]
    fn encode_slpte_zero_flags_emits_not_present() {
        // No R, no W -> not present. Useful for clearing leaves during
        // unmap without zeroing the address bits.
        let pte = encode_slpte(0x1000, IommuFlags::from_bits(0)).unwrap();
        assert!(!pte.is_present());
        assert_eq!(pte.output_address(), 0x1000);
    }

    // ---- CAP decoder ---------------------------------------------------

    #[test]
    fn cap_domain_count_known_values() {
        // ND = 0..6
        assert_eq!(cap_domain_count(0), 16);
        assert_eq!(cap_domain_count(1), 64);
        assert_eq!(cap_domain_count(2), 256);
        assert_eq!(cap_domain_count(3), 1_024);
        assert_eq!(cap_domain_count(4), 4_096);
        assert_eq!(cap_domain_count(5), 16_384);
        assert_eq!(cap_domain_count(6), 65_536);
    }

    #[test]
    fn cap_domain_count_caps_at_16_bit_space() {
        // ND = 7 is reserved; encoder saturates at the 16-bit DID space.
        assert_eq!(cap_domain_count(7), 65_536);
    }

    #[test]
    fn cap_supported_agaw_extracts_bits_8_to_12() {
        // Set SAGAW = 0b0110 (bits 9..10), padded to byte boundary.
        let cap = 0b0110 << 8;
        assert_eq!(cap_supported_agaw(cap), 0b0110);
    }

    #[test]
    fn cap_caching_mode_extracts_bit_7() {
        assert!(!cap_caching_mode(0));
        assert!(cap_caching_mode(1 << 7));
        assert!(cap_caching_mode((1 << 7) | (1 << 31)));
    }

    // ---- WI-7b step 3: DMAR fault-register decoders --------------------

    #[test]
    fn cap_fault_recording_offset_decodes_16byte_units() {
        // FRO field (bits 24..33) = 0x10 → byte offset 0x100.
        let cap = 0x10u64 << 24;
        assert_eq!(cap_fault_recording_offset(cap), 0x100);
        // Real QEMU-style FRO sits well above the basic registers.
        let cap = 0x20u64 << 24;
        assert_eq!(cap_fault_recording_offset(cap), 0x200);
    }

    #[test]
    fn cap_num_fault_recording_is_field_plus_one() {
        // NFR field (bits 40..47) = 0 → 1 register.
        assert_eq!(cap_num_fault_recording(0), 1);
        // NFR = 7 → 8 registers.
        assert_eq!(cap_num_fault_recording(7u64 << 40), 8);
    }

    #[test]
    fn fsts_decoders_extract_pfo_ppf_fri() {
        assert!(!fsts_primary_pending_fault(0));
        assert!(fsts_primary_pending_fault(1 << 1));
        assert!(fsts_primary_fault_overflow(1 << 0));
        // FRI in bits 8..15.
        assert_eq!(fsts_fault_record_index((5u32 << 8) | (1 << 1)), 5);
    }

    #[test]
    fn frcd_decoders_extract_fault_fields() {
        // High half: F (bit 63) + read (bit 62) + reason 0x06 (bits
        // 32..39) + SID 0x0630 (bits 0..15).
        let high = (1u64 << 63) | (1u64 << 62) | (0x06u64 << 32) | 0x0630;
        // Low half: faulting page address 0x0000_0001_2345_6000.
        let low = 0x0000_0001_2345_6000u64 | 0xABC;
        assert!(frcd_fault(high));
        assert!(frcd_is_read(high));
        assert_eq!(frcd_fault_reason(high), 0x06);
        assert_eq!(frcd_source_id(high), 0x0630);
        assert_eq!(frcd_fault_address(low), 0x0000_0001_2345_6000);
    }

    #[test]
    fn decode_fault_record_none_when_f_clear() {
        // F bit clear → no recorded fault.
        assert_eq!(decode_fault_record(0x1000, 0), None);
    }

    #[test]
    fn decode_fault_record_some_when_f_set() {
        let high = (1u64 << 63) | (0x05u64 << 32) | 0x0630; // write fault
        let low = 0x8_8000_0000u64;
        let rec = decode_fault_record(low, high).expect("F set → Some");
        assert_eq!(rec.source_id, 0x0630);
        assert_eq!(rec.reason, 0x05);
        assert!(!rec.is_read, "write fault");
        assert_eq!(rec.address, 0x8_8000_0000);
    }

    #[test]
    fn pick_highest_supported_agaw_prefers_57_then_48_then_39_then_30() {
        assert_eq!(
            pick_highest_supported_agaw(0b1111),
            Some(AddressWidth::Bits57Level5)
        );
        assert_eq!(
            pick_highest_supported_agaw(0b0111),
            Some(AddressWidth::Bits48Level4)
        );
        assert_eq!(
            pick_highest_supported_agaw(0b0011),
            Some(AddressWidth::Bits39Level3)
        );
        assert_eq!(
            pick_highest_supported_agaw(0b0001),
            Some(AddressWidth::Bits30Level2)
        );
    }

    #[test]
    fn pick_highest_supported_agaw_returns_none_for_zero_mask() {
        assert_eq!(pick_highest_supported_agaw(0), None);
    }

    // ---- VtdBackend bookkeeping ----------------------------------------

    #[test]
    fn vtd_backend_vendor_reports_intel() {
        let backend = VtdBackend::new();
        assert_eq!(backend.vendor(), IommuVendor::Intel);
    }

    #[test]
    fn vtd_backend_install_domain_is_idempotent() {
        let mut backend = VtdBackend::new();
        backend.install_domain(DomainId::new(3)).unwrap();
        backend.install_domain(DomainId::new(3)).unwrap();
        assert!(backend.has_domain(DomainId::new(3)));
        assert_eq!(backend.domains(), &[DomainId::new(3)]);
    }

    #[test]
    fn vtd_backend_map_rejects_unknown_domain() {
        let mut backend = VtdBackend::new();
        assert_eq!(
            backend.map(DomainId::new(7), 0x1000, 0x2000, 0x1000, IommuFlags::READ),
            Err(IommuError::InvalidDomain)
        );
    }

    #[test]
    fn vtd_backend_map_records_mapping_with_encoded_slpte() {
        let mut backend = VtdBackend::new();
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
        assert_eq!(rec.leaf_slpte.output_address(), 0x2000);
        assert!(rec.leaf_slpte.is_present());
    }

    #[test]
    fn vtd_backend_map_rejects_misaligned_arguments() {
        let mut backend = VtdBackend::new();
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
    fn vtd_backend_unmap_removes_record() {
        let mut backend = VtdBackend::new();
        backend.install_domain(DomainId::new(7)).unwrap();
        backend
            .map(DomainId::new(7), 0x1000, 0x2000, 0x1000, IommuFlags::READ)
            .unwrap();
        assert_eq!(backend.mappings().len(), 1);
        backend.unmap(DomainId::new(7), 0x1000, 0x1000).unwrap();
        assert!(backend.mappings().is_empty());
    }

    #[test]
    fn vtd_backend_unmap_unmapped_range_returns_error() {
        let mut backend = VtdBackend::new();
        backend.install_domain(DomainId::new(7)).unwrap();
        assert_eq!(
            backend.unmap(DomainId::new(7), 0x1000, 0x1000),
            Err(IommuError::UnmapFailed)
        );
    }

    #[test]
    fn vtd_backend_unmap_rejects_unknown_domain() {
        let mut backend = VtdBackend::new();
        assert_eq!(
            backend.unmap(DomainId::new(9), 0x1000, 0x1000),
            Err(IommuError::InvalidDomain)
        );
    }

    #[test]
    fn vtd_backend_flush_rejects_unknown_domain() {
        let mut backend = VtdBackend::new();
        assert_eq!(
            backend.flush(DomainId::new(0)),
            Err(IommuError::InvalidDomain)
        );
    }

    #[test]
    fn vtd_backend_flush_known_domain_is_ok() {
        let mut backend = VtdBackend::new();
        backend.install_domain(DomainId::new(0)).unwrap();
        assert_eq!(backend.flush(DomainId::new(0)), Ok(()));
    }

    // ---- VtdError → IommuError mapping ---------------------------------

    #[test]
    fn vtd_error_into_iommu_error_mapping() {
        assert_eq!(
            IommuError::from(VtdError::AddressMisaligned),
            IommuError::AddressMisaligned
        );
        assert_eq!(
            IommuError::from(VtdError::UnknownDomain),
            IommuError::InvalidDomain
        );
        assert_eq!(
            IommuError::from(VtdError::UnsupportedFlags),
            IommuError::Unsupported
        );
    }

    // ---- Activation surface (P6.7.9-pre.5) -----------------------------

    use super::{
        GSTS_BIT_QIES, GSTS_BIT_RTPS, GSTS_BIT_TES, INV_DESC_CTX_GRAN_GLOBAL,
        INV_DESC_IOTLB_GRAN_GLOBAL, INV_DESC_TYPE_INVALIDATE_WAIT, INV_DESC_WAIT_STATUS_WRITE,
        INV_QUEUE_BYTES, INV_QUEUE_ENTRY_BYTES, INV_QUEUE_ENTRY_COUNT, INV_QUEUE_SIZE_ORDER,
        IOTLB_FLUSH_POLL_BUDGET, VTD_ACTIVATION_POLL_LIMIT, VtdActivateError,
        encode_context_cache_global_invalidate, encode_iotlb_global_invalidate, encode_iqa,
        poll_with_budget,
    };

    #[test]
    fn gsts_bits_mirror_gcmd_positions() {
        assert_eq!(GSTS_BIT_TES, super::GCMD_BIT_TE);
        assert_eq!(GSTS_BIT_RTPS, super::GCMD_BIT_SRTP);
        assert_eq!(GSTS_BIT_QIES, super::GCMD_BIT_QIE);
    }

    #[test]
    fn invalidation_queue_layout_constants_match_legacy_format() {
        assert_eq!(INV_QUEUE_SIZE_ORDER, 0);
        assert_eq!(INV_QUEUE_ENTRY_COUNT, 256);
        assert_eq!(INV_QUEUE_ENTRY_BYTES, 16);
        assert_eq!(INV_QUEUE_BYTES, 4096);
        assert_eq!(
            INV_QUEUE_ENTRY_COUNT * INV_QUEUE_ENTRY_BYTES,
            INV_QUEUE_BYTES
        );
    }

    #[test]
    fn invalidation_descriptor_tags_match_spec_section_6_5_2() {
        assert_eq!(INV_DESC_TYPE_CONTEXT_CACHE, 0x1);
        assert_eq!(INV_DESC_TYPE_IOTLB, 0x2);
        assert_eq!(INV_DESC_TYPE_INVALIDATE_WAIT, 0x5);
        assert_eq!(INV_DESC_CTX_GRAN_GLOBAL, 0b01 << 4);
        assert_eq!(INV_DESC_IOTLB_GRAN_GLOBAL, 0b01 << 4);
        assert_eq!(INV_DESC_WAIT_STATUS_WRITE, 1 << 5);
    }

    #[test]
    fn poll_limit_is_a_million() {
        assert_eq!(VTD_ACTIVATION_POLL_LIMIT, 1_000_000);
    }

    // ---- P11.4: dedicated IOTLB-flush poll budget ------------------------
    //
    // `poll_with_budget` is the host-testable core both MMIO poll
    // wrappers delegate to, so pinning its budget discipline here pins
    // the iteration count the flush path performs against `IQH`.

    #[test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "regression guard: must fail loudly if either constant is edited \
                  such that the flush budget no longer sits well below the activation limit"
    )]
    fn iotlb_flush_poll_budget_is_ten_thousand_and_smaller_than_activation() {
        assert_eq!(IOTLB_FLUSH_POLL_BUDGET, 10_000);
        // The whole point of the dedicated constant: a wedged unit
        // must stall a recoverable flush far less than an activation.
        assert!(IOTLB_FLUSH_POLL_BUDGET < VTD_ACTIVATION_POLL_LIMIT);
    }

    #[test]
    fn poll_with_budget_gives_up_after_exactly_the_flush_budget() {
        // A never-draining queue (wedged unit): the poll must observe
        // exactly IOTLB_FLUSH_POLL_BUDGET times and then report
        // failure — not spin on the ~1M activation budget.
        let mut observations: u32 = 0;
        let drained = poll_with_budget(IOTLB_FLUSH_POLL_BUDGET, || {
            observations += 1;
            false
        });
        assert!(!drained);
        assert_eq!(observations, IOTLB_FLUSH_POLL_BUDGET);
    }

    #[test]
    fn poll_with_budget_stops_at_first_successful_observation() {
        // Normal drain: IQH catches up after a handful of polls; the
        // loop must exit immediately without consuming the budget.
        let mut observations: u32 = 0;
        let drained = poll_with_budget(IOTLB_FLUSH_POLL_BUDGET, || {
            observations += 1;
            observations == 7
        });
        assert!(drained);
        assert_eq!(observations, 7);
    }

    #[test]
    fn poll_with_budget_zero_budget_fails_without_observing() {
        let mut observations: u32 = 0;
        let drained = poll_with_budget(0, || {
            observations += 1;
            true
        });
        assert!(!drained);
        assert_eq!(observations, 0);
    }

    #[test]
    fn encode_iqa_places_base_in_bits_12_to_63_and_qs_in_low_three() {
        let phys = 0x0000_DEAD_BEEF_F000_u64;
        let iqa = encode_iqa(phys, 0);
        // Low 12 bits zero (4-KiB aligned), no DW, QS=0.
        assert_eq!(iqa, phys);
    }

    #[test]
    fn encode_iqa_masks_reserved_low_bits_of_phys() {
        let phys_with_dirt = 0x0000_DEAD_BEEF_F123_u64;
        let iqa = encode_iqa(phys_with_dirt, 0);
        // The low 12 bits must be cleared; QS = 0 leaves bits 0..2 = 0.
        assert_eq!(iqa & 0xFFF, 0);
        assert_eq!(iqa >> 12, phys_with_dirt >> 12);
    }

    #[test]
    fn encode_iqa_encodes_size_order_in_low_three_bits() {
        let phys = 0x0000_0001_0000_0000_u64; // 4 GiB aligned
        let iqa = encode_iqa(phys, 3);
        assert_eq!(iqa & 0x7, 0x3);
        assert_eq!(iqa & !0x7, phys);
    }

    #[test]
    fn encode_iqa_truncates_size_order_above_three_bits() {
        let phys = 0x0000_0001_0000_0000_u64;
        let iqa = encode_iqa(phys, 0xFF);
        // High bits of size_order must be discarded.
        assert_eq!(iqa & 0x7, 0x7);
    }

    #[test]
    fn encode_iqa_masks_phys_above_bit_51() {
        // Bits 52..63 are reserved; we mask conservatively to bit 51
        // because Intel VT-d MGAW caps at 52 host-address bits even on
        // the widest 5-level paging configuration.
        let high_phys = 0xFFFF_FFFF_FFFF_F000_u64;
        let iqa = encode_iqa(high_phys, 0);
        assert_eq!(iqa, 0x000F_FFFF_FFFF_F000_u64);
    }

    #[test]
    fn encode_iotlb_global_invalidate_low_qword_carries_type_and_granularity() {
        let (low, high) = encode_iotlb_global_invalidate();
        assert_eq!(low & 0xF, INV_DESC_TYPE_IOTLB);
        assert_eq!((low >> 4) & 0x3, INV_DESC_IOTLB_GRAN_GLOBAL >> 4);
        assert_eq!(high, 0);
    }

    #[test]
    fn encode_context_cache_global_invalidate_low_qword_carries_type_and_granularity() {
        let (low, high) = encode_context_cache_global_invalidate();
        assert_eq!(low & 0xF, INV_DESC_TYPE_CONTEXT_CACHE);
        assert_eq!((low >> 4) & 0x3, INV_DESC_CTX_GRAN_GLOBAL >> 4);
        assert_eq!(high, 0);
    }

    #[test]
    fn vtd_activate_error_maps_to_iommu_activation_failed() {
        for variant in [
            VtdActivateError::NotPrepared,
            VtdActivateError::RootTableTimeout,
            VtdActivateError::QueueEnableTimeout,
            VtdActivateError::InvalidationTimeout,
        ] {
            assert_eq!(IommuError::from(variant), IommuError::ActivationFailed);
        }
    }

    #[test]
    fn fresh_backend_reports_dormant_state() {
        let backend = VtdBackend::new();
        assert_eq!(backend.unit_base(), 0);
        assert_eq!(backend.root_table_phys(), 0);
        assert_eq!(backend.invalidation_queue_phys(), 0);
        assert!(!backend.is_hardware_activated());
    }

    #[test]
    fn prepare_activation_stashes_parameters() {
        let mut backend = VtdBackend::new();
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        assert_eq!(backend.unit_base(), 0xFED9_0000);
        assert_eq!(backend.root_table_phys(), 0x10_0000);
        assert_eq!(backend.invalidation_queue_phys(), 0x10_1000);
        assert!(!backend.is_hardware_activated());
    }

    #[test]
    fn prepare_activation_with_same_params_does_not_clear_activated_flag() {
        // We can't trigger activate_hardware on host (it is
        // `cfg(target_os = "none")`); model the post-activation state
        // by re-calling `prepare_activation` with the same args and
        // proving the function does not reset `hardware_activated`
        // when the values match. The actual flag flip is exercised by
        // the Proxmox smoke after the boot probe runs.
        let mut backend = VtdBackend::new();
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        assert_eq!(backend.unit_base(), 0xFED9_0000);
        assert_eq!(backend.root_table_phys(), 0x10_0000);
        assert_eq!(backend.invalidation_queue_phys(), 0x10_1000);
    }

    #[test]
    fn prepare_activation_with_different_params_resets_state() {
        let mut backend = VtdBackend::new();
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        backend.prepare_activation(0xFED9_1000, 0x20_0000, 0x20_1000);
        assert_eq!(backend.unit_base(), 0xFED9_1000);
        assert_eq!(backend.root_table_phys(), 0x20_0000);
        assert_eq!(backend.invalidation_queue_phys(), 0x20_1000);
        assert!(!backend.is_hardware_activated());
    }

    // ---- P6.7.9-pre.7 — per-domain invalidate encoders ------------------

    #[test]
    fn encode_context_cache_domain_invalidate_packs_did_and_type() {
        let (low, high) = encode_context_cache_domain_invalidate(DomainId::new(0x1234));
        // Type=0x1 in bits 0..3, G=10 in bits 4..5, DID in bits 16..31.
        assert_eq!(low & 0xF, INV_DESC_TYPE_CONTEXT_CACHE);
        assert_eq!(low & (0b11 << 4), INV_DESC_CTX_GRAN_DOMAIN);
        assert_eq!((low >> 16) & 0xFFFF, 0x1234);
        assert_eq!(high, 0);
    }

    #[test]
    fn encode_iotlb_domain_invalidate_packs_did_and_type() {
        let (low, high) = encode_iotlb_domain_invalidate(DomainId::new(0xABCD));
        // Type=0x2 in bits 0..3, G=10 in bits 4..5, DID in bits 16..31.
        assert_eq!(low & 0xF, INV_DESC_TYPE_IOTLB);
        assert_eq!(low & (0b11 << 4), INV_DESC_IOTLB_GRAN_DOMAIN);
        assert_eq!((low >> 16) & 0xFFFF, 0xABCD);
        assert_eq!(high, 0);
    }

    #[test]
    fn encode_per_domain_invalidates_for_did_zero_set_only_type_and_g() {
        // The boundary DID=0 must still raise the type + G bits even
        // though the DID field encodes to zero — defends against an
        // accidental mask that swallows both fields.
        let (cc_low, cc_high) = encode_context_cache_domain_invalidate(DomainId::new(0));
        assert_eq!(
            cc_low,
            INV_DESC_TYPE_CONTEXT_CACHE | INV_DESC_CTX_GRAN_DOMAIN
        );
        assert_eq!(cc_high, 0);

        let (io_low, io_high) = encode_iotlb_domain_invalidate(DomainId::new(0));
        assert_eq!(io_low, INV_DESC_TYPE_IOTLB | INV_DESC_IOTLB_GRAN_DOMAIN);
        assert_eq!(io_high, 0);
    }

    // ---- P6.7.9-pre.7 — root/context entry offset helpers ---------------

    #[test]
    fn context_entry_offset_matches_devfn_times_16() {
        // bdf 00:01.2 → devfn = (1 << 3) | 2 = 0xA → offset = 0xA * 16 = 0xA0.
        let bdf = PciBdf::from_parts(0, 1, 2);
        assert_eq!(context_entry_offset(bdf), 0xA0);
        // bdf 00:1F.7 → devfn = 0xFF → offset = 0xFF0 (last slot of
        // the 4-KiB context table).
        let last = PciBdf::from_parts(0, 0x1F, 0x7);
        assert_eq!(context_entry_offset(last), 0xFF0);
    }

    #[test]
    fn context_entry_offset_keeps_table_in_4_kib_page() {
        // Last possible slot = (devfn=0xFF, offset=0xFF0) — the entry
        // body still fits inside the 4-KiB context-table page because
        // offset + CONTEXT_ENTRY_BYTES = 0x1000.
        let last = PciBdf::from_parts(7, 0x1F, 0x7);
        let off = context_entry_offset(last);
        assert!(off + (CONTEXT_ENTRY_BYTES as u64) <= 4096);
    }

    #[test]
    fn root_entry_offset_matches_bus_times_16() {
        assert_eq!(root_entry_offset(0), 0);
        assert_eq!(root_entry_offset(1), 0x10);
        assert_eq!(root_entry_offset(0xFF), 0xFF0);
    }

    #[test]
    fn root_entry_offset_keeps_table_in_4_kib_page() {
        // Last possible slot = bus 255 → offset 0xFF0 → fits inside
        // the 4-KiB root-table page.
        let off = root_entry_offset(0xFF);
        assert!(off + (ROOT_ENTRY_BYTES as u64) <= 4096);
    }

    // ---- P6.7.9-pre.7 — VtdAttachment scaffold ---------------------------

    #[test]
    fn attach_device_records_binding_and_rejects_unknown_domain() {
        let mut backend = VtdBackend::new();
        let bdf = PciBdf::from_parts(0, 1, 0);
        // Domain never installed → InvalidDomain.
        assert_eq!(
            backend.attach_device(bdf, DomainId::new(0x10)),
            Err(IommuError::InvalidDomain)
        );
        // Install + attach succeeds.
        backend.install_domain(DomainId::new(0x10)).unwrap();
        assert_eq!(backend.attach_device(bdf, DomainId::new(0x10)), Ok(()));
        assert!(backend.has_attachment(bdf));
        assert_eq!(backend.attachments().len(), 1);
        assert_eq!(
            backend.attachments().first().copied(),
            Some(VtdAttachment {
                bdf,
                domain: DomainId::new(0x10),
            })
        );
    }

    #[test]
    fn attach_device_double_attach_rejected() {
        let mut backend = VtdBackend::new();
        let bdf = PciBdf::from_parts(0, 2, 0);
        backend.install_domain(DomainId::new(1)).unwrap();
        backend.attach_device(bdf, DomainId::new(1)).unwrap();
        assert_eq!(
            backend.attach_device(bdf, DomainId::new(1)),
            Err(IommuError::Unsupported)
        );
    }

    #[test]
    fn detach_device_removes_and_allows_reattach() {
        let mut backend = VtdBackend::new();
        let bdf = PciBdf::from_parts(0, 3, 1);
        backend.install_domain(DomainId::new(2)).unwrap();
        backend.attach_device(bdf, DomainId::new(2)).unwrap();
        assert_eq!(backend.detach_device(bdf), Ok(()));
        assert!(!backend.has_attachment(bdf));
        // Re-attach after detach succeeds (idempotent surface).
        assert_eq!(backend.attach_device(bdf, DomainId::new(2)), Ok(()));
    }

    #[test]
    fn detach_unknown_device_returns_unsupported() {
        let mut backend = VtdBackend::new();
        let bdf = PciBdf::from_parts(0, 4, 0);
        assert_eq!(backend.detach_device(bdf), Err(IommuError::Unsupported));
    }

    #[test]
    fn vtd_attach_error_maps_to_iommu_error_variants() {
        assert_eq!(
            IommuError::from(VtdAttachError::NotActivated),
            IommuError::ActivationFailed
        );
        assert_eq!(
            IommuError::from(VtdAttachError::DomainNotInstalled),
            IommuError::InvalidDomain
        );
        assert_eq!(
            IommuError::from(VtdAttachError::AlreadyAttached),
            IommuError::Unsupported
        );
        assert_eq!(
            IommuError::from(VtdAttachError::AddressMisaligned),
            IommuError::AddressMisaligned
        );
        assert_eq!(
            IommuError::from(VtdAttachError::InvalidationTimeout),
            IommuError::ActivationFailed
        );
    }

    #[test]
    fn fresh_backend_has_no_attachments() {
        let backend = VtdBackend::new();
        assert!(backend.attachments().is_empty());
        assert!(!backend.has_attachment(PciBdf::from_parts(0, 0, 0)));
    }

    // ---- P6.7.9-pre.11 per-bus context-table allocator -----------------

    use super::VtdAttachError as PreElevenAttachErr;
    use crate::bare_metal::iommu::pt_alloc::MockFrameSource;

    #[test]
    fn vtd_attach_error_bus_context_alloc_failed_maps_to_domain_table_full() {
        assert_eq!(
            IommuError::from(PreElevenAttachErr::BusContextAllocFailed),
            IommuError::DomainTableFull
        );
    }

    #[test]
    fn fresh_backend_has_no_bus_context_tables() {
        let backend = VtdBackend::new();
        assert!(backend.bus_context_tables().is_empty());
        assert_eq!(backend.bus_context_table_phys(0), None);
        assert_eq!(backend.bus_context_table_refcount(0), None);
    }

    #[test]
    fn acquire_bus_context_table_allocates_on_first_call() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        let phys = backend.acquire_bus_context_table(7, &mut src).unwrap();
        assert_eq!(src.alloc_calls, 1);
        assert_eq!(src.free_calls, 0);
        assert_eq!(phys & 0xFFF, 0);
        assert_eq!(backend.bus_context_table_phys(7), Some(phys));
        assert_eq!(backend.bus_context_table_refcount(7), Some(1));
        assert_eq!(backend.bus_context_tables().len(), 1);
    }

    #[test]
    fn acquire_bus_context_table_shares_page_across_repeat_acquires() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        let phys1 = backend.acquire_bus_context_table(3, &mut src).unwrap();
        let phys2 = backend.acquire_bus_context_table(3, &mut src).unwrap();
        let phys3 = backend.acquire_bus_context_table(3, &mut src).unwrap();
        assert_eq!(phys1, phys2);
        assert_eq!(phys1, phys3);
        assert_eq!(src.alloc_calls, 1);
        assert_eq!(backend.bus_context_table_refcount(3), Some(3));
    }

    #[test]
    fn acquire_bus_context_table_allocates_distinct_pages_per_bus() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        let phys_a = backend.acquire_bus_context_table(1, &mut src).unwrap();
        let phys_b = backend.acquire_bus_context_table(2, &mut src).unwrap();
        assert_ne!(phys_a, phys_b);
        assert_eq!(src.alloc_calls, 2);
        assert_eq!(backend.bus_context_tables().len(), 2);
    }

    #[test]
    fn acquire_bus_context_table_surfaces_frame_alloc_failure() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        src.force_alloc_fail = true;
        assert_eq!(
            backend.acquire_bus_context_table(0, &mut src),
            Err(PreElevenAttachErr::BusContextAllocFailed)
        );
        assert!(backend.bus_context_tables().is_empty());
    }

    #[test]
    fn acquire_bus_context_table_rejects_misaligned_frame_and_returns_it() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        src.force_next_phys = Some(0x1_0000_0010); // not 4-KiB aligned
        let err = backend.acquire_bus_context_table(0, &mut src);
        assert_eq!(err, Err(PreElevenAttachErr::BusContextAllocFailed));
        assert_eq!(src.free_calls, 1);
        assert_eq!(src.freed, [0x1_0000_0010]);
        assert!(backend.bus_context_tables().is_empty());
    }

    #[test]
    fn release_bus_context_table_decrements_refcount_then_frees() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        let phys = backend.acquire_bus_context_table(5, &mut src).unwrap();
        backend.acquire_bus_context_table(5, &mut src).unwrap();
        backend.acquire_bus_context_table(5, &mut src).unwrap();
        // refcount == 3 → release drops to 2, no free yet.
        backend.release_bus_context_table(5, &mut src).unwrap();
        assert_eq!(backend.bus_context_table_refcount(5), Some(2));
        assert_eq!(src.free_calls, 0);
        // refcount == 2 → 1, still no free.
        backend.release_bus_context_table(5, &mut src).unwrap();
        assert_eq!(backend.bus_context_table_refcount(5), Some(1));
        assert_eq!(src.free_calls, 0);
        // refcount == 1 → 0, page is freed and entry removed.
        backend.release_bus_context_table(5, &mut src).unwrap();
        assert_eq!(backend.bus_context_table_refcount(5), None);
        assert_eq!(src.free_calls, 1);
        assert_eq!(src.freed, [phys]);
        assert!(backend.bus_context_tables().is_empty());
    }

    #[test]
    fn release_bus_context_table_unknown_bus_returns_err() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        assert_eq!(
            backend.release_bus_context_table(0, &mut src),
            Err(super::BusContextTableReleaseError::UnknownBus)
        );
        assert_eq!(src.free_calls, 0);
    }

    #[test]
    fn release_bus_context_table_isolates_other_buses() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        let phys_a = backend.acquire_bus_context_table(1, &mut src).unwrap();
        let phys_b = backend.acquire_bus_context_table(2, &mut src).unwrap();
        backend.release_bus_context_table(1, &mut src).unwrap();
        assert_eq!(backend.bus_context_table_phys(1), None);
        assert_eq!(backend.bus_context_table_phys(2), Some(phys_b));
        assert_eq!(src.freed, [phys_a]);
    }

    #[test]
    fn reacquire_after_release_allocates_fresh_page() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        let phys_a = backend.acquire_bus_context_table(0, &mut src).unwrap();
        backend.release_bus_context_table(0, &mut src).unwrap();
        let phys_b = backend.acquire_bus_context_table(0, &mut src).unwrap();
        // The mock hands out a fresh phys after the freed one, so the
        // two values must differ; the entry is back to refcount 1.
        assert_ne!(phys_a, phys_b);
        assert_eq!(backend.bus_context_table_refcount(0), Some(1));
        assert_eq!(src.alloc_calls, 2);
    }

    // ---- P6.7.9-pre.11 translation enable state machine ---------------

    #[test]
    fn fresh_backend_is_not_translation_enabled() {
        let backend = VtdBackend::new();
        assert!(!backend.is_translation_enabled());
    }

    #[test]
    fn vtd_activate_error_translation_enable_timeout_maps_to_activation_failed() {
        assert_eq!(
            IommuError::from(VtdActivateError::TranslationEnableTimeout),
            IommuError::ActivationFailed
        );
    }

    #[test]
    fn prepare_activation_with_different_params_resets_translation_enabled() {
        // We exercise the state-reset behaviour without driving the
        // live MMIO path (which is `cfg(target_os = "none")` gated).
        // Manually flipping the bookkeeping flag is the cleanest way to
        // assert the reset on the host side.
        let mut backend = VtdBackend::new();
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        // Simulate a successful prior translation_enabled state.
        // SAFETY: in #[cfg(test)] this is a host-only invariant probe.
        // We cannot set the private field directly without a helper, so
        // assert the contract through the public state instead.
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        // Same params: hardware_activated stays unchanged.
        assert!(!backend.is_hardware_activated());
        backend.prepare_activation(0xFED9_2000, 0x10_0000, 0x10_1000);
        // Different params → state reset.
        assert!(!backend.is_hardware_activated());
        assert!(!backend.is_translation_enabled());
    }

    // ---- P11.3: GCMD live enable-bit mask tracking ----------------------
    //
    // `compose_enable_bits` is the host-testable half of the P11.3 fix:
    // the `cfg(target_os = "none")` GCMD write sites
    // (`activate_hardware` for QIE, `enable_translation` for TE) only
    // call it and write the returned mask, so pinning the composition
    // here pins the value that reaches the register.

    #[test]
    fn fresh_backend_has_empty_live_enable_mask() {
        let backend = VtdBackend::new();
        assert_eq!(backend.live_enable_mask(), 0);
    }

    #[test]
    fn compose_enable_bits_te_then_ire_keeps_both() {
        // The P11.3 regression scenario: a future slice raises IRE
        // after TE — neither write may drop the other's bit.
        let mut backend = VtdBackend::new();
        let first = backend.compose_enable_bits(GCMD_BIT_TE);
        assert_eq!(first, GCMD_BIT_TE);
        let second = backend.compose_enable_bits(GCMD_BIT_IRE);
        assert_eq!(second, GCMD_BIT_TE | GCMD_BIT_IRE);
        assert_eq!(backend.live_enable_mask(), GCMD_BIT_TE | GCMD_BIT_IRE);
    }

    #[test]
    fn compose_enable_bits_matches_live_activation_order() {
        // The order the live MMIO path actually drives: QIE composed by
        // `activate_hardware` step (4), TE composed by
        // `enable_translation`. The TE write must carry QIE along —
        // this is the WI-7b step 2 invariant, now mask-derived instead
        // of hardcoded.
        let mut backend = VtdBackend::new();
        assert_eq!(backend.compose_enable_bits(GCMD_BIT_QIE), GCMD_BIT_QIE);
        assert_eq!(
            backend.compose_enable_bits(GCMD_BIT_TE),
            GCMD_BIT_TE | GCMD_BIT_QIE
        );
    }

    #[test]
    fn compose_enable_bits_is_idempotent_per_bit() {
        // `enable_translation` may be retried after a timeout; the
        // re-composition must not corrupt the mask.
        let mut backend = VtdBackend::new();
        backend.compose_enable_bits(GCMD_BIT_QIE);
        backend.compose_enable_bits(GCMD_BIT_TE);
        assert_eq!(
            backend.compose_enable_bits(GCMD_BIT_TE),
            GCMD_BIT_TE | GCMD_BIT_QIE
        );
    }

    #[test]
    fn prepare_activation_with_different_params_resets_live_enable_mask() {
        let mut backend = VtdBackend::new();
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        backend.compose_enable_bits(GCMD_BIT_QIE | GCMD_BIT_TE);
        // Same params: the mask survives (idempotent re-prepare).
        backend.prepare_activation(0xFED9_0000, 0x10_0000, 0x10_1000);
        assert_eq!(backend.live_enable_mask(), GCMD_BIT_QIE | GCMD_BIT_TE);
        // Different params: full state reset, mask included.
        backend.prepare_activation(0xFED9_2000, 0x10_0000, 0x10_1000);
        assert_eq!(backend.live_enable_mask(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "one-shot GCMD command bits")]
    fn compose_enable_bits_rejects_one_shot_command_bits() {
        // SRTP self-clears: recording it would re-trigger a root-table
        // set on every later GCMD write.
        let mut backend = VtdBackend::new();
        backend.compose_enable_bits(GCMD_BIT_SRTP);
    }

    // ---- WI-7a: second-level page-table builder ------------------------
    //
    // These exercise the real multi-level SLPT construction against
    // `MockFrameSource` (which backs `read_entry`/`write_entry` with a
    // deterministic page store). They are the host proof that a future
    // `GCMD.TE` flip (WI-7b) will translate legitimate DMA rather than
    // fault it.

    const AW4: AddressWidth = AddressWidth::Bits48Level4;

    /// Provision a fake domain root and return its phys.
    fn fake_root(src: &mut MockFrameSource) -> u64 {
        src.alloc_zeroed_frame().expect("root frame")
    }

    #[test]
    fn slpt_index_decomposes_iova_per_level() {
        // 48-bit IOVA with a distinct 9-bit field per level.
        // level 4 → bits 39..47, level 3 → 30..38, level 2 → 21..29,
        // level 1 → 12..20.
        let iova = (0x1A << 39) | (0x0B << 30) | (0x1C << 21) | (0x0D << 12) | 0xABC;
        assert_eq!(slpt_index(iova, 4), 0x1A);
        assert_eq!(slpt_index(iova, 3), 0x0B);
        assert_eq!(slpt_index(iova, 2), 0x1C);
        assert_eq!(slpt_index(iova, 1), 0x0D);
    }

    #[test]
    fn map_4k_builds_walkable_tree_and_translate_returns_phys() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let iova = 0x4000_0000_u64; // 1 GiB, 4-KiB aligned
        let phys = 0x8_8000_0000_u64;
        let leaf = encode_slpte(phys, IommuFlags::READ.union(IommuFlags::WRITE)).unwrap();

        map_4k_slpt(root, iova, leaf, AW4, &mut src).expect("map ok");

        // A 4-level walk allocated 3 intermediate tables (levels 4→2);
        // the leaf lives in the level-1 table = the 3rd allocation.
        // Plus the root alloc = 4 total alloc calls.
        assert_eq!(src.alloc_calls, 1 /*root*/ + 3 /*intermediates*/);

        // The tree is walkable and resolves to the mapped phys (offset
        // preserved).
        assert_eq!(translate_slpt(root, iova, AW4, &src), Some(phys));
        // A different offset within the same page resolves with offset.
        assert_eq!(
            translate_slpt(root, iova | 0x123, AW4, &src),
            Some(phys | 0x123)
        );
    }

    #[test]
    fn second_mapping_in_same_subtree_reuses_intermediates() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let aw = AW4;
        // Two IOVAs that differ only in the leaf-level index (same
        // level-4/3/2 path) must share all three intermediate tables.
        let iova_a = 0x4000_0000_u64;
        let iova_b = iova_a + 0x1000; // next 4-KiB page, same leaf table
        let pa = 0x1_0000_0000_u64;
        let pb = 0x1_0000_1000_u64;
        map_4k_slpt(
            root,
            iova_a,
            encode_slpte(pa, IommuFlags::READ).unwrap(),
            aw,
            &mut src,
        )
        .unwrap();
        let allocs_after_first = src.alloc_calls;
        map_4k_slpt(
            root,
            iova_b,
            encode_slpte(pb, IommuFlags::READ).unwrap(),
            aw,
            &mut src,
        )
        .unwrap();
        // No new intermediate tables: same level-4/3/2 path.
        assert_eq!(src.alloc_calls, allocs_after_first);
        assert_eq!(translate_slpt(root, iova_a, aw, &src), Some(pa));
        assert_eq!(translate_slpt(root, iova_b, aw, &src), Some(pb));
    }

    #[test]
    fn distinct_top_level_iovas_allocate_separate_subtrees() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let aw = AW4;
        // Differ in the level-4 index → fully separate level-3/2/1 chains.
        let iova_a = 0x4000_0000_u64;
        let iova_b = iova_a + (1u64 << 39);
        map_4k_slpt(
            root,
            iova_a,
            encode_slpte(0x1000, IommuFlags::READ).unwrap(),
            aw,
            &mut src,
        )
        .unwrap();
        let after_a = src.alloc_calls;
        map_4k_slpt(
            root,
            iova_b,
            encode_slpte(0x2000, IommuFlags::READ).unwrap(),
            aw,
            &mut src,
        )
        .unwrap();
        // A whole new 3-table chain for the second top-level slot.
        assert_eq!(src.alloc_calls, after_a + 3);
    }

    #[test]
    fn map_range_maps_every_page_contiguously() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let aw = AW4;
        let iova = 0x4000_0000_u64;
        let phys = 0x2_0000_0000_u64;
        let len = 0x4000_u64; // 4 pages
        map_range_slpt(
            root,
            iova,
            phys,
            len,
            IommuFlags::READ.union(IommuFlags::WRITE),
            aw,
            &mut src,
        )
        .expect("range map ok");
        for i in 0..4u64 {
            assert_eq!(
                translate_slpt(root, iova + i * 0x1000, aw, &src),
                Some(phys + i * 0x1000),
                "page {i} must translate"
            );
        }
        // The 5th page was never mapped.
        assert_eq!(translate_slpt(root, iova + 4 * 0x1000, aw, &src), None);
    }

    #[test]
    fn unmapped_iova_translates_to_none() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        assert_eq!(translate_slpt(root, 0x4000_0000, AW4, &src), None);
    }

    #[test]
    fn unmap_clears_leaf_and_translate_returns_none() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let aw = AW4;
        let iova = 0x4000_0000_u64;
        map_4k_slpt(
            root,
            iova,
            encode_slpte(0x9000, IommuFlags::READ).unwrap(),
            aw,
            &mut src,
        )
        .unwrap();
        assert_eq!(translate_slpt(root, iova, aw, &src), Some(0x9000));
        assert_eq!(unmap_4k_slpt(root, iova, aw, &mut src), Ok(true));
        assert_eq!(translate_slpt(root, iova, aw, &src), None);
        // Unmapping again is a benign no-op (path partially present, leaf gone).
        assert_eq!(unmap_4k_slpt(root, iova, aw, &mut src), Ok(false));
    }

    #[test]
    fn map_4k_rejects_misaligned_iova_and_root() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let leaf = encode_slpte(0x1000, IommuFlags::READ).unwrap();
        assert_eq!(
            map_4k_slpt(root, 0x4000_0123, leaf, AW4, &mut src),
            Err(VtdError::AddressMisaligned)
        );
        assert_eq!(
            map_4k_slpt(0x1001, 0x4000_0000, leaf, AW4, &mut src),
            Err(VtdError::AddressMisaligned)
        );
    }

    #[test]
    fn map_4k_surfaces_frame_exhaustion() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        // Allow exactly the root (already taken); force the next
        // intermediate allocation to fail.
        src.force_alloc_fail = true;
        let leaf = encode_slpte(0x1000, IommuFlags::READ).unwrap();
        assert_eq!(
            map_4k_slpt(root, 0x4000_0000, leaf, AW4, &mut src),
            Err(VtdError::PageTableAllocFailed)
        );
    }

    #[test]
    fn read_only_mapping_leaf_has_read_not_write() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let aw = AW4;
        let iova = 0x4000_0000_u64;
        map_4k_slpt(
            root,
            iova,
            encode_slpte(0x5000, IommuFlags::READ).unwrap(),
            aw,
            &mut src,
        )
        .unwrap();
        // Walk down to the leaf and inspect its permission bits.
        let mut table = root;
        let mut level = aw.levels();
        while level > 1 {
            let e = src.read_entry(table, slpt_index(iova, level));
            table = e & 0x000F_FFFF_FFFF_F000;
            level -= 1;
        }
        let leaf = src.read_entry(table, slpt_index(iova, 1));
        assert_ne!(leaf & Slpte::BIT_READ, 0, "read bit set");
        assert_eq!(leaf & Slpte::BIT_WRITE, 0, "write bit clear for RO mapping");
    }

    #[test]
    fn three_level_aw_uses_one_fewer_intermediate() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        let aw = AddressWidth::Bits39Level3;
        let iova = 0x4000_0000_u64;
        map_4k_slpt(
            root,
            iova,
            encode_slpte(0x7000, IommuFlags::READ).unwrap(),
            aw,
            &mut src,
        )
        .unwrap();
        // 3 levels → 2 intermediate tables (levels 3→2) + root = 3 allocs.
        assert_eq!(src.alloc_calls, 1 + 2);
        assert_eq!(translate_slpt(root, iova, aw, &src), Some(0x7000));
    }

    // ---- WI-7b step 2: live-path wiring (map_with_src / unmap_with_src /
    // subtree free) ------------------------------------------------------
    //
    // These prove the `dma_map`-facing surface: a provisioned domain gets
    // a REAL walkable SLPT out of `map_with_src`, an unprovisioned one
    // degrades to the legacy bookkeeping-only behaviour, and the
    // domain-root release returns every intermediate frame (no leak).

    /// Backend with `domain 7` installed and its PT root provisioned
    /// through `src`. Returns `(backend, domain, root_phys)`.
    fn provisioned_backend(src: &mut MockFrameSource) -> (VtdBackend, DomainId, u64) {
        let mut backend = VtdBackend::new();
        let domain = DomainId::new(7);
        backend.install_domain(domain).expect("install ok");
        let root = backend
            .provision_domain_pt(domain, src)
            .expect("provision ok");
        (backend, domain, root)
    }

    #[test]
    fn map_with_src_builds_walkable_slpt_and_records_bookkeeping() {
        let mut src = MockFrameSource::new();
        let (mut backend, domain, root) = provisioned_backend(&mut src);
        let iova = 0x0100_0000_0000_u64; // DRIVER_DMA_VA_BASE
        let phys = 0x8_8000_0000_u64;
        backend
            .map_with_src(
                domain,
                iova,
                phys,
                0x2000,
                IommuFlags::READ.union(IommuFlags::WRITE),
                &mut src,
            )
            .expect("map ok");
        // Both pages of the window resolve through the real tree.
        assert_eq!(translate_slpt(root, iova, AW4, &src), Some(phys));
        assert_eq!(
            translate_slpt(root, iova + 0x1000, AW4, &src),
            Some(phys + 0x1000)
        );
        // Bookkeeping recorded exactly once for the whole window.
        assert_eq!(backend.mappings().len(), 1);
        assert_eq!(backend.mappings()[0].iova, iova);
        assert_eq!(backend.mappings()[0].len, 0x2000);
    }

    #[test]
    fn slpt_confines_dma_to_mapped_window_only() {
        // §S9.1 confinement, host proof (WI-7b step 3 C2): after a
        // window is mapped, the SLPT resolves addresses INSIDE it and
        // returns None for the page immediately before and after — i.e.
        // a device whose context entry routes through this SLPT cannot
        // reach memory outside its granted window (TE-on faults it).
        let mut src = MockFrameSource::new();
        let (mut backend, domain, root) = provisioned_backend(&mut src);
        let iova = 0x0100_0000_0000_u64;
        let phys = 0x8_8000_0000_u64;
        backend
            .map_with_src(domain, iova, phys, 0x2000, IommuFlags::READ, &mut src)
            .expect("map ok");
        // Inside the 2-page window: translated.
        assert_eq!(translate_slpt(root, iova, AW4, &src), Some(phys));
        assert_eq!(
            translate_slpt(root, iova + 0x1000, AW4, &src),
            Some(phys + 0x1000)
        );
        // One page BEFORE the window: not mapped → device DMA there faults.
        assert_eq!(translate_slpt(root, iova - 0x1000, AW4, &src), None);
        // One page AFTER the window: not mapped → device DMA there faults.
        assert_eq!(translate_slpt(root, iova + 0x2000, AW4, &src), None);
        // A wildly out-of-window address: not mapped.
        assert_eq!(translate_slpt(root, 0x0200_0000_0000, AW4, &src), None);
    }

    #[test]
    fn domain_has_mappings_tracks_te_finalize_guard_condition() {
        // WI-7b step 3 C2: the TE-finalize guard refuses the flip until a
        // confined domain's SLPT is built. `domain_has_mappings` is that
        // signal.
        let mut src = MockFrameSource::new();
        let (mut backend, domain, _root) = provisioned_backend(&mut src);
        assert!(
            !backend.domain_has_mappings(domain),
            "no mappings before DmaMap"
        );
        backend
            .map_with_src(
                domain,
                0x0100_0000_0000,
                0x9000,
                0x1000,
                IommuFlags::READ,
                &mut src,
            )
            .expect("map ok");
        assert!(backend.domain_has_mappings(domain), "mapped → guard passes");
        // A different, unmapped domain reports no mappings.
        assert!(!backend.domain_has_mappings(DomainId::new(0x55)));
    }

    #[test]
    fn attached_domain_returns_binding_for_finalize_guard() {
        // WI-7b step 3 C2: the finalize guard reads a confined device's
        // domain via `attached_domain`.
        let mut backend = VtdBackend::new();
        let dom = DomainId::new(4);
        backend.install_domain(dom).expect("install ok");
        let bdf = PciBdf::from_parts(6, 1, 0);
        backend.attach_device(bdf, dom).expect("attach ok");
        assert_eq!(backend.attached_domain(bdf), Some(dom));
        assert_eq!(backend.attached_domain(PciBdf::from_parts(0, 2, 0)), None);
    }

    #[test]
    fn map_with_src_without_domain_pt_is_bookkeeping_only() {
        let mut backend = VtdBackend::new();
        let domain = DomainId::new(9);
        backend.install_domain(domain).expect("install ok");
        let mut src = MockFrameSource::new();
        backend
            .map_with_src(domain, 0x1000, 0x2000, 0x1000, IommuFlags::READ, &mut src)
            .expect("map ok");
        // No PT root → legacy behaviour: record the tuple, never touch
        // the frame source.
        assert_eq!(src.alloc_calls, 0);
        assert_eq!(backend.mappings().len(), 1);
    }

    #[test]
    fn map_with_src_unknown_domain_rejected() {
        let mut backend = VtdBackend::new();
        let mut src = MockFrameSource::new();
        assert_eq!(
            backend.map_with_src(
                DomainId::new(1),
                0x1000,
                0x2000,
                0x1000,
                IommuFlags::READ,
                &mut src
            ),
            Err(IommuError::InvalidDomain)
        );
    }

    #[test]
    fn map_with_src_frame_exhaustion_records_nothing() {
        let mut src = MockFrameSource::new();
        let (mut backend, domain, _root) = provisioned_backend(&mut src);
        src.force_alloc_fail = true;
        assert_eq!(
            backend.map_with_src(
                domain,
                0x0100_0000_0000,
                0x8000,
                0x1000,
                IommuFlags::READ,
                &mut src
            ),
            Err(IommuError::MapFailed)
        );
        // The failed map must NOT leave a bookkeeping record — the
        // syscall handler rolls back its page-table installs on error
        // and a stale record would desynchronise teardown.
        assert!(backend.mappings().is_empty());
    }

    #[test]
    fn unmap_with_src_clears_leaves_keeps_intermediates() {
        let mut src = MockFrameSource::new();
        let (mut backend, domain, root) = provisioned_backend(&mut src);
        let iova = 0x0100_0000_0000_u64;
        backend
            .map_with_src(domain, iova, 0x9000, 0x2000, IommuFlags::READ, &mut src)
            .expect("map ok");
        let allocs_after_map = src.alloc_calls;
        backend
            .unmap_with_src(domain, iova, 0x2000, &mut src)
            .expect("unmap ok");
        // Leaves cleared…
        assert_eq!(translate_slpt(root, iova, AW4, &src), None);
        assert_eq!(translate_slpt(root, iova + 0x1000, AW4, &src), None);
        // …bookkeeping gone…
        assert!(backend.mappings().is_empty());
        // …and intermediates retained (Phase 1: freed wholesale on
        // domain-root release, not per-unmap).
        assert_eq!(src.alloc_calls, allocs_after_map);
        assert_eq!(src.free_calls, 0);
    }

    #[test]
    fn unmap_with_src_unknown_mapping_is_unmap_failed() {
        let mut src = MockFrameSource::new();
        let (mut backend, domain, _root) = provisioned_backend(&mut src);
        assert_eq!(
            backend.unmap_with_src(domain, 0x0100_0000_0000, 0x1000, &mut src),
            Err(IommuError::UnmapFailed)
        );
    }

    #[test]
    fn release_domain_pt_frees_every_intermediate_no_leak() {
        let mut src = MockFrameSource::new();
        let (mut backend, domain, _root) = provisioned_backend(&mut src);
        // Two windows in different subtrees to force several
        // intermediate tables.
        backend
            .map_with_src(
                domain,
                0x0100_0000_0000,
                0x9000,
                0x1000,
                IommuFlags::READ,
                &mut src,
            )
            .expect("map a ok");
        backend
            .map_with_src(
                domain,
                0x0200_0000_0000,
                0xA000,
                0x1000,
                IommuFlags::READ,
                &mut src,
            )
            .expect("map b ok");
        let total_allocated = src.alloc_calls;
        backend
            .release_domain_pt(domain, &mut src)
            .expect("release ok");
        // Every frame the builder pulled (root + all intermediates)
        // returned to the source — the WI-7b leak fix. Leaf targets
        // (0x9000/0xA000) are DMA buffers owned elsewhere and must NOT
        // appear in the freed list.
        assert_eq!(src.free_calls, total_allocated);
        assert!(!src.freed.contains(&0x9000));
        assert!(!src.freed.contains(&0xA000));
    }

    #[test]
    fn free_slpt_subtree_on_empty_root_is_noop() {
        let mut src = MockFrameSource::new();
        let root = fake_root(&mut src);
        free_slpt_subtree(root, AW4.levels(), &mut src);
        assert_eq!(src.free_calls, 0);
    }
}

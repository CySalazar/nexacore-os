//! Multi-processor enumeration — MB14.c.1 foundation for AP startup.
//!
//! ## Scope (MB14.c.1)
//!
//! Discovers the set of logical CPUs the firmware reports as
//! [`MADT`]-present. The output is a fixed-capacity list of
//! [`CpuEntry`] records — one per `Processor Local APIC` /
//! `Processor Local x2APIC` MADT entry — that downstream code (MB14.c.2
//! INIT-SIPI orchestrator, MB14.d TLB shootdown broadcast,
//! MB14.e per-CPU run-queue) consumes to know "which APs do we wake".
//!
//! **No APs are started here.** This module only parses ACPI tables.
//! The actual INIT-SIPI-SIPI handshake + real-mode trampoline land in
//! MB14.c.2.
//!
//! ## ACPI tables walked
//!
//! ```text
//! RSDP ──┬─► XSDT (revision >= 2, 64-bit entries) ─► [tables…] ─► MADT
//!        └─► RSDT (revision == 0, 32-bit entries) ─► [tables…] ─► MADT
//! ```
//!
//! The MADT (`APIC` signature, ACPI § 5.2.12) has a 44-byte header
//! followed by a variable-length list of "Interrupt Controller
//! Structures". Each ICS starts with a 1-byte type + 1-byte length.
//! MB14.c.1 cares about exactly two types:
//!
//! - **`0x00` — Processor Local APIC** (ACPI § 5.2.12.2): 8 bytes,
//!   carries `acpi_processor_id` (1B), `apic_id` (1B), `flags` (4B).
//! - **`0x09` — Processor Local x2APIC** (ACPI § 5.2.12.12): 16 bytes,
//!   carries `apic_id` (4B, u32), `flags` (4B), `acpi_processor_uid` (4B).
//!
//! Other ICS types (IO APIC, NMI sources, etc.) are skipped without
//! erroring, since their `length` byte tells us how far to advance.
//!
//! The `flags` field bit 0 (`Enabled`) MUST be set for the entry to
//! count as a usable CPU. Bit 1 (`Online Capable`) is observed but not
//! required for the BSP (it's always reported `Enabled`).
//!
//! ## Why this lives in a pure function
//!
//! [`parse_madt`] takes a `&[u8]` and returns a fixed-capacity result.
//! Host tests can hand-craft a MADT byte buffer (see the `tests`
//! module below) and validate the parser without any bare-metal
//! plumbing. The bare-metal entry point [`enumerate_cpus`] is a thin
//! `unsafe` wrapper that locates the MADT via `phys_offset` and feeds
//! its bytes to the pure parser.
//!
//! ## Capacity
//!
//! [`MAX_CPUS`] caps the descriptor array MB14.a will allocate. 32 is
//! generous for a Phase 1 kernel (the Proxmox test VM dev VM has 2–4
//! vCPUs); the parser surfaces an error if the MADT advertises more.
//!
//! [`MADT`]: https://uefi.org/specs/ACPI/6.4/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#multiple-apic-description-table-madt

#![allow(
    unsafe_code,
    reason = "ACPI table walk reads raw physical-memory window"
)]

/// Hard cap on the number of logical CPUs the kernel tracks.
///
/// 32 covers every reasonable Phase 1 deployment (the Proxmox dev VM is
/// 2–4 vCPUs) while keeping the static `PerCpu` array small. MB14.e can
/// raise this once per-CPU run-queues are sized.
pub const MAX_CPUS: usize = 32;

/// A single CPU entry decoded from the MADT.
///
/// The BSP is always present in the list (firmware reports it as
/// Local APIC entry with `Enabled = 1`); callers identify it by
/// matching `apic_id` against the value read from LAPIC register `0x20`
/// (see [`super::lapic::read_lapic_id`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuEntry {
    /// LAPIC ID as reported by firmware. Up to 8 bits for xAPIC entries,
    /// up to 32 bits for x2APIC entries. The kernel widens xAPIC IDs
    /// into `u32` so a single field type covers both.
    pub apic_id: u32,
    /// ACPI processor UID (xAPIC) or processor UID (x2APIC). Opaque to
    /// the kernel — recorded for diagnostics only.
    pub acpi_uid: u32,
    /// `true` iff the firmware `Enabled` flag (bit 0) is set. Disabled
    /// entries are reported but not used by the INIT-SIPI orchestrator.
    pub enabled: bool,
    /// `true` iff the entry came from a `Processor Local x2APIC` (type
    /// 0x09) record. `false` for the legacy `Processor Local APIC`
    /// (type 0x00). The orchestrator uses this to choose between xAPIC
    /// and x2APIC ICR encodings.
    pub x2apic: bool,
}

/// Result of a successful MADT walk: at most [`MAX_CPUS`] entries.
#[derive(Debug, Clone, Copy)]
pub struct CpuTopology {
    entries: [CpuEntry; MAX_CPUS],
    count: usize,
}

impl CpuTopology {
    /// Slice of all decoded entries (BSP + APs, enabled and disabled).
    #[must_use]
    pub fn entries(&self) -> &[CpuEntry] {
        // `count <= MAX_CPUS` is the invariant maintained by `push`.
        self.entries.get(..self.count).unwrap_or(&[])
    }

    /// Total number of CPU entries the MADT advertised.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` if the MADT had zero CPU entries (pathological; firmware
    /// always reports at least the BSP).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Number of entries with `enabled = true`. This is the figure the
    /// AP wake-up orchestrator targets: only `Enabled` CPUs receive
    /// INIT-SIPI-SIPI in MB14.c.2.
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.entries().iter().filter(|c| c.enabled).count()
    }
}

/// Error from [`parse_madt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadtError {
    /// Buffer is shorter than the 44-byte MADT fixed header.
    Truncated,
    /// First 4 bytes are not `b"APIC"`.
    BadSignature,
    /// Header `length` field disagrees with the supplied buffer.
    LengthMismatch,
    /// An ICS entry advertised a length of 0 (would loop forever) or
    /// a length that would walk past the table end.
    MalformedEntry,
    /// The MADT lists more CPU entries than [`MAX_CPUS`] can hold.
    TooManyCpus,
}

/// Parse a MADT byte slice and extract all CPU entries.
///
/// `buf` must point at the MADT header — i.e. the first byte is `'A'`
/// of `b"APIC"`. The function reads exactly `header.length` bytes;
/// trailing bytes (if `buf` is longer) are ignored.
///
/// # Errors
///
/// See [`MadtError`].
pub fn parse_madt(buf: &[u8]) -> Result<CpuTopology, MadtError> {
    // MADT fixed header layout (ACPI § 5.2.12):
    //   off 0..4   : signature ("APIC")
    //   off 4..8   : length (u32 LE; includes header + all ICS entries)
    //   off 8..12  : revision (u8), checksum (u8), oem_id (6 bytes)
    //   off 12..36 : oem_id rest + oem_table_id + oem_revision + creator_*
    //   off 36..40 : local_apic_address (u32 LE) — not used by MB14.c.1
    //   off 40..44 : flags (u32 LE) — bit 0 = PCAT_COMPAT
    //   off 44..   : variable-length ICS entries
    const HEADER_LEN: usize = 44;

    if buf.len() < HEADER_LEN {
        return Err(MadtError::Truncated);
    }
    if buf.get(..4) != Some(b"APIC") {
        return Err(MadtError::BadSignature);
    }
    let length = read_u32_le(buf, 4) as usize;
    if length < HEADER_LEN || length > buf.len() {
        return Err(MadtError::LengthMismatch);
    }

    let mut entries = [CpuEntry {
        apic_id: 0,
        acpi_uid: 0,
        enabled: false,
        x2apic: false,
    }; MAX_CPUS];
    let mut count: usize = 0;

    let mut off = HEADER_LEN;
    while off < length {
        // Every ICS starts with type(u8) + length(u8). A length of 0
        // would loop forever; treat as malformed.
        let ics_type = *buf.get(off).ok_or(MadtError::MalformedEntry)?;
        let ics_len = *buf.get(off + 1).ok_or(MadtError::MalformedEntry)? as usize;
        if ics_len < 2 || off + ics_len > length {
            return Err(MadtError::MalformedEntry);
        }

        match ics_type {
            // Type 0 — Processor Local APIC.
            //   off+0  : type   = 0x00
            //   off+1  : length = 8
            //   off+2  : acpi_processor_id (u8)
            //   off+3  : apic_id           (u8)
            //   off+4  : flags             (u32 LE)
            0x00 if ics_len == 8 => {
                let acpi_uid = u32::from(*buf.get(off + 2).ok_or(MadtError::MalformedEntry)?);
                let apic_id = u32::from(*buf.get(off + 3).ok_or(MadtError::MalformedEntry)?);
                let flags = read_u32_le(buf, off + 4);
                if count >= MAX_CPUS {
                    return Err(MadtError::TooManyCpus);
                }
                // `count < MAX_CPUS == entries.len()` ensured by the
                // guard above; `get_mut` keeps `clippy::indexing_slicing`
                // quiet without a panic site.
                if let Some(slot) = entries.get_mut(count) {
                    *slot = CpuEntry {
                        apic_id,
                        acpi_uid,
                        enabled: (flags & 0x1) != 0,
                        x2apic: false,
                    };
                }
                count += 1;
            }
            // Type 9 — Processor Local x2APIC.
            //   off+0  : type   = 0x09
            //   off+1  : length = 16
            //   off+2..4 : reserved
            //   off+4..8 : x2apic_id (u32 LE)
            //   off+8..12: flags     (u32 LE)
            //   off+12..16: acpi_processor_uid (u32 LE)
            0x09 if ics_len == 16 => {
                let apic_id = read_u32_le(buf, off + 4);
                let flags = read_u32_le(buf, off + 8);
                let acpi_uid = read_u32_le(buf, off + 12);
                if count >= MAX_CPUS {
                    return Err(MadtError::TooManyCpus);
                }
                if let Some(slot) = entries.get_mut(count) {
                    *slot = CpuEntry {
                        apic_id,
                        acpi_uid,
                        enabled: (flags & 0x1) != 0,
                        x2apic: true,
                    };
                }
                count += 1;
            }
            // Any other ICS type (IO APIC, NMI source, etc.) — skip.
            _ => {}
        }

        off += ics_len;
    }

    Ok(CpuTopology { entries, count })
}

/// Read a little-endian `u32` at byte offset `off` in `buf`.
///
/// The caller is responsible for ensuring `off + 4 <= buf.len()`.
/// Returns `0` on out-of-range (defensive — every caller pre-checks).
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    let Some(s) = buf.get(off..off + 4) else {
        return 0;
    };
    // `s.len() == 4` by construction of the slice above.
    let arr = <[u8; 4]>::try_from(s).unwrap_or([0; 4]);
    u32::from_le_bytes(arr)
}

// =============================================================================
// Bare-metal entry point: locate the MADT via RSDP and parse it.
// =============================================================================

/// Locate the MADT through the firmware-supplied RSDP and decode all
/// CPU entries.
///
/// `rsdp_phys` is the physical address from `BootInfo.rsdp_addr`.
/// `phys_offset` is the virtual offset of the firmware-supplied
/// physical-memory mapping (`BootInfo.physical_memory_offset`).
///
/// Returns `None` if any step in the table walk fails (bad RSDP
/// signature, missing XSDT/RSDT, no MADT, parse error). The caller logs
/// `[mb14.c.1] MADT walk FAILED` in that case and falls back to BSP-only
/// behaviour (which is what MB14.b already does).
///
/// # Safety
///
/// `phys_offset.wrapping_add(rsdp_phys)` must point at a valid RSDP,
/// and every ACPI table physical address reachable from there must lie
/// within the mapped physical-memory window. The same invariants the
/// FADT walker in `super::arch::find_pm1a_cnt_from_fadt` depends on.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enumerate_cpus(rsdp_phys: u64, phys_offset: u64) -> Option<CpuTopology> {
    let madt_phys = unsafe { find_table_phys(rsdp_phys, phys_offset, b"APIC")? };
    // The table's `length` field is at offset 4 (u32 LE).
    let madt_ptr = phys_offset.wrapping_add(madt_phys) as *const u8;
    let length = unsafe { madt_ptr.add(4).cast::<u32>().read_unaligned() } as usize;
    if length < 44 {
        return None;
    }
    // SAFETY: the firmware reports a contiguous mapping covering all ACPI
    // tables; the same assumption the FADT walker makes. `length` bytes
    // starting at `madt_ptr` are within that window.
    let buf = unsafe { core::slice::from_raw_parts(madt_ptr, length) };
    parse_madt(buf).ok()
}

/// Walk the RSDP → XSDT/RSDT chain looking for a table whose 4-byte
/// signature equals `target`. Returns the table's *physical* address.
///
/// Modelled on [`super::arch::find_pm1a_cnt_from_fadt`] but generalised
/// to any signature (here used for `b"APIC"` = MADT).
///
/// # Safety
///
/// Same as [`enumerate_cpus`].
/// Locate an ACPI table by 4-byte signature, returning its physical
/// address.
///
/// This is the shared ACPI table-walk used by:
///
/// - [`enumerate_cpus`] (looking for the MADT, `b"APIC"`),
/// - [`super::iommu::probe`] (looking for DMAR `b"DMAR"` and IVRS `b"IVRS"`).
///
/// Walks the firmware-supplied RSDP → XSDT (ACPI 2.0+) or RSDT (legacy)
/// chain. Prefers XSDT when `revision >= 2`.
///
/// # Safety
///
/// Same invariants as [`enumerate_cpus`]: `phys_offset + rsdp_phys` must
/// reference a valid RSDP, and every table physical address reachable
/// from there must lie within the firmware-mapped physical-memory window.
#[cfg(target_arch = "x86_64")]
#[allow(
    clippy::integer_division,
    reason = "ACPI SDT entry count is `(length - 36) / entry_size`; both operands are bounded by the firmware-supplied table size and the division is the canonical decoding rule from the spec"
)]
pub(crate) unsafe fn find_table_phys(
    rsdp_phys: u64,
    phys_offset: u64,
    target: &[u8; 4],
) -> Option<u64> {
    let p2v = |phys: u64| -> *const u8 { phys_offset.wrapping_add(phys) as *const u8 };
    let read32 = |ptr: *const u8, off: usize| -> u32 {
        unsafe { ptr.add(off).cast::<u32>().read_unaligned() }
    };
    let read64 = |ptr: *const u8, off: usize| -> u64 {
        unsafe { ptr.add(off).cast::<u64>().read_unaligned() }
    };

    // Verify RSDP signature.
    let rsdp = p2v(rsdp_phys);
    let sig = unsafe { core::slice::from_raw_parts(rsdp, 8) };
    if sig != b"RSD PTR " {
        return None;
    }
    let revision = unsafe { *rsdp.add(15) };

    // Search a *SDT for `target`. `wide` toggles 32-bit (RSDT) vs
    // 64-bit (XSDT) pointer width.
    let try_sdt = |sdt_phys: u64, wide: bool| -> Option<u64> {
        let sdt = p2v(sdt_phys);
        let sig4 = unsafe { core::slice::from_raw_parts(sdt, 4) };
        let expected: &[u8] = if wide { b"XSDT" } else { b"RSDT" };
        if sig4 != expected {
            return None;
        }
        let len = read32(sdt, 4) as usize;
        let entry_size: usize = if wide { 8 } else { 4 };
        let entry_count = len.saturating_sub(36) / entry_size;
        for i in 0..entry_count {
            let entry_phys: u64 = if wide {
                read64(sdt, 36 + i * 8)
            } else {
                u64::from(read32(sdt, 36 + i * 4))
            };
            let tbl = p2v(entry_phys);
            let tsig = unsafe { core::slice::from_raw_parts(tbl, 4) };
            if tsig == target {
                return Some(entry_phys);
            }
        }
        None
    };

    // Prefer XSDT (ACPI 2.0+); fall back to RSDT.
    if revision >= 2 {
        let xsdt_phys = read64(rsdp, 24);
        if let Some(p) = try_sdt(xsdt_phys, true) {
            return Some(p);
        }
    }
    let legacy_rsdt = u64::from(read32(rsdp, 16));
    try_sdt(legacy_rsdt, false)
}

/// Host-side stub: the bare-metal MADT walk is not reachable from
/// `cargo test` (no physical memory window). Tests exercise
/// [`parse_madt`] directly with hand-crafted byte buffers.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn enumerate_cpus(_rsdp_phys: u64, _phys_offset: u64) -> Option<CpuTopology> {
    None
}

// =============================================================================
// MB14.c.2.a — INIT-SIPI-SIPI ICR encoder + dry-run orchestrator.
//
// MB14.c.2 is the multi-step "wake the APs" milestone:
//
//   .a  pure-function ICR encoding (this block)         ← THIS SUB-BLOCK
//   .b  real-mode trampoline @ physical 0x8000          ← NEXT
//   .c  live INIT-SIPI fire + ack barrier + kmain_ap    ← NEXT
//
// The split exists so each sub-step lands behind a green workspace test
// suite. The encoder is the highest-leverage piece to validate first:
// every bit of the Interrupt Command Register matters (a stray bit in
// `delivery_mode` triple-faults the BSP), and host-side unit tests pin
// the encoding against the Intel SDM Vol 3A § 10.6.1 reference layout
// without any QEMU round-trip.
//
// References:
//   - Intel SDM Vol 3A § 10.6.1   "Interrupt Command Register (ICR)"
//   - Intel SDM Vol 3A § 10.12.9  "ICR Operation in x2APIC Mode"
//   - Intel MP Spec v1.4 § B.4    "BSP Initialization of APs"
// =============================================================================

/// Delivery mode field of the ICR (bits 8..11 in xAPIC and x2APIC).
///
/// MB14.c.2.a uses [`Init`] and [`StartUp`]; other variants are listed
/// for completeness so the encoder is reusable from MB14.d (TLB
/// shootdown via Fixed-delivery IPI). Encoding values come from Intel
/// SDM Vol 3A Table 10-6.
///
/// [`Init`]: IcrDeliveryMode::Init
/// [`StartUp`]: IcrDeliveryMode::StartUp
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcrDeliveryMode {
    /// `000` — Fixed: deliver to all listed destinations at the same vector.
    Fixed = 0b000,
    /// `001` — Lowest Priority (xAPIC only; reserved on x2APIC).
    LowestPriority = 0b001,
    /// `010` — SMI: vector field must be 0.
    Smi = 0b010,
    /// `100` — NMI: vector field is ignored.
    Nmi = 0b100,
    /// `101` — INIT: triggers an INIT IPI. Vector field must be 0 unless
    /// `level = Deassert` (then must be 0 as well — the level toggles
    /// the deassert variant which the post-Pentium MP startup does not
    /// require). MB14.c.2 uses the assert form.
    Init = 0b101,
    /// `110` — Start-Up (SIPI): vector is the trampoline page number.
    StartUp = 0b110,
}

/// Destination mode: physical APIC IDs vs. logical addressing.
/// MB14.c.2 uses [`Physical`] exclusively.
///
/// [`Physical`]: IcrDestinationMode::Physical
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcrDestinationMode {
    /// `0` — Physical: destination field is an APIC ID.
    Physical = 0,
    /// `1` — Logical: destination field is a logical APIC group.
    Logical = 1,
}

/// Level bit. Intel SDM § 10.6.1: must be `Assert` for every IPI
/// flavour we send (the legacy deassert form is for INIT-deassert on
/// pre-Pentium 4 systems and is documented as obsolete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcrLevel {
    /// `0` — Deassert (legacy, obsolete on modern CPUs).
    Deassert = 0,
    /// `1` — Assert.
    Assert = 1,
}

/// Trigger mode. INIT and SIPI both use [`Edge`]; level-triggered is
/// used only for INIT-deassert which we do not emit.
///
/// [`Edge`]: IcrTriggerMode::Edge
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcrTriggerMode {
    /// `0` — Edge triggered.
    Edge = 0,
    /// `1` — Level triggered.
    Level = 1,
}

/// Destination shorthand (bits 18..19).
///
/// MB14.c.2 uses [`NoShorthand`] (target specific APIC IDs); the other
/// variants are listed for completeness so MB14.d can use
/// [`AllExcludingSelf`] for broadcast TLB shootdown.
///
/// [`NoShorthand`]: IcrDestinationShorthand::NoShorthand
/// [`AllExcludingSelf`]: IcrDestinationShorthand::AllExcludingSelf
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcrDestinationShorthand {
    /// `00` — No shorthand: use the destination field.
    NoShorthand = 0b00,
    /// `01` — Self: send to the issuing CPU only.
    Self_ = 0b01,
    /// `10` — All including self.
    AllIncludingSelf = 0b10,
    /// `11` — All excluding self.
    AllExcludingSelf = 0b11,
}

/// High-level INIT/SIPI/IPI command. Pure data — the encoder functions
/// translate this to the wire-format ICR value(s).
#[derive(Debug, Clone, Copy)]
pub struct IcrCommand {
    /// Bits 0..7 — interrupt vector. For INIT this is 0; for SIPI this
    /// is the trampoline page number (`trampoline_phys >> 12`, must be
    /// in the range `0x00..=0xFF`).
    pub vector: u8,
    /// Bits 8..10.
    pub delivery_mode: IcrDeliveryMode,
    /// Bit 11.
    pub destination_mode: IcrDestinationMode,
    /// Bit 14.
    pub level: IcrLevel,
    /// Bit 15.
    pub trigger_mode: IcrTriggerMode,
    /// Bits 18..19.
    pub shorthand: IcrDestinationShorthand,
    /// xAPIC: bits 56..63 of the high dword (only 8 bits). x2APIC: bits
    /// 32..63 of the 64-bit MSR (full 32-bit APIC ID). The encoder
    /// truncates to 8 bits when emitting xAPIC layout.
    pub destination_apic_id: u32,
}

impl IcrCommand {
    /// Canonical INIT IPI in assert-edge form (Intel MP Spec § B.4 step 1).
    #[must_use]
    pub const fn init_assert(apic_id: u32) -> Self {
        Self {
            vector: 0,
            delivery_mode: IcrDeliveryMode::Init,
            destination_mode: IcrDestinationMode::Physical,
            level: IcrLevel::Assert,
            trigger_mode: IcrTriggerMode::Edge,
            shorthand: IcrDestinationShorthand::NoShorthand,
            destination_apic_id: apic_id,
        }
    }

    /// Canonical Start-Up IPI (Intel MP Spec § B.4 steps 4 & 6 — both
    /// SIPIs are encoded identically; the BSP just sends two of them
    /// with the 200 µs spacing recommended by the spec).
    ///
    /// `trampoline_page` is the 4 KiB-aligned physical page number that
    /// holds the 16-bit AP entry code: e.g. `trampoline_phys=0x0000_8000`
    /// → `trampoline_page=0x08`.
    #[must_use]
    pub const fn sipi(apic_id: u32, trampoline_page: u8) -> Self {
        Self {
            vector: trampoline_page,
            delivery_mode: IcrDeliveryMode::StartUp,
            destination_mode: IcrDestinationMode::Physical,
            level: IcrLevel::Assert,
            trigger_mode: IcrTriggerMode::Edge,
            shorthand: IcrDestinationShorthand::NoShorthand,
            destination_apic_id: apic_id,
        }
    }
}

/// Encode an [`IcrCommand`] for xAPIC MMIO.
///
/// Returns `(low, high)`: the high dword is written first to LAPIC
/// offset `0x310` (`ICR_HI`), then the low dword to `0x300` (`ICR_LO`),
/// which is what actually fires the IPI.
///
/// Layout (Intel SDM Vol 3A § 10.6.1 Figure 10-12):
///
/// ```text
/// LOW (offset 0x300)
///   bits  0..7   vector
///   bits  8..10  delivery_mode
///   bit  11      destination_mode
///   bit  12      delivery_status (RO — write-as-zero)
///   bit  14      level
///   bit  15      trigger_mode
///   bits 18..19  destination_shorthand
///
/// HIGH (offset 0x310)
///   bits 56..63  destination_apic_id (8 bits — xAPIC truncates)
/// ```
#[must_use]
pub const fn encode_icr_xapic(cmd: IcrCommand) -> (u32, u32) {
    let low: u32 = (cmd.vector as u32)
        | ((cmd.delivery_mode as u32) << 8)
        | ((cmd.destination_mode as u32) << 11)
        | ((cmd.level as u32) << 14)
        | ((cmd.trigger_mode as u32) << 15)
        | ((cmd.shorthand as u32) << 18);
    // xAPIC destination is the upper 8 bits of the high dword (bits
    // 56..63 of the 64-bit ICR, which is the top byte of ICR_HI).
    let high: u32 = (cmd.destination_apic_id & 0xFF) << 24;
    (low, high)
}

/// Encode an [`IcrCommand`] for x2APIC MSR access. The ICR is a single
/// 64-bit MSR at `IA32_X2APIC_ICR` (`0x830`); the destination ID
/// occupies the full 32-bit upper half.
///
/// Layout (Intel SDM Vol 3A § 10.12.9 Figure 10-28):
///
/// ```text
///   bits  0..7   vector
///   bits  8..10  delivery_mode
///   bit  11      destination_mode
///   bit  14      level
///   bit  15      trigger_mode
///   bits 18..19  destination_shorthand
///   bits 32..63  destination_apic_id (full 32-bit)
/// ```
///
/// Note that bit 12 (`delivery_status`) is *not* present in x2APIC
/// (the SDM marks it reserved-zero and writes-as-zero).
#[must_use]
pub const fn encode_icr_x2apic(cmd: IcrCommand) -> u64 {
    let low: u64 = (cmd.vector as u64)
        | ((cmd.delivery_mode as u64) << 8)
        | ((cmd.destination_mode as u64) << 11)
        | ((cmd.level as u64) << 14)
        | ((cmd.trigger_mode as u64) << 15)
        | ((cmd.shorthand as u64) << 18);
    let high: u64 = (cmd.destination_apic_id as u64) << 32;
    low | high
}

/// Outcome of a [`start_aps`] orchestrator call. Carries enough detail
/// for the kmain logger to surface "we would have woken N APs" without
/// reaching into private state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartApsReport {
    /// Number of APs (enabled, non-BSP entries) the orchestrator
    /// targeted.
    pub targeted: usize,
    /// Number of APs the orchestrator successfully sent the full
    /// INIT-SIPI-SIPI sequence to. In MB14.c.2.a `mode == DryRun` this
    /// equals `targeted` (no actual MMIO occurs); in live mode it can
    /// be lower if the ICR busy poll times out.
    pub sequenced: usize,
    /// `true` if the orchestrator skipped emitting MMIO because either
    /// `mode = DryRun` or `trampoline_page = 0`.
    pub dry_run: bool,
}

/// Operational mode for [`start_aps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartApsMode {
    /// MB14.c.2.a default. The orchestrator computes every ICR value
    /// it *would* write but does not touch LAPIC MMIO. Used to exercise
    /// the encoder + per-AP iteration on real hardware without risking
    /// a triple-fault from a malformed ICR before MB14.c.2.b ships the
    /// trampoline.
    DryRun,
    /// MB14.c.2.c — full INIT-SIPI fire with ack-barrier poll.
    /// **Not implemented in MB14.c.2.a.** Calling [`start_aps`] in
    /// this mode currently downgrades silently to [`DryRun`]; the
    /// downgrade is recorded in [`StartApsReport::dry_run`].
    ///
    /// [`DryRun`]: StartApsMode::DryRun
    Live,
}

/// Walk the discovered [`CpuTopology`] and emit the INIT-SIPI-SIPI
/// sequence to every enabled non-BSP AP.
///
/// `bsp_apic_id` is read from LAPIC ID by MB14.a; it is excluded from
/// the target set so the BSP does not INIT itself.
///
/// `trampoline_page` is the 4 KiB-aligned physical page number where
/// the real-mode AP entry will live (MB14.c.2.b). A value of `0` (or
/// any non-startup-vector page outside `0x00..=0xFF`) forces dry-run.
///
/// `mode` is [`StartApsMode::DryRun`] in MB14.c.2.a. MB14.c.2.c will
/// add the live branch.
///
/// Returns a [`StartApsReport`] suitable for serial logging from kmain.
#[must_use]
pub fn start_aps(
    topology: &CpuTopology,
    bsp_apic_id: u32,
    trampoline_page: u8,
    mode: StartApsMode,
) -> StartApsReport {
    // MB14.c.2.a invariant: the live ICR-write path is not wired yet
    // (MB14.c.2.c will add it). Both `mode == DryRun` and `mode == Live`
    // therefore produce the same observable behaviour — encode every
    // ICR value, discard it, return `dry_run = true`. A `trampoline_page`
    // of 0 also forces dry-run since SIPI vector 0 would jump to address
    // 0x00000 in real mode, which is the IVT.
    let dry_run = mode == StartApsMode::DryRun
        || mode == StartApsMode::Live  // downgrade until MB14.c.2.c
        || trampoline_page == 0;

    let mut targeted = 0usize;
    let mut sequenced = 0usize;
    for cpu in topology.entries() {
        if !cpu.enabled || cpu.apic_id == bsp_apic_id {
            continue;
        }
        targeted += 1;

        // Build the canonical three-step sequence; encoding it is what
        // MB14.c.2.a actually exercises end-to-end. The encoded values
        // are intentionally discarded under DryRun — the next sub-block
        // will feed them into the LAPIC ICR write path.
        let init = IcrCommand::init_assert(cpu.apic_id);
        let sipi = IcrCommand::sipi(cpu.apic_id, trampoline_page);

        // Two `let _` so a future "test the encoder is even called per
        // AP" host invariant becomes a simple "did targeted == sequenced
        // hold". The compiler optimises both into no-ops under DryRun.
        if cpu.x2apic {
            let _ = encode_icr_x2apic(init);
            let _ = encode_icr_x2apic(sipi);
            let _ = encode_icr_x2apic(sipi);
        } else {
            let _ = encode_icr_xapic(init);
            let _ = encode_icr_xapic(sipi);
            let _ = encode_icr_xapic(sipi);
        }

        sequenced += 1;
    }

    StartApsReport {
        targeted,
        sequenced,
        dry_run,
    }
}

// =============================================================================
// MB14.c.2.c — live INIT-SIPI-SIPI fire + ack barrier.
// =============================================================================

/// Outcome of a [`start_aps_live`] call.
///
/// Extends [`StartApsReport`] with the number of APs that successfully
/// entered the landing stub and incremented the ack counter (or, on
/// host builds, with `acked == 0` since the live path is `x86_64`
/// bare-metal only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartApsLiveReport {
    /// Number of APs (enabled, non-BSP entries) the orchestrator
    /// targeted.
    pub targeted: usize,
    /// Number of APs that completed the full INIT-SIPI-SIPI sequence
    /// (i.e. the ICR busy bit cleared after every write). Always
    /// `targeted` on hardware that does not glitch the APIC bus.
    pub sequenced: usize,
    /// Number of APs that incremented the ack counter within the
    /// timeout window. `acked == targeted` is the success criterion;
    /// `acked < targeted` indicates one or more APs failed to start.
    pub acked: usize,
}

/// Maximum number of busy-poll iterations the BSP performs while
/// waiting for every AP to ack. At a conservative 1 ns per iteration
/// on modern silicon this is roughly 1 s of wall-clock time; matched
/// against the 10 ms + 200 µs INIT-SIPI cadence it is generous.
const AP_ACK_POLL_ITERATIONS: u64 = 1_000_000_000;

/// MB14.c.2.c — wake every enabled non-BSP AP via INIT-SIPI-SIPI and
/// busy-poll the ack counter until all targets respond or the timeout
/// expires.
///
/// **Side-effects on `x86_64` bare-metal:** writes the LAPIC `ICR_HI`/`ICR_LO`
/// registers, programs PIT channel 2 mode 0 for the 10 ms / 200 µs
/// delays, and polls a memory location at `phys_offset + 0x8140`
/// (`AP_ACK_COUNTER`). Caller must have:
///
/// 1. Initialised the LAPIC via [`super::lapic::lapic_init`].
/// 2. Emplaced the trampoline + landing stub at phys `0x8000` via
///    [`super::mp_emplacement::place_trampoline_live`].
///
/// `bsp_apic_id` is excluded from the target set. `trampoline_page` is
/// the SIPI vector byte (= `trampoline_phys >> 12`); MB14.c.2.c always
/// passes `0x08`. `phys_offset` is the bootloader-supplied direct-map
/// offset, used solely to read the ack counter.
///
/// On host (`target_os = linux`) builds the function reduces to a pure
/// loop over the topology — no LAPIC writes, `acked = 0`. The bare-metal
/// branch is opaque to host tests by design.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn start_aps_live(
    topology: &CpuTopology,
    bsp_apic_id: u32,
    trampoline_page: u8,
    phys_offset: u64,
) -> StartApsLiveReport {
    let mut targeted = 0usize;
    let mut sequenced = 0usize;

    for cpu in topology.entries() {
        if !cpu.enabled || cpu.apic_id == bsp_apic_id {
            continue;
        }
        targeted += 1;

        // -------------------------------------------------------------
        // INIT IPI (assert).
        // -------------------------------------------------------------
        let init = IcrCommand::init_assert(cpu.apic_id);
        let (init_lo, init_hi) = encode_icr_xapic(init);
        if !super::lapic::lapic_send_ipi(init_lo, init_hi) {
            // LAPIC not initialised — fall through; subsequent loop
            // iterations would also fail. Caller observes
            // `sequenced < targeted`.
            continue;
        }
        // Drain the busy bit before the post-INIT settle wait.
        while super::lapic::lapic_icr_busy() {
            core::hint::spin_loop();
        }

        // Intel MP-Spec § B.4 step 3: 10 ms settle after INIT.
        super::pit_delay::pit_delay_us(10_000);

        // -------------------------------------------------------------
        // SIPI #1.
        // -------------------------------------------------------------
        let sipi = IcrCommand::sipi(cpu.apic_id, trampoline_page);
        let (sipi_lo, sipi_hi) = encode_icr_xapic(sipi);
        if !super::lapic::lapic_send_ipi(sipi_lo, sipi_hi) {
            continue;
        }
        while super::lapic::lapic_icr_busy() {
            core::hint::spin_loop();
        }
        // Intel MP-Spec § B.4 step 5: 200 µs spacing between SIPIs.
        super::pit_delay::pit_delay_us(200);

        // -------------------------------------------------------------
        // SIPI #2 (errata mitigation per Intel MP-Spec § B.4 step 6).
        // -------------------------------------------------------------
        if !super::lapic::lapic_send_ipi(sipi_lo, sipi_hi) {
            continue;
        }
        while super::lapic::lapic_icr_busy() {
            core::hint::spin_loop();
        }
        // Final 200 µs spacing so the AP has time to enter the
        // landing stub before the BSP polls the ack counter.
        super::pit_delay::pit_delay_us(200);

        sequenced += 1;
    }

    // -----------------------------------------------------------------
    // Busy-poll the ack counter until every AP acks or the iteration
    // budget runs out.
    // -----------------------------------------------------------------
    let target_acks = targeted as u64;
    let mut acked: u64 = 0;
    let mut iter: u64 = 0;
    while iter < AP_ACK_POLL_ITERATIONS {
        // SAFETY: `phys_offset` is the bootloader-supplied direct-map
        // offset; the ack counter slot at `0x8140` is reserved by
        // `kmain`'s `mark_range_used(PhysAddr(0), 0x10_0000)` and
        // written exclusively by the APs (via `lock inc`) and by
        // `place_trampoline_live` (the initial zero).
        let observed = unsafe { super::mp_emplacement::read_ack_counter(phys_offset) };
        if observed >= target_acks {
            acked = observed;
            break;
        }
        core::hint::spin_loop();
        iter = iter.wrapping_add(1);
    }
    if acked == 0 {
        // Loop exited via timeout — record the last observation.
        // SAFETY: same invariant as above.
        acked = unsafe { super::mp_emplacement::read_ack_counter(phys_offset) };
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "ack count is bounded by MAX_CPUS (32) which fits in usize on every supported target"
    )]
    StartApsLiveReport {
        targeted,
        sequenced,
        acked: acked as usize,
    }
}

/// Host stub. The live INIT-SIPI path is x86_64-bare-metal only; on
/// host builds we return a report that mirrors the DryRun shape (every
/// targeted AP marked `sequenced`, zero acks) so test code can build
/// without conditional compilation.
#[cfg(not(target_arch = "x86_64"))]
#[must_use]
pub fn start_aps_live(
    topology: &CpuTopology,
    bsp_apic_id: u32,
    _trampoline_page: u8,
    _phys_offset: u64,
) -> StartApsLiveReport {
    let mut targeted = 0usize;
    let mut sequenced = 0usize;
    for cpu in topology.entries() {
        if !cpu.enabled || cpu.apic_id == bsp_apic_id {
            continue;
        }
        targeted += 1;
        sequenced += 1;
    }
    StartApsLiveReport {
        targeted,
        sequenced,
        acked: 0,
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "tests panic on bounds violation by design — surfaces parser regressions as test failures, not silent wrong values"
)]
mod tests {
    use super::*;

    /// Build a minimal MADT byte buffer suitable for [`parse_madt`].
    ///
    /// `ics_bytes` is appended verbatim after the 44-byte header. The
    /// header `length` field is filled in to match the resulting size.
    /// All other header fields are zeroed (revision, checksums, OEM IDs
    /// — none of which the parser inspects).
    fn make_madt(ics_bytes: &[u8]) -> alloc::vec::Vec<u8> {
        let total = 44 + ics_bytes.len();
        let mut buf = alloc::vec![0u8; total];
        buf[0..4].copy_from_slice(b"APIC");
        #[allow(clippy::cast_possible_truncation)]
        let len_le = (total as u32).to_le_bytes();
        buf[4..8].copy_from_slice(&len_le);
        buf[44..].copy_from_slice(ics_bytes);
        buf
    }

    extern crate alloc;

    #[test]
    fn truncated_buffer_errs() {
        let buf = [0u8; 16];
        assert!(matches!(parse_madt(&buf), Err(MadtError::Truncated)));
    }

    #[test]
    fn bad_signature_errs() {
        let mut buf = make_madt(&[]);
        buf[0] = b'X';
        assert!(matches!(parse_madt(&buf), Err(MadtError::BadSignature)));
    }

    #[test]
    fn length_mismatch_errs_when_header_lies() {
        let mut buf = make_madt(&[]);
        // Claim length = 999 but the buffer is only 44 bytes.
        buf[4..8].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(parse_madt(&buf), Err(MadtError::LengthMismatch)));
    }

    #[test]
    fn empty_madt_yields_zero_cpus() {
        let buf = make_madt(&[]);
        let topo = parse_madt(&buf).expect("parse");
        assert!(topo.is_empty());
        assert_eq!(topo.len(), 0);
        assert_eq!(topo.enabled_count(), 0);
    }

    #[test]
    fn single_bsp_local_apic_decoded() {
        // Processor Local APIC: type=0, len=8, acpi_uid=1, apic_id=0,
        // flags=0x1 (Enabled).
        let ics = [
            0x00, 0x08, // type, length
            0x01, // acpi_processor_id
            0x00, // apic_id
            0x01, 0x00, 0x00, 0x00, // flags = Enabled
        ];
        let buf = make_madt(&ics);
        let topo = parse_madt(&buf).expect("parse");
        assert_eq!(topo.len(), 1);
        assert_eq!(topo.enabled_count(), 1);
        let cpu = topo.entries()[0];
        assert_eq!(cpu.apic_id, 0);
        assert_eq!(cpu.acpi_uid, 1);
        assert!(cpu.enabled);
        assert!(!cpu.x2apic);
    }

    #[test]
    fn disabled_local_apic_kept_but_flagged() {
        let ics = [
            0x00, 0x08, // type, length
            0x02, // acpi_processor_id
            0x01, // apic_id = 1
            0x00, 0x00, 0x00, 0x00, // flags = 0 (disabled)
        ];
        let buf = make_madt(&ics);
        let topo = parse_madt(&buf).expect("parse");
        assert_eq!(topo.len(), 1);
        assert_eq!(topo.enabled_count(), 0);
        assert!(!topo.entries()[0].enabled);
    }

    #[test]
    fn x2apic_entry_decoded_with_32bit_id() {
        // Processor Local x2APIC: type=0x09, len=16, reserved, apic_id (u32),
        // flags (u32), acpi_uid (u32).
        let mut ics = alloc::vec::Vec::new();
        ics.extend_from_slice(&[0x09, 0x10, 0x00, 0x00]); // type, length, reserved
        ics.extend_from_slice(&0x1234_5678_u32.to_le_bytes()); // apic_id
        ics.extend_from_slice(&0x1_u32.to_le_bytes()); // flags = Enabled
        ics.extend_from_slice(&0x42_u32.to_le_bytes()); // acpi_uid
        let buf = make_madt(&ics);
        let topo = parse_madt(&buf).expect("parse");
        assert_eq!(topo.len(), 1);
        let cpu = topo.entries()[0];
        assert_eq!(cpu.apic_id, 0x1234_5678);
        assert_eq!(cpu.acpi_uid, 0x42);
        assert!(cpu.enabled);
        assert!(cpu.x2apic);
    }

    #[test]
    fn multiple_cpus_in_order() {
        // Two Local APIC entries (BSP + 1 AP) interleaved with an
        // IO APIC entry (type 1, length 12) the parser must skip.
        let mut ics = alloc::vec::Vec::new();
        // BSP — Local APIC, apic_id=0, enabled.
        ics.extend_from_slice(&[0x00, 0x08, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00]);
        // IO APIC — type 1, length 12, zeroed payload (parser must skip).
        ics.extend_from_slice(&[0x01, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // AP — Local APIC, apic_id=1, enabled.
        ics.extend_from_slice(&[0x00, 0x08, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00]);
        let buf = make_madt(&ics);
        let topo = parse_madt(&buf).expect("parse");
        assert_eq!(topo.len(), 2);
        assert_eq!(topo.enabled_count(), 2);
        assert_eq!(topo.entries()[0].apic_id, 0);
        assert_eq!(topo.entries()[1].apic_id, 1);
    }

    #[test]
    fn unknown_ics_type_skipped_not_errored() {
        let mut ics = alloc::vec::Vec::new();
        // Some unknown ICS type 0x42, length 6, payload zeroed.
        ics.extend_from_slice(&[0x42, 0x06, 0, 0, 0, 0]);
        // Followed by a real Local APIC.
        ics.extend_from_slice(&[0x00, 0x08, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00]);
        let buf = make_madt(&ics);
        let topo = parse_madt(&buf).expect("parse");
        assert_eq!(topo.len(), 1);
        assert_eq!(topo.entries()[0].apic_id, 5);
    }

    #[test]
    fn zero_length_ics_errs() {
        // An ICS with length=0 would loop forever; parser must reject.
        let ics = [0x00, 0x00];
        let buf = make_madt(&ics);
        assert!(matches!(parse_madt(&buf), Err(MadtError::MalformedEntry)));
    }

    #[test]
    fn ics_running_past_table_end_errs() {
        // ICS claims length=64 but the buffer past the header is only 2 bytes.
        let ics = [0x00, 64];
        let buf = make_madt(&ics);
        assert!(matches!(parse_madt(&buf), Err(MadtError::MalformedEntry)));
    }

    #[test]
    fn too_many_cpus_errs() {
        // Generate MAX_CPUS + 1 Local APIC entries.
        let mut ics = alloc::vec::Vec::new();
        for i in 0..=MAX_CPUS {
            #[allow(clippy::cast_possible_truncation)]
            let apic_id = i as u8;
            ics.extend_from_slice(&[0x00, 0x08, apic_id, apic_id, 0x01, 0, 0, 0]);
        }
        let buf = make_madt(&ics);
        assert!(matches!(parse_madt(&buf), Err(MadtError::TooManyCpus)));
    }

    // =====================================================================
    // MB14.c.2.a — INIT-SIPI ICR encoder tests.
    //
    // Every bit position is pinned to the Intel SDM Vol 3A § 10.6.1 layout.
    // A regression in any of the encoder helpers would otherwise only show
    // up as a triple-faulted AP on real silicon (or a phantom IPI that
    // wakes up the wrong CPU); these tests turn a 6-hour QEMU debug session
    // into a 50 ms cargo test failure.
    // =====================================================================

    /// Helper: build the canonical INIT IPI for the given APIC ID and run
    /// it through the xAPIC encoder. Returns `(low, high)`.
    fn xapic_init(apic_id: u32) -> (u32, u32) {
        encode_icr_xapic(IcrCommand::init_assert(apic_id))
    }

    /// Helper: build the canonical SIPI for the given APIC ID and
    /// trampoline page, run it through the xAPIC encoder.
    fn xapic_sipi(apic_id: u32, page: u8) -> (u32, u32) {
        encode_icr_xapic(IcrCommand::sipi(apic_id, page))
    }

    #[test]
    fn xapic_init_encoding_matches_intel_layout() {
        // INIT assert-edge to APIC ID 1:
        //   vector             = 0      → bits 0..7   = 0
        //   delivery_mode      = INIT=5 → bits 8..10  = 0b101 → 0x0500
        //   destination_mode   = PHY=0  → bit 11      = 0
        //   level              = ASR=1  → bit 14      = 0x4000
        //   trigger_mode       = EDG=0  → bit 15      = 0
        //   shorthand          = NONE=0 → bits 18..19 = 0
        // LOW = 0x0500 | 0x4000 = 0x4500
        // HIGH = 1 << 24 = 0x0100_0000
        let (low, high) = xapic_init(1);
        assert_eq!(low, 0x4500, "INIT low bits");
        assert_eq!(high, 0x0100_0000, "INIT high bits (APIC ID 1)");
    }

    #[test]
    fn xapic_sipi_encoding_matches_intel_layout() {
        // SIPI to APIC ID 1, trampoline page 0x08 (phys 0x0000_8000):
        //   vector             = 0x08  → bits 0..7  = 0x08
        //   delivery_mode      = SUP=6 → bits 8..10 = 0b110 → 0x0600
        //   level              = ASR=1 → bit 14     = 0x4000
        //   (rest as INIT)
        // LOW = 0x08 | 0x0600 | 0x4000 = 0x4608
        // HIGH = 1 << 24 = 0x0100_0000
        let (low, high) = xapic_sipi(1, 0x08);
        assert_eq!(low, 0x4608, "SIPI low bits");
        assert_eq!(high, 0x0100_0000, "SIPI high bits (APIC ID 1)");
    }

    #[test]
    fn xapic_destination_truncates_to_eight_bits() {
        // APIC ID 0x1234_5678 — the high bits must be dropped by the
        // xAPIC encoder. The truncated byte is 0x78.
        let (_, high) = encode_icr_xapic(IcrCommand::init_assert(0x1234_5678));
        assert_eq!(high, 0x7800_0000, "xAPIC truncates to 8-bit ID");
    }

    #[test]
    fn x2apic_init_encoding_packs_destination_in_high_dword() {
        // x2APIC: same low-dword encoding, but the destination is the
        // full 32-bit upper half. APIC ID 0x1234_5678 stays intact.
        let icr = encode_icr_x2apic(IcrCommand::init_assert(0x1234_5678));
        assert_eq!(icr & 0xFFFF_FFFF, 0x4500, "x2APIC low half (INIT)");
        assert_eq!(icr >> 32, 0x1234_5678, "x2APIC high half = full APIC ID");
    }

    #[test]
    fn x2apic_sipi_packs_trampoline_and_destination() {
        // SIPI to APIC ID 0xCAFE_BABE, trampoline page 0x80.
        let icr = encode_icr_x2apic(IcrCommand::sipi(0xCAFE_BABE, 0x80));
        let low = (icr & 0xFFFF_FFFF) as u32;
        assert_eq!(low & 0xFF, 0x80, "SIPI vector = trampoline page");
        assert_eq!((low >> 8) & 0b111, 0b110, "delivery_mode = StartUp");
        assert_eq!((low >> 14) & 1, 1, "level = Assert");
        assert_eq!(icr >> 32, 0xCAFE_BABE, "x2APIC keeps full 32-bit ID");
    }

    #[test]
    fn encoder_emits_zero_for_default_init_fields() {
        // Sanity: the bits we leave at default (destination_mode=Physical,
        // trigger_mode=Edge, shorthand=NoShorthand) really are zero.
        let (low, _) = xapic_init(0);
        assert_eq!(low & (1 << 11), 0, "destination_mode physical");
        assert_eq!(low & (1 << 15), 0, "trigger_mode edge");
        assert_eq!(low & (0b11 << 18), 0, "no shorthand");
    }

    #[test]
    fn shorthand_all_excluding_self_encodes_to_bits_18_19() {
        // MB14.d will use this shorthand for broadcast TLB shootdown.
        let cmd = IcrCommand {
            vector: 0x42,
            delivery_mode: IcrDeliveryMode::Fixed,
            destination_mode: IcrDestinationMode::Physical,
            level: IcrLevel::Assert,
            trigger_mode: IcrTriggerMode::Edge,
            shorthand: IcrDestinationShorthand::AllExcludingSelf,
            destination_apic_id: 0,
        };
        let (low, _) = encode_icr_xapic(cmd);
        assert_eq!((low >> 18) & 0b11, 0b11, "AllExcludingSelf shorthand");
    }

    /// Build a [`CpuTopology`] with the supplied entries — host-side
    /// shorthand so the start_aps tests stay readable.
    fn topology_from(cpus: &[CpuEntry]) -> CpuTopology {
        let mut entries = [CpuEntry {
            apic_id: 0,
            acpi_uid: 0,
            enabled: false,
            x2apic: false,
        }; MAX_CPUS];
        let mut count = 0;
        for cpu in cpus {
            if let Some(slot) = entries.get_mut(count) {
                *slot = *cpu;
            }
            count += 1;
        }
        CpuTopology { entries, count }
    }

    fn make_cpu(apic_id: u32, enabled: bool, x2apic: bool) -> CpuEntry {
        CpuEntry {
            apic_id,
            acpi_uid: apic_id,
            enabled,
            x2apic,
        }
    }

    #[test]
    fn start_aps_dry_run_targets_every_enabled_non_bsp() {
        // BSP=0 + AP=1 + AP=2 (all enabled) → 2 APs targeted.
        let topo = topology_from(&[
            make_cpu(0, true, false),
            make_cpu(1, true, false),
            make_cpu(2, true, false),
        ]);
        let r = start_aps(&topo, 0, 0x08, StartApsMode::DryRun);
        assert_eq!(r.targeted, 2);
        assert_eq!(r.sequenced, 2);
        assert!(r.dry_run);
    }

    #[test]
    fn start_aps_skips_bsp_even_when_listed_first() {
        // BSP apic_id is taken from the LAPIC, not implicitly entry 0.
        // Verify the orchestrator excludes the BSP by APIC ID match,
        // regardless of where it appears in the topology.
        let topo = topology_from(&[
            make_cpu(3, true, false), // BSP
            make_cpu(0, true, false), // AP
            make_cpu(1, true, false), // AP
        ]);
        let r = start_aps(&topo, 3, 0x08, StartApsMode::DryRun);
        assert_eq!(r.targeted, 2);
    }

    #[test]
    fn start_aps_skips_disabled_entries() {
        let topo = topology_from(&[
            make_cpu(0, true, false),  // BSP
            make_cpu(1, false, false), // disabled AP
            make_cpu(2, true, false),  // enabled AP
        ]);
        let r = start_aps(&topo, 0, 0x08, StartApsMode::DryRun);
        assert_eq!(r.targeted, 1, "disabled AP must not be targeted");
    }

    #[test]
    fn start_aps_with_trampoline_zero_forces_dry_run() {
        // Even mode=Live downgrades to dry_run when trampoline_page=0
        // (SIPI vector 0 would jump into the IVT — never valid).
        let topo = topology_from(&[make_cpu(0, true, false), make_cpu(1, true, false)]);
        let r = start_aps(&topo, 0, 0, StartApsMode::Live);
        assert!(r.dry_run);
    }

    #[test]
    fn start_aps_mode_live_downgrades_in_mb14_c_2_a() {
        // The live ICR-write path is not implemented in this sub-block;
        // calling with Live must report dry_run=true (silent downgrade
        // documented on StartApsMode::Live).
        let topo = topology_from(&[make_cpu(0, true, false), make_cpu(1, true, false)]);
        let r = start_aps(&topo, 0, 0x08, StartApsMode::Live);
        assert!(r.dry_run, "Live downgrades until MB14.c.2.c");
        assert_eq!(r.targeted, 1);
    }

    #[test]
    fn start_aps_returns_zero_targets_on_uniprocessor() {
        // The Proxmox dev VM is 1 vCPU by default; the orchestrator
        // must handle this gracefully without underflow.
        let topo = topology_from(&[make_cpu(0, true, false)]);
        let r = start_aps(&topo, 0, 0x08, StartApsMode::DryRun);
        assert_eq!(r.targeted, 0);
        assert_eq!(r.sequenced, 0);
    }
}

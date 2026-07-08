//! Intel VT-d DMAR ACPI table parser (P6.7.9-pre.0).
//!
//! ## Scope
//!
//! This module is a **pure parser**: it takes a `&[u8]` containing the
//! DMAR table (the firmware-supplied `DMA Remapping Reporting Table`)
//! and returns a fixed-capacity [`DmarTable`] describing every DMA
//! Remapping Hardware Unit Definition (DRHD) the firmware advertises.
//! It does **not** touch hardware or program any registers — that
//! lives in the future `vtd` backend (P6.7.9-pre.1).
//!
//! ## DMAR layout (Intel VT-d spec rev 4.1 § 8.1)
//!
//! ```text
//! offset  size  field
//! ──────  ────  ─────
//! 0..36   36    ACPI SDT header (signature "DMAR")
//! 36       1    Host Address Width (HAW; address width = HAW + 1)
//! 37       1    Flags (bit 0 = INTR_REMAP, bit 1 = X2APIC_OPT_OUT,
//!                       bit 2 = DMA_CTRL_PLATFORM_OPT_IN)
//! 38..48  10    Reserved
//! 48..    var   Remapping Structures list
//! ```
//!
//! Each remapping structure starts with `u16 Type` + `u16 Length`. We
//! decode only **type 0 (DRHD)** in this scaffold — the other types
//! (RMRR, ATSR, RHSA, ANDD, SATC, SIDP) are walked past without
//! erroring so future extensions can land without breaking older
//! firmware traces.
//!
//! ## DRHD layout (§ 8.3)
//!
//! ```text
//! offset  size  field
//! ──────  ────  ─────
//! 0..2     2    Type = 0
//! 2..4     2    Length
//! 4        1    Flags (bit 0 = INCLUDE_PCI_ALL)
//! 5        1    Size (bit 0..3 = num register pages - 1)
//! 6..8     2    Segment Number
//! 8..16    8    Register Base Address (MMIO base for the IOMMU)
//! 16..    var   Device Scope entries (ignored in this scaffold)
//! ```
//!
//! ## References
//!
//! - Intel VT-d spec rev 4.1 § 8 (DMA Remapping ACPI Tables).
//! - ACPI rev 6.5 § 5.2.31 (DMAR table linkage from RSDT/XSDT).

/// Maximum number of DRHD entries the parser tracks.
///
/// A typical server has 1–4 IOMMU instances (one per socket on
/// multi-socket Xeon; one per PCIe root complex on desktop). 16 is a
/// safe upper bound for any first-party Phase 1 deployment.
pub const MAX_DRHD: usize = 16;

/// Length of the standard ACPI SDT header in bytes (§ 5.2.6).
const SDT_HEADER_LEN: usize = 36;

/// Length of the DMAR-specific header fields immediately following the
/// SDT header.
const DMAR_HEADER_EXTRA_LEN: usize = 12;

/// Full DMAR header length (`SDT_HEADER_LEN + DMAR_HEADER_EXTRA_LEN`).
const DMAR_HEADER_LEN: usize = SDT_HEADER_LEN + DMAR_HEADER_EXTRA_LEN;

/// DRHD remapping-structure type tag (§ 8.3).
const REMAP_TYPE_DRHD: u16 = 0x0000;

/// DRHD-specific fixed prefix length (after the 4-byte type+length
/// pair); covers `flags` + `size` + `segment` + `register_base`.
const DRHD_FIXED_LEN: usize = 16;

/// Decoded representation of a single DRHD entry.
///
/// Only the fields used by the future `vtd` backend are tracked here;
/// device-scope sub-entries are deferred to a follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrhdEntry {
    /// PCI segment number the IOMMU covers.
    pub segment: u16,
    /// MMIO base address of the remapping hardware registers.
    pub register_base: u64,
    /// DRHD flags (`bit 0 = INCLUDE_PCI_ALL`).
    pub flags: u8,
    /// `Size` field: number of 4-KiB pages of remapping hardware
    /// register space, encoded as `pages = 1 << (size & 0xF)`.
    pub size_pages: u16,
}

/// Decoded DMAR table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmarTable {
    /// Host Address Width plus 1, in bits. E.g. `HAW=38` means
    /// 39-bit addressable DMA range.
    pub host_addr_width: u8,
    /// DMAR header flags.
    pub flags: u8,
    drhd: [DrhdEntry; MAX_DRHD],
    drhd_count: usize,
}

impl DmarTable {
    /// All DRHD entries the parser recorded.
    #[must_use]
    pub fn drhd_entries(&self) -> &[DrhdEntry] {
        self.drhd.get(..self.drhd_count).unwrap_or(&[])
    }

    /// Number of DRHD entries.
    #[must_use]
    pub fn drhd_count(&self) -> usize {
        self.drhd_count
    }

    /// `true` iff the firmware advertises Interrupt Remapping support
    /// (DMAR header flags bit 0).
    #[must_use]
    pub fn interrupt_remapping(&self) -> bool {
        (self.flags & 0x1) != 0
    }
}

/// Reasons [`parse_dmar`] can reject a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarError {
    /// Buffer shorter than the 48-byte fixed DMAR header.
    Truncated,
    /// First 4 bytes are not `b"DMAR"`.
    BadSignature,
    /// Header `length` field disagrees with the supplied buffer.
    LengthMismatch,
    /// A remapping structure advertised a length of 0 (would loop
    /// forever) or a length that would walk past the table end.
    MalformedEntry,
    /// DMAR lists more DRHD entries than [`MAX_DRHD`] can hold.
    TooManyDrhd,
}

/// Parse a DMAR byte slice and extract every DRHD entry.
///
/// `buf` must point at the DMAR SDT header — i.e. the first byte is
/// `'D'` of `b"DMAR"`. The function reads exactly `header.length`
/// bytes; trailing bytes (if `buf` is longer) are ignored.
///
/// # Errors
///
/// See [`DmarError`].
pub fn parse_dmar(buf: &[u8]) -> Result<DmarTable, DmarError> {
    if buf.len() < DMAR_HEADER_LEN {
        return Err(DmarError::Truncated);
    }
    if buf.get(..4) != Some(b"DMAR") {
        return Err(DmarError::BadSignature);
    }

    let length = read_u32_le(buf, 4) as usize;
    if length < DMAR_HEADER_LEN || length > buf.len() {
        return Err(DmarError::LengthMismatch);
    }

    // DMAR-specific fields immediately follow the SDT header.
    let host_addr_width_raw = *buf.get(SDT_HEADER_LEN).ok_or(DmarError::Truncated)?;
    let flags = *buf.get(SDT_HEADER_LEN + 1).ok_or(DmarError::Truncated)?;
    // `host_addr_width` per spec = HAW + 1; we clamp the addition
    // against u8 wraparound (HAW = 0xFF would otherwise wrap).
    let host_addr_width = host_addr_width_raw.saturating_add(1);

    let mut drhd = [DrhdEntry {
        segment: 0,
        register_base: 0,
        flags: 0,
        size_pages: 0,
    }; MAX_DRHD];
    let mut drhd_count: usize = 0;

    let mut off = DMAR_HEADER_LEN;
    while off < length {
        // Every remapping structure starts with u16 type + u16 length.
        if off + 4 > length {
            return Err(DmarError::MalformedEntry);
        }
        let entry_type = read_u16_le(buf, off);
        let entry_len = read_u16_le(buf, off + 2) as usize;
        if entry_len < 4 || off + entry_len > length {
            return Err(DmarError::MalformedEntry);
        }

        if entry_type == REMAP_TYPE_DRHD {
            if entry_len < 4 + DRHD_FIXED_LEN {
                return Err(DmarError::MalformedEntry);
            }
            let drhd_flags = *buf.get(off + 4).ok_or(DmarError::MalformedEntry)?;
            let size_raw = *buf.get(off + 5).ok_or(DmarError::MalformedEntry)?;
            let segment = read_u16_le(buf, off + 6);
            let register_base = read_u64_le(buf, off + 8);
            // size_pages = 1 << (size & 0xF). Mask to nibble so noisy
            // upper bits are not promoted into a giant left shift.
            let size_pages = 1u16 << (size_raw & 0x0F);

            if drhd_count >= MAX_DRHD {
                return Err(DmarError::TooManyDrhd);
            }
            if let Some(slot) = drhd.get_mut(drhd_count) {
                *slot = DrhdEntry {
                    segment,
                    register_base,
                    flags: drhd_flags,
                    size_pages,
                };
            }
            drhd_count += 1;
        }
        // Every other remapping type is skipped — its `length` field
        // tells us how to advance past it.

        off += entry_len;
    }

    Ok(DmarTable {
        host_addr_width,
        flags,
        drhd,
        drhd_count,
    })
}

/// Read a little-endian `u16` at byte offset `off` in `buf`.
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    let Some(s) = buf.get(off..off + 2) else {
        return 0;
    };
    let arr = <[u8; 2]>::try_from(s).unwrap_or([0; 2]);
    u16::from_le_bytes(arr)
}

/// Read a little-endian `u32` at byte offset `off` in `buf`.
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    let Some(s) = buf.get(off..off + 4) else {
        return 0;
    };
    let arr = <[u8; 4]>::try_from(s).unwrap_or([0; 4]);
    u32::from_le_bytes(arr)
}

/// Read a little-endian `u64` at byte offset `off` in `buf`.
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let Some(s) = buf.get(off..off + 8) else {
        return 0;
    };
    let arr = <[u8; 8]>::try_from(s).unwrap_or([0; 8]);
    u64::from_le_bytes(arr)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "tests panic on bounds violation by design — surfaces parser regressions as test failures, not silent wrong values"
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test helpers cast usize→u32 for the ACPI length field; values are bounded by the buffers built in the same function"
)]
mod tests {
    use super::{
        DMAR_HEADER_LEN, DmarError, DrhdEntry, MAX_DRHD, REMAP_TYPE_DRHD, SDT_HEADER_LEN,
        parse_dmar,
    };

    /// Build a minimal DMAR header with `body` appended after the
    /// 48-byte fixed prefix. The header's `length` field is filled
    /// in to match `48 + body.len()`.
    fn build_dmar(haw: u8, flags: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
        let total_len = (DMAR_HEADER_LEN + body.len()) as u32;
        let mut buf = alloc::vec::Vec::with_capacity(total_len as usize);
        buf.extend_from_slice(b"DMAR");
        buf.extend_from_slice(&total_len.to_le_bytes()); // length
        buf.push(0x01); // revision
        buf.push(0x00); // checksum (not verified by parser)
        buf.extend_from_slice(b"OEMID_"); // 6-byte oem_id
        buf.extend_from_slice(b"OEMTBLID"); // 8-byte oem_table_id
        buf.extend_from_slice(&0u32.to_le_bytes()); // oem_revision
        buf.extend_from_slice(b"CRTR"); // creator_id
        buf.extend_from_slice(&0u32.to_le_bytes()); // creator_revision
        assert_eq!(buf.len(), SDT_HEADER_LEN);
        buf.push(haw);
        buf.push(flags);
        buf.extend_from_slice(&[0; 10]); // reserved
        assert_eq!(buf.len(), DMAR_HEADER_LEN);
        buf.extend_from_slice(body);
        buf
    }

    /// Compose a single DRHD entry as raw bytes.
    fn drhd_bytes(flags: u8, size_nibble: u8, segment: u16, register_base: u64) -> [u8; 20] {
        let entry_len: u16 = 20; // 4 byte (type+len) + 16 byte fixed prefix
        let mut out = [0u8; 20];
        out[0..2].copy_from_slice(&REMAP_TYPE_DRHD.to_le_bytes());
        out[2..4].copy_from_slice(&entry_len.to_le_bytes());
        out[4] = flags;
        out[5] = size_nibble & 0x0F;
        out[6..8].copy_from_slice(&segment.to_le_bytes());
        out[8..16].copy_from_slice(&register_base.to_le_bytes());
        // bytes 16..20 are part of the entry but unused by the parser
        out
    }

    #[test]
    fn parse_dmar_single_drhd_well_formed() {
        let body = drhd_bytes(0x01, 0x00, 0x0000, 0xFED9_0000);
        let buf = build_dmar(0x26, 0x01, &body); // HAW=0x26 → 39-bit
        let parsed = parse_dmar(&buf).expect("well-formed DMAR parses");
        assert_eq!(parsed.host_addr_width, 0x27);
        assert_eq!(parsed.flags, 0x01);
        assert!(parsed.interrupt_remapping());
        let drhds = parsed.drhd_entries();
        assert_eq!(drhds.len(), 1);
        assert_eq!(
            drhds[0],
            DrhdEntry {
                segment: 0,
                register_base: 0xFED9_0000,
                flags: 0x01,
                size_pages: 1,
            }
        );
    }

    #[test]
    fn parse_dmar_multiple_drhd_well_formed() {
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&drhd_bytes(0x00, 0x00, 0x0000, 0xFED9_0000));
        body.extend_from_slice(&drhd_bytes(0x01, 0x00, 0x0000, 0xFED9_1000));
        body.extend_from_slice(&drhd_bytes(0x00, 0x00, 0x0001, 0xFED9_2000));
        let buf = build_dmar(0x26, 0x00, &body);
        let parsed = parse_dmar(&buf).expect("multi-DRHD parses");
        assert_eq!(parsed.drhd_count(), 3);
        assert_eq!(parsed.drhd_entries()[0].register_base, 0xFED9_0000);
        assert_eq!(parsed.drhd_entries()[1].register_base, 0xFED9_1000);
        assert_eq!(parsed.drhd_entries()[2].segment, 1);
        assert!(!parsed.interrupt_remapping());
    }

    #[test]
    fn parse_dmar_rejects_truncated_header() {
        // Less than 48 bytes — entirely below the fixed prefix.
        let buf = alloc::vec![0u8; 10];
        assert_eq!(parse_dmar(&buf), Err(DmarError::Truncated));
    }

    #[test]
    fn parse_dmar_rejects_bad_signature() {
        let body = drhd_bytes(0, 0, 0, 0);
        let mut buf = build_dmar(0x26, 0x00, &body);
        // Overwrite signature.
        buf[0..4].copy_from_slice(b"NMAD");
        assert_eq!(parse_dmar(&buf), Err(DmarError::BadSignature));
    }

    #[test]
    fn parse_dmar_rejects_length_too_small() {
        let body = drhd_bytes(0, 0, 0, 0);
        let mut buf = build_dmar(0x26, 0x00, &body);
        // Set header length field to 32 (below DMAR_HEADER_LEN).
        buf[4..8].copy_from_slice(&32u32.to_le_bytes());
        assert_eq!(parse_dmar(&buf), Err(DmarError::LengthMismatch));
    }

    #[test]
    fn parse_dmar_rejects_length_beyond_buffer() {
        let body = drhd_bytes(0, 0, 0, 0);
        let mut buf = build_dmar(0x26, 0x00, &body);
        // Claim 4 KiB even though we only allocated 68 bytes.
        buf[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(parse_dmar(&buf), Err(DmarError::LengthMismatch));
    }

    #[test]
    fn parse_dmar_rejects_zero_length_entry() {
        // Insert a remapping structure with length=0 — would loop.
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&REMAP_TYPE_DRHD.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // length=0
        let buf = build_dmar(0x26, 0x00, &body);
        assert_eq!(parse_dmar(&buf), Err(DmarError::MalformedEntry));
    }

    #[test]
    fn parse_dmar_rejects_entry_walking_past_end() {
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&REMAP_TYPE_DRHD.to_le_bytes());
        body.extend_from_slice(&0xFFFFu16.to_le_bytes()); // length way past end
        let buf = build_dmar(0x26, 0x00, &body);
        assert_eq!(parse_dmar(&buf), Err(DmarError::MalformedEntry));
    }

    #[test]
    fn parse_dmar_skips_unknown_remapping_types() {
        // Unknown type 0xFF with a sane length — must be walked past
        // silently.
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&0x00FFu16.to_le_bytes()); // unknown type
        body.extend_from_slice(&8u16.to_le_bytes()); // length = 8
        body.extend_from_slice(&[0u8; 4]); // payload
        body.extend_from_slice(&drhd_bytes(0x00, 0x00, 0x0000, 0xFED9_0000));
        let buf = build_dmar(0x26, 0x00, &body);
        let parsed = parse_dmar(&buf).expect("unknown type is skipped");
        assert_eq!(parsed.drhd_count(), 1);
    }

    #[test]
    fn parse_dmar_too_many_drhd_returns_err() {
        // Build MAX_DRHD + 1 DRHD entries — must surface TooManyDrhd.
        let mut body = alloc::vec::Vec::new();
        for i in 0..=MAX_DRHD {
            let base = 0xFED9_0000u64 + (i as u64) * 0x1000;
            body.extend_from_slice(&drhd_bytes(0x00, 0x00, 0x0000, base));
        }
        let buf = build_dmar(0x26, 0x00, &body);
        assert_eq!(parse_dmar(&buf), Err(DmarError::TooManyDrhd));
    }

    #[test]
    fn parse_dmar_drhd_with_short_payload_is_malformed() {
        // DRHD type but length only 8 (below 4 + 16 = 20 fixed bytes).
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&REMAP_TYPE_DRHD.to_le_bytes());
        body.extend_from_slice(&8u16.to_le_bytes()); // length=8 (truncated DRHD)
        body.extend_from_slice(&[0u8; 4]);
        let buf = build_dmar(0x26, 0x00, &body);
        assert_eq!(parse_dmar(&buf), Err(DmarError::MalformedEntry));
    }
}

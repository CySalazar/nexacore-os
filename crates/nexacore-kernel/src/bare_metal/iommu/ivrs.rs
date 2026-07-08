//! AMD-Vi IVRS ACPI table parser (P6.7.9-pre.0).
//!
//! ## Scope
//!
//! Symmetric to [`super::dmar`] for AMD platforms: a **pure parser**
//! over a `&[u8]` slice that yields a fixed-capacity [`IvrsTable`]
//! describing every I/O Virtualization Hardware Definition (IVHD)
//! the firmware advertises. The future `amdvi` backend
//! (P6.7.9-pre.1) will read the parsed table to know which IOMMU MMIO
//! windows to map.
//!
//! ## IVRS layout (AMD I/O Virtualization Technology spec rev 3.10 § 5.2)
//!
//! ```text
//! offset  size  field
//! ──────  ────  ─────
//! 0..36   36    ACPI SDT header (signature "IVRS")
//! 36..40   4    IVinfo (32 bits) — EFR support, GVA size, PA size, ...
//! 40..48   8    Reserved
//! 48..    var   IVHD / IVMD entries list
//! ```
//!
//! Each entry begins with `u8 Type` + `u8 Flags` + `u16 Length`. We
//! decode the three IVHD type variants:
//!
//! - `0x10` — IVHD type 10h (legacy fixed 24-byte header).
//! - `0x11` — IVHD type 11h (32-byte header, EFR mirror).
//! - `0x40` — IVHD type 40h (40-byte header, virtual address space).
//!
//! Memory definitions (`0x20..=0x22` — IVMD) and "Special device"
//! sub-entries inside an IVHD are skipped: the kernel-side scaffold
//! only needs the IOMMU MMIO base + segment to bootstrap the backend.
//!
//! ## References
//!
//! - AMD I/O Virtualization Technology (IOMMU) spec rev 3.10 § 5.

/// Maximum number of IVHD entries the parser tracks.
///
/// Symmetric to [`super::dmar::MAX_DRHD`]; AMD systems typically have
/// one IOMMU per socket plus optionally a chipset-level IOMMU.
pub const MAX_IVHD: usize = 16;

/// Length of the standard ACPI SDT header in bytes (§ 5.2.6 / ACPI).
const SDT_HEADER_LEN: usize = 36;

/// Length of the IVRS-specific header fields immediately following
/// the SDT header.
const IVRS_HEADER_EXTRA_LEN: usize = 12;

/// Full IVRS header length (`SDT_HEADER_LEN + IVRS_HEADER_EXTRA_LEN`).
const IVRS_HEADER_LEN: usize = SDT_HEADER_LEN + IVRS_HEADER_EXTRA_LEN;

/// IVHD type tag — legacy 24-byte header (AMD spec § 5.2.1).
const IVHD_TYPE_10H: u8 = 0x10;
/// IVHD type tag — extended 32-byte header.
const IVHD_TYPE_11H: u8 = 0x11;
/// IVHD type tag — extended 40-byte header with VAS.
const IVHD_TYPE_40H: u8 = 0x40;

/// Decoded representation of a single IVHD entry.
///
/// Only the fields used by the future `amdvi` backend are tracked;
/// device-table sub-entries are deferred to a follow-up sub-step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IvhdEntry {
    /// IVHD type tag (`0x10`, `0x11`, or `0x40`).
    pub ivhd_type: u8,
    /// IVHD flags (§ 5.2.1 table 21).
    pub flags: u8,
    /// PCI device ID (BDF) of the IOMMU itself.
    pub device_id: u16,
    /// Capability offset of the IOMMU's PCI cap header.
    pub capability_offset: u16,
    /// MMIO base address of the IOMMU control registers.
    pub base_address: u64,
    /// PCI segment group the IOMMU covers.
    pub pci_segment_group: u16,
}

/// Decoded IVRS table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IvrsTable {
    /// `IVinfo` (32-bit feature word, § 5.2 table 18).
    pub ivinfo: u32,
    ivhd: [IvhdEntry; MAX_IVHD],
    ivhd_count: usize,
}

impl IvrsTable {
    /// All IVHD entries the parser recorded.
    #[must_use]
    pub fn ivhd_entries(&self) -> &[IvhdEntry] {
        self.ivhd.get(..self.ivhd_count).unwrap_or(&[])
    }

    /// Number of IVHD entries.
    #[must_use]
    pub fn ivhd_count(&self) -> usize {
        self.ivhd_count
    }
}

/// Reasons [`parse_ivrs`] can reject a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvrsError {
    /// Buffer shorter than the 48-byte fixed IVRS header.
    Truncated,
    /// First 4 bytes are not `b"IVRS"`.
    BadSignature,
    /// Header `length` field disagrees with the supplied buffer.
    LengthMismatch,
    /// An IVHD entry advertised a length of 0 or a length that would
    /// walk past the table end.
    MalformedEntry,
    /// IVRS lists more IVHD entries than [`MAX_IVHD`] can hold.
    TooManyIvhd,
}

/// Parse an IVRS byte slice and extract every IVHD entry.
///
/// `buf` must point at the IVRS SDT header — first byte is `'I'` of
/// `b"IVRS"`. The function reads exactly `header.length` bytes;
/// trailing bytes (if `buf` is longer) are ignored.
///
/// # Errors
///
/// See [`IvrsError`].
pub fn parse_ivrs(buf: &[u8]) -> Result<IvrsTable, IvrsError> {
    if buf.len() < IVRS_HEADER_LEN {
        return Err(IvrsError::Truncated);
    }
    if buf.get(..4) != Some(b"IVRS") {
        return Err(IvrsError::BadSignature);
    }

    let length = read_u32_le(buf, 4) as usize;
    if length < IVRS_HEADER_LEN || length > buf.len() {
        return Err(IvrsError::LengthMismatch);
    }

    let ivinfo = read_u32_le(buf, SDT_HEADER_LEN);

    let mut ivhd = [IvhdEntry {
        ivhd_type: 0,
        flags: 0,
        device_id: 0,
        capability_offset: 0,
        base_address: 0,
        pci_segment_group: 0,
    }; MAX_IVHD];
    let mut ivhd_count: usize = 0;

    let mut off = IVRS_HEADER_LEN;
    while off < length {
        // Each IVRS sub-entry: u8 type + u8 flags + u16 length.
        if off + 4 > length {
            return Err(IvrsError::MalformedEntry);
        }
        let entry_type = *buf.get(off).ok_or(IvrsError::MalformedEntry)?;
        let entry_flags = *buf.get(off + 1).ok_or(IvrsError::MalformedEntry)?;
        let entry_len = read_u16_le(buf, off + 2) as usize;
        if entry_len < 4 || off + entry_len > length {
            return Err(IvrsError::MalformedEntry);
        }

        let is_ivhd = matches!(entry_type, IVHD_TYPE_10H | IVHD_TYPE_11H | IVHD_TYPE_40H);

        if is_ivhd {
            // IVHD fixed prefix (all three type variants share the
            // first 24 bytes):
            //   off+0    : type
            //   off+1    : flags
            //   off+2..4 : length
            //   off+4..6 : device_id (BDF)
            //   off+6..8 : capability_offset
            //   off+8..16: iommu_base_address (u64 LE)
            //   off+16..18: pci_segment_group (u16)
            //   off+18..20: iommu_info / reserved
            //   off+20..24: feature_reporting (u32) — type 11h+ only
            const IVHD_MIN_LEN: usize = 24;
            if entry_len < IVHD_MIN_LEN {
                return Err(IvrsError::MalformedEntry);
            }

            let device_id = read_u16_le(buf, off + 4);
            let capability_offset = read_u16_le(buf, off + 6);
            let base_address = read_u64_le(buf, off + 8);
            let pci_segment_group = read_u16_le(buf, off + 16);

            if ivhd_count >= MAX_IVHD {
                return Err(IvrsError::TooManyIvhd);
            }
            if let Some(slot) = ivhd.get_mut(ivhd_count) {
                *slot = IvhdEntry {
                    ivhd_type: entry_type,
                    flags: entry_flags,
                    device_id,
                    capability_offset,
                    base_address,
                    pci_segment_group,
                };
            }
            ivhd_count += 1;
        }
        // Every other entry type (IVMD `0x20..=0x22`, etc.) is
        // walked past using its `length` field.

        off += entry_len;
    }

    Ok(IvrsTable {
        ivinfo,
        ivhd,
        ivhd_count,
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
        IVHD_TYPE_10H, IVHD_TYPE_11H, IVHD_TYPE_40H, IVRS_HEADER_LEN, IvhdEntry, IvrsError,
        MAX_IVHD, SDT_HEADER_LEN, parse_ivrs,
    };

    /// Build a minimal IVRS header with `body` appended after the
    /// 48-byte fixed prefix. `length` is set automatically.
    fn build_ivrs(ivinfo: u32, body: &[u8]) -> alloc::vec::Vec<u8> {
        let total_len = (IVRS_HEADER_LEN + body.len()) as u32;
        let mut buf = alloc::vec::Vec::with_capacity(total_len as usize);
        buf.extend_from_slice(b"IVRS");
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf.push(0x02); // revision
        buf.push(0x00); // checksum
        buf.extend_from_slice(b"AMD___"); // 6-byte oem_id
        buf.extend_from_slice(b"OEMTBLID"); // 8-byte oem_table_id
        buf.extend_from_slice(&0u32.to_le_bytes()); // oem_revision
        buf.extend_from_slice(b"CRTR");
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(buf.len(), SDT_HEADER_LEN);
        buf.extend_from_slice(&ivinfo.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]); // reserved
        assert_eq!(buf.len(), IVRS_HEADER_LEN);
        buf.extend_from_slice(body);
        buf
    }

    /// Compose a single IVHD entry with the fixed 24-byte prefix.
    fn ivhd_bytes(
        ivhd_type: u8,
        flags: u8,
        device_id: u16,
        capability_offset: u16,
        base_address: u64,
        segment: u16,
    ) -> [u8; 24] {
        let entry_len: u16 = 24;
        let mut out = [0u8; 24];
        out[0] = ivhd_type;
        out[1] = flags;
        out[2..4].copy_from_slice(&entry_len.to_le_bytes());
        out[4..6].copy_from_slice(&device_id.to_le_bytes());
        out[6..8].copy_from_slice(&capability_offset.to_le_bytes());
        out[8..16].copy_from_slice(&base_address.to_le_bytes());
        out[16..18].copy_from_slice(&segment.to_le_bytes());
        // bytes 18..24 reserved / iommu_info / feature_reporting
        out
    }

    #[test]
    fn parse_ivrs_single_ivhd_well_formed() {
        let body = ivhd_bytes(IVHD_TYPE_10H, 0x00, 0x0040, 0x0040, 0xFEB8_0000, 0x0000);
        let buf = build_ivrs(0x0000_0040, &body);
        let parsed = parse_ivrs(&buf).expect("well-formed IVRS parses");
        assert_eq!(parsed.ivinfo, 0x0000_0040);
        assert_eq!(parsed.ivhd_count(), 1);
        let entry = &parsed.ivhd_entries()[0];
        assert_eq!(
            *entry,
            IvhdEntry {
                ivhd_type: IVHD_TYPE_10H,
                flags: 0x00,
                device_id: 0x0040,
                capability_offset: 0x0040,
                base_address: 0xFEB8_0000,
                pci_segment_group: 0x0000,
            }
        );
    }

    #[test]
    fn parse_ivrs_multiple_ivhd_types() {
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&ivhd_bytes(
            IVHD_TYPE_10H,
            0x00,
            0x0040,
            0x0040,
            0xFEB8_0000,
            0,
        ));
        body.extend_from_slice(&ivhd_bytes(
            IVHD_TYPE_11H,
            0x01,
            0x0040,
            0x0040,
            0xFEB8_2000,
            0,
        ));
        body.extend_from_slice(&ivhd_bytes(
            IVHD_TYPE_40H,
            0x02,
            0x0040,
            0x0040,
            0xFEB8_4000,
            1,
        ));
        let buf = build_ivrs(0, &body);
        let parsed = parse_ivrs(&buf).expect("multi-IVHD parses");
        assert_eq!(parsed.ivhd_count(), 3);
        assert_eq!(parsed.ivhd_entries()[0].ivhd_type, IVHD_TYPE_10H);
        assert_eq!(parsed.ivhd_entries()[1].ivhd_type, IVHD_TYPE_11H);
        assert_eq!(parsed.ivhd_entries()[2].ivhd_type, IVHD_TYPE_40H);
        assert_eq!(parsed.ivhd_entries()[2].pci_segment_group, 1);
    }

    #[test]
    fn parse_ivrs_rejects_truncated() {
        let buf = alloc::vec![0u8; 8];
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::Truncated));
    }

    #[test]
    fn parse_ivrs_rejects_bad_signature() {
        let body = ivhd_bytes(IVHD_TYPE_10H, 0, 0, 0, 0, 0);
        let mut buf = build_ivrs(0, &body);
        buf[0..4].copy_from_slice(b"SRVI");
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::BadSignature));
    }

    #[test]
    fn parse_ivrs_rejects_length_too_small() {
        let body = ivhd_bytes(IVHD_TYPE_10H, 0, 0, 0, 0, 0);
        let mut buf = build_ivrs(0, &body);
        buf[4..8].copy_from_slice(&32u32.to_le_bytes());
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::LengthMismatch));
    }

    #[test]
    fn parse_ivrs_rejects_length_beyond_buffer() {
        let body = ivhd_bytes(IVHD_TYPE_10H, 0, 0, 0, 0, 0);
        let mut buf = build_ivrs(0, &body);
        buf[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::LengthMismatch));
    }

    #[test]
    fn parse_ivrs_rejects_zero_length_entry() {
        let mut body = alloc::vec::Vec::new();
        body.push(IVHD_TYPE_10H);
        body.push(0x00); // flags
        body.extend_from_slice(&0u16.to_le_bytes()); // length = 0
        let buf = build_ivrs(0, &body);
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::MalformedEntry));
    }

    #[test]
    fn parse_ivrs_rejects_entry_walking_past_end() {
        let mut body = alloc::vec::Vec::new();
        body.push(IVHD_TYPE_10H);
        body.push(0x00);
        body.extend_from_slice(&0xFFFFu16.to_le_bytes());
        let buf = build_ivrs(0, &body);
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::MalformedEntry));
    }

    #[test]
    fn parse_ivrs_skips_unknown_entry_types() {
        let mut body = alloc::vec::Vec::new();
        // IVMD type 0x20, length 8, payload.
        body.push(0x20);
        body.push(0x00);
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&ivhd_bytes(IVHD_TYPE_10H, 0, 0x40, 0x40, 0xFEB8_0000, 0));
        let buf = build_ivrs(0, &body);
        let parsed = parse_ivrs(&buf).expect("unknown type is skipped");
        assert_eq!(parsed.ivhd_count(), 1);
    }

    #[test]
    fn parse_ivrs_too_many_ivhd_returns_err() {
        let mut body = alloc::vec::Vec::new();
        for i in 0..=MAX_IVHD {
            body.extend_from_slice(&ivhd_bytes(
                IVHD_TYPE_10H,
                0,
                0x40,
                0x40,
                0xFEB8_0000 + (i as u64) * 0x2000,
                0,
            ));
        }
        let buf = build_ivrs(0, &body);
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::TooManyIvhd));
    }

    #[test]
    fn parse_ivrs_ivhd_with_short_payload_is_malformed() {
        let mut body = alloc::vec::Vec::new();
        body.push(IVHD_TYPE_10H);
        body.push(0x00);
        body.extend_from_slice(&8u16.to_le_bytes()); // length=8 (< 24)
        body.extend_from_slice(&[0u8; 4]);
        let buf = build_ivrs(0, &body);
        assert_eq!(parse_ivrs(&buf), Err(IvrsError::MalformedEntry));
    }
}

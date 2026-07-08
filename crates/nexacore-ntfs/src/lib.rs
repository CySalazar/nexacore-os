//! # `nexacore-ntfs`
//!
//! Read-only reader for NTFS volumes, WS3-05.6/.7.
//!
//! This crate is the host-testable, dependency-free, strictly **read-only**
//! NTFS member of the WS3-05 compat set (FAT is [`nexacore-fatfs`], ext is
//! [`nexacore-extfs`]). WS3-05.6 (this module) covers the on-disk MFT parse:
//! the [`BootSector`] geometry, the update-sequence ([`apply_fixups`]) integrity
//! protection, [`FileRecord`] headers, the [`Attribute`] iterator over a
//! record's attributes ($STANDARD_INFORMATION / $FILE_NAME / $DATA), the
//! [`FileName`] attribute decode, and non-resident [`DataRun`] decoding.
//!
//! ## Read-only by construction
//!
//! Every parser borrows an immutable image (`&[u8]`); there is no write path.
//! Every device-supplied length is bounds-checked before use — a malformed or
//! hostile record yields a typed [`NtfsError`], never an out-of-bounds read or a
//! panic. Exposing this behind the capability-gated (`READONLY_COMPAT_FS`,
//! WS3-05.1) VFS service is WS3-05.8.
//!
//! ## `no_std` + `alloc`
//!
//! `#![no_std]` pulling only `alloc` (no crypto, no `std`), so it builds for
//! `x86_64-unknown-none` as well as the developer host.
//!
//! [`nexacore-fatfs`]: https://docs.rs
//! [`nexacore-extfs`]: https://docs.rs

#![no_std]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    reason = "NTFS spec terms ($FILE_NAME, $DATA, MFT, BPB, USA, USN) read better unquoted"
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
        // The tests build synthetic NTFS structures byte-by-byte.
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
    )
)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

pub mod reader;

pub use reader::{DirEntry, NtfsVolume};

/// An NTFS parse error over untrusted image bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsError {
    /// The buffer is too short for the structure being parsed.
    Truncated,
    /// The boot sector is not a recognisable NTFS BPB.
    BadBootSector,
    /// A FILE record did not start with the `FILE` signature.
    BadSignature,
    /// The update-sequence array runs past the record buffer.
    FixupOverrun,
    /// A sector's fixup tail did not match the update sequence number
    /// (torn write / corruption).
    FixupMismatch,
    /// A required attribute (e.g. `$DATA` or `$INDEX_ROOT`) was not present.
    MissingAttribute,
}

// -----------------------------------------------------------------------------
// Little-endian primitive reads (all bounds-checked)
// -----------------------------------------------------------------------------

pub(crate) fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([*s.first()?, *s.get(1)?]))
}

pub(crate) fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([
        *s.first()?,
        *s.get(1)?,
        *s.get(2)?,
        *s.get(3)?,
    ]))
}

pub(crate) fn u64_le(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    let mut arr = [0u8; 8];
    for (dst, src) in arr.iter_mut().zip(s) {
        *dst = *src;
    }
    Some(u64::from_le_bytes(arr))
}

/// Read `n` (0..=8) little-endian bytes as an unsigned integer.
fn read_uint_le(b: &[u8], off: usize, n: usize) -> Option<u64> {
    let s = b.get(off..off + n)?;
    let mut acc = 0u64;
    for (i, &byte) in s.iter().enumerate() {
        acc |= u64::from(byte) << (8 * i);
    }
    Some(acc)
}

/// Read `n` (1..=8) little-endian bytes as a sign-extended integer.
#[allow(
    clippy::cast_possible_wrap,
    reason = "deliberate two's-complement reinterpretation"
)]
fn read_int_le(b: &[u8], off: usize, n: usize) -> Option<i64> {
    if n == 0 {
        return None;
    }
    let raw = read_uint_le(b, off, n)?;
    let bits = n * 8;
    // Sign-extend from the top bit of the highest byte read.
    if bits < 64 && (raw & (1 << (bits - 1))) != 0 {
        Some((raw | (u64::MAX << bits)) as i64)
    } else {
        Some(raw as i64)
    }
}

// -----------------------------------------------------------------------------
// Boot sector
// -----------------------------------------------------------------------------

/// NTFS volume geometry parsed from the boot sector (BPB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSector {
    /// Bytes per sector (BPB offset 0x0B).
    pub bytes_per_sector: u16,
    /// Sectors per cluster (BPB offset 0x0D).
    pub sectors_per_cluster: u8,
    /// Logical cluster number of the `$MFT` (BPB offset 0x30).
    pub mft_lcn: u64,
    /// Size of one MFT FILE record in bytes.
    pub mft_record_size: u32,
}

impl BootSector {
    /// The `NTFS    ` OEM identifier at boot-sector offset 3.
    const OEM_ID: &'static [u8] = b"NTFS    ";

    /// Bytes per cluster.
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        u32::from(self.bytes_per_sector) * u32::from(self.sectors_per_cluster)
    }

    /// Parse the boot sector geometry.
    ///
    /// # Errors
    ///
    /// [`NtfsError::BadBootSector`] if the OEM id is not `NTFS`, a size field is
    /// zero, or the buffer is too short.
    pub fn parse(image: &[u8]) -> Result<Self, NtfsError> {
        if image.get(3..11) != Some(Self::OEM_ID) {
            return Err(NtfsError::BadBootSector);
        }
        let bytes_per_sector = u16_le(image, 0x0B).ok_or(NtfsError::Truncated)?;
        let sectors_per_cluster = *image.get(0x0D).ok_or(NtfsError::Truncated)?;
        let mft_lcn = u64_le(image, 0x30).ok_or(NtfsError::Truncated)?;
        let clusters_per_mft = i8::from_ne_bytes([*image.get(0x40).ok_or(NtfsError::Truncated)?]);

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return Err(NtfsError::BadBootSector);
        }
        let cluster_size = u32::from(bytes_per_sector) * u32::from(sectors_per_cluster);

        // Per NTFS: if clusters_per_mft is positive it counts clusters; if
        // negative the record size is `2^(-value)` bytes.
        let mft_record_size = if clusters_per_mft >= 0 {
            let clusters = u32::try_from(clusters_per_mft).map_err(|_| NtfsError::BadBootSector)?;
            cluster_size
                .checked_mul(clusters)
                .ok_or(NtfsError::BadBootSector)?
        } else {
            let shift = i32::from(clusters_per_mft).unsigned_abs();
            if shift >= 32 {
                return Err(NtfsError::BadBootSector);
            }
            1u32 << shift
        };
        if mft_record_size == 0 {
            return Err(NtfsError::BadBootSector);
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            mft_lcn,
            mft_record_size,
        })
    }
}

// -----------------------------------------------------------------------------
// Update sequence (fixup) protection
// -----------------------------------------------------------------------------

/// Apply the NTFS update-sequence (fixup) protection to a FILE/INDX record.
///
/// NTFS replaces the last two bytes of every sector in a multi-sector structure
/// with an "update sequence number" and stores the originals in the update
/// sequence array (USA). This verifies each sector's tail still carries the USN
/// (detecting a torn write) and restores the original bytes in place.
///
/// # Errors
///
/// - [`NtfsError::FixupOverrun`] if the USA or a sector tail falls outside
///   `record`.
/// - [`NtfsError::FixupMismatch`] if a sector tail does not carry the USN.
pub fn apply_fixups(record: &mut [u8], bytes_per_sector: u16) -> Result<(), NtfsError> {
    let bps = usize::from(bytes_per_sector);
    if bps < 2 {
        return Err(NtfsError::FixupOverrun);
    }
    let usa_offset = u16_le(record, 4).ok_or(NtfsError::FixupOverrun)? as usize;
    let usa_count = u16_le(record, 6).ok_or(NtfsError::FixupOverrun)? as usize;
    if usa_count == 0 {
        return Err(NtfsError::FixupOverrun);
    }
    // USA = USN (2 bytes) followed by (usa_count - 1) original tail values.
    let usa_end = usa_offset
        .checked_add(usa_count * 2)
        .ok_or(NtfsError::FixupOverrun)?;
    if usa_end > record.len() {
        return Err(NtfsError::FixupOverrun);
    }
    let usn: [u8; 2] = record
        .get(usa_offset..usa_offset + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or(NtfsError::FixupOverrun)?;

    for i in 0..(usa_count - 1) {
        let tail = i
            .checked_mul(bps)
            .and_then(|v| v.checked_add(bps - 2))
            .ok_or(NtfsError::FixupOverrun)?;
        let tail_val: [u8; 2] = record
            .get(tail..tail + 2)
            .and_then(|s| s.try_into().ok())
            .ok_or(NtfsError::FixupOverrun)?;
        if tail_val != usn {
            return Err(NtfsError::FixupMismatch);
        }
        let src = usa_offset + 2 + i * 2;
        let orig: [u8; 2] = record
            .get(src..src + 2)
            .and_then(|s| s.try_into().ok())
            .ok_or(NtfsError::FixupOverrun)?;
        if let Some(dst) = record.get_mut(tail..tail + 2) {
            dst.copy_from_slice(&orig);
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// FILE record + attributes
// -----------------------------------------------------------------------------

/// Attribute type code: `$STANDARD_INFORMATION`.
pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
/// Attribute type code: `$FILE_NAME`.
pub const ATTR_FILE_NAME: u32 = 0x30;
/// Attribute type code: `$DATA`.
pub const ATTR_DATA: u32 = 0x80;
/// Attribute type code: `$INDEX_ROOT`.
pub const ATTR_INDEX_ROOT: u32 = 0x90;
/// Attribute type code: `$INDEX_ALLOCATION`.
pub const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
/// Attribute list end marker.
const ATTR_END: u32 = 0xFFFF_FFFF;

/// A parsed MFT FILE record (its header + a borrow of the record bytes).
#[derive(Debug, Clone, Copy)]
pub struct FileRecord<'a> {
    bytes: &'a [u8],
    first_attr_offset: usize,
    flags: u16,
}

impl<'a> FileRecord<'a> {
    /// The `FILE` signature.
    const SIGNATURE: &'static [u8] = b"FILE";

    /// Parse a FILE record from (already fixed-up) `bytes`.
    ///
    /// # Errors
    ///
    /// [`NtfsError::BadSignature`] if the record is not a `FILE` record;
    /// [`NtfsError::Truncated`] if a header field or the first attribute offset
    /// lies outside `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, NtfsError> {
        if bytes.get(0..4) != Some(Self::SIGNATURE) {
            return Err(NtfsError::BadSignature);
        }
        let first_attr_offset = u16_le(bytes, 0x14).ok_or(NtfsError::Truncated)? as usize;
        let flags = u16_le(bytes, 0x16).ok_or(NtfsError::Truncated)?;
        if first_attr_offset >= bytes.len() {
            return Err(NtfsError::Truncated);
        }
        Ok(Self {
            bytes,
            first_attr_offset,
            flags,
        })
    }

    /// Whether the record is in use (allocated).
    #[must_use]
    pub fn is_in_use(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Whether the record is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Iterate the record's attributes.
    #[must_use]
    pub fn attributes(&self) -> AttributeIter<'a> {
        AttributeIter {
            bytes: self.bytes,
            offset: self.first_attr_offset,
        }
    }

    /// The first attribute of the given type, if present.
    #[must_use]
    pub fn find_attribute(&self, type_code: u32) -> Option<Attribute<'a>> {
        self.attributes().find(|a| a.type_code() == type_code)
    }
}

/// An iterator over a FILE record's attributes.
#[derive(Debug, Clone)]
pub struct AttributeIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = Attribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let type_code = u32_le(self.bytes, self.offset)?;
        if type_code == ATTR_END {
            return None;
        }
        let length = u32_le(self.bytes, self.offset + 4)? as usize;
        if length < 8 {
            return None; // malformed: would not advance
        }
        let attr_bytes = self.bytes.get(self.offset..self.offset + length)?;
        self.offset += length;
        Some(Attribute { bytes: attr_bytes })
    }
}

/// A single MFT attribute (a borrow of its record bytes).
#[derive(Debug, Clone, Copy)]
pub struct Attribute<'a> {
    bytes: &'a [u8],
}

impl<'a> Attribute<'a> {
    /// The attribute type code (e.g. [`ATTR_FILE_NAME`]).
    #[must_use]
    pub fn type_code(&self) -> u32 {
        u32_le(self.bytes, 0).unwrap_or(ATTR_END)
    }

    /// Whether the attribute is non-resident (its value lives in data runs).
    #[must_use]
    pub fn is_non_resident(&self) -> bool {
        self.bytes.get(8).copied() == Some(1)
    }

    /// The resident value bytes, if the attribute is resident.
    #[must_use]
    pub fn resident_value(&self) -> Option<&'a [u8]> {
        if self.is_non_resident() {
            return None;
        }
        let content_len = u32_le(self.bytes, 0x10)? as usize;
        let content_off = u16_le(self.bytes, 0x14)? as usize;
        self.bytes.get(content_off..content_off + content_len)
    }

    /// Decode the non-resident data runs, if the attribute is non-resident.
    #[must_use]
    pub fn data_runs(&self) -> Option<Vec<DataRun>> {
        if !self.is_non_resident() {
            return None;
        }
        let runs_off = u16_le(self.bytes, 0x20)? as usize;
        let run_bytes = self.bytes.get(runs_off..)?;
        Some(decode_data_runs(run_bytes))
    }

    /// The logical size of the attribute's value in bytes: the resident content
    /// length, or the non-resident "real size" (used to truncate the last
    /// cluster of a materialised run list).
    #[must_use]
    pub fn value_size(&self) -> Option<u64> {
        if self.is_non_resident() {
            u64_le(self.bytes, 0x30)
        } else {
            u32_le(self.bytes, 0x10).map(u64::from)
        }
    }
}

// -----------------------------------------------------------------------------
// $FILE_NAME
// -----------------------------------------------------------------------------

/// A decoded `$FILE_NAME` attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    /// The 48-bit MFT reference of the parent directory (low 48 bits of the
    /// 8-byte file reference).
    pub parent_ref: u64,
    /// The namespace (0 = POSIX, 1 = Win32, 2 = DOS, 3 = Win32 & DOS).
    pub namespace: u8,
    /// The file name.
    pub name: String,
}

impl FileName {
    /// Parse a `$FILE_NAME` attribute value.
    ///
    /// # Errors
    ///
    /// [`NtfsError::Truncated`] if the value is shorter than the fixed header or
    /// the declared name runs past the value.
    pub fn parse(value: &[u8]) -> Result<Self, NtfsError> {
        let parent_field = u64_le(value, 0).ok_or(NtfsError::Truncated)?;
        let parent_ref = parent_field & 0x0000_FFFF_FFFF_FFFF;
        let name_len = *value.get(0x40).ok_or(NtfsError::Truncated)? as usize;
        let namespace = *value.get(0x41).ok_or(NtfsError::Truncated)?;
        let name_bytes = value
            .get(0x42..0x42 + name_len * 2)
            .ok_or(NtfsError::Truncated)?;
        Ok(Self {
            parent_ref,
            namespace,
            name: decode_utf16le(name_bytes, name_len),
        })
    }
}

/// Decode up to `char_count` UTF-16LE code units, substituting U+FFFD for any
/// unpaired surrogate.
fn decode_utf16le(bytes: &[u8], char_count: usize) -> String {
    let mut units = Vec::with_capacity(char_count);
    let mut i = 0;
    while units.len() < char_count {
        let (Some(&lo), Some(&hi)) = (bytes.get(i), bytes.get(i + 1)) else {
            break;
        };
        units.push(u16::from_le_bytes([lo, hi]));
        i += 2;
    }
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

// -----------------------------------------------------------------------------
// Data runs (non-resident content mapping)
// -----------------------------------------------------------------------------

/// One run of a non-resident attribute's data-run list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataRun {
    /// Length of the run in clusters.
    pub length: u64,
    /// Starting logical cluster number, or `None` for a sparse/hole run.
    pub lcn: Option<i64>,
}

/// Decode an NTFS data-run (mapping-pairs) list.
///
/// Each run is a header byte (low nibble = length field size, high nibble = LCN
/// offset field size) followed by the length and a signed LCN delta relative to
/// the previous run. A zero header, or a truncated run, ends the list.
#[must_use]
pub fn decode_data_runs(bytes: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut lcn: i64 = 0;
    let mut i = 0;
    while let Some(&header) = bytes.get(i) {
        if header == 0 {
            break;
        }
        let len_size = usize::from(header & 0x0F);
        let off_size = usize::from(header >> 4);
        i += 1;
        let Some(length) = read_uint_le(bytes, i, len_size) else {
            break;
        };
        i += len_size;
        let run = if off_size == 0 {
            DataRun { length, lcn: None } // sparse run
        } else {
            let Some(delta) = read_int_le(bytes, i, off_size) else {
                break;
            };
            i += off_size;
            lcn = lcn.wrapping_add(delta);
            DataRun {
                length,
                lcn: Some(lcn),
            }
        };
        runs.push(run);
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal NTFS boot sector: 512 B/sector, 8 sectors/cluster,
    /// MFT at LCN 4, 1024-byte MFT records (clusters_per_mft = -10).
    fn boot_sector() -> Vec<u8> {
        let mut b = alloc::vec![0u8; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        b[0x0D] = 8;
        b[0x30..0x38].copy_from_slice(&4u64.to_le_bytes());
        b[0x40] = (-10i8) as u8; // 2^10 = 1024
        b
    }

    #[test]
    fn boot_sector_geometry() {
        let bs = BootSector::parse(&boot_sector()).unwrap();
        assert_eq!(bs.bytes_per_sector, 512);
        assert_eq!(bs.sectors_per_cluster, 8);
        assert_eq!(bs.cluster_size(), 4096);
        assert_eq!(bs.mft_lcn, 4);
        assert_eq!(bs.mft_record_size, 1024);
    }

    #[test]
    fn boot_sector_rejects_non_ntfs_and_zero_geometry() {
        assert_eq!(
            BootSector::parse(&[0u8; 512]),
            Err(NtfsError::BadBootSector)
        );
        let mut b = boot_sector();
        b[0x0B..0x0D].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(BootSector::parse(&b), Err(NtfsError::BadBootSector));
    }

    #[test]
    fn positive_clusters_per_mft_multiplies() {
        let mut b = boot_sector();
        b[0x40] = 1; // 1 cluster per record = 4096 bytes
        assert_eq!(BootSector::parse(&b).unwrap().mft_record_size, 4096);
    }

    #[test]
    fn fixups_are_verified_and_restored() {
        // A 1024-byte record over 512-byte sectors → 2 sector tails to fix.
        let mut rec = alloc::vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        let usa_offset = 0x30usize;
        rec[4..6].copy_from_slice(&(usa_offset as u16).to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // USN + 2 originals
        // USN = 0xBEEF; originals = 0x1122, 0x3344.
        rec[usa_offset..usa_offset + 2].copy_from_slice(&0xBEEFu16.to_le_bytes());
        rec[usa_offset + 2..usa_offset + 4].copy_from_slice(&0x1122u16.to_le_bytes());
        rec[usa_offset + 4..usa_offset + 6].copy_from_slice(&0x3344u16.to_le_bytes());
        // Plant the USN in each sector tail (bytes 510-511 and 1022-1023).
        rec[510..512].copy_from_slice(&0xBEEFu16.to_le_bytes());
        rec[1022..1024].copy_from_slice(&0xBEEFu16.to_le_bytes());

        apply_fixups(&mut rec, 512).unwrap();
        // The tails now carry the restored originals.
        assert_eq!(&rec[510..512], &0x1122u16.to_le_bytes());
        assert_eq!(&rec[1022..1024], &0x3344u16.to_le_bytes());
    }

    #[test]
    fn fixup_mismatch_is_detected() {
        let mut rec = alloc::vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[0x30..0x32].copy_from_slice(&0xBEEFu16.to_le_bytes());
        rec[510..512].copy_from_slice(&0xBEEFu16.to_le_bytes());
        // Second sector tail carries the WRONG value → torn write.
        rec[1022..1024].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert_eq!(apply_fixups(&mut rec, 512), Err(NtfsError::FixupMismatch));
    }

    /// Build a FILE record with a resident $FILE_NAME and a resident $DATA.
    fn file_record_with_name_and_data() -> Vec<u8> {
        let mut rec = alloc::vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[0x16..0x18].copy_from_slice(&0x0001u16.to_le_bytes()); // in-use, file
        let first_attr = 0x38usize;
        rec[0x14..0x16].copy_from_slice(&(first_attr as u16).to_le_bytes());

        // --- $FILE_NAME (resident) ---
        // name "hi" (2 UTF-16 chars). Value: 0x42 header + 4 name bytes = 0x46.
        let name = "hi";
        let value_len = 0x42 + name.len() * 2;
        let content_off = 0x18usize; // resident content offset within the attr
        let attr_len = content_off + value_len;
        let mut fn_attr = alloc::vec![0u8; attr_len];
        fn_attr[0..4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        fn_attr[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        fn_attr[8] = 0; // resident
        fn_attr[0x10..0x14].copy_from_slice(&(value_len as u32).to_le_bytes());
        fn_attr[0x14..0x16].copy_from_slice(&(content_off as u16).to_le_bytes());
        // value: parent ref = 5, name_len, namespace = 1 (Win32), name.
        fn_attr[content_off..content_off + 8].copy_from_slice(&5u64.to_le_bytes());
        fn_attr[content_off + 0x40] = name.len() as u8;
        fn_attr[content_off + 0x41] = 1;
        for (i, u) in name.encode_utf16().enumerate() {
            let at = content_off + 0x42 + i * 2;
            fn_attr[at..at + 2].copy_from_slice(&u.to_le_bytes());
        }

        // --- $DATA (resident), content = b"payload" ---
        let data = b"payload";
        let d_content_off = 0x18usize;
        let d_attr_len = d_content_off + data.len();
        let mut d_attr = alloc::vec![0u8; d_attr_len];
        d_attr[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        d_attr[4..8].copy_from_slice(&(d_attr_len as u32).to_le_bytes());
        d_attr[8] = 0;
        d_attr[0x10..0x14].copy_from_slice(&(data.len() as u32).to_le_bytes());
        d_attr[0x14..0x16].copy_from_slice(&(d_content_off as u16).to_le_bytes());
        d_attr[d_content_off..d_content_off + data.len()].copy_from_slice(data);

        // Splice the attributes in, then the end marker.
        let mut off = first_attr;
        rec[off..off + fn_attr.len()].copy_from_slice(&fn_attr);
        off += fn_attr.len();
        rec[off..off + d_attr.len()].copy_from_slice(&d_attr);
        off += d_attr.len();
        rec[off..off + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        rec
    }

    #[test]
    fn parses_file_record_header_and_attributes() {
        let rec = file_record_with_name_and_data();
        let fr = FileRecord::parse(&rec).unwrap();
        assert!(fr.is_in_use());
        assert!(!fr.is_directory());

        let types: Vec<u32> = fr.attributes().map(|a| a.type_code()).collect();
        assert_eq!(types, alloc::vec![ATTR_FILE_NAME, ATTR_DATA]);

        // $FILE_NAME decodes.
        let fn_attr = fr.find_attribute(ATTR_FILE_NAME).unwrap();
        let name = FileName::parse(fn_attr.resident_value().unwrap()).unwrap();
        assert_eq!(name.parent_ref, 5);
        assert_eq!(name.namespace, 1);
        assert_eq!(name.name, "hi");

        // $DATA resident value.
        let data = fr.find_attribute(ATTR_DATA).unwrap();
        assert_eq!(data.resident_value().unwrap(), b"payload");
        assert!(data.data_runs().is_none()); // resident → no runs
    }

    #[test]
    fn bad_signature_is_rejected() {
        let mut rec = file_record_with_name_and_data();
        rec[0] = b'X';
        assert!(matches!(
            FileRecord::parse(&rec),
            Err(NtfsError::BadSignature)
        ));
    }

    #[test]
    fn decodes_data_runs_with_relative_lcns() {
        // Two runs: (len 0x30 @ LCN 0x60), then (len 0x10 @ LCN 0x60+0x20).
        // Header nibbles: low = length field size, high = offset field size.
        // Run 1: header 0x11 → 1 len byte, 1 offset byte: 0x30, 0x60.
        // Run 2: header 0x11 → 1 len byte, 1 offset byte: 0x10, 0x20 (delta).
        // Terminator: 0x00.
        let runs = decode_data_runs(&[0x11, 0x30, 0x60, 0x11, 0x10, 0x20, 0x00]);
        assert_eq!(
            runs,
            alloc::vec![
                DataRun {
                    length: 0x30,
                    lcn: Some(0x60)
                },
                DataRun {
                    length: 0x10,
                    lcn: Some(0x80)
                },
            ]
        );
    }

    #[test]
    fn decodes_sparse_run_and_negative_delta() {
        // Sparse run (offset size 0): header 0x01 → len 1 byte, no offset.
        // Then a run with a negative delta: header 0x11, len 0x05, delta 0xFF.
        // 0xFF as a 1-byte signed = -1 → lcn = 0 + (-1) = -1 (Some).
        let runs = decode_data_runs(&[0x01, 0x08, 0x11, 0x05, 0xFF, 0x00]);
        assert_eq!(runs.len(), 2);
        assert_eq!(
            runs[0],
            DataRun {
                length: 0x08,
                lcn: None
            }
        );
        assert_eq!(
            runs[1],
            DataRun {
                length: 0x05,
                lcn: Some(-1)
            }
        );
    }
}

//! NTFS read paths: MFT record reads, file materialisation, directory listing
//! (WS3-05.7).
//!
//! [`NtfsVolume`] sits on top of the WS3-05.6 parsers. It reads MFT FILE records
//! out of the image (assuming the `$MFT` runs contiguously from its boot-sector
//! LCN — correct for the low system records and small volumes; a fragmented
//! `$MFT` would need `$MFT`'s own `$DATA` runlist, a follow-up), applies the
//! update-sequence fixups, and materialises a file's unnamed `$DATA` (resident,
//! or non-resident by gathering its data-run clusters and truncating to the real
//! size). Directory listing walks the **resident** `$INDEX_ROOT` entries; the
//! `$INDEX_ALLOCATION` B-tree for large directories is a documented follow-up.

use alloc::{string::String, vec::Vec};

use crate::{
    ATTR_DATA, ATTR_INDEX_ROOT, Attribute, BootSector, FileName, FileRecord, NtfsError,
    apply_fixups, u16_le, u32_le, u64_le,
};

/// A directory entry produced by [`NtfsVolume::list_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry file name.
    pub name: String,
    /// The referenced MFT record number (low 48 bits of the file reference).
    pub mft_ref: u64,
}

/// A read-only view over an NTFS image.
#[derive(Debug, Clone, Copy)]
pub struct NtfsVolume<'a> {
    image: &'a [u8],
    boot: BootSector,
}

impl<'a> NtfsVolume<'a> {
    /// Open a volume, parsing its boot sector.
    ///
    /// # Errors
    ///
    /// Propagates [`BootSector::parse`] errors.
    pub fn open(image: &'a [u8]) -> Result<Self, NtfsError> {
        Ok(Self {
            image,
            boot: BootSector::parse(image)?,
        })
    }

    /// The parsed boot-sector geometry.
    #[must_use]
    pub fn boot(&self) -> BootSector {
        self.boot
    }

    fn cluster_size(&self) -> usize {
        self.boot.cluster_size() as usize
    }

    /// Byte offset of MFT record `n`, assuming the `$MFT` is contiguous from its
    /// boot-sector LCN.
    fn record_offset(&self, n: u64) -> Option<usize> {
        let base = self
            .boot
            .mft_lcn
            .checked_mul(u64::from(self.boot.cluster_size()))?;
        let rec = n.checked_mul(u64::from(self.boot.mft_record_size))?;
        usize::try_from(base.checked_add(rec)?).ok()
    }

    /// Read MFT record `n` into an owned, fixed-up buffer.
    ///
    /// # Errors
    ///
    /// [`NtfsError::Truncated`] if the record lies outside the image; fixup
    /// errors from [`apply_fixups`].
    pub fn read_record(&self, n: u64) -> Result<Vec<u8>, NtfsError> {
        let off = self.record_offset(n).ok_or(NtfsError::Truncated)?;
        let size = self.boot.mft_record_size as usize;
        let slice = self
            .image
            .get(off..off + size)
            .ok_or(NtfsError::Truncated)?;
        let mut buf = slice.to_vec();
        apply_fixups(&mut buf, self.boot.bytes_per_sector)?;
        Ok(buf)
    }

    /// Materialise the unnamed `$DATA` of a (fixed-up) FILE record.
    ///
    /// Resident data is returned directly; non-resident data is gathered from
    /// its data runs (sparse runs contribute zeroed clusters) and truncated to
    /// the attribute's real size.
    ///
    /// # Errors
    ///
    /// [`NtfsError::MissingAttribute`] if there is no `$DATA`;
    /// [`NtfsError::Truncated`] if a run points outside the image.
    pub fn read_file(&self, record: &[u8]) -> Result<Vec<u8>, NtfsError> {
        let fr = FileRecord::parse(record)?;
        let data = fr
            .find_attribute(ATTR_DATA)
            .ok_or(NtfsError::MissingAttribute)?;
        if let Some(resident) = data.resident_value() {
            return Ok(resident.to_vec());
        }
        self.materialise_runs(&data)
    }

    fn materialise_runs(&self, data: &Attribute) -> Result<Vec<u8>, NtfsError> {
        let runs = data.data_runs().ok_or(NtfsError::Truncated)?;
        let real = data.value_size().unwrap_or(0);
        let cs = self.cluster_size();
        let mut out = Vec::new();
        for run in runs {
            let bytes = usize::try_from(run.length)
                .ok()
                .and_then(|l| l.checked_mul(cs));
            let bytes = bytes.ok_or(NtfsError::Truncated)?;
            match run.lcn {
                Some(lcn) if lcn >= 0 => {
                    let start = u64::try_from(lcn)
                        .ok()
                        .and_then(|l| l.checked_mul(cs as u64))
                        .and_then(|b| usize::try_from(b).ok())
                        .ok_or(NtfsError::Truncated)?;
                    let chunk = self
                        .image
                        .get(start..start + bytes)
                        .ok_or(NtfsError::Truncated)?;
                    out.extend_from_slice(chunk);
                }
                // Sparse run (hole) or an out-of-range LCN → zero-fill.
                _ => out.resize(out.len() + bytes, 0),
            }
        }
        let real = usize::try_from(real).unwrap_or(usize::MAX);
        out.truncate(real);
        Ok(out)
    }

    /// List a directory by walking its resident `$INDEX_ROOT` entries.
    ///
    /// # Errors
    ///
    /// [`NtfsError::MissingAttribute`] if the record has no resident
    /// `$INDEX_ROOT`.
    #[allow(
        clippy::unused_self,
        reason = "kept a method for API symmetry with read_file; a resident $INDEX_ROOT needs no volume geometry"
    )]
    pub fn list_dir(&self, record: &[u8]) -> Result<Vec<DirEntry>, NtfsError> {
        let fr = FileRecord::parse(record)?;
        let index_root = fr
            .find_attribute(ATTR_INDEX_ROOT)
            .ok_or(NtfsError::MissingAttribute)?;
        let value = index_root
            .resident_value()
            .ok_or(NtfsError::MissingAttribute)?;
        Ok(parse_index_entries(value))
    }
}

/// Walk the entries of a resident `$INDEX_ROOT` value into directory entries.
fn parse_index_entries(value: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    // INDEX_ROOT: fixed 0x10-byte header, then an INDEX_HEADER at 0x10 whose
    // first field is the offset (relative to the INDEX_HEADER) to entry 0.
    let Some(first_off) = u32_le(value, 0x10) else {
        return entries;
    };
    let Some(mut pos) = (0x10usize).checked_add(first_off as usize) else {
        return entries;
    };
    loop {
        let Some(entry_len) = u16_le(value, pos + 0x08) else {
            break;
        };
        let flags = u16_le(value, pos + 0x0C).unwrap_or(0x02);
        if flags & 0x02 != 0 {
            break; // last (end) entry — no key
        }
        if entry_len < 0x10 {
            break; // malformed; would not advance
        }
        // The key is a $FILE_NAME structure at entry offset 0x10.
        if let Some(key) = value.get(pos + 0x10..pos + entry_len as usize) {
            if let Ok(name) = FileName::parse(key) {
                let mft_ref = u64_le(value, pos).map_or(0, |r| r & 0x0000_FFFF_FFFF_FFFF);
                entries.push(DirEntry {
                    name: name.name,
                    mft_ref,
                });
            }
        }
        pos = match pos.checked_add(entry_len as usize) {
            Some(p) if p < value.len() => p,
            _ => break,
        };
    }
    entries
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]
mod tests {
    use super::*;

    fn cluster_size() -> usize {
        512 * 2 // matches the boot sector below
    }

    /// A boot sector: 512 B/sector, 2 sectors/cluster (1024 B clusters),
    /// `$MFT` at LCN 1, 1024-byte records.
    fn boot() -> Vec<u8> {
        let mut b = alloc::vec![0u8; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        b[0x0D] = 2;
        b[0x30..0x38].copy_from_slice(&1u64.to_le_bytes());
        b[0x40] = (-10i8) as u8; // 1024-byte records
        b
    }

    /// A 1024-byte FILE record carrying a single resident $DATA = `content`.
    fn record_with_resident_data(content: &[u8]) -> Vec<u8> {
        let mut rec = alloc::vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        // Minimal update sequence: offset 0x30, count 1 (USN only, no fixups).
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        rec[6..8].copy_from_slice(&1u16.to_le_bytes());
        rec[0x16..0x18].copy_from_slice(&0x0001u16.to_le_bytes());
        let first_attr = 0x38usize;
        rec[0x14..0x16].copy_from_slice(&(first_attr as u16).to_le_bytes());

        let content_off = 0x18usize;
        let attr_len = content_off + content.len();
        let mut d = alloc::vec![0u8; attr_len];
        d[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        d[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        d[8] = 0; // resident
        d[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
        d[0x14..0x16].copy_from_slice(&(content_off as u16).to_le_bytes());
        d[content_off..content_off + content.len()].copy_from_slice(content);

        rec[first_attr..first_attr + d.len()].copy_from_slice(&d);
        let end = first_attr + d.len();
        rec[end..end + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        rec
    }

    /// A record with a non-resident $DATA whose single run is `length` clusters
    /// starting at `lcn`, real size `real`.
    fn record_with_nonresident_data(lcn: u8, length: u8, real: u32) -> Vec<u8> {
        let mut rec = alloc::vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        rec[6..8].copy_from_slice(&1u16.to_le_bytes());
        rec[0x16..0x18].copy_from_slice(&0x0001u16.to_le_bytes());
        let first_attr = 0x38usize;
        rec[0x14..0x16].copy_from_slice(&(first_attr as u16).to_le_bytes());

        // Non-resident $DATA: runs at offset 0x40, one run header 0x11.
        let runs_off = 0x40usize;
        let attr_len = runs_off + 4;
        let mut d = alloc::vec![0u8; attr_len];
        d[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        d[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        d[8] = 1; // non-resident
        d[0x20..0x22].copy_from_slice(&(runs_off as u16).to_le_bytes());
        d[0x30..0x38].copy_from_slice(&u64::from(real).to_le_bytes());
        // run: header 0x11 (1 len byte, 1 offset byte), length, lcn.
        d[runs_off] = 0x11;
        d[runs_off + 1] = length;
        d[runs_off + 2] = lcn;
        // terminator d[runs_off+3] = 0 (already zero)

        rec[first_attr..first_attr + d.len()].copy_from_slice(&d);
        let end = first_attr + d.len();
        rec[end..end + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        rec
    }

    #[test]
    fn reads_resident_file_data() {
        let b = boot();
        let vol = NtfsVolume::open(&b).unwrap();
        let rec = record_with_resident_data(b"hello ntfs");
        assert_eq!(vol.read_file(&rec).unwrap(), b"hello ntfs");
    }

    #[test]
    fn reads_nonresident_file_data_from_runs() {
        // Build an image: boot(512) + padding to LCN 3 (cluster 1024B), then
        // the file's cluster content at LCN 3.
        let cs = cluster_size();
        let lcn = 3u8;
        let content = b"NONRESIDENT-DATA"; // 16 bytes, real size 16
        let mut image = alloc::vec![0u8; usize::from(lcn) * cs + cs];
        // boot sector at the start (LCN 0 area).
        image[0..512].copy_from_slice(&boot());
        // Place the file content at the start of LCN 3.
        let at = usize::from(lcn) * cs;
        image[at..at + content.len()].copy_from_slice(content);

        let vol = NtfsVolume::open(&image).unwrap();
        let rec = record_with_nonresident_data(lcn, 1, content.len() as u32);
        let out = vol.read_file(&rec).unwrap();
        assert_eq!(out.len(), content.len()); // truncated to real size
        assert_eq!(&out, content);
    }

    #[test]
    fn missing_data_attribute_errors() {
        let b = boot();
        let vol = NtfsVolume::open(&b).unwrap();
        let mut rec = alloc::vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        rec[6..8].copy_from_slice(&1u16.to_le_bytes());
        rec[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
        rec[0x38..0x3C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // only end marker
        assert_eq!(vol.read_file(&rec), Err(NtfsError::MissingAttribute));
    }

    #[test]
    fn record_offset_reads_from_the_mft() {
        // Put a FILE record at MFT record 0 (offset = mft_lcn * cluster_size).
        let cs = cluster_size();
        let mut image = alloc::vec![0u8; cs + 1024 + cs];
        image[0..512].copy_from_slice(&boot());
        let rec = record_with_resident_data(b"payload");
        let at = cs; // mft_lcn = 1 → offset = 1 * 1024
        image[at..at + rec.len()].copy_from_slice(&rec);

        let vol = NtfsVolume::open(&image).unwrap();
        let read = vol.read_record(0).unwrap();
        assert_eq!(&read[0..4], b"FILE");
        assert_eq!(vol.read_file(&read).unwrap(), b"payload");
    }

    #[test]
    fn lists_directory_from_resident_index_root() {
        let b = boot();
        let vol = NtfsVolume::open(&b).unwrap();
        let rec = record_with_index_root(&[("alpha", 11), ("beta", 22)]);
        let entries = vol.list_dir(&rec).unwrap();
        assert_eq!(
            entries,
            alloc::vec![
                DirEntry {
                    name: "alpha".into(),
                    mft_ref: 11
                },
                DirEntry {
                    name: "beta".into(),
                    mft_ref: 22
                },
            ]
        );
    }

    /// A FILE record carrying a resident $INDEX_ROOT with the given entries.
    fn record_with_index_root(names: &[(&str, u64)]) -> Vec<u8> {
        // Build the index entries first.
        let mut entries = Vec::new();
        for &(name, mft) in names {
            entries.extend_from_slice(&build_index_entry(name, mft, false));
        }
        entries.extend_from_slice(&build_index_entry("", 0, true)); // end entry

        // INDEX_ROOT value: 0x10 header + INDEX_HEADER (first entry at 0x10 into
        // the INDEX_HEADER) + entries.
        let mut value = alloc::vec![0u8; 0x20];
        value[0x00..0x04].copy_from_slice(&crate::ATTR_FILE_NAME.to_le_bytes()); // indexed type
        value[0x10..0x14].copy_from_slice(&0x10u32.to_le_bytes()); // first entry offset (rel 0x10)
        value.extend_from_slice(&entries);

        // Wrap in a resident $INDEX_ROOT attribute.
        let content_off = 0x18usize;
        let attr_len = content_off + value.len();
        let mut attr = alloc::vec![0u8; attr_len];
        attr[0..4].copy_from_slice(&ATTR_INDEX_ROOT.to_le_bytes());
        attr[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        attr[8] = 0; // resident
        attr[0x10..0x14].copy_from_slice(&(value.len() as u32).to_le_bytes());
        attr[0x14..0x16].copy_from_slice(&(content_off as u16).to_le_bytes());
        attr[content_off..content_off + value.len()].copy_from_slice(&value);

        let mut rec = alloc::vec![0u8; 2048];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        rec[6..8].copy_from_slice(&1u16.to_le_bytes());
        rec[0x16..0x18].copy_from_slice(&0x0003u16.to_le_bytes()); // in-use + directory
        let first_attr = 0x38usize;
        rec[0x14..0x16].copy_from_slice(&(first_attr as u16).to_le_bytes());
        rec[first_attr..first_attr + attr.len()].copy_from_slice(&attr);
        let end = first_attr + attr.len();
        rec[end..end + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        rec
    }

    /// Build one INDEX_ENTRY whose key is a $FILE_NAME for `name`.
    fn build_index_entry(name: &str, mft: u64, last: bool) -> Vec<u8> {
        // $FILE_NAME key: 0x42 header + name UTF-16.
        let key_len = if last { 0 } else { 0x42 + name.len() * 2 };
        let entry_len = 0x10 + key_len;
        let mut e = alloc::vec![0u8; entry_len];
        e[0x00..0x08].copy_from_slice(&mft.to_le_bytes()); // file reference
        e[0x08..0x0A].copy_from_slice(&(entry_len as u16).to_le_bytes());
        e[0x0A..0x0C].copy_from_slice(&(key_len as u16).to_le_bytes());
        let flags: u16 = if last { 0x02 } else { 0 };
        e[0x0C..0x0E].copy_from_slice(&flags.to_le_bytes());
        if !last {
            // key = $FILE_NAME: parent ref, name_len, namespace, UTF-16 name.
            e[0x10 + 0x40] = name.len() as u8;
            e[0x10 + 0x41] = 1;
            for (i, u) in name.encode_utf16().enumerate() {
                let at = 0x10 + 0x42 + i * 2;
                e[at..at + 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        e
    }
}

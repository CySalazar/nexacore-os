//! # `nexacore-fatfs`
//!
//! Read-only reader for the FAT family (FAT12 / FAT16 / FAT32), WS3-05.4/.5.
//!
//! FAT is unavoidable on a modern machine: the UEFI **EFI System Partition** is
//! FAT, and removable USB media are overwhelmingly FAT. This crate is the
//! host-testable, dependency-free, strictly **read-only** half of mounting them:
//! it parses the BIOS Parameter Block ([`Bpb`]), classifies the volume by its
//! cluster count, walks the FAT cluster chains (12/16/32-bit), and reads
//! directory trees — 8.3 short names plus assembled VFAT long names — and file
//! contents.
//!
//! ## Read-only by construction
//!
//! The reader borrows an immutable image (`&[u8]`) and never exposes a write
//! path. Exposing it as a capability-gated (`READONLY_COMPAT_FS`, WS3-05.1) VFS
//! service and wiring it to a live block device is WS3-05.8; ext4 and NTFS are
//! sibling members of the WS3-05 compat set.
//!
//! ## `no_std` + `alloc`
//!
//! `#![no_std]` pulling only `alloc` (no crypto, no `std`), so it builds for
//! `x86_64-unknown-none` as well as the developer host.

#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
        // The test builds a synthetic FAT image byte-by-byte: length→u32 casts,
        // FAT12 nibble arithmetic, and indexed writes over fixed-size buffers.
        clippy::cast_possible_truncation,
        clippy::integer_division,
        clippy::needless_range_loop,
    )
)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

/// FAT16 formatter for the installer's ESP (WS11-03.3).
pub mod mkfat;

/// Errors from reading a FAT volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatError {
    /// The image is shorter than the structure being read requires.
    Truncated,
    /// A structural field was invalid (bad signature, zero geometry, …).
    Corrupt,
    /// A cluster number was outside the volume's data region.
    BadCluster,
    /// A cluster chain formed a cycle (malformed / hostile image).
    ChainCycle,
    /// The referenced directory entry is not a directory.
    NotADirectory,
}

/// The FAT width, determined by the count of data clusters (per the Microsoft
/// specification: `< 4085` → FAT12, `< 65525` → FAT16, else FAT32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    /// 12-bit FAT (nibble-packed entries).
    Fat12,
    /// 16-bit FAT.
    Fat16,
    /// 32-bit FAT (28 significant bits).
    Fat32,
}

/// The parsed BIOS Parameter Block — the volume geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bpb {
    /// Bytes per logical sector (typically 512).
    pub bytes_per_sector: u16,
    /// Sectors per allocation cluster.
    pub sectors_per_cluster: u8,
    /// Reserved sectors before the first FAT.
    pub reserved_sectors: u16,
    /// Number of FAT copies.
    pub num_fats: u8,
    /// Root directory entries (FAT12/16; `0` on FAT32).
    pub root_entries: u16,
    /// Total sectors on the volume.
    pub total_sectors: u32,
    /// Sectors occupied by one FAT.
    pub fat_size_sectors: u32,
    /// Cluster of the root directory (FAT32; `0` otherwise).
    pub root_cluster: u32,
}

impl Bpb {
    /// Parse the BPB from the boot sector at the start of `image`.
    ///
    /// # Errors
    /// [`FatError::Truncated`] if the image is too small, [`FatError::Corrupt`]
    /// on a missing `0x55AA` signature or impossible geometry.
    pub fn parse(image: &[u8]) -> Result<Self, FatError> {
        if image.len() < 512 {
            return Err(FatError::Truncated);
        }
        if rd_u16(image, 510)? != 0xAA55 {
            return Err(FatError::Corrupt);
        }
        let bytes_per_sector = rd_u16(image, 11)?;
        let sectors_per_cluster = rd_u8(image, 13)?;
        let reserved_sectors = rd_u16(image, 14)?;
        let num_fats = rd_u8(image, 16)?;
        let root_entries = rd_u16(image, 17)?;
        // Geometry that would make cluster arithmetic ill-defined is rejected up
        // front so later reads can trust it.
        if bytes_per_sector < 512
            || !bytes_per_sector.is_power_of_two()
            || sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || reserved_sectors == 0
            || num_fats == 0
        {
            return Err(FatError::Corrupt);
        }
        let total_16 = rd_u16(image, 19)?;
        let fat_16 = rd_u16(image, 22)?;
        let total_sectors = if total_16 != 0 {
            u32::from(total_16)
        } else {
            rd_u32(image, 32)?
        };
        let fat_size_sectors = if fat_16 != 0 {
            u32::from(fat_16)
        } else {
            rd_u32(image, 36)?
        };
        let root_cluster = if fat_16 == 0 { rd_u32(image, 44)? } else { 0 };
        if total_sectors == 0 || fat_size_sectors == 0 {
            return Err(FatError::Corrupt);
        }
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_entries,
            total_sectors,
            fat_size_sectors,
            root_cluster,
        })
    }

    /// Sectors occupied by the fixed FAT12/16 root directory (`0` on FAT32).
    #[must_use]
    fn root_dir_sectors(&self) -> u32 {
        (u32::from(self.root_entries) * 32).div_ceil(u32::from(self.bytes_per_sector))
    }

    /// The first sector of the data region (cluster 2).
    #[must_use]
    fn first_data_sector(&self) -> u32 {
        u32::from(self.reserved_sectors)
            + u32::from(self.num_fats) * self.fat_size_sectors
            + self.root_dir_sectors()
    }

    /// The count of data clusters, which fixes the FAT width.
    #[must_use]
    #[allow(
        clippy::integer_division,
        reason = "data_sectors / sectors_per_cluster is the exact data-cluster count"
    )]
    fn cluster_count(&self) -> u32 {
        let data_sectors = self.total_sectors.saturating_sub(self.first_data_sector());
        data_sectors / u32::from(self.sectors_per_cluster)
    }

    /// The FAT width for this volume.
    #[must_use]
    fn fat_type(&self) -> FatType {
        match self.cluster_count() {
            0..=4084 => FatType::Fat12,
            4085..=65524 => FatType::Fat16,
            _ => FatType::Fat32,
        }
    }
}

/// A parsed directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The file name (VFAT long name if present, else the 8.3 short name).
    pub name: String,
    /// Whether the entry is a subdirectory.
    pub is_dir: bool,
    /// Whether the entry is marked read-only.
    pub read_only: bool,
    /// The first cluster of the entry's data (`0` for an empty file).
    pub first_cluster: u32,
    /// The file size in bytes (`0` for directories).
    pub size: u32,
}

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LFN: u8 = 0x0F;
const ENTRY_END: u8 = 0x00;
const ENTRY_DELETED: u8 = 0xE5;

/// A read-only FAT filesystem over an immutable image.
#[derive(Debug, Clone, Copy)]
pub struct FatFs<'a> {
    image: &'a [u8],
    bpb: Bpb,
    fat_type: FatType,
}

impl<'a> FatFs<'a> {
    /// Open the FAT volume in `image`.
    ///
    /// # Errors
    /// Propagates [`Bpb::parse`] errors.
    pub fn open(image: &'a [u8]) -> Result<Self, FatError> {
        let bpb = Bpb::parse(image)?;
        let fat_type = bpb.fat_type();
        Ok(Self {
            image,
            bpb,
            fat_type,
        })
    }

    /// The volume's FAT width.
    #[must_use]
    pub fn fat_type(&self) -> FatType {
        self.fat_type
    }

    /// The parsed BPB.
    #[must_use]
    pub fn bpb(&self) -> &Bpb {
        &self.bpb
    }

    /// Read the root directory.
    ///
    /// # Errors
    /// [`FatError`] on a malformed image or chain.
    pub fn root(&self) -> Result<Vec<DirEntry>, FatError> {
        match self.fat_type {
            FatType::Fat32 => {
                let bytes = self.read_chain(self.bpb.root_cluster)?;
                parse_dir(&bytes)
            }
            FatType::Fat12 | FatType::Fat16 => {
                // The fixed root region is contiguous, right after the FATs.
                let start = self
                    .sector_offset(self.bpb.first_data_sector())?
                    .checked_sub(self.root_dir_bytes())
                    .ok_or(FatError::Corrupt)?;
                let end = start
                    .checked_add(self.root_dir_bytes())
                    .ok_or(FatError::Corrupt)?;
                let region = self.image.get(start..end).ok_or(FatError::Truncated)?;
                parse_dir(region)
            }
        }
    }

    /// Read the entries of a subdirectory.
    ///
    /// # Errors
    /// [`FatError::NotADirectory`] if `entry` is a file, or a chain/read error.
    pub fn read_dir(&self, entry: &DirEntry) -> Result<Vec<DirEntry>, FatError> {
        if !entry.is_dir {
            return Err(FatError::NotADirectory);
        }
        let bytes = self.read_chain(entry.first_cluster)?;
        parse_dir(&bytes)
    }

    /// Read a file's contents (truncated to its recorded size).
    ///
    /// # Errors
    /// [`FatError`] on a malformed chain or out-of-range cluster.
    pub fn read_file(&self, entry: &DirEntry) -> Result<Vec<u8>, FatError> {
        let mut bytes = self.read_chain(entry.first_cluster)?;
        bytes.truncate(entry.size as usize);
        Ok(bytes)
    }

    /// Bytes occupied by the fixed FAT12/16 root directory region.
    fn root_dir_bytes(&self) -> usize {
        self.bpb.root_dir_sectors() as usize * self.bpb.bytes_per_sector as usize
    }

    /// The byte offset of a logical sector, bounds-aware.
    fn sector_offset(&self, sector: u32) -> Result<usize, FatError> {
        (sector as usize)
            .checked_mul(self.bpb.bytes_per_sector as usize)
            .ok_or(FatError::Corrupt)
    }

    /// The byte offset of a data cluster (`>= 2`).
    fn cluster_offset(&self, cluster: u32) -> Result<usize, FatError> {
        let rel = cluster.checked_sub(2).ok_or(FatError::BadCluster)?;
        let sector = self.bpb.first_data_sector()
            + rel
                .checked_mul(u32::from(self.bpb.sectors_per_cluster))
                .ok_or(FatError::BadCluster)?;
        self.sector_offset(sector)
    }

    /// The bytes of one cluster.
    fn cluster_bytes(&self, cluster: u32) -> Result<&'a [u8], FatError> {
        let start = self.cluster_offset(cluster)?;
        let len =
            usize::from(self.bpb.sectors_per_cluster) * usize::from(self.bpb.bytes_per_sector);
        let end = start.checked_add(len).ok_or(FatError::Corrupt)?;
        self.image.get(start..end).ok_or(FatError::Truncated)
    }

    /// The end-of-chain threshold for this FAT width.
    fn eoc_threshold(&self) -> u32 {
        match self.fat_type {
            FatType::Fat12 => 0x0FF8,
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// The FAT entry for cluster `n`.
    #[allow(
        clippy::integer_division,
        reason = "the FAT12 entry byte offset is n + n/2 by the on-disk definition"
    )]
    fn next_cluster(&self, n: u32) -> Result<u32, FatError> {
        let fat_start = self.sector_offset(u32::from(self.bpb.reserved_sectors))?;
        match self.fat_type {
            FatType::Fat16 => {
                let off = fat_start + (n as usize) * 2;
                Ok(u32::from(rd_u16(self.image, off)?))
            }
            FatType::Fat32 => {
                let off = fat_start + (n as usize) * 4;
                Ok(rd_u32(self.image, off)? & 0x0FFF_FFFF)
            }
            FatType::Fat12 => {
                let off = fat_start + (n as usize) + (n as usize) / 2;
                let raw = rd_u16(self.image, off)?;
                Ok(u32::from(if n & 1 == 1 { raw >> 4 } else { raw & 0x0FFF }))
            }
        }
    }

    /// Concatenate all clusters in the chain starting at `first`.
    fn read_chain(&self, first: u32) -> Result<Vec<u8>, FatError> {
        let mut out = Vec::new();
        if first < 2 {
            return Ok(out); // empty file / empty root
        }
        let eoc = self.eoc_threshold();
        let mut cluster = first;
        // Bound the walk by the cluster count so a cyclic/hostile chain can't
        // loop forever.
        let max_steps = self.bpb.cluster_count() as usize + 2;
        for _ in 0..max_steps {
            out.extend_from_slice(self.cluster_bytes(cluster)?);
            let next = self.next_cluster(cluster)?;
            if next >= eoc || next < 2 {
                return Ok(out);
            }
            if next == cluster {
                return Err(FatError::ChainCycle);
            }
            cluster = next;
        }
        Err(FatError::ChainCycle)
    }
}

/// Parse a directory region into entries, assembling VFAT long names.
fn parse_dir(bytes: &[u8]) -> Result<Vec<DirEntry>, FatError> {
    let mut entries = Vec::new();
    let mut lfn: Vec<u16> = Vec::new();
    let mut offset = 0usize;
    while let Some(raw) = bytes.get(offset..offset + 32) {
        offset += 32;
        let Some(&first) = raw.first() else { break };
        if first == ENTRY_END {
            break;
        }
        if first == ENTRY_DELETED {
            lfn.clear();
            continue;
        }
        let attr = raw.get(11).copied().unwrap_or(0);
        if attr == ATTR_LFN {
            accumulate_lfn(raw, &mut lfn);
            continue;
        }
        if attr & ATTR_VOLUME_ID != 0 {
            lfn.clear();
            continue; // volume label, not a file
        }
        let name = if lfn.is_empty() {
            decode_short_name(raw)
        } else {
            let n = assemble_lfn(&lfn);
            lfn.clear();
            n
        };
        let first_cluster = (u32::from(rd_u16(raw, 20)?) << 16) | u32::from(rd_u16(raw, 26)?);
        entries.push(DirEntry {
            name,
            is_dir: attr & ATTR_DIRECTORY != 0,
            read_only: attr & ATTR_READ_ONLY != 0,
            first_cluster,
            size: rd_u32(raw, 28)?,
        });
    }
    Ok(entries)
}

/// Place one LFN entry's 13 UTF-16 units at their logical position in `buf`.
fn accumulate_lfn(raw: &[u8], buf: &mut Vec<u16>) {
    let seq = usize::from(raw.first().copied().unwrap_or(0) & 0x1F);
    if seq == 0 {
        return;
    }
    let base = (seq - 1) * 13;
    if buf.len() < base + 13 {
        buf.resize(base + 13, 0);
    }
    // name1 [1..11] = 5 units, name2 [14..26] = 6 units, name3 [28..32] = 2 units.
    let slots = [(1usize, 5usize), (14, 6), (28, 2)];
    let mut idx = base;
    for (start, count) in slots {
        for k in 0..count {
            let off = start + k * 2;
            let unit = raw
                .get(off..off + 2)
                .and_then(|s| s.try_into().ok())
                .map_or(0, u16::from_le_bytes);
            if let Some(slot) = buf.get_mut(idx) {
                *slot = unit;
            }
            idx += 1;
        }
    }
}

/// Assemble collected UTF-16 units into a name, stopping at the NUL/pad marker.
fn assemble_lfn(units: &[u16]) -> String {
    let end = units
        .iter()
        .position(|&u| u == 0x0000 || u == 0xFFFF)
        .unwrap_or(units.len());
    let slice = units.get(..end).unwrap_or(units);
    char::decode_utf16(slice.iter().copied())
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Decode an 8.3 short name into `NAME.EXT` (upper-case, space-trimmed).
fn decode_short_name(raw: &[u8]) -> String {
    let mut name = String::new();
    let base = raw.get(0..8).unwrap_or(&[]);
    for (i, &b) in base.iter().enumerate() {
        // A leading 0x05 means the real first byte is 0xE5 (Kanji lead-byte).
        let b = if i == 0 && b == 0x05 { 0xE5 } else { b };
        if b != b' ' {
            name.push(b as char);
        }
    }
    let ext = raw.get(8..11).unwrap_or(&[]);
    let ext: String = ext
        .iter()
        .copied()
        .filter(|&b| b != b' ')
        .map(|b| b as char)
        .collect();
    if !ext.is_empty() {
        name.push('.');
        name.push_str(&ext);
    }
    name
}

fn rd_u8(b: &[u8], off: usize) -> Result<u8, FatError> {
    b.get(off).copied().ok_or(FatError::Truncated)
}

fn rd_u16(b: &[u8], off: usize) -> Result<u16, FatError> {
    b.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(FatError::Truncated)
}

fn rd_u32(b: &[u8], off: usize) -> Result<u32, FatError> {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(FatError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECTOR: usize = 512;

    /// The VFAT 8.3 checksum used by long-name entries.
    fn lfn_checksum(short: &[u8; 11]) -> u8 {
        let mut sum: u8 = 0;
        for &b in short {
            sum = sum.rotate_right(1).wrapping_add(b);
        }
        sum
    }

    fn put16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Write a 12-bit FAT entry (nibble-packed) for `cluster`.
    fn put_fat12(img: &mut [u8], base: usize, cluster: usize, val: u16) {
        let off = base + cluster + cluster / 2;
        let v = val & 0x0FFF;
        if cluster & 1 == 0 {
            img[off] = (v & 0xFF) as u8;
            img[off + 1] = (img[off + 1] & 0xF0) | ((v >> 8) as u8 & 0x0F);
        } else {
            img[off] = (img[off] & 0x0F) | (((v << 4) & 0xF0) as u8);
            img[off + 1] = ((v >> 4) & 0xFF) as u8;
        }
    }

    fn short_entry(buf: &mut [u8], off: usize, name: &[u8; 11], attr: u8, cluster: u16, size: u32) {
        buf[off..off + 11].copy_from_slice(name);
        buf[off + 11] = attr;
        put16(buf, off + 26, cluster);
        put32(buf, off + 28, size);
    }

    /// Build a minimal single-FAT **FAT12** image (small volumes are FAT12 by
    /// spec): root has HELLO.TXT (cluster 2) and dir SUB (cluster 3); SUB has a
    /// long-named file "LongName.txt" (8.3 LONGNA~1.TXT) whose data spans a
    /// **two-cluster chain** 4→5, so reads genuinely follow the FAT.
    fn build_fat12() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // 7 sectors: 0 boot, 1 FAT, 2 root, 3 c2 (HELLO), 4 c3 (SUB dir),
        // 5 c4 (long p1), 6 c5 (long p2).
        let mut img = alloc::vec![0u8; SECTOR * 7];

        // --- boot sector / BPB ---
        put16(&mut img, 11, 512); // bytes/sector
        img[13] = 1; // sectors/cluster
        put16(&mut img, 14, 1); // reserved
        img[16] = 1; // num fats
        put16(&mut img, 17, 16); // root entries (16*32 = 512 = 1 sector)
        put16(&mut img, 19, 7); // total sectors 16
        put16(&mut img, 22, 1); // fat size 16
        put16(&mut img, 510, 0xAA55); // signature

        let hello = b"Hello, ESP!\n".to_vec();
        let longdata: Vec<u8> = (0..600u16).map(|i| (i & 0xFF) as u8).collect();

        // --- FAT (sector 1), FAT12-packed ---
        let fat = SECTOR;
        put_fat12(&mut img, fat, 0, 0x0FF8); // media
        put_fat12(&mut img, fat, 1, 0x0FFF);
        put_fat12(&mut img, fat, 2, 0x0FFF); // c2 EOC
        put_fat12(&mut img, fat, 3, 0x0FFF); // c3 EOC
        put_fat12(&mut img, fat, 4, 0x0005); // c4 -> c5
        put_fat12(&mut img, fat, 5, 0x0FFF); // c5 EOC

        // --- root dir (sector 2) ---
        let root = SECTOR * 2;
        short_entry(&mut img, root, b"HELLO   TXT", 0x20, 2, hello.len() as u32);
        short_entry(&mut img, root + 32, b"SUB        ", 0x10, 3, 0);

        // --- cluster 2 (sector 3): HELLO.TXT data ---
        img[SECTOR * 3..SECTOR * 3 + hello.len()].copy_from_slice(&hello);

        // --- cluster 3 (sector 4): SUB directory ---
        let sub = SECTOR * 4;
        short_entry(&mut img, sub, b".          ", 0x10, 3, 0);
        short_entry(&mut img, sub + 32, b"..         ", 0x10, 0, 0);
        // LFN entry for "LongName.txt" preceding its 8.3 entry.
        let short = *b"LONGNA~1TXT";
        let lfn = sub + 64;
        img[lfn] = 0x41; // last | seq 1
        img[lfn + 11] = ATTR_LFN;
        img[lfn + 13] = lfn_checksum(&short);
        let name: [u16; 13] = {
            let mut n = [0u16; 13];
            for (i, c) in "LongName.txt".encode_utf16().enumerate() {
                n[i] = c;
            }
            n[12] = 0x0000; // 12 chars in 12 slots, 13th is the NUL terminator
            n
        };
        for k in 0..5 {
            put16(&mut img, lfn + 1 + k * 2, name[k]); // name1
        }
        for k in 0..6 {
            put16(&mut img, lfn + 14 + k * 2, name[5 + k]); // name2
        }
        for k in 0..2 {
            put16(&mut img, lfn + 28 + k * 2, name[11 + k]); // name3
        }
        short_entry(&mut img, sub + 96, &short, 0x20, 4, longdata.len() as u32);

        // --- clusters 4 & 5 (sectors 5 & 6): long file data ---
        img[SECTOR * 5..SECTOR * 5 + 512].copy_from_slice(&longdata[..512]);
        img[SECTOR * 6..SECTOR * 6 + (longdata.len() - 512)].copy_from_slice(&longdata[512..]);

        (img, hello, longdata)
    }

    #[test]
    fn parses_geometry_as_fat12() {
        let (img, _, _) = build_fat12();
        let fs = FatFs::open(&img).unwrap();
        assert_eq!(fs.fat_type(), FatType::Fat12);
        assert_eq!(fs.bpb().bytes_per_sector, 512);
        assert_eq!(fs.bpb().first_data_sector(), 3);
    }

    #[test]
    fn rejects_bad_signature_and_geometry() {
        let (mut img, _, _) = build_fat12();
        img[510] = 0; // break the 0x55AA signature
        assert_eq!(FatFs::open(&img).err(), Some(FatError::Corrupt));
        let (mut img, _, _) = build_fat12();
        put16(&mut img, 11, 0); // bytes/sector = 0
        assert_eq!(FatFs::open(&img).err(), Some(FatError::Corrupt));
        assert_eq!(FatFs::open(&img[..100]).err(), Some(FatError::Truncated));
    }

    #[test]
    fn reads_root_files_and_directories() {
        let (img, hello, _) = build_fat12();
        let fs = FatFs::open(&img).unwrap();
        let root = fs.root().unwrap();
        let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["HELLO.TXT", "SUB"]);

        let hello_entry = root.iter().find(|e| e.name == "HELLO.TXT").unwrap();
        assert!(!hello_entry.is_dir);
        assert_eq!(fs.read_file(hello_entry).unwrap(), hello);

        let sub = root.iter().find(|e| e.name == "SUB").unwrap();
        assert!(sub.is_dir);
    }

    #[test]
    fn assembles_vfat_long_name_and_follows_a_multi_cluster_chain() {
        let (img, _, longdata) = build_fat12();
        let fs = FatFs::open(&img).unwrap();
        let root = fs.root().unwrap();
        let sub = root.iter().find(|e| e.name == "SUB").unwrap();
        let sub_entries = fs.read_dir(sub).unwrap();
        // "." and ".." plus the long-named file.
        let long = sub_entries
            .iter()
            .find(|e| e.name == "LongName.txt")
            .expect("VFAT long name assembled");
        assert!(!long.is_dir);
        // 600 bytes spanning clusters 4->5: proves the FAT chain is walked and
        // the result is truncated to the recorded size.
        assert_eq!(fs.read_file(long).unwrap(), longdata);
        assert_eq!(longdata.len(), 600);
    }

    #[test]
    fn read_dir_on_a_file_is_rejected() {
        let (img, _, _) = build_fat12();
        let fs = FatFs::open(&img).unwrap();
        let root = fs.root().unwrap();
        let hello = root.iter().find(|e| e.name == "HELLO.TXT").unwrap();
        assert_eq!(fs.read_dir(hello).err(), Some(FatError::NotADirectory));
    }
}

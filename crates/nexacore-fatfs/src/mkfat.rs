//! FAT16 formatter for the EFI System Partition (WS11-03.3).
//!
//! `mkfs.fat` for the installer's ESP: given a partition size, it computes valid
//! FAT16 geometry (auto-selecting the cluster size so the cluster count lands in
//! the FAT16 range), writes the boot sector / BIOS Parameter Block, seeds both
//! FAT copies, and lays down an empty root directory with a volume label. The
//! result mounts cleanly with this crate's own [`crate::FatFs`] reader.
//!
//! FAT12 (tiny volumes) and FAT32 (multi-GB ESPs) are follow-ups; FAT16 covers
//! the typical 100 MiB – 2 GiB ESP.

use alloc::{vec, vec::Vec};

use crate::{FatFs, FatType};

/// Bytes per sector the formatter emits.
const BYTES_PER_SECTOR: usize = 512;
/// Reserved sectors (just the boot sector).
const RESERVED_SECTORS: u32 = 1;
/// Number of FAT copies (the on-disk standard for redundancy).
const NUM_FATS: u32 = 2;
/// Root directory entries (512 → 32 sectors).
const ROOT_ENTRIES: u32 = 512;
/// The FAT16 lower cluster-count bound (below this a volume is FAT12).
const FAT16_MIN_CLUSTERS: u32 = 4085;
/// The FAT16 upper cluster-count bound (at/above this a volume is FAT32).
const FAT16_MAX_CLUSTERS: u32 = 65525;

/// Why formatting failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkfsError {
    /// The partition is too small to form a FAT16 volume.
    TooSmall,
    /// The partition is too large for FAT16 (needs FAT32, a follow-up).
    TooLarge,
}

/// Computed FAT16 geometry for a partition of `total_sectors`.
struct Geometry {
    sectors_per_cluster: u32,
    fat_size: u32,
}

fn root_dir_sectors() -> u32 {
    (ROOT_ENTRIES * 32).div_ceil(512)
}

/// Pick a cluster size and FAT size that place the cluster count in the FAT16
/// range, per the Microsoft `FatGen` formula.
#[allow(
    clippy::integer_division,
    reason = "FAT sector/cluster arithmetic is integer by definition"
)]
fn geometry(total_sectors: u32) -> Result<Geometry, MkfsError> {
    let rds = root_dir_sectors();
    // Smallest power-of-two cluster size that keeps the count under the FAT16 max.
    let mut spc = 1u32;
    while total_sectors / spc >= FAT16_MAX_CLUSTERS && spc < 128 {
        spc *= 2;
    }
    let after_reserved = total_sectors
        .checked_sub(RESERVED_SECTORS + rds)
        .ok_or(MkfsError::TooSmall)?;
    // FatGen: bytes_per_sector/2 == 256 entries per FAT sector for FAT16.
    let divisor = 256 * spc + NUM_FATS;
    let fat_size = after_reserved.div_ceil(divisor);
    let first_data = RESERVED_SECTORS + NUM_FATS * fat_size + rds;
    let data_sectors = total_sectors
        .checked_sub(first_data)
        .ok_or(MkfsError::TooSmall)?;
    let cluster_count = data_sectors / spc;
    if cluster_count < FAT16_MIN_CLUSTERS {
        return Err(MkfsError::TooSmall);
    }
    if cluster_count >= FAT16_MAX_CLUSTERS {
        return Err(MkfsError::TooLarge);
    }
    Ok(Geometry {
        sectors_per_cluster: spc,
        fat_size,
    })
}

/// Format `total_sectors` (512-byte) as a FAT16 volume with `volume_label`
/// (padded/truncated to 11 bytes), returning the full image.
///
/// # Errors
/// [`MkfsError::TooSmall`] / [`MkfsError::TooLarge`] when the size is outside the
/// FAT16 range.
#[allow(
    clippy::cast_possible_truncation,
    reason = "BPB fields hold small values (bytes/sector 512, spc ≤128, fat_size, counts) validated to fit their width"
)]
pub fn format_fat16(total_sectors: u32, volume_label: &[u8]) -> Result<Vec<u8>, MkfsError> {
    let geo = geometry(total_sectors)?;
    let mut img = vec![0u8; total_sectors as usize * BYTES_PER_SECTOR];

    // --- boot sector / BPB ---
    put_bytes(&mut img, 0, &[0xEB, 0x3C, 0x90]); // jump
    put_bytes(&mut img, 3, b"NEXACORE"); // OEM name
    put_u16(&mut img, 11, BYTES_PER_SECTOR as u16);
    put_u8(&mut img, 13, geo.sectors_per_cluster as u8);
    put_u16(&mut img, 14, RESERVED_SECTORS as u16);
    put_u8(&mut img, 16, NUM_FATS as u8);
    put_u16(&mut img, 17, ROOT_ENTRIES as u16);
    if total_sectors < 0x1_0000 {
        put_u16(&mut img, 19, total_sectors as u16);
    } else {
        put_u32(&mut img, 32, total_sectors);
    }
    put_u8(&mut img, 21, 0xF8); // media descriptor (fixed disk)
    put_u16(&mut img, 22, geo.fat_size as u16);
    // FAT16 extended boot record.
    put_u8(&mut img, 36, 0x80); // drive number
    put_u8(&mut img, 38, 0x29); // extended boot signature
    put_u32(&mut img, 39, 0x4E58_4331); // volume id
    put_label(&mut img, 43, volume_label);
    put_bytes(&mut img, 54, b"FAT16   ");
    put_u16(&mut img, 510, 0xAA55); // boot signature

    // --- FAT copies: entry 0 = media+EOC, entry 1 = EOC, rest free ---
    for copy in 0..NUM_FATS {
        let fat_start = (RESERVED_SECTORS + copy * geo.fat_size) as usize * BYTES_PER_SECTOR;
        put_bytes(&mut img, fat_start, &[0xF8, 0xFF, 0xFF, 0xFF]);
    }

    // --- root directory: a single volume-label entry ---
    let root_start = (RESERVED_SECTORS + NUM_FATS * geo.fat_size) as usize * BYTES_PER_SECTOR;
    put_label(&mut img, root_start, volume_label);
    put_u8(&mut img, root_start + 11, 0x08); // ATTR_VOLUME_ID

    Ok(img)
}

fn put_u8(buf: &mut [u8], off: usize, v: u8) {
    if let Some(slot) = buf.get_mut(off) {
        *slot = v;
    }
}

fn put_bytes(buf: &mut [u8], off: usize, src: &[u8]) {
    if let Some(slot) = buf.get_mut(off..off + src.len()) {
        slot.copy_from_slice(src);
    }
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    put_bytes(buf, off, &v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    put_bytes(buf, off, &v.to_le_bytes());
}

/// Write an 11-byte, space-padded FAT volume label.
fn put_label(buf: &mut [u8], off: usize, label: &[u8]) {
    let mut field = [b' '; 11];
    for (dst, &src) in field.iter_mut().zip(label.iter()) {
        *dst = src;
    }
    put_bytes(buf, off, &field);
}

/// Convenience: format the volume and immediately open it for verification.
///
/// # Errors
/// Formatting errors from [`format_fat16`]; the open cannot fail on a
/// well-formed image.
pub fn format_and_open_check(total_sectors: u32) -> Result<FatType, MkfsError> {
    let img = format_fat16(total_sectors, b"NEXACORE")?;
    let fs = FatFs::open(&img).map_err(|_| MkfsError::TooSmall)?;
    Ok(fs.fat_type())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_reader_mounts_empty_fat16() {
        // 8192 sectors (4 MiB) → FAT16.
        let img = format_fat16(8192, b"ESP").unwrap();
        let fs = FatFs::open(&img).unwrap();
        assert_eq!(fs.fat_type(), FatType::Fat16);
        // The root has only the volume-label entry, which the reader skips.
        let root = fs.root().unwrap();
        assert!(root.is_empty(), "freshly formatted volume has no files");
    }

    #[test]
    fn a_512_mib_esp_stays_fat16() {
        // 512 MiB / 512 = 1_048_576 sectors → cluster size auto-grows to keep FAT16.
        let ty = format_and_open_check(1_048_576).unwrap();
        assert_eq!(ty, FatType::Fat16);
    }

    #[test]
    fn rejects_out_of_range_sizes() {
        assert_eq!(format_fat16(64, b"X").err(), Some(MkfsError::TooSmall));
        // Beyond FAT16 even at the max cluster size → needs FAT32.
        assert_eq!(
            format_fat16(u32::MAX, b"X").err(),
            Some(MkfsError::TooLarge)
        );
    }
}

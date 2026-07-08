//! Spec-correct GUID Partition Table construction (WS11-03.2).
//!
//! Builds the on-disk GPT metadata for a UEFI disk: a protective MBR, the
//! primary and backup GPT headers (each with its little-endian CRC32), and the
//! 128-entry partition array (also CRC32-protected). Partition entries carry the
//! EFI-System and NexaCore-root type GUIDs, LBA range, attributes, and a
//! UTF-16LE name. Everything is pure bytes and host-verifiable — writing the
//! blocks to a real device is the driver-backed integration step.

use alloc::{string::String, vec::Vec};

/// Bytes per logical sector assumed by the layout constants.
pub const SECTOR_SIZE: usize = 512;
/// Number of partition entries in the array (the UEFI-standard 128).
pub const ENTRY_COUNT: u32 = 128;
/// Size of one partition entry in bytes.
pub const ENTRY_SIZE: u32 = 128;
/// LBA at which the primary partition-entry array begins.
pub const PRIMARY_ENTRY_LBA: u64 = 2;
/// Sectors the entry array occupies (`128 * 128 / 512`).
#[allow(clippy::integer_division, reason = "exact: 16384 / 512 = 32")]
pub const ENTRY_SECTORS: u64 = (ENTRY_COUNT as u64 * ENTRY_SIZE as u64) / SECTOR_SIZE as u64;
/// First LBA usable by data: MBR(0) + header(1) + entry array(2..=33).
pub const FIRST_USABLE_LBA: u64 = 2 + ENTRY_SECTORS;

/// The CRC-32/ISO-HDLC checksum (IEEE 802.3) GPT uses.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A 128-bit GUID stored in its GPT on-disk (mixed-endian) form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid([u8; 16]);

impl Guid {
    /// Build a GUID from its canonical fields. The first three are stored
    /// little-endian and the trailing eight bytes as-is, per the GPT format.
    #[must_use]
    pub const fn from_fields(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        let a = d1.to_le_bytes();
        let b = d2.to_le_bytes();
        let c = d3.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4],
            d4[5], d4[6], d4[7],
        ])
    }

    /// The 16 on-disk bytes.
    #[must_use]
    pub fn bytes(&self) -> [u8; 16] {
        self.0
    }

    /// The all-zero GUID (an unused partition entry).
    pub const ZERO: Self = Self([0u8; 16]);

    /// The EFI System Partition type GUID (`C12A7328-F81F-11D2-BA4B-00A0C93EC93B`).
    pub const EFI_SYSTEM: Self = Self::from_fields(
        0xC12A_7328,
        0xF81F,
        0x11D2,
        [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    );

    /// The provisional NexaCore NCFS root type GUID (to be frozen in an NCIP).
    pub const NEXACORE_ROOT: Self = Self::from_fields(
        0x4E43_4653, // "NCFS"
        0x0001,
        0x0001,
        [0x4E, 0x45, 0x58, 0x41, 0x43, 0x4F, 0x52, 0x45], // "NEXACORE"
    );
}

/// A single GPT partition entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// Partition type GUID.
    pub type_guid: Guid,
    /// Unique partition GUID (the installer supplies a random one per install).
    pub unique_guid: Guid,
    /// First LBA (inclusive).
    pub first_lba: u64,
    /// Last LBA (inclusive).
    pub last_lba: u64,
    /// Attribute flags.
    pub attributes: u64,
    /// Human-readable name (≤36 UTF-16 code units).
    pub name: String,
}

impl Partition {
    /// Serialise the entry to its 128-byte on-disk form.
    #[must_use]
    pub fn encode(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        write_bytes(&mut out, 0, &self.type_guid.bytes());
        write_bytes(&mut out, 16, &self.unique_guid.bytes());
        put_u64(&mut out, 32, self.first_lba);
        put_u64(&mut out, 40, self.last_lba);
        put_u64(&mut out, 48, self.attributes);
        // Name: UTF-16LE, up to 36 code units in the 72-byte field.
        let mut off = 56;
        for unit in self.name.encode_utf16().take(36) {
            put_u16(&mut out, off, unit);
            off += 2;
        }
        out
    }
}

/// A complete GPT layout for a disk of `disk_sectors` 512-byte sectors.
#[derive(Debug, Clone)]
pub struct GptLayout {
    disk_sectors: u64,
    disk_guid: Guid,
    partitions: Vec<Partition>,
}

impl GptLayout {
    /// A layout for a disk with `disk_sectors` sectors, identified by
    /// `disk_guid`, holding `partitions`.
    #[must_use]
    pub fn new(disk_sectors: u64, disk_guid: Guid, partitions: Vec<Partition>) -> Self {
        Self {
            disk_sectors,
            disk_guid,
            partitions,
        }
    }

    /// First LBA usable by a partition.
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "constant, but a method for call-site symmetry"
    )]
    pub fn first_usable_lba(&self) -> u64 {
        FIRST_USABLE_LBA
    }

    /// Last LBA usable by a partition (before the backup metadata).
    #[must_use]
    pub fn last_usable_lba(&self) -> u64 {
        self.disk_sectors.saturating_sub(FIRST_USABLE_LBA)
    }

    /// The LBA of the backup GPT header (the last sector).
    #[must_use]
    pub fn backup_header_lba(&self) -> u64 {
        self.disk_sectors.saturating_sub(1)
    }

    /// The LBA at which the backup partition-entry array begins.
    #[must_use]
    pub fn backup_entry_lba(&self) -> u64 {
        self.disk_sectors.saturating_sub(1 + ENTRY_SECTORS)
    }

    /// The full partition-entry array (`ENTRY_COUNT * ENTRY_SIZE` bytes): the
    /// partitions followed by zeroed entries.
    #[must_use]
    pub fn entry_array(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENTRY_COUNT as usize * ENTRY_SIZE as usize);
        for part in self.partitions.iter().take(ENTRY_COUNT as usize) {
            out.extend_from_slice(&part.encode());
        }
        out.resize(ENTRY_COUNT as usize * ENTRY_SIZE as usize, 0);
        out
    }

    /// The CRC32 of the partition-entry array.
    #[must_use]
    pub fn entry_array_crc(&self) -> u32 {
        crc32(&self.entry_array())
    }

    /// The protective MBR (LBA 0): one type-`0xEE` partition covering the disk.
    #[must_use]
    pub fn protective_mbr(&self) -> [u8; SECTOR_SIZE] {
        let mut mbr = [0u8; SECTOR_SIZE];
        // Single partition record at offset 446.
        let rec = 446;
        put_u8(&mut mbr, rec + 4, 0xEE); // partition type: GPT protective
        put_u32(&mut mbr, rec + 8, 1); // starting LBA = 1
        // Size in sectors, saturated to u32::MAX for large disks.
        let size = u32::try_from(self.disk_sectors.saturating_sub(1)).unwrap_or(u32::MAX);
        put_u32(&mut mbr, rec + 12, size);
        put_u16(&mut mbr, 510, 0xAA55); // boot signature
        mbr
    }

    /// A GPT header sector. `backup = false` builds the primary (LBA 1), `true`
    /// builds the backup (the last LBA).
    #[must_use]
    pub fn header(&self, backup: bool) -> [u8; SECTOR_SIZE] {
        let mut h = [0u8; SECTOR_SIZE];
        write_bytes(&mut h, 0, b"EFI PART");
        put_u32(&mut h, 8, 0x0001_0000); // revision 1.0
        put_u32(&mut h, 12, 92); // header size
        // 16..20 header CRC — filled in last.
        // 20..24 reserved = 0.
        let (current, other, entry_lba) = if backup {
            (self.backup_header_lba(), 1, self.backup_entry_lba())
        } else {
            (1, self.backup_header_lba(), PRIMARY_ENTRY_LBA)
        };
        put_u64(&mut h, 24, current);
        put_u64(&mut h, 32, other);
        put_u64(&mut h, 40, self.first_usable_lba());
        put_u64(&mut h, 48, self.last_usable_lba());
        write_bytes(&mut h, 56, &self.disk_guid.bytes());
        put_u64(&mut h, 72, entry_lba);
        put_u32(&mut h, 80, ENTRY_COUNT);
        put_u32(&mut h, 84, ENTRY_SIZE);
        put_u32(&mut h, 88, self.entry_array_crc());
        // Header CRC over the first 92 bytes with the CRC field zeroed.
        let crc = crc32(h.get(0..92).unwrap_or(&[]));
        put_u32(&mut h, 16, crc);
        h
    }
}

fn put_u8(buf: &mut [u8], off: usize, v: u8) {
    if let Some(slot) = buf.get_mut(off) {
        *slot = v;
    }
}

fn write_bytes(buf: &mut [u8], off: usize, src: &[u8]) {
    if let Some(slot) = buf.get_mut(off..off + src.len()) {
        slot.copy_from_slice(src);
    }
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    write_bytes(buf, off, &v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    write_bytes(buf, off, &v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    write_bytes(buf, off, &v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn rd_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn rd_u64(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn crc32_matches_known_vector() {
        // The IEEE CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn efi_system_guid_encodes_mixed_endian() {
        // C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        let b = Guid::EFI_SYSTEM.bytes();
        assert_eq!(&b[0..4], &[0x28, 0x73, 0x2A, 0xC1]); // d1 little-endian
        assert_eq!(&b[4..6], &[0x1F, 0xF8]); // d2 little-endian
        assert_eq!(&b[6..8], &[0xD2, 0x11]); // d3 little-endian
        assert_eq!(&b[8..], &[0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]); // as-is
    }

    fn sample() -> GptLayout {
        // A 1 GiB disk (2_097_152 512-byte sectors).
        let esp = Partition {
            type_guid: Guid::EFI_SYSTEM,
            unique_guid: Guid::from_fields(1, 0, 0, [0; 8]),
            first_lba: 2048,
            last_lba: 2048 + 1024 * 1024 - 1, // 512 MiB
            attributes: 0,
            name: "EFI System".to_string(),
        };
        let root = Partition {
            type_guid: Guid::NEXACORE_ROOT,
            unique_guid: Guid::from_fields(2, 0, 0, [0; 8]),
            first_lba: 2048 + 1024 * 1024,
            last_lba: 2_097_152 - FIRST_USABLE_LBA,
            attributes: 0,
            name: "NexaCore".to_string(),
        };
        GptLayout::new(
            2_097_152,
            Guid::from_fields(9, 9, 9, [9; 8]),
            alloc::vec![esp, root],
        )
    }

    #[test]
    fn header_crc_and_entry_crc_validate() {
        let gpt = sample();
        let header = gpt.header(false);
        // Signature and geometry.
        assert_eq!(&header[0..8], b"EFI PART");
        assert_eq!(rd_u64(&header, 24), 1); // current LBA = primary
        assert_eq!(rd_u64(&header, 32), 2_097_151); // backup LBA
        assert_eq!(rd_u64(&header, 40), FIRST_USABLE_LBA);
        assert_eq!(rd_u32(&header, 80), ENTRY_COUNT);
        // Re-verify the header CRC: zero the field and recompute.
        let stored = rd_u32(&header, 16);
        let mut check = header;
        check[16..20].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(crc32(&check[0..92]), stored);
        // Entry-array CRC in the header matches the array.
        assert_eq!(rd_u32(&header, 88), gpt.entry_array_crc());
    }

    #[test]
    fn backup_header_mirrors_primary() {
        let gpt = sample();
        let backup = gpt.header(true);
        assert_eq!(rd_u64(&backup, 24), 2_097_151); // current = last LBA
        assert_eq!(rd_u64(&backup, 32), 1); // backup points at primary
        assert_eq!(rd_u64(&backup, 72), gpt.backup_entry_lba());
        // Its own CRC validates.
        let stored = rd_u32(&backup, 16);
        let mut check = backup;
        check[16..20].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(crc32(&check[0..92]), stored);
    }

    #[test]
    fn protective_mbr_is_well_formed() {
        let mbr = sample().protective_mbr();
        assert_eq!(mbr[446 + 4], 0xEE); // protective type
        assert_eq!(rd_u32(&mbr, 446 + 8), 1); // starts at LBA 1
        assert_eq!(&mbr[510..512], &[0x55, 0xAA]);
    }

    #[test]
    fn partition_entry_round_trips() {
        let gpt = sample();
        let array = gpt.entry_array();
        assert_eq!(array.len(), 128 * 128);
        // First entry = the ESP.
        assert_eq!(&array[0..16], &Guid::EFI_SYSTEM.bytes());
        assert_eq!(rd_u64(&array, 32), 2048); // first LBA
        // Name decodes back to UTF-16LE "EFI System".
        let units: Vec<u16> = (0..10)
            .map(|i| u16::from_le_bytes([array[56 + i * 2], array[57 + i * 2]]))
            .collect();
        let name: String = char::decode_utf16(units).map(|r| r.unwrap()).collect();
        assert_eq!(name, "EFI System");
        // Third entry onwards is zeroed.
        assert!(array[256..384].iter().all(|&b| b == 0));
    }
}

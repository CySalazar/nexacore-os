//! Deterministic GPT normalization for reproducible disk images (WS0-04.7).
//!
//! `bootloader 0.11`'s `UefiBoot::create_disk_image` generates the GPT disk
//! GUID and every partition's unique GUID with a fresh random UUID on each
//! run, so two builds of the same commit produce different `boot-uefi.img`
//! bytes (disk GUID + partition GUIDs + the three CRC32 fields that cover
//! them) — and therefore different ISOs. This module rewrites those GUIDs
//! with values derived from `SOURCE_DATE_EPOCH` and recomputes the CRCs,
//! mirroring what xorriso already does for the outer ISO GPT.
//!
//! Layout reference: UEFI spec 2.10 § 5.3 (GPT header and partition entry
//! array). Only the GUID and CRC fields are touched; sizes, LBAs and
//! partition contents are preserved byte-for-byte.

/// GPT header field offsets (within the 92-byte header).
const SIG_OFF: usize = 0; // "EFI PART"
const HDR_SIZE_OFF: usize = 12; // u32
const HDR_CRC_OFF: usize = 16; // u32, computed with this field zeroed
const BACKUP_LBA_OFF: usize = 32; // u64
const DISK_GUID_OFF: usize = 56; // 16 bytes
const ARRAY_LBA_OFF: usize = 72; // u64
const ARRAY_NUM_OFF: usize = 80; // u32
const ARRAY_ENTRY_SIZE_OFF: usize = 84; // u32
const ARRAY_CRC_OFF: usize = 88; // u32

const SECTOR: usize = 512;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// CRC-32 (IEEE, reflected, poly 0xEDB88320) — the GPT checksum. Bitwise
/// implementation: the inputs are a few KiB, table speed is irrelevant.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Deterministic GUID: "NexaCore" + SOURCE_DATE_EPOCH (LE) + an index byte that
/// keeps the disk GUID and each partition GUID distinct. The RFC 4122
/// version/variant bits are set so the value still parses as a v4 UUID.
fn derived_guid(epoch: u64, index: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..4].copy_from_slice(b"OMNI");
    g[4..12].copy_from_slice(&epoch.to_le_bytes());
    g[12] = index;
    g[6] = (g[6] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

/// Patch one GPT header (primary or backup) and its partition entry array.
fn normalize_header(img: &mut [u8], header_lba: u64, epoch: u64) -> Result<(), String> {
    let hdr_start = header_lba as usize * SECTOR;
    if hdr_start + SECTOR > img.len() {
        return Err(format!("GPT header LBA {header_lba} beyond image end"));
    }
    if &img[hdr_start + SIG_OFF..hdr_start + SIG_OFF + 8] != GPT_SIGNATURE {
        return Err(format!("no GPT signature at LBA {header_lba}"));
    }

    let hdr_size = read_u32(img, hdr_start + HDR_SIZE_OFF) as usize;
    let array_lba = read_u64(img, hdr_start + ARRAY_LBA_OFF);
    let num_entries = read_u32(img, hdr_start + ARRAY_NUM_OFF) as usize;
    let entry_size = read_u32(img, hdr_start + ARRAY_ENTRY_SIZE_OFF) as usize;
    if hdr_size < 92 || hdr_size > SECTOR || entry_size < 128 {
        return Err(format!("implausible GPT geometry at LBA {header_lba}"));
    }

    let array_start = array_lba as usize * SECTOR;
    let array_len = num_entries * entry_size;
    if array_start + array_len > img.len() {
        return Err(format!("partition array of LBA {header_lba} beyond image end"));
    }

    img[hdr_start + DISK_GUID_OFF..hdr_start + DISK_GUID_OFF + 16]
        .copy_from_slice(&derived_guid(epoch, 0));

    // A used entry has a non-zero partition type GUID (first 16 bytes);
    // its unique GUID lives in the next 16.
    for i in 0..num_entries {
        let e = array_start + i * entry_size;
        if img[e..e + 16].iter().any(|&b| b != 0) {
            img[e + 16..e + 32].copy_from_slice(&derived_guid(epoch, 1 + i as u8));
        }
    }

    let array_crc = crc32(&img[array_start..array_start + array_len]);
    img[hdr_start + ARRAY_CRC_OFF..hdr_start + ARRAY_CRC_OFF + 4]
        .copy_from_slice(&array_crc.to_le_bytes());

    img[hdr_start + HDR_CRC_OFF..hdr_start + HDR_CRC_OFF + 4].copy_from_slice(&[0; 4]);
    let hdr_crc = crc32(&img[hdr_start..hdr_start + hdr_size]);
    img[hdr_start + HDR_CRC_OFF..hdr_start + HDR_CRC_OFF + 4]
        .copy_from_slice(&hdr_crc.to_le_bytes());

    Ok(())
}

/// Normalize the primary GPT (LBA 1) and the backup GPT it points to.
pub fn normalize_gpt(img: &mut [u8], epoch: u64) -> Result<(), String> {
    if img.len() < 3 * SECTOR {
        return Err("image too small to hold a GPT".into());
    }
    let backup_lba = read_u64(img, SECTOR + BACKUP_LBA_OFF);
    normalize_header(img, 1, epoch)?;
    normalize_header(img, backup_lba, epoch)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid GPT image: protective MBR (LBA 0, zeros),
    /// primary header (LBA 1), 4-entry array (LBA 2), backup array
    /// (LBA 4) and backup header (LBA 5). One used partition entry whose
    /// unique GUID is caller-chosen (stands in for bootloader's random one).
    fn synthetic_image(random_guid: [u8; 16]) -> Vec<u8> {
        let mut img = vec![0u8; 6 * SECTOR];
        let entry_size = 128usize;
        let num_entries = 4u32;

        let mut entry = vec![0u8; entry_size];
        entry[..16].copy_from_slice(&[0xEFu8; 16]); // non-zero type GUID
        entry[16..32].copy_from_slice(&random_guid);
        img[2 * SECTOR..2 * SECTOR + entry_size].copy_from_slice(&entry);
        img[4 * SECTOR..4 * SECTOR + entry_size].copy_from_slice(&entry);

        for (hdr_lba, my_lba, other_lba, array_lba) in [(1u64, 1u64, 5u64, 2u64), (5, 5, 1, 4)] {
            let h = hdr_lba as usize * SECTOR;
            img[h..h + 8].copy_from_slice(GPT_SIGNATURE);
            img[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // rev 1.0
            img[h + HDR_SIZE_OFF..h + HDR_SIZE_OFF + 4].copy_from_slice(&92u32.to_le_bytes());
            img[h + 24..h + 32].copy_from_slice(&my_lba.to_le_bytes());
            img[h + BACKUP_LBA_OFF..h + BACKUP_LBA_OFF + 8]
                .copy_from_slice(&other_lba.to_le_bytes());
            img[h + ARRAY_LBA_OFF..h + ARRAY_LBA_OFF + 8]
                .copy_from_slice(&array_lba.to_le_bytes());
            img[h + ARRAY_NUM_OFF..h + ARRAY_NUM_OFF + 4]
                .copy_from_slice(&num_entries.to_le_bytes());
            img[h + ARRAY_ENTRY_SIZE_OFF..h + ARRAY_ENTRY_SIZE_OFF + 4]
                .copy_from_slice(&(entry_size as u32).to_le_bytes());
        }
        img
    }

    const EPOCH: u64 = 1_767_225_600; // build-iso.sh fallback epoch

    #[test]
    fn two_images_with_different_random_guids_converge() {
        let mut a = synthetic_image([0x11; 16]);
        let mut b = synthetic_image([0x22; 16]);
        assert_ne!(a, b);
        normalize_gpt(&mut a, EPOCH).unwrap();
        normalize_gpt(&mut b, EPOCH).unwrap();
        assert_eq!(a, b, "normalized images must be byte-identical");
    }

    #[test]
    fn normalization_is_idempotent() {
        let mut img = synthetic_image([0x33; 16]);
        normalize_gpt(&mut img, EPOCH).unwrap();
        let once = img.clone();
        normalize_gpt(&mut img, EPOCH).unwrap();
        assert_eq!(img, once);
    }

    #[test]
    fn crc_fields_are_valid_after_normalization() {
        let mut img = synthetic_image([0x44; 16]);
        normalize_gpt(&mut img, EPOCH).unwrap();
        for hdr_lba in [1usize, 5] {
            let h = hdr_lba * SECTOR;
            let hdr_size = read_u32(&img, h + HDR_SIZE_OFF) as usize;
            let stored_hdr_crc = read_u32(&img, h + HDR_CRC_OFF);
            let mut hdr = img[h..h + hdr_size].to_vec();
            hdr[HDR_CRC_OFF..HDR_CRC_OFF + 4].copy_from_slice(&[0; 4]);
            assert_eq!(stored_hdr_crc, crc32(&hdr), "header CRC at LBA {hdr_lba}");

            let array_lba = read_u64(&img, h + ARRAY_LBA_OFF) as usize;
            let n = read_u32(&img, h + ARRAY_NUM_OFF) as usize;
            let sz = read_u32(&img, h + ARRAY_ENTRY_SIZE_OFF) as usize;
            let stored_array_crc = read_u32(&img, h + ARRAY_CRC_OFF);
            let array = &img[array_lba * SECTOR..array_lba * SECTOR + n * sz];
            assert_eq!(stored_array_crc, crc32(array), "array CRC at LBA {hdr_lba}");
        }
    }

    #[test]
    fn different_epochs_yield_different_guids() {
        let mut a = synthetic_image([0x55; 16]);
        let mut b = synthetic_image([0x55; 16]);
        normalize_gpt(&mut a, EPOCH).unwrap();
        normalize_gpt(&mut b, EPOCH + 1).unwrap();
        assert_ne!(
            a[SECTOR + DISK_GUID_OFF..SECTOR + DISK_GUID_OFF + 16],
            b[SECTOR + DISK_GUID_OFF..SECTOR + DISK_GUID_OFF + 16]
        );
    }

    #[test]
    fn empty_entries_keep_zero_guids() {
        let mut img = synthetic_image([0x66; 16]);
        normalize_gpt(&mut img, EPOCH).unwrap();
        // Entries 1..3 have an all-zero type GUID and must stay untouched.
        let e1 = 2 * SECTOR + 128;
        assert!(img[e1..e1 + 128].iter().all(|&b| b == 0));
    }

    #[test]
    fn missing_signature_is_rejected() {
        let mut img = vec![0u8; 6 * SECTOR];
        assert!(normalize_gpt(&mut img, EPOCH).is_err());
    }

    #[test]
    fn known_crc32_vector() {
        // Standard test vector: CRC-32("123456789") = 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}

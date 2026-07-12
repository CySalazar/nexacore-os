//! Install partition plan: size and 1-MiB-align the ESP + NCFS root (WS11-03.2).

use alloc::{string::ToString, vec, vec::Vec};

use crate::gpt::{FIRST_USABLE_LBA, GptLayout, Guid, Partition};

/// 1-MiB alignment expressed in 512-byte sectors.
pub const ALIGN_SECTORS: u64 = 2048;

/// The default EFI System Partition size (512 MiB).
pub const DEFAULT_ESP_BYTES: u64 = 512 * 1024 * 1024;

/// Why a plan could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// The disk is too small to hold the ESP plus a non-empty root partition.
    DiskTooSmall,
}

/// The unique per-install GUIDs the installer assigns (from its RNG seam).
#[derive(Debug, Clone, Copy)]
pub struct InstallGuids {
    /// The disk GUID.
    pub disk: Guid,
    /// The ESP's unique partition GUID.
    pub esp: Guid,
    /// The root partition's unique GUID.
    pub root: Guid,
}

/// Round `value` up to the next multiple of `align`.
pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

/// Plan the ESP + NCFS root partitions for a disk of `disk_sectors` 512-byte
/// sectors, with an ESP of `esp_bytes`.
///
/// The ESP starts at the first 1-MiB boundary and the root fills the remaining
/// usable space; both start LBAs are 1-MiB aligned.
///
/// # Errors
/// [`PlanError::DiskTooSmall`] if no non-empty root partition fits.
pub fn plan_partitions(
    disk_sectors: u64,
    esp_bytes: u64,
    guids: &InstallGuids,
) -> Result<Vec<Partition>, PlanError> {
    let esp_sectors = align_up(esp_bytes.div_ceil(512), ALIGN_SECTORS);
    let esp_first = align_up(FIRST_USABLE_LBA, ALIGN_SECTORS);
    let esp_last = esp_first + esp_sectors - 1;

    let root_first = align_up(esp_last + 1, ALIGN_SECTORS);
    let last_usable = disk_sectors.saturating_sub(FIRST_USABLE_LBA);
    if root_first >= last_usable {
        return Err(PlanError::DiskTooSmall);
    }

    Ok(vec![
        Partition {
            type_guid: Guid::EFI_SYSTEM,
            unique_guid: guids.esp,
            first_lba: esp_first,
            last_lba: esp_last,
            attributes: 0,
            name: "EFI System".to_string(),
        },
        Partition {
            type_guid: Guid::NEXACORE_ROOT,
            unique_guid: guids.root,
            first_lba: root_first,
            last_lba: last_usable,
            attributes: 0,
            name: "NexaCore Root".to_string(),
        },
    ])
}

/// Build the full [`GptLayout`] for an install to a disk of `disk_sectors`
/// sectors, using the default ESP size.
///
/// # Errors
/// [`PlanError::DiskTooSmall`] if the disk cannot hold the layout.
pub fn build_layout(disk_sectors: u64, guids: &InstallGuids) -> Result<GptLayout, PlanError> {
    let partitions = plan_partitions(disk_sectors, DEFAULT_ESP_BYTES, guids)?;
    Ok(GptLayout::new(disk_sectors, guids.disk, partitions))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guids() -> InstallGuids {
        InstallGuids {
            disk: Guid::from_fields(1, 0, 0, [0; 8]),
            esp: Guid::from_fields(2, 0, 0, [0; 8]),
            root: Guid::from_fields(3, 0, 0, [0; 8]),
        }
    }

    #[test]
    fn plan_is_aligned_and_ordered() {
        // 16 GiB disk.
        let parts =
            plan_partitions(16 * 1024 * 1024 * 1024 / 512, DEFAULT_ESP_BYTES, &guids()).unwrap();
        assert_eq!(parts.len(), 2);
        let esp = &parts[0];
        let root = &parts[1];
        // ESP: 512 MiB starting at the first 1-MiB boundary.
        assert_eq!(esp.first_lba, ALIGN_SECTORS);
        assert_eq!(esp.last_lba - esp.first_lba + 1, DEFAULT_ESP_BYTES / 512);
        // Both start LBAs are 1-MiB aligned and non-overlapping in order.
        assert_eq!(esp.first_lba % ALIGN_SECTORS, 0);
        assert_eq!(root.first_lba % ALIGN_SECTORS, 0);
        assert!(root.first_lba > esp.last_lba);
        assert_eq!(esp.type_guid, Guid::EFI_SYSTEM);
        assert_eq!(root.type_guid, Guid::NEXACORE_ROOT);
    }

    #[test]
    fn tiny_disk_is_rejected() {
        // A disk smaller than the ESP leaves no room for root.
        assert_eq!(
            plan_partitions(1024, DEFAULT_ESP_BYTES, &guids()),
            Err(PlanError::DiskTooSmall)
        );
    }

    #[test]
    fn build_layout_produces_valid_headers() {
        let disk_sectors = 32 * 1024 * 1024 * 1024 / 512; // 32 GiB
        let gpt = build_layout(disk_sectors, &guids()).unwrap();
        let header = gpt.header(false);
        assert_eq!(&header[0..8], b"EFI PART");
        // The entry-array CRC in the header matches the array (end-to-end).
        let stored = u32::from_le_bytes(header[88..92].try_into().unwrap());
        assert_eq!(stored, gpt.entry_array_crc());
    }
}

//! Live USB image layout model: ESP (FAT) + read-only squashfs root (WS11-01.1).
//!
//! A live image is a self-booting USB stick: a GPT with a FAT EFI System
//! Partition holding the removable-media default loader (`\EFI\BOOT\BOOTX64.EFI`)
//! and a read-only squashfs partition holding the compressed root tree. This
//! module is the pure planning/descriptor half: it sizes and 1-MiB-aligns each
//! region, computes their 512-byte LBA offsets/lengths, and derives the total
//! image size (front + back GPT metadata included). Building the actual squashfs
//! and initramfs, and stamping the GPT, are other sub-tasks.

use alloc::string::String;

use crate::{
    gpt::{FIRST_USABLE_LBA, SECTOR_SIZE},
    plan::{ALIGN_SECTORS, align_up},
};

/// Bytes per 512-byte logical sector (mirrors [`gpt::SECTOR_SIZE`](crate::gpt::SECTOR_SIZE)).
pub const SECTOR_BYTES: u64 = SECTOR_SIZE as u64;

/// Minimum ESP payload for a bootable FAT ESP (loader + FAT metadata): 1 MiB.
pub const MIN_ESP_BYTES: u64 = 1024 * 1024;

/// Why a live-image layout could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveImageError {
    /// The ESP payload is smaller than [`MIN_ESP_BYTES`] (no bootable FAT fits).
    EspTooSmall,
    /// The squashfs root image is empty.
    RootTooSmall,
    /// The loader path is empty or not an absolute EFI path (must start `\`).
    InvalidLoaderPath,
    /// The boot-entry description is empty.
    InvalidBootEntry,
}

/// What the ESP (FAT) region boots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspContents {
    /// The removable-media default loader path, e.g. `\EFI\BOOT\BOOTX64.EFI`.
    pub loader_path: String,
    /// The firmware boot-menu description for the live entry.
    pub boot_entry: String,
}

/// The source tree captured into the read-only squashfs root image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashfsSource {
    /// A label/identifier for the source root tree (e.g. `nexacore-live`).
    pub source_root: String,
}

/// Inputs to [`build_live_layout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveImageInputs {
    /// The ESP payload size in bytes (bootloader + config); aligned up to 1 MiB.
    pub esp_bytes: u64,
    /// The squashfs root-image size in bytes; aligned up to 1 MiB.
    pub squashfs_bytes: u64,
    /// What the ESP boots.
    pub esp: EspContents,
    /// The source tree captured in the squashfs root.
    pub source: SquashfsSource,
}

/// A contiguous, 1-MiB-aligned region of the live image, in 512-byte LBAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageRegion {
    /// First LBA (inclusive), 1-MiB aligned.
    pub first_lba: u64,
    /// Length in 512-byte sectors (a multiple of [`ALIGN_SECTORS`]).
    pub sector_count: u64,
}

impl ImageRegion {
    /// Last LBA (inclusive).
    #[must_use]
    pub fn last_lba(&self) -> u64 {
        self.first_lba + self.sector_count - 1
    }

    /// The region size in bytes.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.sector_count * SECTOR_BYTES
    }
}

/// The computed layout of a live USB image: a 1-MiB-aligned ESP (FAT) region and
/// a read-only squashfs root region, plus the total image size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveImageLayout {
    /// The ESP (FAT) region.
    pub esp: ImageRegion,
    /// What the ESP boots (loader path + boot entry).
    pub esp_contents: EspContents,
    /// The read-only squashfs root region.
    pub root: ImageRegion,
    /// The squashfs source descriptor.
    pub source: SquashfsSource,
    /// Total image size in 512-byte sectors (front + back GPT metadata included).
    pub total_sectors: u64,
}

impl LiveImageLayout {
    /// Total image size in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_sectors * SECTOR_BYTES
    }
}

/// Size, 1-MiB-align, and lay out the ESP + squashfs root of a live image.
///
/// The ESP starts at the first 1-MiB boundary after the primary GPT metadata;
/// the squashfs root follows on the next 1-MiB boundary. The total image size
/// leaves room for the backup GPT metadata and is itself 1-MiB aligned.
///
/// # Errors
/// Fails closed on bad inputs: [`LiveImageError::EspTooSmall`],
/// [`LiveImageError::RootTooSmall`], [`LiveImageError::InvalidLoaderPath`], or
/// [`LiveImageError::InvalidBootEntry`].
pub fn build_live_layout(inputs: &LiveImageInputs) -> Result<LiveImageLayout, LiveImageError> {
    // Validate the ESP contents descriptor.
    let loader = inputs.esp.loader_path.trim();
    if loader.is_empty() || !loader.starts_with('\\') {
        return Err(LiveImageError::InvalidLoaderPath);
    }
    if inputs.esp.boot_entry.trim().is_empty() {
        return Err(LiveImageError::InvalidBootEntry);
    }

    // Validate sizes, failing closed.
    if inputs.esp_bytes < MIN_ESP_BYTES {
        return Err(LiveImageError::EspTooSmall);
    }
    if inputs.squashfs_bytes == 0 {
        return Err(LiveImageError::RootTooSmall);
    }

    // ESP region: the first 1-MiB boundary at/after the primary GPT metadata.
    let esp_first = align_up(FIRST_USABLE_LBA, ALIGN_SECTORS);
    let esp_sectors = align_up(inputs.esp_bytes.div_ceil(SECTOR_BYTES), ALIGN_SECTORS);
    let esp = ImageRegion {
        first_lba: esp_first,
        sector_count: esp_sectors,
    };

    // Root region: the next 1-MiB boundary right after the ESP.
    let root_first = align_up(esp.last_lba() + 1, ALIGN_SECTORS);
    let root_sectors = align_up(inputs.squashfs_bytes.div_ceil(SECTOR_BYTES), ALIGN_SECTORS);
    let root = ImageRegion {
        first_lba: root_first,
        sector_count: root_sectors,
    };

    // Total image: root end + room for the backup GPT metadata (mirror of the
    // front reservation), rounded up to a whole number of 1-MiB units.
    let total_sectors = align_up(root.last_lba() + 1 + FIRST_USABLE_LBA, ALIGN_SECTORS);

    Ok(LiveImageLayout {
        esp,
        esp_contents: inputs.esp.clone(),
        root,
        source: inputs.source.clone(),
        total_sectors,
    })
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn inputs() -> LiveImageInputs {
        LiveImageInputs {
            esp_bytes: 64 * 1024 * 1024,       // 64 MiB
            squashfs_bytes: 800 * 1024 * 1024, // 800 MiB
            esp: EspContents {
                loader_path: "\\EFI\\BOOT\\BOOTX64.EFI".to_string(),
                boot_entry: "NexaCore OS (Live)".to_string(),
            },
            source: SquashfsSource {
                source_root: "nexacore-live".to_string(),
            },
        }
    }

    #[test]
    fn representative_layout_has_expected_offsets_and_sizes() {
        let layout = build_live_layout(&inputs()).unwrap();
        // ESP: 64 MiB starting at the first 1-MiB boundary (LBA 2048).
        assert_eq!(layout.esp.first_lba, 2048);
        assert_eq!(layout.esp.sector_count, 131_072); // 64 MiB / 512
        assert_eq!(layout.esp.last_lba(), 133_119);
        assert_eq!(layout.esp.byte_len(), 64 * 1024 * 1024);
        // Root: 800 MiB on the next 1-MiB boundary right after the ESP.
        assert_eq!(layout.root.first_lba, 133_120);
        assert_eq!(layout.root.sector_count, 1_638_400); // 800 MiB / 512
        assert_eq!(layout.root.last_lba(), 1_771_519);
        // Total: root end + backup GPT metadata, 1-MiB aligned.
        assert_eq!(layout.total_sectors, 1_773_568);
        assert_eq!(layout.total_bytes(), 1_773_568 * 512);
        // Descriptors carried through unchanged.
        assert_eq!(layout.esp_contents, inputs().esp);
        assert_eq!(layout.source, inputs().source);
    }

    #[test]
    fn alignment_invariants_hold() {
        let layout = build_live_layout(&inputs()).unwrap();
        for region in [layout.esp, layout.root] {
            assert_eq!(region.first_lba % ALIGN_SECTORS, 0, "region 1-MiB aligned");
            assert_eq!(region.sector_count % ALIGN_SECTORS, 0, "size 1-MiB aligned");
        }
        // Regions are ordered and non-overlapping.
        assert!(layout.root.first_lba > layout.esp.last_lba());
        // The whole image is 1-MiB aligned and holds every region plus a tail.
        assert_eq!(layout.total_sectors % ALIGN_SECTORS, 0);
        assert!(layout.total_sectors > layout.root.last_lba() + FIRST_USABLE_LBA);
    }

    #[test]
    fn odd_sizes_round_up_to_the_next_mib() {
        let mut i = inputs();
        i.esp_bytes = MIN_ESP_BYTES + 1; // just over 1 MiB
        i.squashfs_bytes = 3 * 1024 * 1024 + 7; // just over 3 MiB
        let layout = build_live_layout(&i).unwrap();
        assert_eq!(layout.esp.sector_count, 2 * ALIGN_SECTORS); // rounds to 2 MiB
        assert_eq!(layout.root.sector_count, 4 * ALIGN_SECTORS); // rounds to 4 MiB
    }

    #[test]
    fn tiny_esp_is_rejected() {
        let mut i = inputs();
        i.esp_bytes = MIN_ESP_BYTES - 1;
        assert_eq!(build_live_layout(&i), Err(LiveImageError::EspTooSmall));
    }

    #[test]
    fn empty_root_is_rejected() {
        let mut i = inputs();
        i.squashfs_bytes = 0;
        assert_eq!(build_live_layout(&i), Err(LiveImageError::RootTooSmall));
    }

    #[test]
    fn non_absolute_loader_path_is_rejected() {
        let mut i = inputs();
        i.esp.loader_path = "EFI/BOOT/BOOTX64.EFI".to_string();
        assert_eq!(
            build_live_layout(&i),
            Err(LiveImageError::InvalidLoaderPath)
        );

        let mut empty = inputs();
        empty.esp.loader_path = String::new();
        assert_eq!(
            build_live_layout(&empty),
            Err(LiveImageError::InvalidLoaderPath)
        );
    }

    #[test]
    fn empty_boot_entry_is_rejected() {
        let mut i = inputs();
        i.esp.boot_entry = "   ".to_string();
        assert_eq!(build_live_layout(&i), Err(LiveImageError::InvalidBootEntry));
    }
}

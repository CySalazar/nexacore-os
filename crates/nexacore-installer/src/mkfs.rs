//! Create the NCFS root filesystem on the root partition (WS11-03.4).
//!
//! Once the GPT ([`crate::gpt`]) and the partition plan ([`crate::plan`]) have
//! sized and placed the NexaCore-root partition, that partition's storage is
//! handed to this module as a [`BlockDevice`] and formatted with a fresh NCFS
//! v3 volume via [`nexacore_fs::v3::mkfs::format`] (`mkfs.ncfs`).
//!
//! The block device is the seam: the pure NCFS formatter runs against any
//! [`BlockDevice`] (an in-memory device in host tests, the driver-backed
//! partition device on real hardware), so this step is fully host-testable.
//! Formatting failures are mapped fail-closed into [`MkfsError`] so a partially
//! formatted volume is never reported as a success.

pub use nexacore_fs::v3::mkfs::VolumeKeys;
use nexacore_fs::v3::{V3Error, blockdev::BlockDevice, mkfs::format, superblock::SuperblockV3};

/// Why the root filesystem could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkfsError {
    /// The NCFS v3 formatter rejected the device or a backing write failed.
    Format(V3Error),
}

impl core::fmt::Display for MkfsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format(e) => write!(f, "mkfs.ncfs failed: {e}"),
        }
    }
}

impl core::error::Error for MkfsError {}

/// Create an NCFS v3 filesystem on the root partition's block `dev`, binding it
/// to `keys`, and return the committed superblock.
///
/// The volume is left mountable: after this returns [`Ok`],
/// [`nexacore_fs::v3::superblock::mount`] succeeds for the same MAC key.
///
/// # Errors
/// [`MkfsError::Format`] if the device is too small or a backing-store write
/// fails; on any error the volume must be treated as not created (fail-closed).
pub fn create_root_filesystem<D: BlockDevice>(
    dev: &mut D,
    keys: &VolumeKeys,
) -> Result<SuperblockV3, MkfsError> {
    format(dev, keys).map_err(MkfsError::Format)
}

#[cfg(test)]
mod tests {
    use nexacore_fs::v3::{
        blockdev::MemBlockDevice,
        merkle::MerkleKey,
        superblock::{MacKey, mount},
    };

    use super::*;
    use crate::{
        gpt::Guid,
        plan::{DEFAULT_ESP_BYTES, InstallGuids, plan_partitions},
    };

    const MAC_KEY: MacKey = [0x11; 32];
    const MERKLE_KEY: MerkleKey = [0x22; 32];

    fn keys() -> VolumeKeys {
        VolumeKeys {
            mac: MAC_KEY,
            merkle: MERKLE_KEY,
        }
    }

    fn guids() -> InstallGuids {
        InstallGuids {
            disk: Guid::from_fields(1, 0, 0, [0; 8]),
            esp: Guid::from_fields(2, 0, 0, [0; 8]),
            root: Guid::from_fields(3, 0, 0, [0; 8]),
        }
    }

    /// A `MemBlockDevice` sized to the root partition the installer plans for a
    /// modest disk (512 MiB ESP + a ~31 MiB root), converting 512-byte GPT
    /// sectors to 4096-byte NCFS blocks.
    fn root_partition_device() -> MemBlockDevice {
        // 544 MiB disk: large enough for the 512 MiB ESP plus a small root.
        let disk_sectors = 544 * 1024 * 1024 / 512;
        let parts = plan_partitions(disk_sectors, DEFAULT_ESP_BYTES, &guids()).unwrap();
        let root = &parts[1];
        let root_sectors = root.last_lba - root.first_lba + 1;
        // 4096-byte NCFS blocks over 512-byte GPT sectors.
        let block_count = root_sectors / 8;
        MemBlockDevice::new(block_count)
    }

    #[test]
    fn formats_planned_root_partition_into_mountable_volume() {
        let mut dev = root_partition_device();
        let expected_blocks = dev.block_count();

        let sb = create_root_filesystem(&mut dev, &keys()).unwrap();

        // A valid, first-generation v3 superblock spanning the whole partition.
        assert_eq!(sb.generation, 1);
        assert_eq!(sb.total_blocks, expected_blocks);
        assert!(sb.root_dir_inode != 0);

        // The volume re-reads (mounts) cleanly and matches what was committed.
        let mounted = mount(&dev, &keys().mac).unwrap();
        assert_eq!(mounted, sb);
    }

    #[test]
    fn too_small_device_is_reported_fail_closed() {
        // A device below the NCFS minimum must not report success.
        let mut dev = MemBlockDevice::new(1);
        let err = create_root_filesystem(&mut dev, &keys()).unwrap_err();
        assert_eq!(err, MkfsError::Format(V3Error::BlockOutOfRange));
    }
}

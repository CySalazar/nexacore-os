//! Disk-geometry model and enumeration seam (WS11-03.1).

use alloc::{string::String, vec::Vec};

/// The bus a disk is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskBus {
    /// NVMe.
    Nvme,
    /// SATA / AHCI.
    Sata,
    /// USB mass storage.
    Usb,
    /// virtio-blk.
    Virtio,
    /// Anything else.
    Other,
}

/// A block device the installer can target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskInfo {
    /// Kernel device name (e.g. `nvme0n1`).
    pub name: String,
    /// Model string, if known.
    pub model: String,
    /// The bus the disk is on.
    pub bus: DiskBus,
    /// Logical sector size in bytes (512 or 4096).
    pub sector_size: u32,
    /// Total logical sectors.
    pub sector_count: u64,
    /// Whether the medium is removable.
    pub removable: bool,
}

impl DiskInfo {
    /// The disk capacity in bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        u64::from(self.sector_size) * self.sector_count
    }

    /// Whether the disk has at least `min_bytes` of capacity.
    #[must_use]
    pub fn fits(&self, min_bytes: u64) -> bool {
        self.capacity_bytes() >= min_bytes
    }
}

/// The disk-enumeration seam. The production implementation probes NVMe/SATA
/// (WS2-07) drivers; a test double lists a fixed set.
pub trait DiskEnumerator {
    /// All disks currently visible to the installer.
    fn list(&self) -> Vec<DiskInfo>;

    /// Disks with at least `min_bytes` of capacity — the installable set.
    fn installable(&self, min_bytes: u64) -> Vec<DiskInfo> {
        self.list()
            .into_iter()
            .filter(|d| d.fits(min_bytes))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use super::*;

    struct FixedDisks(Vec<DiskInfo>);
    impl DiskEnumerator for FixedDisks {
        fn list(&self) -> Vec<DiskInfo> {
            self.0.clone()
        }
    }

    fn disk(name: &str, bus: DiskBus, sectors: u64, removable: bool) -> DiskInfo {
        DiskInfo {
            name: name.to_string(),
            model: "test".to_string(),
            bus,
            sector_size: 512,
            sector_count: sectors,
            removable,
        }
    }

    #[test]
    fn capacity_and_fit() {
        let d = disk("nvme0n1", DiskBus::Nvme, 2_097_152, false);
        assert_eq!(d.capacity_bytes(), 1024 * 1024 * 1024);
        assert!(d.fits(1_000_000_000));
        assert!(!d.fits(2_000_000_000));
    }

    #[test]
    fn installable_filters_by_size() {
        let en = FixedDisks(vec![
            disk("nvme0n1", DiskBus::Nvme, 2_097_152, false), // 1 GiB
            disk("sdb", DiskBus::Usb, 4096, true),            // 2 MiB — too small
        ]);
        let installable = en.installable(1024 * 1024 * 1024);
        assert_eq!(installable.len(), 1);
        assert_eq!(installable[0].name, "nvme0n1");
    }
}

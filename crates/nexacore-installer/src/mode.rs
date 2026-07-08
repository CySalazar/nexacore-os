//! Install mode: dual-boot preservation vs whole-disk replace (WS11-04.2/.3/.4).

use alloc::{string::String, vec, vec::Vec};

use crate::gpt::{ENTRY_SECTORS, FIRST_USABLE_LBA};

/// How the installer treats the target disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    /// Keep existing OS boot entries and add NexaCore alongside them.
    DualBoot,
    /// Wipe the disk (fresh GPT) and install NexaCore only.
    ReplaceDisk,
}

/// An existing OS boot entry discovered on the disk (from WS11-04.1 detection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingBootEntry {
    /// The firmware `Boot####` index.
    pub index: u16,
    /// The entry's description.
    pub description: String,
}

/// The `BootOrder` after installing NexaCore at `nexacore_index`.
///
/// [`InstallMode::DualBoot`] puts NexaCore first, then preserves the existing
/// entries in order. [`InstallMode::ReplaceDisk`] keeps only NexaCore (the old
/// entries are wiped with the disk).
#[must_use]
pub fn merged_boot_order(
    mode: InstallMode,
    nexacore_index: u16,
    existing: &[ExistingBootEntry],
) -> Vec<u16> {
    let mut order = vec![nexacore_index];
    if mode == InstallMode::DualBoot {
        for entry in existing {
            if entry.index != nexacore_index {
                order.push(entry.index);
            }
        }
    }
    order
}

/// The LBA regions to zero to wipe an existing GPT before a fresh
/// [`InstallMode::ReplaceDisk`] install: the primary metadata at the front and
/// the backup metadata at the back.
#[must_use]
pub fn gpt_wipe_regions(disk_sectors: u64) -> [(u64, u64); 2] {
    // Primary: protective MBR + header + entry array (LBA 0..FIRST_USABLE_LBA).
    let primary = (0u64, FIRST_USABLE_LBA);
    // Backup: entry array + header (the last ENTRY_SECTORS + 1 sectors).
    let backup_len = ENTRY_SECTORS + 1;
    let backup_start = disk_sectors.saturating_sub(backup_len);
    [primary, (backup_start, backup_len)]
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn existing() -> Vec<ExistingBootEntry> {
        vec![
            ExistingBootEntry {
                index: 1,
                description: "Windows Boot Manager".to_string(),
            },
            ExistingBootEntry {
                index: 3,
                description: "ubuntu".to_string(),
            },
        ]
    }

    #[test]
    fn dual_boot_preserves_existing_entries() {
        let order = merged_boot_order(InstallMode::DualBoot, 5, &existing());
        assert_eq!(order, [5, 1, 3], "NexaCore first, then existing preserved");
    }

    #[test]
    fn replace_keeps_only_nexacore() {
        let order = merged_boot_order(InstallMode::ReplaceDisk, 5, &existing());
        assert_eq!(order, [5]);
    }

    #[test]
    fn dual_boot_dedupes_a_reused_index() {
        // If NexaCore reuses an existing index, it is not duplicated.
        let order = merged_boot_order(InstallMode::DualBoot, 1, &existing());
        assert_eq!(order, [1, 3]);
    }

    #[test]
    fn gpt_wipe_covers_primary_and_backup() {
        let [primary, backup] = gpt_wipe_regions(2_097_152);
        assert_eq!(primary, (0, FIRST_USABLE_LBA)); // 0..34
        assert_eq!(backup, (2_097_152 - (ENTRY_SECTORS + 1), ENTRY_SECTORS + 1)); // last 33
    }
}

//! Detect existing OS boot loaders in an ESP (WS11-04.1).
//!
//! Reads a FAT-formatted EFI System Partition with the [`nexacore_fatfs`] reader
//! and enumerates the loaders under `\EFI\<vendor>\*.efi`, classifying each by
//! its vendor directory. The installer uses this to offer dual-boot
//! preservation (WS11-04.2) instead of silently overwriting another OS.

use alloc::{string::String, vec::Vec};

use nexacore_fatfs::{FatError, FatFs};

/// A recognised operating system, inferred from an ESP vendor directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownOs {
    /// Windows (`\EFI\Microsoft`).
    Windows,
    /// A Linux distribution (`\EFI\ubuntu`, `\EFI\fedora`, …).
    Linux,
    /// The removable-media fallback (`\EFI\BOOT\BOOTX64.EFI`).
    RemovableFallback,
    /// An unrecognised vendor.
    Unknown,
}

impl KnownOs {
    /// Classify an ESP vendor directory name (case-insensitive).
    #[must_use]
    pub fn for_vendor(vendor: &str) -> Self {
        let v = vendor.to_ascii_lowercase();
        if v == "microsoft" {
            Self::Windows
        } else if matches!(
            v.as_str(),
            "ubuntu" | "debian" | "fedora" | "centos" | "redhat" | "grub" | "systemd" | "opensuse"
        ) {
            Self::Linux
        } else if v == "boot" {
            Self::RemovableFallback
        } else {
            Self::Unknown
        }
    }
}

/// An EFI loader discovered in the ESP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingLoader {
    /// The vendor directory (e.g. `Microsoft`, `ubuntu`, `BOOT`).
    pub vendor: String,
    /// The loader file name (e.g. `bootmgfw.efi`).
    pub file: String,
    /// The OS inferred from the vendor.
    pub os: KnownOs,
}

/// Why detection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectError {
    /// The FAT reader failed.
    Fat(FatError),
    /// The volume has no `\EFI` directory (not an ESP).
    NoEfiDir,
}

fn ends_with_efi(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".efi")
}

/// Enumerate the EFI loaders under `\EFI\<vendor>\*.efi` in an opened ESP.
///
/// # Errors
/// [`DetectError::NoEfiDir`] if there is no `\EFI` directory, or
/// [`DetectError::Fat`] on a read error.
pub fn detect_loaders(fs: &FatFs) -> Result<Vec<ExistingLoader>, DetectError> {
    let root = fs.root().map_err(DetectError::Fat)?;
    let efi = root
        .iter()
        .find(|e| e.is_dir && e.name.eq_ignore_ascii_case("EFI"))
        .ok_or(DetectError::NoEfiDir)?;
    let vendors = fs.read_dir(efi).map_err(DetectError::Fat)?;
    let mut loaders = Vec::new();
    for vendor in &vendors {
        if !vendor.is_dir || vendor.name == "." || vendor.name == ".." {
            continue;
        }
        let files = fs.read_dir(vendor).map_err(DetectError::Fat)?;
        for file in files {
            if !file.is_dir && ends_with_efi(&file.name) {
                loaders.push(ExistingLoader {
                    vendor: vendor.name.clone(),
                    file: file.name.clone(),
                    os: KnownOs::for_vendor(&vendor.name),
                });
            }
        }
    }
    Ok(loaders)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    const SECTOR: usize = 512;

    fn put16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
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
    fn entry(buf: &mut [u8], off: usize, name: &[u8; 11], attr: u8, cluster: u16, size: u32) {
        buf[off..off + 11].copy_from_slice(name);
        buf[off + 11] = attr;
        put16(buf, off + 26, cluster);
        put32(buf, off + 28, size);
    }

    /// Build a FAT12 ESP with `\EFI\BOOT\BOOTX64.EFI`.
    fn build_esp() -> Vec<u8> {
        // 6 sectors: 0 boot, 1 FAT, 2 root, 3 c2(EFI dir), 4 c3(BOOT dir),
        // 5 c4(loader data).
        let mut img = vec![0u8; SECTOR * 6];
        put16(&mut img, 11, 512); // bytes/sector
        img[13] = 1; // sectors/cluster
        put16(&mut img, 14, 1); // reserved
        img[16] = 1; // num fats
        put16(&mut img, 17, 16); // root entries
        put16(&mut img, 19, 6); // total sectors
        put16(&mut img, 22, 1); // fat size
        put16(&mut img, 510, 0xAA55);

        let fat = SECTOR;
        put_fat12(&mut img, fat, 0, 0x0FF8);
        put_fat12(&mut img, fat, 1, 0x0FFF);
        put_fat12(&mut img, fat, 2, 0x0FFF); // EFI dir EOC
        put_fat12(&mut img, fat, 3, 0x0FFF); // BOOT dir EOC
        put_fat12(&mut img, fat, 4, 0x0FFF); // loader EOC

        // root: EFI directory.
        entry(&mut img, SECTOR * 2, b"EFI        ", 0x10, 2, 0);
        // c2: EFI dir = ".", "..", BOOT dir.
        let efi = SECTOR * 3;
        entry(&mut img, efi, b".          ", 0x10, 2, 0);
        entry(&mut img, efi + 32, b"..         ", 0x10, 0, 0);
        entry(&mut img, efi + 64, b"BOOT       ", 0x10, 3, 0);
        // c3: BOOT dir = ".", "..", BOOTX64.EFI.
        let boot = SECTOR * 4;
        entry(&mut img, boot, b".          ", 0x10, 3, 0);
        entry(&mut img, boot + 32, b"..         ", 0x10, 2, 0);
        entry(&mut img, boot + 64, b"BOOTX64 EFI", 0x20, 4, 8);
        // c4: loader data.
        img[SECTOR * 5..SECTOR * 5 + 8].copy_from_slice(b"loader!!");
        img
    }

    #[test]
    fn classifies_vendors() {
        assert_eq!(KnownOs::for_vendor("Microsoft"), KnownOs::Windows);
        assert_eq!(KnownOs::for_vendor("ubuntu"), KnownOs::Linux);
        assert_eq!(KnownOs::for_vendor("BOOT"), KnownOs::RemovableFallback);
        assert_eq!(KnownOs::for_vendor("weird"), KnownOs::Unknown);
    }

    #[test]
    fn detects_the_esp_loader() {
        let img = build_esp();
        let fs = FatFs::open(&img).unwrap();
        let loaders = detect_loaders(&fs).unwrap();
        assert_eq!(loaders.len(), 1);
        assert_eq!(loaders[0].vendor, "BOOT");
        assert_eq!(loaders[0].file, "BOOTX64.EFI");
        assert_eq!(loaders[0].os, KnownOs::RemovableFallback);
    }

    #[test]
    fn a_volume_without_efi_is_not_an_esp() {
        // A blank FAT (no \EFI): format an empty one via the reader's sibling
        // formatter would classify FAT16; here reuse an ESP image but drop EFI.
        let mut img = build_esp();
        // Zero the root directory so \EFI disappears.
        for b in &mut img[SECTOR * 2..SECTOR * 3] {
            *b = 0;
        }
        let fs = FatFs::open(&img).unwrap();
        assert_eq!(detect_loaders(&fs).err(), Some(DetectError::NoEfiDir));
    }
}

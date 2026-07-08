//! UEFI boot entry construction (WS11-03.7), efibootmgr-class.
//!
//! Builds the `EFI_LOAD_OPTION` and the EFI device path that a `Boot####`
//! variable holds so firmware can boot the installed loader
//! (`\EFI\NEXACORE\BOOTX64.EFI`) from the ESP. The device path is a
//! Hard-Drive media node (identifying the ESP by its GPT partition GUID) plus a
//! File-Path node plus the end node. Everything is pure bytes; writing the
//! variable through the firmware's `SetVariable`/`efivarfs` is the integration
//! step.

use alloc::{string::String, vec::Vec};

use crate::gpt::Guid;

/// `LOAD_OPTION_ACTIVE` — the entry is active/bootable.
pub const LOAD_OPTION_ACTIVE: u32 = 0x0000_0001;

/// A Hard-Drive media device-path node identifying a GPT partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardDriveNode {
    /// 1-based partition number.
    pub partition_number: u32,
    /// Partition start LBA.
    pub partition_start: u64,
    /// Partition size in sectors.
    pub partition_size: u64,
    /// The partition's unique GPT GUID (the signature).
    pub signature: Guid,
}

impl HardDriveNode {
    /// The node's 42-byte on-wire encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; 42] {
        let mut n = [0u8; 42];
        put(&mut n, 0, &[0x04, 0x01]); // type: Media, subtype: Hard Drive
        put(&mut n, 2, &42u16.to_le_bytes()); // length
        put(&mut n, 4, &self.partition_number.to_le_bytes());
        put(&mut n, 8, &self.partition_start.to_le_bytes());
        put(&mut n, 16, &self.partition_size.to_le_bytes());
        put(&mut n, 24, &self.signature.bytes());
        put(&mut n, 40, &[0x02, 0x02]); // format: GPT, signature type: GUID
        n
    }
}

/// Copy `src` into `buf` at `off` (bounds-checked, no-op if out of range).
fn put(buf: &mut [u8], off: usize, src: &[u8]) {
    if let Some(slot) = buf.get_mut(off..off + src.len()) {
        slot.copy_from_slice(src);
    }
}

/// A File-Path media node (the loader path within the ESP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePathNode {
    /// The path, e.g. `\EFI\NEXACORE\BOOTX64.EFI`.
    pub path: String,
}

impl FilePathNode {
    /// The node's on-wire encoding: header + null-terminated UTF-16LE path.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut units: Vec<u16> = self.path.encode_utf16().collect();
        units.push(0); // NUL terminator
        let body_len = units.len() * 2;
        let total = 4 + body_len;
        let mut out = Vec::with_capacity(total);
        out.push(0x04); // type: Media Device Path
        out.push(0x04); // subtype: File Path
        out.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_le_bytes());
        for unit in units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }
}

/// The device-path end node (`type 0x7F, subtype 0xFF, length 4`).
#[must_use]
pub fn end_node() -> [u8; 4] {
    [0x7F, 0xFF, 0x04, 0x00]
}

/// Build the full device path for booting `file` from the ESP `hd`.
#[must_use]
pub fn device_path(hd: &HardDriveNode, file: &FilePathNode) -> Vec<u8> {
    let mut path = Vec::new();
    path.extend_from_slice(&hd.encode());
    path.extend_from_slice(&file.encode());
    path.extend_from_slice(&end_node());
    path
}

/// A UEFI boot entry (`EFI_LOAD_OPTION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiLoadOption {
    /// Load-option attribute flags.
    pub attributes: u32,
    /// The human-readable description shown in the firmware boot menu.
    pub description: String,
    /// The boot device path.
    pub device_path: Vec<u8>,
}

impl EfiLoadOption {
    /// A boot entry for `description` that boots `file` from the ESP `hd`.
    #[must_use]
    pub fn new(description: &str, hd: &HardDriveNode, file: &FilePathNode) -> Self {
        Self {
            attributes: LOAD_OPTION_ACTIVE,
            description: String::from(description),
            device_path: device_path(hd, file),
        }
    }

    /// The `EFI_LOAD_OPTION` on-wire encoding: attributes, device-path length,
    /// null-terminated UTF-16LE description, then the device path.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.attributes.to_le_bytes());
        out.extend_from_slice(
            &u16::try_from(self.device_path.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        for unit in self.description.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]); // description NUL terminator
        out.extend_from_slice(&self.device_path);
        out
    }
}

/// The `Boot####` variable name for a 16-bit boot option `index`.
#[must_use]
pub fn boot_variable_name(index: u16) -> String {
    let mut name = String::from("Boot");
    for shift in [12, 8, 4, 0] {
        let nibble = (index >> shift) & 0xF;
        name.push(
            char::from_digit(u32::from(nibble), 16)
                .unwrap_or('0')
                .to_ascii_uppercase(),
        );
    }
    name
}

/// Encode a `BootOrder` variable from an ordered list of boot indices.
#[must_use]
pub fn boot_order(indices: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(indices.len() * 2);
    for &i in indices {
        out.extend_from_slice(&i.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hd() -> HardDriveNode {
        HardDriveNode {
            partition_number: 1,
            partition_start: 2048,
            partition_size: 1024 * 1024,
            signature: Guid::from_fields(0xAABB_CCDD, 0x1122, 0x3344, [1, 2, 3, 4, 5, 6, 7, 8]),
        }
    }

    #[test]
    fn hard_drive_node_layout() {
        let n = hd().encode();
        assert_eq!(n[0], 0x04);
        assert_eq!(n[1], 0x01);
        assert_eq!(u16::from_le_bytes([n[2], n[3]]), 42);
        assert_eq!(u32::from_le_bytes([n[4], n[5], n[6], n[7]]), 1);
        assert_eq!(n[40], 0x02); // GPT
        assert_eq!(n[41], 0x02); // GUID
    }

    #[test]
    fn file_path_node_encodes_utf16_with_nul() {
        let f = FilePathNode {
            path: "\\EFI\\NEXACORE\\BOOTX64.EFI".into(),
        };
        let enc = f.encode();
        assert_eq!(enc[0], 0x04);
        assert_eq!(enc[1], 0x04);
        let len = u16::from_le_bytes([enc[2], enc[3]]) as usize;
        assert_eq!(len, enc.len());
        // 4-byte header + (25 chars + 1 NUL) * 2 bytes.
        assert_eq!(enc.len(), 4 + 26 * 2);
    }

    #[test]
    fn load_option_round_trips_the_fields() {
        let file = FilePathNode {
            path: "\\EFI\\NEXACORE\\BOOTX64.EFI".into(),
        };
        let opt = EfiLoadOption::new("NexaCore OS", &hd(), &file);
        let enc = opt.encode();
        // Attributes.
        assert_eq!(
            u32::from_le_bytes([enc[0], enc[1], enc[2], enc[3]]),
            LOAD_OPTION_ACTIVE
        );
        // Device-path length field == actual device path length.
        let dp_len = u16::from_le_bytes([enc[4], enc[5]]) as usize;
        assert_eq!(dp_len, opt.device_path.len());
        // Description decodes back to "NexaCore OS".
        let desc_units: Vec<u16> = (0.."NexaCore OS".len())
            .map(|i| u16::from_le_bytes([enc[6 + i * 2], enc[7 + i * 2]]))
            .collect();
        let desc: String = char::decode_utf16(desc_units).map(|r| r.unwrap()).collect();
        assert_eq!(desc, "NexaCore OS");
        // The device path ends with the end node.
        assert_eq!(&opt.device_path[opt.device_path.len() - 4..], &end_node());
    }

    #[test]
    fn boot_variable_names_and_order() {
        assert_eq!(boot_variable_name(1), "Boot0001");
        assert_eq!(boot_variable_name(0x1A2B), "Boot1A2B");
        assert_eq!(boot_order(&[1, 0]), [0x01, 0x00, 0x00, 0x00]);
    }
}

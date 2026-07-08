//! HDA stream Buffer Descriptor List (WS2-10.3).
//!
//! Each HDA DMA stream is fed by a BDL: an array of 16-byte entries naming a
//! guest physical buffer, its length, and an interrupt-on-completion flag. The
//! byte layout is host-tested here; allocating the buffers via `DmaMap` and
//! programming the BDL base into the stream descriptor is rig-side.

use alloc::{vec, vec::Vec};

/// Size of one BDL entry in bytes.
pub const BDL_ENTRY_LEN: usize = 16;

/// One `Buffer Descriptor List` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BdlEntry {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Buffer length in bytes.
    pub length: u32,
    /// Raise an interrupt when this buffer completes (IOC bit).
    pub interrupt_on_completion: bool,
}

impl BdlEntry {
    /// Serialize to the 16-byte HDA BDL entry layout
    /// (`addr: u64, length: u32, flags: u32` where flags bit0 = IOC).
    #[must_use]
    pub fn to_bytes(self) -> [u8; BDL_ENTRY_LEN] {
        let mut out = Vec::with_capacity(BDL_ENTRY_LEN);
        out.extend_from_slice(&self.addr.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&u32::from(self.interrupt_on_completion).to_le_bytes());
        let mut b = [0u8; BDL_ENTRY_LEN];
        b.copy_from_slice(&out);
        b
    }
}

/// Serialize a BDL (sequence of entries) into a contiguous byte buffer ready to
/// be copied into the DMA region the stream descriptor points at.
#[must_use]
pub fn serialize_bdl(entries: &[BdlEntry]) -> Vec<u8> {
    let mut out = vec![0u8; 0];
    out.reserve(entries.len() * BDL_ENTRY_LEN);
    for e in entries {
        out.extend_from_slice(&e.to_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_layout_is_16_bytes() {
        let e = BdlEntry {
            addr: 0x1234_5678_9ABC_DEF0,
            length: 4096,
            interrupt_on_completion: true,
        };
        let b = e.to_bytes();
        assert_eq!(b.len(), BDL_ENTRY_LEN);
        assert_eq!(&b[0..8], &0x1234_5678_9ABC_DEF0u64.to_le_bytes());
        assert_eq!(&b[8..12], &4096u32.to_le_bytes());
        assert_eq!(&b[12..16], &1u32.to_le_bytes()); // IOC set
    }

    #[test]
    fn ioc_clear_is_zero_flags() {
        let e = BdlEntry {
            addr: 0,
            length: 64,
            interrupt_on_completion: false,
        };
        assert_eq!(&e.to_bytes()[12..16], &0u32.to_le_bytes());
    }

    #[test]
    fn serialize_concatenates_entries() {
        let entries = [
            BdlEntry {
                addr: 0x1000,
                length: 2048,
                interrupt_on_completion: false,
            },
            BdlEntry {
                addr: 0x2000,
                length: 2048,
                interrupt_on_completion: true,
            },
        ];
        let buf = serialize_bdl(&entries);
        assert_eq!(buf.len(), 2 * BDL_ENTRY_LEN);
        assert_eq!(&buf[0..8], &0x1000u64.to_le_bytes());
        assert_eq!(
            &buf[BDL_ENTRY_LEN..BDL_ENTRY_LEN + 8],
            &0x2000u64.to_le_bytes()
        );
    }
}

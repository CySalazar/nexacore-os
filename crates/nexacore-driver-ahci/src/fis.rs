//! Frame Information Structures (WS2-07.4).
//!
//! An ATA command is issued to a SATA device by writing a **Host-to-Device
//! Register FIS** into a command table, then setting the corresponding `PxCI`
//! bit. This module builds that 20-byte FIS exactly per *Serial ATA 3.0* §
//! 10.3.4 — the byte-layout half of command submission, host-tested here; the
//! command-table DMA + `PxCI` poke are device-side.

/// FIS type tags (first byte of every FIS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FisType {
    /// Register FIS — Host to Device.
    RegisterH2D = 0x27,
    /// Register FIS — Device to Host.
    RegisterD2H = 0x34,
    /// DMA Setup FIS — bidirectional.
    DmaSetup = 0x41,
    /// PIO Setup FIS — Device to Host.
    PioSetup = 0x5F,
    /// Set Device Bits FIS — Device to Host (NCQ completion).
    SetDeviceBits = 0xA1,
}

/// Length of a Host-to-Device Register FIS in bytes (5 dwords).
pub const H2D_FIS_LEN: usize = 20;

/// Command byte (byte 1) bit: this FIS carries a command (not a control
/// update).
pub const H2D_C_BIT: u8 = 1 << 7;

/// ATA command opcodes WS2-07 issues.
pub mod ata {
    /// `IDENTIFY DEVICE` — return the 512-byte identification block.
    pub const IDENTIFY_DEVICE: u8 = 0xEC;
    /// `READ DMA EXT` (LBA48).
    pub const READ_DMA_EXT: u8 = 0x25;
    /// `WRITE DMA EXT` (LBA48).
    pub const WRITE_DMA_EXT: u8 = 0x35;
    /// `READ FPDMA QUEUED` (NCQ).
    pub const READ_FPDMA_QUEUED: u8 = 0x60;
    /// `WRITE FPDMA QUEUED` (NCQ).
    pub const WRITE_FPDMA_QUEUED: u8 = 0x61;
}

/// Device-register bit selecting LBA mode (set for all LBA28/LBA48 commands).
pub const DEVICE_LBA_MODE: u8 = 1 << 6;

/// Build a Host-to-Device Register FIS for an ATA command.
///
/// * `command` — an [`ata`] opcode.
/// * `lba` — the 48-bit LBA (upper 16 bits ignored).
/// * `count` — sector count (`0` means 65536 for `*_EXT` commands).
/// * `device` — the device register (caller sets [`DEVICE_LBA_MODE`]); for NCQ
///   the count field carries the tag instead, so callers compose accordingly.
/// * `features` — the 16-bit features register (NCQ uses it for the sector
///   count; non-NCQ DMA uses `0`).
///
/// The `C` bit (byte 1) is always set — this builder only emits command FISes.
#[must_use]
pub fn build_h2d_register_fis(
    command: u8,
    lba: u64,
    count: u16,
    device: u8,
    features: u16,
) -> [u8; H2D_FIS_LEN] {
    let mut f = [0u8; H2D_FIS_LEN];
    f[0] = FisType::RegisterH2D as u8;
    f[1] = H2D_C_BIT; // pmport = 0, C = 1
    f[2] = command;
    f[3] = features as u8; // features[7:0]
    f[4] = lba as u8; // lba[7:0]
    f[5] = (lba >> 8) as u8; // lba[15:8]
    f[6] = (lba >> 16) as u8; // lba[23:16]
    f[7] = device;
    f[8] = (lba >> 24) as u8; // lba[31:24]
    f[9] = (lba >> 32) as u8; // lba[39:32]
    f[10] = (lba >> 40) as u8; // lba[47:40]
    f[11] = (features >> 8) as u8; // features[15:8]
    f[12] = count as u8; // count[7:0]
    f[13] = (count >> 8) as u8; // count[15:8]
    // bytes 14 (icc), 15 (control), 16..19 (aux) remain zero.
    f
}

/// Build the `IDENTIFY DEVICE` Register FIS (no LBA / count / features).
#[must_use]
pub fn build_identify_fis() -> [u8; H2D_FIS_LEN] {
    build_h2d_register_fis(ata::IDENTIFY_DEVICE, 0, 0, 0, 0)
}

/// Build a `READ DMA EXT` Register FIS for `count` sectors starting at `lba`.
#[must_use]
pub fn build_read_dma_ext_fis(lba: u64, count: u16) -> [u8; H2D_FIS_LEN] {
    build_h2d_register_fis(ata::READ_DMA_EXT, lba, count, DEVICE_LBA_MODE, 0)
}

/// Build a `WRITE DMA EXT` Register FIS for `count` sectors starting at `lba`.
#[must_use]
pub fn build_write_dma_ext_fis(lba: u64, count: u16) -> [u8; H2D_FIS_LEN] {
    build_h2d_register_fis(ata::WRITE_DMA_EXT, lba, count, DEVICE_LBA_MODE, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_fis_has_correct_header_and_command() {
        let f = build_identify_fis();
        assert_eq!(f.len(), 20);
        assert_eq!(f[0], 0x27, "FIS type H2D");
        assert_eq!(f[1], 0x80, "C bit set, pmport 0");
        assert_eq!(f[2], ata::IDENTIFY_DEVICE);
        // No LBA / count / features for IDENTIFY.
        assert!(f[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_dma_ext_packs_lba48_and_count() {
        // LBA = 0x0001_0203_0405, count = 0x0008.
        let f = build_read_dma_ext_fis(0x0001_0203_0405, 8);
        assert_eq!(f[2], ata::READ_DMA_EXT);
        assert_eq!(f[7], DEVICE_LBA_MODE, "LBA mode bit set");
        // lba little-endian across the two halves.
        assert_eq!(f[4], 0x05);
        assert_eq!(f[5], 0x04);
        assert_eq!(f[6], 0x03);
        assert_eq!(f[8], 0x02);
        assert_eq!(f[9], 0x01);
        assert_eq!(f[10], 0x00);
        assert_eq!(f[12], 0x08, "count[7:0]");
        assert_eq!(f[13], 0x00, "count[15:8]");
    }

    #[test]
    fn write_dma_ext_uses_correct_opcode() {
        let f = build_write_dma_ext_fis(0, 1);
        assert_eq!(f[2], ata::WRITE_DMA_EXT);
    }

    #[test]
    fn features_split_across_low_and_high_bytes() {
        // NCQ uses features for the sector count; verify the split.
        let f = build_h2d_register_fis(ata::READ_FPDMA_QUEUED, 0, 0, DEVICE_LBA_MODE, 0xBEEF);
        assert_eq!(f[3], 0xEF, "features[7:0]");
        assert_eq!(f[11], 0xBE, "features[15:8]");
    }

    #[test]
    fn count_high_byte_is_emitted() {
        let f = build_read_dma_ext_fis(0, 0x0102);
        assert_eq!(f[12], 0x02);
        assert_eq!(f[13], 0x01);
    }
}

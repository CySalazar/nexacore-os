//! `IDENTIFY DEVICE` response parsing (WS2-07.5).
//!
//! `IDENTIFY DEVICE` returns a 512-byte block of 256 little-endian `u16`
//! "words" (ACS-4 § 7.13). This parser extracts the fields the driver needs to
//! expose the disk as a block device: addressable sector count, logical sector
//! size, LBA48 support, and the model string. Borrowing parser, mirroring the
//! NVMe `IdentifyController`/`IdentifyNamespace` style.

/// The IDENTIFY block is exactly 512 bytes (256 words).
pub const IDENTIFY_LEN: usize = 512;

/// Default ATA logical sector size when the device does not report a larger one.
pub const DEFAULT_SECTOR_BYTES: u32 = 512;

/// Length of the model-number string in bytes (words 27..47 → 40 bytes).
pub const MODEL_LEN: usize = 40;

/// Why an IDENTIFY block could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifyError {
    /// The buffer is shorter than [`IDENTIFY_LEN`].
    TooShort,
}

/// A parsed view over a 512-byte `IDENTIFY DEVICE` response.
#[derive(Debug, Clone, Copy)]
pub struct IdentifyDevice<'a> {
    buf: &'a [u8],
}

impl<'a> IdentifyDevice<'a> {
    /// Wrap a 512-byte IDENTIFY block.
    ///
    /// # Errors
    ///
    /// [`IdentifyError::TooShort`] if `buf` is shorter than [`IDENTIFY_LEN`].
    pub fn new(buf: &'a [u8]) -> Result<Self, IdentifyError> {
        if buf.len() < IDENTIFY_LEN {
            return Err(IdentifyError::TooShort);
        }
        Ok(Self { buf })
    }

    /// Read IDENTIFY word `n` (`0..256`), little-endian.
    #[must_use]
    pub fn word(&self, n: usize) -> u16 {
        let lo = self.buf.get(n * 2).copied().unwrap_or(0);
        let hi = self.buf.get(n * 2 + 1).copied().unwrap_or(0);
        u16::from_le_bytes([lo, hi])
    }

    /// Whether the device supports 48-bit LBA addressing (word 83, bit 10).
    #[must_use]
    pub fn lba48_supported(&self) -> bool {
        self.word(83) & (1 << 10) != 0
    }

    /// Total number of addressable logical sectors.
    ///
    /// Uses the LBA48 count (words 100..104) when LBA48 is supported and
    /// non-zero, otherwise the LBA28 count (words 60..62).
    #[must_use]
    pub fn total_sectors(&self) -> u64 {
        if self.lba48_supported() {
            let lba48 = u64::from(self.word(100))
                | (u64::from(self.word(101)) << 16)
                | (u64::from(self.word(102)) << 32)
                | (u64::from(self.word(103)) << 48);
            if lba48 != 0 {
                return lba48;
            }
        }
        u64::from(self.word(60)) | (u64::from(self.word(61)) << 16)
    }

    /// Logical sector size in bytes.
    ///
    /// 512 by default; if word 106 reports a larger logical sector (bit 14 set,
    /// bit 15 clear → field valid; bit 12 set → "logical sector longer than 256
    /// words"), the size comes from words 117..119 (in words → ×2 bytes).
    #[must_use]
    pub fn logical_sector_size(&self) -> u32 {
        let w106 = self.word(106);
        let valid = (w106 & (1 << 14)) != 0 && (w106 & (1 << 15)) == 0;
        if valid && (w106 & (1 << 12)) != 0 {
            let words_per_sector = u32::from(self.word(117)) | (u32::from(self.word(118)) << 16);
            if words_per_sector != 0 {
                return words_per_sector.saturating_mul(2);
            }
        }
        DEFAULT_SECTOR_BYTES
    }

    /// Total capacity in bytes (`total_sectors * logical_sector_size`).
    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors()
            .saturating_mul(u64::from(self.logical_sector_size()))
    }

    /// The model-number string (words 27..47), byte-swapped into reading order.
    ///
    /// ATA strings store the high byte of each word first, so this swaps each
    /// pair back. The result is padded with spaces; use [`trim_ata_string`] for
    /// the trimmed length.
    #[must_use]
    pub fn model(&self) -> [u8; MODEL_LEN] {
        let mut out = [b' '; MODEL_LEN];
        for i in 0..(MODEL_LEN / 2) {
            let w = self.word(27 + i);
            if let Some(slot) = out.get_mut(i * 2) {
                *slot = (w >> 8) as u8;
            }
            if let Some(slot) = out.get_mut(i * 2 + 1) {
                *slot = (w & 0xFF) as u8;
            }
        }
        out
    }
}

/// Trimmed length of an ATA space-padded string (trailing spaces/NULs removed).
#[must_use]
pub fn trim_ata_string(s: &[u8]) -> usize {
    let mut end = s.len();
    while end > 0 {
        match s.get(end - 1) {
            Some(b' ' | 0) => end -= 1,
            _ => break,
        }
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic IDENTIFY block with the given fields set.
    fn build_identify(
        lba48: bool,
        lba48_sectors: u64,
        lba28_sectors: u32,
        model: &str,
    ) -> [u8; IDENTIFY_LEN] {
        let mut buf = [0u8; IDENTIFY_LEN];
        let put = |buf: &mut [u8; IDENTIFY_LEN], word: usize, val: u16| {
            let b = val.to_le_bytes();
            buf[word * 2] = b[0];
            buf[word * 2 + 1] = b[1];
        };
        if lba48 {
            put(&mut buf, 83, 1 << 10);
            put(&mut buf, 100, lba48_sectors as u16);
            put(&mut buf, 101, (lba48_sectors >> 16) as u16);
            put(&mut buf, 102, (lba48_sectors >> 32) as u16);
            put(&mut buf, 103, (lba48_sectors >> 48) as u16);
        }
        put(&mut buf, 60, lba28_sectors as u16);
        put(&mut buf, 61, (lba28_sectors >> 16) as u16);
        // Model: ATA byte-swapped (high byte first).
        let mb = model.as_bytes();
        for i in 0..(MODEL_LEN / 2) {
            let hi = mb.get(i * 2).copied().unwrap_or(b' ');
            let lo = mb.get(i * 2 + 1).copied().unwrap_or(b' ');
            put(&mut buf, 27 + i, (u16::from(hi) << 8) | u16::from(lo));
        }
        buf
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(matches!(
            IdentifyDevice::new(&[0u8; 100]),
            Err(IdentifyError::TooShort)
        ));
    }

    #[test]
    fn lba48_sector_count_and_capacity() {
        let buf = build_identify(true, 0x0001_0000_0000, 0, "");
        let id = IdentifyDevice::new(&buf).unwrap();
        assert!(id.lba48_supported());
        assert_eq!(id.total_sectors(), 0x0001_0000_0000);
        // 4 Gi sectors × 512 B.
        assert_eq!(id.capacity_bytes(), 0x0001_0000_0000 * 512);
    }

    #[test]
    fn falls_back_to_lba28_when_no_lba48() {
        let buf = build_identify(false, 0, 1_000_000, "");
        let id = IdentifyDevice::new(&buf).unwrap();
        assert!(!id.lba48_supported());
        assert_eq!(id.total_sectors(), 1_000_000);
    }

    #[test]
    fn default_sector_size_is_512() {
        let buf = build_identify(true, 100, 0, "");
        let id = IdentifyDevice::new(&buf).unwrap();
        assert_eq!(id.logical_sector_size(), 512);
    }

    #[test]
    fn larger_logical_sector_is_read_from_words_117_118() {
        let mut buf = build_identify(true, 100, 0, "");
        // word 106: bit14=valid, bit12=long logical sector.
        let put = |buf: &mut [u8; IDENTIFY_LEN], word: usize, val: u16| {
            let b = val.to_le_bytes();
            buf[word * 2] = b[0];
            buf[word * 2 + 1] = b[1];
        };
        put(&mut buf, 106, (1 << 14) | (1 << 12));
        put(&mut buf, 117, 2048); // 2048 words/sector
        put(&mut buf, 118, 0);
        let id = IdentifyDevice::new(&buf).unwrap();
        assert_eq!(id.logical_sector_size(), 4096); // 2048 words × 2 bytes
    }

    #[test]
    fn model_string_is_byte_swapped_back() {
        let buf = build_identify(true, 1, 0, "QEMU HARDDISK");
        let id = IdentifyDevice::new(&buf).unwrap();
        let model = id.model();
        let len = trim_ata_string(&model);
        assert_eq!(&model[..len], b"QEMU HARDDISK");
    }
}

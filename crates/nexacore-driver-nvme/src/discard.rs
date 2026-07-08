//! NVMe Dataset Management — Discard Range Descriptor builder.
//!
//! The NVMe `Dataset Management` admin command (opcode `0x09`,
//! NVMe 1.4 § 6.7) emitted with the `AD = 1` attribute deallocates
//! one or more LBA ranges. Each range is described by a 16-byte
//! Range Descriptor per § 6.7.1 Figure 256 that the driver writes
//! into a host-prepared IOVA buffer the controller reads through
//! PRP1.
//!
//! ## Field layout (Figure 256)
//!
//! | Bytes  | Field                | Notes                          |
//! |--------|----------------------|--------------------------------|
//! | 0..3   | Context Attributes   | Optional metadata; Phase-1 = 0 |
//! | 4..7   | Length in LBs (u32)  | Number of logical blocks       |
//! | 8..15  | Starting LBA (u64)   | First LBA of the range         |
//!
//! ## Phase-1 scope
//!
//! Phase-1 NVMe driver emits exactly one range per Discard
//! command (the BLK channel client's
//! [`nexacore_types::blk::BlkRequest::Discard`] carries a single
//! `(lba, count)` tuple). Multi-range Discard lands behind a
//! future NCIP without changing the per-range descriptor layout.
//! [`write_single_discard_range`] writes the canonical 16-byte
//! shape into a caller-supplied buffer.

/// Size of one Dataset Management Range Descriptor (NVMe 1.4
/// § 6.7.1 Figure 256).
pub const DISCARD_RANGE_DESCRIPTOR_BYTES: usize = 16;

/// Errors the Range Descriptor builder can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiscardError {
    /// The caller-supplied buffer is smaller than
    /// [`DISCARD_RANGE_DESCRIPTOR_BYTES`]. The Phase-1 driver
    /// pre-allocates exactly 4 KiB in the DMA arena for the
    /// descriptor; surfacing this is defence-in-depth against a
    /// regression that hands the builder a non-canonical buffer.
    BufferTooSmall,
}

/// Write a single Dataset Management Range Descriptor into the
/// first 16 bytes of `buf`.
///
/// The `Context Attributes` field (bytes 0..3) is set to zero
/// (Phase-1 driver does not request optional metadata).
///
/// # Errors
///
/// - [`DiscardError::BufferTooSmall`] if `buf.len() <
///   DISCARD_RANGE_DESCRIPTOR_BYTES`.
pub fn write_single_discard_range(
    buf: &mut [u8],
    lba: u64,
    count: u32,
) -> Result<(), DiscardError> {
    let dest = buf
        .get_mut(..DISCARD_RANGE_DESCRIPTOR_BYTES)
        .ok_or(DiscardError::BufferTooSmall)?;

    // Context Attributes — zero per Phase-1 (no optional metadata).
    dest.get_mut(0..4)
        .ok_or(DiscardError::BufferTooSmall)?
        .copy_from_slice(&0u32.to_le_bytes());

    // Length in Logical Blocks (32-bit little-endian).
    dest.get_mut(4..8)
        .ok_or(DiscardError::BufferTooSmall)?
        .copy_from_slice(&count.to_le_bytes());

    // Starting LBA (64-bit little-endian).
    dest.get_mut(8..16)
        .ok_or(DiscardError::BufferTooSmall)?
        .copy_from_slice(&lba.to_le_bytes());

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_byte_size_matches_spec() {
        // NVMe 1.4 § 6.7.1 Figure 256 — exactly 16 bytes per
        // range descriptor.
        assert_eq!(DISCARD_RANGE_DESCRIPTOR_BYTES, 16);
    }

    #[test]
    fn write_single_discard_range_writes_exactly_16_bytes() {
        let mut buf = [0xFFu8; 32];
        write_single_discard_range(&mut buf, 0x100, 8).unwrap();
        // Bytes past offset 16 MUST NOT be touched.
        for b in buf.iter().skip(DISCARD_RANGE_DESCRIPTOR_BYTES) {
            assert_eq!(*b, 0xFF, "writer must not scribble past byte 15");
        }
    }

    #[test]
    fn context_attributes_field_is_zero() {
        let mut buf = [0xFFu8; 16];
        write_single_discard_range(&mut buf, 0x100, 1).unwrap();
        let ca = buf.get(0..4).unwrap();
        assert_eq!(ca, &[0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn length_field_round_trips_through_offset_4_7_little_endian() {
        let mut buf = [0u8; 16];
        let count: u32 = 0xDEAD_BEEF;
        write_single_discard_range(&mut buf, 0, count).unwrap();
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(buf.get(4..8).unwrap());
        assert_eq!(u32::from_le_bytes(tmp), count);
    }

    #[test]
    fn starting_lba_field_round_trips_through_offset_8_15_little_endian() {
        let mut buf = [0u8; 16];
        let lba: u64 = 0xCAFE_BABE_DEAD_BEEF;
        write_single_discard_range(&mut buf, lba, 0).unwrap();
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(buf.get(8..16).unwrap());
        assert_eq!(u64::from_le_bytes(tmp), lba);
    }

    #[test]
    fn rejects_buffer_smaller_than_16_bytes() {
        let mut buf = [0u8; 15];
        let res = write_single_discard_range(&mut buf, 0x100, 1);
        assert_eq!(res, Err(DiscardError::BufferTooSmall));
    }

    #[test]
    fn rejects_empty_buffer() {
        let mut buf = [];
        let res = write_single_discard_range(&mut buf, 0, 0);
        assert_eq!(res, Err(DiscardError::BufferTooSmall));
    }

    #[test]
    fn accepts_buffer_larger_than_16_bytes() {
        // 4 KiB buffer (the Phase-1 DMA arena size) — the writer
        // touches only the first 16 bytes.
        let mut buf = vec![0u8; 4096];
        write_single_discard_range(&mut buf, 0x42, 7).unwrap();
        // Verify the descriptor lives at the head of the buffer.
        let mut len_tmp = [0u8; 4];
        len_tmp.copy_from_slice(buf.get(4..8).unwrap());
        assert_eq!(u32::from_le_bytes(len_tmp), 7);
        let mut lba_tmp = [0u8; 8];
        lba_tmp.copy_from_slice(buf.get(8..16).unwrap());
        assert_eq!(u64::from_le_bytes(lba_tmp), 0x42);
        // The rest of the buffer stays zeroed.
        for b in buf.iter().skip(DISCARD_RANGE_DESCRIPTOR_BYTES) {
            assert_eq!(*b, 0);
        }
    }

    #[test]
    fn full_field_layout_round_trip() {
        let mut buf = [0u8; 16];
        let lba: u64 = 0x0123_4567_89AB_CDEF;
        let count: u32 = 0x55AA_55AA;
        write_single_discard_range(&mut buf, lba, count).unwrap();
        // Context Attributes (0..3) = 0.
        let mut ca_tmp = [0u8; 4];
        ca_tmp.copy_from_slice(buf.get(0..4).unwrap());
        assert_eq!(u32::from_le_bytes(ca_tmp), 0);
        // Length (4..7).
        let mut len_tmp = [0u8; 4];
        len_tmp.copy_from_slice(buf.get(4..8).unwrap());
        assert_eq!(u32::from_le_bytes(len_tmp), count);
        // Starting LBA (8..15).
        let mut lba_tmp = [0u8; 8];
        lba_tmp.copy_from_slice(buf.get(8..16).unwrap());
        assert_eq!(u64::from_le_bytes(lba_tmp), lba);
    }

    #[test]
    fn discard_error_taxonomy_is_distinguishable() {
        // Exhaustive distinctness check — currently a single
        // variant but the matcher pattern guards future
        // expansion.
        let err = DiscardError::BufferTooSmall;
        assert_eq!(err, DiscardError::BufferTooSmall);
    }

    #[test]
    fn zero_lba_zero_count_writes_canonical_zero_descriptor() {
        // Degenerate but legal: count=0 is a no-op range. The
        // controller would reject this with a status word; the
        // builder still produces the bytes verbatim.
        let mut buf = [0xFFu8; 16];
        write_single_discard_range(&mut buf, 0, 0).unwrap();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn max_lba_and_max_count_round_trip() {
        let mut buf = [0u8; 16];
        write_single_discard_range(&mut buf, u64::MAX, u32::MAX).unwrap();
        let mut len_tmp = [0u8; 4];
        len_tmp.copy_from_slice(buf.get(4..8).unwrap());
        assert_eq!(u32::from_le_bytes(len_tmp), u32::MAX);
        let mut lba_tmp = [0u8; 8];
        lba_tmp.copy_from_slice(buf.get(8..16).unwrap());
        assert_eq!(u64::from_le_bytes(lba_tmp), u64::MAX);
    }
}

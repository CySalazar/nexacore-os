//! RX / TX descriptor ring depth bounds and RX buffer-pool defaults.
//!
//! Pinned by [`NCIP-Driver-Net-015`] § S1 (the common `[net]` block).
//! `DriverLoad` validates the manifest depths against these bounds before
//! the driver issues any controller-register writes; the bring-up FSM
//! rejects an out-of-bounds value with
//! [`crate::bringup::BringUpError::InvalidRingDepth`] (defence-in-depth
//! for tests and harness work).
//!
//! ## Bounds
//!
//! - RX / TX descriptor ring depth: power of 2 in `1..=4096`
//!   (NCIP-015 § S1.1).
//! - RX buffer count: `1..=8192` (NCIP-015 § S1.1).
//!
//! ## Descriptor sizes
//!
//! Intel 82574L datasheet § 10.7.1 (Receive Descriptor Format) and
//! § 10.8.1 (Transmit Descriptor Format) both define **16-byte
//! descriptors** for the legacy format the v0.3 driver uses. Extended
//! formats (advanced TX descriptors, SCTPR receive descriptors) are
//! deferred.
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md

/// Lower bound for the RX / TX descriptor ring depth.
///
/// NCIP-015 § S1.1: a ring of one entry is technically valid (the device
/// hardware accepts it). Anything below is reserved.
pub const MIN_RING_DEPTH: u32 = 1;

/// Upper bound for the RX / TX descriptor ring depth.
///
/// NCIP-015 § S1.1: 4096 entries × 16 bytes = 64 KiB per ring, comfortably
/// fitting inside the 4 GiB IOVA arena the manifest declares.
pub const MAX_RING_DEPTH: u32 = 4096;

/// Default RX descriptor ring depth used by the manifest template
/// (`rx_ring_depth = 256`). Matches the precedent set by
/// `nexacore-driver-net-virtio` (P6.7.8.2).
pub const DEFAULT_RX_RING_DEPTH: u32 = 256;

/// Default TX descriptor ring depth used by the manifest template
/// (`tx_ring_depth = 256`).
pub const DEFAULT_TX_RING_DEPTH: u32 = 256;

/// Lower bound for `rx_buffer_count`.
pub const MIN_RX_BUFFER_COUNT: u32 = 1;

/// Upper bound for `rx_buffer_count`.
///
/// NCIP-015 § S1.1: `rx_buffer_count` is bound at 8192. Per the manifest
/// each buffer is 2 KiB, so the cap matches a 16 MiB pre-allocated pool
/// — sized to absorb a burst on a saturated 1 Gb/s link without dropping.
pub const MAX_RX_BUFFER_COUNT: u32 = 8192;

/// Default RX buffer pool count used by the manifest template
/// (`rx_buffer_count = 512` × 2 KiB = 1 MiB pool).
pub const DEFAULT_RX_BUFFER_COUNT: u32 = 512;

/// Size, in bytes, of one RX descriptor (legacy format, Intel 82574L
/// datasheet § 10.7.1).
pub const RX_DESCRIPTOR_BYTES: usize = 16;

/// Size, in bytes, of one TX descriptor (legacy format, Intel 82574L
/// datasheet § 10.8.1).
pub const TX_DESCRIPTOR_BYTES: usize = 16;

/// Size, in bytes, of a single RX buffer (2 KiB matches `RCTL.BSIZE =
/// 0b00` in `controller_regs::rctl_enable_value`).
pub const RX_BUFFER_BYTES: usize = 2048;

/// Returns `true` if `depth` is a valid ring depth.
///
/// `depth` must be inside `[MIN_RING_DEPTH, MAX_RING_DEPTH]` **and** be a
/// power of two. NCIP-015 § S1.1 mandates the power-of-two constraint
/// (the hardware ring pointer wrap relies on `depth & (depth - 1) == 0`
/// to use a cheap AND instead of a modulo).
#[must_use]
pub const fn is_valid_ring_depth(depth: u32) -> bool {
    depth >= MIN_RING_DEPTH && depth <= MAX_RING_DEPTH && depth.is_power_of_two()
}

/// Returns `true` if `count` is inside
/// `[MIN_RX_BUFFER_COUNT, MAX_RX_BUFFER_COUNT]`.
///
/// No power-of-two requirement: `rx_buffer_count` is a count of
/// independently-allocated 2 KiB buffers, not a ring index.
#[must_use]
pub const fn is_valid_rx_buffer_count(count: u32) -> bool {
    count >= MIN_RX_BUFFER_COUNT && count <= MAX_RX_BUFFER_COUNT
}

/// Returns the byte size of an RX descriptor ring with `depth` entries.
///
/// Returns `None` if the multiplication would overflow `usize`
/// (defence-in-depth — at `depth ≤ 4096` and `16` bytes per entry the
/// result is always 65536 or less, so this only protects against future
/// bound increases).
#[must_use]
pub const fn rx_ring_bytes(depth: u32) -> Option<usize> {
    let Some(d) = (depth as usize).checked_mul(RX_DESCRIPTOR_BYTES) else {
        return None;
    };
    Some(d)
}

/// Returns the byte size of a TX descriptor ring with `depth` entries.
/// See [`rx_ring_bytes`] for overflow semantics.
#[must_use]
pub const fn tx_ring_bytes(depth: u32) -> Option<usize> {
    let Some(d) = (depth as usize).checked_mul(TX_DESCRIPTOR_BYTES) else {
        return None;
    };
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_match_ncip_015() {
        // NCIP-Driver-Net-015 § S1.1 caps:
        assert_eq!(MIN_RING_DEPTH, 1);
        assert_eq!(MAX_RING_DEPTH, 4096);
        assert_eq!(MIN_RX_BUFFER_COUNT, 1);
        assert_eq!(MAX_RX_BUFFER_COUNT, 8192);
    }

    #[test]
    fn defaults_match_manifest_template() {
        assert_eq!(DEFAULT_RX_RING_DEPTH, 256);
        assert_eq!(DEFAULT_TX_RING_DEPTH, 256);
        assert_eq!(DEFAULT_RX_BUFFER_COUNT, 512);
    }

    #[test]
    fn defaults_pass_validation() {
        assert!(is_valid_ring_depth(DEFAULT_RX_RING_DEPTH));
        assert!(is_valid_ring_depth(DEFAULT_TX_RING_DEPTH));
        assert!(is_valid_rx_buffer_count(DEFAULT_RX_BUFFER_COUNT));
    }

    #[test]
    fn descriptor_size_matches_legacy_format() {
        // Intel 82574L datasheet § 10.7.1 / § 10.8.1: legacy descriptor
        // format is 16 bytes.
        assert_eq!(RX_DESCRIPTOR_BYTES, 16);
        assert_eq!(TX_DESCRIPTOR_BYTES, 16);
    }

    #[test]
    fn rx_buffer_size_matches_rctl_bsize_00() {
        // RCTL.BSIZE = 0b00 selects 2 KiB buffers per Intel 82574L
        // datasheet § 10.7.6.
        assert_eq!(RX_BUFFER_BYTES, 2048);
    }

    #[test]
    fn ring_depth_validator_rejects_zero() {
        assert!(!is_valid_ring_depth(0));
    }

    #[test]
    fn ring_depth_validator_rejects_above_max() {
        assert!(!is_valid_ring_depth(MAX_RING_DEPTH + 1));
        assert!(!is_valid_ring_depth(u32::MAX));
    }

    #[test]
    fn ring_depth_validator_rejects_non_power_of_two() {
        // NCIP-015 § S1.1 mandates power-of-two depths for ring pointer
        // wrap. Drift here would silently corrupt indexing.
        assert!(!is_valid_ring_depth(3));
        assert!(!is_valid_ring_depth(100));
        assert!(!is_valid_ring_depth(255));
        assert!(!is_valid_ring_depth(513));
    }

    #[test]
    fn ring_depth_validator_accepts_every_power_of_two_in_bounds() {
        for shift in 0..=12 {
            let depth = 1u32 << shift;
            // 1..=4096 is exactly bits 0..=12.
            assert!(
                is_valid_ring_depth(depth),
                "validator rejected valid depth {depth}"
            );
        }
    }

    #[test]
    fn rx_buffer_count_validator_rejects_zero_and_above_max() {
        assert!(!is_valid_rx_buffer_count(0));
        assert!(!is_valid_rx_buffer_count(MAX_RX_BUFFER_COUNT + 1));
        assert!(!is_valid_rx_buffer_count(u32::MAX));
    }

    #[test]
    fn rx_buffer_count_validator_accepts_any_in_range() {
        // No power-of-two requirement for buffer count.
        assert!(is_valid_rx_buffer_count(1));
        assert!(is_valid_rx_buffer_count(3));
        assert!(is_valid_rx_buffer_count(100));
        assert!(is_valid_rx_buffer_count(512));
        assert!(is_valid_rx_buffer_count(MAX_RX_BUFFER_COUNT));
    }

    #[test]
    fn rx_ring_bytes_at_default_depth_matches_4_kib() {
        // 256 entries × 16 bytes = 4 KiB — fits in exactly one 4 KiB page.
        assert_eq!(rx_ring_bytes(DEFAULT_RX_RING_DEPTH), Some(4096));
    }

    #[test]
    fn tx_ring_bytes_at_default_depth_matches_4_kib() {
        assert_eq!(tx_ring_bytes(DEFAULT_TX_RING_DEPTH), Some(4096));
    }

    #[test]
    fn rx_ring_bytes_at_max_depth_matches_64_kib() {
        assert_eq!(rx_ring_bytes(MAX_RING_DEPTH), Some(64 * 1024));
    }

    #[test]
    fn ring_bytes_overflow_is_defended() {
        // u32::MAX descriptors × 16 bytes is 64 GiB on a 64-bit target —
        // representable, so the checked_mul does NOT trip. The check
        // exists for future 16-bit targets / bound increases; we
        // exercise the function rather than the overflow path.
        let _ = rx_ring_bytes(u32::MAX);
        let _ = tx_ring_bytes(u32::MAX);
    }
}

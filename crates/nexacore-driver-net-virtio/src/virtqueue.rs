//! Virtqueue layout constants for the M1 virtio-net deliverable.
//!
//! `NCIP-Driver-Net-015` § S4.1 step 6 instructs the driver to allocate two
//! virtqueues (RX = queue 0, TX = queue 1). The exact byte layout follows
//! virtio 1.0 § 2.4 ("Split Virtqueues"); v0.3 does NOT implement packed
//! virtqueues (deferred to a follow-up NCIP).
//!
//! ## Sizing
//!
//! `NCIP-Driver-Net-015` § S1 sets the manifest defaults to
//! `rx_ring_depth = 256`, `tx_ring_depth = 256` (each MUST be a power of
//! 2 in `1..=4096`). The split-virtqueue formula from virtio 1.0 § 2.4 is:
//!
//! ```text
//!   descriptor table : queue_size * 16
//!   available ring   : 6 + queue_size * 2 + 2         (with USED_EVENT_IDX)
//!   used ring        : 6 + queue_size * 8 + 2         (with AVAIL_EVENT_IDX)
//! ```
//!
//! All three regions are placed in a contiguous IOVA arena (the driver
//! `DmaMap`s a single page-set per virtqueue, then programs the queue's
//! IOVA bases into the Common Configuration `queue_desc` / `queue_driver`
//! / `queue_device` 64-bit fields per virtio 1.0 § 4.1.4.3).

/// Index of the receive virtqueue (virtio-net § 5.1.2).
pub const RX_QUEUE_IDX: u16 = 0;

/// Index of the transmit virtqueue (virtio-net § 5.1.2).
pub const TX_QUEUE_IDX: u16 = 1;

/// Default RX virtqueue depth used by the M1 deliverable.
///
/// Matches `NCIP-Driver-Net-015` § S1's `rx_ring_depth = 256` default. MUST
/// be a power of 2 in `1..=4096`; the bring-up state machine validates the
/// manifest-supplied override against [`is_valid_queue_depth`].
pub const DEFAULT_RX_QUEUE_DEPTH: u16 = 256;

/// Default TX virtqueue depth used by the M1 deliverable.
///
/// Matches `NCIP-Driver-Net-015` § S1's `tx_ring_depth = 256` default. Same
/// `1..=4096` power-of-2 constraint as the RX queue.
pub const DEFAULT_TX_QUEUE_DEPTH: u16 = 256;

/// Byte size of a single `virtq_desc` (descriptor table entry).
///
/// Source: virtio 1.0 § 2.4.5. The descriptor struct is `{u64 addr, u32
/// len, u16 flags, u16 next}` — exactly 16 bytes.
pub const VIRTQ_DESC_BYTES: usize = 16;

/// Fixed-size overhead of the available ring excluding the variable
/// `ring` array.
///
/// Layout: `{u16 flags, u16 idx}` + trailing `u16 used_event` = 6 bytes.
/// The variable part is `queue_size * 2` bytes (u16 entries).
pub const VIRTQ_AVAIL_FIXED_BYTES: usize = 6;

/// Fixed-size overhead of the used ring.
///
/// Layout: `{u16 flags, u16 idx}` + trailing `u16 avail_event` = 6
/// bytes. The variable part is `queue_size * 8` bytes (each used-ring
/// entry is `{u32 id, u32 len}` = 8 bytes).
pub const VIRTQ_USED_FIXED_BYTES: usize = 6;

/// Size of one `virtq_used_elem` entry in bytes.
///
/// Source: virtio 1.0 § 2.4.8. `{u32 id, u32 len}` = 8 bytes.
pub const VIRTQ_USED_ELEM_BYTES: usize = 8;

/// Maximum manifest-allowed queue depth per `NCIP-Driver-Net-015` § S1.1.
pub const MAX_QUEUE_DEPTH: u16 = 4096;

/// Returns `true` if `depth` is a permitted virtqueue size per
/// `NCIP-Driver-Net-015` § S1.1: power of 2 in `1..=4096`.
#[must_use]
pub const fn is_valid_queue_depth(depth: u16) -> bool {
    depth >= 1 && depth <= MAX_QUEUE_DEPTH && depth.is_power_of_two()
}

/// Compute the byte size of one split virtqueue's descriptor table.
///
/// Total = `queue_size × 16` bytes. Returns `None` if the multiplication
/// overflows `usize` (cannot happen at `queue_size ≤ MAX_QUEUE_DEPTH`, but
/// kept as defence-in-depth for the eventual bring-up code path).
#[must_use]
pub const fn descriptor_table_bytes(queue_size: u16) -> Option<usize> {
    (queue_size as usize).checked_mul(VIRTQ_DESC_BYTES)
}

/// Compute the byte size of one split virtqueue's available ring (incl.
/// the `used_event` suffix). Total = `6 + queue_size × 2`.
#[must_use]
pub const fn avail_ring_bytes(queue_size: u16) -> Option<usize> {
    match (queue_size as usize).checked_mul(2) {
        Some(variable) => variable.checked_add(VIRTQ_AVAIL_FIXED_BYTES),
        None => None,
    }
}

/// Compute the byte size of one split virtqueue's used ring (incl. the
/// `avail_event` suffix). Total = `6 + queue_size × 8`.
#[must_use]
pub const fn used_ring_bytes(queue_size: u16) -> Option<usize> {
    match (queue_size as usize).checked_mul(VIRTQ_USED_ELEM_BYTES) {
        Some(variable) => variable.checked_add(VIRTQ_USED_FIXED_BYTES),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rx_and_tx_queue_indices_match_spec() {
        // virtio-net § 5.1.2 pins receiveq0 = 0, transmitq0 = 1.
        assert_eq!(RX_QUEUE_IDX, 0);
        assert_eq!(TX_QUEUE_IDX, 1);
    }

    #[test]
    fn default_queue_depths_pass_validation() {
        assert!(is_valid_queue_depth(DEFAULT_RX_QUEUE_DEPTH));
        assert!(is_valid_queue_depth(DEFAULT_TX_QUEUE_DEPTH));
    }

    #[test]
    fn queue_depth_rejects_zero_and_above_max() {
        assert!(!is_valid_queue_depth(0));
        assert!(!is_valid_queue_depth(MAX_QUEUE_DEPTH + 1));
    }

    #[test]
    fn queue_depth_rejects_non_power_of_two() {
        // NCIP-015 § S1.1 mandates power-of-2 depths; 3 / 5 / 1000 are
        // intentionally invalid even though they fit the 1..=4096 range.
        assert!(!is_valid_queue_depth(3));
        assert!(!is_valid_queue_depth(5));
        assert!(!is_valid_queue_depth(1000));
    }

    #[test]
    fn descriptor_table_size_for_default_depth() {
        // 256 entries × 16 bytes each = 4096 bytes (exactly one page).
        assert_eq!(descriptor_table_bytes(DEFAULT_RX_QUEUE_DEPTH), Some(4096));
    }

    #[test]
    fn avail_ring_size_for_default_depth() {
        // 6 + 256 × 2 = 518 bytes.
        assert_eq!(avail_ring_bytes(DEFAULT_RX_QUEUE_DEPTH), Some(518));
    }

    #[test]
    fn used_ring_size_for_default_depth() {
        // 6 + 256 × 8 = 2054 bytes.
        assert_eq!(used_ring_bytes(DEFAULT_RX_QUEUE_DEPTH), Some(2054));
    }

    #[test]
    fn queue_depth_accepts_full_range_boundaries() {
        // 1 and MAX_QUEUE_DEPTH are both powers of 2 within range.
        assert!(is_valid_queue_depth(1));
        assert!(is_valid_queue_depth(MAX_QUEUE_DEPTH));
    }
}

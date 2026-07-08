//! Admin + IO queue depth bounds and queue entry sizes.
//!
//! Pinned by [`NCIP-Driver-NVMe-014`] § S1 and § S5. The driver validates
//! the manifest-supplied depths against the bounds below before any
//! controller register write; the bring-up FSM rejects any out-of-bounds
//! value with `BringUpError::InvalidManifestQueueDepth` (per NCIP-014
//! § S1.1 the rejection happens kernel-side via `DriverLoad`, but the
//! crate-internal check is defence-in-depth for tests and host harness
//! work).
//!
//! ## Bounds
//!
//! - Admin queue depth: `1..=4096` per NVMe 1.4 § 5.1 ("Admin
//!   Submission Queue Size").
//! - IO queue depth: `1..=65536` per NVMe 1.4 § 5.5 ("Create I/O
//!   Submission Queue" — Queue Size in CDW10).
//! - IO queue count: `1..=4` per NCIP-014 § R5 (BSP-only IRQ delivery in
//!   v0.3 caps the practical vector budget at 4).
//!
//! ## Entry sizes
//!
//! NVMe 1.4 fixes the architected entry sizes; v0.3 does not implement
//! the optional alternate-size paths (`CC.IOSQES` / `CC.IOCQES` would
//! never be programmed to anything other than 6 / 4):
//!
//! - Submission queue entry: 64 bytes (NVMe 1.4 § 4.2).
//! - Completion queue entry: 16 bytes (NVMe 1.4 § 4.6).
//!
//! [`NCIP-Driver-NVMe-014`]: ../../../ncips/ncip-driver-nvme-014.md

/// Lower bound for any submission/completion queue depth (admin or IO).
///
/// NVMe 1.4 § 5.1 / § 5.5: a controller MAY support queue size 1 but no
/// smaller — `0` is reserved.
pub const MIN_QUEUE_DEPTH: u32 = 1;

/// Upper bound for the admin queue depth.
///
/// NVMe 1.4 § 3.1.8 (`AQA`) reserves 12 bits each for `ASQS` and
/// `ACQS`, so the maximum depth fits in `1..=4096`.
pub const MAX_ADMIN_QUEUE_DEPTH: u32 = 4096;

/// Upper bound for the IO queue depth.
///
/// NVMe 1.4 § 5.5 (`Create I/O Submission Queue` CDW10) encodes the
/// queue size as a 16-bit field, allowing `1..=65536`.
pub const MAX_IO_QUEUE_DEPTH: u32 = 65536;

/// Default admin submission queue depth used by the manifest template.
///
/// 64 entries matches the NCIP-014 § S1 default (`admin_sq_depth = 64`)
/// and gives ample headroom for the half-dozen Identify commands the
/// bring-up sequence issues serially.
pub const DEFAULT_ADMIN_SQ_DEPTH: u32 = 64;

/// Default admin completion queue depth used by the manifest template.
pub const DEFAULT_ADMIN_CQ_DEPTH: u32 = 64;

/// Default IO submission queue depth used by the manifest template.
///
/// 1024 entries matches the NCIP-014 § S1 default (`io_sq_depth = 1024`).
pub const DEFAULT_IO_SQ_DEPTH: u32 = 1024;

/// Default IO completion queue depth used by the manifest template.
pub const DEFAULT_IO_CQ_DEPTH: u32 = 1024;

/// Maximum number of IO queue pairs the driver may request.
///
/// NCIP-014 § R5: BSP-only IRQ delivery caps the IRQ vector budget at 4
/// for v0.3. Per-CPU affinity (future NCIP) will relax this.
pub const MAX_IO_QUEUE_COUNT: u32 = 4;

/// Default number of IO queue pairs (single-queue per the NCIP-014 § R2
/// rationale).
pub const DEFAULT_IO_QUEUE_COUNT: u32 = 1;

/// Submission queue entry size in bytes (NVMe 1.4 § 4.2).
///
/// Architected at 64 bytes; the driver writes `CC.IOSQES = 6` (encoding
/// `2^6 = 64`) per [`crate::controller_regs::CC_IOSQES_VALUE`].
pub const SQ_ENTRY_BYTES: usize = 64;

/// Completion queue entry size in bytes (NVMe 1.4 § 4.6).
///
/// Architected at 16 bytes; the driver writes `CC.IOCQES = 4` (encoding
/// `2^4 = 16`) per [`crate::controller_regs::CC_IOCQES_VALUE`].
pub const CQ_ENTRY_BYTES: usize = 16;

/// Returns `true` if `depth` is a permitted **admin** queue depth per
/// NCIP-014 § S1.1.
#[must_use]
pub const fn is_valid_admin_depth(depth: u32) -> bool {
    depth >= MIN_QUEUE_DEPTH && depth <= MAX_ADMIN_QUEUE_DEPTH
}

/// Returns `true` if `depth` is a permitted **IO** queue depth per
/// NCIP-014 § S1.1.
#[must_use]
pub const fn is_valid_io_depth(depth: u32) -> bool {
    depth >= MIN_QUEUE_DEPTH && depth <= MAX_IO_QUEUE_DEPTH
}

/// Returns `true` if `count` is a permitted IO queue count per NCIP-014
/// § R5 (`1..=4` for v0.3).
#[must_use]
pub const fn is_valid_io_queue_count(count: u32) -> bool {
    count >= MIN_QUEUE_DEPTH && count <= MAX_IO_QUEUE_COUNT
}

/// Compute the byte size of a contiguous submission-queue allocation.
///
/// Returns `None` on overflow (cannot happen at
/// `depth ≤ MAX_IO_QUEUE_DEPTH` × 64 = 4 MiB, but kept as
/// defence-in-depth for the eventual `DmaMap` call site).
#[must_use]
pub const fn sq_allocation_bytes(depth: u32) -> Option<usize> {
    (depth as usize).checked_mul(SQ_ENTRY_BYTES)
}

/// Compute the byte size of a contiguous completion-queue allocation
/// of `depth` entries.
#[must_use]
pub const fn cq_allocation_bytes(depth: u32) -> Option<usize> {
    (depth as usize).checked_mul(CQ_ENTRY_BYTES)
}

/// Encode the `AQA` register value from admin queue depths per NVMe
/// 1.4 § 3.1.8. `AQA[11:0] = ASQS - 1`, `AQA[27:16] = ACQS - 1`.
///
/// Returns `None` if either depth is out of range; callers in the
/// bring-up FSM convert `None` into a structured error event.
#[must_use]
pub const fn encode_aqa(sq_depth: u32, cq_depth: u32) -> Option<u32> {
    if !is_valid_admin_depth(sq_depth) || !is_valid_admin_depth(cq_depth) {
        return None;
    }
    // `is_valid_admin_depth` guarantees `1..=4096`, so the subtractions
    // never underflow and the values fit in 12 bits.
    Some((sq_depth - 1) | ((cq_depth - 1) << 16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_match_nvme_1_4_spec() {
        // NVMe 1.4 § 5.1 / § 5.5 pin: any drift here would let a
        // manifest pass validation that the device subsequently rejects.
        assert_eq!(MIN_QUEUE_DEPTH, 1);
        assert_eq!(MAX_ADMIN_QUEUE_DEPTH, 4096);
        assert_eq!(MAX_IO_QUEUE_DEPTH, 65536);
        assert_eq!(MAX_IO_QUEUE_COUNT, 4);
    }

    #[test]
    fn manifest_defaults_pass_validation() {
        // NCIP-014 § S1 defaults — round-trip through every validator.
        assert!(is_valid_admin_depth(DEFAULT_ADMIN_SQ_DEPTH));
        assert!(is_valid_admin_depth(DEFAULT_ADMIN_CQ_DEPTH));
        assert!(is_valid_io_depth(DEFAULT_IO_SQ_DEPTH));
        assert!(is_valid_io_depth(DEFAULT_IO_CQ_DEPTH));
        assert!(is_valid_io_queue_count(DEFAULT_IO_QUEUE_COUNT));
    }

    #[test]
    fn entry_sizes_match_nvme_1_4_fixed_values() {
        // NVMe 1.4 § 4.2 / § 4.6: SQE = 64 B (2^6), CQE = 16 B (2^4).
        assert_eq!(SQ_ENTRY_BYTES, 64);
        assert_eq!(CQ_ENTRY_BYTES, 16);
    }

    #[test]
    fn admin_depth_validator_rejects_zero_and_above_max() {
        assert!(!is_valid_admin_depth(0));
        assert!(!is_valid_admin_depth(MAX_ADMIN_QUEUE_DEPTH + 1));
    }

    #[test]
    fn admin_depth_validator_accepts_boundaries() {
        // NCIP-014 § S1.1 admits the full 1..=4096 range (no
        // power-of-2 constraint — the spec is more permissive than
        // virtio's queue depth check).
        assert!(is_valid_admin_depth(1));
        assert!(is_valid_admin_depth(MAX_ADMIN_QUEUE_DEPTH));
    }

    #[test]
    fn io_depth_validator_accepts_boundaries() {
        assert!(is_valid_io_depth(1));
        assert!(is_valid_io_depth(MAX_IO_QUEUE_DEPTH));
        assert!(!is_valid_io_depth(0));
        assert!(!is_valid_io_depth(MAX_IO_QUEUE_DEPTH + 1));
    }

    #[test]
    fn io_queue_count_validator_caps_at_four() {
        assert!(is_valid_io_queue_count(1));
        assert!(is_valid_io_queue_count(4));
        assert!(!is_valid_io_queue_count(0));
        assert!(!is_valid_io_queue_count(5));
    }

    #[test]
    fn sq_allocation_bytes_for_default_depth() {
        // 1024 × 64 = 64 KiB.
        assert_eq!(sq_allocation_bytes(DEFAULT_IO_SQ_DEPTH), Some(64 * 1024));
    }

    #[test]
    fn cq_allocation_bytes_for_default_depth() {
        // 1024 × 16 = 16 KiB.
        assert_eq!(cq_allocation_bytes(DEFAULT_IO_CQ_DEPTH), Some(16 * 1024));
    }

    #[test]
    fn encode_aqa_round_trips_defaults() {
        // ASQS=64, ACQS=64 → AQA = 63 | (63 << 16) = 0x003F_003F.
        let encoded = encode_aqa(DEFAULT_ADMIN_SQ_DEPTH, DEFAULT_ADMIN_CQ_DEPTH);
        assert_eq!(encoded, Some(0x003F_003F));
    }

    #[test]
    fn encode_aqa_rejects_out_of_range() {
        // Either depth out of range collapses to `None`.
        assert_eq!(encode_aqa(0, 64), None);
        assert_eq!(encode_aqa(64, 0), None);
        assert_eq!(encode_aqa(MAX_ADMIN_QUEUE_DEPTH + 1, 64), None);
    }

    #[test]
    fn encode_aqa_accepts_max_admin_depth() {
        // ASQS=4096 fits the 12-bit field after `-1` → 0xFFF.
        let encoded = encode_aqa(MAX_ADMIN_QUEUE_DEPTH, MAX_ADMIN_QUEUE_DEPTH);
        assert_eq!(encoded, Some(0x0FFF_0FFF));
    }
}

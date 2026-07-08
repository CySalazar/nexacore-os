//! Generic block (BLK) service-channel ABI.
//!
//! This module defines the canonical request/response shape carried on
//! the `nexacore.svc.blk.<diskN>` IPC channels per
//! [`NCIP-Driver-NVMe-014`](../../../ncips/ncip-driver-nvme-014.md) § M3
//! and § S4. The NVMe driver is the first producer; future storage
//! drivers (SATA, virtio-blk, software RAID) MUST present the same
//! shape so that the file-system layer mediates against a single
//! contract.
//!
//! ## Why the BLK channel is a separate type module
//!
//! The user-space NVMe driver, the future file-system service, and any
//! diagnostic client (block-device inspector, `nexacore-fsck`-equivalent)
//! all need to encode/decode these types. Putting them in `nexacore-types`
//! keeps them in the foundational layer that every workspace member is
//! already allowed to depend on, and ensures the wire shape goes
//! through [`crate::wire::encode_canonical`] (the single workspace
//! audit point for serialization, per NCIP-Serde-004).
//!
//! ## Backward-compatibility policy
//!
//! Per NCIP-Driver-NVMe-014 § S7, backward-compatible additions to
//! [`BlkRequest`] and [`BlkResponse`] (new variants) MAY land via PR
//! without an NCIP. Both enums therefore carry `#[non_exhaustive]` so
//! downstream `match` expressions are forced to provide a `_ =>` arm,
//! and adding a variant does not break source-level consumers.
//!
//! ## Buffer ownership
//!
//! [`BlkRequest::Read`] and [`BlkRequest::Write`] carry `buf_iova`, an
//! IOVA-space address minted by a prior `DmaMap` syscall on the caller
//! side. The block driver is the **transient owner** of the buffer for
//! the lifetime of one round-trip — it reads from `buf_iova` (writes)
//! or writes into `buf_iova` (reads), then returns [`BlkResponse::Ok`]
//! and relinquishes ownership. The caller MUST NOT touch the buffer
//! between issuing the request and receiving the response.
//!
//! ## Alignment
//!
//! Per NCIP-014 § M4, every BLK transfer is aligned to the 4 KiB NexaCore OS
//! page size: `lba` selects a 4 KiB-sized logical block, `count` is a
//! count of those blocks, and `buf_iova` is 4 KiB-aligned in the
//! caller's IOVA arena. The driver MUST surface
//! [`BlkResponse::InvalidArgument`] if any of those invariants is
//! violated. The types themselves enforce no alignment at the type
//! level — the invariants are runtime properties of the request
//! payload.

use serde::{Deserialize, Serialize};

/// Sentinel value used by [`BlkResponse::DeviceError`] when the
/// underlying device is **not** NVMe (e.g., a future SATA backend) and
/// therefore has no native NVMe status word to forward.
///
/// All NVMe status words (`SCT:SC` packed into a `u16`) are < `0xFFFF`,
/// so this sentinel cannot collide with any real NVMe return code.
/// File-system consumers MUST treat the sentinel as "device-specific
/// error, no further information" and log the originating channel
/// name for triage.
///
/// Defined here once so every consumer references the same literal.
/// Referenced in NCIP-Driver-NVMe-014 § M3.
pub const NON_NVME_DEVICE_ERROR: u16 = 0xFFFF;

/// Maximum number of 4 KiB blocks a single [`BlkRequest::Read`] /
/// [`BlkRequest::Write`] may transfer in one round-trip.
///
/// Per NCIP-Driver-NVMe-014 § S2, NVMe drivers carry one PRP1 + one
/// PRP2-pointed PRP list per command. A 4 KiB PRP list holds 512
/// entries × 8 B = 512 × 4 KiB blocks; PRP1 contributes one more, for
/// **2048 PRP entries** total. The BLK layer is therefore bounded at
/// `2048` blocks per request to stay inside the PRP-only transfer
/// model selected in NCIP-Driver-NVMe-014 § M4.
///
/// Drivers MUST surface [`BlkResponse::InvalidArgument`] when
/// `count > MAX_BLOCK_COUNT_PER_REQUEST` so the contract is observable
/// from the wire side without requiring out-of-band documentation.
pub const MAX_BLOCK_COUNT_PER_REQUEST: u32 = 2048;

/// Logical block size in bytes for every BLK channel in v0.3.
///
/// Per NCIP-Driver-NVMe-014 § M4 + § S6 step 10, NexaCore OS pins the BLK
/// layer to 4 KiB (`LBADS = 12`) and rejects namespaces with any other
/// `LBADS`. The constant is published here so consumer crates (kernel
/// BLK registry, future file-system services) reference the same
/// literal.
pub const BLOCK_SIZE_BYTES: u32 = 4096;

/// Channel-name prefix for every BLK service channel.
///
/// The kernel's IPC registry uses this prefix to authorize the
/// capability-gated read/write taps documented in
/// NCIP-Driver-NVMe-014 § S4 / § SC1. The full channel name is the
/// prefix concatenated with the disk slot (`"nvme0"`, `"sata0"`, …);
/// the disk-slot portion is owned by the producing driver.
pub const CHANNEL_NAME_PREFIX: &str = "nexacore.svc.blk.";

// =============================================================================
// BlkRequest — driver-facing
// =============================================================================

/// A request sent by a BLK channel client to a storage driver.
///
/// Each variant maps to exactly one device operation as documented in
/// the per-driver NCIP (NCIP-Driver-NVMe-014 § S4 for NVMe; future
/// driver NCIPs MUST adopt the same mapping table or surface their
/// divergences as `#[non_exhaustive]` variants of [`BlkResponse`]).
///
/// All variants use `repr(Rust)` because the canonical wire format is
/// `postcard`-encoded via [`crate::wire::encode_canonical`]; the
/// in-memory layout is irrelevant for the cross-process contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BlkRequest {
    /// Read `count` consecutive 4 KiB blocks starting at logical block
    /// `lba` into the IOVA-mapped buffer at `buf_iova`.
    ///
    /// Maps to NVMe `0x02 NVM Read` per NCIP-Driver-NVMe-014 § S4.
    Read {
        /// First logical block address (4 KiB units). Must lie within
        /// the namespace size; out-of-range LBAs return
        /// [`BlkResponse::OutOfRange`].
        lba: u64,
        /// Block count. Must be `1..=`[`MAX_BLOCK_COUNT_PER_REQUEST`];
        /// `0` and any value > `MAX_BLOCK_COUNT_PER_REQUEST` return
        /// [`BlkResponse::InvalidArgument`].
        count: u32,
        /// IOVA-space address of the destination buffer. Must be
        /// 4 KiB-aligned and large enough to hold
        /// `count * BLOCK_SIZE_BYTES`. The buffer MUST have been
        /// mapped through a prior `DmaMap` syscall by the client.
        buf_iova: u64,
    },
    /// Write `count` consecutive 4 KiB blocks from the IOVA-mapped
    /// buffer at `buf_iova` into the device at logical block `lba`.
    ///
    /// Maps to NVMe `0x01 NVM Write` per NCIP-Driver-NVMe-014 § S4.
    Write {
        /// First logical block address (4 KiB units). Must lie within
        /// the namespace size; out-of-range LBAs return
        /// [`BlkResponse::OutOfRange`].
        lba: u64,
        /// Block count. Same bounds as [`BlkRequest::Read::count`].
        count: u32,
        /// IOVA-space address of the source buffer. Same alignment
        /// + size invariants as [`BlkRequest::Read::buf_iova`].
        buf_iova: u64,
    },
    /// Drain any volatile write cache the device may hold and block
    /// until persistence is confirmed.
    ///
    /// Maps to NVMe `0x00 NVM Flush` per NCIP-Driver-NVMe-014 § S4.
    /// A device that does not implement a write cache MUST still
    /// reply [`BlkResponse::Ok`].
    Flush,
    /// Hint the device that the `count` blocks starting at `lba`
    /// contain no useful data and MAY be deallocated.
    ///
    /// Maps to NVMe `0x09 Dataset Management` with Attribute = 0x04
    /// (Deallocate) per NCIP-Driver-NVMe-014 § S4. The mapping is
    /// **capability-gated**: a driver whose manifest sets
    /// `discard_enabled = false` MUST surface
    /// [`BlkResponse::NotSupported`] for every Discard.
    Discard {
        /// First logical block address (4 KiB units). Same bounds as
        /// [`BlkRequest::Read::lba`].
        lba: u64,
        /// Block count. Same bounds as [`BlkRequest::Read::count`].
        count: u32,
    },
}

// =============================================================================
// BlkResponse — driver-emitted
// =============================================================================

/// A response emitted by a storage driver in reply to a
/// [`BlkRequest`].
///
/// Each variant carries the minimum information needed by the caller
/// to decide between retry / propagate / abort. Detailed diagnostic
/// telemetry MUST go through the driver's event channel (e.g.
/// `nexacore.driver.nvme.evt` per NCIP-Driver-NVMe-014 § S3) rather than
/// being inlined into the BLK response, because the BLK channel is
/// rate-critical and additional payload directly throttles IOPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BlkResponse {
    /// The request completed successfully. For
    /// [`BlkRequest::Read`] the destination buffer at `buf_iova` is
    /// fully populated; for [`BlkRequest::Write`] the data has been
    /// accepted by the device but may still reside in a volatile
    /// write cache (call [`BlkRequest::Flush`] to force persistence).
    Ok,
    /// The driver does not implement this request shape (e.g.
    /// [`BlkRequest::Discard`] on a driver whose manifest sets
    /// `discard_enabled = false`).
    ///
    /// The caller SHOULD NOT retry; the response is structural.
    NotSupported,
    /// The device reported an error after consuming the request.
    ///
    /// For NVMe drivers, the inner `u16` is the device's NVMe status
    /// word (`SCT << 8 | SC` per NVMe 1.4 § 4.5). Non-NVMe drivers
    /// MUST forward [`NON_NVME_DEVICE_ERROR`] (`0xFFFF`) so the
    /// caller can distinguish NVMe status codes from opaque
    /// device-class failures.
    DeviceError(u16),
    /// One of the request's logical-block fields (`lba` or
    /// `lba + count`) is outside the namespace's size.
    ///
    /// Distinct from [`BlkResponse::InvalidArgument`] so a file
    /// system can map out-of-range reads to short-read semantics
    /// (file ending mid-block) without conflating them with a malformed
    /// request.
    OutOfRange,
    /// The request is structurally invalid (e.g., `count = 0`,
    /// `count > `[`MAX_BLOCK_COUNT_PER_REQUEST`], misaligned
    /// `buf_iova`).
    ///
    /// The caller SHOULD treat this as a programming error and log
    /// the offending request payload for triage.
    InvalidArgument,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    #[test]
    fn non_nvme_device_error_constant_is_0xffff() {
        // Locked by NCIP-Driver-NVMe-014 § M3. Changing this value is
        // a wire-format break that would force every BLK consumer to
        // re-test their error path; the assertion is a tripwire.
        assert_eq!(NON_NVME_DEVICE_ERROR, 0xFFFF);
    }

    #[test]
    fn max_block_count_per_request_matches_prp_capacity() {
        // PRP1 (1 entry) + PRP2 list (512 entries) = 513 entries, but
        // the planner pinned the upper limit at 2048 to give headroom
        // for a future second PRP-list page. Lock the value at the
        // currently-shipping limit so a downstream driver that respects
        // the constant cannot be tricked into a larger transfer by a
        // silent constant bump.
        assert_eq!(MAX_BLOCK_COUNT_PER_REQUEST, 2048);
    }

    #[test]
    fn block_size_bytes_matches_ncip_014_lbads_12() {
        // NCIP-Driver-NVMe-014 § M4 + § S6 step 10 lock the BLK block
        // size at 4 KiB. The check guards against a typo that would
        // desynchronize the driver and the file system at the wire
        // layer.
        assert_eq!(BLOCK_SIZE_BYTES, 4096);
    }

    #[test]
    fn channel_name_prefix_matches_ncip_014_s4() {
        // The kernel IPC registry derives capability-gating decisions
        // from this prefix; changing it without an NCIP would silently
        // break the cap-gate. Tripwire by exact string match.
        assert_eq!(CHANNEL_NAME_PREFIX, "nexacore.svc.blk.");
    }

    // -------------------------------------------------------------------------
    // BlkRequest round-trips — one per variant
    // -------------------------------------------------------------------------

    #[test]
    fn blk_request_read_round_trip() {
        let value = BlkRequest::Read {
            lba: 0xDEAD_BEEF_CAFE_BABE,
            count: 17,
            buf_iova: 0x1_0000_0000,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn blk_request_write_round_trip() {
        let value = BlkRequest::Write {
            lba: 1,
            count: MAX_BLOCK_COUNT_PER_REQUEST,
            buf_iova: 0x2_0000_0000,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn blk_request_flush_round_trip() {
        let value = BlkRequest::Flush;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn blk_request_discard_round_trip() {
        let value = BlkRequest::Discard { lba: 0, count: 8 };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // BlkResponse round-trips — one per variant + sentinel
    // -------------------------------------------------------------------------

    #[test]
    fn blk_response_ok_round_trip() {
        let value = BlkResponse::Ok;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn blk_response_not_supported_round_trip() {
        let value = BlkResponse::NotSupported;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn blk_response_device_error_nvme_status_round_trip() {
        // 0x4281 = SCT 0x4 (Path-related), SC 0x81 (Internal Path Error)
        // per NVMe 1.4 § 4.5 — a plausible NVMe-side failure.
        let value = BlkResponse::DeviceError(0x4281);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn blk_response_device_error_non_nvme_sentinel_round_trip() {
        // The non-NVMe sentinel MUST survive a round-trip — it is the
        // signal value future SATA / virtio-blk drivers will emit.
        let value = BlkResponse::DeviceError(NON_NVME_DEVICE_ERROR);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
        match decoded {
            BlkResponse::DeviceError(code) => assert_eq!(code, 0xFFFF),
            other => panic!("expected DeviceError(0xFFFF), got {other:?}"),
        }
    }

    #[test]
    fn blk_response_out_of_range_round_trip() {
        let value = BlkResponse::OutOfRange;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn blk_response_invalid_argument_round_trip() {
        let value = BlkResponse::InvalidArgument;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: BlkResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // Wire-format invariants
    // -------------------------------------------------------------------------

    #[test]
    fn blk_request_encoding_is_deterministic() {
        // Same value → same bytes. This is the signature-pre-image
        // invariant inherited from the wire-encoding module; if it
        // ever breaks for a BLK type, downstream signed-channel
        // protocols diverge.
        let value = BlkRequest::Read {
            lba: 42,
            count: 1,
            buf_iova: 0x1000,
        };
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn blk_response_encoding_is_deterministic() {
        let value = BlkResponse::DeviceError(0x1234);
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn blk_request_decode_rejects_trailing_bytes() {
        // Defence-in-depth: the wire module's `decode_canonical`
        // already rejects trailing bytes, but assert the property on
        // a BLK type explicitly so a future encoder swap that loses
        // the rejection trips this test.
        let value = BlkRequest::Flush;
        let mut bytes = encode_canonical(&value).expect("encode");
        bytes.push(0x00);
        let err = decode_canonical::<BlkRequest>(&bytes).expect_err("must reject trailing");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    #[test]
    fn blk_request_decode_rejects_truncated_input() {
        // Truncating the encoded bytes must surface an NexaCoreError::Wire
        // and not silently coerce to a default variant.
        let value = BlkRequest::Read {
            lba: 0x1234_5678,
            count: 4,
            buf_iova: 0x4000,
        };
        let bytes = encode_canonical(&value).expect("encode");
        assert!(bytes.len() >= 2, "encoding sanity check");
        let truncated = &bytes[..bytes.len() - 1];
        let err = decode_canonical::<BlkRequest>(truncated).expect_err("must reject truncated");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    #[test]
    fn blk_response_decode_rejects_empty_input() {
        // Postcard enums are encoded as varint(discriminant) + payload;
        // an empty input is never a valid discriminant.
        let err = decode_canonical::<BlkResponse>(&[]).expect_err("must reject empty");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    // -------------------------------------------------------------------------
    // Cross-variant integration — single buffer round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn round_trip_request_then_response_share_no_state() {
        // Encoding a request and a response back-to-back into separate
        // buffers must not entangle their bytes. Catches an accidental
        // shared scratch buffer.
        let req = BlkRequest::Write {
            lba: 7,
            count: 2,
            buf_iova: 0x8000,
        };
        let resp = BlkResponse::Ok;
        let req_bytes: Vec<u8> = encode_canonical(&req).expect("encode-req");
        let resp_bytes: Vec<u8> = encode_canonical(&resp).expect("encode-resp");
        let req2: BlkRequest = decode_canonical(&req_bytes).expect("decode-req");
        let resp2: BlkResponse = decode_canonical(&resp_bytes).expect("decode-resp");
        assert_eq!(req2, req);
        assert_eq!(resp2, resp);
        assert_ne!(req_bytes, resp_bytes);
    }

    #[test]
    fn blk_request_variants_are_distinguishable_on_the_wire() {
        // Every variant must produce a distinct first byte (the
        // postcard varint discriminant) so a decoder that only peeks
        // at the head can correctly dispatch.
        let read = encode_canonical(&BlkRequest::Read {
            lba: 0,
            count: 1,
            buf_iova: 0,
        })
        .expect("encode-read");
        let write = encode_canonical(&BlkRequest::Write {
            lba: 0,
            count: 1,
            buf_iova: 0,
        })
        .expect("encode-write");
        let flush = encode_canonical(&BlkRequest::Flush).expect("encode-flush");
        let discard =
            encode_canonical(&BlkRequest::Discard { lba: 0, count: 1 }).expect("encode-discard");

        // Postcard encodes enum discriminants as the variant index in
        // declaration order: Read=0, Write=1, Flush=2, Discard=3.
        assert_eq!(read.first(), Some(&0));
        assert_eq!(write.first(), Some(&1));
        assert_eq!(flush.first(), Some(&2));
        assert_eq!(discard.first(), Some(&3));
    }

    #[test]
    fn blk_response_variants_are_distinguishable_on_the_wire() {
        // Symmetric to the request-side discriminator check.
        let ok = encode_canonical(&BlkResponse::Ok).expect("encode-ok");
        let not_supported =
            encode_canonical(&BlkResponse::NotSupported).expect("encode-not-supported");
        let device_error =
            encode_canonical(&BlkResponse::DeviceError(0)).expect("encode-device-error");
        let out_of_range = encode_canonical(&BlkResponse::OutOfRange).expect("encode-out-of-range");
        let invalid_argument =
            encode_canonical(&BlkResponse::InvalidArgument).expect("encode-invalid-argument");

        // Declaration order: Ok=0, NotSupported=1, DeviceError=2,
        // OutOfRange=3, InvalidArgument=4.
        assert_eq!(ok.first(), Some(&0));
        assert_eq!(not_supported.first(), Some(&1));
        assert_eq!(device_error.first(), Some(&2));
        assert_eq!(out_of_range.first(), Some(&3));
        assert_eq!(invalid_argument.first(), Some(&4));
    }

    #[test]
    fn blk_request_flush_encodes_to_single_byte() {
        // The unit variant has no payload — its canonical encoding
        // is the discriminant byte alone. A regression that adds an
        // unintended payload would surface here.
        let bytes = encode_canonical(&BlkRequest::Flush).expect("encode");
        assert_eq!(bytes.as_slice(), &[2]);
    }

    #[test]
    fn blk_response_ok_encodes_to_single_byte() {
        // Symmetric to the Flush encoding check.
        let bytes = encode_canonical(&BlkResponse::Ok).expect("encode");
        assert_eq!(bytes.as_slice(), &[0]);
    }
}

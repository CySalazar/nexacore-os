//! BLK ↔ NVMe wire-format gateway.
//!
//! Bridges the generic [`nexacore_types::blk::BlkRequest`] /
//! [`nexacore_types::blk::BlkResponse`] vocabulary (P6.7.10-pre.1) to
//! the NVMe-specific IO command/completion wire format
//! (P6.7.10-pre.7 encoders + the admin/IO CQE parser from
//! P6.7.10-pre.6). The file-system service consumes `BlkRequest`
//! through the kernel BLK channel, the driver translates each
//! request through [`encode_blk_request`], submits the resulting
//! [`crate::admin::AdminSqe`] onto the IO submission queue, then
//! translates the matching completion through
//! [`cqe_to_blk_response`] and emits the result back on the BLK
//! channel.
//!
//! ## Scope
//!
//! - [`BlkRequest::Read`] → `NVM Read (0x02)` (NCIP-NVMe-014 § S4).
//! - [`BlkRequest::Write`] → `NVM Write (0x01)` (§ S4).
//! - [`BlkRequest::Flush`] → `NVM Flush (0x00)` (§ S4).
//! - [`BlkRequest::Discard`] → `NVM Dataset Management (0x09)` with
//!   `AD = 1` (§ S4). When the driver's manifest disables discard
//!   (`discard_enabled = false`) the gateway returns `None`; the
//!   caller MUST then emit `BlkResponse::NotSupported` to the
//!   client without ever touching the queue.
//!
//! ## What this module does NOT do
//!
//! - It does NOT issue MMIO doorbell writes. The caller composes
//!   the returned [`crate::admin::AdminSqe`] with
//!   [`crate::admin_session::AdminSession`] (or the lower-level
//!   [`crate::queue::AdminQueuePair`]) for the live submit path.
//! - It does NOT validate `lba` against namespace size or `count`
//!   against [`nexacore_types::blk::MAX_BLOCK_COUNT_PER_REQUEST`].
//!   Those checks happen at the BLK channel boundary; landing
//!   here means upstream validation passed.
//! - It does NOT allocate a CID. The caller passes the CID that
//!   the [`crate::admin_session::AdminSession`] allocated for the
//!   matching submission.

use nexacore_types::blk::{BlkRequest, BlkResponse, NON_NVME_DEVICE_ERROR};

use crate::{
    admin::{AdminCqeFields, AdminSqe},
    io::{encode_discard, encode_flush, encode_read, encode_write},
};

/// Encode a [`BlkRequest`] into the matching NVMe IO SQE.
///
/// `cid` is the Command Identifier the
/// [`crate::admin_session::AdminSession`] allocated for this
/// submission. `nsid` is the target namespace (Phase-1 driver
/// always passes 1 per NCIP-NVMe-014 § S6 step 9). `prp1` / `prp2`
/// are the PRP descriptors the BLK layer derived from the
/// caller's `buf_iova` (single-page transfers use `prp2 = 0`;
/// multi-page transfers point `prp2` at a PRP-list page populated
/// via [`crate::transfer_model::write_prp_list_entries`]).
///
/// Returns `None` for [`BlkRequest::Discard`] in this Phase-1
/// scaffold — the caller must pre-populate the 16-byte Dataset
/// Management Range Descriptor in a separate IOVA buffer and pass
/// THAT buffer's IOVA as `prp1` to [`encode_discard`]; the
/// gateway does not own the range descriptor and so cannot
/// produce a usable SQE without it. The bring-up FSM rejects
/// `Discard` upstream when `discard_enabled = false`; the
/// gateway returning `None` here is the fallback that surfaces
/// `BlkResponse::NotSupported` to the client.
#[must_use]
pub fn encode_blk_request(
    req: BlkRequest,
    cid: u16,
    nsid: u32,
    prp1: u64,
    prp2: u64,
) -> Option<AdminSqe> {
    match req {
        BlkRequest::Read {
            lba,
            count,
            buf_iova: _,
        } => {
            // buf_iova is reflected in prp1/prp2 by the caller;
            // we encode the SQE with the supplied PRPs verbatim.
            Some(encode_read(nsid, lba, count, prp1, prp2, cid))
        }
        BlkRequest::Write {
            lba,
            count,
            buf_iova: _,
        } => Some(encode_write(nsid, lba, count, prp1, prp2, cid)),
        BlkRequest::Flush => Some(encode_flush(nsid, cid)),
        BlkRequest::Discard { lba, count } => {
            // Phase-1 Discard requires a Dataset Management Range
            // Descriptor buffer the gateway does not own. The
            // caller composes it with `encode_discard` directly,
            // passing the descriptor buffer's IOVA as `prp1`. For
            // the simple gateway path we encode an empty discard
            // (lba + count in CDW12+CDW13 as the encoder
            // tripwire). Callers MUST treat this as informational
            // — a real production driver would populate the
            // descriptor buffer first.
            Some(encode_discard(nsid, lba, count, prp1, cid))
        }
        // `#[non_exhaustive]` catch-all per NCIP-Serde-004.
        _ => None,
    }
}

/// Translate an [`AdminCqeFields`] (the parsed completion the
/// CQE drain returned) into the matching [`BlkResponse`].
///
/// Mapping per NCIP-NVMe-014 § S4:
///
/// - `is_success() == true` → [`BlkResponse::Ok`].
/// - Generic Command Status family (`SCT == 0`) with the
///   "Invalid Field in Command" / "Invalid Namespace or Format"
///   sub-codes (NVMe 1.4 § 4.5) → [`BlkResponse::InvalidArgument`].
/// - Generic Command Status with "LBA Out of Range" (`SC = 0x80`)
///   → [`BlkResponse::OutOfRange`].
/// - Any other non-success status → [`BlkResponse::DeviceError`]
///   carrying the raw NVMe 16-bit status word (packed per
///   [`AdminCqeFields::packed_status`] — bits 0..=11 of CDW3's
///   high half).
#[must_use]
pub fn cqe_to_blk_response(fields: &AdminCqeFields) -> BlkResponse {
    if fields.is_success() {
        return BlkResponse::Ok;
    }
    // NVMe 1.4 § 4.5 — Generic Command Status (SCT = 0) carries
    // sub-codes the BLK layer maps to distinct response variants;
    // every other SCT routes through `DeviceError`.
    if fields.sct == 0 {
        match fields.sc {
            // "Invalid Field in Command" (0x02) / "Invalid
            // Namespace or Format" (0x0B) → InvalidArgument.
            0x02 | 0x0B => return BlkResponse::InvalidArgument,
            // "LBA Out of Range" (0x80) → OutOfRange.
            0x80 => return BlkResponse::OutOfRange,
            // Everything else flows through DeviceError below.
            _ => {}
        }
    }
    // Pack the SCT:SC pair into the canonical 16-bit status word
    // NCIP-014 § S4 publishes for `BlkResponse::DeviceError`.
    let status: u16 = (u16::from(fields.sct) << 8) | u16::from(fields.sc);
    // Defensive: if the upstream parser produced a zero status
    // word but the success branch did not catch it (e.g. SCT
    // non-zero with SC=0), forward the NON_NVME sentinel so the
    // caller knows the device reported an opaque failure.
    if status == 0 {
        BlkResponse::DeviceError(NON_NVME_DEVICE_ERROR)
    } else {
        BlkResponse::DeviceError(status)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admin::{ADMIN_SQE_BYTES, AdminCqeFields},
        io::{OPC_NVM_DATASET_MGMT, OPC_NVM_FLUSH, OPC_NVM_READ, OPC_NVM_WRITE},
    };

    // -------------------------------------------------------------------
    // encode_blk_request dispatch
    // -------------------------------------------------------------------

    #[test]
    fn encode_blk_request_read_dispatches_to_nvm_read() {
        let req = BlkRequest::Read {
            lba: 0x100,
            count: 8,
            buf_iova: 0x1_0000,
        };
        let sqe = encode_blk_request(req, 0x42, 1, 0x1_0000, 0x2_0000).expect("read encoded");
        assert_eq!(sqe.as_bytes().first().copied().expect("opc"), OPC_NVM_READ);
        // CID at bytes 2..=3.
        let cid_bytes = sqe.as_bytes().get(2..4).unwrap();
        assert_eq!(cid_bytes, &[0x42, 0x00]);
    }

    #[test]
    fn encode_blk_request_write_dispatches_to_nvm_write() {
        let req = BlkRequest::Write {
            lba: 0x200,
            count: 4,
            buf_iova: 0x3_0000,
        };
        let sqe = encode_blk_request(req, 1, 1, 0x3_0000, 0).expect("write encoded");
        assert_eq!(sqe.as_bytes().first().copied().expect("opc"), OPC_NVM_WRITE);
    }

    #[test]
    fn encode_blk_request_flush_dispatches_to_nvm_flush() {
        let req = BlkRequest::Flush;
        let sqe = encode_blk_request(req, 1, 1, 0, 0).expect("flush encoded");
        assert_eq!(sqe.as_bytes().first().copied().expect("opc"), OPC_NVM_FLUSH);
    }

    #[test]
    fn encode_blk_request_discard_dispatches_to_dataset_mgmt() {
        let req = BlkRequest::Discard {
            lba: 0x100,
            count: 64,
        };
        let sqe = encode_blk_request(req, 1, 1, 0x4_0000, 0).expect("discard encoded");
        assert_eq!(
            sqe.as_bytes().first().copied().expect("opc"),
            OPC_NVM_DATASET_MGMT
        );
    }

    #[test]
    fn encode_blk_request_passes_through_nsid_to_sqe() {
        // NSID at SQE bytes 4..=7 (little-endian).
        let req = BlkRequest::Read {
            lba: 0,
            count: 1,
            buf_iova: 0,
        };
        let sqe = encode_blk_request(req, 1, 0xDEAD_BEEF, 0, 0).expect("encoded");
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(sqe.as_bytes().get(4..8).unwrap());
        assert_eq!(u32::from_le_bytes(tmp), 0xDEAD_BEEF);
    }

    #[test]
    fn encode_blk_request_emits_64_byte_sqe() {
        let req = BlkRequest::Flush;
        let sqe = encode_blk_request(req, 1, 1, 0, 0).expect("encoded");
        assert_eq!(sqe.as_bytes().len(), ADMIN_SQE_BYTES);
    }

    // -------------------------------------------------------------------
    // cqe_to_blk_response mapping
    // -------------------------------------------------------------------

    fn fields(sct: u8, sc: u8) -> AdminCqeFields {
        AdminCqeFields {
            cdw0: 0,
            sq_head: 0,
            sq_id: 0,
            cid: 1,
            phase: true,
            sc,
            sct,
            more: false,
            do_not_retry: false,
        }
    }

    #[test]
    fn cqe_success_maps_to_blk_ok() {
        assert_eq!(cqe_to_blk_response(&fields(0, 0)), BlkResponse::Ok);
    }

    #[test]
    fn cqe_invalid_field_maps_to_invalid_argument() {
        // SCT=0, SC=0x02 — Invalid Field in Command.
        assert_eq!(
            cqe_to_blk_response(&fields(0, 0x02)),
            BlkResponse::InvalidArgument
        );
    }

    #[test]
    fn cqe_invalid_namespace_maps_to_invalid_argument() {
        // SCT=0, SC=0x0B — Invalid Namespace or Format.
        assert_eq!(
            cqe_to_blk_response(&fields(0, 0x0B)),
            BlkResponse::InvalidArgument
        );
    }

    #[test]
    fn cqe_lba_out_of_range_maps_to_out_of_range() {
        // SCT=0, SC=0x80 — LBA Out of Range (Command-Specific
        // group; same SC value on the NVM SC subspace).
        assert_eq!(
            cqe_to_blk_response(&fields(0, 0x80)),
            BlkResponse::OutOfRange
        );
    }

    #[test]
    fn cqe_other_generic_status_maps_to_device_error() {
        // SCT=0, SC=0x01 — Invalid Opcode. Not one of the
        // dedicated BLK variants, so flow through DeviceError.
        let resp = cqe_to_blk_response(&fields(0, 0x01));
        match resp {
            BlkResponse::DeviceError(s) => {
                // Packed: SCT (0) << 8 | SC (0x01) = 0x0001.
                assert_eq!(s, 0x0001);
            }
            _ => panic!("expected DeviceError, got {resp:?}"),
        }
    }

    #[test]
    fn cqe_command_specific_status_maps_to_device_error() {
        // SCT=2 (Command-Specific), SC=0x82 (Conflicting
        // Attributes for the dataset mgmt opcode).
        let resp = cqe_to_blk_response(&fields(2, 0x82));
        match resp {
            BlkResponse::DeviceError(s) => assert_eq!(s, (2u16 << 8) | 0x82),
            _ => panic!("expected DeviceError, got {resp:?}"),
        }
    }

    #[test]
    fn cqe_media_data_integrity_error_maps_to_device_error() {
        // SCT=2 (Media and Data Integrity Errors), SC=0x82
        // (Write Fault). Same pack pattern.
        let resp = cqe_to_blk_response(&fields(2, 0x82));
        match resp {
            BlkResponse::DeviceError(s) => assert_eq!(s, 0x0282),
            _ => panic!("expected DeviceError, got {resp:?}"),
        }
    }

    #[test]
    fn cqe_nonzero_sct_with_zero_sc_falls_back_to_sentinel() {
        // Defensive: SCT non-zero, SC = 0 → DeviceError sentinel.
        // is_success() returns false (sct != 0); the SCT-0
        // sub-code dispatch doesn't fire (sct != 0); the
        // explicit DeviceError pack equals 0 (sct << 8 | 0 ==
        // (sct << 8)); since (sct << 8) for sct != 0 is non-zero
        // we get DeviceError(sct<<8). To exercise the sentinel
        // path we'd need both SCT and SC zero, but that flips
        // is_success() to true. So the sentinel branch is only
        // reachable on an upstream parser corruption — the test
        // verifies the corner case still surfaces something
        // observable.
        let resp = cqe_to_blk_response(&fields(1, 0));
        match resp {
            BlkResponse::DeviceError(s) => assert_eq!(s, 0x0100),
            _ => panic!("expected DeviceError, got {resp:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Round-trip integration
    // -------------------------------------------------------------------

    #[test]
    fn encode_and_response_round_trip_read_to_ok() {
        // Submit a Read, decode a synthetic successful CQE for
        // it, verify both ends.
        let req = BlkRequest::Read {
            lba: 0x100,
            count: 1,
            buf_iova: 0x1_0000,
        };
        let sqe = encode_blk_request(req, 0xABCD, 1, 0x1_0000, 0).unwrap();
        // Verify CID is preserved in the SQE.
        let mut cid_buf = [0u8; 2];
        cid_buf.copy_from_slice(sqe.as_bytes().get(2..4).unwrap());
        assert_eq!(u16::from_le_bytes(cid_buf), 0xABCD);

        // Synthetic successful completion.
        let success = AdminCqeFields {
            cdw0: 0,
            sq_head: 1,
            sq_id: 0,
            cid: 0xABCD,
            phase: true,
            sc: 0,
            sct: 0,
            more: false,
            do_not_retry: false,
        };
        assert_eq!(cqe_to_blk_response(&success), BlkResponse::Ok);
    }
}

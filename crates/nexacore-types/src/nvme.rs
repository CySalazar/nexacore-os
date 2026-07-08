//! NVMe driver-facing command + event channel ABI types.
//!
//! This module defines the canonical wire shapes carried on the two
//! driver-private NVMe channels per
//! [`NCIP-Driver-NVMe-014`](../../../ncips/ncip-driver-nvme-014.md)
//! § S2 (command channel `nexacore.driver.nvme.cmd`) and § S3 (event
//! channel `nexacore.driver.nvme.evt`).
//!
//! The [`crate::blk`] module declares the generic `BlkRequest` /
//! `BlkResponse` types that file-system services consume. This module
//! is the lower-level, NVMe-specific surface that the user-space NVMe
//! driver itself implements between its hardware interaction code and
//! its admin / IO queue logic.
//!
//! ## Why a separate NVMe types module
//!
//! The user-space NVMe driver, the kernel-side BLK / IRQ infrastructure,
//! and any diagnostic client (NVMe inspector, `nexacore-nvme-cli` analogue)
//! all need to encode/decode these types. Putting them in `nexacore-types`
//! keeps them in the foundational layer that every workspace member is
//! already allowed to depend on, and ensures the wire shape goes
//! through [`crate::wire::encode_canonical`] (the single workspace
//! audit point for serialization, per NCIP-Serde-004).
//!
//! ## Backward-compatibility policy
//!
//! Per NCIP-Driver-NVMe-014 § S7, backward-compatible additions to
//! [`NvmeCommand`] / [`NvmeEvent`] / [`IdentifyTarget`] (new variants)
//! MAY land via PR without an NCIP. All three enums therefore carry
//! `#[non_exhaustive]` so downstream `match` expressions are forced to
//! provide a `_ =>` arm, and adding a variant does not break
//! source-level consumers.
//!
//! ## Buffer ownership
//!
//! [`NvmeCommand::Identify`], [`NvmeCommand::Read`], [`NvmeCommand::Write`],
//! and [`NvmeCommand::GetLogPage`] carry `buf_iova`, an IOVA-space
//! address minted by a prior `DmaMap` syscall on the caller side. The
//! NVMe driver is the **transient owner** of the buffer between
//! receiving the command and emitting the matching
//! [`NvmeEvent::CommandComplete`]. The caller MUST NOT touch the
//! buffer between issuing the command and observing the completion.
//!
//! ## Correlation
//!
//! Every [`NvmeCommand`] variant that yields a completion carries an
//! `opaque_id: u64` chosen by the client. The driver echoes it
//! verbatim in the matching [`NvmeEvent::CommandComplete`] so that
//! clients can multiplex an arbitrary number of concurrent commands
//! over the single command channel without a separate per-command
//! channel allocation. `opaque_id == 0` is reserved for the driver's
//! own internal correlation (admin commands issued during bring-up).
//!
//! See [`RESERVED_DRIVER_OPAQUE_ID`] for the sentinel value clients
//! MUST NOT use.
//!
//! ## Status-word semantics
//!
//! [`NvmeEvent::CommandComplete::status`] carries the raw 16-bit NVMe
//! status field — the `(Status Code Type:Status Code)` pair NVMe 1.4
//! § 4.5 defines packed into a single `u16` (bits \[14:9\] = SCT, bits
//! \[8:0\] = SC). Clients SHOULD decode it via the NVMe 1.4 spec § 4.5
//! table; helper decoders live alongside the driver-side code in
//! `nexacore-driver-nvme`, not here, because the table changes with new
//! NVMe spec revisions and this types crate must stay version-stable.

use serde::{Deserialize, Serialize};

/// Channel-name prefix for the driver-private NVMe command channel.
///
/// The full channel name is the prefix as published — Phase 1 ships
/// exactly one NVMe driver process, so there is no per-instance
/// suffix. Future multi-controller support will append `.<n>` per
/// NCIP-Driver-NVMe-014 § S7.
///
/// Published here once so every consumer (driver, kernel, future
/// inspector tools) references the same literal.
pub const CMD_CHANNEL_NAME: &str = "nexacore.driver.nvme.cmd";

/// Channel-name prefix for the driver-private NVMe event channel.
///
/// See [`CMD_CHANNEL_NAME`] for the per-instance-suffix rationale.
pub const EVT_CHANNEL_NAME: &str = "nexacore.driver.nvme.evt";

/// Maximum number of 4 KiB blocks a single [`NvmeCommand::Read`] /
/// [`NvmeCommand::Write`] may transfer in one round-trip.
///
/// Matches [`crate::blk::MAX_BLOCK_COUNT_PER_REQUEST`] — the NVMe
/// driver maps `Read` / `Write` to the corresponding NVMe NVM
/// commands at this exact ceiling so the BLK→NVMe lowering layer
/// never has to chunk a single BLK request. Drivers MUST surface
/// completion with a non-success status word when `block_count`
/// exceeds this value.
pub const MAX_BLOCK_COUNT_PER_REQUEST: u32 = 2048;

/// Logical block size in bytes for every Phase-1 NVMe namespace.
///
/// Phase-1 NVMe rejects namespaces with `LBADS != 12` per
/// NCIP-Driver-NVMe-014 § M4 + § S6 step 10. The constant is republished
/// here (matching [`crate::blk::BLOCK_SIZE_BYTES`]) so consumers of the
/// NVMe-specific types do not need to import the BLK module to
/// validate `block_count` arithmetic.
pub const BLOCK_SIZE_BYTES: u32 = 4096;

/// Sentinel `opaque_id` for driver-internal admin commands.
///
/// The driver itself emits Identify Controller, Identify Namespace,
/// Create IO Completion Queue, etc. during bring-up; these commands
/// are not initiated by a client and so carry this reserved value
/// instead of a client-chosen correlation token.
///
/// Clients MUST NOT use this value — the driver enforces uniqueness
/// of `opaque_id` against the reserved set when accepting incoming
/// commands. Reserving zero rather than a high-bit value keeps the
/// wire bytes for the common driver-internal case minimal (1 byte
/// for the `u64` zero per `postcard` variable-length encoding).
pub const RESERVED_DRIVER_OPAQUE_ID: u64 = 0;

// =============================================================================
// IdentifyTarget
// =============================================================================

/// Target of an [`NvmeCommand::Identify`] command.
///
/// Mirrors the NVMe `Identify` admin command's CNS field per NVMe 1.4
/// § 5.15.1, restricted to the three values NexaCore OS Phase 1 actually
/// issues. Future CNS additions (Namespace ID list with controller
/// affinity, NVM Set list, etc.) land as new `#[non_exhaustive]`
/// variants per NCIP-Driver-NVMe-014 § S7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IdentifyTarget {
    /// Identify Controller (CNS = `0x01` per NVMe 1.4 § 5.15.1).
    /// Returns a 4 KiB controller-wide data structure: vendor / device
    /// ids, NN (number of namespaces), supported features, queue
    /// limits.
    Controller,
    /// Identify Namespace (CNS = `0x00`) for the supplied namespace id.
    /// Returns a 4 KiB namespace-specific data structure: NSZE, NCAP,
    /// LBA format table.
    Namespace {
        /// NVMe Namespace Identifier. `0xFFFF_FFFF` is reserved by the
        /// NVMe spec for "all namespaces"; NexaCore OS rejects that value
        /// for `Identify Namespace` because Phase 1 only supports
        /// per-namespace introspection.
        nsid: u32,
    },
    /// Identify Active Namespace List (CNS = `0x02`). Returns the
    /// list of NSIDs currently active on the controller; the driver
    /// picks the first entry in NCIP-Driver-NVMe-014 § S6 step 9.
    ActiveNsList,
}

// =============================================================================
// NvmeCommand — driver-facing
// =============================================================================

/// A command sent by a client to the user-space NVMe driver over the
/// `nexacore.driver.nvme.cmd` channel.
///
/// Each variant maps to one or more NVMe submission queue entries
/// (admin or IO) per NCIP-Driver-NVMe-014 § S2 + § S6. Completions
/// land on the [`NvmeEvent::CommandComplete`] stream keyed by
/// `opaque_id`.
///
/// All variants use `repr(Rust)` because the canonical wire format is
/// `postcard`-encoded via [`crate::wire::encode_canonical`]; the
/// in-memory layout is irrelevant for the cross-process contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NvmeCommand {
    /// Issue an `Identify` admin command. The driver returns the
    /// 4 KiB Identify data structure by writing it into the IOVA
    /// buffer at `buf_iova`, then emits
    /// [`NvmeEvent::CommandComplete`] keyed by `opaque_id`.
    Identify {
        /// What to identify — see [`IdentifyTarget`].
        target: IdentifyTarget,
        /// IOVA address of a 4 KiB buffer the driver fills with the
        /// Identify response. Caller MUST keep the buffer mapped via
        /// `DmaMap` until the completion arrives.
        buf_iova: u64,
        /// Client-chosen correlation token echoed in the matching
        /// completion. MUST NOT be [`RESERVED_DRIVER_OPAQUE_ID`].
        opaque_id: u64,
    },
    /// Read `block_count` consecutive 4 KiB blocks starting at logical
    /// block `lba` from namespace `nsid` into the IOVA buffer at
    /// `buf_iova`.
    ///
    /// Maps to NVMe `0x02 NVM Read`. PRP1 = first 4 KiB; PRP2 =
    /// pointer to PRP list if `block_count > 1`.
    Read {
        /// Namespace identifier returned by a prior
        /// [`IdentifyTarget::ActiveNsList`].
        nsid: u32,
        /// Logical block address (0-based) of the first block to
        /// read.
        lba: u64,
        /// Number of consecutive 4 KiB blocks to read.
        /// `1..=`[`MAX_BLOCK_COUNT_PER_REQUEST`].
        block_count: u32,
        /// IOVA address of the destination buffer. Length =
        /// `block_count * BLOCK_SIZE_BYTES`. 4 KiB-aligned per
        /// NCIP-Driver-NVMe-014 § M4.
        buf_iova: u64,
        /// Client-chosen correlation token echoed in the matching
        /// completion. MUST NOT be [`RESERVED_DRIVER_OPAQUE_ID`].
        opaque_id: u64,
    },
    /// Write `block_count` consecutive 4 KiB blocks starting at
    /// logical block `lba` to namespace `nsid` from the IOVA buffer
    /// at `buf_iova`.
    ///
    /// Maps to NVMe `0x01 NVM Write`. Same PRP rules as
    /// [`NvmeCommand::Read`].
    Write {
        /// Namespace identifier.
        nsid: u32,
        /// Logical block address of the first block to write.
        lba: u64,
        /// Number of 4 KiB blocks to write.
        block_count: u32,
        /// IOVA address of the source buffer.
        buf_iova: u64,
        /// Client-chosen correlation token.
        opaque_id: u64,
    },
    /// Flush the volatile write cache for namespace `nsid`.
    ///
    /// Maps to NVMe `0x00 NVM Flush`. Completion arrives only after
    /// the controller commits every outstanding write to persistent
    /// media. Drivers SHOULD reject `Flush` if the controller does
    /// not implement a volatile write cache (the operation is then
    /// a no-op on the wire but consumes an admin command slot).
    Flush {
        /// Namespace identifier.
        nsid: u32,
        /// Client-chosen correlation token.
        opaque_id: u64,
    },
    /// Discard `block_count` consecutive 4 KiB blocks starting at
    /// `lba` (TRIM equivalent).
    ///
    /// Maps to NVMe `0x09 Dataset Management` with the
    /// `Attribute = Deallocate` bit. Only supported when the manifest
    /// sets `discard_enabled = true`; drivers MUST surface a
    /// non-success completion otherwise.
    Discard {
        /// Namespace identifier.
        nsid: u32,
        /// Logical block address of the first block to deallocate.
        lba: u64,
        /// Number of 4 KiB blocks to deallocate.
        block_count: u32,
        /// Client-chosen correlation token.
        opaque_id: u64,
    },
    /// Fetch an NVMe log page (e.g. SMART, Firmware Slot, Error
    /// Information).
    ///
    /// Maps to NVMe `0x02 Get Log Page` admin command. Log IDs
    /// follow NVMe 1.4 § 5.14.1: `0x01 = Error`, `0x02 = SMART`,
    /// `0x03 = Firmware Slot`. Driver writes the 4 KiB log page
    /// response into `buf_iova` before emitting the completion.
    GetLogPage {
        /// NVMe log page identifier.
        log_id: u8,
        /// IOVA address of the destination buffer (4 KiB).
        buf_iova: u64,
        /// Client-chosen correlation token.
        opaque_id: u64,
    },
    /// Format the namespace (capability-gated; refused without a
    /// separate `Format` cap-token, per NCIP-Driver-NVMe-014 § S2).
    ///
    /// Maps to NVMe `0x80 Format NVM` admin command. Phase-1 default
    /// driver policy rejects this variant unconditionally — the
    /// future format-cap deposit is a Phase-2 deliverable.
    FormatNVM {
        /// Namespace identifier.
        nsid: u32,
        /// Client-chosen correlation token.
        opaque_id: u64,
    },
}

// =============================================================================
// NvmeEvent — driver-emitted
// =============================================================================

/// An event emitted by the user-space NVMe driver on the
/// `nexacore.driver.nvme.evt` channel.
///
/// The channel is broadcast per NCIP-013 § S6 — every client that
/// attached a recv endpoint receives every event. Clients filter by
/// `opaque_id` to match their own commands; unmatched events (async
/// notifications, link state changes, controller fatal) MUST be
/// inspectable without correlation state.
///
/// As with [`NvmeCommand`], the canonical wire format is
/// `postcard`-encoded via [`crate::wire::encode_canonical`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NvmeEvent {
    /// A submitted command has reached its final state.
    ///
    /// Emitted once per [`NvmeCommand`] the driver accepted. The
    /// `opaque_id` echoes the value from the originating command;
    /// for driver-internal admin commands issued during bring-up the
    /// event carries [`RESERVED_DRIVER_OPAQUE_ID`] and is informational
    /// only (the driver consumes its own internal completions before
    /// re-emitting per-client events).
    CommandComplete {
        /// Echoed from the originating [`NvmeCommand`].
        opaque_id: u64,
        /// Raw 16-bit NVMe status word per NVMe 1.4 § 4.5
        /// (bits \[14:9\] = SCT, bits \[8:0\] = SC). `0x0000` = success.
        status: u16,
        /// NVMe Command Specific Dword 0 (e.g. Identify response
        /// length, Format completion code). Most commands return
        /// `0` here; documented per-command in NVMe 1.4 § 5.
        cdw0: u32,
    },
    /// NVMe Asynchronous Event (NVMe 1.4 § 5.2). Decoded from the
    /// async-event notification the controller raises out-of-band of
    /// any specific command.
    AsyncEvent {
        /// AEN Type per NVMe 1.4 § 5.2 (`0 = Error`, `1 = SMART/Health`,
        /// `2 = Notice`, `3..` reserved/vendor-specific).
        event_type: u8,
        /// AEN Information per NVMe 1.4 § 5.2 (type-specific
        /// sub-code).
        event_info: u8,
        /// Log page identifier to read for the full AEN payload
        /// (e.g. SMART for type=1, Error for type=0).
        log_page: u8,
    },
    /// PCIe link state changed. Phase-1 NVMe drivers monitor the
    /// PCIe Link Status register and emit this event on a transition
    /// so the filesystem service can surface "drive unplugged" / "
    /// drive reappeared" to the OS without polling.
    LinkStateChange {
        /// `true` = link is up; `false` = link is down.
        link_up: bool,
    },
    /// NVMe controller raised a fatal status (`CSTS.CFS = 1`). The
    /// driver MUST stop processing IO until the kernel resets the
    /// controller via PCI FLR or the driver process exits.
    ControllerFatal {
        /// Snapshot of the NVMe `CSTS` register (32-bit) at the time
        /// the fault was detected. Lets the kernel boot log surface
        /// the exact failure cause without re-reading MMIO.
        cstatus: u32,
    },
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_cmd(cmd: NvmeCommand) -> NvmeCommand {
        let bytes = crate::wire::encode_canonical(&cmd).expect("encode");
        let decoded: NvmeCommand = crate::wire::decode_canonical(&bytes).expect("decode");
        decoded
    }

    fn round_trip_evt(evt: NvmeEvent) -> NvmeEvent {
        let bytes = crate::wire::encode_canonical(&evt).expect("encode");
        let decoded: NvmeEvent = crate::wire::decode_canonical(&bytes).expect("decode");
        decoded
    }

    // -------------------------------------------------------------------
    // Constant tripwires
    // -------------------------------------------------------------------

    #[test]
    fn cmd_channel_name_matches_ncip_014_s2() {
        // Tripwire: changing the channel name silently breaks every
        // existing NVMe driver consumer. The kernel-side BLK-channel
        // capability gate uses an identical literal-equality pattern;
        // see `nexacore-kernel::services::blk::CHANNEL_NAME_PREFIX`.
        assert_eq!(CMD_CHANNEL_NAME, "nexacore.driver.nvme.cmd");
    }

    #[test]
    fn evt_channel_name_matches_ncip_014_s3() {
        assert_eq!(EVT_CHANNEL_NAME, "nexacore.driver.nvme.evt");
    }

    #[test]
    fn max_block_count_matches_blk_module() {
        // Both modules MUST agree — a divergence would let the BLK
        // layer accept requests the NVMe driver immediately rejects.
        assert_eq!(
            MAX_BLOCK_COUNT_PER_REQUEST,
            crate::blk::MAX_BLOCK_COUNT_PER_REQUEST
        );
    }

    #[test]
    fn block_size_matches_blk_module() {
        assert_eq!(BLOCK_SIZE_BYTES, crate::blk::BLOCK_SIZE_BYTES);
    }

    #[test]
    fn reserved_driver_opaque_id_is_zero() {
        // Pinning at zero keeps the wire-byte cost of the common
        // driver-internal case minimal (`postcard` varint zero = 1
        // byte) and lets clients sanity-check `opaque_id != 0` with
        // a single comparison.
        assert_eq!(RESERVED_DRIVER_OPAQUE_ID, 0);
    }

    // -------------------------------------------------------------------
    // NvmeCommand round-trips
    // -------------------------------------------------------------------

    #[test]
    fn nvme_command_identify_controller_round_trip() {
        let cmd = NvmeCommand::Identify {
            target: IdentifyTarget::Controller,
            buf_iova: 0x1_0000_0000,
            opaque_id: 42,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_identify_namespace_round_trip() {
        let cmd = NvmeCommand::Identify {
            target: IdentifyTarget::Namespace { nsid: 1 },
            buf_iova: 0x2_0000_0000,
            opaque_id: 43,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_identify_active_ns_list_round_trip() {
        let cmd = NvmeCommand::Identify {
            target: IdentifyTarget::ActiveNsList,
            buf_iova: 0x3_0000_0000,
            opaque_id: 44,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_read_round_trip() {
        let cmd = NvmeCommand::Read {
            nsid: 1,
            lba: 0x1_0000,
            block_count: 8,
            buf_iova: 0x4_0000_0000,
            opaque_id: 100,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_read_at_max_block_count_round_trip() {
        let cmd = NvmeCommand::Read {
            nsid: 1,
            lba: 0,
            block_count: MAX_BLOCK_COUNT_PER_REQUEST,
            buf_iova: 0x5_0000_0000,
            opaque_id: 101,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_write_round_trip() {
        let cmd = NvmeCommand::Write {
            nsid: 1,
            lba: 0xDEAD_BEEF,
            block_count: 16,
            buf_iova: 0x6_0000_0000,
            opaque_id: 200,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_flush_round_trip() {
        let cmd = NvmeCommand::Flush {
            nsid: 1,
            opaque_id: 300,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_discard_round_trip() {
        let cmd = NvmeCommand::Discard {
            nsid: 1,
            lba: 0x1000,
            block_count: 64,
            opaque_id: 400,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_get_log_page_smart_round_trip() {
        let cmd = NvmeCommand::GetLogPage {
            log_id: 0x02, // SMART/Health Information
            buf_iova: 0x7_0000_0000,
            opaque_id: 500,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    #[test]
    fn nvme_command_format_nvm_round_trip() {
        let cmd = NvmeCommand::FormatNVM {
            nsid: 1,
            opaque_id: 600,
        };
        assert_eq!(round_trip_cmd(cmd), cmd);
    }

    // -------------------------------------------------------------------
    // NvmeEvent round-trips
    // -------------------------------------------------------------------

    #[test]
    fn nvme_event_command_complete_success_round_trip() {
        let evt = NvmeEvent::CommandComplete {
            opaque_id: 42,
            status: 0x0000, // success
            cdw0: 0,
        };
        assert_eq!(round_trip_evt(evt), evt);
    }

    #[test]
    fn nvme_event_command_complete_with_status_round_trip() {
        let evt = NvmeEvent::CommandComplete {
            opaque_id: 42,
            status: 0x4080, // SCT=0x2 (Command-Specific), SC=0x80
            cdw0: 0xDEAD_BEEF,
        };
        assert_eq!(round_trip_evt(evt), evt);
    }

    #[test]
    fn nvme_event_async_event_round_trip() {
        let evt = NvmeEvent::AsyncEvent {
            event_type: 1,  // SMART/Health
            event_info: 0,  // Available Spare Below Threshold
            log_page: 0x02, // SMART log
        };
        assert_eq!(round_trip_evt(evt), evt);
    }

    #[test]
    fn nvme_event_link_state_change_up_round_trip() {
        let evt = NvmeEvent::LinkStateChange { link_up: true };
        assert_eq!(round_trip_evt(evt), evt);
    }

    #[test]
    fn nvme_event_link_state_change_down_round_trip() {
        let evt = NvmeEvent::LinkStateChange { link_up: false };
        assert_eq!(round_trip_evt(evt), evt);
    }

    #[test]
    fn nvme_event_controller_fatal_round_trip() {
        let evt = NvmeEvent::ControllerFatal {
            cstatus: 0x0000_0002, // CSTS.CFS=1
        };
        assert_eq!(round_trip_evt(evt), evt);
    }

    // -------------------------------------------------------------------
    // Wire invariants
    // -------------------------------------------------------------------

    #[test]
    fn nvme_command_encoding_is_deterministic() {
        let cmd = NvmeCommand::Read {
            nsid: 1,
            lba: 0x1_0000,
            block_count: 8,
            buf_iova: 0x4_0000_0000,
            opaque_id: 100,
        };
        let a = crate::wire::encode_canonical(&cmd).expect("encode a");
        let b = crate::wire::encode_canonical(&cmd).expect("encode b");
        assert_eq!(a, b);
    }

    #[test]
    fn nvme_event_encoding_is_deterministic() {
        let evt = NvmeEvent::CommandComplete {
            opaque_id: 42,
            status: 0x4080,
            cdw0: 0xDEAD_BEEF,
        };
        let a = crate::wire::encode_canonical(&evt).expect("encode a");
        let b = crate::wire::encode_canonical(&evt).expect("encode b");
        assert_eq!(a, b);
    }

    #[test]
    fn nvme_command_decode_rejects_trailing_bytes() {
        let cmd = NvmeCommand::Flush {
            nsid: 1,
            opaque_id: 300,
        };
        let mut bytes = crate::wire::encode_canonical(&cmd).expect("encode");
        bytes.push(0x00); // trailing byte
        let decoded: Result<NvmeCommand, _> = crate::wire::decode_canonical(&bytes);
        assert!(
            decoded.is_err(),
            "decode_canonical MUST reject trailing bytes"
        );
    }

    #[test]
    fn nvme_command_decode_rejects_truncated_input() {
        let cmd = NvmeCommand::Read {
            nsid: 1,
            lba: 0x1_0000,
            block_count: 8,
            buf_iova: 0x4_0000_0000,
            opaque_id: 100,
        };
        let bytes = crate::wire::encode_canonical(&cmd).expect("encode");
        let truncated = &bytes[..bytes.len() - 1];
        let decoded: Result<NvmeCommand, _> = crate::wire::decode_canonical(truncated);
        assert!(
            decoded.is_err(),
            "decode_canonical MUST reject truncated input"
        );
    }

    #[test]
    fn nvme_event_decode_rejects_empty_input() {
        let decoded: Result<NvmeEvent, _> = crate::wire::decode_canonical(&[]);
        assert!(decoded.is_err(), "empty input MUST surface as decode error");
    }

    // -------------------------------------------------------------------
    // Discriminator distinctness
    // -------------------------------------------------------------------

    #[test]
    fn nvme_command_variants_are_distinguishable_on_the_wire() {
        // Postcard encodes the enum discriminant as the first byte
        // (variable-length-int, but variants ≤ 127 fit in 1 byte).
        // Failing this test means two variants share the same
        // discriminant — a copy-paste regression on the enum.
        let identify = crate::wire::encode_canonical(&NvmeCommand::Identify {
            target: IdentifyTarget::Controller,
            buf_iova: 0,
            opaque_id: 1,
        })
        .expect("identify");
        let read = crate::wire::encode_canonical(&NvmeCommand::Read {
            nsid: 0,
            lba: 0,
            block_count: 1,
            buf_iova: 0,
            opaque_id: 1,
        })
        .expect("read");
        let write = crate::wire::encode_canonical(&NvmeCommand::Write {
            nsid: 0,
            lba: 0,
            block_count: 1,
            buf_iova: 0,
            opaque_id: 1,
        })
        .expect("write");
        let flush = crate::wire::encode_canonical(&NvmeCommand::Flush {
            nsid: 0,
            opaque_id: 1,
        })
        .expect("flush");
        let discard = crate::wire::encode_canonical(&NvmeCommand::Discard {
            nsid: 0,
            lba: 0,
            block_count: 1,
            opaque_id: 1,
        })
        .expect("discard");
        let get_log = crate::wire::encode_canonical(&NvmeCommand::GetLogPage {
            log_id: 0x02,
            buf_iova: 0,
            opaque_id: 1,
        })
        .expect("get_log");
        let format = crate::wire::encode_canonical(&NvmeCommand::FormatNVM {
            nsid: 0,
            opaque_id: 1,
        })
        .expect("format");
        let firsts = [
            identify[0],
            read[0],
            write[0],
            flush[0],
            discard[0],
            get_log[0],
            format[0],
        ];
        for i in 0..firsts.len() {
            for j in (i + 1)..firsts.len() {
                assert_ne!(
                    firsts[i], firsts[j],
                    "NvmeCommand variants {i} and {j} share discriminant byte"
                );
            }
        }
    }

    #[test]
    fn nvme_event_variants_are_distinguishable_on_the_wire() {
        let cmd_complete = crate::wire::encode_canonical(&NvmeEvent::CommandComplete {
            opaque_id: 1,
            status: 0,
            cdw0: 0,
        })
        .expect("cmd_complete");
        let async_event = crate::wire::encode_canonical(&NvmeEvent::AsyncEvent {
            event_type: 0,
            event_info: 0,
            log_page: 0,
        })
        .expect("async_event");
        let link = crate::wire::encode_canonical(&NvmeEvent::LinkStateChange { link_up: true })
            .expect("link");
        let fatal = crate::wire::encode_canonical(&NvmeEvent::ControllerFatal { cstatus: 0 })
            .expect("fatal");
        let firsts = [cmd_complete[0], async_event[0], link[0], fatal[0]];
        for i in 0..firsts.len() {
            for j in (i + 1)..firsts.len() {
                assert_ne!(
                    firsts[i], firsts[j],
                    "NvmeEvent variants {i} and {j} share discriminant byte"
                );
            }
        }
    }

    #[test]
    fn identify_target_variants_are_distinguishable_on_the_wire() {
        let controller = crate::wire::encode_canonical(&IdentifyTarget::Controller).expect("ctrl");
        let namespace =
            crate::wire::encode_canonical(&IdentifyTarget::Namespace { nsid: 1 }).expect("ns");
        let list = crate::wire::encode_canonical(&IdentifyTarget::ActiveNsList).expect("list");
        assert_ne!(controller[0], namespace[0]);
        assert_ne!(controller[0], list[0]);
        assert_ne!(namespace[0], list[0]);
    }

    // -------------------------------------------------------------------
    // Cross-channel integration (cmd + event correlation)
    // -------------------------------------------------------------------

    #[test]
    fn opaque_id_round_trips_unchanged_command_to_event() {
        // The driver's responsibility is to echo `opaque_id`
        // verbatim. Sanity-check the type-level invariant by
        // round-tripping a non-trivial 64-bit value through both
        // sides and asserting equality.
        let id = 0xCAFE_F00D_DEAD_BEEF_u64;
        let cmd = NvmeCommand::Read {
            nsid: 1,
            lba: 0,
            block_count: 1,
            buf_iova: 0,
            opaque_id: id,
        };
        let evt = NvmeEvent::CommandComplete {
            opaque_id: id,
            status: 0,
            cdw0: 0,
        };
        let cmd_back = round_trip_cmd(cmd);
        let evt_back = round_trip_evt(evt);
        let NvmeCommand::Read {
            opaque_id: cmd_id, ..
        } = cmd_back
        else {
            panic!("unexpected command variant")
        };
        let NvmeEvent::CommandComplete {
            opaque_id: evt_id, ..
        } = evt_back
        else {
            panic!("unexpected event variant")
        };
        assert_eq!(cmd_id, id);
        assert_eq!(evt_id, id);
        assert_eq!(cmd_id, evt_id);
    }
}

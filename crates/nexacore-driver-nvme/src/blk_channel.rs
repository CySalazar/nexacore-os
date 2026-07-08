//! BLK IPC channel handler — fixed-wire NVMe dispatch scaffold.
//!
//! This module bridges the fixed-size [`nexacore_driver_shared::blk`] wire
//! types (the transport layer for `nexacore.svc.blk.<diskN>` ring-buffer
//! frames) to the NVMe namespace underneath.
//!
//! ## Relationship to `blk_gateway`
//!
//! [`crate::blk_gateway`] bridges the *higher-level*
//! `nexacore_types::blk::BlkRequest` / `BlkResponse` enums (postcard-encoded
//! over the capability-gated channel) to NVMe SQE/CQE encoding. This
//! module handles the *lower-level* fixed-size IPC ring frames defined in
//! [`nexacore_driver_shared::blk`]. The two layers are complementary: the
//! channel handler decodes a frame, forwards to the gateway, and re-encodes
//! the result. In Phase-1 the inner NVMe dispatch is scaffolded (returns
//! synthetic responses) — the actual queue submission path lives in
//! `nexacore-driver-nvme-image` (P6.7.8.5).
//!
//! ## Phase-1 scaffold contract
//!
//! [`BlkChannelHandler::handle_request`] implements the following scaffold
//! policy per NCIP-Driver-NVMe-014 § S4:
//!
//! - [`BlkOpCode::Read`]  — returns [`BlkStatus::Ok`] with
//!   `bytes_transferred = count * sector_size`.
//! - [`BlkOpCode::Write`] — returns [`BlkStatus::Ok`] with
//!   `bytes_transferred = count * sector_size`.
//! - [`BlkOpCode::Flush`] — returns [`BlkStatus::Ok`] with
//!   `bytes_transferred = 0`.
//! - [`BlkOpCode::Discard`] — returns [`BlkStatus::Ok`] with
//!   `bytes_transferred = 0`.
//!
//! Out-of-range sector validation is performed: if
//! `req.sector + req.count as u64 > total_sectors`, the handler returns
//! [`BlkStatus::InvalidSector`] with `bytes_transferred = 0`.
//!
//! If the namespace is read-only and the operation is a write or discard,
//! [`BlkStatus::ReadOnly`] is returned.
//!
//! ## Cross-references
//!
//! - NCIP-Driver-NVMe-014 § S4 (BLK channel service contract)
//! - [`nexacore_driver_shared::blk`] — fixed-size wire frame types
//! - [`crate::blk_gateway`] — higher-level postcard-based bridge
//! - [`crate::namespace_map::NamespaceDescriptor`] — namespace metadata

use nexacore_driver_shared::blk::{BlkCapacity, BlkOpCode, BlkRequest, BlkResponse, BlkStatus};

// ---------------------------------------------------------------------------
// BlkChannelHandler
// ---------------------------------------------------------------------------

/// Handler for a single `nexacore.svc.blk.<diskN>` IPC channel instance.
///
/// Each `BlkChannelHandler` is bound to one logical disk (channel) and one
/// NVMe namespace. The handler decodes incoming [`BlkRequest`] frames from
/// the ring buffer, performs lightweight validation, and returns the
/// matching [`BlkResponse`] frame (Phase-1 scaffold responses — no actual
/// queue submission).
///
/// # Example
///
/// ```
/// use nexacore_driver_nvme::blk_channel::BlkChannelHandler;
/// use nexacore_driver_shared::blk::{BlkOpCode, BlkRequest, BlkStatus};
///
/// let handler = BlkChannelHandler::new(
///     /* channel_id  */ 0, /* nsid        */ 1, /* total_sectors */ 4096,
///     /* sector_size */ 512, /* read_only   */ false,
/// );
///
/// let req = BlkRequest::new(BlkOpCode::Read, 0, 8, 0x1_0000, 42);
/// let resp = handler.handle_request(&req);
/// assert_eq!(resp.request_id, 42);
/// assert_eq!(resp.status, BlkStatus::Ok);
/// assert_eq!(resp.bytes_transferred, 8 * 512);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlkChannelHandler {
    /// IPC channel identifier assigned by the kernel registry at
    /// `RegisterBlkChannel` time (NCIP-Driver-NVMe-014 § S6 step 12).
    channel_id: u64,
    /// NVMe Namespace Identifier this channel is bound to.
    nsid: u32,
    /// Total number of addressable sectors in the namespace.
    total_sectors: u64,
    /// Sector size in bytes (must be 512 for Phase-1 wire-level; the
    /// NVMe layer uses 4 KiB LBAs but the BLK channel transport uses
    /// 512-byte sector units per NCIP-014 § M4 to stay compatible with
    /// legacy block-device consumers).
    sector_size: u32,
    /// `true` if the namespace is write-protected.
    read_only: bool,
}

impl BlkChannelHandler {
    /// Construct a new handler bound to the given channel and namespace.
    ///
    /// `channel_id` is the opaque identifier returned by `IpcCreateChannel`
    /// at bring-up step 12. `nsid` is the NVMe Namespace Identifier.
    /// `total_sectors` is the namespace size in `sector_size`-byte units.
    /// `sector_size` is the number of bytes per sector. `read_only` must
    /// be `true` if the namespace's `NSATTR.WriteProtected` flag is set.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_nvme::blk_channel::BlkChannelHandler;
    ///
    /// let handler = BlkChannelHandler::new(7, 1, 2048, 512, false);
    /// assert_eq!(handler.channel_id(), 7);
    /// assert_eq!(handler.nsid(), 1);
    /// ```
    #[must_use]
    pub const fn new(
        channel_id: u64,
        nsid: u32,
        total_sectors: u64,
        sector_size: u32,
        read_only: bool,
    ) -> Self {
        Self {
            channel_id,
            nsid,
            total_sectors,
            sector_size,
            read_only,
        }
    }

    /// Return the IPC channel identifier.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_nvme::blk_channel::BlkChannelHandler;
    ///
    /// let h = BlkChannelHandler::new(99, 1, 1024, 512, false);
    /// assert_eq!(h.channel_id(), 99);
    /// ```
    #[must_use]
    pub const fn channel_id(&self) -> u64 {
        self.channel_id
    }

    /// Return the NVMe Namespace Identifier this handler is bound to.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_nvme::blk_channel::BlkChannelHandler;
    ///
    /// let h = BlkChannelHandler::new(0, 3, 1024, 512, false);
    /// assert_eq!(h.nsid(), 3);
    /// ```
    #[must_use]
    pub const fn nsid(&self) -> u32 {
        self.nsid
    }

    /// Process one [`BlkRequest`] and return the matching [`BlkResponse`].
    ///
    /// ## Phase-1 scaffold policy
    ///
    /// - **Read / Write**: validate that `sector + count as u64 <= total_sectors`.
    ///   On out-of-range, return [`BlkStatus::InvalidSector`] with
    ///   `bytes_transferred = 0`. On range-valid, return [`BlkStatus::Ok`]
    ///   with `bytes_transferred = count * sector_size` (capped at
    ///   [`u32::MAX`] via saturating multiply).
    /// - **Write / Discard** on a read-only namespace: return
    ///   [`BlkStatus::ReadOnly`] with `bytes_transferred = 0` before the
    ///   range check.
    /// - **Flush**: always returns [`BlkStatus::Ok`] with
    ///   `bytes_transferred = 0`.
    /// - **Discard**: range-validate then return [`BlkStatus::Ok`] with
    ///   `bytes_transferred = 0` (discard is advisory and carries no data).
    ///
    /// The `request_id` is always echoed from the incoming request.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_nvme::blk_channel::BlkChannelHandler;
    /// use nexacore_driver_shared::blk::{BlkOpCode, BlkRequest, BlkStatus};
    ///
    /// let h = BlkChannelHandler::new(0, 1, 100, 512, false);
    ///
    /// // Out-of-range read.
    /// let req = BlkRequest::new(BlkOpCode::Read, 99, 2, 0, 1);
    /// let resp = h.handle_request(&req);
    /// assert_eq!(resp.status, BlkStatus::InvalidSector);
    /// assert_eq!(resp.bytes_transferred, 0);
    ///
    /// // Zero-sector flush.
    /// let flush = BlkRequest::new(BlkOpCode::Flush, 0, 0, 0, 2);
    /// let r = h.handle_request(&flush);
    /// assert_eq!(r.status, BlkStatus::Ok);
    /// assert_eq!(r.bytes_transferred, 0);
    /// ```
    #[must_use]
    pub fn handle_request(&self, req: &BlkRequest) -> BlkResponse {
        let request_id = req.request_id;

        match req.op {
            BlkOpCode::Read => {
                if self.sector_out_of_range(req.sector, req.count) {
                    return BlkResponse {
                        request_id,
                        status: BlkStatus::InvalidSector,
                        bytes_transferred: 0,
                    };
                }
                BlkResponse {
                    request_id,
                    status: BlkStatus::Ok,
                    bytes_transferred: self.bytes_for(req.count),
                }
            }
            BlkOpCode::Write => {
                if self.read_only {
                    return BlkResponse {
                        request_id,
                        status: BlkStatus::ReadOnly,
                        bytes_transferred: 0,
                    };
                }
                if self.sector_out_of_range(req.sector, req.count) {
                    return BlkResponse {
                        request_id,
                        status: BlkStatus::InvalidSector,
                        bytes_transferred: 0,
                    };
                }
                BlkResponse {
                    request_id,
                    status: BlkStatus::Ok,
                    bytes_transferred: self.bytes_for(req.count),
                }
            }
            BlkOpCode::Flush => BlkResponse {
                request_id,
                status: BlkStatus::Ok,
                bytes_transferred: 0,
            },
            BlkOpCode::Discard => {
                if self.read_only {
                    return BlkResponse {
                        request_id,
                        status: BlkStatus::ReadOnly,
                        bytes_transferred: 0,
                    };
                }
                if self.sector_out_of_range(req.sector, req.count) {
                    return BlkResponse {
                        request_id,
                        status: BlkStatus::InvalidSector,
                        bytes_transferred: 0,
                    };
                }
                // Discard is advisory; no data is transferred.
                BlkResponse {
                    request_id,
                    status: BlkStatus::Ok,
                    bytes_transferred: 0,
                }
            }
        }
    }

    /// Report the capacity of the device namespace this handler is bound to.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_nvme::blk_channel::BlkChannelHandler;
    ///
    /// let h = BlkChannelHandler::new(0, 1, 8192, 512, true);
    /// let cap = h.report_capacity();
    /// assert_eq!(cap.total_sectors, 8192);
    /// assert_eq!(cap.sector_size, 512);
    /// assert!(cap.read_only);
    /// ```
    #[must_use]
    pub const fn report_capacity(&self) -> BlkCapacity {
        BlkCapacity {
            total_sectors: self.total_sectors,
            sector_size: self.sector_size,
            read_only: self.read_only,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Return `true` if `sector + count as u64` would exceed `total_sectors`.
    ///
    /// Uses checked arithmetic to avoid overflow on hostile inputs: if
    /// `sector.checked_add(count as u64)` overflows, the range is
    /// trivially out of bounds. A `count` of 0 is treated as valid (an
    /// empty transfer never exceeds any bound).
    fn sector_out_of_range(&self, sector: u64, count: u32) -> bool {
        // `checked_add` returns `None` on overflow — `is_none_or` treats
        // a `None` result as `true` (out of range), which is correct because
        // no finite `total_sectors` value can be exceeded by an overflow.
        sector
            .checked_add(u64::from(count))
            .is_none_or(|end| end > self.total_sectors)
    }

    /// Compute `count * sector_size` saturating at [`u32::MAX`].
    ///
    /// Saturation prevents overflow on hypothetically large
    /// `count * sector_size` products; the actual NVMe stack is bounded
    /// by `MAX_BLOCK_COUNT_PER_REQUEST * BLOCK_SIZE_BYTES` which is well
    /// within `u32::MAX`, but the scaffold must handle all inputs safely.
    fn bytes_for(&self, count: u32) -> u32 {
        count.saturating_mul(self.sector_size)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use nexacore_driver_shared::blk::BlkRequest;

    use super::*;

    // Build a test handler with 1 000 sectors, 512 bytes per sector.
    fn handler() -> BlkChannelHandler {
        BlkChannelHandler::new(0, 1, 1_000, 512, false)
    }

    // Build a read-only handler.
    fn ro_handler() -> BlkChannelHandler {
        BlkChannelHandler::new(1, 1, 1_000, 512, true)
    }

    // -----------------------------------------------------------------------
    // Constructor and accessor
    // -----------------------------------------------------------------------

    #[test]
    fn constructor_stores_all_fields() {
        let h = BlkChannelHandler::new(7, 3, 2048, 4096, true);
        assert_eq!(h.channel_id(), 7);
        assert_eq!(h.nsid(), 3);
    }

    // -----------------------------------------------------------------------
    // handle_request — Read
    // -----------------------------------------------------------------------

    #[test]
    fn read_in_range_returns_ok_with_correct_bytes() {
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Read, 0, 8, 0x1_0000, 1);
        let resp = h.handle_request(&req);
        assert_eq!(resp.request_id, 1);
        assert_eq!(resp.status, BlkStatus::Ok);
        assert_eq!(resp.bytes_transferred, 8 * 512);
    }

    #[test]
    fn read_at_last_valid_sector_returns_ok() {
        // sector=999, count=1 → end=1000 == total_sectors → valid
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Read, 999, 1, 0, 2);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::Ok);
        assert_eq!(resp.bytes_transferred, 512);
    }

    #[test]
    fn read_past_end_returns_invalid_sector() {
        // sector=999, count=2 → end=1001 > 1000
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Read, 999, 2, 0, 3);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::InvalidSector);
        assert_eq!(resp.bytes_transferred, 0);
    }

    #[test]
    fn read_sector_exactly_at_total_returns_invalid_sector() {
        // sector=1000, count=1 → end=1001 > 1000
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Read, 1_000, 1, 0, 4);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::InvalidSector);
    }

    #[test]
    fn read_zero_count_returns_ok_with_zero_bytes() {
        // Zero-sector read: end=sector+0=sector; always in range if sector <= total.
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Read, 0, 0, 0, 5);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::Ok);
        assert_eq!(resp.bytes_transferred, 0);
    }

    #[test]
    fn read_echoes_request_id() {
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Read, 0, 1, 0, 0xDEAD_BEEF_CAFE_0001);
        let resp = h.handle_request(&req);
        assert_eq!(resp.request_id, 0xDEAD_BEEF_CAFE_0001);
    }

    // -----------------------------------------------------------------------
    // handle_request — Write
    // -----------------------------------------------------------------------

    #[test]
    fn write_in_range_returns_ok_with_correct_bytes() {
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Write, 10, 4, 0x2_0000, 10);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::Ok);
        assert_eq!(resp.bytes_transferred, 4 * 512);
    }

    #[test]
    fn write_past_end_returns_invalid_sector() {
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Write, 998, 5, 0, 11);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::InvalidSector);
        assert_eq!(resp.bytes_transferred, 0);
    }

    #[test]
    fn write_on_read_only_returns_read_only() {
        let h = ro_handler();
        let req = BlkRequest::new(BlkOpCode::Write, 0, 1, 0, 12);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::ReadOnly);
        assert_eq!(resp.bytes_transferred, 0);
    }

    #[test]
    fn write_read_only_check_precedes_range_check() {
        // Even an out-of-range sector returns ReadOnly (not InvalidSector)
        // when the namespace is write-protected.
        let h = ro_handler();
        let req = BlkRequest::new(BlkOpCode::Write, u64::MAX, u32::MAX, 0, 13);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::ReadOnly);
    }

    // -----------------------------------------------------------------------
    // handle_request — Flush
    // -----------------------------------------------------------------------

    #[test]
    fn flush_returns_ok_with_zero_bytes() {
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Flush, 0, 0, 0, 20);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::Ok);
        assert_eq!(resp.bytes_transferred, 0);
    }

    #[test]
    fn flush_on_read_only_returns_ok() {
        // Flush is not a write; read-only restriction does not apply.
        let h = ro_handler();
        let req = BlkRequest::new(BlkOpCode::Flush, 0, 0, 0, 21);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::Ok);
    }

    // -----------------------------------------------------------------------
    // handle_request — Discard
    // -----------------------------------------------------------------------

    #[test]
    fn discard_in_range_returns_ok_with_zero_bytes() {
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Discard, 0, 10, 0, 30);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::Ok);
        assert_eq!(resp.bytes_transferred, 0);
    }

    #[test]
    fn discard_past_end_returns_invalid_sector() {
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Discard, 995, 10, 0, 31);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::InvalidSector);
    }

    #[test]
    fn discard_on_read_only_returns_read_only() {
        let h = ro_handler();
        let req = BlkRequest::new(BlkOpCode::Discard, 0, 5, 0, 32);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::ReadOnly);
    }

    // -----------------------------------------------------------------------
    // handle_request — edge: max sector values
    // -----------------------------------------------------------------------

    #[test]
    fn read_u64_max_sector_returns_invalid_sector() {
        // u64::MAX + 1 overflows → checked_add returns None → out of range.
        let h = handler();
        let req = BlkRequest::new(BlkOpCode::Read, u64::MAX, 1, 0, 40);
        let resp = h.handle_request(&req);
        assert_eq!(resp.status, BlkStatus::InvalidSector);
    }

    // -----------------------------------------------------------------------
    // report_capacity
    // -----------------------------------------------------------------------

    #[test]
    fn report_capacity_returns_correct_values() {
        let h = BlkChannelHandler::new(0, 1, 8192, 4096, false);
        let cap = h.report_capacity();
        assert_eq!(cap.total_sectors, 8192);
        assert_eq!(cap.sector_size, 4096);
        assert!(!cap.read_only);
    }

    #[test]
    fn report_capacity_reflects_read_only_flag() {
        let h = ro_handler();
        let cap = h.report_capacity();
        assert!(cap.read_only);
    }

    #[test]
    fn report_capacity_is_consistent_with_handle_request_range() {
        // The total_sectors in capacity must match the range enforcement
        // used by handle_request. Verify by issuing a read at exactly
        // total_sectors - 1 (valid) and total_sectors (invalid).
        let h = BlkChannelHandler::new(0, 1, 500, 512, false);
        let cap = h.report_capacity();

        let valid_req = BlkRequest::new(BlkOpCode::Read, cap.total_sectors - 1, 1, 0, 0);
        assert_eq!(h.handle_request(&valid_req).status, BlkStatus::Ok);

        let invalid_req = BlkRequest::new(BlkOpCode::Read, cap.total_sectors, 1, 0, 1);
        assert_eq!(
            h.handle_request(&invalid_req).status,
            BlkStatus::InvalidSector
        );
    }
}

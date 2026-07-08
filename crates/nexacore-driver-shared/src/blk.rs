//! Fixed-size wire types for the `nexacore.svc.blk.<diskN>` IPC channel.
//!
//! ## Purpose
//!
//! This module defines the transport-layer wire frame types used by the
//! `nexacore.svc.blk.<diskN>` service channel as specified in
//! NCIP-Driver-NVMe-014 § S4. They complement the higher-level
//! `nexacore_types::blk::BlkRequest` / `BlkResponse` enums (which use
//! postcard canonical encoding via `nexacore_types::wire::encode_canonical`):
//! the types here are **fixed-size, serde-free frames** suitable for
//! direct memory-mapped IPC ring buffers where the payload size must be
//! known statically at both ends without a framing header.
//!
//! ## Wire format invariants
//!
//! All multi-byte fields are **little-endian** (`u64::to_le_bytes`,
//! `u32::to_le_bytes`). No implicit padding. The layout is fully
//! determined by the order of fields in each struct — changing field
//! order is a breaking wire-format change and requires an NCIP update.
//!
//! ### `BlkRequest` wire layout ([`crate::blk::BLK_REQUEST_WIRE_SIZE`] = 29 bytes)
//!
//! ```text
//! Offset   Size   Field
//! ──────   ────   ─────────────────────────────────────────────
//!  0        1 B   op_code       (u8, BlkOpCode discriminant)
//!  1        8 B   sector        (u64 LE — starting sector)
//!  9        4 B   count         (u32 LE — number of sectors)
//! 13        8 B   buffer_va     (u64 LE — user-space VA)
//! 21        8 B   request_id    (u64 LE — caller correlation ID)
//! ```
//!
//! ### `BlkResponse` wire layout ([`crate::blk::BLK_RESPONSE_WIRE_SIZE`] = 13 bytes)
//!
//! ```text
//! Offset   Size   Field
//! ──────   ────   ─────────────────────────────────────────────
//!  0        8 B   request_id        (u64 LE — echoes request)
//!  8        1 B   status            (u8, BlkStatus discriminant)
//!  9        4 B   bytes_transferred (u32 LE)
//! ```
//!
//! ## No `unsafe`
//!
//! All encode/decode paths use safe slice operations, `copy_from_slice`,
//! and `to_le_bytes` / `from_le_bytes` — no `ptr::read_unaligned` or
//! `transmute`.
//!
//! ## Cross-references
//!
//! - NCIP-Driver-NVMe-014 § S4 (BLK channel service contract)
//! - `nexacore_types::blk` — higher-level protocol types (postcard-encoded)
//! - `crates/nexacore-driver-nvme/src/blk_channel.rs` — channel handler

// ---------------------------------------------------------------------------
// Wire size constants
// ---------------------------------------------------------------------------

/// Byte length of the fixed-size [`BlkRequest`] wire frame.
///
/// Layout: `op_code(1) + sector(8) + count(4) + buffer_va(8) + request_id(8)`.
///
/// # Example
///
/// ```
/// assert_eq!(nexacore_driver_shared::blk::BLK_REQUEST_WIRE_SIZE, 29);
/// ```
pub const BLK_REQUEST_WIRE_SIZE: usize = 29;

/// Byte length of the fixed-size [`BlkResponse`] wire frame.
///
/// Layout: `request_id(8) + status(1) + bytes_transferred(4)`.
///
/// # Example
///
/// ```
/// assert_eq!(nexacore_driver_shared::blk::BLK_RESPONSE_WIRE_SIZE, 13);
/// ```
pub const BLK_RESPONSE_WIRE_SIZE: usize = 13;

// ---------------------------------------------------------------------------
// BlkOpCode
// ---------------------------------------------------------------------------

/// Discriminant for the block I/O operation carried in a [`BlkRequest`].
///
/// The `repr(u8)` discriminant is the first byte of the
/// [`BLK_REQUEST_WIRE_SIZE`]-byte fixed wire frame and determines which
/// device operation the driver must execute.
///
/// # Example
///
/// ```
/// use nexacore_driver_shared::blk::BlkOpCode;
/// assert_eq!(BlkOpCode::Read as u8, 0);
/// assert_eq!(BlkOpCode::Write as u8, 1);
/// assert_eq!(BlkOpCode::Flush as u8, 2);
/// assert_eq!(BlkOpCode::Discard as u8, 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlkOpCode {
    /// Read sectors from the device into the caller's buffer.
    Read = 0,
    /// Write sectors from the caller's buffer to the device.
    Write = 1,
    /// Flush the device's volatile write cache to persistent storage.
    Flush = 2,
    /// Hint that a range of sectors may be discarded (TRIM/Unmap).
    Discard = 3,
}

impl BlkOpCode {
    /// Decode a `u8` discriminant into a `BlkOpCode`.
    ///
    /// Returns `None` for any value outside `[0, 3]`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_shared::blk::BlkOpCode;
    /// assert_eq!(BlkOpCode::from_u8(0), Some(BlkOpCode::Read));
    /// assert_eq!(BlkOpCode::from_u8(4), None);
    /// ```
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Flush),
            3 => Some(Self::Discard),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BlkRequest
// ---------------------------------------------------------------------------

/// A driver-agnostic block I/O request sent over the BLK service channel.
///
/// The struct is fixed-size and can be encoded into a
/// [`BLK_REQUEST_WIRE_SIZE`]-byte frame with [`BlkRequest::encode`] or
/// recovered from one with [`BlkRequest::decode`]. Both encode and decode
/// are deterministic and endian-explicit (little-endian for all multi-byte
/// fields).
///
/// # Example
///
/// ```
/// use nexacore_driver_shared::blk::{BLK_REQUEST_WIRE_SIZE, BlkOpCode, BlkRequest};
///
/// let req = BlkRequest::new(BlkOpCode::Read, 0, 8, 0x1000_0000, 42);
/// let encoded = req.encode();
/// assert_eq!(encoded.len(), BLK_REQUEST_WIRE_SIZE);
/// let decoded = BlkRequest::decode(&encoded).expect("valid frame");
/// assert_eq!(decoded, req);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlkRequest {
    /// The type of I/O operation requested.
    pub op: BlkOpCode,
    /// Starting sector number (512-byte units).
    pub sector: u64,
    /// Number of sectors to transfer.
    pub count: u32,
    /// User-space virtual address of the data buffer.
    pub buffer_va: u64,
    /// Caller-assigned correlation identifier; echoed in the response.
    pub request_id: u64,
}

impl BlkRequest {
    /// Construct a new `BlkRequest` with the given fields.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_shared::blk::{BlkOpCode, BlkRequest};
    ///
    /// let req = BlkRequest::new(BlkOpCode::Write, 128, 4, 0x2000_0000, 7);
    /// assert_eq!(req.op, BlkOpCode::Write);
    /// assert_eq!(req.sector, 128);
    /// assert_eq!(req.count, 4);
    /// assert_eq!(req.buffer_va, 0x2000_0000);
    /// assert_eq!(req.request_id, 7);
    /// ```
    #[must_use]
    pub const fn new(
        op: BlkOpCode,
        sector: u64,
        count: u32,
        buffer_va: u64,
        request_id: u64,
    ) -> Self {
        Self {
            op,
            sector,
            count,
            buffer_va,
            request_id,
        }
    }

    /// Encode this request into the fixed [`BLK_REQUEST_WIRE_SIZE`]-byte
    /// little-endian frame.
    ///
    /// The layout is:
    /// - byte 0: `op` discriminant (`u8`)
    /// - bytes 1..9: `sector` (`u64` LE)
    /// - bytes 9..13: `count` (`u32` LE)
    /// - bytes 13..21: `buffer_va` (`u64` LE)
    /// - bytes 21..29: `request_id` (`u64` LE)
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_shared::blk::{BlkOpCode, BlkRequest};
    ///
    /// let req = BlkRequest::new(BlkOpCode::Read, 1, 1, 0x1000, 99);
    /// let wire = req.encode();
    /// // First byte is the op discriminant for Read (0).
    /// assert_eq!(wire[0], 0);
    /// // Sector field is 1u64 little-endian starting at byte 1.
    /// assert_eq!(&wire[1..9], &1u64.to_le_bytes());
    /// ```
    #[must_use]
    pub fn encode(&self) -> [u8; BLK_REQUEST_WIRE_SIZE] {
        let mut buf = [0u8; BLK_REQUEST_WIRE_SIZE];
        // byte 0 — op discriminant
        buf[0] = self.op as u8;
        // bytes 1..9 — sector (u64 LE)
        buf[1..9].copy_from_slice(&self.sector.to_le_bytes());
        // bytes 9..13 — count (u32 LE)
        buf[9..13].copy_from_slice(&self.count.to_le_bytes());
        // bytes 13..21 — buffer_va (u64 LE)
        buf[13..21].copy_from_slice(&self.buffer_va.to_le_bytes());
        // bytes 21..29 — request_id (u64 LE)
        buf[21..29].copy_from_slice(&self.request_id.to_le_bytes());
        buf
    }

    /// Decode a `BlkRequest` from a byte slice.
    ///
    /// The slice must be at least [`BLK_REQUEST_WIRE_SIZE`] bytes long.
    /// Only the first `BLK_REQUEST_WIRE_SIZE` bytes are consumed; any
    /// trailing bytes are ignored (callers that require strict length
    /// enforcement must check `bytes.len() == BLK_REQUEST_WIRE_SIZE`
    /// themselves).
    ///
    /// # Errors
    ///
    /// - [`BlkDecodeError::TooShort`] if `bytes.len() < BLK_REQUEST_WIRE_SIZE`.
    /// - [`BlkDecodeError::InvalidOpCode`] if byte 0 is not a valid
    ///   [`BlkOpCode`] discriminant (`0..=3`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_shared::blk::{BlkDecodeError, BlkOpCode, BlkRequest};
    ///
    /// // Too-short buffer.
    /// let err = BlkRequest::decode(&[0u8; 10]).unwrap_err();
    /// assert_eq!(err, BlkDecodeError::TooShort);
    ///
    /// // Invalid op-code byte.
    /// let mut bad = [0u8; 29];
    /// bad[0] = 0xFF;
    /// let err = BlkRequest::decode(&bad).unwrap_err();
    /// assert_eq!(err, BlkDecodeError::InvalidOpCode);
    /// ```
    pub fn decode(bytes: &[u8]) -> Result<Self, BlkDecodeError> {
        if bytes.len() < BLK_REQUEST_WIRE_SIZE {
            return Err(BlkDecodeError::TooShort);
        }
        // byte 0 — op discriminant.
        // `.first()` is safe: the length check above guarantees at least 29 bytes.
        let op_byte = *bytes.first().ok_or(BlkDecodeError::TooShort)?;
        let op = BlkOpCode::from_u8(op_byte).ok_or(BlkDecodeError::InvalidOpCode)?;
        // bytes 1..9 — sector (u64 LE).
        // The `try_into` on a `&[u8; 8]` slice cannot fail because `.get(1..9)`
        // returns exactly 8 bytes when `bytes.len() >= 29`.
        let sector = {
            let raw: [u8; 8] = bytes
                .get(1..9)
                .and_then(|s| s.try_into().ok())
                .ok_or(BlkDecodeError::TooShort)?;
            u64::from_le_bytes(raw)
        };
        // bytes 9..13 — count (u32 LE).
        let count = {
            let raw: [u8; 4] = bytes
                .get(9..13)
                .and_then(|s| s.try_into().ok())
                .ok_or(BlkDecodeError::TooShort)?;
            u32::from_le_bytes(raw)
        };
        // bytes 13..21 — buffer_va (u64 LE).
        let buffer_va = {
            let raw: [u8; 8] = bytes
                .get(13..21)
                .and_then(|s| s.try_into().ok())
                .ok_or(BlkDecodeError::TooShort)?;
            u64::from_le_bytes(raw)
        };
        // bytes 21..29 — request_id (u64 LE).
        let request_id = {
            let raw: [u8; 8] = bytes
                .get(21..29)
                .and_then(|s| s.try_into().ok())
                .ok_or(BlkDecodeError::TooShort)?;
            u64::from_le_bytes(raw)
        };
        Ok(Self {
            op,
            sector,
            count,
            buffer_va,
            request_id,
        })
    }
}

// ---------------------------------------------------------------------------
// BlkStatus
// ---------------------------------------------------------------------------

/// Completion status reported in a [`BlkResponse`].
///
/// The `repr(u8)` discriminant occupies byte 8 of the
/// [`BLK_RESPONSE_WIRE_SIZE`]-byte fixed wire frame.
///
/// # Example
///
/// ```
/// use nexacore_driver_shared::blk::BlkStatus;
/// assert_eq!(BlkStatus::Ok as u8, 0);
/// assert_eq!(BlkStatus::IoError as u8, 1);
/// assert_eq!(BlkStatus::Timeout as u8, 5);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlkStatus {
    /// The operation completed successfully.
    Ok = 0,
    /// A device-level I/O error occurred.
    IoError = 1,
    /// One or more sector addresses are outside the device's range.
    InvalidSector = 2,
    /// The device or the target namespace is write-protected.
    ReadOnly = 3,
    /// The device has been removed or is no longer accessible.
    DeviceGone = 4,
    /// The operation did not complete within the allowed time window.
    Timeout = 5,
}

impl BlkStatus {
    /// Decode a `u8` discriminant into a `BlkStatus`.
    ///
    /// Returns `None` for any value outside `[0, 5]`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_shared::blk::BlkStatus;
    /// assert_eq!(BlkStatus::from_u8(0), Some(BlkStatus::Ok));
    /// assert_eq!(BlkStatus::from_u8(6), None);
    /// ```
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::IoError),
            2 => Some(Self::InvalidSector),
            3 => Some(Self::ReadOnly),
            4 => Some(Self::DeviceGone),
            5 => Some(Self::Timeout),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BlkResponse
// ---------------------------------------------------------------------------

/// A completion notification returned by a storage driver for a
/// [`BlkRequest`].
///
/// The struct is fixed-size and can be encoded into a
/// [`BLK_RESPONSE_WIRE_SIZE`]-byte frame with [`BlkResponse::encode`] or
/// recovered from one with [`BlkResponse::decode`].
///
/// # Example
///
/// ```
/// use nexacore_driver_shared::blk::{BLK_RESPONSE_WIRE_SIZE, BlkResponse, BlkStatus};
///
/// let resp = BlkResponse {
///     request_id: 42,
///     status: BlkStatus::Ok,
///     bytes_transferred: 512,
/// };
/// let encoded = resp.encode();
/// assert_eq!(encoded.len(), BLK_RESPONSE_WIRE_SIZE);
/// let decoded = BlkResponse::decode(&encoded).expect("valid frame");
/// assert_eq!(decoded, resp);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlkResponse {
    /// Echoes the `request_id` field from the originating [`BlkRequest`].
    pub request_id: u64,
    /// Outcome of the operation.
    pub status: BlkStatus,
    /// Number of bytes successfully transferred (0 for non-data operations
    /// such as [`BlkOpCode::Flush`] or on any error status).
    pub bytes_transferred: u32,
}

impl BlkResponse {
    /// Encode this response into the fixed [`BLK_RESPONSE_WIRE_SIZE`]-byte
    /// little-endian frame.
    ///
    /// Layout:
    /// - bytes 0..8: `request_id` (`u64` LE)
    /// - byte 8: `status` discriminant (`u8`)
    /// - bytes 9..13: `bytes_transferred` (`u32` LE)
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_shared::blk::{BlkResponse, BlkStatus};
    ///
    /// let resp = BlkResponse {
    ///     request_id: 1,
    ///     status: BlkStatus::Ok,
    ///     bytes_transferred: 4096,
    /// };
    /// let wire = resp.encode();
    /// assert_eq!(&wire[0..8], &1u64.to_le_bytes());
    /// assert_eq!(wire[8], BlkStatus::Ok as u8);
    /// assert_eq!(&wire[9..13], &4096u32.to_le_bytes());
    /// ```
    #[must_use]
    pub fn encode(&self) -> [u8; BLK_RESPONSE_WIRE_SIZE] {
        let mut buf = [0u8; BLK_RESPONSE_WIRE_SIZE];
        // bytes 0..8 — request_id (u64 LE)
        buf[0..8].copy_from_slice(&self.request_id.to_le_bytes());
        // byte 8 — status discriminant
        buf[8] = self.status as u8;
        // bytes 9..13 — bytes_transferred (u32 LE)
        buf[9..13].copy_from_slice(&self.bytes_transferred.to_le_bytes());
        buf
    }

    /// Decode a `BlkResponse` from a byte slice.
    ///
    /// The slice must be at least [`BLK_RESPONSE_WIRE_SIZE`] bytes long.
    ///
    /// # Errors
    ///
    /// - [`BlkDecodeError::TooShort`] if `bytes.len() < BLK_RESPONSE_WIRE_SIZE`.
    /// - [`BlkDecodeError::InvalidStatus`] if byte 8 is not a valid
    ///   [`BlkStatus`] discriminant (`0..=5`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_shared::blk::{BlkDecodeError, BlkResponse};
    ///
    /// // Too-short buffer.
    /// let err = BlkResponse::decode(&[0u8; 5]).unwrap_err();
    /// assert_eq!(err, BlkDecodeError::TooShort);
    ///
    /// // Invalid status byte.
    /// let mut bad = [0u8; 13];
    /// bad[8] = 0xFF;
    /// let err = BlkResponse::decode(&bad).unwrap_err();
    /// assert_eq!(err, BlkDecodeError::InvalidStatus);
    /// ```
    pub fn decode(bytes: &[u8]) -> Result<Self, BlkDecodeError> {
        if bytes.len() < BLK_RESPONSE_WIRE_SIZE {
            return Err(BlkDecodeError::TooShort);
        }
        // bytes 0..8 — request_id (u64 LE).
        // The `try_into` on a `&[u8; 8]` slice cannot fail because `.get(0..8)`
        // returns exactly 8 bytes when `bytes.len() >= 13`.
        let request_id = {
            let raw: [u8; 8] = bytes
                .get(0..8)
                .and_then(|s| s.try_into().ok())
                .ok_or(BlkDecodeError::TooShort)?;
            u64::from_le_bytes(raw)
        };
        // byte 8 — status discriminant.
        let status_byte = *bytes.get(8).ok_or(BlkDecodeError::TooShort)?;
        let status = BlkStatus::from_u8(status_byte).ok_or(BlkDecodeError::InvalidStatus)?;
        // bytes 9..13 — bytes_transferred (u32 LE).
        let bytes_transferred = {
            let raw: [u8; 4] = bytes
                .get(9..13)
                .and_then(|s| s.try_into().ok())
                .ok_or(BlkDecodeError::TooShort)?;
            u32::from_le_bytes(raw)
        };
        Ok(Self {
            request_id,
            status,
            bytes_transferred,
        })
    }
}

// ---------------------------------------------------------------------------
// BlkCapacity
// ---------------------------------------------------------------------------

/// Device capacity information reported by a storage driver.
///
/// Returned by `BlkChannelHandler::report_capacity` and consumable by
/// higher-level block-device managers that need to know the device's
/// extent before issuing I/O.
///
/// # Example
///
/// ```
/// use nexacore_driver_shared::blk::BlkCapacity;
///
/// let cap = BlkCapacity {
///     total_sectors: 2048,
///     sector_size: 512,
///     read_only: false,
/// };
/// assert_eq!(cap.total_sectors, 2048);
/// assert_eq!(cap.sector_size, 512);
/// assert!(!cap.read_only);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlkCapacity {
    /// Total number of addressable sectors on the device.
    pub total_sectors: u64,
    /// Size of each sector in bytes.
    pub sector_size: u32,
    /// `true` if the device or namespace is write-protected.
    pub read_only: bool,
}

// ---------------------------------------------------------------------------
// BlkDecodeError
// ---------------------------------------------------------------------------

/// Errors that can occur when decoding a fixed-size BLK wire frame.
///
/// Returned by [`BlkRequest::decode`] and [`BlkResponse::decode`].
///
/// # Example
///
/// ```
/// use nexacore_driver_shared::blk::{BlkDecodeError, BlkRequest};
///
/// let err = BlkRequest::decode(&[]).unwrap_err();
/// assert_eq!(err, BlkDecodeError::TooShort);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkDecodeError {
    /// The input slice is shorter than the expected wire frame size.
    TooShort,
    /// The `op` byte does not match any [`BlkOpCode`] discriminant.
    InvalidOpCode,
    /// The `status` byte does not match any [`BlkStatus`] discriminant.
    InvalidStatus,
}

impl core::fmt::Display for BlkDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => f.write_str("BLK wire frame is shorter than expected"),
            Self::InvalidOpCode => f.write_str("BLK request op-code byte is out of range"),
            Self::InvalidStatus => f.write_str("BLK response status byte is out of range"),
        }
    }
}

impl core::error::Error for BlkDecodeError {}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Wire-size constants
    // -----------------------------------------------------------------------

    #[test]
    fn blk_request_wire_size_constant_matches_layout() {
        // Verify arithmetic: 1 (op) + 8 (sector) + 4 (count) + 8 (buffer_va) + 8 (request_id).
        assert_eq!(BLK_REQUEST_WIRE_SIZE, 1 + 8 + 4 + 8 + 8);
    }

    #[test]
    fn blk_response_wire_size_constant_matches_layout() {
        // Verify arithmetic: 8 (request_id) + 1 (status) + 4 (bytes_transferred).
        assert_eq!(BLK_RESPONSE_WIRE_SIZE, 8 + 1 + 4);
    }

    // -----------------------------------------------------------------------
    // BlkOpCode discriminants
    // -----------------------------------------------------------------------

    #[test]
    fn blk_op_code_discriminants_are_stable() {
        assert_eq!(BlkOpCode::Read as u8, 0);
        assert_eq!(BlkOpCode::Write as u8, 1);
        assert_eq!(BlkOpCode::Flush as u8, 2);
        assert_eq!(BlkOpCode::Discard as u8, 3);
    }

    #[test]
    fn blk_op_code_from_u8_round_trips_all_variants() {
        for (raw, expected) in [
            (0u8, BlkOpCode::Read),
            (1, BlkOpCode::Write),
            (2, BlkOpCode::Flush),
            (3, BlkOpCode::Discard),
        ] {
            assert_eq!(BlkOpCode::from_u8(raw), Some(expected));
        }
    }

    #[test]
    fn blk_op_code_from_u8_rejects_out_of_range() {
        for bad in [4u8, 0x0F, 0xFF] {
            assert_eq!(
                BlkOpCode::from_u8(bad),
                None,
                "expected None for op byte {bad}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // BlkStatus discriminants
    // -----------------------------------------------------------------------

    #[test]
    fn blk_status_discriminants_are_stable() {
        assert_eq!(BlkStatus::Ok as u8, 0);
        assert_eq!(BlkStatus::IoError as u8, 1);
        assert_eq!(BlkStatus::InvalidSector as u8, 2);
        assert_eq!(BlkStatus::ReadOnly as u8, 3);
        assert_eq!(BlkStatus::DeviceGone as u8, 4);
        assert_eq!(BlkStatus::Timeout as u8, 5);
    }

    #[test]
    fn blk_status_from_u8_round_trips_all_variants() {
        for (raw, expected) in [
            (0u8, BlkStatus::Ok),
            (1, BlkStatus::IoError),
            (2, BlkStatus::InvalidSector),
            (3, BlkStatus::ReadOnly),
            (4, BlkStatus::DeviceGone),
            (5, BlkStatus::Timeout),
        ] {
            assert_eq!(BlkStatus::from_u8(raw), Some(expected));
        }
    }

    #[test]
    fn blk_status_from_u8_rejects_out_of_range() {
        for bad in [6u8, 0x0F, 0xFF] {
            assert_eq!(
                BlkStatus::from_u8(bad),
                None,
                "expected None for status byte {bad}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // BlkRequest encode/decode roundtrips — one per OpCode variant
    // -----------------------------------------------------------------------

    fn roundtrip_request(op: BlkOpCode) {
        let req = BlkRequest::new(
            op,
            0xDEAD_BEEF_0000_0001,
            0xCAFE_BABE,
            0x1234_5678_9ABC_DEF0,
            0xFF00_FF00_FF00_FF00,
        );
        let wire = req.encode();
        assert_eq!(wire.len(), BLK_REQUEST_WIRE_SIZE);
        let decoded = BlkRequest::decode(&wire).expect("round-trip decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn blk_request_read_roundtrip() {
        roundtrip_request(BlkOpCode::Read);
    }

    #[test]
    fn blk_request_write_roundtrip() {
        roundtrip_request(BlkOpCode::Write);
    }

    #[test]
    fn blk_request_flush_roundtrip() {
        roundtrip_request(BlkOpCode::Flush);
    }

    #[test]
    fn blk_request_discard_roundtrip() {
        roundtrip_request(BlkOpCode::Discard);
    }

    // -----------------------------------------------------------------------
    // BlkResponse encode/decode roundtrips — one per Status variant
    // -----------------------------------------------------------------------

    fn roundtrip_response(status: BlkStatus) {
        let resp = BlkResponse {
            request_id: 0xABCD_EF01_2345_6789,
            status,
            bytes_transferred: 0x0010_0000,
        };
        let wire = resp.encode();
        assert_eq!(wire.len(), BLK_RESPONSE_WIRE_SIZE);
        let decoded = BlkResponse::decode(&wire).expect("round-trip decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn blk_response_ok_roundtrip() {
        roundtrip_response(BlkStatus::Ok);
    }

    #[test]
    fn blk_response_io_error_roundtrip() {
        roundtrip_response(BlkStatus::IoError);
    }

    #[test]
    fn blk_response_invalid_sector_roundtrip() {
        roundtrip_response(BlkStatus::InvalidSector);
    }

    #[test]
    fn blk_response_read_only_roundtrip() {
        roundtrip_response(BlkStatus::ReadOnly);
    }

    #[test]
    fn blk_response_device_gone_roundtrip() {
        roundtrip_response(BlkStatus::DeviceGone);
    }

    #[test]
    fn blk_response_timeout_roundtrip() {
        roundtrip_response(BlkStatus::Timeout);
    }

    // -----------------------------------------------------------------------
    // Rejection: invalid op-code byte
    // -----------------------------------------------------------------------

    #[test]
    fn blk_request_decode_rejects_invalid_op_code() {
        let mut buf = [0u8; BLK_REQUEST_WIRE_SIZE];
        buf[0] = 0xFF;
        let err = BlkRequest::decode(&buf).unwrap_err();
        assert_eq!(err, BlkDecodeError::InvalidOpCode);
    }

    #[test]
    fn blk_request_decode_rejects_op_code_4() {
        let mut buf = [0u8; BLK_REQUEST_WIRE_SIZE];
        buf[0] = 4;
        let err = BlkRequest::decode(&buf).unwrap_err();
        assert_eq!(err, BlkDecodeError::InvalidOpCode);
    }

    // -----------------------------------------------------------------------
    // Rejection: invalid status byte
    // -----------------------------------------------------------------------

    #[test]
    fn blk_response_decode_rejects_invalid_status() {
        let mut buf = [0u8; BLK_RESPONSE_WIRE_SIZE];
        buf[8] = 0xFF;
        let err = BlkResponse::decode(&buf).unwrap_err();
        assert_eq!(err, BlkDecodeError::InvalidStatus);
    }

    #[test]
    fn blk_response_decode_rejects_status_6() {
        let mut buf = [0u8; BLK_RESPONSE_WIRE_SIZE];
        buf[8] = 6;
        let err = BlkResponse::decode(&buf).unwrap_err();
        assert_eq!(err, BlkDecodeError::InvalidStatus);
    }

    // -----------------------------------------------------------------------
    // Rejection: too-short buffers
    // -----------------------------------------------------------------------

    #[test]
    fn blk_request_decode_rejects_too_short() {
        for len in 0..BLK_REQUEST_WIRE_SIZE {
            let buf = vec![0u8; len];
            let err = BlkRequest::decode(&buf).unwrap_err();
            assert_eq!(
                err,
                BlkDecodeError::TooShort,
                "expected TooShort for len={len}"
            );
        }
    }

    #[test]
    fn blk_response_decode_rejects_too_short() {
        for len in 0..BLK_RESPONSE_WIRE_SIZE {
            let buf = vec![0u8; len];
            let err = BlkResponse::decode(&buf).unwrap_err();
            assert_eq!(
                err,
                BlkDecodeError::TooShort,
                "expected TooShort for len={len}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Edge cases: zero sector, max sector values
    // -----------------------------------------------------------------------

    #[test]
    fn blk_request_zero_sector_roundtrip() {
        let req = BlkRequest::new(BlkOpCode::Read, 0, 0, 0, 0);
        let decoded = BlkRequest::decode(&req.encode()).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn blk_request_max_sector_roundtrip() {
        let req = BlkRequest::new(BlkOpCode::Read, u64::MAX, u32::MAX, u64::MAX, u64::MAX);
        let decoded = BlkRequest::decode(&req.encode()).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn blk_response_max_values_roundtrip() {
        let resp = BlkResponse {
            request_id: u64::MAX,
            status: BlkStatus::Timeout,
            bytes_transferred: u32::MAX,
        };
        let decoded = BlkResponse::decode(&resp.encode()).unwrap();
        assert_eq!(decoded, resp);
    }

    // -----------------------------------------------------------------------
    // Decode accepts buffers longer than wire size (trailing bytes ignored)
    // -----------------------------------------------------------------------

    #[test]
    fn blk_request_decode_accepts_buffer_longer_than_wire_size() {
        let req = BlkRequest::new(BlkOpCode::Flush, 10, 2, 0x5000, 1);
        let mut buf = vec![0xFFu8; BLK_REQUEST_WIRE_SIZE + 16];
        buf[..BLK_REQUEST_WIRE_SIZE].copy_from_slice(&req.encode());
        let decoded = BlkRequest::decode(&buf).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn blk_response_decode_accepts_buffer_longer_than_wire_size() {
        let resp = BlkResponse {
            request_id: 5,
            status: BlkStatus::Ok,
            bytes_transferred: 512,
        };
        let mut buf = vec![0xFFu8; BLK_RESPONSE_WIRE_SIZE + 8];
        buf[..BLK_RESPONSE_WIRE_SIZE].copy_from_slice(&resp.encode());
        let decoded = BlkResponse::decode(&buf).unwrap();
        assert_eq!(decoded, resp);
    }

    // -----------------------------------------------------------------------
    // Endianness: verify little-endian layout at specific offsets
    // -----------------------------------------------------------------------

    #[test]
    fn blk_request_encode_sector_is_little_endian() {
        let sector: u64 = 0x0102_0304_0506_0708;
        let req = BlkRequest::new(BlkOpCode::Read, sector, 0, 0, 0);
        let wire = req.encode();
        assert_eq!(&wire[1..9], &sector.to_le_bytes());
    }

    #[test]
    fn blk_response_encode_request_id_is_little_endian() {
        let id: u64 = 0xAABB_CCDD_EEFF_0011;
        let resp = BlkResponse {
            request_id: id,
            status: BlkStatus::Ok,
            bytes_transferred: 0,
        };
        let wire = resp.encode();
        assert_eq!(&wire[0..8], &id.to_le_bytes());
    }

    // -----------------------------------------------------------------------
    // BlkDecodeError Display
    // -----------------------------------------------------------------------

    #[test]
    fn blk_decode_error_display_messages_are_non_empty() {
        for e in [
            BlkDecodeError::TooShort,
            BlkDecodeError::InvalidOpCode,
            BlkDecodeError::InvalidStatus,
        ] {
            let s = format!("{e}");
            assert!(
                !s.is_empty(),
                "Display for BlkDecodeError::{e:?} must not be empty"
            );
        }
    }

    // -----------------------------------------------------------------------
    // BlkCapacity construction
    // -----------------------------------------------------------------------

    #[test]
    fn blk_capacity_fields_are_accessible() {
        let cap = BlkCapacity {
            total_sectors: 4096,
            sector_size: 512,
            read_only: true,
        };
        assert_eq!(cap.total_sectors, 4096);
        assert_eq!(cap.sector_size, 512);
        assert!(cap.read_only);
    }
}

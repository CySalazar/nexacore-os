//! USB Mass Storage class driver logic — BOT/SCSI (Bulk-Only Transport).
//!
//! Implements DE-E4 (ADR-0049): CBW/CSW wire codecs, SCSI CDB builders,
//! and a `BlkRequest` → `ScsiOp` gateway bridging the `nexacore-types` BLK
//! channel ABI to the USB BOT/SCSI transfer model.
//!
//! ## BOT protocol (USB Mass Storage Class — Bulk Only Transport rev 1.0)
//!
//! ```text
//! Host → Device: CBW (31 bytes, bulk-OUT)
//! Host ↔ Device: data phase (bulk-IN or bulk-OUT, optional)
//! Device → Host: CSW (13 bytes, bulk-IN)
//! ```
//!
//! ## Security posture
//!
//! The CSW and INQUIRY/READ CAPACITY response data arrive from an untrusted
//! USB device.  Every parse function is explicitly length- and
//! signature-checked before any field access; malformed or short inputs yield
//! typed errors, never panics or over-reads.
//!
//! ## References
//!
//! - USB Mass Storage Class — Bulk Only Transport revision 1.0 § 5.1–5.3.
//! - SCSI Primary Commands-4 (SPC-4) and SCSI Block Commands-3 (SBC-3).
//! - `nexacore_types::blk` — `BlkRequest`, `BlkResponse`, `BLOCK_SIZE_BYTES`.

use nexacore_types::blk::{BLOCK_SIZE_BYTES, BlkRequest, BlkResponse, NON_NVME_DEVICE_ERROR};

// =============================================================================
// Error type
// =============================================================================

/// Errors returned by Mass Storage parsing functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StorageError {
    /// The input slice is shorter than the minimum required for this
    /// structure.
    ///
    /// A CSW requires 13 bytes; a READ CAPACITY(10) response requires 8 bytes;
    /// an INQUIRY response requires at least 36 bytes.
    TooShort,
    /// The dCSWSignature field does not match the expected magic `0x53425355`.
    BadSignature,
    /// The CSW `bCSWStatus` field indicates a command failure (`1`).
    CommandFailed,
    /// The CSW `bCSWStatus` field indicates a phase error (`2`).
    ///
    /// A phase error requires a bulk-endpoint reset-recovery sequence before
    /// the next command can be issued.
    PhaseError,
    /// The CBW CDB length exceeds 16 bytes (the maximum allowed by BOT).
    CdbTooLong,
    /// The `BlkRequest` variant is not supported by this storage driver.
    ///
    /// Currently only `Read`, `Write`, and `Flush` are mapped.
    UnsupportedRequest,
}

// =============================================================================
// CBW — Command Block Wrapper (BOT § 5.1)
// =============================================================================

/// Expected dCBWSignature value (LE representation of `"USBC"`).
pub const CBW_SIGNATURE: u32 = 0x4342_5355;

/// Expected dCSWSignature value (LE representation of `"USBS"`).
pub const CSW_SIGNATURE: u32 = 0x5342_5355;

/// Byte length of an encoded CBW.
pub const CBW_LEN: usize = 31;

/// Byte length of an encoded CSW.
pub const CSW_LEN: usize = 13;

/// Encode a Command Block Wrapper into a 31-byte array.
///
/// The CBW is the fixed-size command block sent on the bulk-OUT endpoint to
/// initiate a SCSI command sequence.
///
/// - `tag`: a host-generated tag used to associate the subsequent CSW with
///   this CBW. Must be unique per command in-flight.
/// - `data_transfer_length`: the total expected data phase byte count (may be
///   zero for commands with no data phase, e.g. TEST UNIT READY).
/// - `dir_in`: `true` for device-to-host (bulk-IN) data phase; `false` for
///   host-to-device (bulk-OUT). Encoded in `bmCBWFlags` bit 7.
/// - `lun`: Logical Unit Number (0 for single-LUN devices).
/// - `cdb`: the SCSI Command Descriptor Block bytes. Must be at most 16 bytes
///   (the maximum `bCBWCBLength` per BOT § 5.1).
///
/// # Errors
///
/// Returns [`StorageError::CdbTooLong`] if `cdb.len() > 16`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::{CBW_LEN, CBW_SIGNATURE, cdb_inquiry, encode_cbw};
///
/// let cdb = cdb_inquiry(36);
/// let cbw = encode_cbw(1, 36, true, 0, &cdb).unwrap();
/// assert_eq!(cbw.len(), CBW_LEN);
/// // dCBWSignature at bytes 0..4 (LE) = 0x43425355.
/// let sig = u32::from_le_bytes(cbw[0..4].try_into().unwrap());
/// assert_eq!(sig, CBW_SIGNATURE);
/// ```
pub fn encode_cbw(
    tag: u32,
    data_transfer_length: u32,
    dir_in: bool,
    lun: u8,
    cdb: &[u8],
) -> Result<[u8; CBW_LEN], StorageError> {
    if cdb.len() > 16 {
        return Err(StorageError::CdbTooLong);
    }
    let mut cbw = [0u8; CBW_LEN];
    // Bytes 0..3: dCBWSignature = 0x43425355 (LE).
    if let Some(dest) = cbw.get_mut(0..4) {
        dest.copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    }
    // Bytes 4..7: dCBWTag (LE).
    if let Some(dest) = cbw.get_mut(4..8) {
        dest.copy_from_slice(&tag.to_le_bytes());
    }
    // Bytes 8..11: dCBWDataTransferLength (LE).
    if let Some(dest) = cbw.get_mut(8..12) {
        dest.copy_from_slice(&data_transfer_length.to_le_bytes());
    }
    // Byte 12: bmCBWFlags.  Bit 7 = direction (1 = IN, 0 = OUT).
    if let Some(b) = cbw.get_mut(12) {
        *b = if dir_in { 0x80 } else { 0x00 };
    }
    // Byte 13: bCBWLUN (bits 3:0).
    if let Some(b) = cbw.get_mut(13) {
        *b = lun & 0x0F;
    }
    // Byte 14: bCBWCBLength (bits 4:0) = cdb.len().
    #[allow(clippy::cast_possible_truncation)]
    if let Some(b) = cbw.get_mut(14) {
        *b = cdb.len() as u8 & 0x1F;
    }
    // Bytes 15..30: CBWCB (CDB, zero-padded to 16 bytes).
    for (i, &byte) in cdb.iter().enumerate() {
        if let Some(dest) = cbw.get_mut(15 + i) {
            *dest = byte;
        }
    }
    Ok(cbw)
}

// =============================================================================
// CSW — Command Status Wrapper (BOT § 5.2)
// =============================================================================

/// A parsed Command Status Wrapper returned by the device on the bulk-IN
/// endpoint after the data phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandStatusWrapper {
    /// `dCSWTag` — must match the `dCBWTag` from the associated CBW.
    pub tag: u32,
    /// `dCSWDataResidue` — difference between the requested and actual
    /// data transfer length.
    pub residue: u32,
    /// `bCSWStatus` — `0` = command passed, `1` = command failed,
    /// `2` = phase error.
    pub status: u8,
}

/// Parse a Command Status Wrapper from a 13-byte slice.
///
/// Returns typed errors for structural problems; field-level errors (non-zero
/// status) are surfaced through the returned `CommandStatusWrapper::status`
/// field, NOT as parse errors.
///
/// # Errors
///
/// - [`StorageError::TooShort`] when `data.len() < 13`.
/// - [`StorageError::BadSignature`] when `dCSWSignature != 0x53425355`.
///
/// Note: status `1` (command failed) and `2` (phase error) are NOT returned
/// as parse errors — they are stored in `status` so the caller can
/// distinguish between a well-formed failure CSW and a malformed one.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::{CSW_LEN, CSW_SIGNATURE, parse_csw};
///
/// let mut raw = [0u8; CSW_LEN];
/// raw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes()); // signature
/// raw[4..8].copy_from_slice(&42u32.to_le_bytes()); // tag
/// // residue and status = 0 (success).
/// let csw = parse_csw(&raw).unwrap();
/// assert_eq!(csw.tag, 42);
/// assert_eq!(csw.status, 0);
/// ```
pub fn parse_csw(data: &[u8]) -> Result<CommandStatusWrapper, StorageError> {
    if data.len() < CSW_LEN {
        return Err(StorageError::TooShort);
    }
    // Bytes 0..3: dCSWSignature — must be 0x53425355.
    let sig_bytes = data
        .get(0..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(StorageError::TooShort)?;
    if sig_bytes != CSW_SIGNATURE {
        return Err(StorageError::BadSignature);
    }
    // Bytes 4..7: dCSWTag.
    let tag = data
        .get(4..8)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(StorageError::TooShort)?;
    // Bytes 8..11: dCSWDataResidue.
    let residue = data
        .get(8..12)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(StorageError::TooShort)?;
    // Byte 12: bCSWStatus.
    let status = *data.get(12).ok_or(StorageError::TooShort)?;
    Ok(CommandStatusWrapper {
        tag,
        residue,
        status,
    })
}

// =============================================================================
// SCSI CDB builders
// =============================================================================

/// Build a SCSI INQUIRY CDB (6 bytes).
///
/// `alloc_len` is the number of bytes the host allocates to receive the
/// INQUIRY response data (typically 36 for a standard response).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_inquiry;
///
/// let cdb = cdb_inquiry(36);
/// assert_eq!(cdb[0], 0x12); // INQUIRY opcode
/// assert_eq!(cdb[4], 36); // Allocation Length
/// ```
#[must_use]
pub fn cdb_inquiry(alloc_len: u8) -> [u8; 6] {
    // Byte 0: opcode 0x12 (INQUIRY).
    // Byte 1: EVPD = 0 (standard inquiry).
    // Byte 2: page code = 0.
    // Byte 3: allocation length high byte = 0 (alloc_len fits in u8).
    // Byte 4: allocation length low byte.
    // Byte 5: control = 0.
    [0x12, 0x00, 0x00, 0x00, alloc_len, 0x00]
}

/// Build a SCSI TEST UNIT READY CDB (6 bytes).
///
/// Tests whether the logical unit is ready to accept commands.  No data
/// phase; a GOOD status in the CSW indicates the unit is ready.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_test_unit_ready;
///
/// let cdb = cdb_test_unit_ready();
/// assert_eq!(cdb[0], 0x00); // TEST UNIT READY opcode
/// ```
#[must_use]
pub fn cdb_test_unit_ready() -> [u8; 6] {
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

/// Build a SCSI READ CAPACITY(10) CDB (10 bytes).
///
/// Reads the last addressable LBA and the block size in bytes.  The response
/// is 8 bytes (4 bytes last LBA + 4 bytes block length), parsed by
/// [`parse_read_capacity10`].
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_read_capacity10;
///
/// let cdb = cdb_read_capacity10();
/// assert_eq!(cdb[0], 0x25); // READ CAPACITY(10) opcode
/// ```
#[must_use]
pub fn cdb_read_capacity10() -> [u8; 10] {
    // All fields except opcode are 0 (PMI=0, LBA=0).
    [0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

/// Build a SCSI READ CAPACITY(16) CDB (16 bytes).
///
/// The `SERVICE ACTION IN(16)` (opcode 0x9E, service action 0x10) variant
/// returns a 64-bit last LBA, so it addresses capacities beyond the ~2 `TiB`
/// reach of READ CAPACITY(10). `alloc_len` is the expected response length
/// (32 bytes for a full response), parsed by [`parse_read_capacity16`].
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_read_capacity16;
///
/// let cdb = cdb_read_capacity16(32);
/// assert_eq!(cdb[0], 0x9E); // SERVICE ACTION IN(16) opcode
/// assert_eq!(cdb[1], 0x10); // READ CAPACITY(16) service action
/// ```
#[must_use]
pub fn cdb_read_capacity16(alloc_len: u32) -> [u8; 16] {
    // Byte 0: opcode 0x9E. Byte 1: service action 0x10 (bits 4:0).
    // Bytes 2..9: obsolete/reserved LBA (0). Bytes 10..13: allocation length
    // (big-endian). Byte 14: reserved/PMI. Byte 15: control.
    let len = alloc_len.to_be_bytes();
    [
        0x9E, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, len[0], len[1], len[2], len[3],
        0x00, 0x00,
    ]
}

/// Build a SCSI READ(10) CDB (10 bytes).
///
/// Reads `blocks` consecutive logical blocks starting at `lba`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_read10;
///
/// let cdb = cdb_read10(0, 1);
/// assert_eq!(cdb[0], 0x28); // READ(10) opcode
/// assert_eq!(cdb[8], 1); // transfer length (blocks)
/// ```
#[must_use]
pub fn cdb_read10(lba: u32, blocks: u16) -> [u8; 10] {
    // Byte 0: opcode 0x28 (READ(10)).
    // Bytes 1..4: LBA (big-endian).
    // Bytes 7..8: transfer length in blocks (big-endian).
    let lba_bytes = lba.to_be_bytes();
    let blk_bytes = blocks.to_be_bytes();
    [
        0x28,
        0x00,
        lba_bytes[0],
        lba_bytes[1],
        lba_bytes[2],
        lba_bytes[3],
        0x00,
        blk_bytes[0],
        blk_bytes[1],
        0x00,
    ]
}

/// Build a SCSI WRITE(10) CDB (10 bytes).
///
/// Writes `blocks` consecutive logical blocks starting at `lba`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_write10;
///
/// let cdb = cdb_write10(5, 2);
/// assert_eq!(cdb[0], 0x2A); // WRITE(10) opcode
/// assert_eq!(cdb[2], 0); // LBA[0]
/// assert_eq!(cdb[5], 5); // LBA[3]
/// ```
#[must_use]
pub fn cdb_write10(lba: u32, blocks: u16) -> [u8; 10] {
    // Byte 0: opcode 0x2A (WRITE(10)).
    // Bytes 1..4: LBA (big-endian).
    // Bytes 7..8: transfer length in blocks (big-endian).
    let lba_bytes = lba.to_be_bytes();
    let blk_bytes = blocks.to_be_bytes();
    [
        0x2A,
        0x00,
        lba_bytes[0],
        lba_bytes[1],
        lba_bytes[2],
        lba_bytes[3],
        0x00,
        blk_bytes[0],
        blk_bytes[1],
        0x00,
    ]
}

/// Build a SCSI READ(16) CDB (16 bytes).
///
/// Reads `blocks` consecutive logical blocks starting at the 64-bit `lba`,
/// addressing devices beyond the 32-bit LBA range of [`cdb_read10`].
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_read16;
///
/// let cdb = cdb_read16(0x1_0000_0000, 1);
/// assert_eq!(cdb[0], 0x88); // READ(16) opcode
/// ```
#[must_use]
pub fn cdb_read16(lba: u64, blocks: u32) -> [u8; 16] {
    // Byte 0: opcode 0x88. Bytes 2..10: LBA (big-endian). Bytes 10..14:
    // transfer length in blocks (big-endian). Byte 14: group. Byte 15: control.
    let l = lba.to_be_bytes();
    let b = blocks.to_be_bytes();
    [
        0x88, 0x00, l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], b[0], b[1], b[2], b[3], 0x00,
        0x00,
    ]
}

/// Build a SCSI WRITE(16) CDB (16 bytes).
///
/// Writes `blocks` consecutive logical blocks starting at the 64-bit `lba`,
/// the write counterpart of [`cdb_read16`].
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_write16;
///
/// let cdb = cdb_write16(0x1_0000_0000, 1);
/// assert_eq!(cdb[0], 0x8A); // WRITE(16) opcode
/// ```
#[must_use]
pub fn cdb_write16(lba: u64, blocks: u32) -> [u8; 16] {
    let l = lba.to_be_bytes();
    let b = blocks.to_be_bytes();
    [
        0x8A, 0x00, l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], b[0], b[1], b[2], b[3], 0x00,
        0x00,
    ]
}

// =============================================================================
// BLK ↔ SCSI gateway
// =============================================================================

/// A SCSI operation produced by [`blk_request_to_scsi`].
///
/// Encodes the CDB bytes, data direction, and expected data length for a
/// single BOT transaction.  The image crate builds a CBW from these fields,
/// submits the bulk-OUT transfer, drives the data phase, and awaits the CSW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScsiOp {
    /// SCSI CDB bytes. Lengths shorter than 16 have the remainder zeroed.
    pub cdb: [u8; 16],
    /// Length of the valid prefix of `cdb`.
    pub cdb_len: usize,
    /// `true` if the data phase is device-to-host (bulk-IN), `false` for
    /// host-to-device (bulk-OUT).
    pub dir_in: bool,
    /// Expected data transfer length in bytes (0 for no data phase).
    pub data_len: u32,
}

impl ScsiOp {
    /// Construct a `ScsiOp` from a fixed-size CDB slice.
    fn from_cdb6(cdb: [u8; 6], dir_in: bool, data_len: u32) -> Self {
        let mut full = [0u8; 16];
        for (i, &b) in cdb.iter().enumerate() {
            if let Some(dest) = full.get_mut(i) {
                *dest = b;
            }
        }
        Self {
            cdb: full,
            cdb_len: 6,
            dir_in,
            data_len,
        }
    }

    /// Construct a `ScsiOp` from a 10-byte CDB slice.
    fn from_cdb10(cdb: [u8; 10], dir_in: bool, data_len: u32) -> Self {
        let mut full = [0u8; 16];
        for (i, &b) in cdb.iter().enumerate() {
            if let Some(dest) = full.get_mut(i) {
                *dest = b;
            }
        }
        Self {
            cdb: full,
            cdb_len: 10,
            dir_in,
            data_len,
        }
    }

    /// Construct a `ScsiOp` from a 16-byte CDB (already full-width).
    fn from_cdb16(cdb: [u8; 16], dir_in: bool, data_len: u32) -> Self {
        Self {
            cdb,
            cdb_len: 16,
            dir_in,
            data_len,
        }
    }
}

/// Whether a `(lba, count)` pair exceeds the 32-bit LBA or 16-bit block-count
/// fields of the 10-byte SCSI commands and therefore needs the 16-byte form.
fn needs_cdb16(lba: u64, count: u32) -> bool {
    lba > u64::from(u32::MAX) || count > u32::from(u16::MAX)
}

/// Convert a [`BlkRequest`] to a [`ScsiOp`].
///
/// - `Read { lba, count, .. }` → `READ(10)`, or `READ(16)` when `lba`/`count`
///   exceed the 10-byte fields; `data_len = count * BLOCK_SIZE_BYTES`.
/// - `Write { lba, count, .. }` → `WRITE(10)`/`WRITE(16)` symmetrically.
/// - `Flush` → `TEST UNIT READY` (no data phase, `data_len` = 0).
/// - `Discard` and any future variants → [`StorageError::UnsupportedRequest`].
///
/// # Errors
///
/// Returns [`StorageError::UnsupportedRequest`] for unsupported variants.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::blk_request_to_scsi;
/// use nexacore_types::blk::{BLOCK_SIZE_BYTES, BlkRequest};
///
/// let req = BlkRequest::Read {
///     lba: 0,
///     count: 2,
///     buf_iova: 0x1000,
/// };
/// let op = blk_request_to_scsi(&req).unwrap();
/// assert!(op.dir_in);
/// assert_eq!(op.data_len, 2 * BLOCK_SIZE_BYTES);
/// assert_eq!(op.cdb[0], 0x28); // READ(10)
/// ```
pub fn blk_request_to_scsi(req: &BlkRequest) -> Result<ScsiOp, StorageError> {
    match req {
        BlkRequest::Read { lba, count, .. } => {
            let data_len = count.saturating_mul(BLOCK_SIZE_BYTES);
            if needs_cdb16(*lba, *count) {
                Ok(ScsiOp::from_cdb16(cdb_read16(*lba, *count), true, data_len))
            } else {
                // Within the 32-bit LBA / 16-bit block-count range of READ(10);
                // the casts are guarded by `needs_cdb16` returning false.
                #[allow(clippy::cast_possible_truncation)]
                let cdb = cdb_read10(*lba as u32, *count as u16);
                Ok(ScsiOp::from_cdb10(cdb, true, data_len))
            }
        }
        BlkRequest::Write { lba, count, .. } => {
            let data_len = count.saturating_mul(BLOCK_SIZE_BYTES);
            if needs_cdb16(*lba, *count) {
                Ok(ScsiOp::from_cdb16(
                    cdb_write16(*lba, *count),
                    false,
                    data_len,
                ))
            } else {
                #[allow(clippy::cast_possible_truncation)]
                let cdb = cdb_write10(*lba as u32, *count as u16);
                Ok(ScsiOp::from_cdb10(cdb, false, data_len))
            }
        }
        BlkRequest::Flush => {
            let cdb = cdb_test_unit_ready();
            Ok(ScsiOp::from_cdb6(cdb, false, 0))
        }
        // Discard and future variants are not supported by this driver.
        _ => Err(StorageError::UnsupportedRequest),
    }
}

/// Convert a [`CommandStatusWrapper`] to a [`BlkResponse`].
///
/// - `status = 0` (GOOD) → [`BlkResponse::Ok`].
/// - Any other status → [`BlkResponse::DeviceError`] with
///   [`NON_NVME_DEVICE_ERROR`] (`0xFFFF`) sentinel (the USB storage device is
///   not NVMe, so no native NVMe status word is available).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::{CommandStatusWrapper, csw_to_blk_response};
/// use nexacore_types::blk::BlkResponse;
///
/// let ok_csw = CommandStatusWrapper {
///     tag: 1,
///     residue: 0,
///     status: 0,
/// };
/// assert_eq!(csw_to_blk_response(&ok_csw), BlkResponse::Ok);
///
/// let fail_csw = CommandStatusWrapper {
///     tag: 2,
///     residue: 0,
///     status: 1,
/// };
/// assert!(matches!(
///     csw_to_blk_response(&fail_csw),
///     BlkResponse::DeviceError(_)
/// ));
/// ```
#[must_use]
pub fn csw_to_blk_response(csw: &CommandStatusWrapper) -> BlkResponse {
    if csw.status == 0 {
        BlkResponse::Ok
    } else {
        BlkResponse::DeviceError(NON_NVME_DEVICE_ERROR)
    }
}

// =============================================================================
// SCSI response parsers (untrusted — device-written data)
// =============================================================================

/// Minimum byte length of a SCSI READ CAPACITY(10) response.
pub const READ_CAPACITY10_RESPONSE_LEN: usize = 8;

/// Parse a SCSI READ CAPACITY(10) response.
///
/// `data` must be at least [`READ_CAPACITY10_RESPONSE_LEN`] (8) bytes.
/// Returns `(last_lba, block_size)` where both fields are big-endian in the
/// wire encoding.
///
/// # Errors
///
/// Returns [`StorageError::TooShort`] when `data.len() < 8`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::parse_read_capacity10;
///
/// // Last LBA = 0x0000_0FFF (4095), block size = 4096.
/// let mut data = [0u8; 8];
/// data[0..4].copy_from_slice(&0x0000_0FFFu32.to_be_bytes());
/// data[4..8].copy_from_slice(&4096u32.to_be_bytes());
/// let (last_lba, block_size) = parse_read_capacity10(&data).unwrap();
/// assert_eq!(last_lba, 0x0000_0FFF);
/// assert_eq!(block_size, 4096);
/// ```
pub fn parse_read_capacity10(data: &[u8]) -> Result<(u32, u32), StorageError> {
    if data.len() < READ_CAPACITY10_RESPONSE_LEN {
        return Err(StorageError::TooShort);
    }
    let last_lba = data
        .get(0..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(StorageError::TooShort)?;
    let block_size = data
        .get(4..8)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(StorageError::TooShort)?;
    Ok((last_lba, block_size))
}

/// Byte length of a SCSI READ CAPACITY(16) response.
pub const READ_CAPACITY16_RESPONSE_LEN: usize = 32;

/// Parse a SCSI READ CAPACITY(16) response.
///
/// `data` must be at least [`READ_CAPACITY16_RESPONSE_LEN`] (32) bytes.
/// Returns `(last_lba, block_size)` where the last LBA is a 64-bit big-endian
/// value (bytes 0..8) and the block size a 32-bit big-endian value
/// (bytes 8..12), supporting capacities beyond the reach of READ CAPACITY(10).
///
/// # Errors
///
/// Returns [`StorageError::TooShort`] when `data.len() < 32`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::parse_read_capacity16;
///
/// let mut data = [0u8; 32];
/// data[0..8].copy_from_slice(&0x0000_0001_0000_0000u64.to_be_bytes());
/// data[8..12].copy_from_slice(&4096u32.to_be_bytes());
/// let (last_lba, block_size) = parse_read_capacity16(&data).unwrap();
/// assert_eq!(last_lba, 0x1_0000_0000);
/// assert_eq!(block_size, 4096);
/// ```
pub fn parse_read_capacity16(data: &[u8]) -> Result<(u64, u32), StorageError> {
    if data.len() < READ_CAPACITY16_RESPONSE_LEN {
        return Err(StorageError::TooShort);
    }
    let last_lba = data
        .get(0..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(StorageError::TooShort)?;
    let block_size = data
        .get(8..12)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(StorageError::TooShort)?;
    Ok((last_lba, block_size))
}

/// Minimum byte length of a standard SCSI INQUIRY response.
pub const INQUIRY_RESPONSE_MIN_LEN: usize = 36;

/// A parsed SCSI INQUIRY response (standard, VPD page 0x00).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InquiryResponse {
    /// Peripheral device type (bits 4:0 of byte 0).
    ///
    /// `0x00` = Direct-access block device (hard disk, USB flash drive).
    pub device_type: u8,
    /// Vendor identification string (bytes 8..15, 8 bytes, ASCII-padded with
    /// spaces, trailing null stripped by convention).
    pub vendor: [u8; 8],
    /// Product identification string (bytes 16..31, 16 bytes, ASCII-padded).
    pub product: [u8; 16],
}

/// Parse a SCSI INQUIRY response.
///
/// `data` must be at least [`INQUIRY_RESPONSE_MIN_LEN`] (36) bytes.
///
/// # Errors
///
/// Returns [`StorageError::TooShort`] when `data.len() < 36`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::parse_inquiry;
///
/// let mut data = [0x20u8; 36]; // space-padded
/// data[0] = 0x00; // direct-access device
/// let resp = parse_inquiry(&data).unwrap();
/// assert_eq!(resp.device_type, 0x00);
/// ```
pub fn parse_inquiry(data: &[u8]) -> Result<InquiryResponse, StorageError> {
    if data.len() < INQUIRY_RESPONSE_MIN_LEN {
        return Err(StorageError::TooShort);
    }
    let device_type = data
        .first()
        .map(|&b| b & 0x1F)
        .ok_or(StorageError::TooShort)?;
    let mut vendor = [0u8; 8];
    let mut product = [0u8; 16];
    // Vendor: bytes 8..15.
    if let Some(src) = data.get(8..16) {
        vendor.copy_from_slice(src);
    } else {
        return Err(StorageError::TooShort);
    }
    // Product: bytes 16..31.
    if let Some(src) = data.get(16..32) {
        product.copy_from_slice(src);
    } else {
        return Err(StorageError::TooShort);
    }
    Ok(InquiryResponse {
        device_type,
        vendor,
        product,
    })
}

/// Build a SCSI REQUEST SENSE CDB (6 bytes).
///
/// Retrieves fixed-format sense data explaining a prior CHECK CONDITION
/// (a CSW status of `Failed`).  The device returns up to `alloc_len` bytes,
/// parsed by [`parse_sense`].
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::cdb_request_sense;
///
/// let cdb = cdb_request_sense(18);
/// assert_eq!(cdb[0], 0x03); // REQUEST SENSE opcode
/// assert_eq!(cdb[4], 18); // allocation length
/// ```
#[must_use]
pub fn cdb_request_sense(alloc_len: u8) -> [u8; 6] {
    // Byte 0: opcode 0x03 (REQUEST SENSE).
    // Byte 1: DESC = 0 (fixed-format sense data).
    // Bytes 2..3: reserved.
    // Byte 4: allocation length.
    // Byte 5: control = 0.
    [0x03, 0x00, 0x00, 0x00, alloc_len, 0x00]
}

/// Minimum byte length of fixed-format sense data required to read the sense
/// key, ASC, and ASCQ (through byte 13).
pub const SENSE_RESPONSE_MIN_LEN: usize = 14;

/// Parsed fixed-format SCSI REQUEST SENSE data (SPC-4 § 4.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenseData {
    /// Response code (bits 6:0 of byte 0): `0x70` = current error,
    /// `0x71` = deferred error.
    pub response_code: u8,
    /// Sense key (bits 3:0 of byte 2) — the top-level error category, e.g.
    /// `0x02` NOT READY, `0x03` MEDIUM ERROR, `0x05` ILLEGAL REQUEST,
    /// `0x06` UNIT ATTENTION.
    pub sense_key: u8,
    /// Additional Sense Code (byte 12).
    pub asc: u8,
    /// Additional Sense Code Qualifier (byte 13).
    pub ascq: u8,
}

impl SenseData {
    /// Whether these sense data report no error (`sense_key == 0`, NO SENSE).
    #[must_use]
    pub fn is_no_sense(self) -> bool {
        self.sense_key == 0
    }
}

/// Parse fixed-format SCSI REQUEST SENSE data.
///
/// `data` must be at least [`SENSE_RESPONSE_MIN_LEN`] (14) bytes so the sense
/// key, ASC, and ASCQ are present.  The high bit of byte 0 (the valid bit) is
/// masked off to yield the response code.
///
/// # Errors
///
/// Returns [`StorageError::TooShort`] when `data.len() < 14`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::storage::parse_sense;
///
/// let mut data = [0u8; 18];
/// data[0] = 0x70; // current error
/// data[2] = 0x06; // UNIT ATTENTION
/// data[12] = 0x28; // ASC: NOT READY TO READY CHANGE
/// data[13] = 0x00; // ASCQ
/// let sense = parse_sense(&data).unwrap();
/// assert_eq!(sense.sense_key, 0x06);
/// assert_eq!(sense.asc, 0x28);
/// ```
pub fn parse_sense(data: &[u8]) -> Result<SenseData, StorageError> {
    if data.len() < SENSE_RESPONSE_MIN_LEN {
        return Err(StorageError::TooShort);
    }
    let response_code = data
        .first()
        .map(|&b| b & 0x7F)
        .ok_or(StorageError::TooShort)?;
    let sense_key = data
        .get(2)
        .map(|&b| b & 0x0F)
        .ok_or(StorageError::TooShort)?;
    let asc = data.get(12).copied().ok_or(StorageError::TooShort)?;
    let ascq = data.get(13).copied().ok_or(StorageError::TooShort)?;
    Ok(SenseData {
        response_code,
        sense_key,
        asc,
        ascq,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]
mod tests {
    use nexacore_types::blk::BlkRequest;

    use super::*;

    // -- encode_cbw ----------------------------------------------------------

    #[test]
    fn cbw_signature_correct() {
        let cdb = cdb_inquiry(36);
        let cbw = encode_cbw(1, 36, true, 0, &cdb).unwrap();
        let sig = u32::from_le_bytes(cbw[0..4].try_into().unwrap());
        assert_eq!(sig, CBW_SIGNATURE);
    }

    #[test]
    fn cbw_tag_encoded() {
        let cdb = cdb_test_unit_ready();
        let cbw = encode_cbw(0xDEAD_BEEF, 0, false, 0, &cdb).unwrap();
        let tag = u32::from_le_bytes(cbw[4..8].try_into().unwrap());
        assert_eq!(tag, 0xDEAD_BEEF);
    }

    #[test]
    fn cbw_data_transfer_length_encoded() {
        let cdb = cdb_read10(0, 1);
        let cbw = encode_cbw(1, 4096, true, 0, &cdb).unwrap();
        let dtl = u32::from_le_bytes(cbw[8..12].try_into().unwrap());
        assert_eq!(dtl, 4096);
    }

    #[test]
    fn cbw_flags_dir_in() {
        let cdb = cdb_inquiry(36);
        let cbw = encode_cbw(1, 36, true, 0, &cdb).unwrap();
        assert_eq!(cbw[12], 0x80, "bmCBWFlags bit 7 = 1 for IN");
    }

    #[test]
    fn cbw_flags_dir_out() {
        let cdb = cdb_write10(0, 1);
        let cbw = encode_cbw(1, 4096, false, 0, &cdb).unwrap();
        assert_eq!(cbw[12], 0x00, "bmCBWFlags = 0 for OUT");
    }

    #[test]
    fn cbw_lun_encoded() {
        let cdb = cdb_test_unit_ready();
        let cbw = encode_cbw(1, 0, false, 3, &cdb).unwrap();
        assert_eq!(cbw[13] & 0x0F, 3, "bCBWLUN");
    }

    #[test]
    fn cbw_cdb_length_encoded() {
        let cdb = cdb_inquiry(36); // 6-byte CDB
        let cbw = encode_cbw(1, 36, true, 0, &cdb).unwrap();
        assert_eq!(cbw[14] & 0x1F, 6, "bCBWCBLength = 6");
    }

    #[test]
    fn cbw_cdb_bytes_copied() {
        let cdb = cdb_read10(0x1234_5678, 7);
        let cbw = encode_cbw(1, 7 * 4096, true, 0, &cdb).unwrap();
        // cbw[15..24] should contain the 10-byte READ(10) CDB.
        for (i, &b) in cdb.iter().enumerate() {
            assert_eq!(cbw[15 + i], b, "CDB byte {i}");
        }
    }

    #[test]
    fn cbw_cdb_too_long_rejects() {
        let cdb = [0u8; 17];
        assert_eq!(
            encode_cbw(1, 0, false, 0, &cdb),
            Err(StorageError::CdbTooLong)
        );
    }

    #[test]
    fn cbw_length_is_31() {
        let cdb = cdb_test_unit_ready();
        let cbw = encode_cbw(1, 0, false, 0, &cdb).unwrap();
        assert_eq!(cbw.len(), CBW_LEN);
    }

    // -- parse_csw -----------------------------------------------------------

    fn make_csw(tag: u32, residue: u32, status: u8) -> [u8; CSW_LEN] {
        let mut raw = [0u8; CSW_LEN];
        raw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        raw[4..8].copy_from_slice(&tag.to_le_bytes());
        raw[8..12].copy_from_slice(&residue.to_le_bytes());
        raw[12] = status;
        raw
    }

    #[test]
    fn csw_happy_path_success() {
        let raw = make_csw(42, 0, 0);
        let csw = parse_csw(&raw).unwrap();
        assert_eq!(csw.tag, 42);
        assert_eq!(csw.residue, 0);
        assert_eq!(csw.status, 0);
    }

    #[test]
    fn csw_happy_path_failed_status() {
        let raw = make_csw(7, 512, 1);
        let csw = parse_csw(&raw).unwrap();
        assert_eq!(csw.status, 1);
        assert_eq!(csw.residue, 512);
    }

    #[test]
    fn csw_phase_error_status() {
        let raw = make_csw(3, 0, 2);
        let csw = parse_csw(&raw).unwrap();
        assert_eq!(csw.status, 2);
    }

    #[test]
    fn csw_bad_signature_rejects() {
        let mut raw = make_csw(1, 0, 0);
        raw[0] = 0xFF; // corrupt signature
        assert_eq!(parse_csw(&raw), Err(StorageError::BadSignature));
    }

    #[test]
    fn csw_too_short_rejects() {
        assert_eq!(parse_csw(&[0u8; 12]), Err(StorageError::TooShort));
        assert_eq!(parse_csw(&[]), Err(StorageError::TooShort));
    }

    #[test]
    fn csw_exact_length_ok() {
        let raw = make_csw(0, 0, 0);
        assert_eq!(raw.len(), CSW_LEN);
        assert!(parse_csw(&raw).is_ok());
    }

    // -- SCSI CDB builders --------------------------------------------------

    #[test]
    fn cdb_inquiry_opcode_and_alloc_len() {
        let cdb = cdb_inquiry(36);
        assert_eq!(cdb[0], 0x12, "INQUIRY opcode");
        assert_eq!(cdb[4], 36, "alloc_len");
    }

    #[test]
    fn cdb_test_unit_ready_all_zeros_except_opcode() {
        let cdb = cdb_test_unit_ready();
        assert_eq!(cdb[0], 0x00, "TUR opcode");
        assert_eq!(&cdb[1..], &[0u8; 5]);
    }

    #[test]
    fn cdb_read_capacity10_opcode() {
        let cdb = cdb_read_capacity10();
        assert_eq!(cdb[0], 0x25, "READ CAPACITY(10) opcode");
        assert_eq!(&cdb[1..], &[0u8; 9]);
    }

    #[test]
    fn cdb_read10_lba_and_blocks() {
        let cdb = cdb_read10(0x1234_5678, 3);
        assert_eq!(cdb[0], 0x28, "READ(10) opcode");
        // LBA in big-endian: bytes 2..5.
        assert_eq!(
            u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]),
            0x1234_5678
        );
        // Transfer length in big-endian: bytes 7..8.
        assert_eq!(u16::from_be_bytes([cdb[7], cdb[8]]), 3);
    }

    #[test]
    fn cdb_write10_lba_and_blocks() {
        let cdb = cdb_write10(0xABCD_EF01, 5);
        assert_eq!(cdb[0], 0x2A, "WRITE(10) opcode");
        assert_eq!(
            u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]),
            0xABCD_EF01
        );
        assert_eq!(u16::from_be_bytes([cdb[7], cdb[8]]), 5);
    }

    #[test]
    fn cdb_read10_lba_zero_blocks_zero() {
        let cdb = cdb_read10(0, 0);
        assert_eq!(&cdb[1..], &[0u8; 9]);
    }

    // -- BlkRequest → SCSI round-trip ----------------------------------------

    #[test]
    fn blk_read_maps_to_read10() {
        let req = BlkRequest::Read {
            lba: 0,
            count: 2,
            buf_iova: 0x1000,
        };
        let op = blk_request_to_scsi(&req).unwrap();
        assert!(op.dir_in, "READ is dir_in");
        assert_eq!(op.cdb[0], 0x28, "READ(10) opcode");
        assert_eq!(op.data_len, 2 * BLOCK_SIZE_BYTES, "data_len = 2 × 4096");
    }

    #[test]
    fn blk_write_maps_to_write10() {
        let req = BlkRequest::Write {
            lba: 10,
            count: 3,
            buf_iova: 0x2000,
        };
        let op = blk_request_to_scsi(&req).unwrap();
        assert!(!op.dir_in, "WRITE is !dir_in");
        assert_eq!(op.cdb[0], 0x2A, "WRITE(10) opcode");
        assert_eq!(op.data_len, 3 * BLOCK_SIZE_BYTES);
        // LBA 10 in READ/WRITE(10) bytes 2..5 (big-endian).
        assert_eq!(
            u32::from_be_bytes([op.cdb[2], op.cdb[3], op.cdb[4], op.cdb[5]]),
            10
        );
    }

    #[test]
    fn blk_flush_maps_to_test_unit_ready() {
        let req = BlkRequest::Flush;
        let op = blk_request_to_scsi(&req).unwrap();
        assert_eq!(op.cdb[0], 0x00, "TEST UNIT READY opcode");
        assert_eq!(op.data_len, 0, "no data phase");
        assert!(!op.dir_in);
    }

    #[test]
    fn blk_discard_unsupported() {
        let req = BlkRequest::Discard { lba: 0, count: 1 };
        assert_eq!(
            blk_request_to_scsi(&req),
            Err(StorageError::UnsupportedRequest)
        );
    }

    #[test]
    fn blk_read_lba_encoded_correctly() {
        let req = BlkRequest::Read {
            lba: 0x0000_0000_DEAD_BEEF,
            count: 1,
            buf_iova: 0,
        };
        let op = blk_request_to_scsi(&req).unwrap();
        // lba truncated to 32 bits for READ(10).
        #[allow(clippy::cast_possible_truncation)]
        let expected_lba = 0xDEAD_BEEF_u32;
        assert_eq!(
            u32::from_be_bytes([op.cdb[2], op.cdb[3], op.cdb[4], op.cdb[5]]),
            expected_lba
        );
    }

    // -- csw_to_blk_response ------------------------------------------------

    #[test]
    fn csw_status_0_maps_to_ok() {
        let csw = CommandStatusWrapper {
            tag: 1,
            residue: 0,
            status: 0,
        };
        assert_eq!(csw_to_blk_response(&csw), BlkResponse::Ok);
    }

    #[test]
    fn csw_status_1_maps_to_device_error() {
        let csw = CommandStatusWrapper {
            tag: 1,
            residue: 0,
            status: 1,
        };
        assert!(matches!(
            csw_to_blk_response(&csw),
            BlkResponse::DeviceError(NON_NVME_DEVICE_ERROR)
        ));
    }

    #[test]
    fn csw_status_2_maps_to_device_error() {
        let csw = CommandStatusWrapper {
            tag: 1,
            residue: 0,
            status: 2,
        };
        assert!(matches!(
            csw_to_blk_response(&csw),
            BlkResponse::DeviceError(_)
        ));
    }

    // -- parse_read_capacity10 ----------------------------------------------

    #[test]
    fn read_capacity10_happy_path() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&0x0000_0FFFu32.to_be_bytes());
        data[4..8].copy_from_slice(&4096u32.to_be_bytes());
        let (last_lba, block_size) = parse_read_capacity10(&data).unwrap();
        assert_eq!(last_lba, 0x0000_0FFF);
        assert_eq!(block_size, 4096);
    }

    #[test]
    fn read_capacity10_too_short_rejects() {
        assert_eq!(
            parse_read_capacity10(&[0u8; 7]),
            Err(StorageError::TooShort)
        );
    }

    // -- parse_inquiry -------------------------------------------------------

    #[test]
    fn inquiry_happy_path() {
        let mut data = [0x20u8; 36]; // space-padded ASCII
        data[0] = 0x00; // direct-access device
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(resp.device_type, 0x00);
    }

    #[test]
    fn inquiry_device_type_mask() {
        let mut data = [0x00u8; 36];
        data[0] = 0xFF; // all bits set; device_type is bits 4:0 = 0x1F
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(resp.device_type, 0x1F, "device_type mask 0x1F");
    }

    #[test]
    fn inquiry_too_short_rejects() {
        assert_eq!(parse_inquiry(&[0u8; 35]), Err(StorageError::TooShort));
        assert_eq!(parse_inquiry(&[]), Err(StorageError::TooShort));
    }

    #[test]
    fn inquiry_vendor_and_product_fields() {
        let mut data = [0x20u8; 36];
        // Vendor: bytes 8..15 = "NexaCore    ".
        data[8..16].copy_from_slice(b"OMNI    ");
        // Product: bytes 16..31 = "TEST DRIVE      ".
        data[16..32].copy_from_slice(b"TEST DRIVE      ");
        let resp = parse_inquiry(&data).unwrap();
        assert_eq!(&resp.vendor, b"OMNI    ");
        assert_eq!(&resp.product[..10], b"TEST DRIVE");
    }

    // -- READ(16) / WRITE(16) ------------------------------------------------

    #[test]
    fn read16_write16_cdb_shape() {
        let r = cdb_read16(0x1_0000_0000, 8);
        assert_eq!(r[0], 0x88); // READ(16)
        assert_eq!(
            u64::from_be_bytes(r[2..10].try_into().unwrap()),
            0x1_0000_0000
        );
        assert_eq!(u32::from_be_bytes(r[10..14].try_into().unwrap()), 8);
        let w = cdb_write16(0x1_0000_0000, 8);
        assert_eq!(w[0], 0x8A); // WRITE(16)
    }

    #[test]
    fn gateway_picks_16byte_cdb_for_large_lba() {
        // An LBA beyond the 32-bit range forces READ(16).
        let big = BlkRequest::Read {
            lba: 0x1_0000_0000,
            count: 1,
            buf_iova: 0x1000,
        };
        let op = blk_request_to_scsi(&big).unwrap();
        assert_eq!(op.cdb_len, 16);
        assert_eq!(op.cdb[0], 0x88); // READ(16)

        // A block count beyond the 16-bit range also forces the 16-byte form.
        let many = BlkRequest::Write {
            lba: 0,
            count: 0x1_0000,
            buf_iova: 0x2000,
        };
        let op = blk_request_to_scsi(&many).unwrap();
        assert_eq!(op.cdb_len, 16);
        assert_eq!(op.cdb[0], 0x8A); // WRITE(16)
    }

    #[test]
    fn gateway_keeps_10byte_cdb_for_small_requests() {
        let small = BlkRequest::Read {
            lba: 0xFFFF_FFFF,
            count: 0xFFFF,
            buf_iova: 0x1000,
        };
        let op = blk_request_to_scsi(&small).unwrap();
        assert_eq!(op.cdb_len, 10);
        assert_eq!(op.cdb[0], 0x28); // READ(10)
    }

    // -- READ CAPACITY(16) ---------------------------------------------------

    #[test]
    fn read_capacity16_cdb_shape() {
        let cdb = cdb_read_capacity16(32);
        assert_eq!(cdb[0], 0x9E); // SERVICE ACTION IN(16)
        assert_eq!(cdb[1], 0x10); // READ CAPACITY(16) service action
        assert_eq!(u32::from_be_bytes(cdb[10..14].try_into().unwrap()), 32);
    }

    #[test]
    fn read_capacity16_parses_64bit_last_lba() {
        let mut data = [0u8; 32];
        data[0..8].copy_from_slice(&0x0000_0002_0000_0000u64.to_be_bytes());
        data[8..12].copy_from_slice(&512u32.to_be_bytes());
        let (last_lba, block_size) = parse_read_capacity16(&data).unwrap();
        assert_eq!(last_lba, 0x2_0000_0000);
        assert_eq!(block_size, 512);
    }

    #[test]
    fn read_capacity16_too_short_rejects() {
        assert_eq!(
            parse_read_capacity16(&[0u8; 31]),
            Err(StorageError::TooShort)
        );
    }

    // -- REQUEST SENSE -------------------------------------------------------

    #[test]
    fn request_sense_cdb_shape() {
        let cdb = cdb_request_sense(18);
        assert_eq!(cdb[0], 0x03); // REQUEST SENSE opcode
        assert_eq!(cdb[4], 18); // allocation length
        assert_eq!(cdb[1], 0x00); // fixed-format (DESC=0)
    }

    #[test]
    fn sense_extracts_key_asc_ascq_and_masks() {
        let mut data = [0u8; 18];
        data[0] = 0xF0; // valid bit set + response code 0x70
        data[2] = 0xE6; // reserved high nibble + sense key 0x06 (UNIT ATTENTION)
        data[12] = 0x28; // ASC
        data[13] = 0x02; // ASCQ
        let sense = parse_sense(&data).unwrap();
        assert_eq!(sense.response_code, 0x70); // high (valid) bit masked off
        assert_eq!(sense.sense_key, 0x06); // high nibble masked off
        assert_eq!(sense.asc, 0x28);
        assert_eq!(sense.ascq, 0x02);
        assert!(!sense.is_no_sense());
    }

    #[test]
    fn sense_no_sense_key_is_reported() {
        let data = [0x70u8, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sense = parse_sense(&data).unwrap();
        assert!(sense.is_no_sense());
    }

    #[test]
    fn sense_too_short_rejects_without_panic() {
        // 13 bytes cannot reach the ASCQ at byte 13.
        assert_eq!(parse_sense(&[0u8; 13]), Err(StorageError::TooShort));
        assert_eq!(parse_sense(&[]), Err(StorageError::TooShort));
    }
}

//! TPM 2.0 command serialization (WS2-15.4/.5/.6/.8).
//!
//! TPM 2.0 commands are big-endian, length-prefixed structures (TPM 2.0 Part 1
//! § 18, Part 2 structures, Part 3 commands):
//!
//! ```text
//!   TPM_ST    tag           (u16)   — sessions vs no-sessions
//!   UINT32    commandSize   (u32)   — total bytes incl. this header
//!   TPM_CC    commandCode   (u32)
//!   <handles> <auth area> <parameters>
//! ```
//!
//! [`TpmCommand`] builds one with the size back-patched on [`TpmCommand::finish`].
//! [`build_pcr_extend`] and [`build_quote`] compose the two commands WS2-15
//! needs; [`parse_response_header`] reads the 10-byte response header back.

use alloc::vec::Vec;

/// `TPM_ST_NO_SESSIONS` — command carries no authorization area.
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_ST_SESSIONS` — command carries an authorization area.
pub const TPM_ST_SESSIONS: u16 = 0x8002;

/// `TPM_CC_PCR_Extend`.
pub const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
/// `TPM_CC_Quote`.
pub const TPM_CC_QUOTE: u32 = 0x0000_0158;
/// `TPM_CC_Startup`.
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;

/// `TPM_RS_PW` — the password authorization session handle.
pub const TPM_RS_PW: u32 = 0x4000_0009;

/// `TPM_ALG_SHA256`.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// `TPM_ALG_SHA1`.
pub const TPM_ALG_SHA1: u16 = 0x0004;
/// `TPM_ALG_NULL` — "use the key's default" (signing scheme).
pub const TPM_ALG_NULL: u16 = 0x0010;

/// `TPM_RC_SUCCESS`.
pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;

/// Length of a TPM command/response header (tag + size + code).
pub const HEADER_LEN: usize = 10;

/// SHA-256 digest length.
pub const SHA256_LEN: usize = 32;

/// A TPM 2.0 command being assembled.
///
/// Construct with [`Self::new`], append fields, then [`Self::finish`] to get the
/// wire bytes with `commandSize` filled in.
#[derive(Debug, Clone)]
pub struct TpmCommand {
    buf: Vec<u8>,
}

impl TpmCommand {
    /// Begin a command with the given tag + command code. The 4-byte size field
    /// is reserved and back-patched by [`Self::finish`].
    #[must_use]
    pub fn new(tag: u16, command_code: u32) -> Self {
        let mut buf = Vec::with_capacity(HEADER_LEN);
        buf.extend_from_slice(&tag.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
        buf.extend_from_slice(&command_code.to_be_bytes());
        Self { buf }
    }

    /// Append a big-endian `u8`.
    pub fn push_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Append a big-endian `u16`.
    pub fn push_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian `u32`.
    pub fn push_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append raw bytes.
    pub fn push_bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Append a `TPM2B` (a `u16` length prefix followed by the bytes).
    pub fn push_tpm2b(&mut self, b: &[u8]) {
        self.push_u16(b.len() as u16);
        self.push_bytes(b);
    }

    /// Append an empty password authorization area (`TPM_RS_PW`, no nonce, no
    /// attributes, empty HMAC) wrapped in its `authorizationSize` prefix.
    pub fn push_empty_password_auth(&mut self) {
        // The auth area itself: handle + nonce(TPM2B, empty) + attrs + hmac(TPM2B, empty).
        // sessionHandle(4) + nonceSize(2)=0 + attrs(1) + hmacSize(2)=0 = 9 bytes.
        const AUTH_AREA_LEN: u32 = 4 + 2 + 1 + 2;
        self.push_u32(AUTH_AREA_LEN);
        self.push_u32(TPM_RS_PW);
        self.push_u16(0); // nonce size
        self.push_u8(0); // session attributes
        self.push_u16(0); // hmac size
    }

    /// Finalize: back-patch `commandSize` and return the wire bytes.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        let size = self.buf.len() as u32;
        if let Some(slot) = self.buf.get_mut(2..6) {
            slot.copy_from_slice(&size.to_be_bytes());
        }
        self.buf
    }

    /// Current length (for tests / size assertions before `finish`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing beyond the header has been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.len() <= HEADER_LEN
    }
}

/// Build a `TPM2_PCR_Extend` command extending PCR `pcr_index` in the `alg`
/// bank with `digest` (WS2-15.5).
///
/// Uses an empty-password authorization session. `digest` must be the bank's
/// digest length (32 for SHA-256); it is sent as-is.
#[must_use]
pub fn build_pcr_extend(pcr_index: u32, alg: u16, digest: &[u8]) -> Vec<u8> {
    let mut cmd = TpmCommand::new(TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND);
    cmd.push_u32(pcr_index); // @pcrHandle
    cmd.push_empty_password_auth();
    // TPML_DIGEST_VALUES: count, then one TPMT_HA { hashAlg, digest }.
    cmd.push_u32(1);
    cmd.push_u16(alg);
    cmd.push_bytes(digest);
    cmd.finish()
}

/// A PCR selection over PCRs 0..24 (the standard 24-PCR platform bank).
#[derive(Debug, Clone, Copy, Default)]
pub struct PcrSelection {
    bitmap: [u8; 3],
}

impl PcrSelection {
    /// An empty selection.
    #[must_use]
    pub const fn new() -> Self {
        Self { bitmap: [0; 3] }
    }

    /// Select PCR `index` (0..24). Out-of-range indices are ignored.
    pub fn select(&mut self, index: u8) {
        let byte = (index / 8) as usize;
        let bit = index % 8;
        if let Some(slot) = self.bitmap.get_mut(byte) {
            *slot |= 1 << bit;
        }
    }

    /// The 3-byte selection bitmap.
    #[must_use]
    pub const fn bitmap(self) -> [u8; 3] {
        self.bitmap
    }
}

/// Build a `TPM2_Quote` command signing PCRs `pcrs` (in the `bank_alg` bank)
/// with the attestation key `ak_handle`, over `qualifying_data` (WS2-15.6).
///
/// The signing scheme is `TPM_ALG_NULL` — the AK's own scheme is used.
#[must_use]
pub fn build_quote(
    ak_handle: u32,
    qualifying_data: &[u8],
    bank_alg: u16,
    pcrs: PcrSelection,
) -> Vec<u8> {
    let mut cmd = TpmCommand::new(TPM_ST_SESSIONS, TPM_CC_QUOTE);
    cmd.push_u32(ak_handle); // @signHandle
    cmd.push_empty_password_auth();
    // qualifyingData: TPM2B_DATA.
    cmd.push_tpm2b(qualifying_data);
    // inScheme: TPMT_SIG_SCHEME = { scheme alg }. NULL → no further fields.
    cmd.push_u16(TPM_ALG_NULL);
    // PCRselect: TPML_PCR_SELECTION = count, then one TPMS_PCR_SELECTION.
    cmd.push_u32(1);
    cmd.push_u16(bank_alg);
    cmd.push_u8(3); // sizeofSelect = 3 bytes (24 PCRs)
    cmd.push_bytes(&pcrs.bitmap());
    cmd.finish()
}

/// Build a `TPM2_Startup(TPM_SU_CLEAR)` command (the first command after reset).
#[must_use]
pub fn build_startup_clear() -> Vec<u8> {
    let mut cmd = TpmCommand::new(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP);
    cmd.push_u16(0x0000); // TPM_SU_CLEAR
    cmd.finish()
}

/// A parsed TPM response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    /// Response tag (echoes the command's session mode).
    pub tag: u16,
    /// Total response size in bytes (incl. this header).
    pub size: u32,
    /// Response code; `0` ([`TPM_RC_SUCCESS`]) on success.
    pub code: u32,
}

impl ResponseHeader {
    /// Whether the command succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.code == TPM_RC_SUCCESS
    }
}

/// Why a response could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    /// The buffer is shorter than a 10-byte header.
    ShortResponse,
    /// `responseSize` disagrees with the actual buffer length.
    SizeMismatch,
}

/// Parse the 10-byte TPM response header, validating `responseSize` against the
/// buffer length.
///
/// # Errors
///
/// [`TpmError::ShortResponse`] if `buf` is shorter than [`HEADER_LEN`];
/// [`TpmError::SizeMismatch`] if the declared `responseSize` exceeds the buffer.
pub fn parse_response_header(buf: &[u8]) -> Result<ResponseHeader, TpmError> {
    let header: [u8; HEADER_LEN] = buf
        .get(..HEADER_LEN)
        .ok_or(TpmError::ShortResponse)?
        .try_into()
        .map_err(|_| TpmError::ShortResponse)?;
    let tag = u16::from_be_bytes([header[0], header[1]]);
    let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
    let code = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
    // The TPM must not claim more bytes than were delivered.
    if (size as usize) > buf.len() {
        return Err(TpmError::SizeMismatch);
    }
    Ok(ResponseHeader { tag, size, code })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be_u16(b: &[u8], off: usize) -> u16 {
        u16::from_be_bytes([b[off], b[off + 1]])
    }
    fn be_u32(b: &[u8], off: usize) -> u32 {
        u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    #[test]
    fn command_header_size_is_back_patched() {
        let mut c = TpmCommand::new(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP);
        c.push_u16(0);
        let bytes = c.finish();
        assert_eq!(be_u16(&bytes, 0), TPM_ST_NO_SESSIONS);
        assert_eq!(
            be_u32(&bytes, 2) as usize,
            bytes.len(),
            "size = total length"
        );
        assert_eq!(be_u32(&bytes, 6), TPM_CC_STARTUP);
    }

    #[test]
    fn pcr_extend_layout_is_correct() {
        let digest = [0xABu8; SHA256_LEN];
        let bytes = build_pcr_extend(7, TPM_ALG_SHA256, &digest);
        assert_eq!(be_u16(&bytes, 0), TPM_ST_SESSIONS);
        assert_eq!(be_u32(&bytes, 2) as usize, bytes.len());
        assert_eq!(be_u32(&bytes, 6), TPM_CC_PCR_EXTEND);
        // @pcrHandle at offset 10.
        assert_eq!(be_u32(&bytes, 10), 7);
        // authSize at 14 = 9; session handle at 18 = TPM_RS_PW.
        assert_eq!(be_u32(&bytes, 14), 9);
        assert_eq!(be_u32(&bytes, 18), TPM_RS_PW);
        // After the 9-byte auth area (18..27): count=1, alg, digest.
        let after_auth = 14 + 4 + 9; // sizefield + auth area
        assert_eq!(be_u32(&bytes, after_auth), 1, "digest count");
        assert_eq!(be_u16(&bytes, after_auth + 4), TPM_ALG_SHA256);
        assert_eq!(
            &bytes[after_auth + 6..],
            &digest,
            "digest appended verbatim"
        );
    }

    #[test]
    fn quote_includes_qualifying_data_and_pcr_selection() {
        let mut sel = PcrSelection::new();
        sel.select(0);
        sel.select(7);
        let qual = [0x11u8, 0x22, 0x33];
        let bytes = build_quote(0x8100_0000, &qual, TPM_ALG_SHA256, sel);
        assert_eq!(be_u32(&bytes, 6), TPM_CC_QUOTE);
        assert_eq!(be_u32(&bytes, 10), 0x8100_0000, "AK handle");
        // qualifyingData TPM2B starts after the 13-byte auth block (14 + 4 + 9).
        let q_off = 14 + 4 + 9;
        assert_eq!(be_u16(&bytes, q_off), 3, "qualifyingData length");
        assert_eq!(&bytes[q_off + 2..q_off + 5], &qual);
        // inScheme NULL follows.
        assert_eq!(be_u16(&bytes, q_off + 5), TPM_ALG_NULL);
        // PCR selection: count=1, alg, sizeofSelect=3, bitmap.
        let s_off = q_off + 7;
        assert_eq!(be_u32(&bytes, s_off), 1);
        assert_eq!(be_u16(&bytes, s_off + 4), TPM_ALG_SHA256);
        assert_eq!(bytes[s_off + 6], 3);
        // PCR 0 and 7 → byte 0 = 0b1000_0001 = 0x81.
        assert_eq!(bytes[s_off + 7], 0x81);
    }

    #[test]
    fn pcr_selection_sets_correct_bits() {
        let mut sel = PcrSelection::new();
        sel.select(0);
        sel.select(8);
        sel.select(23);
        // byte0 bit0, byte1 bit0, byte2 bit7.
        assert_eq!(sel.bitmap(), [0x01, 0x01, 0x80]);
        // Out-of-range ignored.
        sel.select(99);
        assert_eq!(sel.bitmap(), [0x01, 0x01, 0x80]);
    }

    #[test]
    fn response_header_parses_and_validates_size() {
        // tag 0x8001, size 10, code 0 (success), exactly 10 bytes.
        let resp = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00];
        let h = parse_response_header(&resp).unwrap();
        assert_eq!(h.tag, 0x8001);
        assert_eq!(h.size, 10);
        assert!(h.is_success());
    }

    #[test]
    fn response_too_short_is_rejected() {
        assert_eq!(
            parse_response_header(&[0u8; 9]),
            Err(TpmError::ShortResponse)
        );
    }

    #[test]
    fn response_claiming_more_than_buffer_is_rejected() {
        // size says 32 but only 10 bytes present.
        let resp = [0x80, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_response_header(&resp), Err(TpmError::SizeMismatch));
    }

    #[test]
    fn error_response_code_is_surfaced() {
        // code 0x0000_0101 (a TPM error).
        let resp = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x01];
        let h = parse_response_header(&resp).unwrap();
        assert!(!h.is_success());
        assert_eq!(h.code, 0x0000_0101);
    }
}

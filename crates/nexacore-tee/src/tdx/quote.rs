//! Intel TDX Quote v4 / TD-report parsing and report-data binding
//! (WS10-01.5, WS10-01.7).
//!
//! A TDX quote (Intel DCAP "Quote4") is a little-endian binary structure:
//!
//! ```text
//! Header        (48 bytes)  version, att-key type, TEE type, QE/PCE SVN, …
//! TD Report     (584 bytes) TEE_TCB_SVN, MRSEAM, MRTD, RTMR0..3, REPORT_DATA, …
//! Signature data            sig_data_len(u32) + ECDSA-P256 sig(64) +
//!                           attestation key(64) + certification data
//! ```
//!
//! Parsing the structure is pure, deterministic, and host-testable — and it is
//! the precondition for every later check (MRTD comparison, RTMR replay,
//! report-data binding, TCB evaluation).  The *cryptographic* verification of
//! the ECDSA signature and the PCK certificate chain needs ECDSA-P-256 / X.509,
//! which `nexacore-crypto` does not yet provide; that step is therefore
//! library-gated and lives behind [`super::pck`].  This module recovers the
//! bytes those steps operate on, including the exact `signed_region` the
//! signature covers (header ‖ TD report).

use alloc::vec::Vec;

/// Quote format version this parser understands (Intel DCAP Quote v4).
pub const TDX_QUOTE_VERSION_4: u16 = 4;

/// TEE type discriminator for Intel TDX in the quote header.
pub const TEE_TYPE_TDX: u32 = 0x0000_0081;

/// Attestation-key type: ECDSA-256-with-P-256 curve.
pub const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;

/// Byte length of the quote header.
pub const HEADER_LEN: usize = 48;

/// Byte length of the TD report body (`sgx_report2_body_t`).
pub const TD_REPORT_BODY_LEN: usize = 584;

/// Byte length of the region the quote signature covers (header ‖ body).
pub const SIGNED_REGION_LEN: usize = HEADER_LEN + TD_REPORT_BODY_LEN;

/// Errors that can arise while parsing a TDX quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteParseError {
    /// The buffer ended before a field could be read.
    Truncated,
    /// The header `version` field was not [`TDX_QUOTE_VERSION_4`].
    UnsupportedVersion(u16),
    /// The header `tee_type` field was not [`TEE_TYPE_TDX`].
    NotTdx(u32),
    /// The declared signature-data length exceeded the remaining bytes.
    BadSignatureLength,
}

impl core::fmt::Display for QuoteParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("tdx quote truncated"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported tdx quote version {v}"),
            Self::NotTdx(t) => write!(f, "quote tee_type {t:#x} is not TDX"),
            Self::BadSignatureLength => f.write_str("tdx quote signature length out of range"),
        }
    }
}

impl core::error::Error for QuoteParseError {}

/// The 48-byte quote header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteHeader {
    /// Quote format version (expected [`TDX_QUOTE_VERSION_4`]).
    pub version: u16,
    /// Attestation key type (expected [`ATT_KEY_TYPE_ECDSA_P256`]).
    pub att_key_type: u16,
    /// TEE type (expected [`TEE_TYPE_TDX`]).
    pub tee_type: u32,
    /// Quoting-Enclave security version number.
    pub qe_svn: u16,
    /// Provisioning-Certification-Enclave security version number.
    pub pce_svn: u16,
    /// Quoting-Enclave vendor identifier.
    pub qe_vendor_id: [u8; 16],
    /// 20 bytes of user data carried in the header.
    pub user_data: [u8; 20],
}

/// The 584-byte TD report body — the measured state of the TD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdReportBody {
    /// TEE TCB security-version numbers (16 components).
    pub tee_tcb_svn: [u8; 16],
    /// Measurement of the TDX module (SEAM).
    pub mr_seam: [u8; 48],
    /// Measurement of the TDX-module signer.
    pub mr_signer_seam: [u8; 48],
    /// SEAM attributes.
    pub seam_attributes: [u8; 8],
    /// TD attributes.
    pub td_attributes: [u8; 8],
    /// Extended features available mask.
    pub xfam: [u8; 8],
    /// Build-time measurement of the TD (the MRTD — maps to [`Measurement`]).
    ///
    /// [`Measurement`]: crate::attestation::Measurement
    pub mr_td: [u8; 48],
    /// Software-defined configuration measurement.
    pub mr_config_id: [u8; 48],
    /// TD owner measurement.
    pub mr_owner: [u8; 48],
    /// TD owner configuration measurement.
    pub mr_owner_config: [u8; 48],
    /// Run-time measurement registers RTMR0..RTMR3.
    pub rtmr: [[u8; 48]; 4],
    /// 64 bytes of report data — the binding slot (mesh handshake transcript).
    pub report_data: [u8; 64],
}

/// The ECDSA-P-256 signature section of the quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignatureData {
    /// ECDSA-P-256 signature over `signed_region` (`r ‖ s`, 64 bytes).
    pub signature: [u8; 64],
    /// The attestation public key (`x ‖ y`, 64 bytes).
    pub attestation_key: [u8; 64],
    /// Certification-data type (6 = QE report + PCK cert chain).
    pub cert_data_type: u16,
    /// Raw certification data (parsed further by [`super::pck`]).
    pub cert_data: Vec<u8>,
}

/// A fully parsed TDX quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxQuote {
    /// Parsed header.
    pub header: QuoteHeader,
    /// Parsed TD report body.
    pub body: TdReportBody,
    /// Parsed signature section.
    pub signature: EcdsaSignatureData,
    /// The exact header ‖ body bytes the ECDSA signature is computed over.
    pub signed_region: Vec<u8>,
}

/// A little-endian forward cursor that never indexes out of bounds.
struct Le<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Le<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], QuoteParseError> {
        let end = self.pos.checked_add(n).ok_or(QuoteParseError::Truncated)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(QuoteParseError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], QuoteParseError> {
        let slice = self.take(N)?;
        <[u8; N]>::try_from(slice).map_err(|_| QuoteParseError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, QuoteParseError> {
        Ok(u16::from_le_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, QuoteParseError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }
}

/// Parse a TDX quote-v4 byte buffer (typically `Quote::body`).
///
/// # Errors
/// Returns [`QuoteParseError`] on truncation, a non-v4 version, a non-TDX TEE
/// type, or an out-of-range signature-data length.
pub fn parse(bytes: &[u8]) -> Result<TdxQuote, QuoteParseError> {
    let signed_region = bytes
        .get(..SIGNED_REGION_LEN)
        .ok_or(QuoteParseError::Truncated)?
        .to_vec();

    let mut r = Le::new(bytes);

    // --- Header (48 bytes) ---
    let version = r.u16()?;
    if version != TDX_QUOTE_VERSION_4 {
        return Err(QuoteParseError::UnsupportedVersion(version));
    }
    let att_key_type = r.u16()?;
    let tee_type = r.u32()?;
    if tee_type != TEE_TYPE_TDX {
        return Err(QuoteParseError::NotTdx(tee_type));
    }
    let qe_svn = r.u16()?;
    let pce_svn = r.u16()?;
    let qe_vendor_id = r.array::<16>()?;
    let user_data = r.array::<20>()?;
    let header = QuoteHeader {
        version,
        att_key_type,
        tee_type,
        qe_svn,
        pce_svn,
        qe_vendor_id,
        user_data,
    };

    // --- TD report body (584 bytes) ---
    let tee_tcb_svn = r.array::<16>()?;
    let mr_seam = r.array::<48>()?;
    let mr_signer_seam = r.array::<48>()?;
    let seam_attributes = r.array::<8>()?;
    let td_attributes = r.array::<8>()?;
    let xfam = r.array::<8>()?;
    let mr_td = r.array::<48>()?;
    let mr_config_id = r.array::<48>()?;
    let mr_owner = r.array::<48>()?;
    let mr_owner_config = r.array::<48>()?;
    let rtmr = [
        r.array::<48>()?,
        r.array::<48>()?,
        r.array::<48>()?,
        r.array::<48>()?,
    ];
    let report_data = r.array::<64>()?;
    let body = TdReportBody {
        tee_tcb_svn,
        mr_seam,
        mr_signer_seam,
        seam_attributes,
        td_attributes,
        xfam,
        mr_td,
        mr_config_id,
        mr_owner,
        mr_owner_config,
        rtmr,
        report_data,
    };

    // --- Signature data ---
    let sig_data_len = r.u32()? as usize;
    let signature = r.array::<64>()?;
    let attestation_key = r.array::<64>()?;
    let cert_data_type = r.u16()?;
    let cert_data_size = r.u32()? as usize;
    // The declared sig_data_len must cover sig(64)+key(64)+type(2)+size(4)+cert.
    let expected = 64 + 64 + 2 + 4 + cert_data_size;
    if sig_data_len < expected {
        return Err(QuoteParseError::BadSignatureLength);
    }
    let cert_data = r.take(cert_data_size)?.to_vec();

    Ok(TdxQuote {
        header,
        body,
        signature: EcdsaSignatureData {
            signature,
            attestation_key,
            cert_data_type,
            cert_data,
        },
        signed_region,
    })
}

impl TdReportBody {
    /// `true` if the 64-byte report-data slot equals `expected`.
    ///
    /// The mesh handshake commits its transcript hash into `report_data`; the
    /// verifier confirms the binding by exact comparison (WS10-01.7).
    #[must_use]
    pub fn report_data_matches(&self, expected: &[u8; 64]) -> bool {
        // `[u8; 64]` derives `PartialEq` only up to 32 historically; compare via
        // slices to be unambiguous and constant-shaped.
        self.report_data.as_slice() == expected.as_slice()
    }

    /// `true` if the MRTD equals `expected` (the vendor-neutral measurement).
    #[must_use]
    pub fn mr_td_matches(&self, expected: &[u8; 48]) -> bool {
        self.mr_td.as_slice() == expected.as_slice()
    }
}

/// Build the 64-byte report-data field that binds a quote to a mesh handshake.
///
/// The mesh handshake produces a transcript hash; TDX commits 64 bytes of
/// report data, so a 32-byte transcript hash is placed in the low half and the
/// high half is zero-padded (the verifier reconstructs the same layout).  This
/// is the canonical binding the attestor requests and the verifier checks.
#[must_use]
pub fn bind_transcript_hash(transcript_hash: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some(dst) = out.get_mut(..32) {
        dst.copy_from_slice(transcript_hash);
    }
    out
}

/// Build a synthetic but structurally valid TDX quote (host tests only).
///
/// Parametric in MRTD, report-data, TEE-TCB SVN, and PCE SVN so the quote,
/// TCB, and offline-verification tests can all drive it.
#[cfg(test)]
#[allow(
    clippy::missing_docs_in_private_items,
    clippy::cast_possible_truncation,
    reason = "test fixture lengths are tiny and cast usize->u32 for the wire layout"
)]
pub(crate) fn build_test_quote(
    mr_td: [u8; 48],
    report_data: [u8; 64],
    tee_tcb_svn: [u8; 16],
    pce_svn: u16,
    cert: &[u8],
) -> Vec<u8> {
    let mut q = Vec::new();
    // Header.
    q.extend_from_slice(&TDX_QUOTE_VERSION_4.to_le_bytes());
    q.extend_from_slice(&ATT_KEY_TYPE_ECDSA_P256.to_le_bytes());
    q.extend_from_slice(&TEE_TYPE_TDX.to_le_bytes());
    q.extend_from_slice(&7u16.to_le_bytes()); // qe_svn
    q.extend_from_slice(&pce_svn.to_le_bytes()); // pce_svn
    q.extend_from_slice(&[0xAB; 16]); // qe_vendor_id
    q.extend_from_slice(&[0xCD; 20]); // user_data

    // TD report body.
    q.extend_from_slice(&tee_tcb_svn); // tee_tcb_svn
    q.extend_from_slice(&[0x02; 48]); // mr_seam
    q.extend_from_slice(&[0x03; 48]); // mr_signer_seam
    q.extend_from_slice(&[0x04; 8]); // seam_attributes
    q.extend_from_slice(&[0x05; 8]); // td_attributes
    q.extend_from_slice(&[0x06; 8]); // xfam
    q.extend_from_slice(&mr_td); // mr_td
    q.extend_from_slice(&[0x07; 48]); // mr_config_id
    q.extend_from_slice(&[0x08; 48]); // mr_owner
    q.extend_from_slice(&[0x09; 48]); // mr_owner_config
    q.extend_from_slice(&[0x0A; 48]); // rtmr0
    q.extend_from_slice(&[0x0B; 48]); // rtmr1
    q.extend_from_slice(&[0x0C; 48]); // rtmr2
    q.extend_from_slice(&[0x0D; 48]); // rtmr3
    q.extend_from_slice(&report_data); // report_data

    // Signature data.
    let cert_data_size = cert.len();
    let sig_data_len = 64 + 64 + 2 + 4 + cert_data_size;
    q.extend_from_slice(&(sig_data_len as u32).to_le_bytes());
    q.extend_from_slice(&[0x11; 64]); // signature
    q.extend_from_slice(&[0x22; 64]); // attestation_key
    q.extend_from_slice(&6u16.to_le_bytes()); // cert_data_type
    q.extend_from_slice(&(cert_data_size as u32).to_le_bytes());
    q.extend_from_slice(cert);
    q
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn synth_quote(mr_td: [u8; 48], report_data: [u8; 64], cert: &[u8]) -> Vec<u8> {
        build_test_quote(mr_td, report_data, [0x01; 16], 13, cert)
    }

    #[test]
    fn parses_a_valid_quote() {
        let mr = [0x42; 48];
        let rd = [0x55; 64];
        let bytes = synth_quote(mr, rd, b"PCKCHAIN");
        let quote = parse(&bytes).expect("parses");

        assert_eq!(quote.header.version, TDX_QUOTE_VERSION_4);
        assert_eq!(quote.header.tee_type, TEE_TYPE_TDX);
        assert_eq!(quote.header.qe_svn, 7);
        assert_eq!(quote.header.pce_svn, 13);
        assert!(quote.body.mr_td_matches(&mr));
        assert!(quote.body.report_data_matches(&rd));
        assert_eq!(quote.body.rtmr[2], [0x0C; 48]);
        assert_eq!(quote.signature.cert_data_type, 6);
        assert_eq!(quote.signature.cert_data, b"PCKCHAIN");
        assert_eq!(quote.signed_region.len(), SIGNED_REGION_LEN);
        // The signed region is exactly header ‖ body.
        assert_eq!(&quote.signed_region[..], &bytes[..SIGNED_REGION_LEN]);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = synth_quote([0; 48], [0; 64], b"x");
        bytes[0] = 9; // version low byte
        assert_eq!(parse(&bytes), Err(QuoteParseError::UnsupportedVersion(9)));
    }

    #[test]
    fn rejects_non_tdx_tee_type() {
        let mut bytes = synth_quote([0; 48], [0; 64], b"x");
        // tee_type is at offset 4 (after version u16 + att_key_type u16).
        bytes[4] = 0x00;
        bytes[5] = 0x00;
        bytes[6] = 0x00;
        bytes[7] = 0x00;
        assert!(matches!(parse(&bytes), Err(QuoteParseError::NotTdx(0))));
    }

    #[test]
    fn rejects_truncation() {
        let bytes = synth_quote([0; 48], [0; 64], b"x");
        assert_eq!(
            parse(&bytes[..HEADER_LEN + 10]),
            Err(QuoteParseError::Truncated)
        );
    }

    #[test]
    fn report_data_mismatch_is_detected() {
        let bytes = synth_quote([0; 48], [0x55; 64], b"x");
        let quote = parse(&bytes).unwrap();
        assert!(!quote.body.report_data_matches(&[0x66; 64]));
    }

    #[test]
    fn binds_transcript_hash_into_low_half() {
        let hash = [0xEE; 32];
        let rd = bind_transcript_hash(&hash);
        assert_eq!(&rd[..32], &hash[..]);
        assert_eq!(&rd[32..], &[0u8; 32][..]);
    }
}

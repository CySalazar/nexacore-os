//! AMD SEV-SNP attestation-report parsing and report-data binding
//! (WS10-02.4, WS10-02.8).
//!
//! The `SNP_GET_REPORT` ioctl returns a 1184-byte `snp_attestation_report`
//! (report ABI v2).  Its layout is fixed and little-endian; the ECDSA-P-384
//! signature at offset `0x2A0` covers the first `0x2A0` (672) bytes.  Parsing it
//! is pure and host-testable, and recovers everything later checks need: the
//! `MEASUREMENT`, the 64-byte `REPORT_DATA` binding slot, the `REPORTED_TCB`,
//! the `CHIP_ID` (which keys the VCEK fetch), and the `signed_region` the
//! signature is computed over.
//!
//! The signature's *cryptographic* verification (ECDSA-P-384 against the VCEK)
//! needs primitives `nexacore-crypto` does not yet expose, so it is delegated to
//! [`super::cert`] (library-gated); this module only recovers the bytes.

use alloc::vec::Vec;

/// Total length of an `snp_attestation_report` (ABI v2), in bytes.
pub const SNP_REPORT_LEN: usize = 1184;

/// Offset at which the ECDSA-P-384 signature begins.
pub const SIGNATURE_OFFSET: usize = 0x2A0;

/// Length of the region the signature covers (report start .. signature).
pub const SIGNED_REGION_LEN: usize = SIGNATURE_OFFSET;

/// Errors that can arise parsing an SNP attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpReportError {
    /// The buffer was shorter than [`SNP_REPORT_LEN`].
    Truncated,
    /// The report `version` field was not a supported value (expected 2 or 3).
    UnsupportedVersion(u32),
}

impl core::fmt::Display for SnpReportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("snp report truncated"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snp report version {v}"),
        }
    }
}

impl core::error::Error for SnpReportError {}

/// A parsed AMD SEV-SNP attestation report (the fields NexaCore consumes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpReport {
    /// Report structure version (2 or 3).
    pub version: u32,
    /// Guest security version number.
    pub guest_svn: u32,
    /// Guest policy bits.
    pub policy: u64,
    /// VM permission level the report was generated at.
    pub vmpl: u32,
    /// Signature algorithm id (1 = ECDSA-P-384-with-SHA-384).
    pub signature_algo: u32,
    /// Current platform TCB version.
    pub current_tcb: u64,
    /// Platform info bits (SMT enabled, TSME, …).
    pub platform_info: u64,
    /// 64-byte report data — the binding slot (mesh handshake transcript).
    pub report_data: [u8; 64],
    /// Launch measurement of the guest (maps to [`Measurement`]).
    ///
    /// [`Measurement`]: crate::attestation::Measurement
    pub measurement: [u8; 48],
    /// Host-provided data.
    pub host_data: [u8; 32],
    /// Report id.
    pub report_id: [u8; 32],
    /// TCB version the report was signed against (keys the VCEK).
    pub reported_tcb: u64,
    /// Unique chip identifier (keys the VCEK fetch from the AMD KDS).
    pub chip_id: [u8; 64],
    /// The full 512-byte signature field (ECDSA-P-384 `r ‖ s`, LE, zero-padded).
    pub signature: [u8; 512],
    /// The exact bytes (report start .. signature) the signature covers.
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

    fn skip(&mut self, n: usize) -> Result<(), SnpReportError> {
        self.pos = self.pos.checked_add(n).ok_or(SnpReportError::Truncated)?;
        if self.pos > self.buf.len() {
            return Err(SnpReportError::Truncated);
        }
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SnpReportError> {
        let end = self.pos.checked_add(N).ok_or(SnpReportError::Truncated)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(SnpReportError::Truncated)?;
        let arr = <[u8; N]>::try_from(slice).map_err(|_| SnpReportError::Truncated)?;
        self.pos = end;
        Ok(arr)
    }

    fn u32(&mut self) -> Result<u32, SnpReportError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, SnpReportError> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }
}

/// Parse an SNP attestation report buffer (typically `Quote::body`).
///
/// # Errors
/// Returns [`SnpReportError`] on truncation or an unsupported report version.
pub fn parse(bytes: &[u8]) -> Result<SnpReport, SnpReportError> {
    if bytes.len() < SNP_REPORT_LEN {
        return Err(SnpReportError::Truncated);
    }
    let signed_region = bytes
        .get(..SIGNED_REGION_LEN)
        .ok_or(SnpReportError::Truncated)?
        .to_vec();

    let mut r = Le::new(bytes);
    let version = r.u32()?; // 0x000
    if version != 2 && version != 3 {
        return Err(SnpReportError::UnsupportedVersion(version));
    }
    let guest_svn = r.u32()?; // 0x004
    let policy = r.u64()?; // 0x008
    r.skip(16)?; // family_id  0x010
    r.skip(16)?; // image_id   0x020
    let vmpl = r.u32()?; // 0x030
    let signature_algo = r.u32()?; // 0x034
    let current_tcb = r.u64()?; // 0x038
    let platform_info = r.u64()?; // 0x040
    r.skip(4)?; // author_key_en / flags  0x048
    r.skip(4)?; // reserved              0x04C
    let report_data = r.array::<64>()?; // 0x050
    let measurement = r.array::<48>()?; // 0x090
    let host_data = r.array::<32>()?; // 0x0C0
    r.skip(48)?; // id_key_digest      0x0E0
    r.skip(48)?; // author_key_digest  0x110
    let report_id = r.array::<32>()?; // 0x140
    r.skip(32)?; // report_id_ma       0x160
    let reported_tcb = r.u64()?; // 0x180
    r.skip(24)?; // reserved           0x188
    let chip_id = r.array::<64>()?; // 0x1A0
    // committed_tcb .. reserved up to the signature at 0x2A0.
    r.skip(SIGNATURE_OFFSET - 0x1E0)?; // from 0x1E0 to 0x2A0
    let signature = r.array::<512>()?; // 0x2A0

    Ok(SnpReport {
        version,
        guest_svn,
        policy,
        vmpl,
        signature_algo,
        current_tcb,
        platform_info,
        report_data,
        measurement,
        host_data,
        report_id,
        reported_tcb,
        chip_id,
        signature,
        signed_region,
    })
}

impl SnpReport {
    /// `true` if the 64-byte report-data slot equals `expected` (WS10-02.8).
    #[must_use]
    pub fn report_data_matches(&self, expected: &[u8; 64]) -> bool {
        self.report_data.as_slice() == expected.as_slice()
    }

    /// `true` if the launch measurement equals `expected`.
    #[must_use]
    pub fn measurement_matches(&self, expected: &[u8; 48]) -> bool {
        self.measurement.as_slice() == expected.as_slice()
    }
}

/// Build the 64-byte report-data field binding a report to a mesh handshake.
///
/// The 32-byte transcript hash is placed in the low half and the high half is
/// zero (the verifier reconstructs the same layout); mirrors the TDX binding so
/// both backends share one mesh-handshake contract.
#[must_use]
pub fn bind_transcript_hash(transcript_hash: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some(dst) = out.get_mut(..32) {
        dst.copy_from_slice(transcript_hash);
    }
    out
}

/// Build a structurally valid SNP report (host tests only).
#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::missing_docs_in_private_items)]
pub(crate) fn build_test_report(
    measurement: [u8; 48],
    report_data: [u8; 64],
    reported_tcb: u64,
    chip_id: [u8; 64],
) -> Vec<u8> {
    let mut b = alloc::vec![0u8; SNP_REPORT_LEN];
    b[0x000..0x004].copy_from_slice(&2u32.to_le_bytes()); // version
    b[0x004..0x008].copy_from_slice(&1u32.to_le_bytes()); // guest_svn
    b[0x030..0x034].copy_from_slice(&0u32.to_le_bytes()); // vmpl
    b[0x034..0x038].copy_from_slice(&1u32.to_le_bytes()); // signature_algo
    b[0x038..0x040].copy_from_slice(&0x07u64.to_le_bytes()); // current_tcb
    b[0x050..0x090].copy_from_slice(&report_data);
    b[0x090..0x0C0].copy_from_slice(&measurement);
    b[0x180..0x188].copy_from_slice(&reported_tcb.to_le_bytes());
    b[0x1A0..0x1E0].copy_from_slice(&chip_id);
    b[0x2A0..0x2A0 + 96].copy_from_slice(&[0x33; 96]); // signature r||s
    b
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn build_report(
        measurement: [u8; 48],
        report_data: [u8; 64],
        reported_tcb: u64,
        chip_id: [u8; 64],
    ) -> Vec<u8> {
        build_test_report(measurement, report_data, reported_tcb, chip_id)
    }

    #[test]
    fn parses_a_valid_report() {
        let m = [0x42; 48];
        let rd = [0x55; 64];
        let chip = [0xC1; 64];
        let bytes = build_report(m, rd, 0x0A0B_0C0D, chip);
        let report = parse(&bytes).expect("parses");

        assert_eq!(report.version, 2);
        assert_eq!(report.signature_algo, 1);
        assert_eq!(report.current_tcb, 0x07);
        assert!(report.measurement_matches(&m));
        assert!(report.report_data_matches(&rd));
        assert_eq!(report.reported_tcb, 0x0A0B_0C0D);
        assert_eq!(report.chip_id, chip);
        assert_eq!(report.signed_region.len(), SIGNED_REGION_LEN);
        assert_eq!(&report.signed_region[..], &bytes[..SIGNATURE_OFFSET]);
        assert_eq!(&report.signature[..96], &[0x33; 96][..]);
    }

    #[test]
    fn rejects_truncation() {
        let bytes = build_report([0; 48], [0; 64], 0, [0; 64]);
        assert_eq!(
            parse(&bytes[..SNP_REPORT_LEN - 1]),
            Err(SnpReportError::Truncated)
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = build_report([0; 48], [0; 64], 0, [0; 64]);
        bytes[0] = 9;
        assert_eq!(parse(&bytes), Err(SnpReportError::UnsupportedVersion(9)));
    }

    #[test]
    fn binds_transcript_hash() {
        let h = [0xEE; 32];
        let rd = bind_transcript_hash(&h);
        assert_eq!(&rd[..32], &h[..]);
        assert_eq!(&rd[32..], &[0u8; 32][..]);
    }
}

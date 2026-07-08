//! AMD SEV-SNP backend — **scaffold only**.
//!
//! Feature-gated behind `sev-snp`. Same shape as [`crate::tdx::TdxBackend`]:
//! trait surface implemented, every method returns
//! [`TeeErrorKind::Unsupported`] until P5.3 lands the real integration.
//!
//! ## SEV-SNP integration roadmap (P5.3)
//!
//! 1. Vendor library selection:
//!    - Option A: `sev` crate (Red Hat, maintained, MIT/Apache-2.0).
//!    - Option B: `snpguest` crate (AMD reference, GPL-2; **rejected** —
//!      incompatible with our AGPL-3.0+commercial dual-licensing).
//!    - Option C: hand-rolled FFI to `psp-ioctl` (`/dev/sev-guest`).
//! 2. Attestation report request:
//!    - `ioctl(SNP_GET_REPORT, ...)` returning the attestation report
//!      with embedded `REPORT_DATA` field (set to the NexaCore nonce +
//!      transcript hash).
//!    - Wrap in `Quote { body: serialized_report }`.
//! 3. Report verification:
//!    - Parse the AMD attestation report (v2 layout, ABI 1.55).
//!    - Walk the VCEK certificate chain to AMD root.
//!    - Verify ECDSA-P384 signature over the report.
//!    - Cross-check `MEASUREMENT`, `REPORTED_TCB`, `PLATFORM_INFO` against
//!      the allowlist.
//! 4. Sealing flow: same approach as TDX (HKDF over an attested local
//!    secret + AEAD).
//! 5. `derive_key_for`: same HKDF pattern as TDX.
//!
//! The `cfg(feature = "sev-snp")` gating lives on `pub mod sev_snp;` in
//! [`crate`]; we do not repeat it here.

use alloc::vec::Vec;

use crate::{
    attestation::{Measurement, Nonce, Quote},
    sealed_keys::{SealPolicy, SealedBlob, TeeSharedKey},
    traits::{TeeBackend, TeeError, TeeErrorKind, TeeFamily},
};

pub mod cert;
pub mod device;
pub mod report;

/// AMD SEV-SNP backend.
#[derive(Debug, Default)]
pub struct SevSnpBackend {
    /// Reserved for future configuration. Empty in v0.1.
    _config: (),
}

impl SevSnpBackend {
    /// Constructs a default SEV-SNP backend.
    #[must_use]
    pub const fn new() -> Self {
        Self { _config: () }
    }

    fn not_yet_implemented(context: &'static str) -> TeeError {
        TeeError::new(TeeErrorKind::Unsupported, context)
    }
}

impl TeeBackend for SevSnpBackend {
    fn family(&self) -> TeeFamily {
        TeeFamily::AmdSevSnp
    }

    fn attest(&self, _nonce: &Nonce, _report_data: Option<&[u8]>) -> Result<Quote, TeeError> {
        Err(Self::not_yet_implemented(
            "sev-snp: attest not yet implemented",
        ))
    }

    fn verify_quote(
        &self,
        _quote: &Quote,
        _expected_nonce: &Nonce,
        _expected_measurement: &Measurement,
    ) -> Result<(), TeeError> {
        Err(Self::not_yet_implemented(
            "sev-snp: verify_quote not yet implemented",
        ))
    }

    fn seal(&self, _plaintext: &[u8], _policy: &SealPolicy) -> Result<SealedBlob, TeeError> {
        Err(Self::not_yet_implemented(
            "sev-snp: seal not yet implemented",
        ))
    }

    fn unseal(&self, _blob: &SealedBlob) -> Result<Vec<u8>, TeeError> {
        Err(Self::not_yet_implemented(
            "sev-snp: unseal not yet implemented",
        ))
    }

    fn derive_key_for(&self, _peer_attestation: &Quote) -> Result<TeeSharedKey, TeeError> {
        Err(Self::not_yet_implemented(
            "sev-snp: derive_key_for not yet implemented",
        ))
    }
}

// -----------------------------------------------------------------------------
// Offline structural verification (WS10-02.4/.8 composed)
// -----------------------------------------------------------------------------

/// The result of the offline (non-cryptographic) checks on an SNP report.
///
/// These are the steps that do **not** need ECDSA-P-384 / X.509 (delegated to
/// [`cert`]): parse the report, confirm the launch `MEASUREMENT` matches the
/// expected [`Measurement`], confirm the 64-byte report-data binds the expected
/// value, and confirm the reported TCB meets a minimum policy.  A full
/// attestation additionally requires the report signature and the
/// ARK→ASK→VCEK chain (hardware/CVM-gated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineVerification {
    /// `true` if the report's measurement equals the expected measurement.
    pub measurement_ok: bool,
    /// `true` if the report's report-data equals the expected binding.
    pub report_data_ok: bool,
    /// `true` if the reported TCB meets the minimum-SPL policy.
    pub tcb_ok: bool,
}

impl OfflineVerification {
    /// `true` only if measurement, report-data, and TCB policy all pass.
    #[must_use]
    pub const fn structurally_trusted(self) -> bool {
        self.measurement_ok && self.report_data_ok && self.tcb_ok
    }
}

/// Run the offline structural verification of an SNP report (WS10-02.4 + .8).
///
/// # Errors
/// Returns [`report::SnpReportError`] if the report cannot be parsed.
pub fn verify_report_offline(
    report_bytes: &[u8],
    expected_measurement: &Measurement,
    expected_report_data: &[u8; 64],
    min_tcb: cert::TcbVersion,
) -> Result<OfflineVerification, report::SnpReportError> {
    let parsed = report::parse(report_bytes)?;
    let measurement_ok = parsed.measurement_matches(expected_measurement.as_bytes());
    let report_data_ok = parsed.report_data_matches(expected_report_data);
    let tcb = cert::TcbVersion::from_reported_tcb(parsed.reported_tcb);
    let tcb_ok = tcb.bootloader >= min_tcb.bootloader
        && tcb.tee >= min_tcb.tee
        && tcb.snp >= min_tcb.snp
        && tcb.microcode >= min_tcb.microcode;
    Ok(OfflineVerification {
        measurement_ok,
        report_data_ok,
        tcb_ok,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn family_is_amd_sev_snp() {
        let b = SevSnpBackend::new();
        assert_eq!(b.family(), TeeFamily::AmdSevSnp);
    }

    fn min_tcb() -> cert::TcbVersion {
        cert::TcbVersion {
            bootloader: 3,
            tee: 0,
            snp: 20,
            microcode: 200,
        }
    }

    #[test]
    fn offline_verification_passes_for_matching_report() {
        let m = [0x42u8; 48];
        let rd = [0x55u8; 64];
        // reported_tcb with SPLs BL=4 TEE=1 SNP=21 UCODE=210 (>= policy).
        let reported = u64::from_le_bytes([4, 1, 0, 0, 0, 0, 21, 210]);
        let bytes = report::build_test_report(m, rd, reported, [0xC1; 64]);
        let v = verify_report_offline(&bytes, &Measurement(m), &rd, min_tcb()).expect("parses");
        assert!(v.measurement_ok);
        assert!(v.report_data_ok);
        assert!(v.tcb_ok);
        assert!(v.structurally_trusted());
    }

    #[test]
    fn offline_verification_flags_mismatches() {
        let rd = [0x55u8; 64];
        // MEASUREMENT 0x42 but expect 0x99; TCB microcode below policy.
        let reported = u64::from_le_bytes([4, 1, 0, 0, 0, 0, 21, 100]);
        let bytes = report::build_test_report([0x42u8; 48], rd, reported, [0xC1; 64]);
        let v = verify_report_offline(&bytes, &Measurement([0x99u8; 48]), &rd, min_tcb())
            .expect("parses");
        assert!(!v.measurement_ok);
        assert!(v.report_data_ok);
        assert!(!v.tcb_ok);
        assert!(!v.structurally_trusted());
    }

    #[test]
    fn offline_verification_rejects_malformed_report() {
        assert!(
            verify_report_offline(&[0u8; 16], &Measurement::zero(), &[0u8; 64], min_tcb()).is_err()
        );
    }
}

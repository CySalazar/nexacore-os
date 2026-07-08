//! `/dev/sev-guest` attestation-device abstraction (WS10-02.2, .3).
//!
//! On Linux an SEV-SNP guest obtains its attestation report by issuing the
//! `SNP_GET_REPORT` ioctl on `/dev/sev-guest` with a `snp_guest_request_ioctl`
//! wrapping a `snp_report_req { user_data[64]; vmpl; rsvd[28] }`; the kernel
//! returns a `snp_report_resp` containing the 1184-byte attestation report
//! ([`super::report`]).
//!
//! The real `open`/`ioctl` is a `std` + Linux syscall on actual hardware, so it
//! is feature-gated and validated on an AMD EPYC / Confidential VM (WS10-02.11).
//! Host-testable here: the ioctl request code, the `snp_report_req` layout, the
//! `user_data` (report-data) placement, and the [`SnpReportProvider`] seam.

use alloc::vec::Vec;

use super::report::{SNP_REPORT_LEN, parse};

// Linux ioctl encoding (asm-generic) — mirrors the TDX device module.
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

/// Compute a Linux ioctl request code (`_IOC`).
const fn ioc(dir: u32, typ: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (typ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

/// Path of the SEV-SNP guest attestation device.
pub const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

/// Size of `struct snp_guest_request_ioctl` (the ioctl argument), in bytes.
pub const SNP_GUEST_REQUEST_IOCTL_LEN: u32 = 32;

/// Length of the caller-supplied report (user) data, in bytes.
pub const USER_DATA_LEN: usize = 64;

/// Length of the `snp_report_req` message, in bytes.
pub const SNP_REPORT_REQ_LEN: usize = 96;

/// `SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)`.
///
/// The kernel ABI value; host-asserted in the tests to equal `0xc020_5300`.
pub const SNP_GET_REPORT: u32 = ioc(
    IOC_READ | IOC_WRITE,
    b'S' as u32,
    0x0,
    SNP_GUEST_REQUEST_IOCTL_LEN,
);

/// A failure obtaining an SNP attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpDeviceError {
    /// `/dev/sev-guest` is absent — the platform is not an SNP guest.
    Unavailable,
    /// The `ioctl` syscall failed.
    Ioctl,
    /// The kernel returned a short / malformed report.
    ShortReport,
}

impl core::fmt::Display for SnpDeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Unavailable => "/dev/sev-guest unavailable",
            Self::Ioctl => "SNP_GET_REPORT ioctl failed",
            Self::ShortReport => "short or malformed SNP report",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SnpDeviceError {}

/// The `snp_report_req` message: 64 bytes of user data + the VMPL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpReportRequest {
    /// Caller-supplied data bound into the report (WS10-02.8).
    pub user_data: [u8; USER_DATA_LEN],
    /// VM permission level to attest at.
    pub vmpl: u32,
}

impl SnpReportRequest {
    /// A request for `vmpl` carrying `user_data`.
    #[must_use]
    pub const fn new(user_data: [u8; USER_DATA_LEN], vmpl: u32) -> Self {
        Self { user_data, vmpl }
    }

    /// Serialise to the exact `snp_report_req` wire layout
    /// (`user_data[64] ‖ vmpl(u32 LE) ‖ rsvd[28]`).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SNP_REPORT_REQ_LEN);
        buf.extend_from_slice(&self.user_data);
        buf.extend_from_slice(&self.vmpl.to_le_bytes());
        buf.resize(SNP_REPORT_REQ_LEN, 0); // rsvd[28]
        buf
    }
}

/// Source of SNP attestation reports — the real device or a host mock.
pub trait SnpReportProvider {
    /// Obtain a 1184-byte attestation report bound to `user_data` at `vmpl`.
    ///
    /// # Errors
    /// Returns [`SnpDeviceError`] if the device is unavailable or the ioctl
    /// fails.
    fn get_report(
        &self,
        user_data: &[u8; USER_DATA_LEN],
        vmpl: u32,
    ) -> Result<Vec<u8>, SnpDeviceError>;
}

/// A host [`SnpReportProvider`] that synthesises a report whose `REPORT_DATA`
/// is the requested `user_data` (host tests / dry runs).
#[derive(Debug, Default, Clone)]
pub struct MockSnpReportProvider {
    /// If set, the provider reports the device as unavailable.
    pub unavailable: bool,
}

impl SnpReportProvider for MockSnpReportProvider {
    fn get_report(
        &self,
        user_data: &[u8; USER_DATA_LEN],
        _vmpl: u32,
    ) -> Result<Vec<u8>, SnpDeviceError> {
        if self.unavailable {
            return Err(SnpDeviceError::Unavailable);
        }
        let mut report = alloc::vec![0u8; SNP_REPORT_LEN];
        // version = 2; report_data at 0x050.
        if let Some(v) = report.get_mut(0..4) {
            v.copy_from_slice(&2u32.to_le_bytes());
        }
        if let Some(slot) = report.get_mut(0x050..0x090) {
            slot.copy_from_slice(user_data);
        }
        Ok(report)
    }
}

/// Verify a buffer is a well-formed SNP report (a quick parse-only check).
///
/// # Errors
/// Returns [`SnpDeviceError::ShortReport`] if the buffer does not parse.
pub fn sanity_check_report(report: &[u8]) -> Result<(), SnpDeviceError> {
    parse(report)
        .map(|_| ())
        .map_err(|_| SnpDeviceError::ShortReport)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_code_matches_kernel_abi() {
        // _IOWR('S', 0, struct snp_guest_request_ioctl) size 32 == 0xc020_5300.
        assert_eq!(SNP_GET_REPORT, 0xc020_5300);
    }

    #[test]
    fn request_encodes_to_exact_layout() {
        let req = SnpReportRequest::new([0x5A; USER_DATA_LEN], 1);
        let buf = req.encode();
        assert_eq!(buf.len(), SNP_REPORT_REQ_LEN);
        assert_eq!(&buf[..USER_DATA_LEN], &[0x5A; USER_DATA_LEN][..]);
        assert_eq!(
            &buf[USER_DATA_LEN..USER_DATA_LEN + 4],
            &1u32.to_le_bytes()[..]
        );
        assert!(buf[USER_DATA_LEN + 4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn mock_provider_embeds_user_data_as_report_data() {
        let provider = MockSnpReportProvider::default();
        let ud = [0x77; USER_DATA_LEN];
        let report = provider.get_report(&ud, 0).unwrap();
        assert_eq!(report.len(), SNP_REPORT_LEN);
        sanity_check_report(&report).unwrap();
        let parsed = super::super::report::parse(&report).unwrap();
        assert!(parsed.report_data_matches(&ud));
    }

    #[test]
    fn unavailable_device_errors() {
        let provider = MockSnpReportProvider { unavailable: true };
        assert_eq!(
            provider.get_report(&[0u8; USER_DATA_LEN], 0),
            Err(SnpDeviceError::Unavailable)
        );
    }
}

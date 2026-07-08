//! `/dev/tdx_guest` attestation-device abstraction (WS10-01.2, .3, .4).
//!
//! On Linux a TD obtains a TDREPORT by issuing the `TDX_CMD_GET_REPORT0` ioctl
//! on `/dev/tdx_guest` with a `tdx_report_req { reportdata[64]; tdreport[1024] }`
//! buffer; the 1024-byte TDREPORT is then handed to the in-guest Quote
//! Generation Service (QGS), which signs it into a Quote-v4 ([`super::quote`]).
//!
//! The actual `open`/`ioctl` is a `std` + Linux syscall and needs real hardware,
//! so it is feature-gated and validated on the test VM / a Confidential VM
//! (WS10-01.10/.11).  What is host-testable, and lives here, is the **device
//! contract**: the exact ioctl request code, the request/report buffer layout,
//! the `report_data` placement, and the [`TdReportProvider`] / [`QuoteGenerator`]
//! seams the real device and the host mocks both implement.

use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Linux ioctl request-code encoding (asm-generic).
// ---------------------------------------------------------------------------

/// Bits for the ioctl "number" field.
const IOC_NRBITS: u32 = 8;
/// Bits for the ioctl "type" field.
const IOC_TYPEBITS: u32 = 8;
/// Bits for the ioctl "size" field.
const IOC_SIZEBITS: u32 = 14;
/// Shift of the "number" field (lowest).
const IOC_NRSHIFT: u32 = 0;
/// Shift of the "type" field.
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
/// Shift of the "size" field.
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
/// Shift of the "direction" field (highest).
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
/// Direction bit: userspace writes to the kernel.
const IOC_WRITE: u32 = 1;
/// Direction bit: userspace reads from the kernel.
const IOC_READ: u32 = 2;

/// Compute a Linux ioctl request code (`_IOC`).
const fn ioc(dir: u32, typ: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (typ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

/// Path of the TDX guest attestation device.
pub const TDX_GUEST_DEVICE: &str = "/dev/tdx_guest";

/// Length of the caller-supplied report data, in bytes.
pub const REPORT_DATA_LEN: usize = 64;

/// Length of the kernel-returned TDREPORT structure, in bytes.
pub const TD_REPORT_LEN: usize = 1024;

/// Length of the `tdx_report_req` buffer (`reportdata` ‖ `tdreport`).
pub const TD_REPORT_REQ_LEN: usize = REPORT_DATA_LEN + TD_REPORT_LEN;

/// Offset of the `REPORTDATA` field inside the TDREPORT (`REPORTMACSTRUCT`).
pub const TD_REPORT_REPORTDATA_OFFSET: usize = 128;

/// `TDX_CMD_GET_REPORT0 = _IOWR('T', 1, struct tdx_report_req)`.
///
/// The kernel ABI value; host-asserted in the tests to equal `0xc440_5401`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "TD_REPORT_REQ_LEN is the compile-time constant 1088, which fits u32"
)]
pub const TDX_CMD_GET_REPORT0: u32 = ioc(
    IOC_READ | IOC_WRITE,
    b'T' as u32,
    1,
    TD_REPORT_REQ_LEN as u32,
);

/// A failure obtaining a TDREPORT or generating a quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdxDeviceError {
    /// `/dev/tdx_guest` is absent — the platform is not a TD.
    Unavailable,
    /// The `ioctl` syscall failed.
    Ioctl,
    /// The kernel returned a short / malformed report.
    ShortReport,
    /// The Quote Generation Service declined or failed.
    QuoteGeneration,
}

impl core::fmt::Display for TdxDeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Unavailable => "/dev/tdx_guest unavailable",
            Self::Ioctl => "TDX_CMD_GET_REPORT0 ioctl failed",
            Self::ShortReport => "short or malformed TDREPORT",
            Self::QuoteGeneration => "quote generation failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for TdxDeviceError {}

/// The `tdx_report_req` buffer passed to the ioctl.
#[derive(Clone)]
pub struct TdReportRequest {
    /// Caller-supplied report data (bound into the report; WS10-01.7).
    pub report_data: [u8; REPORT_DATA_LEN],
    /// Kernel-filled TDREPORT (zeroed on the way in).
    pub td_report: Vec<u8>,
}

impl TdReportRequest {
    /// A fresh request carrying `report_data`, with a zeroed report buffer.
    #[must_use]
    pub fn new(report_data: [u8; REPORT_DATA_LEN]) -> Self {
        Self {
            report_data,
            td_report: alloc::vec![0u8; TD_REPORT_LEN],
        }
    }

    /// Serialise to the exact `tdx_report_req` wire layout (`reportdata` then
    /// `tdreport`), the buffer the ioctl reads and writes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TD_REPORT_REQ_LEN);
        buf.extend_from_slice(&self.report_data);
        buf.extend_from_slice(&self.td_report);
        buf.resize(TD_REPORT_REQ_LEN, 0);
        buf
    }
}

/// Source of TDREPORTs — the real device or a host mock.
pub trait TdReportProvider {
    /// Obtain a 1024-byte TDREPORT bound to `report_data`.
    ///
    /// # Errors
    /// Returns [`TdxDeviceError`] if the device is unavailable or the ioctl
    /// fails.
    fn get_report(&self, report_data: &[u8; REPORT_DATA_LEN]) -> Result<Vec<u8>, TdxDeviceError>;
}

/// Generates a signed Quote-v4 from a TDREPORT (the QGS seam, WS10-01.4).
pub trait QuoteGenerator {
    /// Convert a TDREPORT into a signed TDX quote (vendor bytes).
    ///
    /// # Errors
    /// Returns [`TdxDeviceError::QuoteGeneration`] on failure.
    fn generate_quote(&self, td_report: &[u8]) -> Result<Vec<u8>, TdxDeviceError>;
}

/// A host [`TdReportProvider`] that synthesises a TDREPORT embedding the
/// `report_data` at [`TD_REPORT_REPORTDATA_OFFSET`] (host tests / dry runs).
#[derive(Debug, Default, Clone)]
pub struct MockTdReportProvider {
    /// If set, the provider reports the device as unavailable.
    pub unavailable: bool,
}

impl TdReportProvider for MockTdReportProvider {
    fn get_report(&self, report_data: &[u8; REPORT_DATA_LEN]) -> Result<Vec<u8>, TdxDeviceError> {
        if self.unavailable {
            return Err(TdxDeviceError::Unavailable);
        }
        let mut report = alloc::vec![0u8; TD_REPORT_LEN];
        let end = TD_REPORT_REPORTDATA_OFFSET + REPORT_DATA_LEN;
        if let Some(slot) = report.get_mut(TD_REPORT_REPORTDATA_OFFSET..end) {
            slot.copy_from_slice(report_data);
        }
        Ok(report)
    }
}

/// Extract the `REPORTDATA` field from a TDREPORT buffer, if present.
#[must_use]
pub fn report_data_of(td_report: &[u8]) -> Option<[u8; REPORT_DATA_LEN]> {
    let end = TD_REPORT_REPORTDATA_OFFSET + REPORT_DATA_LEN;
    let slice = td_report.get(TD_REPORT_REPORTDATA_OFFSET..end)?;
    <[u8; REPORT_DATA_LEN]>::try_from(slice).ok()
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
        // _IOWR('T', 1, struct tdx_report_req) with size 1088 == 0xc440_5401.
        assert_eq!(TDX_CMD_GET_REPORT0, 0xc440_5401);
    }

    #[test]
    fn request_encodes_to_exact_layout() {
        let req = TdReportRequest::new([0x5A; REPORT_DATA_LEN]);
        let buf = req.encode();
        assert_eq!(buf.len(), TD_REPORT_REQ_LEN);
        assert_eq!(&buf[..REPORT_DATA_LEN], &[0x5A; REPORT_DATA_LEN][..]);
        assert!(buf[REPORT_DATA_LEN..].iter().all(|&b| b == 0));
    }

    #[test]
    fn mock_provider_embeds_report_data() {
        let provider = MockTdReportProvider::default();
        let rd = [0x77; REPORT_DATA_LEN];
        let report = provider.get_report(&rd).unwrap();
        assert_eq!(report.len(), TD_REPORT_LEN);
        assert_eq!(report_data_of(&report), Some(rd));
    }

    #[test]
    fn unavailable_device_errors() {
        let provider = MockTdReportProvider { unavailable: true };
        assert_eq!(
            provider.get_report(&[0u8; REPORT_DATA_LEN]),
            Err(TdxDeviceError::Unavailable)
        );
    }
}

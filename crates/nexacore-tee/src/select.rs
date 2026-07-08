//! TEE backend selection / routing (WS10-02.10, closes WS10-01.12).
//!
//! Given the detected CPU vendor ([`crate::cpuid`]) and which hardware backends
//! are actually available, choose the [`TeeFamily`] to attest with.  The policy
//! is vendor-neutral and pure, so it is host-testable across the Intel / AMD /
//! mock matrix (WS10-02.12) without any backend feature enabled — it returns a
//! family, not a concrete `Box<dyn TeeBackend>` (constructing one needs the
//! corresponding feature and `std`).

use crate::{cpuid::CpuVendor, traits::TeeFamily};

/// Which hardware/software backends the platform can actually use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackendAvailability {
    /// An Intel TDX backend can be constructed and the platform is a TD.
    pub tdx: bool,
    /// An AMD SEV-SNP backend can be constructed and the platform is an SNP
    /// guest.
    pub sev_snp: bool,
    /// The deterministic in-process mock is permitted (dev / CI only).
    pub allow_mock: bool,
}

/// Select the [`TeeFamily`] to attest with, or `None` if nothing is usable.
///
/// Routing: an Intel CPU with TDX available → [`TeeFamily::IntelTdx`]; an AMD
/// CPU with SEV-SNP available → [`TeeFamily::AmdSevSnp`].  If the vendor's
/// hardware backend is unavailable (or the vendor is `Other`) the mock is used
/// **only** when explicitly allowed; otherwise the result is `None` and the
/// caller must fail closed.
#[must_use]
pub fn select_tee_family(
    vendor: CpuVendor,
    availability: BackendAvailability,
) -> Option<TeeFamily> {
    match vendor {
        CpuVendor::Intel if availability.tdx => Some(TeeFamily::IntelTdx),
        CpuVendor::Amd if availability.sev_snp => Some(TeeFamily::AmdSevSnp),
        _ if availability.allow_mock => Some(TeeFamily::Mock),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::missing_docs_in_private_items)]
mod tests {
    use super::*;

    #[test]
    fn intel_with_tdx_routes_to_tdx() {
        let avail = BackendAvailability {
            tdx: true,
            sev_snp: false,
            allow_mock: true,
        };
        assert_eq!(
            select_tee_family(CpuVendor::Intel, avail),
            Some(TeeFamily::IntelTdx)
        );
    }

    #[test]
    fn amd_with_snp_routes_to_sev_snp() {
        let avail = BackendAvailability {
            tdx: false,
            sev_snp: true,
            allow_mock: true,
        };
        assert_eq!(
            select_tee_family(CpuVendor::Amd, avail),
            Some(TeeFamily::AmdSevSnp)
        );
    }

    #[test]
    fn intel_without_tdx_falls_back_to_mock_when_allowed() {
        let avail = BackendAvailability {
            tdx: false,
            sev_snp: false,
            allow_mock: true,
        };
        assert_eq!(
            select_tee_family(CpuVendor::Intel, avail),
            Some(TeeFamily::Mock)
        );
    }

    #[test]
    fn no_hardware_and_no_mock_is_none() {
        let avail = BackendAvailability {
            tdx: false,
            sev_snp: false,
            allow_mock: false,
        };
        assert_eq!(select_tee_family(CpuVendor::Intel, avail), None);
        assert_eq!(select_tee_family(CpuVendor::Amd, avail), None);
        assert_eq!(select_tee_family(CpuVendor::Other, avail), None);
    }

    #[test]
    fn amd_cpu_does_not_route_to_tdx_even_if_tdx_flag_set() {
        // A mismatched availability flag must not cross vendors.
        let avail = BackendAvailability {
            tdx: true,
            sev_snp: false,
            allow_mock: false,
        };
        assert_eq!(select_tee_family(CpuVendor::Amd, avail), None);
    }
}

//! TDX TCB-level evaluation against TCB-info collateral (WS10-01.8).
//!
//! A quote proves *what* TCB the platform is running (`TEE_TCB_SVN` in the TD
//! report, `PCE_SVN` in the header); the Intel PCS publishes *which* TCBs are
//! still trusted as a signed `TCB-Info` document with a descending list of
//! [`TcbLevel`]s.  Evaluation walks that list and returns the status of the
//! highest level the platform satisfies — exactly the algorithm the Intel
//! Quote-Verification-Library applies.
//!
//! The document's own signature (PCS-signed) is verified upstream by the same
//! ECDSA path as the PCK chain ([`super::pck`]); this module operates on the
//! already-authenticated TCB-Info and is pure, deterministic, host-testable.

use alloc::vec::Vec;

use super::quote::{QuoteHeader, TdReportBody};

/// Number of TCB SVN components Intel defines for TDX.
pub const TCB_COMPONENT_COUNT: usize = 16;

/// Trust status of a platform's TCB relative to the collateral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbStatus {
    /// The platform is at the latest TCB — fully trusted.
    UpToDate,
    /// A configuration change is needed but the TCB is otherwise current.
    ConfigurationNeeded,
    /// The TCB is behind the latest; a security update is available.
    OutOfDate,
    /// Out of date *and* a configuration change is needed.
    OutOfDateConfigurationNeeded,
    /// The TCB has been revoked — never trust.
    Revoked,
    /// The platform's SVNs match no published level (below all of them).
    Unrecognized,
}

impl TcbStatus {
    /// `true` only for [`TcbStatus::UpToDate`] — the conservative default a
    /// strict verifier accepts.  Looser policies (e.g. accepting
    /// `ConfigurationNeeded`) are the caller's decision.
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::UpToDate)
    }
}

/// The platform SVNs taken from a quote, ready for evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformTcb {
    /// The 16 TEE-TCB SVN components from the TD report body.
    pub tee_tcb_svn: [u8; TCB_COMPONENT_COUNT],
    /// The PCE SVN from the quote header.
    pub pce_svn: u16,
}

impl PlatformTcb {
    /// Extract the platform TCB from a parsed quote's header and body.
    #[must_use]
    pub const fn from_quote(header: &QuoteHeader, body: &TdReportBody) -> Self {
        Self {
            tee_tcb_svn: body.tee_tcb_svn,
            pce_svn: header.pce_svn,
        }
    }
}

/// One published TCB level: the minimum SVNs that qualify for `status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcbLevel {
    /// Minimum required TEE-TCB SVN components for this level.
    pub tee_tcb_svn: [u8; TCB_COMPONENT_COUNT],
    /// Minimum required PCE SVN for this level.
    pub pce_svn: u16,
    /// The status awarded to a platform that meets this level.
    pub status: TcbStatus,
}

impl TcbLevel {
    /// `true` if `platform` meets *every* component requirement of this level.
    #[must_use]
    pub fn is_met_by(&self, platform: &PlatformTcb) -> bool {
        if platform.pce_svn < self.pce_svn {
            return false;
        }
        platform
            .tee_tcb_svn
            .iter()
            .zip(self.tee_tcb_svn.iter())
            .all(|(have, need)| have >= need)
    }
}

/// Authenticated TCB-Info collateral for one platform family (`fmspc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbInfo {
    /// Family-Model-Stepping-Platform-Custom id this collateral applies to.
    pub fmspc: [u8; 6],
    /// TCB levels, expected in descending SVN order (newest first).
    pub levels: Vec<TcbLevel>,
}

impl TcbInfo {
    /// Evaluate a platform's TCB against this collateral (WS10-01.8).
    ///
    /// Returns the status of the **highest** level the platform satisfies; if
    /// it satisfies none, the platform is below every published level and the
    /// result is [`TcbStatus::Unrecognized`].
    #[must_use]
    pub fn evaluate(&self, platform: &PlatformTcb) -> TcbStatus {
        for level in &self.levels {
            if level.is_met_by(platform) {
                return level.status;
            }
        }
        TcbStatus::Unrecognized
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn svn(first: u8) -> [u8; TCB_COMPONENT_COUNT] {
        let mut a = [0u8; TCB_COMPONENT_COUNT];
        a[0] = first;
        a
    }

    fn collateral() -> TcbInfo {
        TcbInfo {
            fmspc: [0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00],
            // Descending: newest (svn 5) UpToDate, svn 3 OutOfDate, svn 1 Revoked.
            levels: alloc::vec![
                TcbLevel {
                    tee_tcb_svn: svn(5),
                    pce_svn: 13,
                    status: TcbStatus::UpToDate
                },
                TcbLevel {
                    tee_tcb_svn: svn(3),
                    pce_svn: 11,
                    status: TcbStatus::OutOfDate
                },
                TcbLevel {
                    tee_tcb_svn: svn(1),
                    pce_svn: 9,
                    status: TcbStatus::Revoked
                },
            ],
        }
    }

    #[test]
    fn latest_platform_is_up_to_date() {
        let info = collateral();
        let p = PlatformTcb {
            tee_tcb_svn: svn(6),
            pce_svn: 14,
        };
        assert_eq!(info.evaluate(&p), TcbStatus::UpToDate);
        assert!(info.evaluate(&p).is_trusted());
    }

    #[test]
    fn middle_platform_is_out_of_date() {
        let info = collateral();
        let p = PlatformTcb {
            tee_tcb_svn: svn(4),
            pce_svn: 12,
        };
        assert_eq!(info.evaluate(&p), TcbStatus::OutOfDate);
        assert!(!info.evaluate(&p).is_trusted());
    }

    #[test]
    fn low_pce_svn_demotes_even_with_high_components() {
        let info = collateral();
        // Components meet the top level but PCE SVN is below it -> falls through.
        let p = PlatformTcb {
            tee_tcb_svn: svn(9),
            pce_svn: 11,
        };
        assert_eq!(info.evaluate(&p), TcbStatus::OutOfDate);
    }

    #[test]
    fn revoked_level_is_reported() {
        let info = collateral();
        let p = PlatformTcb {
            tee_tcb_svn: svn(2),
            pce_svn: 10,
        };
        assert_eq!(info.evaluate(&p), TcbStatus::Revoked);
    }

    #[test]
    fn below_all_levels_is_unrecognized() {
        let info = collateral();
        let p = PlatformTcb {
            tee_tcb_svn: svn(0),
            pce_svn: 0,
        };
        assert_eq!(info.evaluate(&p), TcbStatus::Unrecognized);
    }
}

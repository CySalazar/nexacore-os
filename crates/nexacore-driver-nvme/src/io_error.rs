//! Robust IO error handling for the NVMe data path.
//!
//! Classifies every IO command failure into a structured taxonomy
//! that the driver can act on: retry, reset the controller, or
//! propagate as a permanent error. The taxonomy covers the four
//! failure domains the NVMe IO path encounters:
//!
//! - **Timeout** — the controller did not produce a CQE within the
//!   poll/interrupt budget.
//! - **Controller error** — the CQE arrived but carries a non-zero
//!   status word (SCT/SC per NVMe 1.4 § 4.6.1).
//! - **Transport error** — the queue bookkeeping surfaced a
//!   [`crate::queue::QueueError`] (full, page too small, doorbell
//!   overflow).
//! - **Namespace error** — the NSID targeted by the IO command is
//!   not admitted (rejected by
//!   [`crate::namespace_map::NamespaceMap::is_admitted`]).
//!
//! ## Retry policy
//!
//! Each error carries a [`RetryVerdict`] the driver reads to decide
//! the next action without re-classifying the error:
//!
//! - [`RetryVerdict::Retry`] — re-submit the same command (media
//!   errors, transient controller states). The budget is bounded
//!   by [`MAX_IO_RETRIES`].
//! - [`RetryVerdict::ResetAndRetry`] — the controller entered a
//!   fatal or wedged state; the driver must run the reset protocol
//!   (disable → reprogram → enable) before re-submitting.
//! - [`RetryVerdict::Permanent`] — the error is not recoverable
//!   (invalid NSID, unsupported opcode, namespace rejected). The
//!   driver must propagate the failure to the BLK channel client.

use crate::queue::QueueError;

/// Maximum IO command retries before permanent failure.
///
/// Phase-1 uses a conservative budget of 3; production drivers
/// may increase this per-namespace based on the controller's
/// error rate.
pub const MAX_IO_RETRIES: u32 = 3;

/// What the driver should do after an IO error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryVerdict {
    /// Re-submit the same command immediately.
    Retry,
    /// Run the controller reset protocol, then re-submit.
    ResetAndRetry,
    /// The error is permanent; propagate to the BLK client.
    Permanent,
}

/// NVMe Status Code Type (SCT) per NVMe 1.4 § 4.6.1 Table 38.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusCodeType {
    /// SCT 0 — Generic Command Status.
    Generic,
    /// SCT 1 — Command Specific Status.
    CommandSpecific,
    /// SCT 2 — Media and Data Integrity Errors.
    MediaError,
    /// SCT 3 — Path Related Status (NVMe 1.4+).
    PathRelated,
    /// SCT 7 — Vendor Specific.
    VendorSpecific,
    /// Any other SCT value (4–6 are reserved).
    Unknown(u8),
}

impl StatusCodeType {
    /// Decode the SCT from the raw 3-bit field.
    #[must_use]
    pub const fn from_raw(sct: u8) -> Self {
        match sct {
            0 => Self::Generic,
            1 => Self::CommandSpecific,
            2 => Self::MediaError,
            3 => Self::PathRelated,
            7 => Self::VendorSpecific,
            other => Self::Unknown(other),
        }
    }
}

/// Structured IO error carrying the classification and the
/// recommended retry action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IoError {
    /// The completion poll/interrupt budget was exhausted.
    Timeout {
        /// Number of poll iterations or interrupt waits consumed.
        polls_consumed: u32,
    },

    /// The CQE arrived with a non-zero status word.
    ControllerStatus {
        /// Status Code Type per NVMe 1.4 § 4.6.1.
        sct: StatusCodeType,
        /// Status Code per NVMe 1.4 § 4.6.1.
        sc: u8,
        /// The raw packed status for logging.
        raw_status: u16,
    },

    /// The underlying queue submission or drain failed.
    Transport(QueueError),

    /// The target NSID is not admitted by the namespace map.
    NamespaceNotAdmitted {
        /// The NSID the caller tried to target.
        nsid: u32,
    },

    /// The controller is in the fatal state (`CSTS.CFS = 1`).
    ControllerFatal,
}

impl IoError {
    /// Classify a controller status word (SCT + SC) into an
    /// [`IoError::ControllerStatus`].
    #[must_use]
    pub const fn from_status(sct_raw: u8, sc: u8) -> Self {
        let raw_status = ((sct_raw as u16) << 8) | (sc as u16);
        Self::ControllerStatus {
            sct: StatusCodeType::from_raw(sct_raw),
            sc,
            raw_status,
        }
    }

    /// Returns the recommended retry action for this error.
    #[must_use]
    pub const fn verdict(self) -> RetryVerdict {
        match self {
            Self::Timeout { .. } | Self::ControllerFatal => RetryVerdict::ResetAndRetry,

            Self::ControllerStatus { sct, sc, .. } => classify_by_sct(sct, sc),

            Self::Transport(_) | Self::NamespaceNotAdmitted { .. } => RetryVerdict::Permanent,
        }
    }
}

/// Classify by SCT, dispatching to the per-SCT classifier.
const fn classify_by_sct(sct: StatusCodeType, sc: u8) -> RetryVerdict {
    match sct {
        StatusCodeType::Generic => classify_generic_sc(sc),
        StatusCodeType::MediaError | StatusCodeType::PathRelated => RetryVerdict::Retry,
        StatusCodeType::CommandSpecific
        | StatusCodeType::VendorSpecific
        | StatusCodeType::Unknown(_) => RetryVerdict::Permanent,
    }
}

/// Classify a Generic Command Status (SCT 0) Status Code per
/// NVMe 1.4 § 4.6.1 Table 39.
const fn classify_generic_sc(sc: u8) -> RetryVerdict {
    match sc {
        // Permanent: invalid opcode, invalid field, invalid NS,
        // command sequence error, invalid NS attachment, LBA OOR,
        // capacity exceeded, successful completion (shouldn't reach).
        0x00 | 0x01 | 0x02 | 0x04 | 0x05 | 0x0B | 0x80 | 0x81 => RetryVerdict::Permanent,
        _ => RetryVerdict::Retry,
    }
}

/// Outcome of an IO operation attempted with retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOutcome {
    /// The IO command completed successfully.
    Success,
    /// The IO command failed after exhausting all retries.
    Failed {
        /// The last error observed.
        last_error: IoError,
        /// Total attempts made (1 + retries).
        attempts: u32,
    },
    /// A controller reset was triggered; the caller must
    /// re-establish the IO queue pair before retrying.
    ResetRequired {
        /// The error that triggered the reset.
        cause: IoError,
    },
}

/// Controller reset sequence: disable → reprogram → enable.
///
/// The reset protocol follows NVMe 1.4 § 7.6.1 (Controller Reset):
///
/// 1. Clear `CC.EN` (disable the controller).
/// 2. Wait for `CSTS.RDY = 0`.
/// 3. Re-program `AQA` + `ASQ` + `ACQ` with the original admin
///    queue base addresses.
/// 4. Re-write `CC` fields (`MPS`, `IOSQES`, `IOCQES`, `CSS`, `AMS`).
/// 5. Set `CC.EN` (enable the controller).
/// 6. Wait for `CSTS.RDY = 1`.
/// 7. Check `CSTS.CFS` — if set, the reset itself failed.
///
/// Phase-1 captures this as a stateless protocol object; the
/// actual execution is performed by the caller (the nvme-image
/// bring-up code or a future driver service) using the existing
/// `disable_controller` / `program_admin_queue_bases` /
/// `program_cc_fields` / `enable_controller` /
/// `check_controller_fatal` helpers from [`crate::queue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetProtocol {
    /// Number of reset attempts made so far.
    pub attempts: u32,
    /// Maximum number of reset attempts before giving up.
    pub max_attempts: u32,
}

/// Maximum number of controller reset attempts before the driver
/// declares the controller permanently dead.
pub const MAX_RESET_ATTEMPTS: u32 = 2;

impl Default for ResetProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl ResetProtocol {
    /// Create a fresh reset protocol with the default budget.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            max_attempts: MAX_RESET_ATTEMPTS,
        }
    }

    /// Returns `true` if the reset budget is exhausted.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.attempts >= self.max_attempts
    }

    /// Record one reset attempt. Returns `true` if the budget
    /// still has room; `false` if exhausted.
    pub fn record_attempt(&mut self) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        !self.is_exhausted()
    }
}

/// Per-command retry tracker.
///
/// Wraps the retry budget for a single IO command and cooperates
/// with the [`ResetProtocol`] to decide whether a reset-and-retry
/// cycle is still viable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryTracker {
    attempts: u32,
    max_retries: u32,
}

impl Default for RetryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryTracker {
    /// Create a tracker with the default retry budget.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            max_retries: MAX_IO_RETRIES,
        }
    }

    /// Create a tracker with a custom retry budget.
    #[must_use]
    pub const fn with_max_retries(max_retries: u32) -> Self {
        Self {
            attempts: 0,
            max_retries,
        }
    }

    /// Total attempts made so far (including the initial attempt).
    #[must_use]
    pub const fn attempts(self) -> u32 {
        self.attempts
    }

    /// Returns `true` if the retry budget is exhausted.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.attempts >= self.max_retries
    }

    /// Record one attempt. Returns `true` if the budget still has
    /// room for another attempt; `false` if exhausted.
    pub fn record_attempt(&mut self) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        self.attempts <= self.max_retries
    }

    /// Evaluate an error against this tracker's budget.
    #[must_use]
    pub fn evaluate(self, error: IoError) -> IoOutcome {
        match error.verdict() {
            RetryVerdict::ResetAndRetry => IoOutcome::ResetRequired { cause: error },
            RetryVerdict::Retry | RetryVerdict::Permanent => IoOutcome::Failed {
                last_error: error,
                attempts: self.attempts,
            },
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------

    #[test]
    fn max_io_retries_is_three() {
        assert_eq!(MAX_IO_RETRIES, 3);
    }

    #[test]
    fn max_reset_attempts_is_two() {
        assert_eq!(MAX_RESET_ATTEMPTS, 2);
    }

    // -------------------------------------------------------------------
    // StatusCodeType::from_raw
    // -------------------------------------------------------------------

    #[test]
    fn sct_from_raw_maps_known_values() {
        assert_eq!(StatusCodeType::from_raw(0), StatusCodeType::Generic);
        assert_eq!(StatusCodeType::from_raw(1), StatusCodeType::CommandSpecific);
        assert_eq!(StatusCodeType::from_raw(2), StatusCodeType::MediaError);
        assert_eq!(StatusCodeType::from_raw(3), StatusCodeType::PathRelated);
        assert_eq!(StatusCodeType::from_raw(7), StatusCodeType::VendorSpecific);
    }

    #[test]
    fn sct_from_raw_maps_reserved_to_unknown() {
        for sct in [4, 5, 6] {
            assert_eq!(StatusCodeType::from_raw(sct), StatusCodeType::Unknown(sct));
        }
    }

    // -------------------------------------------------------------------
    // IoError::from_status
    // -------------------------------------------------------------------

    #[test]
    fn from_status_packs_raw_correctly() {
        let err = IoError::from_status(2, 0x80);
        match err {
            IoError::ControllerStatus {
                sct,
                sc,
                raw_status,
            } => {
                assert_eq!(sct, StatusCodeType::MediaError);
                assert_eq!(sc, 0x80);
                assert_eq!(raw_status, 0x0280);
            }
            _ => panic!("expected ControllerStatus"),
        }
    }

    // -------------------------------------------------------------------
    // RetryVerdict classification
    // -------------------------------------------------------------------

    #[test]
    fn timeout_verdict_is_reset_and_retry() {
        let err = IoError::Timeout {
            polls_consumed: 50_000,
        };
        assert_eq!(err.verdict(), RetryVerdict::ResetAndRetry);
    }

    #[test]
    fn controller_fatal_verdict_is_reset_and_retry() {
        assert_eq!(
            IoError::ControllerFatal.verdict(),
            RetryVerdict::ResetAndRetry
        );
    }

    #[test]
    fn transport_error_verdict_is_permanent() {
        let err = IoError::Transport(QueueError::Full);
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    #[test]
    fn namespace_not_admitted_verdict_is_permanent() {
        let err = IoError::NamespaceNotAdmitted { nsid: 42 };
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    #[test]
    fn generic_invalid_opcode_is_permanent() {
        let err = IoError::from_status(0, 0x01);
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    #[test]
    fn generic_invalid_field_is_permanent() {
        let err = IoError::from_status(0, 0x02);
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    #[test]
    fn generic_lba_out_of_range_is_permanent() {
        let err = IoError::from_status(0, 0x80);
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    #[test]
    fn generic_namespace_not_ready_is_retry() {
        let err = IoError::from_status(0, 0x82);
        assert_eq!(err.verdict(), RetryVerdict::Retry);
    }

    #[test]
    fn media_error_is_retry() {
        let err = IoError::from_status(2, 0x81);
        assert_eq!(err.verdict(), RetryVerdict::Retry);
    }

    #[test]
    fn path_related_is_retry() {
        let err = IoError::from_status(3, 0x01);
        assert_eq!(err.verdict(), RetryVerdict::Retry);
    }

    #[test]
    fn command_specific_is_permanent() {
        let err = IoError::from_status(1, 0x06);
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    #[test]
    fn vendor_specific_is_permanent() {
        let err = IoError::from_status(7, 0xFF);
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    #[test]
    fn unknown_sct_is_permanent() {
        let err = IoError::from_status(5, 0x00);
        assert_eq!(err.verdict(), RetryVerdict::Permanent);
    }

    // -------------------------------------------------------------------
    // RetryTracker
    // -------------------------------------------------------------------

    #[test]
    fn retry_tracker_starts_at_zero() {
        let t = RetryTracker::new();
        assert_eq!(t.attempts(), 0);
        assert!(!t.is_exhausted());
    }

    #[test]
    fn retry_tracker_records_attempts() {
        let mut t = RetryTracker::new();
        assert!(t.record_attempt()); // 1
        assert!(t.record_attempt()); // 2
        assert!(t.record_attempt()); // 3
        assert!(!t.record_attempt()); // 4 > MAX_IO_RETRIES
        assert!(t.is_exhausted());
    }

    #[test]
    fn retry_tracker_with_custom_budget() {
        let mut t = RetryTracker::with_max_retries(1);
        assert!(t.record_attempt()); // 1
        assert!(!t.record_attempt()); // 2 > 1
        assert!(t.is_exhausted());
    }

    #[test]
    fn retry_tracker_evaluate_permanent_gives_failed() {
        let t = RetryTracker::new();
        let err = IoError::NamespaceNotAdmitted { nsid: 1 };
        let outcome = t.evaluate(err);
        assert!(matches!(outcome, IoOutcome::Failed { .. }));
    }

    #[test]
    fn retry_tracker_evaluate_reset_gives_reset_required() {
        let t = RetryTracker::new();
        let err = IoError::Timeout {
            polls_consumed: 50_000,
        };
        let outcome = t.evaluate(err);
        assert!(matches!(outcome, IoOutcome::ResetRequired { .. }));
    }

    // -------------------------------------------------------------------
    // ResetProtocol
    // -------------------------------------------------------------------

    #[test]
    fn reset_protocol_starts_fresh() {
        let r = ResetProtocol::new();
        assert_eq!(r.attempts, 0);
        assert!(!r.is_exhausted());
    }

    #[test]
    fn reset_protocol_records_and_exhausts() {
        let mut r = ResetProtocol::new();
        assert!(r.record_attempt()); // 1 — still under budget
        assert!(!r.record_attempt()); // 2 — exhausted
        assert!(r.is_exhausted());
    }

    // -------------------------------------------------------------------
    // IoOutcome taxonomy
    // -------------------------------------------------------------------

    #[test]
    fn io_outcome_success_variant_exists() {
        let o = IoOutcome::Success;
        assert!(matches!(o, IoOutcome::Success));
    }

    #[test]
    fn io_outcome_failed_carries_error_and_count() {
        let err = IoError::from_status(0, 0x01);
        let o = IoOutcome::Failed {
            last_error: err,
            attempts: 3,
        };
        match o {
            IoOutcome::Failed {
                last_error,
                attempts,
            } => {
                assert_eq!(attempts, 3);
                assert_eq!(last_error.verdict(), RetryVerdict::Permanent);
            }
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn io_outcome_reset_carries_cause() {
        let err = IoError::ControllerFatal;
        let o = IoOutcome::ResetRequired { cause: err };
        match o {
            IoOutcome::ResetRequired { cause } => {
                assert_eq!(cause, IoError::ControllerFatal);
            }
            _ => panic!("expected ResetRequired"),
        }
    }

    // -------------------------------------------------------------------
    // IoError variant taxonomy is distinguishable
    // -------------------------------------------------------------------

    #[test]
    fn io_error_variants_are_distinguishable() {
        let timeout = IoError::Timeout {
            polls_consumed: 100,
        };
        let status = IoError::from_status(0, 0x01);
        let transport = IoError::Transport(QueueError::Full);
        let ns_err = IoError::NamespaceNotAdmitted { nsid: 1 };
        let fatal = IoError::ControllerFatal;
        assert_ne!(timeout, status);
        assert_ne!(status, transport);
        assert_ne!(transport, ns_err);
        assert_ne!(ns_err, fatal);
        assert_ne!(timeout, fatal);
    }
}

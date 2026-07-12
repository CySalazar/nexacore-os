//! Short-TTL validity schema (`issued_at` + `ttl_secs`).
//!
//! Capability tokens carry a [`crate::scope::TimeWindow`]
//! (`[not_before, not_after)`) as their canonical validity bound. This
//! module adds the *issuance-relative* view mandated by the short-TTL
//! policy: an issuer states "valid from `issued_at`, for `ttl_secs`
//! seconds" and the checker derives the absolute expiry. Short TTLs
//! (5–15 min per `revocation.rs`) keep the revocation list bounded and
//! shrink the window in which a leaked token is useful.
//!
//! # Fail-closed
//!
//! Every ambiguity resolves to *deny*:
//!
//! * If `issued_at + ttl_secs` overflows `u64`, the window is not
//!   representable — [`ValidityWindow`] reports it as malformed rather
//!   than "never expires".
//! * If the injected [`Clock`] cannot produce a reading, the checker
//!   denies rather than assuming a convenient instant.
//! * The upper bound is exclusive (`now < not_after`), so a token is
//!   invalid on the exact second it expires.

use nexacore_types::{
    error::{CapabilityErrorKind, NexaCoreError, Result},
    wire,
};
use serde::{Deserialize, Serialize};

use crate::{clock::Clock, scope::TimeWindow};

/// An issuance-relative validity window: `[issued_at, issued_at + ttl_secs)`.
///
/// This is the wire-facing short-TTL schema. It is intentionally tiny —
/// two `u64`s — and canonically encodable so an issuer and a verifier on
/// different hosts derive byte-identical expiries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ValidityWindow {
    /// Issuance instant, in whole seconds since the Unix epoch. This is
    /// the inclusive lower bound of validity.
    pub issued_at: u64,
    /// Time-to-live in seconds. The (exclusive) expiry is
    /// `issued_at + ttl_secs`.
    pub ttl_secs: u64,
}

impl ValidityWindow {
    /// Construct a validity window issued at `issued_at`, living for
    /// `ttl_secs` seconds.
    #[must_use]
    pub const fn new(issued_at: u64, ttl_secs: u64) -> Self {
        Self {
            issued_at,
            ttl_secs,
        }
    }

    /// The exclusive expiry instant (`issued_at + ttl_secs`), or `None`
    /// if that sum overflows `u64` (a malformed, non-representable TTL).
    #[must_use]
    pub const fn not_after(&self) -> Option<u64> {
        self.issued_at.checked_add(self.ttl_secs)
    }

    /// Returns `true` iff `now` falls within `[issued_at, not_after)`.
    ///
    /// Fail-closed: an overflowing (non-representable) window is never
    /// valid.
    #[must_use]
    pub const fn is_valid_at(&self, now: u64) -> bool {
        match self.not_after() {
            Some(not_after) => now >= self.issued_at && now < not_after,
            None => false,
        }
    }

    /// Check validity against an explicit instant, returning a typed
    /// error on failure.
    ///
    /// # Errors
    ///
    /// * [`CapabilityErrorKind::MalformedToken`] if `issued_at + ttl_secs`
    ///   overflows `u64`.
    /// * [`CapabilityErrorKind::NotYetValid`] if `now < issued_at`.
    /// * [`CapabilityErrorKind::Expired`] if `now >= issued_at + ttl_secs`.
    pub fn check_at(&self, now: u64) -> Result<()> {
        let Some(not_after) = self.not_after() else {
            return Err(NexaCoreError::capability(
                CapabilityErrorKind::MalformedToken,
                "ttl::check_at::overflow",
            ));
        };
        if now < self.issued_at {
            return Err(NexaCoreError::capability(
                CapabilityErrorKind::NotYetValid,
                "ttl::check_at::not_before",
            ));
        }
        if now >= not_after {
            return Err(NexaCoreError::capability(
                CapabilityErrorKind::Expired,
                "ttl::check_at::expired",
            ));
        }
        Ok(())
    }

    /// Check validity against an injected [`Clock`] seam.
    ///
    /// This is the production entry point: the caller supplies the
    /// attested clock and the checker reads "now" from it.
    ///
    /// # Errors
    ///
    /// Fails closed. In addition to the [`check_at`](Self::check_at)
    /// errors, a clock backend that cannot produce a reading yields
    /// [`CapabilityErrorKind::Expired`] — a token whose validity cannot
    /// be established is treated as no longer valid, never as valid.
    pub fn check(&self, clock: &dyn Clock) -> Result<()> {
        let now = clock.now_unix_secs().map_err(|_| {
            NexaCoreError::capability(
                CapabilityErrorKind::Expired,
                "ttl::check::clock_unavailable",
            )
        })?;
        self.check_at(now)
    }

    /// Encode this window into its canonical byte representation
    /// (`postcard` via [`nexacore_types::wire`]).
    ///
    /// # Errors
    ///
    /// [`CapabilityErrorKind::MalformedToken`] on encoding failure
    /// (practically infallible for two `u64`s).
    pub fn canonical_bytes(&self) -> Result<alloc::vec::Vec<u8>> {
        wire::encode_canonical(self).map_err(|_| {
            NexaCoreError::capability(
                CapabilityErrorKind::MalformedToken,
                "ttl::canonical_bytes::encode",
            )
        })
    }

    /// Convert to the absolute [`TimeWindow`] used by
    /// [`crate::scope::Scope`], or `None` if the expiry overflows.
    ///
    /// This bridges the issuance-relative schema onto the crate's
    /// existing absolute-window vocabulary so a short-TTL grant can be
    /// embedded in a [`Scope`](crate::scope::Scope) without a second
    /// source of truth.
    #[must_use]
    pub fn to_time_window(self) -> Option<TimeWindow> {
        TimeWindow::new(self.issued_at, self.not_after()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;

    /// A clock double whose backend is unavailable — used to prove the
    /// checker fails closed rather than defaulting to a convenient time.
    struct BrokenClock;
    impl Clock for BrokenClock {
        fn now_unix_secs(&self) -> Result<u64> {
            Err(NexaCoreError::capability(
                CapabilityErrorKind::AttestationMismatch,
                "test::broken_clock",
            ))
        }
    }

    fn kind(err: &NexaCoreError) -> CapabilityErrorKind {
        match err {
            NexaCoreError::Capability { kind, .. } => *kind,
            _ => panic!("expected Capability error, got {err:?}"),
        }
    }

    #[test]
    fn valid_before_expiry_over_clock_seam() {
        let window = ValidityWindow::new(1_000, 300); // expires at 1_300
        let clock = FixedClock::at(1_200);
        window.check(&clock).expect("inside window must pass");
    }

    #[test]
    fn accepts_at_issued_at_lower_bound() {
        let window = ValidityWindow::new(1_000, 300);
        let clock = FixedClock::at(1_000); // inclusive lower bound
        window.check(&clock).expect("issued_at is inclusive");
    }

    #[test]
    fn rejects_after_expiry_over_clock_seam() {
        let window = ValidityWindow::new(1_000, 300); // expires at 1_300
        let clock = FixedClock::at(1_301);
        let err = window.check(&clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::Expired);
    }

    #[test]
    fn rejects_exactly_at_expiry_exclusive_upper_bound() {
        let window = ValidityWindow::new(1_000, 300); // not_after == 1_300
        let clock = FixedClock::at(1_300);
        let err = window.check(&clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::Expired);
    }

    #[test]
    fn rejects_before_issued_at() {
        let window = ValidityWindow::new(1_000, 300);
        let clock = FixedClock::at(999);
        let err = window.check(&clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::NotYetValid);
    }

    #[test]
    fn fails_closed_on_overflowing_ttl() {
        let window = ValidityWindow::new(u64::MAX - 5, 100); // overflows
        assert_eq!(window.not_after(), None);
        assert!(!window.is_valid_at(u64::MAX - 4));
        let err = window.check_at(u64::MAX - 4).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::MalformedToken);
    }

    #[test]
    fn fails_closed_when_clock_unavailable() {
        let window = ValidityWindow::new(1_000, 300);
        let err = window.check(&BrokenClock).unwrap_err();
        // Deny, never allow, when the clock cannot be trusted.
        assert_eq!(kind(&err), CapabilityErrorKind::Expired);
    }

    #[test]
    fn zero_ttl_is_always_expired() {
        // A zero-length window contains no instant.
        let window = ValidityWindow::new(1_000, 0);
        assert!(!window.is_valid_at(1_000));
        assert_eq!(
            kind(&window.check_at(1_000).unwrap_err()),
            CapabilityErrorKind::Expired
        );
    }

    #[test]
    fn to_time_window_bridges_absolute_vocabulary() {
        let window = ValidityWindow::new(1_000, 300);
        let tw = window.to_time_window().expect("representable window");
        assert_eq!(tw.not_before, 1_000);
        assert_eq!(tw.not_after, 1_300);
        // Overflowing windows have no absolute representation.
        assert_eq!(ValidityWindow::new(u64::MAX, 1).to_time_window(), None);
    }

    #[test]
    fn canonical_bytes_round_trip_via_wire() {
        let window = ValidityWindow::new(1_000, 300);
        let bytes = window.canonical_bytes().unwrap();
        let decoded: ValidityWindow = wire::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, window);
    }
}

//! Wall-clock seam for time-based capability checks.
//!
//! This crate is `no_std` and, per project policy, MUST NOT read the
//! host clock directly (`SystemTime::now()` is unavailable on
//! `x86_64-unknown-none` and, more importantly, the security model
//! mandates a monotonic, attestable time source). Time is therefore
//! injected through the [`Clock`] seam — mirroring how TEE evidence is
//! injected through [`crate::tee::AttestationSource`].
//!
//! Production builds wire a concrete backend (a monotonic counter fed by
//! the platform HAL / attested TSC). Tests and offline tooling use
//! [`FixedClock`], which returns a caller-controlled instant so validity
//! windows can be exercised deterministically on both sides of an expiry.
//!
//! # Fail-closed
//!
//! [`Clock::now_unix_secs`] is fallible on purpose: a clock backend that
//! cannot produce a trustworthy reading returns an error, and every
//! TTL checker in [`crate::ttl`] treats that error as "deny", never as
//! "allow". A missing clock can never widen authority.

use nexacore_types::error::Result;

/// Source of the current wall-clock time, in whole seconds since the
/// Unix epoch.
///
/// The capability layer depends only on this trait; concrete backends
/// (HAL-backed monotonic clocks, attested TSC readers) live outside the
/// crate. Keeping the surface this small is what lets the kernel's
/// verify-only build supply a bare-metal clock without pulling `std`.
pub trait Clock {
    /// Return the current time as whole seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing time source is unavailable or
    /// untrustworthy. Callers MUST fail closed on this error (treat the
    /// capability as invalid), never fall back to a default instant.
    fn now_unix_secs(&self) -> Result<u64>;
}

/// A fixed-instant [`Clock`] for tests and offline tooling.
///
/// Returns [`FixedClock::now`] unconditionally. Production code MUST NOT
/// use this — a frozen clock defeats TTL enforcement entirely.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    /// The instant this clock always reports (Unix seconds).
    pub now: u64,
}

impl FixedClock {
    /// Construct a [`FixedClock`] pinned to `now` (Unix seconds).
    #[must_use]
    pub const fn at(now: u64) -> Self {
        Self { now }
    }
}

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> Result<u64> {
        Ok(self.now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_reports_configured_instant() {
        let clock = FixedClock::at(1_700_000_000);
        assert_eq!(clock.now_unix_secs().unwrap(), 1_700_000_000);
    }

    #[test]
    fn clock_is_object_safe() {
        // The verifier holds `&dyn Clock`; confirm the trait stays
        // object-safe so that dynamic dispatch keeps compiling.
        let clock = FixedClock::at(42);
        let dynamic: &dyn Clock = &clock;
        assert_eq!(dynamic.now_unix_secs().unwrap(), 42);
    }
}

//! Authoritative capability enforcement entry point.
//!
//! [`token`](crate::token) verifies a token's signature, absolute time
//! window, and TEE binding in isolation; [`crl`](crate::crl) parses and
//! validates a signed revocation list; [`ttl`](crate::ttl) turns an
//! issuance-relative window into a fail-closed expiry check over the
//! [`Clock`](crate::clock) seam. This module is where those pieces are
//! composed into the single decision a caller actually asks for: *may
//! this capability be honoured right now?*
//!
//! [`check_capability`] returns `Ok(())` **only** if every one of the
//! following holds, and fails closed on the first that does not:
//!
//! 1. The capability's own signature verifies under its embedded issuer
//!    key ([`CapabilityToken::verify_signature`]).
//! 2. The capability's TTL window is unexpired at the instant read from
//!    the injected [`Clock`] — reusing the fail-closed
//!    [`ValidityWindow::check_at`] logic so a token is invalid on the
//!    exact second it expires.
//! 3. The CRL itself verifies (supported version **and** signature under
//!    its embedded issuer key) **and** is not stale — a CRL at or past
//!    its `next_update` is treated as no longer authoritative.
//! 4. The capability id does not appear in the (now-trusted) CRL.
//!
//! # Fail-closed choices
//!
//! * **Clock unavailable.** If the [`Clock`] backend cannot produce a
//!   reading, we deny with [`CapabilityErrorKind::Expired`] — a
//!   capability whose validity cannot be established is never honoured.
//!   This mirrors [`ValidityWindow::check`].
//! * **Stale CRL.** The [`CapabilityErrorKind`] vocabulary has no
//!   dedicated "stale" variant, and adding one is avoidable. A stale
//!   revocation list is a freshness envelope that has run out, which is
//!   semantically an expiry, so a CRL at or past `next_update` is
//!   rejected with [`CapabilityErrorKind::Expired`]. Crucially we reject
//!   rather than trust a stale list: an out-of-date CRL might be missing
//!   a revocation we would otherwise honour, so continuing would be
//!   fail-*open*. The `next_update` bound is treated as **exclusive**
//!   (`now >= next_update` is stale), matching the exclusive upper bound
//!   used everywhere else in this crate.
//! * **CRL checked before revocation lookup.** [`SignedCrl::is_revoked`]
//!   trusts `body` as-is, so we never consult it until the CRL's
//!   signature, version, and freshness have all passed.

use nexacore_types::error::{CapabilityErrorKind, NexaCoreError, Result};

use crate::{clock::Clock, crl::SignedCrl, token::CapabilityToken, ttl::ValidityWindow};

/// Decide whether `cap` may be honoured at the instant reported by
/// `now`, given the revocation list `crl`.
///
/// This is the authoritative enforcement entry point. It composes the
/// signature, TTL, CRL-validity, and revocation checks and fails closed
/// on the first failure. See the [module docs](self) for the exact
/// ordering and the fail-closed rationale.
///
/// # Errors
///
/// Returns [`NexaCoreError::Capability`] with the most specific kind that
/// applies:
///
/// * [`CapabilityErrorKind::InvalidSignature`] — the capability or the
///   CRL signature does not verify.
/// * [`CapabilityErrorKind::NotYetValid`] — `now` is before the
///   capability's window opens.
/// * [`CapabilityErrorKind::Expired`] — the capability's TTL has run out,
///   the clock is unavailable, or the CRL is stale.
/// * [`CapabilityErrorKind::MalformedToken`] — the CRL version is
///   unsupported or a body cannot be re-encoded.
/// * [`CapabilityErrorKind::Revoked`] — the capability id is listed in a
///   valid, fresh CRL.
pub fn check_capability(cap: &CapabilityToken, crl: &SignedCrl, now: &dyn Clock) -> Result<()> {
    // (a) The capability's own signature. Cheapest, and nothing else can
    //     be trusted until it passes.
    cap.verify_signature()?;

    // Read the attested clock exactly once, so the TTL check and the CRL
    // staleness check reason about the same instant. Fail closed: a clock
    // that cannot produce a reading denies rather than assuming a time.
    let now_secs = now.now_unix_secs().map_err(|_| {
        NexaCoreError::capability(
            CapabilityErrorKind::Expired,
            "enforcement::check_capability::clock_unavailable",
        )
    })?;

    // (b) The capability's TTL window must be unexpired at `now`. The
    //     token carries an absolute `[not_before, not_after)`; bridge it
    //     onto `ValidityWindow` (lossless, since `not_before <= not_after`
    //     is a `TimeWindow` invariant) to reuse its fail-closed check.
    let window = cap.payload.scope.window;
    ValidityWindow::new(window.not_before, window.duration_secs()).check_at(now_secs)?;

    // (c) The CRL must itself verify — supported version AND signature
    //     under its embedded issuer key — before we trust anything it
    //     says.
    crl.verify()?;
    //     ... and it must be fresh. A CRL at or past `next_update` is
    //     stale; trusting it would be fail-open (it may lack a revocation
    //     we should honour), so we deny. `next_update` is exclusive.
    if now_secs >= crl.body.next_update {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::Expired,
            "enforcement::check_capability::crl_stale",
        ));
    }

    // (d) Finally, with a trusted, fresh CRL in hand, reject a revoked id.
    if crl.is_revoked(&cap.payload.id) {
        return Err(NexaCoreError::capability(
            CapabilityErrorKind::Revoked,
            "enforcement::check_capability::revoked",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use nexacore_crypto::signing::NexaCoreSigningKey;
    use nexacore_types::identity::NodeId;

    use super::*;
    use crate::{
        clock::FixedClock,
        scope::{Action, Resource, Scope, TimeWindow},
    };

    fn kind(err: &NexaCoreError) -> CapabilityErrorKind {
        match err {
            NexaCoreError::Capability { kind, .. } => *kind,
            _ => panic!("expected Capability error, got {err:?}"),
        }
    }

    fn subject() -> NodeId {
        NodeId::from_attestation_hash([0x11; 32])
    }

    /// Mint a capability whose absolute TTL window is `[not_before, not_after)`.
    fn cap_with_window(
        sk: &NexaCoreSigningKey,
        not_before: u64,
        not_after: u64,
    ) -> CapabilityToken {
        let scope = Scope {
            action: Action::Read,
            resource: Resource::Any,
            window: TimeWindow::new(not_before, not_after).expect("valid window"),
            caveats: vec![],
        };
        CapabilityToken::mint(sk, subject(), scope, None).expect("mint")
    }

    #[test]
    fn valid_unrevoked_capability_within_ttl_is_ok() {
        let cap_sk = NexaCoreSigningKey::generate();
        let crl_sk = NexaCoreSigningKey::generate();
        let cap = cap_with_window(&cap_sk, 1_000, 1_300);
        // Fresh CRL (next_update far in the future) that revokes nothing.
        let crl = SignedCrl::sign(&crl_sk, 1_000, 1_900, vec![]).unwrap();
        let clock = FixedClock::at(1_200);

        check_capability(&cap, &crl, &clock).expect("valid cap must be honoured");
    }

    #[test]
    fn revoked_capability_still_within_ttl_is_rejected() {
        // The headline case: the cap is cryptographically sound AND inside
        // its TTL, but a fresh CRL names it. Revocation must win.
        let cap_sk = NexaCoreSigningKey::generate();
        let crl_sk = NexaCoreSigningKey::generate();
        let cap = cap_with_window(&cap_sk, 1_000, 1_300);
        let crl = SignedCrl::sign(&crl_sk, 1_000, 1_900, vec![cap.payload.id]).unwrap();
        let clock = FixedClock::at(1_200); // squarely inside the TTL window

        let err = check_capability(&cap, &crl, &clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::Revoked);
    }

    #[test]
    fn expired_ttl_is_rejected() {
        let cap_sk = NexaCoreSigningKey::generate();
        let crl_sk = NexaCoreSigningKey::generate();
        let cap = cap_with_window(&cap_sk, 1_000, 1_300);
        // CRL still fresh so the failure can only be the TTL.
        let crl = SignedCrl::sign(&crl_sk, 1_000, 5_000, vec![]).unwrap();
        let clock = FixedClock::at(1_400); // past not_after

        let err = check_capability(&cap, &crl, &clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::Expired);
    }

    #[test]
    fn crl_past_next_update_is_stale_and_rejected() {
        let cap_sk = NexaCoreSigningKey::generate();
        let crl_sk = NexaCoreSigningKey::generate();
        // Cap is comfortably inside a long TTL so the *only* failure is the
        // stale CRL — proving the staleness path, not the token expiry.
        let cap = cap_with_window(&cap_sk, 1_000, 5_000);
        let crl = SignedCrl::sign(&crl_sk, 1_000, 1_900, vec![]).unwrap();
        let clock = FixedClock::at(2_000); // >= next_update (1_900) -> stale

        let err = check_capability(&cap, &crl, &clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::Expired);
    }

    #[test]
    fn tampered_crl_is_rejected() {
        let cap_sk = NexaCoreSigningKey::generate();
        let crl_sk = NexaCoreSigningKey::generate();
        let cap = cap_with_window(&cap_sk, 1_000, 5_000);
        let mut crl = SignedCrl::sign(&crl_sk, 1_000, 5_000, vec![]).unwrap();
        // Inject a revocation after signing: the signature no longer covers
        // the body, so the CRL must be treated as untrusted.
        crl.body.revoked.push(cap.payload.id);
        let clock = FixedClock::at(2_000);

        let err = check_capability(&cap, &crl, &clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::InvalidSignature);
    }

    #[test]
    fn bad_capability_signature_is_rejected() {
        let cap_sk = NexaCoreSigningKey::generate();
        let crl_sk = NexaCoreSigningKey::generate();
        let mut cap = cap_with_window(&cap_sk, 1_000, 5_000);
        // Widen the window after signing: the signature was computed over
        // the original payload, so verification must now fail.
        cap.payload.scope.window = TimeWindow::new(0, u64::MAX).unwrap();
        let crl = SignedCrl::sign(&crl_sk, 1_000, 5_000, vec![]).unwrap();
        let clock = FixedClock::at(2_000);

        let err = check_capability(&cap, &crl, &clock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::InvalidSignature);
    }

    /// A clock whose backend is unavailable — proves we deny rather than
    /// default to a convenient instant when time cannot be established.
    struct BrokenClock;
    impl Clock for BrokenClock {
        fn now_unix_secs(&self) -> Result<u64> {
            Err(NexaCoreError::capability(
                CapabilityErrorKind::AttestationMismatch,
                "test::broken_clock",
            ))
        }
    }

    #[test]
    fn unavailable_clock_fails_closed() {
        let cap_sk = NexaCoreSigningKey::generate();
        let crl_sk = NexaCoreSigningKey::generate();
        let cap = cap_with_window(&cap_sk, 1_000, 5_000);
        let crl = SignedCrl::sign(&crl_sk, 1_000, 5_000, vec![]).unwrap();

        let err = check_capability(&cap, &crl, &BrokenClock).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::Expired);
    }
}

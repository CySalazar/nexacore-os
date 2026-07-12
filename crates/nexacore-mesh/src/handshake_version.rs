//! No-downgrade protocol-version negotiation for the mesh handshake (WS6-03.7).
//!
//! This is the concrete logic behind invariant **I7** (protocol-version
//! binding): a downgrade to an earlier protocol version cannot succeed
//! *silently*. Per spec (`docs/protocol/handshake.md` §4.1, invariant I7):
//!
//! - The implementation negotiates the pinned [`NEGOTIATED_VERSION`]
//!   (`NexaCore-PROTO-v0.2`) *only*. `NexaCore-PROTO-v0.1` is removed from the
//!   menu — a peer that offers only v0.1 MUST be rejected, never silently
//!   accepted at the lower version ([`select_version`]).
//! - A downgrade requires an explicit "version-renegotiation" frame *before*
//!   `m1`. To stop a man-in-the-middle from *stripping* the pinned version out
//!   of that frame, each party commits to the exact set of versions it offered
//!   ([`VersionOffer::commitment`]); the commitment is signed in the transcript,
//!   so a tampered offer no longer reproduces the signed commitment and the
//!   receiver aborts ([`verify_offer_integrity`]).
//! - The negotiated `proto_version` is *also* mixed into every KDF call
//!   (see [`crate::handshake_kex`]) and signed in the transcript (see
//!   [`crate::handshake_auth`]) — the two other legs of I7.
//!
//! No cryptographic primitive is implemented here: the commitment is the
//! mandated domain-separated BLAKE3 ([`nexacore_crypto::hash::domain_separated_hash`])
//! over a canonical encoding of the offered set. This module remains subject to
//! the WS10-03 crypto review before production.

use std::vec::Vec;

use nexacore_crypto::hash::domain_separated_hash;
use nexacore_types::version::{PROTOCOL_VERSION_V0_2, ProtocolVersion};

/// Domain separator for the version-offer commitment (I7 anti-stripping).
pub const NEGOTIATION_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake/version-offer";

/// The single protocol version this implementation will negotiate (§4.1).
///
/// There is no legacy support window: `NexaCore-PROTO-v0.1` is not on the menu.
pub const NEGOTIATED_VERSION: ProtocolVersion = PROTOCOL_VERSION_V0_2;

/// Why version negotiation was refused (I7). The state machine maps either
/// variant onto its terminal `VersionMismatch` abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DowngradeError {
    /// The peer's offer did not include the pinned [`NEGOTIATED_VERSION`]. A
    /// silent downgrade to an earlier version is refused (§4.1, I7).
    #[error("peer offer does not include the pinned protocol version (no silent downgrade)")]
    NoAcceptableVersion,

    /// The offer as received does not reproduce its signed commitment — a
    /// man-in-the-middle stripped or altered an advertised version (I7).
    #[error("version offer does not match its signed commitment (offer tampered)")]
    OfferTampered,
}

/// The set of protocol versions a party advertises in the pre-`m1`
/// version-renegotiation frame.
///
/// The set is canonicalized (sorted + de-duplicated) so its commitment depends
/// on the *set*, not on wire ordering or repetition — both peers compute the
/// same commitment for the same offered set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionOffer {
    versions: Vec<ProtocolVersion>,
}

impl VersionOffer {
    /// Build a canonical offer from the advertised versions.
    #[must_use]
    pub fn new(versions: &[ProtocolVersion]) -> Self {
        let mut versions = versions.to_vec();
        versions.sort_unstable();
        versions.dedup();
        Self { versions }
    }

    /// The canonicalized offered versions (sorted, de-duplicated).
    #[must_use]
    pub fn versions(&self) -> &[ProtocolVersion] {
        &self.versions
    }

    /// Whether the offer includes `version`.
    #[must_use]
    pub fn offers(&self, version: ProtocolVersion) -> bool {
        self.versions.contains(&version)
    }

    /// The domain-separated BLAKE3 commitment to this offer (I7 anti-stripping).
    ///
    /// Each version is encoded as `major_le(2) || minor_le(2)` in canonical
    /// order; the commitment binds the full set into the transcript, so removing
    /// a version from the wire offer changes the value a verifier recomputes.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.versions.len() * 4);
        for version in &self.versions {
            buf.extend_from_slice(&version.major.to_le_bytes());
            buf.extend_from_slice(&version.minor.to_le_bytes());
        }
        domain_separated_hash(NEGOTIATION_DOMAIN, &buf)
    }
}

/// Select the version to speak from a peer's offer (§4.1, I7).
///
/// Only the pinned [`NEGOTIATED_VERSION`] is acceptable. A peer that omits it —
/// including one that offers only the removed `NexaCore-PROTO-v0.1` — is
/// rejected with [`DowngradeError::NoAcceptableVersion`]: there is no silent
/// fallback to a lower version.
///
/// # Errors
///
/// Returns [`DowngradeError::NoAcceptableVersion`] when the pinned version is
/// absent from `peer_offer`.
pub fn select_version(peer_offer: &VersionOffer) -> Result<ProtocolVersion, DowngradeError> {
    if peer_offer.offers(NEGOTIATED_VERSION) {
        Ok(NEGOTIATED_VERSION)
    } else {
        Err(DowngradeError::NoAcceptableVersion)
    }
}

/// Verify that a received offer reproduces the commitment signed in the
/// transcript (I7 anti-stripping).
///
/// A man-in-the-middle that removes the pinned version from the wire offer
/// changes the recomputed commitment, so it no longer matches the peer's signed
/// value and the handshake aborts.
///
/// # Errors
///
/// Returns [`DowngradeError::OfferTampered`] when the recomputed commitment does
/// not equal `signed_commitment`.
pub fn verify_offer_integrity(
    received: &VersionOffer,
    signed_commitment: &[u8; 32],
) -> Result<(), DowngradeError> {
    if &received.commitment() == signed_commitment {
        Ok(())
    } else {
        Err(DowngradeError::OfferTampered)
    }
}

#[cfg(test)]
mod tests {
    use nexacore_types::version::{PROTOCOL_VERSION_V0_1, PROTOCOL_VERSION_V1_0};

    use super::*;

    #[test]
    fn select_accepts_an_offer_including_the_pinned_version() {
        let offer = VersionOffer::new(&[PROTOCOL_VERSION_V0_2]);
        assert_eq!(select_version(&offer), Ok(NEGOTIATED_VERSION));
    }

    #[test]
    fn select_rejects_a_v0_1_only_offer_no_silent_downgrade() {
        // The core I7 property: a peer offering only the removed v0.1 must be
        // rejected, never silently accepted at v0.1.
        let offer = VersionOffer::new(&[PROTOCOL_VERSION_V0_1]);
        assert_eq!(
            select_version(&offer),
            Err(DowngradeError::NoAcceptableVersion)
        );
    }

    #[test]
    fn select_rejects_an_empty_offer() {
        let offer = VersionOffer::new(&[]);
        assert_eq!(
            select_version(&offer),
            Err(DowngradeError::NoAcceptableVersion)
        );
    }

    #[test]
    fn select_picks_the_pinned_version_amid_other_versions() {
        // A future v1.0 in the menu does not change what we negotiate: v0.2 only.
        let offer = VersionOffer::new(&[
            PROTOCOL_VERSION_V0_1,
            PROTOCOL_VERSION_V0_2,
            PROTOCOL_VERSION_V1_0,
        ]);
        assert_eq!(select_version(&offer), Ok(NEGOTIATED_VERSION));
    }

    #[test]
    fn commitment_is_order_and_duplicate_independent() {
        let a = VersionOffer::new(&[PROTOCOL_VERSION_V0_1, PROTOCOL_VERSION_V0_2]);
        let reordered = VersionOffer::new(&[PROTOCOL_VERSION_V0_2, PROTOCOL_VERSION_V0_1]);
        let with_dups = VersionOffer::new(&[
            PROTOCOL_VERSION_V0_2,
            PROTOCOL_VERSION_V0_1,
            PROTOCOL_VERSION_V0_2,
        ]);
        assert_eq!(a.commitment(), reordered.commitment());
        assert_eq!(a.commitment(), with_dups.commitment());
    }

    #[test]
    fn stripping_a_version_changes_the_commitment() {
        // The anti-stripping property: [v0.1, v0.2] and [v0.1] must differ.
        let full = VersionOffer::new(&[PROTOCOL_VERSION_V0_1, PROTOCOL_VERSION_V0_2]);
        let stripped = VersionOffer::new(&[PROTOCOL_VERSION_V0_1]);
        assert_ne!(full.commitment(), stripped.commitment());
    }

    #[test]
    fn verify_offer_integrity_accepts_an_untampered_offer() {
        let offer = VersionOffer::new(&[PROTOCOL_VERSION_V0_1, PROTOCOL_VERSION_V0_2]);
        let signed = offer.commitment();
        assert_eq!(verify_offer_integrity(&offer, &signed), Ok(()));
    }

    #[test]
    fn verify_offer_integrity_rejects_a_stripped_offer() {
        // MITM removed v0.2 from the wire; the peer signed the full offer.
        let signed =
            VersionOffer::new(&[PROTOCOL_VERSION_V0_1, PROTOCOL_VERSION_V0_2]).commitment();
        let received = VersionOffer::new(&[PROTOCOL_VERSION_V0_1]);
        assert_eq!(
            verify_offer_integrity(&received, &signed),
            Err(DowngradeError::OfferTampered)
        );
        // And the stripped offer would itself fail selection — belt and braces.
        assert_eq!(
            select_version(&received),
            Err(DowngradeError::NoAcceptableVersion)
        );
    }

    #[test]
    fn different_offers_have_different_commitments() {
        let a = VersionOffer::new(&[PROTOCOL_VERSION_V0_2]);
        let b = VersionOffer::new(&[PROTOCOL_VERSION_V0_2, PROTOCOL_VERSION_V1_0]);
        assert_ne!(a.commitment(), b.commitment());
    }
}

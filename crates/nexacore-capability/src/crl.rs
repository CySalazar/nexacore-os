//! Capability Revocation List (CRL): a versioned, signable list of
//! revoked capability identifiers.
//!
//! The in-memory [`crate::revocation::RevocationList`] answers "is this
//! id revoked?" for a single node. The CRL is its *wire* counterpart:
//! the serialized, issuer-signed artifact that a node imports to learn
//! which ids to reject. This module is the **data format + validation**
//! layer only — where a CRL comes from (WS10-06.8 distribution) and how
//! a live verifier consults it (WS10-06.9 enforcement) are follow-ups.
//!
//! # Format
//!
//! A [`SignedCrl`] is `(CrlBody, NexaCoreSignature)`, exactly mirroring
//! [`crate::token::CapabilityToken`]. The signature covers the canonical
//! encoding of [`CrlBody`] (`postcard` via [`nexacore_types::wire`],
//! `NCIP-Serde-004`) and verifies under the issuer key embedded in the
//! body — so a CRL, like a token, is self-contained.
//!
//! [`CrlBody`] carries:
//!
//! * `version` — a format discriminant. [`SignedCrl::verify`] rejects any
//!   version it does not understand (fail-closed forward compatibility).
//! * `issuer` — the Ed25519 public key the signature must verify under.
//! * `issued_at` / `next_update` — the freshness envelope, in Unix
//!   seconds. Consumers use `next_update` to decide when a CRL is stale;
//!   this module only carries the fields (staleness policy is
//!   WS10-06.9).
//! * `revoked` — the revoked [`CapabilityId`]s.
//!
//! # Fail-closed
//!
//! * [`SignedCrl::decode`] rejects malformed or truncated input — a CRL
//!   that will not parse grants nothing and is never treated as "empty".
//! * [`SignedCrl::verify`] rejects an unknown `version` and any
//!   signature that does not verify under the embedded issuer key.

use alloc::vec::Vec;

use nexacore_crypto::signing::{NexaCoreSignature, NexaCoreSigningKey};
use nexacore_types::{
    error::{CapabilityErrorKind, NexaCoreError, Result},
    identity::CapabilityId,
    wire,
};
use serde::{Deserialize, Serialize};

/// The only CRL wire-format version this crate understands.
///
/// [`SignedCrl::verify`] rejects any other value: a newer format we
/// cannot parse must be treated as untrusted, not silently accepted.
pub const CRL_FORMAT_VERSION: u32 = 1;

// =============================================================================
// CrlBody
// =============================================================================

/// The signed body of a Capability Revocation List.
///
/// Field order is the wire order. Do not reorder without a
/// `version` / wire-format bump.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CrlBody {
    /// Wire-format version. See [`CRL_FORMAT_VERSION`].
    pub version: u32,

    /// Public key of the issuer. The [`SignedCrl`] signature verifies
    /// under this key. Embedding it keeps the CRL self-contained, matching
    /// [`crate::token::TokenPayload::issuer`].
    pub issuer: nexacore_crypto::signing::NexaCoreVerifyingKey,

    /// Issuance instant (Unix seconds). Inclusive lower bound of the
    /// freshness envelope.
    pub issued_at: u64,

    /// The instant by which a fresher CRL is expected (Unix seconds).
    /// Consumers treat a CRL past this instant as stale (policy lives in
    /// WS10-06.9; this module only carries the field).
    pub next_update: u64,

    /// The revoked capability identifiers.
    pub revoked: Vec<CapabilityId>,
}

impl CrlBody {
    /// Encode this body into the canonical byte representation used as
    /// the signature pre-image.
    ///
    /// # Errors
    ///
    /// [`CapabilityErrorKind::MalformedToken`] on encoding failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        wire::encode_canonical(self).map_err(|_| {
            NexaCoreError::capability(
                CapabilityErrorKind::MalformedToken,
                "crl::canonical_bytes::encode",
            )
        })
    }

    /// Returns `true` iff `id` appears in this list's revoked set.
    #[must_use]
    pub fn is_revoked(&self, id: &CapabilityId) -> bool {
        self.revoked.iter().any(|r| r == id)
    }
}

// =============================================================================
// SignedCrl
// =============================================================================

/// A signed Capability Revocation List: body + Ed25519 signature.
///
/// Construct via [`SignedCrl::sign`]. Validate via [`SignedCrl::verify`]
/// before trusting [`SignedCrl::is_revoked`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedCrl {
    /// The signed body.
    pub body: CrlBody,
    /// Ed25519 signature over the canonical encoding of `body`.
    pub signature: NexaCoreSignature,
}

impl SignedCrl {
    /// Sign a CRL under `issuer_key`.
    ///
    /// The issuer public key is derived from `issuer_key` and embedded in
    /// the body, so the returned CRL verifies without any out-of-band key
    /// lookup. The body is stamped with [`CRL_FORMAT_VERSION`].
    ///
    /// # Errors
    ///
    /// [`CapabilityErrorKind::MalformedToken`] if canonical encoding of
    /// the body fails.
    pub fn sign(
        issuer_key: &NexaCoreSigningKey,
        issued_at: u64,
        next_update: u64,
        revoked: Vec<CapabilityId>,
    ) -> Result<Self> {
        let body = CrlBody {
            version: CRL_FORMAT_VERSION,
            issuer: issuer_key.verifying_key(),
            issued_at,
            next_update,
            revoked,
        };
        let bytes = body.canonical_bytes()?;
        let signature = issuer_key.sign(&bytes);
        Ok(Self { body, signature })
    }

    /// Verify the CRL: supported version AND signature under the embedded
    /// issuer key.
    ///
    /// Fail-closed: an unknown `version` is rejected before the signature
    /// is even checked, because a format we cannot fully parse must not be
    /// trusted.
    ///
    /// # Errors
    ///
    /// * [`CapabilityErrorKind::MalformedToken`] if `version` is not
    ///   [`CRL_FORMAT_VERSION`], or if the body cannot be re-encoded.
    /// * [`CapabilityErrorKind::InvalidSignature`] if the signature does
    ///   not verify under the embedded issuer key.
    pub fn verify(&self) -> Result<()> {
        if self.body.version != CRL_FORMAT_VERSION {
            return Err(NexaCoreError::capability(
                CapabilityErrorKind::MalformedToken,
                "crl::verify::unsupported_version",
            ));
        }
        let bytes = self.body.canonical_bytes()?;
        self.body
            .issuer
            .verify(&bytes, &self.signature)
            .map_err(|_| {
                NexaCoreError::capability(
                    CapabilityErrorKind::InvalidSignature,
                    "crl::verify::signature",
                )
            })
    }

    /// Encode the whole signed CRL to canonical bytes for transport.
    ///
    /// # Errors
    ///
    /// [`CapabilityErrorKind::MalformedToken`] on encoding failure.
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode_canonical(self).map_err(|_| {
            NexaCoreError::capability(CapabilityErrorKind::MalformedToken, "crl::encode")
        })
    }

    /// Decode a signed CRL from canonical bytes.
    ///
    /// Fail-closed: malformed or truncated input, or input carrying
    /// trailing bytes past the canonical encoding, is rejected. Decoding
    /// does NOT verify the signature — call [`SignedCrl::verify`] next.
    ///
    /// # Errors
    ///
    /// [`CapabilityErrorKind::MalformedToken`] if the bytes are not a
    /// valid canonical `SignedCrl` encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        wire::decode_canonical(bytes).map_err(|_| {
            NexaCoreError::capability(CapabilityErrorKind::MalformedToken, "crl::decode")
        })
    }

    /// Returns `true` iff `id` is revoked by this list.
    ///
    /// Callers MUST have validated the CRL via [`SignedCrl::verify`]
    /// first; this method trusts `body` as-is.
    #[must_use]
    pub fn is_revoked(&self, id: &CapabilityId) -> bool {
        self.body.is_revoked(id)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn id(b: u8) -> CapabilityId {
        CapabilityId::from_bytes([b; 16])
    }

    fn kind(err: &NexaCoreError) -> CapabilityErrorKind {
        match err {
            NexaCoreError::Capability { kind, .. } => *kind,
            _ => panic!("expected Capability error, got {err:?}"),
        }
    }

    fn sample_crl() -> (NexaCoreSigningKey, SignedCrl) {
        let sk = NexaCoreSigningKey::generate();
        let crl = SignedCrl::sign(&sk, 1_000, 1_900, vec![id(1), id(2), id(3)]).unwrap();
        (sk, crl)
    }

    #[test]
    fn encode_decode_round_trip() {
        let (_sk, crl) = sample_crl();
        let bytes = crl.encode().unwrap();
        let decoded = SignedCrl::decode(&bytes).unwrap();
        assert_eq!(decoded, crl);
    }

    #[test]
    fn signature_verifies_after_round_trip() {
        let (_sk, crl) = sample_crl();
        let decoded = SignedCrl::decode(&crl.encode().unwrap()).unwrap();
        decoded.verify().expect("round-tripped CRL must verify");
    }

    #[test]
    fn revoked_id_is_found_non_revoked_is_not() {
        let (_sk, crl) = sample_crl();
        assert!(crl.is_revoked(&id(1)));
        assert!(crl.is_revoked(&id(3)));
        assert!(!crl.is_revoked(&id(9)));
    }

    #[test]
    fn tampered_body_breaks_signature() {
        let (_sk, mut crl) = sample_crl();
        // Add a revocation after signing: the signature was computed over
        // the original revoked set, so verification must now fail.
        crl.body.revoked.push(id(42));
        let err = crl.verify().unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::InvalidSignature);
    }

    #[test]
    fn tampered_issued_at_breaks_signature() {
        let (_sk, mut crl) = sample_crl();
        crl.body.issued_at += 1;
        let err = crl.verify().unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::InvalidSignature);
    }

    #[test]
    fn wrong_issuer_key_does_not_verify() {
        // A signature made by one key must not verify against a body that
        // claims a different issuer.
        let (_sk, mut crl) = sample_crl();
        let other = NexaCoreSigningKey::generate();
        crl.body.issuer = other.verifying_key();
        let err = crl.verify().unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::InvalidSignature);
    }

    #[test]
    fn unsupported_version_rejected_fail_closed() {
        let (_sk, mut crl) = sample_crl();
        crl.body.version = CRL_FORMAT_VERSION + 1;
        let err = crl.verify().unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::MalformedToken);
    }

    #[test]
    fn truncated_input_rejected() {
        let (_sk, crl) = sample_crl();
        let bytes = crl.encode().unwrap();
        // Chop the last byte: a truncated CRL must not decode.
        let truncated = &bytes[..bytes.len() - 1];
        let err = SignedCrl::decode(truncated).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::MalformedToken);
    }

    #[test]
    fn trailing_bytes_rejected() {
        let (_sk, crl) = sample_crl();
        let mut bytes = crl.encode().unwrap();
        bytes.push(0x00); // canonical encoding forbids trailing data
        let err = SignedCrl::decode(&bytes).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::MalformedToken);
    }

    #[test]
    fn empty_input_rejected() {
        let err = SignedCrl::decode(&[]).unwrap_err();
        assert_eq!(kind(&err), CapabilityErrorKind::MalformedToken);
    }

    #[test]
    fn empty_revocation_list_verifies_and_revokes_nothing() {
        let sk = NexaCoreSigningKey::generate();
        let crl = SignedCrl::sign(&sk, 1_000, 1_900, vec![]).unwrap();
        crl.verify()
            .expect("empty CRL is still a valid, signed CRL");
        assert!(!crl.is_revoked(&id(1)));
    }
}

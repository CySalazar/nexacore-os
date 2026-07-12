//! Mutual authentication of mesh node identities (WS6-03.3).
//!
//! This is the concrete cryptography behind invariant **I1** (mutual
//! authentication) of the mesh handshake: each party signs the running handshake
//! transcript with its static ED25519 identity key, and the peer verifies that
//! signature against the identity key bound to the peer's TEE attestation. The
//! boolean result feeds the `signature_verified` gate of the handshake state
//! machine ([`crate::handshake_fsm`], WS6-03.1).
//!
//! No cryptographic primitive is implemented here. Signatures use
//! `nexacore-crypto`'s [`NexaCoreVerifyingKey::verify`], which is
//! `ed25519-dalek`'s `verify_strict` (rejects malleable / non-canonical `S`,
//! spec §4.4). The transcript hash uses the mandated domain-separated BLAKE3
//! ([`nexacore_crypto::hash::domain_separated_hash`]) under the
//! [`TRANSCRIPT_DOMAIN`] separator — raw hashing is forbidden by code review.
//! This module remains subject to the WS10-03 crypto review before production.

use std::vec::Vec;

use nexacore_crypto::{
    hash::domain_separated_hash,
    signing::{
        NexaCoreSignature, NexaCoreSigningKey, NexaCoreVerifyingKey, SIGNATURE_LEN,
        SIGNING_KEY_LEN, VERIFYING_KEY_LEN,
    },
};

/// The hash domain separator for the handshake transcript (spec §1: `H(...)` is
/// BLAKE3 under `"NexaCore-PROTO-v0.2/handshake"`).
pub const TRANSCRIPT_DOMAIN: &str = "NexaCore-PROTO-v0.2/handshake";

/// A signed transcript hash — the 64-byte ED25519 signature carried on the wire.
pub type TranscriptSignature = [u8; SIGNATURE_LEN];

/// Compute the handshake transcript hash `H(part_0 || part_1 || …)` (spec §3).
///
/// Uses the mandated domain-separated BLAKE3 construction under
/// [`TRANSCRIPT_DOMAIN`]; the parts are concatenated in order (`||`).
#[must_use]
pub fn transcript_hash(parts: &[&[u8]]) -> [u8; 32] {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut buf = Vec::with_capacity(total);
    for p in parts {
        buf.extend_from_slice(p);
    }
    domain_separated_hash(TRANSCRIPT_DOMAIN, &buf)
}

/// A node's static ED25519 identity, including the secret key (WS6-03.3).
///
/// The secret is held only inside `nexacore-crypto`'s zeroize-on-drop
/// [`NexaCoreSigningKey`]; per the spec, static keys are wiped from the QUIC
/// handler's working memory after the handshake and re-accessed only through the
/// TEE sealed-key API.
pub struct NodeIdentity {
    signing: NexaCoreSigningKey,
}

impl NodeIdentity {
    /// Generate a fresh node identity.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: NexaCoreSigningKey::generate(),
        }
    }

    /// Build an identity from a 32-byte ED25519 secret seed (e.g. from the TEE
    /// sealed-key API).
    #[must_use]
    pub fn from_secret(secret: [u8; SIGNING_KEY_LEN]) -> Self {
        Self {
            signing: NexaCoreSigningKey::from_bytes(secret),
        }
    }

    /// The public identity to publish (bound to this node's TEE attestation).
    #[must_use]
    pub fn public(&self) -> NodePublicIdentity {
        NodePublicIdentity {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Sign a handshake transcript hash with this node's static key (I1).
    #[must_use]
    pub fn sign_transcript(&self, transcript: &[u8; 32]) -> TranscriptSignature {
        self.signing.sign(transcript).to_bytes()
    }
}

/// A node's static ED25519 public identity (WS6-03.3).
#[derive(Clone)]
pub struct NodePublicIdentity {
    verifying: NexaCoreVerifyingKey,
}

impl NodePublicIdentity {
    /// Parse a 32-byte ED25519 public identity, or `None` if it is not a valid
    /// point.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Option<Self> {
        NexaCoreVerifyingKey::from_bytes(bytes)
            .ok()
            .map(|verifying| Self { verifying })
    }

    /// The 32-byte encoding of this public identity.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.verifying.as_bytes()
    }

    /// Verify a peer's transcript `signature` over `transcript` (I1 / §4.4).
    ///
    /// Uses `ed25519-dalek`'s `verify_strict`, so a malleable or non-canonical
    /// signature is rejected. Returns `true` only on a strictly-valid signature.
    #[must_use]
    pub fn verify_transcript(
        &self,
        transcript: &[u8; 32],
        signature: &TranscriptSignature,
    ) -> bool {
        let sig = NexaCoreSignature::from_bytes(*signature);
        self.verifying.verify(transcript, &sig).is_ok()
    }
}

/// Authenticate a peer over a handshake transcript (WS6-03.3): the peer's
/// `signature` must verify against `peer` for `transcript`.
///
/// This is the value the handshake state machine consumes as
/// `signature_verified` (WS6-03.1). Kept as a named function so the mutual-auth
/// check is a single, auditable call site.
#[must_use]
pub fn authenticate_peer(
    peer: &NodePublicIdentity,
    transcript: &[u8; 32],
    signature: &TranscriptSignature,
) -> bool {
    peer.verify_transcript(transcript, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_hash_is_deterministic_and_order_sensitive() {
        let base = transcript_hash(&[b"proto", b"epk", b"nonce"]);
        let repeat = transcript_hash(&[b"proto", b"epk", b"nonce"]);
        assert_eq!(base, repeat); // deterministic
        // Same concatenated bytes → same hash (|| is concatenation).
        let regrouped = transcript_hash(&[b"pr", b"otoepknonce"]);
        let joined = transcript_hash(&[b"protoepknonce"]);
        assert_eq!(regrouped, joined);
        // Different content → different hash.
        let altered = transcript_hash(&[b"proto", b"epk", b"NONCE"]);
        assert_ne!(base, altered);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = NodeIdentity::generate();
        let public = id.public();
        let transcript = transcript_hash(&[b"NexaCore-PROTO-v0.2", b"epk_A", b"nonce_A"]);
        let sig = id.sign_transcript(&transcript);
        assert!(public.verify_transcript(&transcript, &sig));
        assert!(authenticate_peer(&public, &transcript, &sig));
    }

    #[test]
    fn a_different_key_rejects_the_signature() {
        let signer = NodeIdentity::generate();
        let other = NodeIdentity::generate().public();
        let transcript = transcript_hash(&[b"t"]);
        let sig = signer.sign_transcript(&transcript);
        // The wrong identity must not authenticate the signature.
        assert!(!other.verify_transcript(&transcript, &sig));
    }

    #[test]
    fn a_tampered_transcript_is_rejected() {
        let id = NodeIdentity::generate();
        let public = id.public();
        let transcript = transcript_hash(&[b"original"]);
        let sig = id.sign_transcript(&transcript);
        let tampered = transcript_hash(&[b"tampered"]);
        assert!(!public.verify_transcript(&tampered, &sig));
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let id = NodeIdentity::generate();
        let public = id.public();
        let transcript = transcript_hash(&[b"t"]);
        let mut sig = id.sign_transcript(&transcript);
        sig[0] ^= 0x01; // flip a bit
        assert!(!public.verify_transcript(&transcript, &sig));
    }

    #[test]
    fn mutual_authentication_in_both_directions() {
        // A and B each sign their side's transcript; each verifies the other.
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let a_pub = a.public();
        let b_pub = b.public();

        let ta = transcript_hash(&[b"m1", &a_pub.to_bytes()]);
        let tb = transcript_hash(&[b"m2", &b_pub.to_bytes()]);
        let sig_a = a.sign_transcript(&ta);
        let sig_b = b.sign_transcript(&tb);

        // B authenticates A, A authenticates B.
        assert!(authenticate_peer(&a_pub, &ta, &sig_a));
        assert!(authenticate_peer(&b_pub, &tb, &sig_b));
        // Cross-use (A's sig verified against B's transcript) must fail.
        assert!(!authenticate_peer(&a_pub, &tb, &sig_a));
    }

    #[test]
    fn public_identity_serialises_roundtrip() {
        let id = NodeIdentity::generate();
        let bytes = id.public().to_bytes();
        let reparsed = NodePublicIdentity::from_bytes(&bytes);
        assert!(reparsed.is_some());
        if let Some(pk) = reparsed {
            assert_eq!(pk.to_bytes(), bytes);
        }
    }

    #[test]
    fn identity_from_fixed_secret_is_stable() {
        let secret = [42u8; SIGNING_KEY_LEN];
        let a = NodeIdentity::from_secret(secret);
        let b = NodeIdentity::from_secret(secret);
        // Same secret → same public identity.
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
        // And a signature from one verifies under the other's public key.
        let t = transcript_hash(&[b"x"]);
        assert!(b.public().verify_transcript(&t, &a.sign_transcript(&t)));
    }
}

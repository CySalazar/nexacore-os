//! Canonical wire messages and transcript stitching for the mesh handshake
//! (WS6-03.8).
//!
//! This is the integration layer that ties the per-invariant handshake bricks
//! (`handshake_auth` I1, `handshake_kex` I2, `handshake_attest` I3,
//! `handshake_measurement` I8, `handshake_version` I7) into the concrete
//! `m1`/`m2`/`m3` wire flow of `docs/protocol/handshake.md` §3.
//!
//! ## Two byte layouts, deliberately distinct
//!
//! Mesh messages travel on the wire under the crate's canonical encoding —
//! **postcard 1.0** via [`nexacore_types::wire::encode_canonical`], per
//! `NCIP-Serde-004` (the [`crate::transport`] docstring is authoritative). The
//! *transcript*, by contrast, is hashed over the exact field concatenation the
//! spec mandates (§3/§6). Keeping the two separate matters: the transcript is
//! the pre-image every signature and every quote-nonce binds to, so its byte
//! order must be fixed and agreed independently of how the message is framed.
//!
//! ## Interop-vector scope
//!
//! No cross-vendor implementation exists yet, so authoritative *interop* vectors
//! (this implementation's bytes checked against a second, independent one)
//! cannot be produced here — that validation folds into the 2-node lab handshake
//! (WS6-03.10, rig-deferred). What this module delivers is the automatable core:
//! the postcard-canonical message types, the spec-defined transcript chain, and
//! round-trip / determinism / field-binding tests that *are* the spec-derived
//! vectors a second implementation will validate against. No cryptographic
//! primitive is implemented here; the transcript hash is the mandated
//! domain-separated BLAKE3 (via [`crate::handshake_auth::transcript_hash`]).
//! This module remains subject to the WS10-03 crypto review.

use std::vec::Vec;

use nexacore_tee::Quote;
use nexacore_types::{error::Result, version::ProtocolVersion, wire::encode_canonical};
use serde::{Deserialize, Serialize};

use crate::handshake_auth::transcript_hash;

/// The signed payload fields of message 1 (`A → B`, §3.1).
///
/// `Sig_A` is *not* part of the payload — it signs
/// [`transcript_after_m1`] of this payload and travels alongside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M1Payload {
    /// Pinned protocol version (I7).
    pub proto_version: ProtocolVersion,
    /// Initiator ephemeral X25519 public key (I2).
    pub epk_a: [u8; 32],
    /// Initiator freshness nonce.
    pub nonce_a: [u8; 32],
    /// Initiator TEE attestation quote (I3).
    pub quote_a: Quote,
}

/// The signed payload fields of message 2 (`B → A`, §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M2Payload {
    /// Responder ephemeral X25519 public key (I2).
    pub epk_b: [u8; 32],
    /// Responder freshness nonce.
    pub nonce_b: [u8; 32],
    /// Responder TEE attestation quote (I3).
    pub quote_b: Quote,
    /// BLAKE3 Merkle root of the responder's active measurement allowlist (I8).
    pub measurement_root: [u8; 32],
}

/// The signed payload fields of message 3 (`A → B`, §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M3Payload {
    /// BLAKE3 hash of the intersection of both allowlists (I8, §3.3).
    pub measurement_ack: [u8; 32],
    /// Initiator's declared compliance-proof scheme(s) (§4.6).
    pub compliance_capabilities: Vec<u8>,
}

/// The canonical byte encoding of a protocol version used inside the transcript:
/// `major_le(2) || minor_le(2)`.
///
/// This is the same compact encoding [`crate::handshake_version`] commits to,
/// chosen over the spec §1 "16-byte string" field (whose 19-character value is
/// self-inconsistent) so the version bytes are unambiguous across the crate.
fn proto_version_bytes(version: ProtocolVersion) -> [u8; 4] {
    let mut bytes = [0u8; 4];
    let (lo, hi) = bytes.split_at_mut(2);
    lo.copy_from_slice(&version.major.to_le_bytes());
    hi.copy_from_slice(&version.minor.to_le_bytes());
    bytes
}

/// Compute `transcript_after_m1_payload = H(proto_version || epk_A || nonce_A ||
/// Quote_A)` (§3.1) over the canonical field concatenation.
///
/// `Quote_A` is folded in as its canonical postcard encoding, so the opaque
/// vendor quote contributes a deterministic byte string to the transcript.
///
/// # Errors
///
/// Returns a wire error if the quote cannot be canonically encoded (in practice
/// a bug or out-of-memory, since every `Serialize` impl is total).
pub fn transcript_after_m1(m1: &M1Payload) -> Result<[u8; 32]> {
    let version = proto_version_bytes(m1.proto_version);
    let quote = encode_canonical(&m1.quote_a)?;
    Ok(transcript_hash(&[&version, &m1.epk_a, &m1.nonce_a, &quote]))
}

/// Compute `transcript_after_m2_payload = H(transcript_after_m1 || epk_B ||
/// nonce_B || Quote_B || measurement_root)` (§3.2).
///
/// # Errors
///
/// Returns a wire error if the quote cannot be canonically encoded.
pub fn transcript_after_m2(transcript_after_m1: &[u8; 32], m2: &M2Payload) -> Result<[u8; 32]> {
    let quote = encode_canonical(&m2.quote_b)?;
    Ok(transcript_hash(&[
        transcript_after_m1,
        &m2.epk_b,
        &m2.nonce_b,
        &quote,
        &m2.measurement_root,
    ]))
}

/// Compute `transcript_after_m3_payload = H(transcript_after_m2 ||
/// measurement_ack || compliance_capabilities)` (§3.3).
#[must_use]
pub fn transcript_after_m3(transcript_after_m2: &[u8; 32], m3: &M3Payload) -> [u8; 32] {
    transcript_hash(&[
        transcript_after_m2,
        &m3.measurement_ack,
        &m3.compliance_capabilities,
    ])
}

#[cfg(test)]
mod tests {
    use nexacore_tee::{Measurement, Nonce, QuoteVersion, traits::TeeFamily};
    use nexacore_types::{version::PROTOCOL_VERSION_V0_2, wire::decode_canonical};

    use super::*;

    fn quote(seed: u8) -> Quote {
        Quote {
            version: QuoteVersion::V0_1,
            family: TeeFamily::Mock,
            measurement: Measurement([seed; 48]),
            nonce: Nonce([seed; 32]),
            report_data: Some([seed; 32]),
            body: std::vec![seed; 8],
        }
    }

    fn m1() -> M1Payload {
        M1Payload {
            proto_version: PROTOCOL_VERSION_V0_2,
            epk_a: [1u8; 32],
            nonce_a: [2u8; 32],
            quote_a: quote(0x11),
        }
    }

    fn m2() -> M2Payload {
        M2Payload {
            epk_b: [3u8; 32],
            nonce_b: [4u8; 32],
            quote_b: quote(0x22),
            measurement_root: [5u8; 32],
        }
    }

    fn m3() -> M3Payload {
        M3Payload {
            measurement_ack: [6u8; 32],
            compliance_capabilities: std::vec![b's', b'i', b'g', b'-', b'v', b'1'],
        }
    }

    #[test]
    fn m1_payload_round_trips_under_canonical_encoding() {
        let original = m1();
        let encoded = encode_canonical(&original);
        assert!(encoded.is_ok());
        let Ok(bytes) = encoded else { return };
        let decoded: Result<M1Payload> = decode_canonical(&bytes);
        assert_eq!(decoded.ok(), Some(original));
    }

    #[test]
    fn m2_payload_round_trips_under_canonical_encoding() {
        let original = m2();
        let encoded = encode_canonical(&original);
        assert!(encoded.is_ok());
        let Ok(bytes) = encoded else { return };
        let decoded: Result<M2Payload> = decode_canonical(&bytes);
        assert_eq!(decoded.ok(), Some(original));
    }

    #[test]
    fn m3_payload_round_trips_under_canonical_encoding() {
        let original = m3();
        let encoded = encode_canonical(&original);
        assert!(encoded.is_ok());
        let Ok(bytes) = encoded else { return };
        let decoded: Result<M3Payload> = decode_canonical(&bytes);
        assert_eq!(decoded.ok(), Some(original));
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        // The golden-vector property: identical input → identical bytes.
        let a = encode_canonical(&m1()).ok();
        let b = encode_canonical(&m1()).ok();
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // Anti-smuggling: extra bytes past the encoding must not decode (they
        // could otherwise ride past a signature pre-image).
        let encoded = encode_canonical(&m1());
        assert!(encoded.is_ok());
        let Ok(mut bytes) = encoded else { return };
        bytes.push(0xFF);
        let decoded: Result<M1Payload> = decode_canonical(&bytes);
        assert!(decoded.is_err());
    }

    #[test]
    fn transcript_chain_is_deterministic() {
        let t1_a = transcript_after_m1(&m1()).ok();
        let t1_b = transcript_after_m1(&m1()).ok();
        assert_eq!(t1_a, t1_b);
        assert!(t1_a.is_some());
    }

    #[test]
    fn transcript_after_m1_binds_every_field() {
        let base_result = transcript_after_m1(&m1());
        assert!(base_result.is_ok());
        let Ok(base) = base_result else { return };

        // Different epk → different transcript.
        let mut altered = m1();
        altered.epk_a = [9u8; 32];
        assert_ne!(Some(base), transcript_after_m1(&altered).ok());

        // Different nonce → different transcript.
        let mut altered = m1();
        altered.nonce_a = [9u8; 32];
        assert_ne!(Some(base), transcript_after_m1(&altered).ok());

        // Different quote → different transcript.
        let mut altered = m1();
        altered.quote_a = quote(0x99);
        assert_ne!(Some(base), transcript_after_m1(&altered).ok());
    }

    #[test]
    fn transcript_chains_forward_through_m2_and_m3() {
        let t1_result = transcript_after_m1(&m1());
        assert!(t1_result.is_ok());
        let Ok(t1) = t1_result else { return };
        // A different m1 transcript yields a different m2 transcript, even with
        // an identical m2 — the chain carries history forward.
        let t2_result = transcript_after_m2(&t1, &m2());
        assert!(t2_result.is_ok());
        let Ok(t2) = t2_result else { return };
        let other = transcript_after_m2(&[0u8; 32], &m2()).ok();
        assert_ne!(Some(t2), other);

        // m3 likewise depends on the m2 transcript.
        let t3 = transcript_after_m3(&t2, &m3());
        let t3_other = transcript_after_m3(&[0u8; 32], &m3());
        assert_ne!(t3, t3_other);
    }

    #[test]
    fn transcript_after_m2_binds_the_measurement_root() {
        let t1_result = transcript_after_m1(&m1());
        assert!(t1_result.is_ok());
        let Ok(t1) = t1_result else { return };
        let base_result = transcript_after_m2(&t1, &m2());
        assert!(base_result.is_ok());
        let Ok(base) = base_result else { return };
        let mut altered = m2();
        altered.measurement_root = [0xEEu8; 32];
        assert_ne!(Some(base), transcript_after_m2(&t1, &altered).ok());
    }

    #[test]
    fn transcript_after_m3_binds_the_ack_and_capabilities() {
        let base = transcript_after_m3(&[7u8; 32], &m3());

        let mut altered = m3();
        altered.measurement_ack = [0xEEu8; 32];
        assert_ne!(base, transcript_after_m3(&[7u8; 32], &altered));

        let mut altered = m3();
        altered.compliance_capabilities = std::vec![b'x'];
        assert_ne!(base, transcript_after_m3(&[7u8; 32], &altered));
    }
}

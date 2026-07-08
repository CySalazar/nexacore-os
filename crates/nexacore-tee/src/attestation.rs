//! Attestation primitives: [`Quote`], [`Measurement`], [`Nonce`], and the
//! [`QuoteVersion`] discriminant.
//!
//! These types are vendor-neutral. The concrete TDX or SEV-SNP byte layout
//! is hidden behind the opaque `body` field of [`Quote`] and is parsed by
//! the relevant backend. Consumers depend only on the public methods of
//! these types.

use alloc::vec::Vec;

use crate::traits::TeeFamily;

// -----------------------------------------------------------------------------
// Measurement
// -----------------------------------------------------------------------------

/// A TEE measurement value (e.g., Intel TDX MRTD, AMD SEV-SNP `MEASUREMENT`).
///
/// 48 bytes is the cross-vendor common denominator. Intel TDX MRTD is 48
/// bytes (SHA-384). AMD SEV-SNP `MEASUREMENT` is 48 bytes (SHA-384).
/// Apple Secure Enclave and `ARMv9` CCA both use shorter measurements
/// (SHA-256, 32 bytes); when those backends land, the 16 trailing bytes
/// are zero-padded with a discriminator in the high byte.
///
/// **Equality and hashing** are constant-time for cryptographic safety.
/// (Currently `PartialEq` derives `==` on `[u8; 48]`, which the compiler
/// usually lowers to `memcmp` — short-circuiting. A constant-time
/// implementation will land before P5.2 when this type is used in
/// signature-comparison code paths.)
///
/// `Serialize` / `Deserialize` are implemented manually because `serde`
/// only auto-derives these traits for arrays up to `[T; 32]`. The
/// implementation emits the 48 bytes as a fixed-length byte sequence
/// and rejects deserialization inputs of any other length, preserving
/// the type's invariant on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Measurement(pub [u8; 48]);

impl serde::Serialize for Measurement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Measurement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MeasurementVisitor;

        impl<'de> serde::de::Visitor<'de> for MeasurementVisitor {
            type Value = Measurement;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a 48-byte sequence (TEE measurement)")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 48 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut buf = [0u8; 48];
                buf.copy_from_slice(v);
                Ok(Measurement(buf))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut buf = [0u8; 48];
                for (idx, slot) in buf.iter_mut().enumerate() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| serde::de::Error::invalid_length(idx, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(49, &self));
                }
                Ok(Measurement(buf))
            }
        }

        deserializer.deserialize_bytes(MeasurementVisitor)
    }
}

impl Measurement {
    /// Returns a measurement of all-zero bytes. Useful for testing only —
    /// the real measurement is computed by the TEE firmware over the
    /// loaded binary. An all-zero measurement MUST be rejected by any
    /// production verifier.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 48])
    }

    /// Borrows the underlying byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

// -----------------------------------------------------------------------------
// Nonce
// -----------------------------------------------------------------------------

/// A 32-byte (256-bit) random nonce used for quote freshness binding.
///
/// Consumers (typically `nexacore-mesh`) generate a fresh `Nonce` per
/// handshake, send it to the peer in `m1`, and pass it through to
/// [`crate::TeeBackend::verify_quote`] as `expected_nonce` when the
/// peer's quote arrives.
///
/// 32 bytes is enough entropy to make collision attacks computationally
/// infeasible while keeping the on-wire size small.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Nonce(pub [u8; 32]);

impl Nonce {
    /// Returns an all-zero nonce. Mock backend uses this as a stub; any
    /// production verifier MUST reject quotes with an all-zero nonce.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Borrows the underlying byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// -----------------------------------------------------------------------------
// QuoteVersion
// -----------------------------------------------------------------------------

/// Versioning discriminant for [`Quote`].
///
/// Adding a variant requires a Standards-Track NCIP. The variant set tracks
/// the project's *protocol* version, not the underlying TEE vendor's
/// firmware version.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum QuoteVersion {
    /// v0.1 baseline. Layout TBD per-family in the backend implementation.
    V0_1 = 1,
}

// -----------------------------------------------------------------------------
// Quote
// -----------------------------------------------------------------------------

/// A vendor-neutral wrapper around a TEE attestation report.
///
/// The internal `body` byte buffer carries the raw vendor-specific quote
/// format (Intel TDX quote v4, AMD SEV-SNP attestation report v2, …).
/// Parsing that buffer is the responsibility of the backend that emitted
/// it; cross-vendor code only inspects the public fields.
///
/// `measurement` and `nonce` are duplicated in the wrapper for cheap
/// access without re-parsing the body. **Trust note**: these duplicated
/// fields are populated by the backend and MUST be consistent with the
/// signed body. A consumer that wishes to be safe against a malicious
/// peer MUST verify the duplicated fields by parsing the body itself
/// (the [`TeeBackend::verify_quote`](crate::traits::TeeBackend::verify_quote)
/// implementation does this).
///
/// The wrapper is `Clone`-able and `Serialize`/`Deserialize`-able so it
/// flows through `postcard` on the wire (per `NCIP-Serde-004`) and
/// through `serde_json` in audit records.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Quote {
    /// Protocol version of this Quote envelope.
    pub version: QuoteVersion,
    /// TEE family that produced the quote. Routing key for backend
    /// dispatch on the verifier.
    pub family: TeeFamily,
    /// The TEE measurement (MRTD / MEASUREMENT / equivalent) committed
    /// by this quote. Verifier cross-checks against the signed body
    /// during verification.
    pub measurement: Measurement,
    /// The nonce the attestor was challenged with. Verifier MUST
    /// confirm this matches the nonce it sent.
    pub nonce: Nonce,
    /// Optional report-data committed in the signed body (e.g., transcript
    /// hash for mesh handshake). Up to 32 bytes per current backend
    /// support.
    pub report_data: Option<[u8; 32]>,
    /// The vendor-specific quote body. Opaque to non-backend code.
    /// Length-prefixed on the wire (4-byte big-endian u32) so a
    /// downstream consumer can skip a quote whose family it does not
    /// support without parsing.
    pub body: Vec<u8>,
}

impl Quote {
    /// Convenience accessor: returns the byte length of the opaque body.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn zero_measurement_is_all_zero() {
        let m = Measurement::zero();
        assert!(m.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn zero_nonce_is_all_zero() {
        let n = Nonce::zero();
        assert!(n.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn measurement_serde_round_trip_via_wire_helper() {
        let mut bytes = [0u8; 48];
        for (i, slot) in bytes.iter_mut().enumerate() {
            // i ∈ 0..48 fits in a u8.
            *slot = u8::try_from(i).expect("i bounded by array length");
        }
        let m = Measurement(bytes);
        let encoded = nexacore_types::wire::encode_canonical(&m).expect("encode Measurement");
        let decoded: Measurement =
            nexacore_types::wire::decode_canonical(&encoded).expect("decode Measurement");
        assert_eq!(m, decoded);
    }

    #[test]
    fn measurement_deserialize_rejects_wrong_length() {
        // Encode a 47-byte byte sequence via the canonical wire helper,
        // then try to decode it as `Measurement`. The custom
        // `Measurement` deserializer enforces a 48-byte length, so the
        // shorter input must be rejected — either at decode time (the
        // visitor returns an error) or at the trailing-bytes guard
        // (the wire helper enforces no-trailing-data canonically).
        let too_short: alloc::vec::Vec<u8> = alloc::vec![0u8; 47];
        let encoded = nexacore_types::wire::encode_canonical(&too_short).expect("encode short vec");
        let result: nexacore_types::error::Result<Measurement> =
            nexacore_types::wire::decode_canonical(&encoded);
        assert!(result.is_err(), "wrong-length input must be rejected");
    }

    #[test]
    fn quote_shape_unit() {
        // Shape assertion only; the actual round-trip lives in
        // `tests/mock_integration.rs` to exercise the public path.
        let q = Quote {
            version: QuoteVersion::V0_1,
            family: TeeFamily::Mock,
            measurement: Measurement::zero(),
            nonce: Nonce::zero(),
            report_data: None,
            body: alloc::vec![0xAB; 16],
        };
        assert_eq!(q.body_len(), 16);
        assert_eq!(q.family, TeeFamily::Mock);
    }
}

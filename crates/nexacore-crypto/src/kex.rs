//! Key exchange.
//!
//! Implements `X25519` Elliptic Curve Diffie-Hellman per RFC 7748.
//!
//! # Hybrid post-quantum migration (Phase 4)
//!
//! Phase 4 introduces a hybrid `X25519 + Kyber-768` key exchange that
//! combines classical and post-quantum security in a single shared
//! secret. The wire format will allow a peer to advertise hybrid
//! support; legacy peers continue to do `X25519` only. The Phase 4
//! API will be additive (no breaking change) — see
//! `/ncips/ncip-crypto-002.md` (P3.3 in the backlog).

use core::fmt;

use nexacore_types::error::{CryptoErrorKind, NexaCoreError, Result};
#[cfg(feature = "rng")]
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an `X25519` private/public key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of an `X25519` shared secret in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

// =============================================================================
// NexaCoreEphemeralSecret
// =============================================================================

/// Ephemeral `X25519` private scalar.
///
/// "Ephemeral" means: usable for exactly one Diffie-Hellman operation.
/// The scalar is consumed by [`NexaCoreEphemeralSecret::diffie_hellman`],
/// after which the value is dropped (and zeroized).
///
/// For long-lived static keys (e.g., a node's identity key), use
/// [`NexaCoreStaticSecret`] instead.
pub struct NexaCoreEphemeralSecret {
    // We use `ReusableSecret` from x25519-dalek (rather than the
    // single-use `EphemeralSecret`) so we can take `&self` in
    // `diffie_hellman` without consuming. The "ephemeral" semantics
    // are enforced at the API level by accepting only one DH per
    // value (the type is not `Clone`, so callers cannot duplicate it).
    inner: ReusableSecret,
}

impl NexaCoreEphemeralSecret {
    /// Generate a fresh ephemeral secret from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; bare-metal builds use a
    /// `from_bytes`-style construction with a kernel-provided
    /// seed instead (when one is needed at all — the kernel currently
    /// does not perform key exchange).
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn generate() -> Self {
        Self {
            inner: ReusableSecret::random_from_rng(OsRng),
        }
    }

    /// Compute the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> NexaCorePublicKey {
        NexaCorePublicKey {
            inner: PublicKey::from(&self.inner),
        }
    }

    /// Perform Diffie-Hellman with `peer` and return the shared
    /// secret. Consumes `self` to enforce one-time use.
    #[must_use]
    pub fn diffie_hellman(self, peer: &NexaCorePublicKey) -> NexaCoreSharedSecret {
        let s = self.inner.diffie_hellman(&peer.inner);
        NexaCoreSharedSecret {
            bytes: s.to_bytes(),
        }
    }
}

// We deliberately do not implement Debug printing the bytes.
impl fmt::Debug for NexaCoreEphemeralSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreEphemeralSecret(<redacted>)")
    }
}

// =============================================================================
// NexaCoreStaticSecret
// =============================================================================

/// Long-lived `X25519` private scalar.
///
/// Use for identity keys whose lifetime spans multiple sessions.
/// Cloning is allowed (a static key can fan out to many concurrent
/// handshakes) but every clone is `ZeroizeOnDrop`.
pub struct NexaCoreStaticSecret {
    inner: StaticSecret,
}

impl NexaCoreStaticSecret {
    /// Generate a fresh static secret from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature.
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn generate() -> Self {
        Self {
            inner: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Construct from raw bytes (deserialization path).
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            inner: StaticSecret::from(bytes),
        }
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Compute the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> NexaCorePublicKey {
        NexaCorePublicKey {
            inner: PublicKey::from(&self.inner),
        }
    }

    /// Perform Diffie-Hellman with `peer`. Does not consume `self` —
    /// a static key is reusable.
    #[must_use]
    pub fn diffie_hellman(&self, peer: &NexaCorePublicKey) -> NexaCoreSharedSecret {
        let s = self.inner.diffie_hellman(&peer.inner);
        NexaCoreSharedSecret {
            bytes: s.to_bytes(),
        }
    }
}

impl Clone for NexaCoreStaticSecret {
    fn clone(&self) -> Self {
        Self::from_bytes(self.as_bytes())
    }
}

impl fmt::Debug for NexaCoreStaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreStaticSecret(<redacted>)")
    }
}

// =============================================================================
// NexaCorePublicKey
// =============================================================================

/// `X25519` public key (32-byte Curve25519 u-coordinate).
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NexaCorePublicKey {
    inner: PublicKey,
}

impl NexaCorePublicKey {
    /// Construct from raw bytes.
    ///
    /// `X25519` accepts any 32-byte value — there is no validation
    /// step (unlike `Ed25519` point verification). This means you
    /// cannot get an error from this function; bad bytes simply
    /// produce a public key that yields a useless shared secret.
    /// Counterparties detect this via the higher-level handshake
    /// (e.g., MAC failure on the first encrypted message).
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            inner: PublicKey::from(bytes),
        }
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; KEY_LEN] {
        self.inner.to_bytes()
    }
}

impl PartialEq for NexaCorePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_bytes().ct_eq(other.inner.as_bytes()).into()
    }
}
impl Eq for NexaCorePublicKey {}

impl fmt::Debug for NexaCorePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.inner.to_bytes();
        write!(
            f,
            "NexaCorePublicKey({:02x}{:02x}{:02x}{:02x}…)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

// =============================================================================
// NexaCoreSharedSecret
// =============================================================================

/// 256-bit shared secret produced by Diffie-Hellman.
///
/// Should be passed through a KDF (typically `HKDF-SHA-256` from
/// [`crate::kdf`]) before being used as a symmetric key. Do not use
/// the raw bytes directly as an AEAD key — the bias on the LSB of the
/// X-coordinate makes raw use risky.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NexaCoreSharedSecret {
    bytes: [u8; SHARED_SECRET_LEN],
}

impl NexaCoreSharedSecret {
    /// Borrow the raw bytes. Avoid using this directly as a key — see
    /// type docs.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.bytes
    }

    /// Returns `true` iff this shared secret is the all-zero "trivial"
    /// secret produced by an attacker-supplied low-order public key.
    /// Honest peers should reject the handshake when this returns true.
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        let zero = [0u8; SHARED_SECRET_LEN];
        self.bytes.ct_eq(&zero).into()
    }
}

impl PartialEq for NexaCoreSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}
impl Eq for NexaCoreSharedSecret {}

impl fmt::Debug for NexaCoreSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreSharedSecret(<redacted>)")
    }
}

// =============================================================================
// Convenience helpers
// =============================================================================

/// Generate an ephemeral keypair `(secret, public)` in one call.
///
/// Convenience wrapper used by the mesh handshake. Equivalent to
/// `let s = NexaCoreEphemeralSecret::generate(); let p = s.public_key();`
/// then returning the pair.
///
/// Gated behind the `rng` feature.
#[cfg(feature = "rng")]
#[must_use]
pub fn generate_ephemeral() -> (NexaCoreEphemeralSecret, NexaCorePublicKey) {
    let secret = NexaCoreEphemeralSecret::generate();
    let public = secret.public_key();
    (secret, public)
}

/// Validate a peer public key against known low-order points and reject
/// trivially-attackable ones. Returns the key on success.
///
/// `X25519` is generally robust against low-order point attacks at the
/// shared-secret stage, but rejecting them at parse time gives a
/// clearer error to the upper layer than waiting for the all-zero
/// shared secret.
///
/// # Errors
///
/// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InvalidKey`]
/// if `bytes` matches one of the canonical low-order public keys per
/// RFC 7748 § 5.
pub fn validate_peer_public_key(bytes: [u8; KEY_LEN]) -> Result<NexaCorePublicKey> {
    // The canonical low-order points for Curve25519. Listed in many
    // references; see e.g. https://cr.yp.to/ecdh.html and the libsodium
    // implementation.
    const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
        // 0 (identity)
        [0u8; 32],
        // 1
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        // 325606250916557431795983626356110631294008115727848805560023387167927233504
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        // p - 1
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p + 1
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];
    for low in &LOW_ORDER_POINTS {
        if bool::from(bytes.ct_eq(low)) {
            return Err(NexaCoreError::crypto(
                CryptoErrorKind::InvalidKey,
                "kex::validate_peer_public_key::low_order",
            ));
        }
    }
    Ok(NexaCorePublicKey::from_bytes(bytes))
}

// =============================================================================
// Tests — RFC 7748 vectors + property + negative.
// =============================================================================

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // RFC 7748 § 6.1 — X25519 test vector.
    // Alice's private key clamped from 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    // Alice's public key 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    // Bob's private key clamped from 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
    // Bob's public key de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
    // Shared secret  4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

    fn parse_arr<const N: usize>(s: &str) -> [u8; N] {
        let v = hex::decode(s).unwrap();
        assert_eq!(v.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn rfc7748_pk_derivation_alice() {
        let sk = NexaCoreStaticSecret::from_bytes(parse_arr::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let expected =
            parse_arr::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(sk.public_key().as_bytes(), expected);
    }

    #[test]
    fn rfc7748_pk_derivation_bob() {
        let sk = NexaCoreStaticSecret::from_bytes(parse_arr::<32>(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        let expected =
            parse_arr::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(sk.public_key().as_bytes(), expected);
    }

    #[test]
    fn rfc7748_shared_secret() {
        let alice_sk = NexaCoreStaticSecret::from_bytes(parse_arr::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob_pk = NexaCorePublicKey::from_bytes(parse_arr::<32>(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        let s = alice_sk.diffie_hellman(&bob_pk);
        let expected =
            parse_arr::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(s.as_bytes(), &expected);
    }

    #[cfg(feature = "rng")]
    #[test]
    fn dh_is_symmetric() {
        let (a_sec, a_pub) = generate_ephemeral();
        let (b_sec, b_pub) = generate_ephemeral();
        let s_ab = a_sec.diffie_hellman(&b_pub);
        let s_ba = b_sec.diffie_hellman(&a_pub);
        assert_eq!(s_ab, s_ba);
    }

    #[test]
    fn low_order_zero_point_is_rejected() {
        let zero = [0u8; KEY_LEN];
        let err = validate_peer_public_key(zero).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => assert_eq!(kind, CryptoErrorKind::InvalidKey),
            _ => panic!("expected Crypto::InvalidKey"),
        }
    }

    #[cfg(feature = "rng")]
    #[test]
    fn random_public_key_passes_validation() {
        let (_, pk) = generate_ephemeral();
        let bytes = pk.as_bytes();
        let _ok = validate_peer_public_key(bytes).unwrap();
    }

    #[cfg(feature = "rng")]
    #[test]
    fn debug_does_not_leak_secret() {
        let s = NexaCoreEphemeralSecret::generate();
        let dbg = alloc::format!("{s:?}");
        assert!(dbg.contains("redacted"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn dh_symmetry_property(
            a_seed in proptest::array::uniform32(any::<u8>()),
            b_seed in proptest::array::uniform32(any::<u8>()),
        ) {
            let a_sk = NexaCoreStaticSecret::from_bytes(a_seed);
            let b_sk = NexaCoreStaticSecret::from_bytes(b_seed);
            let a_pk = a_sk.public_key();
            let b_pk = b_sk.public_key();
            let s_ab = a_sk.diffie_hellman(&b_pk);
            let s_ba = b_sk.diffie_hellman(&a_pk);
            prop_assert_eq!(s_ab.as_bytes(), s_ba.as_bytes());
        }
    }
}

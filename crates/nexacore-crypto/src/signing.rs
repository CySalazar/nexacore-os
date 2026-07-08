//! Digital signatures.
//!
//! Implements `Ed25519` per RFC 8032. Verification uses
//! [`ed25519_dalek::VerifyingKey::verify_strict`], which rejects
//! signatures of mixed-order points and small-subgroup attacks — the
//! "strict" check is the only acceptable verification mode for
//! `Ed25519` in NexaCore OS.
//!
//! # Misuse-resistant API
//!
//! Keys are typed wrappers; the private key is `Zeroize`-on-`Drop`,
//! does not implement `Debug` in a way that prints bytes, and cannot
//! be cloned (forces explicit move semantics for secret material).
//!
//! # Constant-time guarantees
//!
//! Verification is constant-time per the underlying library. Signing
//! is constant-time on Curve25519 scalar multiplication. Equality on
//! [`NexaCoreSignature`] uses [`subtle::ConstantTimeEq`].

use core::fmt;

use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use nexacore_types::error::{CryptoErrorKind, NexaCoreError, Result};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an `Ed25519` signing (private) key in bytes.
pub const SIGNING_KEY_LEN: usize = SECRET_KEY_LENGTH;

/// Length of an `Ed25519` verifying (public) key in bytes.
pub const VERIFYING_KEY_LEN: usize = PUBLIC_KEY_LENGTH;

/// Length of an `Ed25519` signature in bytes.
pub const SIGNATURE_LEN: usize = SIGNATURE_LENGTH;

// =============================================================================
// NexaCoreSigningKey
// =============================================================================

/// 256-bit `Ed25519` private key.
///
/// `ZeroizeOnDrop` wipes the inner key material when the value goes
/// out of scope. Cloning is intentionally NOT derived: secret keys
/// should travel by ownership, not by copy.
pub struct NexaCoreSigningKey {
    inner: SigningKey,
}

impl NexaCoreSigningKey {
    /// Generate a fresh `Ed25519` signing key from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; bare-metal builds use
    /// [`Self::from_bytes`] with a kernel-provided seed. Verify-only
    /// paths (`NexaCoreVerifyingKey::verify`) remain available without it.
    ///
    /// # Panics
    ///
    /// Panics if `getrandom` fails to produce entropy.
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = [0u8; SIGNING_KEY_LEN];
        #[allow(clippy::expect_used)]
        getrandom::getrandom(&mut secret)
            .expect("NexaCore: CSPRNG (getrandom) failed during Ed25519 key generation");
        let inner = SigningKey::from_bytes(&secret);
        // Best-effort wipe of the local copy. The library has its own
        // zeroize-on-drop on `SigningKey`.
        secret.zeroize();
        Self { inner }
    }

    /// Construct from raw bytes (deserialization path).
    ///
    /// The 32-byte input is interpreted as the seed; the public key is
    /// derived from it deterministically.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNING_KEY_LEN]) -> Self {
        Self {
            inner: SigningKey::from_bytes(&bytes),
        }
    }

    /// Borrow the underlying 32-byte seed.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; SIGNING_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Return the corresponding public key.
    #[must_use]
    pub fn verifying_key(&self) -> NexaCoreVerifyingKey {
        NexaCoreVerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign `message` with this key. Constant-time.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> NexaCoreSignature {
        let sig = self.inner.sign(message);
        NexaCoreSignature { inner: sig }
    }
}

impl Zeroize for NexaCoreSigningKey {
    fn zeroize(&mut self) {
        // `SigningKey` provides its own zeroize via Drop; explicitly
        // re-construct from zeroes to satisfy our trait impl.
        self.inner = SigningKey::from_bytes(&[0u8; SIGNING_KEY_LEN]);
    }
}

impl ZeroizeOnDrop for NexaCoreSigningKey {}

impl fmt::Debug for NexaCoreSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreSigningKey(<redacted>)")
    }
}

// =============================================================================
// NexaCoreVerifyingKey
// =============================================================================

/// 256-bit `Ed25519` public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NexaCoreVerifyingKey {
    inner: VerifyingKey,
}

impl NexaCoreVerifyingKey {
    /// Construct from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InvalidKey`]
    /// if the bytes do not form a valid `Ed25519` point.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| {
                NexaCoreError::crypto(CryptoErrorKind::InvalidKey, "signing::vk_from_bytes")
            })
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Verify `signature` over `message` against this public key.
    ///
    /// Uses [`VerifyingKey::verify_strict`] internally, which rejects
    /// signatures with non-canonical R or A points (defending against
    /// signature malleability and small-subgroup attacks).
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InvalidSignature`]
    /// on any verification failure. The error is opaque (no leak of
    /// failure cause).
    pub fn verify(&self, message: &[u8], signature: &NexaCoreSignature) -> Result<()> {
        self.inner
            .verify_strict(message, &signature.inner)
            .map_err(|_| {
                NexaCoreError::crypto(CryptoErrorKind::InvalidSignature, "signing::verify")
            })
    }

    /// Permissive verification — accepts non-canonical signatures.
    ///
    /// Provided for compatibility with legacy peers that produce
    /// non-strict signatures. Use [`NexaCoreVerifyingKey::verify`] in all
    /// new code; this method is intentionally named ugly to discourage
    /// accidental use.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InvalidSignature`]
    /// on verification failure.
    pub fn verify_permissive_legacy_only(
        &self,
        message: &[u8],
        signature: &NexaCoreSignature,
    ) -> Result<()> {
        self.inner.verify(message, &signature.inner).map_err(|_| {
            NexaCoreError::crypto(
                CryptoErrorKind::InvalidSignature,
                "signing::verify_permissive_legacy",
            )
        })
    }
}

impl fmt::Debug for NexaCoreVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are not secret, but printing 32 bytes in logs is
        // visual noise. Show a 4-byte hex prefix.
        let bytes = self.inner.to_bytes();
        write!(
            f,
            "NexaCoreVerifyingKey({:02x}{:02x}{:02x}{:02x}…)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

// =============================================================================
// NexaCoreSignature
// =============================================================================

/// 512-bit `Ed25519` signature (R || s).
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct NexaCoreSignature {
    inner: Signature,
}

impl NexaCoreSignature {
    /// Construct from 64 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self {
            inner: Signature::from_bytes(&bytes),
        }
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; SIGNATURE_LEN] {
        self.inner.to_bytes()
    }
}

// Constant-time equality for signatures (paranoid; signatures are public,
// but keeping the discipline avoids subtle side channels in higher-level
// code that compares signatures).
impl PartialEq for NexaCoreSignature {
    fn eq(&self, other: &Self) -> bool {
        self.inner.to_bytes().ct_eq(&other.inner.to_bytes()).into()
    }
}
impl Eq for NexaCoreSignature {}

impl fmt::Debug for NexaCoreSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.inner.to_bytes();
        write!(
            f,
            "NexaCoreSignature({:02x}{:02x}{:02x}{:02x}…)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

// =============================================================================
// Tests — RFC 8032 vectors + property + negative.
// =============================================================================

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // RFC 8032 § 7.1 — TEST 1.
    // SK seed is 9d61... (32 bytes). PK is d75a... (32 bytes). Empty message.
    // Signature is e556...100b (64 bytes).
    const RFC8032_TEST1_SK_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC8032_TEST1_PK_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_TEST1_SIG_HEX: &str = concat!(
        "e5564300c360ac729086e2cc806e828a",
        "84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b",
        "d25bf5f0595bbe24655141438e7a100b"
    );

    fn parse_array<const N: usize>(hex_str: &str) -> [u8; N] {
        let v = hex::decode(hex_str).unwrap();
        assert_eq!(v.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn rfc8032_test1_sign_matches_vector() {
        let sk =
            NexaCoreSigningKey::from_bytes(parse_array::<SIGNING_KEY_LEN>(RFC8032_TEST1_SK_HEX));
        let sig = sk.sign(b"");
        let expected = parse_array::<SIGNATURE_LEN>(RFC8032_TEST1_SIG_HEX);
        assert_eq!(sig.to_bytes(), expected);
    }

    #[test]
    fn rfc8032_test1_pk_derivation() {
        let sk =
            NexaCoreSigningKey::from_bytes(parse_array::<SIGNING_KEY_LEN>(RFC8032_TEST1_SK_HEX));
        let vk = sk.verifying_key();
        let expected = parse_array::<VERIFYING_KEY_LEN>(RFC8032_TEST1_PK_HEX);
        assert_eq!(vk.as_bytes(), expected);
    }

    #[test]
    fn rfc8032_test1_verify_succeeds() {
        let vk_bytes = parse_array::<VERIFYING_KEY_LEN>(RFC8032_TEST1_PK_HEX);
        let vk = NexaCoreVerifyingKey::from_bytes(&vk_bytes).unwrap();
        let sig =
            NexaCoreSignature::from_bytes(parse_array::<SIGNATURE_LEN>(RFC8032_TEST1_SIG_HEX));
        vk.verify(b"", &sig).unwrap();
    }

    // ---- Round-trip (gated behind `rng` feature) ----------------------------

    #[cfg(feature = "rng")]
    #[test]
    fn round_trip_random_key() {
        let sk = NexaCoreSigningKey::generate();
        let vk = sk.verifying_key();
        let msg = b"NexaCore mesh handshake";
        let sig = sk.sign(msg);
        vk.verify(msg, &sig).unwrap();
    }

    // ---- Negative tests (gated behind `rng` feature) ------------------------

    #[cfg(feature = "rng")]
    #[test]
    fn wrong_message_fails_verification() {
        let sk = NexaCoreSigningKey::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        let err = vk.verify(b"tampered", &sig).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::InvalidSignature);
            }
            _ => panic!("expected Crypto::InvalidSignature"),
        }
    }

    #[cfg(feature = "rng")]
    #[test]
    fn wrong_key_fails_verification() {
        let sk = NexaCoreSigningKey::generate();
        let other_vk = NexaCoreSigningKey::generate().verifying_key();
        let sig = sk.sign(b"msg");
        let err = other_vk.verify(b"msg", &sig).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::InvalidSignature);
            }
            _ => panic!("expected Crypto::InvalidSignature"),
        }
    }

    #[cfg(feature = "rng")]
    #[test]
    fn tampered_signature_fails_verification() {
        let sk = NexaCoreSigningKey::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"msg");
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 0x01;
        let bad = NexaCoreSignature::from_bytes(bytes);
        let err = vk.verify(b"msg", &bad).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::InvalidSignature);
            }
            _ => panic!("expected Crypto::InvalidSignature"),
        }
    }

    // The two tests below document the parsing surface of
    // `NexaCoreVerifyingKey::from_bytes`. Behaviour summary:
    //
    // * Valid Ed25519 compressed points (e.g., the RFC 8032 test
    //   vectors) parse successfully.
    // * Inputs that are not the compressed encoding of a curve point
    //   (most arbitrary 32-byte values) are rejected with
    //   `CryptoErrorKind::InvalidKey`.
    //
    // Subgroup validity (rejecting small-subgroup / non-prime-order
    // points) is enforced separately by `verify_strict` at verification
    // time. Tampered-signature / wrong-key / wrong-message tests above
    // exercise that path.

    #[test]
    fn from_bytes_accepts_valid_compressed_point() {
        // The RFC 8032 § 7.1 test 1 public key is a known-valid point.
        let valid = parse_array::<VERIFYING_KEY_LEN>(RFC8032_TEST1_PK_HEX);
        let _vk = NexaCoreVerifyingKey::from_bytes(&valid).unwrap();
    }

    #[test]
    fn from_bytes_rejects_invalid_compressed_point() {
        // `[0xAB; 32]` is not the compressed encoding of any curve
        // point — `decompress()` fails on this input.
        let bad = [0xABu8; VERIFYING_KEY_LEN];
        let err = NexaCoreVerifyingKey::from_bytes(&bad).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => assert_eq!(kind, CryptoErrorKind::InvalidKey),
            _ => panic!("expected Crypto::InvalidKey"),
        }
    }

    #[test]
    fn signing_key_debug_does_not_leak() {
        let sk = NexaCoreSigningKey::from_bytes([0xCD; SIGNING_KEY_LEN]);
        let dbg = alloc::format!("{sk:?}");
        assert!(!dbg.contains("cd"));
        assert!(dbg.contains("redacted"));
    }

    // ---- Property tests -----------------------------------------------------

    proptest! {
        // Stress level: 256 cases on each property. Acts as a
        // poor-man's fuzz pass until `cargo-fuzz` runs land in P3
        // (`crates/nexacore-crypto/fuzz/`).
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn sign_verify_round_trip(
            seed in proptest::array::uniform32(any::<u8>()),
            msg in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let sk = NexaCoreSigningKey::from_bytes(seed);
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);
            prop_assert!(vk.verify(&msg, &sig).is_ok());
        }

        #[test]
        fn sign_is_deterministic(
            seed in proptest::array::uniform32(any::<u8>()),
            msg in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            // Ed25519 signatures are deterministic per RFC 8032: the same
            // (key, message) pair always yields the same signature.
            let sk = NexaCoreSigningKey::from_bytes(seed);
            let s1 = sk.sign(&msg);
            let s2 = sk.sign(&msg);
            prop_assert_eq!(s1.to_bytes(), s2.to_bytes());
        }

        #[test]
        fn any_message_modification_fails(
            seed in proptest::array::uniform32(any::<u8>()),
            mut msg in proptest::collection::vec(any::<u8>(), 1..128),
            tweak_index in 0usize..128,
        ) {
            let sk = NexaCoreSigningKey::from_bytes(seed);
            let vk = sk.verifying_key();
            // Sign the original message first, then mutate `msg` in place.
            let sig = sk.sign(&msg);
            let i = tweak_index % msg.len();
            msg[i] ^= 0x01;
            prop_assert!(vk.verify(&msg, &sig).is_err());
        }
    }
}

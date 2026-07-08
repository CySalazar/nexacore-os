//! Authenticated Encryption with Associated Data.
//!
//! Implements `ChaCha20-Poly1305` per RFC 8439. The choice of cipher is
//! recorded in `/docs/04-security-model.md` and is the only AEAD
//! supported in v0.1; algorithm agility lives at the protocol layer
//! (see [`crate`] root docs).
//!
//! # Misuse-resistant API
//!
//! Calling code never touches a raw byte array as a key or a nonce.
//! All inputs are typed wrappers ([`NexaCoreAeadKey`], [`NexaCoreNonce`],
//! [`NexaCoreCiphertext`]) so accidental swaps are caught by the compiler.
//!
//! Nonces are produced by a [`NonceCounter`] that panics on counter
//! overflow. The panic is intentional: a (key, nonce) collision under
//! `ChaCha20-Poly1305` is catastrophic, so it is safer to crash the
//! process than to risk reuse. The same key MUST never be used to
//! encrypt more than `2^96 - 1` messages — the counter enforces this
//! at runtime. (`ChaCha20` is the underlying stream cipher.)
//!
//! # Constant-time guarantees
//!
//! Tag verification is performed by the wrapped library
//! (`chacha20poly1305 = 0.10.x`), which uses constant-time comparison
//! internally. Higher-level equality checks here go through
//! [`subtle::ConstantTimeEq`].

use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use nexacore_types::error::{CryptoErrorKind, NexaCoreError, Result};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an AEAD key in bytes (256-bit ChaCha20).
pub const KEY_LEN: usize = 32;

/// Length of an AEAD nonce in bytes (96-bit IETF ChaCha20-Poly1305).
pub const NONCE_LEN: usize = 12;

/// Length of an AEAD authentication tag in bytes (Poly1305 MAC).
pub const TAG_LEN: usize = 16;

// =============================================================================
// NexaCoreAeadKey
// =============================================================================

/// 256-bit symmetric key for `ChaCha20-Poly1305`.
///
/// Wipes itself on `Drop` via `ZeroizeOnDrop`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct NexaCoreAeadKey([u8; KEY_LEN]);

impl NexaCoreAeadKey {
    /// Construct a key from raw bytes. The caller is responsible for
    /// the source's secrecy and quality — typically this is the output
    /// of an HKDF expand with sufficient salt and info entropy.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh AEAD key from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; bare-metal builds use
    /// [`Self::from_bytes`] with a kernel-provided seed instead.
    ///
    /// # Panics
    ///
    /// Panics if `getrandom` fails to produce entropy. See
    /// `nexacore_types::identity::random_uuid_bytes` for the rationale on
    /// why this is unrecoverable.
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_LEN];
        // `expect_used` is intentional: a CSPRNG failure is fatal for
        // any cryptographic workload. See lib.rs for the project-wide
        // policy.
        #[allow(clippy::expect_used)]
        getrandom::getrandom(&mut key)
            .expect("NexaCore: CSPRNG (getrandom) failed during AEAD key generation");
        Self(key)
    }

    /// Borrow the underlying bytes.
    ///
    /// Avoid surfacing this slice in logs or wire protocols. The
    /// `ZeroizeOnDrop` invariant only holds for owned values.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

// Manual `PartialEq` / `Eq` via `ConstantTimeEq` to defeat timing
// side-channels on naive comparison. Two equal keys MUST take the same
// time to compare as two unequal keys.
impl PartialEq for NexaCoreAeadKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for NexaCoreAeadKey {}

// `Debug` deliberately does NOT print the key bytes. We surface only
// the kind name — useful in logs without leaking secrets.
impl fmt::Debug for NexaCoreAeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreAeadKey(<redacted>)")
    }
}

// =============================================================================
// NexaCoreNonce
// =============================================================================

/// 96-bit nonce for `ChaCha20-Poly1305`.
///
/// Nonces are not secret but MUST be unique per key. Use [`NonceCounter`]
/// for monotonic sequence numbers, or construct directly from random
/// bytes when the protocol mandates random nonces.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct NexaCoreNonce([u8; NONCE_LEN]);

impl NexaCoreNonce {
    /// Construct a nonce from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

// =============================================================================
// NonceCounter
// =============================================================================

/// Monotonic 96-bit counter that yields a fresh [`NexaCoreNonce`] per call.
///
/// The counter starts at zero and is incremented by 1 after each
/// [`NonceCounter::next`] call. The internal representation is
/// little-endian to match the wire layout of `ChaCha20-Poly1305`
/// nonces.
///
/// # Panics
///
/// [`NonceCounter::next`] panics if the counter would overflow `2^96 - 1`.
/// Reaching this state means the same (key, nonce) pair would be
/// reused, which breaks the security of `ChaCha20-Poly1305`. The panic
/// is the correct behaviour: rotate the key before this happens.
#[derive(Clone, Debug, Default)]
pub struct NonceCounter {
    /// Stored as a `u128`; only the low 96 bits are used. The `u128`
    /// representation keeps overflow detection free.
    counter: u128,
}

impl NonceCounter {
    /// Construct a fresh counter starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { counter: 0 }
    }

    /// Construct a counter starting at `start`. Useful for test-vector
    /// reproduction and protocol resumption.
    ///
    /// # Panics
    ///
    /// Panics if `start >= 2^96`.
    #[must_use]
    pub fn from_start(start: u128) -> Self {
        assert!(
            start < (1u128 << 96),
            "NonceCounter::from_start: value exceeds 2^96"
        );
        Self { counter: start }
    }

    /// Yield the next nonce and advance the counter.
    ///
    /// # Panics
    ///
    /// Panics on overflow past `2^96 - 1`. See type docs.
    //
    // `should_implement_trait`: this method is intentionally NOT named to
    // align with `Iterator::next` — implementing `Iterator` would expose a
    // never-ending stream of nonces and invite infinite-`for` loops where a
    // bounded number of nonces is intended. The name `next` is the
    // domain-correct verb (sequence successor); silencing the lint is
    // preferable to renaming.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> NexaCoreNonce {
        // Defensive: refuse to issue a nonce that would push the
        // counter to or past 2^96. The check happens BEFORE the
        // `+= 1` so we never produce a duplicate.
        assert!(
            self.counter < (1u128 << 96),
            "NonceCounter overflow: rotate the AEAD key (limit 2^96 - 1 messages)"
        );
        let mut bytes = [0u8; NONCE_LEN];
        let counter_bytes = self.counter.to_le_bytes();
        // Take the low 12 bytes of the 16-byte u128 little-endian
        // representation. The high 4 bytes are guaranteed zero by the
        // overflow check above.
        // `indexing_slicing` is allowed because both slice lengths are
        // compile-time constants (12 == NONCE_LEN; 12 < 16).
        #[allow(clippy::indexing_slicing)]
        bytes.copy_from_slice(&counter_bytes[..NONCE_LEN]);
        self.counter += 1;
        NexaCoreNonce(bytes)
    }

    /// Return the next counter value without advancing. Useful for
    /// auditing and tests.
    #[must_use]
    pub const fn peek(&self) -> u128 {
        self.counter
    }
}

// =============================================================================
// NexaCoreCiphertext
// =============================================================================

/// Opaque AEAD ciphertext (plaintext + 16-byte authentication tag).
///
/// The ciphertext is `plaintext_len + TAG_LEN` bytes. The tag is the
/// last 16 bytes; we treat the whole buffer as opaque on the wire.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NexaCoreCiphertext(Vec<u8>);

impl NexaCoreCiphertext {
    /// Wrap a raw ciphertext buffer. Reserved for deserialization.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes (ciphertext + tag).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length of the ciphertext (plaintext + tag) in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` iff the ciphertext is empty (length 0).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// =============================================================================
// seal / open
// =============================================================================

/// Encrypt and authenticate `plaintext` under `key` and `nonce`,
/// binding `aad` (additional authenticated data, not encrypted but
/// authenticated).
///
/// # Errors
///
/// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InternalInvariant`]
/// if the underlying library reports a failure (this should never
/// happen for valid inputs of the right length).
///
/// # Panics
///
/// Does not panic for any input length supported by `ChaCha20-Poly1305`
/// (effectively unbounded; messages are limited to `2^32 - 1` blocks
/// of 64 bytes each).
pub fn seal(
    key: &NexaCoreAeadKey,
    nonce: &NexaCoreNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<NexaCoreCiphertext> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce_ref = Nonce::from_slice(nonce.as_bytes());
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(nonce_ref, payload)
        .map(NexaCoreCiphertext)
        .map_err(|_| {
            NexaCoreError::crypto(CryptoErrorKind::InternalInvariant, "aead::seal::encrypt")
        })
}

/// Authenticate and decrypt `ciphertext` under `key` and `nonce`,
/// verifying that `aad` matches what was bound at encryption time.
///
/// # Errors
///
/// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::DecryptionFailure`]
/// on tag mismatch, wrong key, or any tampering of the ciphertext or
/// AAD. The error is opaque: we deliberately do NOT distinguish "wrong
/// key" from "tampered ciphertext" because the distinction can leak
/// information to an adversary.
pub fn open(
    key: &NexaCoreAeadKey,
    nonce: &NexaCoreNonce,
    aad: &[u8],
    ciphertext: &NexaCoreCiphertext,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce_ref = Nonce::from_slice(nonce.as_bytes());
    let payload = Payload {
        msg: ciphertext.as_bytes(),
        aad,
    };
    cipher.decrypt(nonce_ref, payload).map_err(|_| {
        NexaCoreError::crypto(CryptoErrorKind::DecryptionFailure, "aead::open::decrypt")
    })
}

// =============================================================================
// Tests — RFC 8439 vectors + property + negative.
// =============================================================================

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // ---- RFC 8439 § 2.8.2 test vector --------------------------------------
    // ChaCha20-Poly1305 AEAD; verifies that the wrapper produces the same
    // ciphertext bytes as the spec.

    fn rfc8439_key() -> NexaCoreAeadKey {
        let bytes = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&bytes);
        NexaCoreAeadKey::from_bytes(k)
    }

    fn rfc8439_nonce() -> NexaCoreNonce {
        let bytes = hex::decode("070000004041424344454647").unwrap();
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&bytes);
        NexaCoreNonce::from_bytes(n)
    }

    const RFC8439_AAD_HEX: &str = "50515253c0c1c2c3c4c5c6c7";
    const RFC8439_PT: &[u8] =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    // Expected ciphertext (with tag) per RFC 8439 § 2.8.2.
    const RFC8439_CT_HEX: &str = concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2",
        "a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b",
        "1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58",
        "fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b",
        "6116",
        "1ae10b594f09e26a7e902ecbd0600691"
    );

    #[test]
    fn rfc8439_seal_produces_expected_ciphertext() {
        let key = rfc8439_key();
        let nonce = rfc8439_nonce();
        let aad = hex::decode(RFC8439_AAD_HEX).unwrap();
        let ct = seal(&key, &nonce, &aad, RFC8439_PT).unwrap();
        let expected = hex::decode(RFC8439_CT_HEX).unwrap();
        assert_eq!(ct.as_bytes(), &expected[..]);
    }

    #[test]
    fn rfc8439_open_recovers_plaintext() {
        let key = rfc8439_key();
        let nonce = rfc8439_nonce();
        let aad = hex::decode(RFC8439_AAD_HEX).unwrap();
        let ct = NexaCoreCiphertext::from_bytes(hex::decode(RFC8439_CT_HEX).unwrap());
        let pt = open(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(&pt[..], RFC8439_PT);
    }

    // ---- Round-trip (gated behind `rng` feature) ----------------------------

    #[cfg(feature = "rng")]
    #[test]
    fn round_trip_with_random_key() {
        let key = NexaCoreAeadKey::generate();
        let nonce = NexaCoreNonce::from_bytes([0u8; NONCE_LEN]);
        let aad = b"app=test";
        let pt = b"hello, NexaCore";
        let ct = seal(&key, &nonce, aad, pt).unwrap();
        let recovered = open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(&recovered[..], pt);
    }

    // ---- Negative tests (gated behind `rng` feature) ------------------------

    #[cfg(feature = "rng")]
    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let key = NexaCoreAeadKey::generate();
        let nonce = NexaCoreNonce::from_bytes([1u8; NONCE_LEN]);
        let aad = b"";
        let pt = b"do not tamper with me";
        let mut ct_bytes = seal(&key, &nonce, aad, pt).unwrap().as_bytes().to_vec();
        // Flip a bit somewhere in the middle.
        ct_bytes[5] ^= 0x01;
        let tampered = NexaCoreCiphertext::from_bytes(ct_bytes);
        let err = open(&key, &nonce, aad, &tampered).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::DecryptionFailure);
            }
            _ => panic!("expected Crypto::DecryptionFailure, got {err:?}"),
        }
    }

    #[cfg(feature = "rng")]
    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key = NexaCoreAeadKey::generate();
        let other_key = NexaCoreAeadKey::generate();
        let nonce = NexaCoreNonce::from_bytes([2u8; NONCE_LEN]);
        let aad = b"";
        let pt = b"secret";
        let ct = seal(&key, &nonce, aad, pt).unwrap();
        let err = open(&other_key, &nonce, aad, &ct).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::DecryptionFailure);
            }
            _ => panic!("expected Crypto::DecryptionFailure"),
        }
    }

    #[cfg(feature = "rng")]
    #[test]
    fn tampered_aad_fails_to_decrypt() {
        let key = NexaCoreAeadKey::generate();
        let nonce = NexaCoreNonce::from_bytes([3u8; NONCE_LEN]);
        let aad_correct = b"correct-aad";
        let aad_tampered = b"tampered-aad";
        let pt = b"payload";
        let ct = seal(&key, &nonce, aad_correct, pt).unwrap();
        let err = open(&key, &nonce, aad_tampered, &ct).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::DecryptionFailure);
            }
            _ => panic!("expected Crypto::DecryptionFailure"),
        }
    }

    // ---- NonceCounter -------------------------------------------------------

    #[test]
    fn nonce_counter_starts_at_zero() {
        let mut c = NonceCounter::new();
        let n = c.next();
        assert_eq!(n.as_bytes(), &[0u8; NONCE_LEN]);
        assert_eq!(c.peek(), 1);
    }

    #[test]
    fn nonce_counter_advances() {
        let mut c = NonceCounter::new();
        let _ = c.next();
        let n2 = c.next();
        let mut expected = [0u8; NONCE_LEN];
        expected[0] = 1;
        assert_eq!(n2.as_bytes(), &expected);
        assert_eq!(c.peek(), 2);
    }

    #[test]
    fn nonce_counter_from_start() {
        let mut c = NonceCounter::from_start(42);
        let n = c.next();
        let mut expected = [0u8; NONCE_LEN];
        expected[0] = 42;
        assert_eq!(n.as_bytes(), &expected);
    }

    #[test]
    #[should_panic(expected = "NonceCounter overflow")]
    fn nonce_counter_panics_on_overflow() {
        let mut c = NonceCounter::from_start((1u128 << 96) - 1);
        let _ = c.next(); // OK — uses the last valid value.
        let _ = c.next(); // PANIC — would overflow.
    }

    // ---- AeadKey opacity ----------------------------------------------------

    #[test]
    fn aead_key_debug_does_not_leak_bytes() {
        let key = NexaCoreAeadKey::from_bytes([0xAB; KEY_LEN]);
        let dbg = alloc::format!("{key:?}");
        assert!(!dbg.contains("ab"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn aead_key_eq_is_consistent() {
        let a = NexaCoreAeadKey::from_bytes([1u8; KEY_LEN]);
        let b = NexaCoreAeadKey::from_bytes([1u8; KEY_LEN]);
        let c = NexaCoreAeadKey::from_bytes([2u8; KEY_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ---- Property tests -----------------------------------------------------

    proptest! {
        // Stress level: 256 cases on each property. Acts as a
        // poor-man's fuzz pass until `cargo-fuzz` runs land in P3
        // (`crates/nexacore-crypto/fuzz/`).
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn round_trip_arbitrary_payload(
            key_bytes in proptest::array::uniform32(any::<u8>()),
            nonce_bytes in proptest::array::uniform12(any::<u8>()),
            aad in proptest::collection::vec(any::<u8>(), 0..128),
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let key = NexaCoreAeadKey::from_bytes(key_bytes);
            let nonce = NexaCoreNonce::from_bytes(nonce_bytes);
            let ct = seal(&key, &nonce, &aad, &plaintext).unwrap();
            let pt = open(&key, &nonce, &aad, &ct).unwrap();
            prop_assert_eq!(pt, plaintext);
        }

        #[test]
        fn ciphertext_is_pt_len_plus_tag(
            key_bytes in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let key = NexaCoreAeadKey::from_bytes(key_bytes);
            let nonce = NexaCoreNonce::from_bytes([0u8; NONCE_LEN]);
            let ct = seal(&key, &nonce, &[], &plaintext).unwrap();
            prop_assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
        }
    }
}

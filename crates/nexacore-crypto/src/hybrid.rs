//! Hybrid post-quantum key encapsulation — `X25519 + ML-KEM-768`.
//!
//! Composes the classical [`crate::kex`] `X25519` Diffie-Hellman exchange
//! (RFC 7748) with the post-quantum [`crate::mlkem`] `ML-KEM-768` KEM
//! (FIPS 203) into a single hybrid KEM whose shared secret stays secure as
//! long as *either* component resists attack. This is the migration shape
//! promised in the `kex` and `mlkem` module docs: additive, and reusing the
//! two vetted halves rather than inventing a third primitive.
//!
//! # Combiner construction
//!
//! The two component shared secrets are merged with a **concatenation KEM
//! combiner** fed through `HKDF-SHA-256` (the crate's [`crate::kdf`]), binding
//! the full protocol transcript — both ciphertexts and both public keys:
//!
//! ```text
//! ss_hybrid = HKDF-SHA-256(
//!     salt = "",
//!     ikm  = ss_X25519 ‖ ss_ML-KEM ‖ ct_X25519 ‖ ct_ML-KEM ‖ pk_X25519 ‖ ek_ML-KEM,
//!     info = "NexaCore-OS/hybrid-kem/X25519+ML-KEM-768/v1",
//!     L    = 32)
//! ```
//!
//! This follows the `dualPRF`/nested transcript-binding combiner analysed by
//! Bindel, Brendel, Fischlin, Goncalves & Stebila, *"Hybrid Key Encapsulation
//! Mechanisms and Authenticated Key Exchange"* (`PQCrypto` 2019), and mirrored by
//! the concatenation combiner of `draft-ietf-tls-hybrid-design` and the two-step
//! KDF of NIST SP 800-56C Rev. 3. Hashing **both** ciphertexts and **both**
//! public keys into the transcript makes the combiner *robust*: the hybrid
//! secret is a domain-separated pseudo-random function of every public value on
//! the wire, so an adversary who breaks one primitive still cannot control or
//! predict the output while the other primitive stands.
//!
//! The classical half is a `DHKEM(X25519)`-style construction (as in HPKE,
//! RFC 9180): "encapsulation" mints a one-shot ephemeral `X25519` key whose
//! public value *is* the classical ciphertext, and the ECDH output is the
//! classical shared secret.
//!
//! # Determinism and randomness
//!
//! Following [`crate::mlkem`], every operation has a deterministic entry point
//! ([`NexaCoreHybridSecretKey::from_seed`],
//! [`NexaCoreHybridPublicKey::encapsulate_deterministic`]) that takes raw seed /
//! message bytes — used by the round-trip and sensitivity tests and by
//! bare-metal (`x86_64-unknown-none`) builds that mint entropy from the kernel —
//! plus an `rng`-gated convenience wrapper
//! ([`NexaCoreHybridSecretKey::generate`],
//! [`NexaCoreHybridPublicKey::encapsulate`]) that sources the platform CSPRNG.

use alloc::vec::Vec;
use core::fmt;

use nexacore_types::error::Result;
#[cfg(feature = "rng")]
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    kdf::hkdf_extract_and_expand,
    kex::{KEY_LEN as X25519_KEY_LEN, NexaCorePublicKey, NexaCoreStaticSecret},
    mlkem::{
        ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN, ML_KEM_768_MESSAGE_LEN,
        ML_KEM_768_SEED_LEN, NexaCoreMlKemCiphertext, NexaCoreMlKemPublicKey,
        NexaCoreMlKemSecretKey,
    },
};

/// Length in bytes of a serialized hybrid public key (`X25519 ‖ ML-KEM-768`).
pub const HYBRID_PUBLIC_KEY_LEN: usize = X25519_KEY_LEN + ML_KEM_768_ENCAPSULATION_KEY_LEN;

/// Length in bytes of a serialized hybrid ciphertext
/// (`X25519 ephemeral public ‖ ML-KEM-768 ciphertext`).
pub const HYBRID_CIPHERTEXT_LEN: usize = X25519_KEY_LEN + ML_KEM_768_CIPHERTEXT_LEN;

/// Length in bytes of the hybrid shared secret.
pub const HYBRID_SHARED_SECRET_LEN: usize = 32;

/// Length in bytes of the deterministic key-generation seed
/// (`X25519 scalar ‖ ML-KEM-768 d‖z seed`).
pub const HYBRID_SEED_LEN: usize = X25519_KEY_LEN + ML_KEM_768_SEED_LEN;

/// Length in bytes of the deterministic encapsulation seed
/// (`X25519 ephemeral scalar ‖ ML-KEM-768 message m`).
pub const HYBRID_ENCAPS_SEED_LEN: usize = X25519_KEY_LEN + ML_KEM_768_MESSAGE_LEN;

/// Domain-separation label bound into the combiner KDF. Versioned so a future
/// combiner change is a distinct, non-colliding derivation.
const HYBRID_KDF_LABEL: &[u8] = b"NexaCore-OS/hybrid-kem/X25519+ML-KEM-768/v1";

// =============================================================================
// Combiner
// =============================================================================

/// Derive the hybrid shared secret from the two component secrets and the full
/// transcript (both ciphertexts, both public keys), per the module-level
/// construction. `ss_x25519 ‖ ss_mlkem ‖ transcript` is the HKDF input keying
/// material; [`HYBRID_KDF_LABEL`] is the `info` domain separator.
///
/// The assembled `ikm` buffer holds both raw component shared secrets, so it is
/// zeroized before returning.
fn combine(
    ss_x25519: &[u8],
    ss_mlkem: &[u8],
    ct_x25519: &[u8; X25519_KEY_LEN],
    ct_mlkem: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
    pk_x25519: &[u8; X25519_KEY_LEN],
    ek_mlkem: &[u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
) -> Result<NexaCoreHybridSharedSecret> {
    let mut ikm = Vec::with_capacity(
        ss_x25519.len()
            + ss_mlkem.len()
            + X25519_KEY_LEN
            + ML_KEM_768_CIPHERTEXT_LEN
            + X25519_KEY_LEN
            + ML_KEM_768_ENCAPSULATION_KEY_LEN,
    );
    // Component shared secrets first, then the transcript.
    ikm.extend_from_slice(ss_x25519);
    ikm.extend_from_slice(ss_mlkem);
    ikm.extend_from_slice(ct_x25519);
    ikm.extend_from_slice(ct_mlkem);
    ikm.extend_from_slice(pk_x25519);
    ikm.extend_from_slice(ek_mlkem);

    let okm = hkdf_extract_and_expand(&[], &ikm, HYBRID_KDF_LABEL, HYBRID_SHARED_SECRET_LEN);
    ikm.zeroize();
    let okm = okm?;

    let mut bytes = [0u8; HYBRID_SHARED_SECRET_LEN];
    bytes.copy_from_slice(&okm);
    Ok(NexaCoreHybridSharedSecret { bytes })
}

// =============================================================================
// NexaCoreHybridSecretKey
// =============================================================================

/// A hybrid `X25519 + ML-KEM-768` decapsulation (private) key.
///
/// Wraps a long-lived `X25519` [`NexaCoreStaticSecret`] and an `ML-KEM-768`
/// [`NexaCoreMlKemSecretKey`]. Both fields zeroize their key material on drop
/// (the `X25519` scalar via `x25519-dalek`'s `ZeroizeOnDrop`, the ML-KEM key via
/// the `ml-kem` crate's workspace-wide `zeroize` feature), so this composite is
/// effectively zeroize-on-drop through its members without extra code.
pub struct NexaCoreHybridSecretKey {
    x25519: NexaCoreStaticSecret,
    mlkem: NexaCoreMlKemSecretKey,
}

impl NexaCoreHybridSecretKey {
    /// Deterministically derive a hybrid decapsulation key from a
    /// [`HYBRID_SEED_LEN`]-byte seed, split as
    /// `X25519 scalar (32) ‖ ML-KEM-768 d‖z seed (64)`.
    ///
    /// Used by the tests and by bare-metal builds that mint the seed from a
    /// kernel entropy source.
    #[must_use]
    pub fn from_seed(seed: [u8; HYBRID_SEED_LEN]) -> Self {
        let (x_seed, ml_seed) = seed.split_at(X25519_KEY_LEN);
        let mut x_arr = [0u8; X25519_KEY_LEN];
        x_arr.copy_from_slice(x_seed);
        let mut ml_arr = [0u8; ML_KEM_768_SEED_LEN];
        ml_arr.copy_from_slice(ml_seed);
        let key = Self {
            x25519: NexaCoreStaticSecret::from_bytes(x_arr),
            mlkem: NexaCoreMlKemSecretKey::from_seed(ml_arr),
        };
        x_arr.zeroize();
        ml_arr.zeroize();
        key
    }

    /// Generate a fresh hybrid decapsulation key from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; the seed is drawn from [`OsRng`] and
    /// wiped after the key is derived.
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; HYBRID_SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        let key = Self::from_seed(seed);
        seed.zeroize();
        key
    }

    /// Compute the corresponding hybrid encapsulation (public) key.
    #[must_use]
    pub fn public_key(&self) -> NexaCoreHybridPublicKey {
        NexaCoreHybridPublicKey {
            x25519: self.x25519.public_key(),
            mlkem: self.mlkem.public_key(),
        }
    }

    /// Decapsulate `ciphertext` and recover the hybrid shared secret.
    ///
    /// Mirrors [`NexaCoreHybridPublicKey::encapsulate_deterministic`]: it runs
    /// the `X25519` ECDH against the ephemeral public in the ciphertext, the
    /// `ML-KEM-768` decapsulation, and feeds both through the same combiner with
    /// the recipient's own public keys as the transcript's public-key half.
    ///
    /// Neither component KEM signals decapsulation failure (`X25519` always
    /// yields a scalar; `ML-KEM` uses implicit rejection), so a wrong key or a
    /// tampered ciphertext produces a *different* — not an erroring — shared
    /// secret. The surrounding protocol must authenticate the result.
    ///
    /// # Errors
    ///
    /// Returns [`nexacore_types::NexaCoreError::Crypto`] only if the combiner
    /// KDF fails, which cannot happen for the fixed 32-byte output length.
    pub fn decapsulate(
        &self,
        ciphertext: &NexaCoreHybridCiphertext,
    ) -> Result<NexaCoreHybridSharedSecret> {
        let ss_x = self.x25519.diffie_hellman(&ciphertext.x25519);
        let ss_m = self.mlkem.decapsulate(&ciphertext.mlkem);
        let pk = self.public_key();
        combine(
            ss_x.as_bytes(),
            ss_m.as_bytes(),
            &ciphertext.x25519.as_bytes(),
            &ciphertext.mlkem.as_bytes(),
            &pk.x25519.as_bytes(),
            &pk.mlkem.as_bytes(),
        )
    }
}

impl fmt::Debug for NexaCoreHybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreHybridSecretKey(<redacted>)")
    }
}

// =============================================================================
// NexaCoreHybridPublicKey
// =============================================================================

/// A hybrid `X25519 + ML-KEM-768` encapsulation (public) key.
#[derive(Clone)]
pub struct NexaCoreHybridPublicKey {
    x25519: NexaCorePublicKey,
    mlkem: NexaCoreMlKemPublicKey,
}

impl NexaCoreHybridPublicKey {
    /// Parse a hybrid public key from its [`HYBRID_PUBLIC_KEY_LEN`]-byte form,
    /// split as `X25519 public (32) ‖ ML-KEM-768 encapsulation key (1184)`.
    ///
    /// # Errors
    ///
    /// Returns [`nexacore_types::NexaCoreError::Crypto`] with
    /// [`nexacore_types::error::CryptoErrorKind::InvalidKey`] if the ML-KEM half
    /// fails its FIPS 203 §7.2 modulus check. (`X25519` accepts any 32 bytes.)
    pub fn from_bytes(bytes: &[u8; HYBRID_PUBLIC_KEY_LEN]) -> Result<Self> {
        let (x_part, ml_part) = bytes.split_at(X25519_KEY_LEN);
        let mut x_arr = [0u8; X25519_KEY_LEN];
        x_arr.copy_from_slice(x_part);
        let mut ml_arr = [0u8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
        ml_arr.copy_from_slice(ml_part);
        Ok(Self {
            x25519: NexaCorePublicKey::from_bytes(x_arr),
            mlkem: NexaCoreMlKemPublicKey::from_bytes(&ml_arr)?,
        })
    }

    /// Serialize this hybrid public key to its [`HYBRID_PUBLIC_KEY_LEN`]-byte
    /// form (`X25519 ‖ ML-KEM-768`).
    #[must_use]
    pub fn as_bytes(&self) -> [u8; HYBRID_PUBLIC_KEY_LEN] {
        let mut out = [0u8; HYBRID_PUBLIC_KEY_LEN];
        let (x_part, ml_part) = out.split_at_mut(X25519_KEY_LEN);
        x_part.copy_from_slice(&self.x25519.as_bytes());
        ml_part.copy_from_slice(&self.mlkem.as_bytes());
        out
    }

    /// Encapsulate a hybrid shared secret to the holder of the matching hybrid
    /// decapsulation key, drawing all randomness from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; the `X25519` ephemeral scalar and the
    /// `ML-KEM` message are drawn from [`OsRng`] and wiped after use.
    ///
    /// # Errors
    ///
    /// Returns [`nexacore_types::NexaCoreError::Crypto`] only if the combiner
    /// KDF fails, which cannot happen for the fixed 32-byte output length.
    #[cfg(feature = "rng")]
    pub fn encapsulate(&self) -> Result<(NexaCoreHybridCiphertext, NexaCoreHybridSharedSecret)> {
        let mut seed = [0u8; HYBRID_ENCAPS_SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        let out = self.encapsulate_deterministic(seed);
        seed.zeroize();
        out
    }

    /// Encapsulate using a caller-supplied [`HYBRID_ENCAPS_SEED_LEN`]-byte seed,
    /// split as `X25519 ephemeral scalar (32) ‖ ML-KEM-768 message m (32)`.
    ///
    /// This is the deterministic entry point used by the tests and bare-metal
    /// builds. Prefer [`encapsulate`](Self::encapsulate) in userspace: reusing
    /// or biasing the seed is a catastrophic failure of the scheme.
    ///
    /// # Errors
    ///
    /// Returns [`nexacore_types::NexaCoreError::Crypto`] only if the combiner
    /// KDF fails, which cannot happen for the fixed 32-byte output length.
    pub fn encapsulate_deterministic(
        &self,
        seed: [u8; HYBRID_ENCAPS_SEED_LEN],
    ) -> Result<(NexaCoreHybridCiphertext, NexaCoreHybridSharedSecret)> {
        let (x_seed, m_seed) = seed.split_at(X25519_KEY_LEN);
        let mut x_arr = [0u8; X25519_KEY_LEN];
        x_arr.copy_from_slice(x_seed);
        let mut m_arr = [0u8; ML_KEM_768_MESSAGE_LEN];
        m_arr.copy_from_slice(m_seed);

        // DHKEM(X25519): the ephemeral public value is the classical ciphertext.
        let ephemeral = NexaCoreStaticSecret::from_bytes(x_arr);
        x_arr.zeroize();
        let ct_x = ephemeral.public_key();
        let ss_x = ephemeral.diffie_hellman(&self.x25519);

        let (ct_m, ss_m) = self.mlkem.encapsulate_deterministic(m_arr);
        m_arr.zeroize();

        let shared = combine(
            ss_x.as_bytes(),
            ss_m.as_bytes(),
            &ct_x.as_bytes(),
            &ct_m.as_bytes(),
            &self.x25519.as_bytes(),
            &self.mlkem.as_bytes(),
        )?;
        Ok((
            NexaCoreHybridCiphertext {
                x25519: ct_x,
                mlkem: ct_m,
            },
            shared,
        ))
    }
}

impl fmt::Debug for NexaCoreHybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreHybridPublicKey(<x25519+ml-kem-768 public key>)")
    }
}

// =============================================================================
// NexaCoreHybridCiphertext
// =============================================================================

/// A hybrid ciphertext: the `X25519` ephemeral public value concatenated with
/// the `ML-KEM-768` ciphertext.
#[derive(Clone)]
pub struct NexaCoreHybridCiphertext {
    x25519: NexaCorePublicKey,
    mlkem: NexaCoreMlKemCiphertext,
}

impl NexaCoreHybridCiphertext {
    /// Construct a hybrid ciphertext from its [`HYBRID_CIPHERTEXT_LEN`]-byte
    /// form, split as `X25519 ephemeral public (32) ‖ ML-KEM-768 ciphertext
    /// (1088)`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; HYBRID_CIPHERTEXT_LEN]) -> Self {
        let (x_part, ml_part) = bytes.split_at(X25519_KEY_LEN);
        let mut x_arr = [0u8; X25519_KEY_LEN];
        x_arr.copy_from_slice(x_part);
        let mut ml_arr = [0u8; ML_KEM_768_CIPHERTEXT_LEN];
        ml_arr.copy_from_slice(ml_part);
        Self {
            x25519: NexaCorePublicKey::from_bytes(x_arr),
            mlkem: NexaCoreMlKemCiphertext::from_bytes(&ml_arr),
        }
    }

    /// Serialize this hybrid ciphertext to its [`HYBRID_CIPHERTEXT_LEN`]-byte
    /// form (`X25519 ephemeral public ‖ ML-KEM-768 ciphertext`).
    #[must_use]
    pub fn as_bytes(&self) -> [u8; HYBRID_CIPHERTEXT_LEN] {
        let mut out = [0u8; HYBRID_CIPHERTEXT_LEN];
        let (x_part, ml_part) = out.split_at_mut(X25519_KEY_LEN);
        x_part.copy_from_slice(&self.x25519.as_bytes());
        ml_part.copy_from_slice(&self.mlkem.as_bytes());
        out
    }
}

impl fmt::Debug for NexaCoreHybridCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreHybridCiphertext(<x25519+ml-kem-768 ciphertext>)")
    }
}

// =============================================================================
// NexaCoreHybridSharedSecret
// =============================================================================

/// The 256-bit hybrid shared secret output by the combiner KDF.
///
/// Already a KDF output, so it is safe to use directly as symmetric keying
/// material — unlike the raw component secrets. Wipes itself on `Drop`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NexaCoreHybridSharedSecret {
    bytes: [u8; HYBRID_SHARED_SECRET_LEN],
}

impl NexaCoreHybridSharedSecret {
    /// Borrow the raw shared-secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HYBRID_SHARED_SECRET_LEN] {
        &self.bytes
    }
}

impl PartialEq for NexaCoreHybridSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}
impl Eq for NexaCoreHybridSharedSecret {}

impl fmt::Debug for NexaCoreHybridSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreHybridSharedSecret(<redacted>)")
    }
}

// =============================================================================
// Tests — round-trip, component sensitivity, determinism, negative.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, distinct 96-byte key seed for deterministic tests.
    fn key_seed(fill: u8) -> [u8; HYBRID_SEED_LEN] {
        [fill; HYBRID_SEED_LEN]
    }

    /// A fixed, distinct 64-byte encapsulation seed for deterministic tests.
    fn encaps_seed(fill: u8) -> [u8; HYBRID_ENCAPS_SEED_LEN] {
        [fill; HYBRID_ENCAPS_SEED_LEN]
    }

    #[test]
    fn round_trip_recovers_same_secret() {
        let sk = NexaCoreHybridSecretKey::from_seed(key_seed(0x11));
        let pk = sk.public_key();
        let (ct, ss_send) = pk.encapsulate_deterministic(encaps_seed(0x22)).unwrap();
        let ss_recv = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn round_trip_survives_ciphertext_serialization() {
        let sk = NexaCoreHybridSecretKey::from_seed(key_seed(0x33));
        let pk = sk.public_key();
        let (ct, ss_send) = pk.encapsulate_deterministic(encaps_seed(0x44)).unwrap();
        let ct2 = NexaCoreHybridCiphertext::from_bytes(&ct.as_bytes());
        let ss_recv = sk.decapsulate(&ct2).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn deterministic_same_seeds_same_secret() {
        let sk1 = NexaCoreHybridSecretKey::from_seed(key_seed(0x55));
        let sk2 = NexaCoreHybridSecretKey::from_seed(key_seed(0x55));
        // Same key seed derives the same public key.
        assert_eq!(sk1.public_key().as_bytes(), sk2.public_key().as_bytes());
        let (cipher_a, secret_a) = sk1
            .public_key()
            .encapsulate_deterministic(encaps_seed(0x66))
            .unwrap();
        let (cipher_b, secret_b) = sk2
            .public_key()
            .encapsulate_deterministic(encaps_seed(0x66))
            .unwrap();
        // Same key + same encaps seed ⇒ identical ciphertext and secret.
        assert_eq!(cipher_a.as_bytes(), cipher_b.as_bytes());
        assert_eq!(secret_a, secret_b);
    }

    #[test]
    fn secret_changes_when_x25519_ephemeral_changes() {
        let sk = NexaCoreHybridSecretKey::from_seed(key_seed(0x77));
        let pk = sk.public_key();
        // Same ML-KEM message m, different X25519 ephemeral scalar.
        let mut seed_a = encaps_seed(0x00);
        let mut seed_b = encaps_seed(0x00);
        let (x_a, _) = seed_a.split_at_mut(X25519_KEY_LEN);
        x_a.copy_from_slice(&[0xAA; X25519_KEY_LEN]);
        let (x_b, _) = seed_b.split_at_mut(X25519_KEY_LEN);
        x_b.copy_from_slice(&[0xBB; X25519_KEY_LEN]);

        let (_, ss_a) = pk.encapsulate_deterministic(seed_a).unwrap();
        let (_, ss_b) = pk.encapsulate_deterministic(seed_b).unwrap();
        assert_ne!(ss_a, ss_b);
    }

    #[test]
    fn secret_changes_when_mlkem_message_changes() {
        let sk = NexaCoreHybridSecretKey::from_seed(key_seed(0x88));
        let pk = sk.public_key();
        // Same X25519 ephemeral scalar, different ML-KEM message m.
        let mut seed_a = encaps_seed(0x00);
        let mut seed_b = encaps_seed(0x00);
        let (_, m_a) = seed_a.split_at_mut(X25519_KEY_LEN);
        m_a.copy_from_slice(&[0x01; ML_KEM_768_MESSAGE_LEN]);
        let (_, m_b) = seed_b.split_at_mut(X25519_KEY_LEN);
        m_b.copy_from_slice(&[0x02; ML_KEM_768_MESSAGE_LEN]);

        let (_, ss_a) = pk.encapsulate_deterministic(seed_a).unwrap();
        let (_, ss_b) = pk.encapsulate_deterministic(seed_b).unwrap();
        assert_ne!(ss_a, ss_b);
    }

    #[test]
    fn secret_changes_when_recipient_x25519_component_changes() {
        // Two recipients whose seeds differ ONLY in the X25519 half.
        let mut seed_x = key_seed(0x99);
        let (x_half, _) = seed_x.split_at_mut(X25519_KEY_LEN);
        x_half.copy_from_slice(&[0xEE; X25519_KEY_LEN]);

        let base = NexaCoreHybridSecretKey::from_seed(key_seed(0x99));
        let variant = NexaCoreHybridSecretKey::from_seed(seed_x);

        let seed = encaps_seed(0x5A);
        let (_, ss_base) = base.public_key().encapsulate_deterministic(seed).unwrap();
        let (_, ss_var) = variant
            .public_key()
            .encapsulate_deterministic(seed)
            .unwrap();
        assert_ne!(ss_base, ss_var);
    }

    #[test]
    fn secret_changes_when_recipient_mlkem_component_changes() {
        // Two recipients whose seeds differ ONLY in the ML-KEM half.
        let mut seed_m = key_seed(0xA1);
        let (_, ml_half) = seed_m.split_at_mut(X25519_KEY_LEN);
        ml_half.copy_from_slice(&[0xCC; ML_KEM_768_SEED_LEN]);

        let base = NexaCoreHybridSecretKey::from_seed(key_seed(0xA1));
        let variant = NexaCoreHybridSecretKey::from_seed(seed_m);

        let seed = encaps_seed(0x3C);
        let (_, ss_base) = base.public_key().encapsulate_deterministic(seed).unwrap();
        let (_, ss_var) = variant
            .public_key()
            .encapsulate_deterministic(seed)
            .unwrap();
        assert_ne!(ss_base, ss_var);
    }

    #[test]
    fn wrong_secret_key_fails_to_recover() {
        let sk = NexaCoreHybridSecretKey::from_seed(key_seed(0xB2));
        let wrong = NexaCoreHybridSecretKey::from_seed(key_seed(0xC3));
        let (ct, ss_send) = sk
            .public_key()
            .encapsulate_deterministic(encaps_seed(0xD4))
            .unwrap();
        let ss_wrong = wrong.decapsulate(&ct).unwrap();
        assert_ne!(ss_send, ss_wrong);
    }

    #[test]
    fn public_key_bytes_round_trip() {
        let sk = NexaCoreHybridSecretKey::from_seed(key_seed(0xE5));
        let pk = sk.public_key();
        let parsed = NexaCoreHybridPublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert_eq!(pk.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        // All-0xFF ML-KEM half fails the FIPS 203 modulus check.
        let bad = [0xffu8; HYBRID_PUBLIC_KEY_LEN];
        assert!(NexaCoreHybridPublicKey::from_bytes(&bad).is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let sk = NexaCoreHybridSecretKey::from_seed(key_seed(0xF6));
        let secret_key_debug = alloc::format!("{sk:?}");
        assert!(secret_key_debug.contains("redacted"));
        let (_, ss) = sk
            .public_key()
            .encapsulate_deterministic(encaps_seed(0x07))
            .unwrap();
        let shared_debug = alloc::format!("{ss:?}");
        assert!(shared_debug.contains("redacted"));
    }

    #[cfg(feature = "rng")]
    #[test]
    fn round_trip_random() {
        let sk = NexaCoreHybridSecretKey::generate();
        let pk = sk.public_key();
        let (ct, ss_send) = pk.encapsulate().unwrap();
        let ss_recv = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }
}

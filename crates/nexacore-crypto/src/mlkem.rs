//! Post-quantum key encapsulation — `ML-KEM-768` (FIPS 203).
//!
//! Wraps the RustCrypto [`ml_kem`] implementation of the Module-Lattice-based
//! Key-Encapsulation Mechanism standardized in NIST FIPS 203, at the
//! `ML-KEM-768` parameter set (security category 3). Like every other module
//! in this crate, no lattice arithmetic is implemented here — this is the
//! typed composition layer over a vetted primitive.
//!
//! # Roles
//!
//! - The **holder** generates a [`NexaCoreMlKemSecretKey`] (decapsulation key)
//!   and publishes the corresponding [`NexaCoreMlKemPublicKey`] (encapsulation
//!   key).
//! - A **sender** calls [`NexaCoreMlKemPublicKey::encapsulate`] (or the
//!   deterministic variant) to obtain a [`NexaCoreMlKemCiphertext`] and a
//!   [`NexaCoreMlKemSharedSecret`]. The ciphertext travels to the holder.
//! - The holder calls [`NexaCoreMlKemSecretKey::decapsulate`] to recover the
//!   same shared secret.
//!
//! # Determinism and randomness
//!
//! The `rng`-gated [`NexaCoreMlKemSecretKey::generate`] and
//! [`NexaCoreMlKemPublicKey::encapsulate`] source entropy from the platform
//! CSPRNG ([`rand_core::OsRng`]) and forward it to FIPS 203's deterministic
//! core. The deterministic entry points
//! ([`NexaCoreMlKemSecretKey::from_seed`],
//! [`NexaCoreMlKemPublicKey::encapsulate_deterministic`]) take the raw seed /
//! message bytes directly; they exist so the module can be validated against
//! the NIST ACVP known-answer vectors and so bare-metal
//! (`x86_64-unknown-none`) builds — which disable the `rng` feature — can still
//! run the KEM with a kernel-provided seed.
//!
//! # Hybrid migration
//!
//! Phase 4 pairs this KEM with the classical [`crate::kex`] `X25519` exchange
//! into a hybrid `X25519 + ML-KEM-768` shared secret. This module is the
//! post-quantum half; the hybrid combiner is additive and lands separately.
//!
//! # Shared-secret handling
//!
//! As with [`crate::kex`], the raw [`NexaCoreMlKemSharedSecret`] bytes should
//! be passed through a KDF (e.g. `HKDF-SHA-256` from [`crate::kdf`]) before use
//! as a symmetric key, per FIPS 203 guidance on domain separation.

use core::fmt;

use ml_kem::{
    B32, Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768, Seed, SharedKey,
    array::Array,
    kem::{Decapsulate, KeyExport},
};
use nexacore_types::error::{CryptoErrorKind, NexaCoreError, Result};
#[cfg(feature = "rng")]
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of an `ML-KEM-768` encapsulation (public) key.
pub const ML_KEM_768_ENCAPSULATION_KEY_LEN: usize = 1184;

/// Length in bytes of the `ML-KEM-768` decapsulation-key seed (`d || z`).
///
/// This 64-byte seed is the preferred serialization for the private key: it is
/// constant across parameter sets and always reconstructs a valid key, unlike
/// the larger, validation-requiring expanded form.
pub const ML_KEM_768_SEED_LEN: usize = 64;

/// Length in bytes of an `ML-KEM-768` ciphertext (encapsulation).
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;

/// Length in bytes of an `ML-KEM` shared secret (all parameter sets).
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

/// Length in bytes of the encapsulation randomness / message `m`.
pub const ML_KEM_768_MESSAGE_LEN: usize = 32;

// =============================================================================
// NexaCoreMlKemSecretKey (decapsulation key)
// =============================================================================

/// An `ML-KEM-768` decapsulation (private) key.
///
/// The wrapped [`ml_kem::DecapsulationKey`] zeroizes its key material on drop
/// (the crate's `zeroize` feature is enabled workspace-wide), so this wrapper
/// inherits `ZeroizeOnDrop` semantics without extra code.
pub struct NexaCoreMlKemSecretKey {
    inner: DecapsulationKey<MlKem768>,
}

impl NexaCoreMlKemSecretKey {
    /// Deterministically derive a decapsulation key from a 64-byte seed
    /// (`d || z`), per FIPS 203 `ML-KEM.KeyGen_internal`.
    ///
    /// This is the constructor used by the NIST known-answer tests and by
    /// bare-metal builds that mint the seed from a kernel entropy source.
    #[must_use]
    pub fn from_seed(seed: [u8; ML_KEM_768_SEED_LEN]) -> Self {
        Self {
            inner: DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed)),
        }
    }

    /// Generate a fresh decapsulation key from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; the 64-byte seed is drawn from
    /// [`OsRng`] and wiped after the key is derived.
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; ML_KEM_768_SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        let key = Self::from_seed(seed);
        seed.zeroize();
        key
    }

    /// Compute the corresponding encapsulation (public) key.
    #[must_use]
    pub fn public_key(&self) -> NexaCoreMlKemPublicKey {
        NexaCoreMlKemPublicKey {
            inner: self.inner.encapsulation_key().clone(),
        }
    }

    /// Serialize the 64-byte seed (`d || z`) that reconstructs this key.
    ///
    /// This value is private key material — treat it with the same care as the
    /// key itself.
    #[must_use]
    pub fn to_seed_bytes(&self) -> [u8; ML_KEM_768_SEED_LEN] {
        self.inner
            .to_seed()
            .map_or([0u8; ML_KEM_768_SEED_LEN], |seed| {
                let mut out = [0u8; ML_KEM_768_SEED_LEN];
                out.copy_from_slice(seed.as_ref());
                out
            })
    }

    /// Decapsulate `ciphertext` and recover the shared secret.
    ///
    /// FIPS 203 decapsulation never fails: an invalid or tampered ciphertext
    /// yields a pseudo-random secret (implicit rejection) rather than an error,
    /// so the caller must authenticate the shared secret via the surrounding
    /// protocol.
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &NexaCoreMlKemCiphertext) -> NexaCoreMlKemSharedSecret {
        let shared = self.inner.decapsulate(&ciphertext.inner);
        NexaCoreMlKemSharedSecret::from_shared_key(&shared)
    }

    /// Test-only constructor wrapping a raw [`ml_kem::DecapsulationKey`], used
    /// to load the NIST expanded-form known-answer decapsulation key.
    #[cfg(test)]
    pub(crate) fn from_inner(inner: DecapsulationKey<MlKem768>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for NexaCoreMlKemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreMlKemSecretKey(<redacted>)")
    }
}

// =============================================================================
// NexaCoreMlKemPublicKey (encapsulation key)
// =============================================================================

/// An `ML-KEM-768` encapsulation (public) key.
#[derive(Clone)]
pub struct NexaCoreMlKemPublicKey {
    inner: EncapsulationKey<MlKem768>,
}

impl NexaCoreMlKemPublicKey {
    /// Parse an encapsulation key from its 1184-byte serialized form.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InvalidKey`]
    /// if `bytes` fails the FIPS 203 §7.2 encapsulation-key (modulus) check.
    pub fn from_bytes(bytes: &[u8; ML_KEM_768_ENCAPSULATION_KEY_LEN]) -> Result<Self> {
        let encoded = Array::try_from(bytes.as_slice()).map_err(|_| {
            NexaCoreError::crypto(CryptoErrorKind::InvalidKey, "mlkem::public_key::length")
        })?;
        let inner = EncapsulationKey::<MlKem768>::new(&encoded).map_err(|_| {
            NexaCoreError::crypto(
                CryptoErrorKind::InvalidKey,
                "mlkem::public_key::modulus_check",
            )
        })?;
        Ok(Self { inner })
    }

    /// Serialize this encapsulation key to its 1184-byte form.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN] {
        let encoded = self.inner.to_bytes();
        let mut out = [0u8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
        out.copy_from_slice(encoded.as_ref());
        out
    }

    /// Encapsulate a shared secret to the holder of the matching decapsulation
    /// key, drawing the message randomness from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; the 32-byte message is drawn from
    /// [`OsRng`] and wiped after use.
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn encapsulate(&self) -> (NexaCoreMlKemCiphertext, NexaCoreMlKemSharedSecret) {
        let mut message = [0u8; ML_KEM_768_MESSAGE_LEN];
        OsRng.fill_bytes(&mut message);
        let out = self.encapsulate_deterministic(message);
        message.zeroize();
        out
    }

    /// Encapsulate using caller-supplied 32-byte randomness `m`, per FIPS 203
    /// `ML-KEM.Encaps_internal`.
    ///
    /// This is the entry point used by the NIST known-answer tests and by
    /// bare-metal builds. Prefer [`encapsulate`](Self::encapsulate) in
    /// userspace: reusing or biasing `m` is a catastrophic failure of the
    /// scheme.
    #[must_use]
    pub fn encapsulate_deterministic(
        &self,
        m: [u8; ML_KEM_768_MESSAGE_LEN],
    ) -> (NexaCoreMlKemCiphertext, NexaCoreMlKemSharedSecret) {
        let (ct, shared) = self.inner.encapsulate_deterministic(&B32::from(m));
        (
            NexaCoreMlKemCiphertext { inner: ct },
            NexaCoreMlKemSharedSecret::from_shared_key(&shared),
        )
    }
}

impl fmt::Debug for NexaCoreMlKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreMlKemPublicKey(<ml-kem-768 encapsulation key>)")
    }
}

// =============================================================================
// NexaCoreMlKemCiphertext
// =============================================================================

/// An `ML-KEM-768` ciphertext (the encapsulated form of a shared secret).
#[derive(Clone)]
pub struct NexaCoreMlKemCiphertext {
    inner: Ciphertext<MlKem768>,
}

impl NexaCoreMlKemCiphertext {
    /// Construct a ciphertext from its 1088-byte serialized form.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; ML_KEM_768_CIPHERTEXT_LEN]) -> Self {
        let inner = Ciphertext::<MlKem768>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
            // The input is a fixed-size array whose length equals the
            // ML-KEM-768 ciphertext size, so `try_from` cannot fail here.
            unreachable!("ciphertext length is a compile-time constant")
        });
        Self { inner }
    }

    /// Serialize this ciphertext to its 1088-byte form.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; ML_KEM_768_CIPHERTEXT_LEN] {
        let mut out = [0u8; ML_KEM_768_CIPHERTEXT_LEN];
        out.copy_from_slice(self.inner.as_ref());
        out
    }
}

impl fmt::Debug for NexaCoreMlKemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreMlKemCiphertext(<ml-kem-768 ciphertext>)")
    }
}

// =============================================================================
// NexaCoreMlKemSharedSecret
// =============================================================================

/// A 256-bit shared secret produced by `ML-KEM-768` encapsulation /
/// decapsulation.
///
/// Pass through a KDF before using as a symmetric key — see the module docs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NexaCoreMlKemSharedSecret {
    bytes: [u8; ML_KEM_768_SHARED_SECRET_LEN],
}

impl NexaCoreMlKemSharedSecret {
    /// Copy the 32-byte shared key out of the `ml-kem` array.
    fn from_shared_key(shared: &SharedKey) -> Self {
        let mut bytes = [0u8; ML_KEM_768_SHARED_SECRET_LEN];
        bytes.copy_from_slice(shared.as_ref());
        Self { bytes }
    }

    /// Borrow the raw shared-secret bytes. Avoid using these directly as a
    /// symmetric key — run them through a KDF first.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ML_KEM_768_SHARED_SECRET_LEN] {
        &self.bytes
    }
}

impl PartialEq for NexaCoreMlKemSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}
impl Eq for NexaCoreMlKemSharedSecret {}

impl fmt::Debug for NexaCoreMlKemSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreMlKemSharedSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::{DecapsulationKey, ExpandedDecapsulationKey, MlKem768};

    use super::*;

    // ML-KEM-768 known-answer test vectors from the NIST ACVP test suite
    // (FIPS 203). Source: usnistgov/ACVP-Server, gen-val/json-files,
    // ML-KEM-keyGen-FIPS203 and ML-KEM-encapDecap-FIPS203 internal projections,
    // parameter set ML-KEM-768. These are authoritative, independently-sourced
    // vectors (NOT produced by the `ml-kem` crate under test).
    //
    // keyGen test case tcId=26; encapsulation (AFT) test case tcId=26.
    const KAT_KEYGEN_D: &str = "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0";
    const KAT_KEYGEN_Z: &str = "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0";
    const KAT_KEYGEN_EK: &str = include_str!("mlkem_kat/keygen_ek.hex");

    const KAT_ENCAPS_EK: &str = include_str!("mlkem_kat/encaps_ek.hex");
    const KAT_ENCAPS_DK: &str = include_str!("mlkem_kat/encaps_dk.hex");
    const KAT_ENCAPS_M: &str = "7d5201502fad05b1463bc2212d6aec1c8503204c491f12d9366ae750144b7831";
    const KAT_ENCAPS_C: &str = include_str!("mlkem_kat/encaps_c.hex");
    const KAT_ENCAPS_K: &str = "11b62291b1a9d307c8240d70be0b45436db445793173f6e79fcd2b273d7f3b01";

    fn hexn<const N: usize>(s: &str) -> [u8; N] {
        let v = hex::decode(s.trim()).unwrap();
        assert_eq!(v.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    fn kat_seed() -> [u8; ML_KEM_768_SEED_LEN] {
        let d = hexn::<32>(KAT_KEYGEN_D);
        let z = hexn::<32>(KAT_KEYGEN_Z);
        let mut seed = [0u8; ML_KEM_768_SEED_LEN];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);
        seed
    }

    #[test]
    fn keygen_matches_nist_kat() {
        let seed = kat_seed();
        let sk = NexaCoreMlKemSecretKey::from_seed(seed);
        let ek = sk.public_key();
        assert_eq!(
            ek.as_bytes().as_slice(),
            hexn::<ML_KEM_768_ENCAPSULATION_KEY_LEN>(KAT_KEYGEN_EK).as_slice(),
        );
        assert_eq!(sk.to_seed_bytes(), seed);
    }

    #[test]
    fn encapsulate_matches_nist_kat() {
        let ek_bytes = hexn::<ML_KEM_768_ENCAPSULATION_KEY_LEN>(KAT_ENCAPS_EK);
        let pk = NexaCoreMlKemPublicKey::from_bytes(&ek_bytes).unwrap();
        let m = hexn::<ML_KEM_768_MESSAGE_LEN>(KAT_ENCAPS_M);
        let (ct, ss) = pk.encapsulate_deterministic(m);
        assert_eq!(
            ct.as_bytes().as_slice(),
            hexn::<ML_KEM_768_CIPHERTEXT_LEN>(KAT_ENCAPS_C).as_slice(),
        );
        assert_eq!(
            ss.as_bytes(),
            &hexn::<ML_KEM_768_SHARED_SECRET_LEN>(KAT_ENCAPS_K)
        );
    }

    #[test]
    #[allow(deprecated)]
    fn decapsulate_matches_nist_kat() {
        // The expanded (legacy) decapsulation-key encoding is deprecated in
        // `ml-kem`, but it is the only form the NIST encapDecap vectors ship,
        // so we use it here — scoped to this test — to obtain an official
        // decapsulation known-answer.
        use ml_kem::ExpandedKeyEncoding;

        // Load the official expanded decapsulation key that matches the
        // encapsulation-KAT ciphertext, and confirm decapsulation reproduces
        // the official shared key `k`.
        let dk_bytes = hexn::<2400>(KAT_ENCAPS_DK);
        let expanded = ExpandedDecapsulationKey::<MlKem768>::try_from(dk_bytes.as_slice()).unwrap();
        let inner = DecapsulationKey::<MlKem768>::from_expanded_bytes(&expanded).unwrap();
        let sk = NexaCoreMlKemSecretKey::from_inner(inner);
        let ct =
            NexaCoreMlKemCiphertext::from_bytes(&hexn::<ML_KEM_768_CIPHERTEXT_LEN>(KAT_ENCAPS_C));
        let ss = sk.decapsulate(&ct);
        assert_eq!(
            ss.as_bytes(),
            &hexn::<ML_KEM_768_SHARED_SECRET_LEN>(KAT_ENCAPS_K)
        );
    }

    #[test]
    fn round_trip_deterministic() {
        let sk = NexaCoreMlKemSecretKey::from_seed(kat_seed());
        let pk = sk.public_key();
        let (ct, ss_send) = pk.encapsulate_deterministic([0x42u8; ML_KEM_768_MESSAGE_LEN]);
        let ss_recv = sk.decapsulate(&ct);
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn public_key_bytes_round_trip() {
        let ek_bytes = hexn::<ML_KEM_768_ENCAPSULATION_KEY_LEN>(KAT_ENCAPS_EK);
        let pk = NexaCoreMlKemPublicKey::from_bytes(&ek_bytes).unwrap();
        assert_eq!(pk.as_bytes(), ek_bytes);
    }

    #[test]
    fn ciphertext_bytes_round_trip() {
        let c = hexn::<ML_KEM_768_CIPHERTEXT_LEN>(KAT_ENCAPS_C);
        let ct = NexaCoreMlKemCiphertext::from_bytes(&c);
        assert_eq!(ct.as_bytes(), c);
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        let bad = [0xffu8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
        assert!(NexaCoreMlKemPublicKey::from_bytes(&bad).is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let sk = NexaCoreMlKemSecretKey::from_seed(kat_seed());
        let secret_debug = alloc::format!("{sk:?}");
        assert!(secret_debug.contains("redacted"));
        let (_, ss) = sk
            .public_key()
            .encapsulate_deterministic([1u8; ML_KEM_768_MESSAGE_LEN]);
        let shared_debug = alloc::format!("{ss:?}");
        assert!(shared_debug.contains("redacted"));
    }

    #[cfg(feature = "rng")]
    #[test]
    fn round_trip_random() {
        let sk = NexaCoreMlKemSecretKey::generate();
        let pk = sk.public_key();
        let (ct, ss_send) = pk.encapsulate();
        let ss_recv = sk.decapsulate(&ct);
        assert_eq!(ss_send, ss_recv);
    }
}

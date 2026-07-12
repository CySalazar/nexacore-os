//! Post-quantum digital signatures — ML-DSA (FIPS 204).
//!
//! Wraps the RustCrypto [`ml_dsa`] crate (a pure-Rust, `no_std`
//! implementation of FIPS 204 / CRYSTALS-Dilithium) behind
//! NexaCore-typed keys and signatures, mirroring the misuse-resistant
//! shape of the [`crate::signing`] (`Ed25519`) module.
//!
//! # Parameter set
//!
//! This module fixes the **ML-DSA-65** parameter set (NIST security
//! category 3, ≈192-bit classical / PQ level 3). It is the parameter
//! set the FIPS 204 authors recommend as the best balance of security
//! and performance, and it matches the level-3 posture of NexaCore's
//! ML-KEM-768 key-encapsulation. Encoded sizes: 32-byte seed,
//! 1952-byte verifying key, 3309-byte signature.
//!
//! # Interface (internal vs. external)
//!
//! The public [`NexaCoreMlDsaSigningKey::sign`] /
//! [`NexaCoreMlDsaVerifyingKey::verify`] pair implements the FIPS 204
//! **external** signature interface (Algorithm 2 / 3): the message is
//! bound to a domain separator and an optional caller **context**
//! string before hashing, which prevents cross-protocol signature
//! reuse. Signing is the FIPS 204 **deterministic** variant
//! (`rnd = 0^32`), so a given `(key, context, message)` always yields
//! the same signature — friendly to reproducible builds and KAT.
//!
//! # Misuse-resistant API
//!
//! * Secret keys are typed wrappers, are `Zeroize`-on-`Drop`, do not
//!   print their bytes via [`fmt::Debug`], and are not [`Clone`]
//!   (secret material travels by ownership).
//! * Verification is constant-time inside `ml_dsa`; signature equality
//!   goes through [`subtle::ConstantTimeEq`].
//! * Fresh key generation ([`NexaCoreMlDsaSigningKey::generate`]) is
//!   gated behind the `rng` feature; bare-metal builds derive keys from
//!   a kernel-supplied seed via [`NexaCoreMlDsaSigningKey::from_seed`].
//!
//! # Validation
//!
//! Keygen (seed → public key), deterministic signing, and
//! verify-accept / tamper-reject are validated against the official
//! **NIST ACVP FIPS 204** ML-DSA-65 vectors (see `src/mldsa_kat/`).

use core::fmt;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Seed, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use nexacore_types::error::{CryptoErrorKind, NexaCoreError, Result};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of an ML-DSA-65 key-generation seed.
pub const SEED_LEN: usize = 32;

/// Length in bytes of an encoded ML-DSA-65 verifying (public) key.
pub const VERIFYING_KEY_LEN: usize = 1952;

/// Length in bytes of an encoded ML-DSA-65 signature.
pub const SIGNATURE_LEN: usize = 3309;

/// Maximum length of a FIPS 204 signing context string, in bytes.
pub const MAX_CONTEXT_LEN: usize = 255;

// =============================================================================
// NexaCoreMlDsaSigningKey
// =============================================================================

/// ML-DSA-65 signing (private) key.
///
/// Constructed from a 32-byte seed; the expanded key and matching
/// public key are derived deterministically per FIPS 204 Algorithm 6.
/// `ZeroizeOnDrop` wipes the secret material (both the seed and the
/// expanded key) when the value goes out of scope. Cloning is
/// intentionally not derived.
pub struct NexaCoreMlDsaSigningKey {
    inner: MlDsaSigningKey<MlDsa65>,
}

impl NexaCoreMlDsaSigningKey {
    /// Deterministically derive a signing key from a 32-byte seed.
    ///
    /// This is the FIPS 204 `ML-DSA.KeyGen_internal` derivation and is
    /// the bare-metal / KAT construction path.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut xi = Seed::default();
        xi.copy_from_slice(seed);
        Self {
            inner: MlDsaSigningKey::from_seed(&xi),
        }
    }

    /// Generate a fresh signing key from the platform CSPRNG.
    ///
    /// Gated behind the `rng` feature; bare-metal builds use
    /// [`Self::from_seed`] with a kernel-provided seed.
    ///
    /// # Panics
    ///
    /// Panics if the platform CSPRNG fails to produce entropy.
    #[cfg(feature = "rng")]
    #[must_use]
    pub fn generate() -> Self {
        use ml_dsa::Generate;
        Self {
            inner: MlDsaSigningKey::<MlDsa65>::generate(),
        }
    }

    /// Serialize the 32-byte seed that reconstructs this key.
    ///
    /// The returned value is secret key material — handle with care.
    #[must_use]
    pub fn to_seed(&self) -> [u8; SEED_LEN] {
        let seed = self.inner.to_seed();
        let mut out = [0u8; SEED_LEN];
        out.copy_from_slice(&seed);
        out
    }

    /// Return the corresponding verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> NexaCoreMlDsaVerifyingKey {
        NexaCoreMlDsaVerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign `message` with an empty context. Deterministic.
    ///
    /// Equivalent to [`Self::sign_with_context`] with an empty context.
    ///
    /// # Panics
    ///
    /// Does not panic: an empty context is always within
    /// [`MAX_CONTEXT_LEN`], the only condition under which the underlying
    /// signer can reject the request.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> NexaCoreMlDsaSignature {
        self.sign_with_context(message, &[])
            .unwrap_or_else(|_| unreachable!("empty context is within the FIPS 204 limit"))
    }

    /// Sign `message` bound to `context`. Deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InvalidKey`]
    /// if `context` exceeds [`MAX_CONTEXT_LEN`] bytes (the FIPS 204 limit).
    pub fn sign_with_context(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<NexaCoreMlDsaSignature> {
        let sig = self
            .inner
            .expanded_key()
            .sign_deterministic(message, context)
            .map_err(|_| {
                NexaCoreError::crypto(CryptoErrorKind::InvalidKey, "mldsa::sign::context_too_long")
            })?;
        let enc = sig.encode();
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes.copy_from_slice(&enc);
        Ok(NexaCoreMlDsaSignature { bytes })
    }
}

impl Zeroize for NexaCoreMlDsaSigningKey {
    fn zeroize(&mut self) {
        // Replace the secret with a deterministic dummy key. The prior
        // inner `SigningKey` (itself `ZeroizeOnDrop`) wipes its seed and
        // expanded secret material as it is dropped by the assignment.
        self.inner = MlDsaSigningKey::from_seed(&Seed::default());
    }
}

impl ZeroizeOnDrop for NexaCoreMlDsaSigningKey {}

impl fmt::Debug for NexaCoreMlDsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NexaCoreMlDsaSigningKey(<redacted>)")
    }
}

// =============================================================================
// NexaCoreMlDsaVerifyingKey
// =============================================================================

/// ML-DSA-65 verifying (public) key.
#[derive(Clone, PartialEq)]
pub struct NexaCoreMlDsaVerifyingKey {
    inner: MlDsaVerifyingKey<MlDsa65>,
}

// Public-key equality is a total, reflexive byte comparison; the inner
// `ml_dsa::VerifyingKey` only derives `PartialEq`, so we assert `Eq`
// explicitly (there are no NaN-like values in the encoding).
impl Eq for NexaCoreMlDsaVerifyingKey {}

impl NexaCoreMlDsaVerifyingKey {
    /// Decode a verifying key from its 1952-byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::InvalidKey`]
    /// if `bytes` is not exactly [`VERIFYING_KEY_LEN`] bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(|_| {
            NexaCoreError::crypto(CryptoErrorKind::InvalidKey, "mldsa::vk_from_bytes")
        })?;
        Ok(Self {
            inner: MlDsaVerifyingKey::<MlDsa65>::decode(&enc),
        })
    }

    /// Serialize this verifying key to its 1952-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        let enc = self.inner.encode();
        let mut out = [0u8; VERIFYING_KEY_LEN];
        out.copy_from_slice(&enc);
        out
    }

    /// Verify `signature` over `message` with an empty context.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with
    /// [`CryptoErrorKind::InvalidSignature`] on any verification failure.
    pub fn verify(&self, message: &[u8], signature: &NexaCoreMlDsaSignature) -> Result<()> {
        self.verify_with_context(message, &[], signature)
    }

    /// Verify `signature` over `message` bound to `context`.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with
    /// [`CryptoErrorKind::InvalidSignature`] if `context` is longer than
    /// [`MAX_CONTEXT_LEN`], if the signature bytes do not decode to a
    /// well-formed ML-DSA signature, or if verification does not hold.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &NexaCoreMlDsaSignature,
    ) -> Result<()> {
        let enc =
            EncodedSignature::<MlDsa65>::try_from(signature.bytes.as_slice()).map_err(|_| {
                NexaCoreError::crypto(CryptoErrorKind::InvalidSignature, "mldsa::verify::length")
            })?;
        let sig = MlDsaSignature::<MlDsa65>::decode(&enc).ok_or_else(|| {
            NexaCoreError::crypto(CryptoErrorKind::InvalidSignature, "mldsa::verify::decode")
        })?;
        if self.inner.verify_with_context(message, context, &sig) {
            Ok(())
        } else {
            Err(NexaCoreError::crypto(
                CryptoErrorKind::InvalidSignature,
                "mldsa::verify",
            ))
        }
    }
}

impl fmt::Debug for NexaCoreMlDsaVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.as_bytes();
        write!(
            f,
            "NexaCoreMlDsaVerifyingKey({:02x}{:02x}{:02x}{:02x}…)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

// =============================================================================
// NexaCoreMlDsaSignature
// =============================================================================

/// ML-DSA-65 signature (3309 bytes, `c_tilde || z || h`).
#[derive(Clone)]
pub struct NexaCoreMlDsaSignature {
    bytes: [u8; SIGNATURE_LEN],
}

impl NexaCoreMlDsaSignature {
    /// Construct a signature from its 3309-byte encoding.
    ///
    /// This performs a length check only; structural validity is
    /// enforced at verification time.
    ///
    /// # Errors
    ///
    /// Returns [`NexaCoreError::Crypto`] with
    /// [`CryptoErrorKind::InvalidSignature`] if `bytes` is not exactly
    /// [`SIGNATURE_LEN`] bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| {
            NexaCoreError::crypto(CryptoErrorKind::InvalidSignature, "mldsa::sig_from_bytes")
        })?;
        Ok(Self { bytes: arr })
    }

    /// Borrow the signature's 3309-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.bytes
    }
}

impl PartialEq for NexaCoreMlDsaSignature {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}
impl Eq for NexaCoreMlDsaSignature {}

impl fmt::Debug for NexaCoreMlDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NexaCoreMlDsaSignature({:02x}{:02x}{:02x}{:02x}…)",
            self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]
        )
    }
}

// =============================================================================
// Tests — NIST ACVP FIPS 204 KAT + round-trip + negative.
// =============================================================================

#[cfg(test)]
#[path = "mldsa_kat/mod.rs"]
mod mldsa_kat;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use ml_dsa::{
        B32, EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes,
        MlDsa65, Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    };

    use super::*;
    use crate::mldsa::mldsa_kat as kat;

    fn hex_bytes(s: &str) -> Vec<u8> {
        hex::decode(s.trim()).unwrap()
    }

    fn seed32(s: &str) -> [u8; SEED_LEN] {
        hex_bytes(s).try_into().unwrap()
    }

    // ---- Size sanity: our consts match the ml-dsa parameter set --------------

    #[test]
    fn parameter_sizes_match_ml_dsa_65() {
        assert_eq!(
            EncodedVerifyingKey::<MlDsa65>::default().len(),
            VERIFYING_KEY_LEN
        );
        assert_eq!(EncodedSignature::<MlDsa65>::default().len(), SIGNATURE_LEN);
    }

    // ---- NIST ACVP keyGen: seed → public key (through the wrapper) -----------

    #[test]
    fn acvp_keygen_seed_to_public_key() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&seed32(kat::KEYGEN_SEED));
        let vk = sk.verifying_key();
        assert_eq!(
            vk.as_bytes().as_slice(),
            hex_bytes(kat::KEYGEN_PK).as_slice()
        );
    }

    // ---- NIST ACVP sigGen: deterministic signature (internal interface) ------

    #[test]
    fn acvp_siggen_deterministic_signature() {
        let sk_bytes =
            ExpandedSigningKeyBytes::<MlDsa65>::try_from(hex_bytes(kat::SIGGEN_SK).as_slice())
                .unwrap();
        #[allow(deprecated)]
        let esk = ExpandedSigningKey::<MlDsa65>::from_expanded(&sk_bytes);

        let msg = hex_bytes(kat::SIGGEN_MSG);
        let rnd = B32::default(); // deterministic variant: rnd = 0^32
        let sig = esk.sign_internal(&[msg.as_slice()], &rnd);

        assert_eq!(
            sig.encode().as_slice(),
            hex_bytes(kat::SIGGEN_SIG).as_slice()
        );
    }

    // ---- NIST ACVP sigVer: accept + tamper reject (internal interface) -------

    fn acvp_verify_internal(pk_hex: &str, msg_hex: &str, sig_hex: &str) -> bool {
        let vk_bytes =
            EncodedVerifyingKey::<MlDsa65>::try_from(hex_bytes(pk_hex).as_slice()).unwrap();
        let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&vk_bytes);

        let sig_bytes =
            EncodedSignature::<MlDsa65>::try_from(hex_bytes(sig_hex).as_slice()).unwrap();
        let msg = hex_bytes(msg_hex);
        // A structurally invalid signature (`decode` → None) is a rejection.
        MlDsaSignature::<MlDsa65>::decode(&sig_bytes)
            .is_some_and(|sig| vk.verify_internal(&msg, &sig))
    }

    #[test]
    fn acvp_sigver_accepts_valid_signature() {
        assert!(acvp_verify_internal(
            kat::SIGVER_PK,
            kat::SIGVER_ACCEPT_MSG,
            kat::SIGVER_ACCEPT_SIG,
        ));
    }

    #[test]
    fn acvp_sigver_rejects_modified_message() {
        assert!(!acvp_verify_internal(
            kat::SIGVER_PK,
            kat::SIGVER_REJECT_MSG_MSG,
            kat::SIGVER_REJECT_MSG_SIG,
        ));
    }

    #[test]
    fn acvp_sigver_rejects_modified_signature() {
        assert!(!acvp_verify_internal(
            kat::SIGVER_PK,
            kat::SIGVER_REJECT_SIG_MSG,
            kat::SIGVER_REJECT_SIG_SIG,
        ));
    }

    // ---- Wrapper round-trips (external FIPS 204 interface) --------------------

    #[test]
    fn wrapper_sign_verify_round_trip() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[7u8; SEED_LEN]);
        let vk = sk.verifying_key();
        let msg = b"NexaCore post-quantum handshake";
        let sig = sk.sign(msg);
        vk.verify(msg, &sig).unwrap();
    }

    #[test]
    fn wrapper_sign_is_deterministic() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[9u8; SEED_LEN]);
        let msg = b"deterministic";
        assert_eq!(sk.sign(msg).to_bytes(), sk.sign(msg).to_bytes());
    }

    #[test]
    fn wrapper_context_binds_signature() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[11u8; SEED_LEN]);
        let vk = sk.verifying_key();
        let msg = b"payload";
        let sig = sk.sign_with_context(msg, b"context-A").unwrap();
        // Correct context verifies; a different context does not.
        vk.verify_with_context(msg, b"context-A", &sig).unwrap();
        assert!(vk.verify_with_context(msg, b"context-B", &sig).is_err());
        // Empty-context `verify` also rejects a context-bound signature.
        assert!(vk.verify(msg, &sig).is_err());
    }

    #[test]
    fn wrapper_wrong_message_rejected() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[13u8; SEED_LEN]);
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

    #[test]
    fn wrapper_wrong_key_rejected() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[1u8; SEED_LEN]);
        let other = NexaCoreMlDsaSigningKey::from_seed(&[2u8; SEED_LEN]).verifying_key();
        let sig = sk.sign(b"msg");
        assert!(other.verify(b"msg", &sig).is_err());
    }

    #[test]
    fn wrapper_tampered_signature_rejected() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[3u8; SEED_LEN]);
        let vk = sk.verifying_key();
        let sig = sk.sign(b"msg");
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 0x01;
        let bad = NexaCoreMlDsaSignature::from_bytes(&bytes).unwrap();
        assert!(vk.verify(b"msg", &bad).is_err());
    }

    #[test]
    fn context_too_long_is_rejected() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[5u8; SEED_LEN]);
        let long_ctx = [0u8; MAX_CONTEXT_LEN + 1];
        let err = sk.sign_with_context(b"msg", &long_ctx).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => assert_eq!(kind, CryptoErrorKind::InvalidKey),
            _ => panic!("expected Crypto::InvalidKey"),
        }
    }

    // ---- Serialization round-trips ------------------------------------------

    #[test]
    fn verifying_key_bytes_round_trip() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[21u8; SEED_LEN]);
        let vk = sk.verifying_key();
        let bytes = vk.as_bytes();
        let vk2 = NexaCoreMlDsaVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, vk2);
        let sig = sk.sign(b"round");
        vk2.verify(b"round", &sig).unwrap();
    }

    #[test]
    fn signature_bytes_round_trip() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[22u8; SEED_LEN]);
        let sig = sk.sign(b"round");
        let sig2 = NexaCoreMlDsaSignature::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn from_bytes_rejects_bad_length() {
        assert!(NexaCoreMlDsaVerifyingKey::from_bytes(&[0u8; 10]).is_err());
        assert!(NexaCoreMlDsaSignature::from_bytes(&[0u8; 10]).is_err());
    }

    // ---- Secret hygiene ------------------------------------------------------

    #[test]
    fn signing_key_debug_does_not_leak() {
        let sk = NexaCoreMlDsaSigningKey::from_seed(&[0xCD; SEED_LEN]);
        let dbg = alloc::format!("{sk:?}");
        assert!(!dbg.contains("cd"));
        assert!(dbg.contains("redacted"));
    }

    #[cfg(feature = "rng")]
    #[test]
    fn generate_round_trip() {
        let sk = NexaCoreMlDsaSigningKey::generate();
        let vk = sk.verifying_key();
        let msg = b"random key";
        let sig = sk.sign(msg);
        vk.verify(msg, &sig).unwrap();
    }
}

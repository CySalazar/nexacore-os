//! Vendor-neutral sealing abstraction and the software-only security profile
//! (WS10-08).
//!
//! NexaCore must run **fully** even with no confidential-computing hardware:
//! sealing (protecting the PII vault key, the full-disk-encryption key, and
//! persistent capabilities at rest) is expressed against one
//! [`SealingProvider`] trait with three backends — a hardware TEE, a TPM 2.0,
//! and a pure-software keystore — selected best-available at runtime.  The
//! resulting [`SecurityProfile`] is surfaced to settings and the mesh so a
//! node's trust tier is explicit and honest.
//!
//! Host-testable here (pure, no RNG, `no_std`): the trait, the backend
//! selection, the `SecurityProfile` policy, and a **real** software keystore
//! that derives subkeys with HKDF-SHA-256 and seals with ChaCha20-Poly1305
//! (deterministic counter nonces) over [`nexacore_crypto`].  The Argon2id
//! master-key derivation (memory-hard, needs the crypto `rng`/std feature), the
//! TPM 2.0 owner-hierarchy backend, and `mlock` are gated behind their seams.

use alloc::vec::Vec;

use nexacore_crypto::{
    aead::{self, NONCE_LEN, NexaCoreAeadKey, NexaCoreCiphertext, NexaCoreNonce},
    kdf,
};

use crate::sealed_keys::{SealPolicy, SealedBlob};

/// Which sealing backend a provider speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealingBackendKind {
    /// A hardware confidential-computing TEE (Intel TDX / AMD SEV-SNP).
    HardwareTee,
    /// A TPM 2.0 (measured boot + owner-hierarchy sealing).
    Tpm2,
    /// A pure-software keystore (no hardware root of trust).
    SoftwareKeystore,
}

/// Why a sealing operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealingError {
    /// The backend is present but the operation is not yet implemented (TPM).
    Unsupported,
    /// Key derivation failed.
    KeyDerivation,
    /// Encryption failed.
    SealFailed,
    /// Decryption / authentication failed (wrong key or tampering).
    UnsealFailed,
    /// The blob was shorter than the minimum envelope.
    Malformed,
}

impl core::fmt::Display for SealingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Unsupported => "sealing backend not implemented",
            Self::KeyDerivation => "key derivation failed",
            Self::SealFailed => "seal failed",
            Self::UnsealFailed => "unseal failed",
            Self::Malformed => "malformed sealed blob",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SealingError {}

/// Seal / unseal / derive across a hardware TEE, a TPM, or software.
pub trait SealingProvider {
    /// Which backend this provider implements.
    fn backend_kind(&self) -> SealingBackendKind;

    /// Seal `plaintext` under `policy`, returning an opaque blob.
    ///
    /// # Errors
    /// Returns [`SealingError`] if the backend cannot seal.
    fn seal(&self, plaintext: &[u8], policy: &SealPolicy) -> Result<SealedBlob, SealingError>;

    /// Unseal a blob previously produced by [`seal`](SealingProvider::seal).
    ///
    /// # Errors
    /// Returns [`SealingError`] on authentication failure or malformed input.
    fn unseal(&self, blob: &SealedBlob) -> Result<Vec<u8>, SealingError>;

    /// Derive a 32-byte subkey bound to `context` (HKDF-style).
    ///
    /// # Errors
    /// Returns [`SealingError::KeyDerivation`] if derivation fails.
    fn derive_subkey(&self, context: &[u8]) -> Result<[u8; 32], SealingError>;
}

// ---------------------------------------------------------------------------
// SecurityProfile (WS10-08.9)
// ---------------------------------------------------------------------------

/// The node's security profile, derived from its active sealing backend.
///
/// Per NCIP-024 every profile may **originate and consume** mesh messages; only
/// hardware-rooted profiles may **contribute Tier-2** (relay/compute) capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Hardware TEE root of trust (Tier 1).
    HardwareTee,
    /// TPM 2.0 measured boot (Tier 2).
    Tpm,
    /// Software-only, no hardware root of trust (Tier 3).
    SoftwareOnly,
}

impl SecurityProfile {
    /// The profile implied by an active sealing backend.
    #[must_use]
    pub const fn from_backend(kind: SealingBackendKind) -> Self {
        match kind {
            SealingBackendKind::HardwareTee => Self::HardwareTee,
            SealingBackendKind::Tpm2 => Self::Tpm,
            SealingBackendKind::SoftwareKeystore => Self::SoftwareOnly,
        }
    }

    /// The mesh trust tier (1 = highest).
    #[must_use]
    pub const fn mesh_tier(self) -> u8 {
        match self {
            Self::HardwareTee => 1,
            Self::Tpm => 2,
            Self::SoftwareOnly => 3,
        }
    }

    /// Every profile may originate mesh messages.
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "per-profile capability that NCIP-024 currently grants to every profile; method form keeps the matrix uniform and future-proof"
    )]
    pub const fn can_originate(self) -> bool {
        true
    }

    /// Every profile may consume mesh messages.
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "per-profile capability that NCIP-024 currently grants to every profile; method form keeps the matrix uniform and future-proof"
    )]
    pub const fn can_consume(self) -> bool {
        true
    }

    /// Only hardware-rooted profiles may contribute Tier-2 relay/compute.
    #[must_use]
    pub const fn can_contribute_tier2(self) -> bool {
        matches!(self, Self::HardwareTee | Self::Tpm)
    }

    /// A stable human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HardwareTee => "hardware-tee",
            Self::Tpm => "tpm",
            Self::SoftwareOnly => "software-only",
        }
    }
}

// ---------------------------------------------------------------------------
// Backend probe + best-available selection (WS10-08.2)
// ---------------------------------------------------------------------------

/// Which sealing backends the platform can use (software is always available).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SealingAvailability {
    /// A hardware TEE backend can be constructed.
    pub hardware_tee: bool,
    /// A TPM 2.0 backend can be constructed.
    pub tpm2: bool,
}

/// Select the best-available sealing backend: TEE → TPM 2.0 → software.
///
/// Software is the always-present floor, so this never fails.
#[must_use]
pub const fn select_sealing_backend(avail: SealingAvailability) -> SealingBackendKind {
    if avail.hardware_tee {
        SealingBackendKind::HardwareTee
    } else if avail.tpm2 {
        SealingBackendKind::Tpm2
    } else {
        SealingBackendKind::SoftwareKeystore
    }
}

/// The [`SecurityProfile`] the platform runs at given its availability.
#[must_use]
pub const fn current_security_profile(avail: SealingAvailability) -> SecurityProfile {
    SecurityProfile::from_backend(select_sealing_backend(avail))
}

// ---------------------------------------------------------------------------
// Software keystore (WS10-08.3, .4)
// ---------------------------------------------------------------------------

/// Derives the keystore master key from a passphrase and a device-bound salt.
///
/// The production implementation is **Argon2id** (memory-hard, RFC 9106) via
/// `nexacore_crypto::kdf::argon2id_derive`; it needs the crypto `rng`/std
/// feature, so it binds in behind this seam.  Host tests use a deterministic
/// stub to exercise the keystore logic.
pub trait MasterKeyKdf {
    /// Derive a 32-byte master key from `passphrase` and device `salt`.
    fn derive_master_key(&self, passphrase: &[u8], salt: &[u8]) -> [u8; 32];
}

/// 32 bytes of key material zeroized on drop (mirrors `TeeSharedKey`; this
/// crate intentionally avoids the `zeroize` dependency, see `sealed_keys`).
struct KeyMaterial([u8; 32]);

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: `byte` is a valid, aligned `&mut u8`; the volatile write
            // defeats dead-store elimination of the zeroization.
            #[allow(unsafe_code)]
            unsafe {
                core::ptr::write_volatile(byte, 0u8);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// Disjoint HKDF domains. Each `info` string has a distinct fixed prefix so no
// caller-supplied `derive_subkey` context can ever collide with the seal-key or
// nonce domains (the confused-deputy / key-separation guarantee).
/// Domain label for the per-keystore seal key.
const SEAL_KEY_INFO: &[u8] = b"nexacore/WS10-08/software-keystore/seal-key/v1";
/// Domain prefix for caller subkeys (`derive_subkey`).
const SUBKEY_INFO_PREFIX: &[u8] = b"nexacore/WS10-08/software-keystore/subkey/v1/";
/// Domain prefix for the synthetic, content-bound seal nonce.
const NONCE_INFO_PREFIX: &[u8] = b"nexacore/WS10-08/software-keystore/seal-nonce/v1/";

/// A pure-software [`SealingProvider`]: HKDF subkeys + ChaCha20-Poly1305 seals.
///
/// The master key never leaves the struct (and is zeroized on drop).  Sealing is
/// **deterministic / SIV-style**: the nonce is a master-keyed PRF of the AAD and
/// the plaintext (`synthetic_nonce`), so distinct plaintexts get distinct
/// nonces while the same `(policy, plaintext)` is stable.  This eliminates any
/// `(key, nonce)` reuse with *different* data — including across keystore
/// re-instantiations, since there is no resettable counter.  Sealing the
/// identical secret twice yields the identical blob, an accepted property for
/// at-rest key sealing.
pub struct SoftwareKeystore {
    master: KeyMaterial,
}

impl SoftwareKeystore {
    /// Construct a keystore from a raw 32-byte master key (host tests / when the
    /// master is already sealed elsewhere).
    #[must_use]
    pub const fn from_master_key(master: [u8; 32]) -> Self {
        Self {
            master: KeyMaterial(master),
        }
    }

    /// Construct a keystore by deriving the master key from a passphrase and a
    /// device-bound salt via the supplied [`MasterKeyKdf`] (Argon2id in prod).
    #[must_use]
    pub fn derive_from_passphrase<K: MasterKeyKdf>(
        kdf_impl: &K,
        passphrase: &[u8],
        device_salt: &[u8],
    ) -> Self {
        Self::from_master_key(kdf_impl.derive_master_key(passphrase, device_salt))
    }

    /// AAD bound into every seal: envelope version ‖ family ‖ measurement.
    ///
    /// Binding the version prevents a downgrade swap of the envelope format.
    fn seal_aad(version: u8, policy: &SealPolicy) -> Vec<u8> {
        let mut aad = Vec::with_capacity(2 + 48);
        aad.push(version);
        aad.push(policy.family as u8);
        aad.extend_from_slice(policy.measurement.as_bytes());
        aad
    }

    /// Derive the per-keystore seal key from the master key.
    fn seal_key(&self) -> Result<NexaCoreAeadKey, SealingError> {
        let bytes = kdf::hkdf_expand(&self.master.0, SEAL_KEY_INFO, 32)
            .map_err(|_| SealingError::KeyDerivation)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| SealingError::KeyDerivation)?;
        Ok(NexaCoreAeadKey::from_bytes(arr))
    }

    /// Compute the master-keyed, content-bound synthetic nonce (no RNG needed).
    ///
    /// `nonce = HKDF(master, NONCE_INFO_PREFIX ‖ aad ‖ plaintext)[..12]`.  An
    /// attacker cannot predict it without the master, and different plaintexts
    /// (or policies) yield different nonces, so the deterministic seal never
    /// reuses `(key, nonce)` over distinct data.
    fn synthetic_nonce(&self, aad: &[u8], plaintext: &[u8]) -> Result<NexaCoreNonce, SealingError> {
        let mut info = Vec::with_capacity(NONCE_INFO_PREFIX.len() + aad.len() + plaintext.len());
        info.extend_from_slice(NONCE_INFO_PREFIX);
        info.extend_from_slice(aad);
        info.extend_from_slice(plaintext);
        let bytes = kdf::hkdf_expand(&self.master.0, &info, NONCE_LEN)
            .map_err(|_| SealingError::KeyDerivation)?;
        let arr: [u8; NONCE_LEN] = bytes.try_into().map_err(|_| SealingError::KeyDerivation)?;
        Ok(NexaCoreNonce::from_bytes(arr))
    }

    /// The raw seal-key bytes, for the key-separation test only.
    #[cfg(test)]
    fn seal_key_bytes(&self) -> [u8; 32] {
        let bytes = kdf::hkdf_expand(&self.master.0, SEAL_KEY_INFO, 32).unwrap_or_default();
        bytes.try_into().unwrap_or([0u8; 32])
    }
}

impl SealingProvider for SoftwareKeystore {
    fn backend_kind(&self) -> SealingBackendKind {
        SealingBackendKind::SoftwareKeystore
    }

    fn seal(&self, plaintext: &[u8], policy: &SealPolicy) -> Result<SealedBlob, SealingError> {
        let version = SealedBlob::CURRENT_ENVELOPE_VERSION;
        let key = self.seal_key()?;
        let aad = Self::seal_aad(version, policy);
        let nonce = self.synthetic_nonce(&aad, plaintext)?;
        let nonce_bytes = *nonce.as_bytes();
        let ct = aead::seal(&key, &nonce, &aad, plaintext).map_err(|_| SealingError::SealFailed)?;

        // Envelope: nonce(12) ‖ ciphertext+tag.
        let mut ciphertext = Vec::with_capacity(NONCE_LEN + ct.len());
        ciphertext.extend_from_slice(&nonce_bytes);
        ciphertext.extend_from_slice(ct.as_bytes());

        Ok(SealedBlob {
            envelope_version: version,
            policy: policy.clone(),
            ciphertext,
        })
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<Vec<u8>, SealingError> {
        let nonce_bytes: [u8; NONCE_LEN] = blob
            .ciphertext
            .get(..NONCE_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(SealingError::Malformed)?;
        let ct_bytes = blob
            .ciphertext
            .get(NONCE_LEN..)
            .ok_or(SealingError::Malformed)?;
        let key = self.seal_key()?;
        let nonce = NexaCoreNonce::from_bytes(nonce_bytes);
        // The version bound here must match what was sealed, or the tag fails.
        let aad = Self::seal_aad(blob.envelope_version, &blob.policy);
        let ct = NexaCoreCiphertext::from_bytes(ct_bytes.to_vec());
        aead::open(&key, &nonce, &aad, &ct).map_err(|_| SealingError::UnsealFailed)
    }

    fn derive_subkey(&self, context: &[u8]) -> Result<[u8; 32], SealingError> {
        // Prefix with the subkey domain so a context can never collide with the
        // seal-key or nonce domains (key separation / confused-deputy defence).
        let mut info = Vec::with_capacity(SUBKEY_INFO_PREFIX.len() + context.len());
        info.extend_from_slice(SUBKEY_INFO_PREFIX);
        info.extend_from_slice(context);
        let bytes =
            kdf::hkdf_expand(&self.master.0, &info, 32).map_err(|_| SealingError::KeyDerivation)?;
        bytes.try_into().map_err(|_| SealingError::KeyDerivation)
    }
}

// ---------------------------------------------------------------------------
// TPM 2.0 provider scaffold (WS10-08.5)
// ---------------------------------------------------------------------------

/// TPM 2.0 owner-hierarchy sealing provider — **scaffold**.
///
/// The real implementation seals to the TPM owner hierarchy via the TSS stack
/// (`std` + `/dev/tpm0`), so every method returns [`SealingError::Unsupported`]
/// until that hardware integration lands; the type exists so the selector and
/// `SecurityProfile` can route to TPM today.
#[derive(Debug, Default, Clone)]
pub struct Tpm2SealingProvider {
    /// Reserved for the TSS context handle / owner-auth in the real backend.
    _reserved: (),
}

impl Tpm2SealingProvider {
    /// Construct the scaffold provider.
    #[must_use]
    pub const fn new() -> Self {
        Self { _reserved: () }
    }
}

impl SealingProvider for Tpm2SealingProvider {
    fn backend_kind(&self) -> SealingBackendKind {
        SealingBackendKind::Tpm2
    }
    fn seal(&self, _plaintext: &[u8], _policy: &SealPolicy) -> Result<SealedBlob, SealingError> {
        Err(SealingError::Unsupported)
    }
    fn unseal(&self, _blob: &SealedBlob) -> Result<Vec<u8>, SealingError> {
        Err(SealingError::Unsupported)
    }
    fn derive_subkey(&self, _context: &[u8]) -> Result<[u8; 32], SealingError> {
        Err(SealingError::Unsupported)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use crate::{attestation::Measurement, traits::TeeFamily};

    fn policy() -> SealPolicy {
        SealPolicy::new(TeeFamily::SoftwareMpc, Measurement([0x11; 48]))
    }

    #[test]
    fn software_keystore_seal_unseal_roundtrip() {
        let ks = SoftwareKeystore::from_master_key([0x42; 32]);
        let secret = b"full-disk-encryption-key-material";
        let blob = ks.seal(secret, &policy()).expect("seals");
        assert_eq!(blob.envelope_version, SealedBlob::CURRENT_ENVELOPE_VERSION);
        let opened = ks.unseal(&blob).expect("unseals");
        assert_eq!(opened, secret);
    }

    #[test]
    fn deterministic_seal_is_stable_and_survives_reinstantiation() {
        // SIV-style: the same (master, policy, plaintext) yields the identical
        // blob, and — crucially — a fresh keystore from the same master uses
        // the same content-bound nonce, so there is no (key, nonce) reuse over
        // *different* data even across restarts (the nonce-reuse fix).
        let a = SoftwareKeystore::from_master_key([0x42; 32])
            .seal(b"x", &policy())
            .unwrap();
        let b = SoftwareKeystore::from_master_key([0x42; 32])
            .seal(b"x", &policy())
            .unwrap();
        assert_eq!(a.ciphertext, b.ciphertext);
        // Distinct plaintexts get distinct nonces / ciphertexts.
        let c = SoftwareKeystore::from_master_key([0x42; 32])
            .seal(b"y", &policy())
            .unwrap();
        assert_ne!(&a.ciphertext[..NONCE_LEN], &c.ciphertext[..NONCE_LEN]);
        let ks = SoftwareKeystore::from_master_key([0x42; 32]);
        assert_eq!(ks.unseal(&a).unwrap(), b"x");
        assert_eq!(ks.unseal(&c).unwrap(), b"y");
    }

    #[test]
    fn derive_subkey_cannot_recover_the_seal_key() {
        // Key separation: even feeding `derive_subkey` the exact seal-key /
        // nonce domain labels must not reproduce the seal key (disjoint HKDF
        // domains), defeating a confused-deputy key extraction.
        let ks = SoftwareKeystore::from_master_key([0x42; 32]);
        let seal_key = ks.seal_key_bytes();
        assert_ne!(ks.derive_subkey(SEAL_KEY_INFO).unwrap(), seal_key);
        assert_ne!(ks.derive_subkey(NONCE_INFO_PREFIX).unwrap(), seal_key);
        assert_ne!(ks.derive_subkey(b"").unwrap(), seal_key);
    }

    #[test]
    fn envelope_version_is_bound_as_aad() {
        let ks = SoftwareKeystore::from_master_key([0x42; 32]);
        let mut blob = ks.seal(b"secret", &policy()).unwrap();
        // Tampering the version must break authentication (AAD coverage).
        blob.envelope_version = blob.envelope_version.wrapping_add(1);
        assert_eq!(ks.unseal(&blob), Err(SealingError::UnsealFailed));
    }

    #[test]
    fn tampering_is_detected() {
        let ks = SoftwareKeystore::from_master_key([0x42; 32]);
        let mut blob = ks.seal(b"secret", &policy()).unwrap();
        let last = blob.ciphertext.len() - 1;
        blob.ciphertext[last] ^= 0xFF;
        assert_eq!(ks.unseal(&blob), Err(SealingError::UnsealFailed));
    }

    #[test]
    fn wrong_master_key_fails_to_unseal() {
        let ks = SoftwareKeystore::from_master_key([0x42; 32]);
        let blob = ks.seal(b"secret", &policy()).unwrap();
        let other = SoftwareKeystore::from_master_key([0x43; 32]);
        assert_eq!(other.unseal(&blob), Err(SealingError::UnsealFailed));
    }

    #[test]
    fn subkey_derivation_is_deterministic_and_context_separated() {
        let ks = SoftwareKeystore::from_master_key([0x42; 32]);
        let a1 = ks.derive_subkey(b"pii-vault").unwrap();
        let a2 = ks.derive_subkey(b"pii-vault").unwrap();
        let b = ks.derive_subkey(b"fde-key").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    }

    struct StubKdf;
    impl MasterKeyKdf for StubKdf {
        fn derive_master_key(&self, passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
            let mut k = [0u8; 32];
            for (i, slot) in k.iter_mut().enumerate() {
                *slot = passphrase.get(i).copied().unwrap_or(0) ^ salt.get(i).copied().unwrap_or(0);
            }
            k
        }
    }

    #[test]
    fn keystore_from_passphrase_roundtrips() {
        let ks =
            SoftwareKeystore::derive_from_passphrase(&StubKdf, b"correct horse", b"device-salt");
        let blob = ks.seal(b"data", &policy()).unwrap();
        assert_eq!(ks.unseal(&blob).unwrap(), b"data");
    }

    #[test]
    fn tpm_scaffold_is_unsupported_but_routes() {
        let tpm = Tpm2SealingProvider::new();
        assert_eq!(tpm.backend_kind(), SealingBackendKind::Tpm2);
        assert_eq!(tpm.seal(b"x", &policy()), Err(SealingError::Unsupported));
    }

    #[test]
    fn selection_prefers_hardware_then_tpm_then_software() {
        let tee = SealingAvailability {
            hardware_tee: true,
            tpm2: true,
        };
        assert_eq!(select_sealing_backend(tee), SealingBackendKind::HardwareTee);
        assert_eq!(current_security_profile(tee), SecurityProfile::HardwareTee);

        let tpm = SealingAvailability {
            hardware_tee: false,
            tpm2: true,
        };
        assert_eq!(select_sealing_backend(tpm), SealingBackendKind::Tpm2);
        assert_eq!(current_security_profile(tpm), SecurityProfile::Tpm);

        let none = SealingAvailability::default();
        assert_eq!(
            select_sealing_backend(none),
            SealingBackendKind::SoftwareKeystore
        );
        assert_eq!(
            current_security_profile(none),
            SecurityProfile::SoftwareOnly
        );
    }

    #[test]
    fn security_profile_capability_matrix() {
        for p in [
            SecurityProfile::HardwareTee,
            SecurityProfile::Tpm,
            SecurityProfile::SoftwareOnly,
        ] {
            // Originate/consume always allowed.
            assert!(p.can_originate());
            assert!(p.can_consume());
        }
        assert!(SecurityProfile::HardwareTee.can_contribute_tier2());
        assert!(SecurityProfile::Tpm.can_contribute_tier2());
        assert!(!SecurityProfile::SoftwareOnly.can_contribute_tier2());
        assert_eq!(SecurityProfile::HardwareTee.mesh_tier(), 1);
        assert_eq!(SecurityProfile::SoftwareOnly.mesh_tier(), 3);
    }
}

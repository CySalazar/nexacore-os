//! Key derivation functions.
//!
//! Two KDF families are exposed:
//!
//! | Function | Use |
//! |---|---|
//! | `HKDF-SHA-256` | Deriving symmetric session keys from a high-entropy input (e.g., the output of `X25519` ECDH). RFC 5869. |
//! | `Argon2id`     | Hashing user secrets / passwords. Memory-hard; defends against GPU/ASIC brute force. RFC 9106. |
//!
//! `Argon2id` parameters follow the OWASP cheatsheet (May 2026
//! revision): `m_cost = 19456 KiB ≈ 19 MiB`, `t_cost = 2 iterations`,
//! `p = 1`. These are conservative defaults appropriate for an
//! interactive auth flow on commodity hardware. Bulk-storage hashing
//! (e.g., DB-side) should use higher `m_cost`.

use alloc::{vec, vec::Vec};

#[cfg(feature = "rng")]
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use nexacore_types::error::{CryptoErrorKind, NexaCoreError, Result};
use sha2::Sha256;
#[cfg(feature = "rng")]
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// HKDF-SHA-256
// =============================================================================

/// Maximum HKDF output length, per RFC 5869: `255 * HashLen` bytes.
/// For `SHA-256` (32-byte digest) this is `255 * 32 = 8160` bytes.
pub const HKDF_MAX_OUTPUT: usize = 255 * 32;

/// Expand a high-entropy pseudo-random key (`prk`) into `len` bytes of
/// keying material via `HKDF-SHA-256` (RFC 5869, expand step only).
///
/// `info` is the optional context-specific binding string. Use it to
/// separate keys derived from the same `prk` for different purposes
/// (e.g., `b"nexacore-mesh-session-encryption"` vs
/// `b"nexacore-mesh-session-mac"`).
///
/// # Errors
///
/// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::KdfFailure`]
/// if `len > HKDF_MAX_OUTPUT`.
pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    if len > HKDF_MAX_OUTPUT {
        return Err(NexaCoreError::crypto(
            CryptoErrorKind::KdfFailure,
            "kdf::hkdf_expand::output_too_long",
        ));
    }
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| {
        NexaCoreError::crypto(
            CryptoErrorKind::KdfFailure,
            "kdf::hkdf_expand::prk_too_short",
        )
    })?;
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).map_err(|_| {
        NexaCoreError::crypto(CryptoErrorKind::KdfFailure, "kdf::hkdf_expand::expand")
    })?;
    Ok(out)
}

/// Full `HKDF-SHA-256` extract+expand: `HKDF(salt, ikm, info, len)`.
///
/// Use this when the input keying material (`ikm`) is not yet a PRK
/// (e.g., the raw output of a KEM combiner or a noisy entropy source).
/// For ECDH outputs that are already 32 bytes of high entropy, prefer
/// [`hkdf_expand`] with the ECDH bytes used directly as the `prk`.
///
/// # Errors
///
/// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::KdfFailure`]
/// if `len > HKDF_MAX_OUTPUT`.
pub fn hkdf_extract_and_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    if len > HKDF_MAX_OUTPUT {
        return Err(NexaCoreError::crypto(
            CryptoErrorKind::KdfFailure,
            "kdf::hkdf_extract_and_expand::output_too_long",
        ));
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).map_err(|_| {
        NexaCoreError::crypto(
            CryptoErrorKind::KdfFailure,
            "kdf::hkdf_extract_and_expand::expand",
        )
    })?;
    Ok(out)
}

/// `HKDF-SHA-256` extract step in isolation: `PRK = HMAC-SHA-256(salt, ikm)`.
///
/// Returns the 32-byte pseudo-random key. TLS 1.3 (RFC 8446 § 7.1) drives
/// its key schedule with the extract and expand halves used *separately*
/// (`HKDF-Extract` then a chain of `HKDF-Expand-Label` derivations), so the
/// combined [`hkdf_extract_and_expand`] is not sufficient there. When `salt`
/// is empty the RFC-5869 convention (a zero-filled `HashLen` salt) is applied
/// by the underlying library.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _hk) = Hkdf::<Sha256>::extract(salt_opt, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

// =============================================================================
// Argon2id (gated behind the `rng` feature — argon2 is RNG-adjacent and
// excluded from bare-metal builds)
// =============================================================================

/// `Argon2id` output: a 32-byte hash plus the parameters used to
/// produce it. Wipes itself on `Drop`.
#[cfg(feature = "rng")]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Argon2idHash {
    /// The 32-byte digest.
    pub hash: [u8; 32],
}

/// `Argon2id` parameters compatible with the OWASP 2026 cheatsheet
/// (interactive-auth profile).
///
/// | Parameter | Value | Rationale |
/// |---|---|---|
/// | `m_cost`  | 19456 KiB | ~19 MiB; defeats commodity GPUs |
/// | `t_cost`  | 2 iterations | Fast enough for interactive UX |
/// | `p`       | 1 | Conservative; raise on multi-core servers |
/// | `out_len` | 32 bytes  | Matches symmetric key sizes elsewhere |
///
/// # Panics
///
/// Cannot panic in practice: the embedded constants
/// `(m_cost = 19456, t_cost = 2, p = 1, out_len = Some(32))` are all
/// inside Argon2's documented valid ranges. The `.expect` exists only
/// to translate the library's `Result` into a value usable in `const`-
/// adjacent contexts; if it ever did fire, that would mean the
/// upstream `argon2` crate changed its validation rules and this
/// function needs to be revisited.
#[cfg(feature = "rng")]
#[must_use]
pub fn argon2id_default_params() -> Params {
    // Argon2's `Params::new` is fallible only on out-of-range arguments;
    // these constants are valid by construction (they fit Argon2's
    // documented bounds).
    #[allow(clippy::expect_used)]
    Params::new(19456, 2, 1, Some(32))
        .expect("NexaCore: Argon2 default params are statically valid")
}

/// Hash `password` with `salt` using `Argon2id` and OWASP-recommended
/// default parameters.
///
/// `salt` MUST be at least 16 bytes and unique per password (per
/// Argon2 spec recommendation; the function accepts shorter salts but
/// returns an error).
///
/// # Errors
///
/// Returns [`NexaCoreError::Crypto`] with [`CryptoErrorKind::KdfFailure`]
/// on any underlying error (salt too short, params invalid).
#[cfg(feature = "rng")]
pub fn argon2id_hash(password: &[u8], salt: &[u8]) -> Result<Argon2idHash> {
    if salt.len() < 16 {
        return Err(NexaCoreError::crypto(
            CryptoErrorKind::KdfFailure,
            "kdf::argon2id_hash::salt_too_short",
        ));
    }
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2id_default_params(),
    );
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| {
            NexaCoreError::crypto(
                CryptoErrorKind::KdfFailure,
                "kdf::argon2id_hash::hash_password_into",
            )
        })?;
    Ok(Argon2idHash { hash: out })
}

// =============================================================================
// Tests — RFC 5869 vectors + Argon2 sanity.
// =============================================================================

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // ---- RFC 5869 § A.1 — HKDF-SHA-256 Test Case 1. ------------------------
    // IKM:    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    // salt:   000102030405060708090a0b0c (13 bytes)
    // info:   f0f1f2f3f4f5f6f7f8f9 (10 bytes)
    // L:      42
    // PRK:    077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    // OKM:    3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865

    #[test]
    fn rfc5869_test1_extract_and_expand() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_extract_and_expand(&salt, &ikm, &info, 42).unwrap();
        let expected = hex::decode(concat!(
            "3cb25f25faacd57a90434f64d0362f2a",
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865"
        ))
        .unwrap();
        assert_eq!(okm, expected);
    }

    #[test]
    fn rfc5869_test1_extract_only_matches_known_prk() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let prk = hkdf_extract(&salt, &ikm);
        let expected =
            hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .unwrap();
        assert_eq!(prk.as_slice(), expected.as_slice());
    }

    #[test]
    fn rfc5869_test1_expand_only_with_known_prk() {
        let prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
            .unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_expand(&prk, &info, 42).unwrap();
        let expected = hex::decode(concat!(
            "3cb25f25faacd57a90434f64d0362f2a",
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865"
        ))
        .unwrap();
        assert_eq!(okm, expected);
    }

    #[test]
    fn hkdf_rejects_too_long_output() {
        let prk = [0u8; 32];
        let err = hkdf_expand(&prk, b"", HKDF_MAX_OUTPUT + 1).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => assert_eq!(kind, CryptoErrorKind::KdfFailure),
            _ => panic!("expected Crypto::KdfFailure"),
        }
    }

    // ---- Argon2id sanity (gated behind `rng` feature) ------------------------

    #[cfg(feature = "rng")]
    #[test]
    fn argon2id_is_deterministic_given_same_inputs() {
        let salt = [0xAB; 16];
        let h1 = argon2id_hash(b"hunter2", &salt).unwrap();
        let h2 = argon2id_hash(b"hunter2", &salt).unwrap();
        assert_eq!(h1.hash, h2.hash);
    }

    #[cfg(feature = "rng")]
    #[test]
    fn argon2id_different_passwords_produce_different_hashes() {
        let salt = [0xCD; 16];
        let h1 = argon2id_hash(b"alpha", &salt).unwrap();
        let h2 = argon2id_hash(b"beta", &salt).unwrap();
        assert_ne!(h1.hash, h2.hash);
    }

    #[cfg(feature = "rng")]
    #[test]
    fn argon2id_different_salts_produce_different_hashes() {
        let s1 = [0x11u8; 16];
        let s2 = [0x22u8; 16];
        let h1 = argon2id_hash(b"same-pw", &s1).unwrap();
        let h2 = argon2id_hash(b"same-pw", &s2).unwrap();
        assert_ne!(h1.hash, h2.hash);
    }

    #[cfg(feature = "rng")]
    #[test]
    fn argon2id_rejects_short_salt() {
        let salt = [0xFFu8; 8];
        let err = argon2id_hash(b"pw", &salt).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => assert_eq!(kind, CryptoErrorKind::KdfFailure),
            _ => panic!("expected Crypto::KdfFailure"),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn hkdf_round_trip_arbitrary(
            prk in proptest::array::uniform32(any::<u8>()),
            info in proptest::collection::vec(any::<u8>(), 0..64),
            len in 1usize..256,
        ) {
            let a = hkdf_expand(&prk, &info, len).unwrap();
            let b = hkdf_expand(&prk, &info, len).unwrap();
            prop_assert_eq!(a, b);
        }
    }
}

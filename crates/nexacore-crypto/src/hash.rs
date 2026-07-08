//! Cryptographic hashes.
//!
//! Three hash families are exposed behind the [`NexaCoreHash`] trait:
//!
//! | Algorithm | Output length | Usage |
//! |---|---|---|
//! | `BLAKE3`     | 32 bytes | Default protocol-level hash. Fastest, hardware-friendly, post-quantum resilient. |
//! | `SHA-256`    | 32 bytes | Required for `HKDF-SHA-256` (interop) and a few RFC-mandated paths. |
//! | `SHA3-256`   | 32 bytes | Standby for `BLAKE3` should a structural weakness be found. |
//!
//! # Domain separation is mandatory
//!
//! Every hash invocation in NexaCore OS MUST go through
//! [`domain_separated_hash`] — directly hashing arbitrary user data is
//! forbidden by code review. The domain prefix prevents cross-protocol
//! collisions: a `NodeId` derived from a TEE quote and a `ModelId`
//! derived from a manifest cannot accidentally collide because the
//! domain strings differ.
//!
//! # Constant-time?
//!
//! Hashes themselves are constant-time on the input. Where downstream
//! code compares two hash digests for equality, it MUST use
//! [`subtle::ConstantTimeEq`] (digests can be public, but disciplined
//! use prevents accidental timing leaks elsewhere).

use alloc::vec::Vec;

use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// Length of the hash output in bytes (all three algorithms produce
/// 32-byte digests).
pub const HASH_LEN: usize = 32;

/// Trait implemented by every hash algorithm in NexaCore OS.
///
/// Stateless — there is no incremental "Update / Finalize" interface
/// at this level. If you need streaming hashing, use the underlying
/// library's hasher directly with care; the wrapper here is geared to
/// one-shot domain-separated hashing.
pub trait NexaCoreHash {
    /// Stable, machine-readable identifier of this hash algorithm.
    /// Used in audit logs and protocol negotiation.
    const NAME: &'static str;

    /// Compute the digest of `data`.
    fn hash(data: &[u8]) -> [u8; HASH_LEN];
}

// =============================================================================
// BLAKE3
// =============================================================================

/// `BLAKE3` (default protocol-level hash).
pub struct Blake3;

impl NexaCoreHash for Blake3 {
    const NAME: &'static str = "BLAKE3";

    fn hash(data: &[u8]) -> [u8; HASH_LEN] {
        let mut h = Blake3Hasher::new();
        h.update(data);
        let out = h.finalize();
        *out.as_bytes()
    }
}

// =============================================================================
// SHA-256
// =============================================================================

/// `SHA-256` — used for `HKDF` interop and RFC-mandated paths.
pub struct Sha256H;

impl NexaCoreHash for Sha256H {
    const NAME: &'static str = "SHA-256";

    fn hash(data: &[u8]) -> [u8; HASH_LEN] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}

// =============================================================================
// SHA3-256
// =============================================================================

/// `SHA3-256` — standby in case `BLAKE3` is broken.
pub struct Sha3_256H;

impl NexaCoreHash for Sha3_256H {
    const NAME: &'static str = "SHA3-256";

    fn hash(data: &[u8]) -> [u8; HASH_LEN] {
        let mut h = Sha3_256::new();
        h.update(data);
        h.finalize().into()
    }
}

// =============================================================================
// Domain-separated hashing
// =============================================================================

/// Compute `H(domain_tag || domain || 0x00 || data)` using `BLAKE3`.
///
/// `domain_tag` is the literal byte sequence `b"OMNI-DOMAIN-v1\x00"`,
/// which is unlikely to occur as a prefix of any user data.
/// The trailing `0x00` separator after `domain` prevents extension
/// attacks where two `(domain, data)` pairs canonicalise to the same
/// concatenation (e.g., `("foo", "bar")` vs `("foob", "ar")`).
///
/// Domain separation is the only sanctioned way to invoke hashing in
/// NexaCore OS code. New domains MUST be registered in
/// `/docs/04-security-model.md` § "Hash domain registry".
#[must_use]
pub fn domain_separated_hash(domain: &str, data: &[u8]) -> [u8; HASH_LEN] {
    const TAG: &[u8] = b"OMNI-DOMAIN-v1\x00";
    let mut buf = Vec::with_capacity(TAG.len() + domain.len() + 1 + data.len());
    buf.extend_from_slice(TAG);
    buf.extend_from_slice(domain.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(data);
    Blake3::hash(&buf)
}

// =============================================================================
// Tests — NIST / RFC vectors + property + collision sanity.
// =============================================================================

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // ---- Reference vectors --------------------------------------------------

    // SHA-256 of empty input — NIST FIPS 180-4 Appendix A.
    const SHA256_EMPTY_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    // BLAKE3 of empty input — official BLAKE3 reference.
    const BLAKE3_EMPTY_HEX: &str =
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    // SHA3-256 of empty input — NIST.
    const SHA3_256_EMPTY_HEX: &str =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

    fn parse32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn sha256_empty_matches_nist_vector() {
        assert_eq!(Sha256H::hash(b""), parse32(SHA256_EMPTY_HEX));
    }

    #[test]
    fn blake3_empty_matches_reference_vector() {
        assert_eq!(Blake3::hash(b""), parse32(BLAKE3_EMPTY_HEX));
    }

    #[test]
    fn sha3_256_empty_matches_nist_vector() {
        assert_eq!(Sha3_256H::hash(b""), parse32(SHA3_256_EMPTY_HEX));
    }

    // SHA-256 of "abc" — NIST FIPS 180-4 Appendix B.1.
    #[test]
    fn sha256_abc_matches_nist_vector() {
        let h = Sha256H::hash(b"abc");
        assert_eq!(
            h,
            parse32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    // BLAKE3 of "abc" — official reference.
    #[test]
    fn blake3_abc_matches_reference_vector() {
        let h = Blake3::hash(b"abc");
        assert_eq!(
            h,
            parse32("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
        );
    }

    // ---- Determinism --------------------------------------------------------

    #[test]
    fn all_three_algorithms_are_deterministic() {
        let data = b"NexaCore hash test";
        assert_eq!(Blake3::hash(data), Blake3::hash(data));
        assert_eq!(Sha256H::hash(data), Sha256H::hash(data));
        assert_eq!(Sha3_256H::hash(data), Sha3_256H::hash(data));
    }

    // ---- Domain separation --------------------------------------------------

    #[test]
    fn domain_separation_avoids_obvious_collisions() {
        // Two `(domain, data)` pairs whose naive concatenation would
        // collide. The 0x00 separator must prevent the collision.
        let h1 = domain_separated_hash("foo", b"bar");
        let h2 = domain_separated_hash("foob", b"ar");
        assert_ne!(h1, h2);
    }

    #[test]
    fn domain_separation_is_deterministic() {
        let a = domain_separated_hash("identity::node_id", b"payload");
        let b = domain_separated_hash("identity::node_id", b"payload");
        assert_eq!(a, b);
    }

    #[test]
    fn different_domains_produce_different_hashes() {
        let a = domain_separated_hash("identity::node_id", b"x");
        let b = domain_separated_hash("identity::model_id", b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn names_are_unique_and_well_known() {
        assert_eq!(Blake3::NAME, "BLAKE3");
        assert_eq!(Sha256H::NAME, "SHA-256");
        assert_eq!(Sha3_256H::NAME, "SHA3-256");
        let names = [Blake3::NAME, Sha256H::NAME, Sha3_256H::NAME];
        for (i, a) in names.iter().enumerate() {
            for b in names.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    // ---- Property tests -----------------------------------------------------

    proptest! {
        // Stress level: 256 cases on each property. Acts as a
        // poor-man's fuzz pass until `cargo-fuzz` runs land in P3.
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn distinct_inputs_produce_distinct_blake3(
            a in proptest::collection::vec(any::<u8>(), 0..64),
            b in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assume!(a != b);
            prop_assert_ne!(Blake3::hash(&a), Blake3::hash(&b));
        }

        #[test]
        fn output_length_is_32_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            prop_assert_eq!(Blake3::hash(&data).len(), HASH_LEN);
            prop_assert_eq!(Sha256H::hash(&data).len(), HASH_LEN);
            prop_assert_eq!(Sha3_256H::hash(&data).len(), HASH_LEN);
        }
    }
}

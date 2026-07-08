//! Passphrase hashing and constant-time credential verification (WS12-05.2).
//!
//! A [`Credential`] stores the hash scheme, the salt, and the digest. The
//! [`PasswordHasher`] trait is the seam behind which the production memory-hard
//! **Argon2id** (`nexacore-crypto::kdf::argon2id_hash`) is wired; the crate
//! ships [`Blake3Hasher`] as a functional but **not memory-hard** placeholder so
//! the store and auth logic can be exercised host-side.

use alloc::vec::Vec;

/// Identifies the hasher that produced a [`Credential`], so verification refuses
/// to check a digest with the wrong scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashScheme {
    /// Memory-hard Argon2id (the production scheme).
    Argon2id,
    /// The iterated-BLAKE3 placeholder (not memory-hard).
    Blake3Placeholder,
}

/// A stored password credential: `hash = hasher(password, salt)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The scheme that produced [`Credential::hash`].
    pub scheme: HashScheme,
    /// The per-credential salt.
    pub salt: Vec<u8>,
    /// The password digest.
    pub hash: Vec<u8>,
}

/// A pluggable password hasher (the Argon2id seam).
pub trait PasswordHasher {
    /// The scheme this hasher produces (stamped into the [`Credential`]).
    fn scheme(&self) -> HashScheme;

    /// Hash `password` with `salt`.
    fn hash(&self, password: &[u8], salt: &[u8]) -> Vec<u8>;
}

/// An iterated-BLAKE3 password hasher.
///
/// **SECURITY: not memory-hard — do NOT use for production password storage.**
/// It exists only to exercise the store/auth logic host-side; a deployment MUST
/// wire the memory-hard Argon2id (`nexacore-crypto::kdf::argon2id_hash`) through
/// [`PasswordHasher`]. The [`HashScheme::Blake3Placeholder`] tag it stamps makes
/// its use auditable in any stored [`Credential`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Hasher {
    /// Number of extra keyed-hash iterations (a cost knob for the placeholder).
    pub iterations: u32,
}

impl Blake3Hasher {
    /// A hasher performing `iterations` extra keyed-hash rounds.
    #[must_use]
    pub fn new(iterations: u32) -> Self {
        Self { iterations }
    }
}

impl PasswordHasher for Blake3Hasher {
    fn scheme(&self) -> HashScheme {
        HashScheme::Blake3Placeholder
    }

    fn hash(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        let salt_key = *blake3::hash(salt).as_bytes();
        let mut acc = *blake3::keyed_hash(&salt_key, password).as_bytes();
        for _ in 0..self.iterations {
            acc = *blake3::keyed_hash(&salt_key, &acc).as_bytes();
        }
        acc.to_vec()
    }
}

/// Build a [`Credential`] by hashing `password` with `salt` under `hasher`.
#[must_use]
pub fn make_credential<H: PasswordHasher>(hasher: &H, password: &[u8], salt: &[u8]) -> Credential {
    Credential {
        scheme: hasher.scheme(),
        salt: salt.to_vec(),
        hash: hasher.hash(password, salt),
    }
}

/// Verify `password` against `credential` in constant time. Returns `false` if
/// `hasher`'s scheme differs from the credential's (no cross-scheme check).
#[must_use]
pub fn verify<H: PasswordHasher>(hasher: &H, credential: &Credential, password: &[u8]) -> bool {
    if hasher.scheme() != credential.scheme {
        return false;
    }
    let candidate = hasher.hash(password, &credential.salt);
    ct_eq(&candidate, &credential.hash)
}

/// Constant-time byte-slice equality (length is not treated as secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_salted() {
        let h = Blake3Hasher::new(3);
        let a = h.hash(b"secret", b"salt-1");
        assert_eq!(a, h.hash(b"secret", b"salt-1"), "deterministic");
        assert_ne!(a, h.hash(b"secret", b"salt-2"), "salt separates");
        assert_ne!(a, h.hash(b"other", b"salt-1"), "password separates");
    }

    #[test]
    fn verify_accepts_correct_and_rejects_wrong() {
        let h = Blake3Hasher::new(2);
        let cred = make_credential(&h, b"hunter2", b"NaCl");
        assert!(verify(&h, &cred, b"hunter2"));
        assert!(!verify(&h, &cred, b"hunter3"));
    }

    #[test]
    fn verify_refuses_mismatched_scheme() {
        let h = Blake3Hasher::new(1);
        let mut cred = make_credential(&h, b"pw", b"salt");
        cred.scheme = HashScheme::Argon2id; // pretend a different scheme produced it
        assert!(!verify(&h, &cred, b"pw"), "scheme mismatch must not verify");
    }
}

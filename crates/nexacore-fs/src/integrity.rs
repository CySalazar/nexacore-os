//! # Per-block AEAD integrity tags
//!
//! Implements the block-level integrity scheme described in
//! NCIP-FS-Wire-023 §S4.  Each 4 KiB data block has an associated
//! 16-byte authentication tag stored in the volume's integrity region.
//!
//! ## Algorithm
//!
//! `ChaCha20-Poly1305` (RFC 8439) is used for tag computation:
//!
//! - **Key**: a 32-byte [`BlockKey`] derived from the volume's AEAD key.
//!   Phase-2 stub: all-zero key (`BlockKey::zeroed()`).
//! - **Nonce**: the block number encoded as little-endian `u64`, zero-padded
//!   to 12 bytes.  Using the block number as the nonce ensures that each block
//!   has a unique ciphertext even when the plaintext is identical, and prevents
//!   nonce reuse across blocks.
//! - **AAD**: empty (no additional authenticated data in Phase 2).
//! - **Output**: the 16-byte Poly1305 authentication tag extracted from the
//!   ChaCha20-Poly1305 ciphertext suffix.
//!
//! ## Phase-2 stub
//!
//! Tags are computed with an all-zero key.  This provides integrity checking
//! (detects accidental bit-flips) but NOT security (an attacker who knows the
//! key is zero can forge tags).  Phase 3 will source the key from the TEE
//! keystore identified by `Superblock::aead_key_id`.
//!
//! ## Verification
//!
//! [`verify_tag`] uses a constant-time XOR accumulator to compare the
//! expected and stored tags.  This prevents timing-based tag-oracle attacks
//! even with an all-zero key.

extern crate alloc;
use alloc::vec::Vec;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

use crate::FsError;

// =============================================================================
// Constants
// =============================================================================

/// Length of a [`BlockKey`] in bytes (256-bit ChaCha20-Poly1305 key).
pub const BLOCK_KEY_LEN: usize = 32;

/// Length of a per-block AEAD authentication tag in bytes (Poly1305 output).
pub const TAG_LEN: usize = 16;

// =============================================================================
// BlockKey
// =============================================================================

/// A 256-bit key used to compute and verify per-block AEAD integrity tags.
///
/// In Phase 2 the key is always the all-zero value returned by
/// [`BlockKey::zeroed`].  Phase 3 will derive the key from the TEE keystore
/// using HKDF-BLAKE3 and the volume's `aead_key_id`.
///
/// The inner byte array is intentionally NOT `pub` so that the key material
/// can only be accessed via the controlled `as_bytes()` accessor.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::integrity::BlockKey;
///
/// let key = BlockKey::zeroed();
/// assert_eq!(key.as_bytes(), &[0u8; 32]);
/// ```
#[derive(Clone)]
pub struct BlockKey([u8; BLOCK_KEY_LEN]);

impl BlockKey {
    /// Construct a [`BlockKey`] from a 32-byte array.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::integrity::BlockKey;
    ///
    /// let raw = [0xABu8; 32];
    /// let key = BlockKey::from_bytes(raw);
    /// assert_eq!(key.as_bytes(), &[0xABu8; 32]);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: [u8; BLOCK_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Return an all-zero key (Phase-2 stub).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::integrity::BlockKey;
    ///
    /// let key = BlockKey::zeroed();
    /// assert_eq!(key.as_bytes(), &[0u8; 32]);
    /// ```
    #[must_use]
    pub fn zeroed() -> Self {
        Self([0u8; BLOCK_KEY_LEN])
    }

    /// Return a reference to the raw key bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::integrity::BlockKey;
    ///
    /// let key = BlockKey::zeroed();
    /// assert_eq!(key.as_bytes().len(), 32);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; BLOCK_KEY_LEN] {
        &self.0
    }
}

// Implement Debug without printing key material — avoids accidental key leakage
// in log output or test failure messages.
impl core::fmt::Debug for BlockKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BlockKey(<redacted>)")
    }
}

// =============================================================================
// Tag computation and verification
// =============================================================================

/// Build the 12-byte ChaCha20-Poly1305 nonce from a block number.
///
/// The block number is encoded as little-endian `u64` in the first 8 bytes;
/// the remaining 4 bytes are zero.  This scheme guarantees a unique nonce
/// per block as long as `block_number < 2^64` (i.e., always).
fn nonce_from_block_number(block_number: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&block_number.to_le_bytes());
    nonce
}

/// Compute the 16-byte AEAD integrity tag for a block.
///
/// Uses ChaCha20-Poly1305 to encrypt `block_data` with `key` and the nonce
/// derived from `block_number`.  The returned tag is the last 16 bytes of
/// the ChaCha20-Poly1305 ciphertext (the Poly1305 MAC).
///
/// # Panics
///
/// Panics if the ChaCha20-Poly1305 cipher fails to encrypt — this should
/// never happen for valid keys (32 bytes) and nonces (12 bytes), which are
/// enforced by the type system.  Any panic here indicates a bug in the
/// caller or a broken `chacha20poly1305` dependency.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::integrity::{BlockKey, TAG_LEN, compute_tag};
///
/// let key = BlockKey::zeroed();
/// let data = [0u8; 4096];
/// let tag = compute_tag(&key, 1, &data);
/// assert_eq!(tag.len(), TAG_LEN);
/// ```
#[must_use]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "ChaCha20-Poly1305 encrypt cannot fail for a valid 32-byte key and 12-byte nonce — both are type-guaranteed here; the tag_start slice is within ciphertext.len() by construction"
)]
pub fn compute_tag(key: &BlockKey, block_number: u64, block_data: &[u8]) -> [u8; TAG_LEN] {
    let cipher_key = Key::from_slice(key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce_bytes = nonce_from_block_number(block_number);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // encrypt returns ciphertext || tag (tag is appended by ChaCha20-Poly1305).
    // The tag is always the last TAG_LEN bytes of the output.
    let ciphertext = cipher
        .encrypt(nonce, block_data)
        .expect("ChaCha20-Poly1305 encryption must not fail for valid key/nonce");

    // Extract the 16-byte Poly1305 tag from the end of the ciphertext.
    let tag_start = ciphertext.len().saturating_sub(TAG_LEN);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ciphertext[tag_start..]);
    tag
}

/// Verify that `stored_tag` matches the expected tag for `block_data`.
///
/// Computes the expected tag via [`compute_tag`] and compares it to
/// `stored_tag` using a constant-time XOR accumulator to prevent
/// timing-based tag-oracle attacks.
///
/// # Errors
///
/// Returns [`FsError::IntegrityViolation`] if the tags do not match.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::integrity::{BlockKey, compute_tag, verify_tag};
///
/// let key = BlockKey::zeroed();
/// let data = [0xAAu8; 4096];
/// let tag = compute_tag(&key, 42, &data);
/// assert!(verify_tag(&key, 42, &data, &tag).is_ok());
///
/// // Tampered tag must fail.
/// let bad_tag = [0u8; 16];
/// assert!(verify_tag(&key, 42, &data, &bad_tag).is_err());
/// ```
pub fn verify_tag(
    key: &BlockKey,
    block_number: u64,
    block_data: &[u8],
    stored_tag: &[u8; TAG_LEN],
) -> Result<(), FsError> {
    let expected = compute_tag(key, block_number, block_data);

    // Constant-time comparison: XOR all bytes and accumulate.
    // If all bytes match, the accumulator remains 0.
    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(stored_tag.iter()) {
        diff |= a ^ b;
    }

    if diff == 0 {
        Ok(())
    } else {
        Err(FsError::IntegrityViolation)
    }
}

// =============================================================================
// Utility: stub tag (Phase-2)
// =============================================================================

/// Return a zeroed 16-byte tag, used as the Phase-2 stub.
///
/// In Phase 2 tags are zeroed rather than computed from real data.
/// This function centralises the stub value so it is easy to find and
/// replace in Phase 3.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::integrity::{TAG_LEN, stub_tag};
///
/// assert_eq!(stub_tag().len(), TAG_LEN);
/// assert!(stub_tag().iter().all(|&b| b == 0));
/// ```
#[must_use]
pub fn stub_tag() -> [u8; TAG_LEN] {
    [0u8; TAG_LEN]
}

/// Compute a tag vector suitable for serialisation.
///
/// Combines [`compute_tag`] and wraps the result in a `Vec<u8>` for
/// callers that need a heap-allocated buffer (e.g., the integrity region
/// writer in [`ondisk::OnDiskVolume`]).
///
/// [`ondisk::OnDiskVolume`]: crate::ondisk::OnDiskVolume
///
/// # Example
///
/// ```rust
/// use nexacore_fs::integrity::{BlockKey, TAG_LEN, compute_tag_vec};
///
/// let key = BlockKey::zeroed();
/// let data = [0u8; 4096];
/// let tag = compute_tag_vec(&key, 1, &data);
/// assert_eq!(tag.len(), TAG_LEN);
/// ```
#[must_use]
pub fn compute_tag_vec(key: &BlockKey, block_number: u64, block_data: &[u8]) -> Vec<u8> {
    compute_tag(key, block_number, block_data).to_vec()
}

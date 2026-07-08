//! Per-volume confidentiality: XChaCha20-Poly1305 + key hierarchy (WS3-01.8).
//!
//! Data blocks are sealed with XChaCha20-Poly1305 under a key derived through a
//! BLAKE3 hierarchy:
//!
//! ```text
//!   master (TEE-sealed, supplied by the caller)
//!     └─ volume key   = BLAKE3-keyed(master,     volume_id)
//!          └─ epoch key = BLAKE3-keyed(volume key, key_epoch)   ← bump = erasure
//! ```
//!
//! Bumping `key_epoch` derives an unrelated epoch key, so old ciphertext becomes
//! permanently unreadable (crypto erasure) without rewriting it. The 24-byte
//! XChaCha nonce is **deterministic** — `generation ‖ block` — and is therefore
//! never reused: every copy-on-write touch of a block lands at a new generation
//! (WS3-01.2), so each `(generation, block)` pair, and hence each nonce, is
//! unique. The AEAD additional data binds `(generation, block, key_epoch)` so a
//! sealed block cannot be replayed at another position, generation, or epoch.
//!
//! Sealing the master key itself is the TEE keystore's job (WS10); it arrives
//! here already unsealed.

use alloc::vec::Vec;

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use super::V3Error;

/// AEAD key length.
pub const KEY_LEN: usize = 32;
/// XChaCha nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// A 32-byte key in the hierarchy (master / volume / epoch).
pub type Key32 = [u8; KEY_LEN];

/// Derive the per-volume key from the (already-unsealed) master and a volume id.
#[must_use]
pub fn derive_volume_key(master: &Key32, volume_id: &[u8]) -> Key32 {
    *blake3::keyed_hash(master, volume_id).as_bytes()
}

/// Derive the per-epoch key from the volume key and the current `key_epoch`.
/// Bumping the epoch yields an unrelated key — the crypto-erasure primitive.
#[must_use]
pub fn derive_epoch_key(volume_key: &Key32, key_epoch: u64) -> Key32 {
    *blake3::keyed_hash(volume_key, &key_epoch.to_le_bytes()).as_bytes()
}

/// The deterministic per-block nonce: `generation ‖ block` (little-endian),
/// zero-padded to 24 bytes. Unique because every CoW write bumps the generation.
#[must_use]
pub fn block_nonce(generation: u64, block: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[0..8].copy_from_slice(&generation.to_le_bytes());
    n[8..16].copy_from_slice(&block.to_le_bytes());
    n
}

/// The AEAD additional data binding a sealed block to its position and epoch.
fn block_aad(generation: u64, block: u64, key_epoch: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[0..8].copy_from_slice(&generation.to_le_bytes());
    aad[8..16].copy_from_slice(&block.to_le_bytes());
    aad[16..24].copy_from_slice(&key_epoch.to_le_bytes());
    aad
}

/// Seal `plaintext` for block `block` at `generation`/`key_epoch` under
/// `epoch_key`, returning `ciphertext ‖ tag`.
///
/// # Errors
/// [`V3Error::Crypto`] if the AEAD fails (effectively never for valid inputs).
pub fn seal_block(
    epoch_key: &Key32,
    generation: u64,
    block: u64,
    key_epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, V3Error> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(epoch_key));
    let nonce = block_nonce(generation, block);
    let aad = block_aad(generation, block, key_epoch);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| V3Error::Crypto)
}

/// Open a `ciphertext ‖ tag` sealed by [`seal_block`] with the same parameters.
///
/// # Errors
/// [`V3Error::Crypto`] if the tag does not verify (wrong key/epoch/position,
/// tampering, or truncation).
pub fn open_block(
    epoch_key: &Key32,
    generation: u64,
    block: u64,
    key_epoch: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, V3Error> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(epoch_key));
    let nonce = block_nonce(generation, block);
    let aad = block_aad(generation, block, key_epoch);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| V3Error::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: Key32 = [0x42; KEY_LEN];

    #[test]
    fn key_hierarchy_is_deterministic_and_separated() {
        let vk = derive_volume_key(&MASTER, b"vol-A");
        assert_eq!(vk, derive_volume_key(&MASTER, b"vol-A"), "deterministic");
        // Different volume id / master → different volume key.
        assert_ne!(vk, derive_volume_key(&MASTER, b"vol-B"));
        assert_ne!(vk, derive_volume_key(&[0x43; KEY_LEN], b"vol-A"));
    }

    #[test]
    fn bumping_epoch_erases() {
        let vk = derive_volume_key(&MASTER, b"vol");
        let e0 = derive_epoch_key(&vk, 0);
        let e1 = derive_epoch_key(&vk, 1);
        assert_ne!(e0, e1, "epoch bump must change the key (crypto erasure)");
    }

    #[test]
    fn nonce_is_unique_per_generation_and_block() {
        assert_ne!(block_nonce(1, 5), block_nonce(2, 5), "generation differs");
        assert_ne!(block_nonce(1, 5), block_nonce(1, 6), "block differs");
        assert_eq!(block_nonce(1, 5), block_nonce(1, 5), "deterministic");
    }

    #[test]
    fn seal_open_round_trips() {
        let ek = derive_epoch_key(&derive_volume_key(&MASTER, b"vol"), 7);
        let plain = b"the quick brown fox jumps over the lazy dog";
        let sealed = seal_block(&ek, 3, 10, 7, plain).unwrap();
        assert_eq!(sealed.len(), plain.len() + TAG_LEN, "ciphertext + tag");
        let opened = open_block(&ek, 3, 10, 7, &sealed).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn tamper_is_detected() {
        let ek = [0x11; KEY_LEN];
        let mut sealed = seal_block(&ek, 1, 1, 0, b"secret").unwrap();
        sealed[0] ^= 0xFF;
        assert_eq!(open_block(&ek, 1, 1, 0, &sealed), Err(V3Error::Crypto));
    }

    #[test]
    fn wrong_position_or_epoch_fails_aad() {
        let ek = [0x22; KEY_LEN];
        let sealed = seal_block(&ek, 5, 9, 2, b"payload").unwrap();
        // Right key, wrong block → AAD mismatch.
        assert_eq!(open_block(&ek, 5, 8, 2, &sealed), Err(V3Error::Crypto));
        // Right key/position, wrong epoch → AAD mismatch.
        assert_eq!(open_block(&ek, 5, 9, 3, &sealed), Err(V3Error::Crypto));
    }

    #[test]
    fn old_epoch_key_cannot_open_new_epoch_block() {
        let vk = derive_volume_key(&MASTER, b"vol");
        let old = derive_epoch_key(&vk, 0);
        let new = derive_epoch_key(&vk, 1);
        let sealed = seal_block(&new, 1, 1, 1, b"after rotation").unwrap();
        assert_eq!(open_block(&old, 1, 1, 1, &sealed), Err(V3Error::Crypto));
    }
}

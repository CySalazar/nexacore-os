//! Full-disk encryption key management: volume header + unlock paths
//! (WS3-07.1/.5/.9, NCIP-027 §S7).
//!
//! A per-volume [`FdeHeader`] carries the metadata needed to unlock an
//! encrypted volume without ever storing the volume key in the clear:
//!
//! - a **key id** — a volume-keyed BLAKE3 MAC of a fixed label, so a mount can
//!   confirm the correct key was recovered *before* trusting any data, without
//!   the key ever appearing on disk (WS3-07.1 validation-at-mount);
//! - a **wrapped volume key** — the volume key sealed (XChaCha20-Poly1305, via
//!   [`super::block_crypto`]) under a *key-encryption key* (KEK). The KEK comes
//!   either from the TEE/TPM sealing provider (WS3-07.3, the caller's job — this
//!   module never sees the master) or from a passphrase (WS3-07.5);
//! - a **KDF salt + iteration count** for the passphrase path;
//! - the current **`key_epoch`**, whose rotation is the per-volume crypto
//!   erasure primitive (WS3-07.9).
//!
//! The passphrase KDF is a seam: [`Blake3IteratedKdf`] is a functional
//! placeholder — a memory-hard **Argon2id** is the production requirement and is
//! library-gated (no vetted `no_std` Argon2 crate is vendored yet), exactly like
//! the SHA-1/PBKDF2 seam in the Wi-Fi supplicant.

use alloc::vec::Vec;

use super::{
    V3Error,
    block_crypto::{Key32, open_block, seal_block},
};

/// Header magic (`"NCFSFDE1"`).
const MAGIC: [u8; 8] = *b"NCFSFDE1";
/// Header format version.
const VERSION: u32 = 1;
/// Length of the KDF salt.
pub const SALT_LEN: usize = 16;
/// The wrapping nonce coordinate for the key slot (a sentinel, not a real
/// block); the wrap AEAD binds `key_epoch` in its additional data.
const KEY_SLOT: u64 = u64::MAX;
/// The label MAC-ed under the volume key to form the key id.
const KEY_ID_LABEL: &[u8] = b"NCFS-FDE-key-id-v1";

// Byte offsets within the header block.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 8;
const OFF_KEY_EPOCH: usize = 12;
const OFF_KDF_ITERS: usize = 20;
const OFF_SALT: usize = 24;
const OFF_KEY_ID: usize = 40;
const OFF_WRAPPED_LEN: usize = 72;
const OFF_WRAPPED: usize = 76;

/// A pluggable passphrase key-derivation function. The default
/// [`Blake3IteratedKdf`] is a placeholder; a memory-hard Argon2id backend plugs
/// in behind this trait.
pub trait PassphraseKdf {
    /// Derive a 32-byte key-encryption key from `passphrase` and `salt`.
    fn derive(&self, passphrase: &[u8], salt: &[u8], iterations: u32) -> Key32;
}

/// An iterated-BLAKE3 KDF. **Not memory-hard** — a stand-in until Argon2id is
/// vendored; adequate for exercising the wrapping/unlock logic host-side.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3IteratedKdf;

impl PassphraseKdf for Blake3IteratedKdf {
    fn derive(&self, passphrase: &[u8], salt: &[u8], iterations: u32) -> Key32 {
        // Seed = keyed(salt-derived key, passphrase); then iterate.
        let salt_key = *blake3::hash(salt).as_bytes();
        let mut acc = *blake3::keyed_hash(&salt_key, passphrase).as_bytes();
        for _ in 0..iterations {
            acc = *blake3::keyed_hash(&salt_key, &acc).as_bytes();
        }
        acc
    }
}

/// Compute the volume key id (a keyed MAC that proves key possession without
/// revealing the key).
fn compute_key_id(volume_key: &Key32) -> [u8; 32] {
    *blake3::keyed_hash(volume_key, KEY_ID_LABEL).as_bytes()
}

/// Constant-time equality for two 32-byte digests.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn wrap_key(kek: &Key32, key_epoch: u64, volume_key: &Key32) -> Result<Vec<u8>, V3Error> {
    seal_block(kek, 0, KEY_SLOT, key_epoch, volume_key)
}

fn unwrap_key(kek: &Key32, key_epoch: u64, wrapped: &[u8]) -> Result<Key32, V3Error> {
    let plain = open_block(kek, 0, KEY_SLOT, key_epoch, wrapped)?;
    Key32::try_from(plain.as_slice()).map_err(|_| V3Error::Crypto)
}

/// The full-disk-encryption volume header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdeHeader {
    key_epoch: u64,
    kdf_iterations: u32,
    salt: [u8; SALT_LEN],
    key_id: [u8; 32],
    wrapped_key: Vec<u8>,
}

impl FdeHeader {
    /// Create a header wrapping `volume_key` under `kek`, recording the key id
    /// and the passphrase-KDF parameters.
    ///
    /// # Errors
    /// [`V3Error::Crypto`] if wrapping the volume key fails.
    pub fn create(
        volume_key: &Key32,
        kek: &Key32,
        key_epoch: u64,
        salt: [u8; SALT_LEN],
        kdf_iterations: u32,
    ) -> Result<Self, V3Error> {
        Ok(Self {
            key_epoch,
            kdf_iterations,
            salt,
            key_id: compute_key_id(volume_key),
            wrapped_key: wrap_key(kek, key_epoch, volume_key)?,
        })
    }

    /// The current crypto-erasure epoch.
    #[must_use]
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// The passphrase-KDF salt.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The passphrase-KDF iteration count.
    #[must_use]
    pub fn kdf_iterations(&self) -> u32 {
        self.kdf_iterations
    }

    /// Whether `volume_key` matches the header's recorded key id (the
    /// validation performed at mount before trusting any decrypted data).
    #[must_use]
    pub fn verify_key(&self, volume_key: &Key32) -> bool {
        ct_eq(&compute_key_id(volume_key), &self.key_id)
    }

    /// Recover the volume key from the header using a key-encryption key,
    /// checking it against the recorded key id (fail-closed).
    ///
    /// # Errors
    /// [`V3Error::Crypto`] if the wrapped key does not unseal under `kek`, or
    /// the recovered key does not match the header's key id.
    pub fn unlock_with_kek(&self, kek: &Key32) -> Result<Key32, V3Error> {
        let volume_key = unwrap_key(kek, self.key_epoch, &self.wrapped_key)?;
        if self.verify_key(&volume_key) {
            Ok(volume_key)
        } else {
            Err(V3Error::Crypto)
        }
    }

    /// Recover the volume key via a passphrase: derive the KEK with `kdf` over
    /// the header's salt/iterations, then [`Self::unlock_with_kek`].
    ///
    /// # Errors
    /// [`V3Error::Crypto`] if the derived KEK does not unlock the header (wrong
    /// passphrase).
    pub fn unlock_with_passphrase<K: PassphraseKdf>(
        &self,
        kdf: &K,
        passphrase: &[u8],
    ) -> Result<Key32, V3Error> {
        let kek = kdf.derive(passphrase, &self.salt, self.kdf_iterations);
        self.unlock_with_kek(&kek)
    }

    /// Rotate the crypto-erasure epoch: recover the volume key under `kek`, bump
    /// `key_epoch`, and re-wrap. Data still sealed under the old epoch key
    /// becomes unreadable (erasure); the volume key and key id are unchanged, so
    /// re-encrypting the volume under the new epoch is a separate step.
    ///
    /// # Errors
    /// [`V3Error::Crypto`] if the current wrapped key does not unlock under
    /// `kek`, or [`V3Error::Overflow`] if the epoch counter would wrap.
    pub fn rotate_epoch(&self, kek: &Key32) -> Result<Self, V3Error> {
        let volume_key = self.unlock_with_kek(kek)?;
        let next_epoch = self.key_epoch.checked_add(1).ok_or(V3Error::Overflow)?;
        Ok(Self {
            key_epoch: next_epoch,
            kdf_iterations: self.kdf_iterations,
            salt: self.salt,
            key_id: self.key_id,
            wrapped_key: wrap_key(kek, next_epoch, &volume_key)?,
        })
    }

    /// Serialise the header into a 4 KiB block.
    ///
    /// # Errors
    /// [`V3Error::Overflow`] if the wrapped key does not fit the header block.
    pub fn encode(&self) -> Result<super::Block, V3Error> {
        let mut block = super::zero_block();
        let wrapped_len = u32::try_from(self.wrapped_key.len()).map_err(|_| V3Error::Overflow)?;
        put(&mut block, OFF_MAGIC, &MAGIC)?;
        put(&mut block, OFF_VERSION, &VERSION.to_le_bytes())?;
        put(&mut block, OFF_KEY_EPOCH, &self.key_epoch.to_le_bytes())?;
        put(
            &mut block,
            OFF_KDF_ITERS,
            &self.kdf_iterations.to_le_bytes(),
        )?;
        put(&mut block, OFF_SALT, &self.salt)?;
        put(&mut block, OFF_KEY_ID, &self.key_id)?;
        put(&mut block, OFF_WRAPPED_LEN, &wrapped_len.to_le_bytes())?;
        // Bounds-checked by `put`: an over-long wrapped key returns Overflow.
        put(&mut block, OFF_WRAPPED, &self.wrapped_key)?;
        Ok(block)
    }

    /// Parse a header from a 4 KiB block.
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] on a bad magic, version, or out-of-range length.
    pub fn decode(block: &super::Block) -> Result<Self, V3Error> {
        if get(block, OFF_MAGIC, 8)? != MAGIC {
            return Err(V3Error::Corrupt);
        }
        if u32::from_le_bytes(get_arr(block, OFF_VERSION)?) != VERSION {
            return Err(V3Error::Corrupt);
        }
        let key_epoch = u64::from_le_bytes(get_arr8(block, OFF_KEY_EPOCH)?);
        let kdf_iterations = u32::from_le_bytes(get_arr(block, OFF_KDF_ITERS)?);
        let salt: [u8; SALT_LEN] = get(block, OFF_SALT, SALT_LEN)?
            .try_into()
            .map_err(|_| V3Error::Corrupt)?;
        let key_id: [u8; 32] = get(block, OFF_KEY_ID, 32)?
            .try_into()
            .map_err(|_| V3Error::Corrupt)?;
        let wrapped_len = u32::from_le_bytes(get_arr(block, OFF_WRAPPED_LEN)?) as usize;
        let wrapped_key = get(block, OFF_WRAPPED, wrapped_len)?.to_vec();
        Ok(Self {
            key_epoch,
            kdf_iterations,
            salt,
            key_id,
            wrapped_key,
        })
    }
}

fn put(block: &mut super::Block, off: usize, bytes: &[u8]) -> Result<(), V3Error> {
    let end = off.checked_add(bytes.len()).ok_or(V3Error::Overflow)?;
    block
        .get_mut(off..end)
        .ok_or(V3Error::Overflow)?
        .copy_from_slice(bytes);
    Ok(())
}

fn get(block: &super::Block, off: usize, len: usize) -> Result<&[u8], V3Error> {
    let end = off.checked_add(len).ok_or(V3Error::Corrupt)?;
    block.get(off..end).ok_or(V3Error::Corrupt)
}

fn get_arr(block: &super::Block, off: usize) -> Result<[u8; 4], V3Error> {
    get(block, off, 4)?.try_into().map_err(|_| V3Error::Corrupt)
}

fn get_arr8(block: &super::Block, off: usize) -> Result<[u8; 8], V3Error> {
    get(block, off, 8)?.try_into().map_err(|_| V3Error::Corrupt)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{super::block_crypto::KEY_LEN, *};

    const VOLUME_KEY: Key32 = [0x5C; KEY_LEN];
    const KEK: Key32 = [0xA1; KEY_LEN];
    const SALT: [u8; SALT_LEN] = [0x33; SALT_LEN];

    fn header() -> FdeHeader {
        FdeHeader::create(&VOLUME_KEY, &KEK, 0, SALT, 4).unwrap()
    }

    #[test]
    fn unlock_with_correct_kek_recovers_volume_key() {
        let h = header();
        assert!(h.verify_key(&VOLUME_KEY));
        assert_eq!(h.unlock_with_kek(&KEK).unwrap(), VOLUME_KEY);
    }

    #[test]
    fn wrong_kek_fails_closed() {
        let h = header();
        let bad_kek: Key32 = [0xFF; KEY_LEN];
        assert_eq!(h.unlock_with_kek(&bad_kek).err(), Some(V3Error::Crypto));
        // A wrong volume key also fails the id check.
        assert!(!h.verify_key(&[0u8; KEY_LEN]));
    }

    #[test]
    fn passphrase_unlock_round_trips_and_rejects_wrong_secret() {
        let kdf = Blake3IteratedKdf;
        // The KEK is whatever the KDF yields; wrap under it, then unlock.
        let kek = kdf.derive(b"correct horse", &SALT, 4);
        let h = FdeHeader::create(&VOLUME_KEY, &kek, 0, SALT, 4).unwrap();
        assert_eq!(
            h.unlock_with_passphrase(&kdf, b"correct horse").unwrap(),
            VOLUME_KEY
        );
        assert_eq!(
            h.unlock_with_passphrase(&kdf, b"battery staple").err(),
            Some(V3Error::Crypto)
        );
    }

    #[test]
    fn epoch_rotation_advances_and_still_unlocks() {
        let h = header();
        assert_eq!(h.key_epoch(), 0);
        let rotated = h.rotate_epoch(&KEK).unwrap();
        assert_eq!(rotated.key_epoch(), 1);
        // Still recovers the same volume key under the new epoch.
        assert_eq!(rotated.unlock_with_kek(&KEK).unwrap(), VOLUME_KEY);
        // The old header's wrapped key was bound to epoch 0; the new one differs.
        assert_ne!(rotated.wrapped_key, h.wrapped_key);
        // The key id is unchanged (same volume key).
        assert_eq!(rotated.key_id, h.key_id);
    }

    #[test]
    fn header_encode_decode_round_trips() {
        let h = header();
        let block = h.encode().unwrap();
        let decoded = FdeHeader::decode(&block).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(decoded.unlock_with_kek(&KEK).unwrap(), VOLUME_KEY);
    }

    #[test]
    fn decode_rejects_bad_magic_and_version() {
        let mut block = header().encode().unwrap();
        block[0] ^= 0xFF;
        assert_eq!(FdeHeader::decode(&block).err(), Some(V3Error::Corrupt));

        let mut block = header().encode().unwrap();
        block[OFF_VERSION] = 9; // unsupported version
        assert_eq!(FdeHeader::decode(&block).err(), Some(V3Error::Corrupt));
    }
}

//! 256-byte v3 inode with capability fingerprint and crypto epoch (WS3-01.5).
//!
//! Each inode is a fixed 256-byte record. A 32-byte **capability fingerprint**
//! at byte offset 40 binds the object to the capability authorised to open it
//! (the contract WS3-01 freezes), and `key_epoch` ties the object to a crypto
//! erasure epoch. Up to four extents live inline; larger files reference an
//! extent-tree block.

#![allow(clippy::cast_possible_truncation)]

use super::{
    V3Error,
    extent::{EXTENT_LEN, Extent, INLINE_EXTENTS},
};

/// Encoded size of a v3 inode.
pub const INODE_SIZE: usize = 256;
/// Byte offset of the 32-byte capability fingerprint (frozen by WS3-01).
pub const FINGERPRINT_OFFSET: usize = 40;
/// Length of the capability fingerprint.
pub const FINGERPRINT_LEN: usize = 32;

/// Inode flag: the object is a directory.
pub const FLAG_DIR: u32 = 1 << 0;
/// Inode flag: the object's extents are ZSTD-compressed (WS3-01.11).
pub const FLAG_COMPRESSED: u32 = 1 << 1;

/// A decoded v3 inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeV3 {
    /// POSIX-style mode (type + permission bits).
    pub mode: u32,
    /// Hard-link count.
    pub nlink: u32,
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Logical file size in bytes (up to 2⁶³).
    pub size: u64,
    /// Modification time (ns since epoch; `0` if no clock).
    pub mtime: u64,
    /// Crypto erasure epoch this object's data is sealed under.
    pub key_epoch: u64,
    /// Capability fingerprint binding the object to its opener.
    pub fingerprint: [u8; FINGERPRINT_LEN],
    /// Inode flags ([`FLAG_DIR`], [`FLAG_COMPRESSED`]).
    pub flags: u32,
    /// Number of valid inline extents (`0..=4`).
    pub extent_count: u32,
    /// Inline extents.
    pub extents: [Extent; INLINE_EXTENTS],
    /// Block index of the extent-tree root for large files (`0` = inline only).
    pub extent_tree_root: u64,
}

impl Default for InodeV3 {
    fn default() -> Self {
        Self {
            mode: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            key_epoch: 0,
            fingerprint: [0u8; FINGERPRINT_LEN],
            flags: 0,
            extent_count: 0,
            extents: [Extent::default(); INLINE_EXTENTS],
            extent_tree_root: 0,
        }
    }
}

impl InodeV3 {
    /// `true` if this inode is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.flags & FLAG_DIR != 0
    }

    /// Validate structural invariants (extent count in range, dirs use inline
    /// extents only).
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] if `extent_count` exceeds the inline capacity.
    pub const fn validate(&self) -> Result<(), V3Error> {
        if self.extent_count as usize > INLINE_EXTENTS {
            return Err(V3Error::Corrupt);
        }
        Ok(())
    }

    /// Encode to a 256-byte record.
    #[must_use]
    pub fn encode(&self) -> [u8; INODE_SIZE] {
        let mut b = [0u8; INODE_SIZE];
        b[0..4].copy_from_slice(&self.mode.to_le_bytes());
        b[4..8].copy_from_slice(&self.nlink.to_le_bytes());
        b[8..12].copy_from_slice(&self.uid.to_le_bytes());
        b[12..16].copy_from_slice(&self.gid.to_le_bytes());
        b[16..24].copy_from_slice(&self.size.to_le_bytes());
        b[24..32].copy_from_slice(&self.mtime.to_le_bytes());
        b[32..40].copy_from_slice(&self.key_epoch.to_le_bytes());
        b[FINGERPRINT_OFFSET..FINGERPRINT_OFFSET + FINGERPRINT_LEN]
            .copy_from_slice(&self.fingerprint);
        b[72..76].copy_from_slice(&self.flags.to_le_bytes());
        b[76..80].copy_from_slice(&self.extent_count.to_le_bytes());
        for (i, e) in self.extents.iter().enumerate() {
            let off = 80 + i * EXTENT_LEN;
            if let Some(slot) = b.get_mut(off..off + EXTENT_LEN) {
                slot.copy_from_slice(&e.encode());
            }
        }
        b[176..184].copy_from_slice(&self.extent_tree_root.to_le_bytes());
        b
    }

    /// Decode a 256-byte record. Returns [`V3Error::Corrupt`] on a short buffer
    /// or a structural violation.
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] if the buffer is shorter than [`INODE_SIZE`] or
    /// fails [`InodeV3::validate`].
    pub fn decode(buf: &[u8]) -> Result<Self, V3Error> {
        let r = buf.get(..INODE_SIZE).ok_or(V3Error::Corrupt)?;
        let u32_at = |o: usize| -> Result<u32, V3Error> {
            Ok(u32::from_le_bytes(
                r.get(o..o + 4)
                    .ok_or(V3Error::Corrupt)?
                    .try_into()
                    .map_err(|_| V3Error::Corrupt)?,
            ))
        };
        let u64_at = |o: usize| -> Result<u64, V3Error> {
            Ok(u64::from_le_bytes(
                r.get(o..o + 8)
                    .ok_or(V3Error::Corrupt)?
                    .try_into()
                    .map_err(|_| V3Error::Corrupt)?,
            ))
        };
        let fingerprint: [u8; FINGERPRINT_LEN] = r
            .get(FINGERPRINT_OFFSET..FINGERPRINT_OFFSET + FINGERPRINT_LEN)
            .ok_or(V3Error::Corrupt)?
            .try_into()
            .map_err(|_| V3Error::Corrupt)?;
        let mut extents = [Extent::default(); INLINE_EXTENTS];
        for (i, slot) in extents.iter_mut().enumerate() {
            let off = 80 + i * EXTENT_LEN;
            *slot = Extent::decode(r.get(off..off + EXTENT_LEN).ok_or(V3Error::Corrupt)?)
                .ok_or(V3Error::Corrupt)?;
        }
        let inode = Self {
            mode: u32_at(0)?,
            nlink: u32_at(4)?,
            uid: u32_at(8)?,
            gid: u32_at(12)?,
            size: u64_at(16)?,
            mtime: u64_at(24)?,
            key_epoch: u64_at(32)?,
            fingerprint,
            flags: u32_at(72)?,
            extent_count: u32_at(76)?,
            extents,
            extent_tree_root: u64_at(176)?,
        };
        inode.validate()?;
        Ok(inode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InodeV3 {
        let mut ino = InodeV3 {
            mode: 0o100_644,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            size: 8192,
            mtime: 42,
            key_epoch: 3,
            fingerprint: [0xAB; FINGERPRINT_LEN],
            flags: 0,
            extent_count: 1,
            extents: [Extent::default(); INLINE_EXTENTS],
            extent_tree_root: 0,
        };
        ino.extents[0] = Extent {
            logical_block: 0,
            physical_block: 500,
            len_blocks: 2,
        };
        ino
    }

    #[test]
    fn inode_is_256_bytes() {
        assert_eq!(sample().encode().len(), INODE_SIZE);
    }

    #[test]
    fn fingerprint_lives_at_offset_40() {
        let ino = sample();
        let enc = ino.encode();
        assert_eq!(
            &enc[FINGERPRINT_OFFSET..FINGERPRINT_OFFSET + FINGERPRINT_LEN],
            &[0xAB; 32]
        );
        assert_eq!(FINGERPRINT_OFFSET, 40, "frozen by WS3-01");
    }

    #[test]
    fn round_trips() {
        let ino = sample();
        let back = InodeV3::decode(&ino.encode()).unwrap();
        assert_eq!(back, ino);
    }

    #[test]
    fn dir_flag_and_default() {
        let mut ino = InodeV3 {
            flags: FLAG_DIR,
            ..InodeV3::default()
        };
        assert!(ino.is_dir());
        ino.flags = 0;
        assert!(!ino.is_dir());
        assert_eq!(InodeV3::default().nlink, 1);
    }

    #[test]
    fn decode_rejects_short_and_bad_extent_count() {
        assert_eq!(InodeV3::decode(&[0u8; 100]), Err(V3Error::Corrupt));
        let mut ino = sample();
        ino.extent_count = 9; // > INLINE_EXTENTS
        assert_eq!(InodeV3::decode(&ino.encode()), Err(V3Error::Corrupt));
    }
}

//! Dual-superblock A/B atomic CoW root commit (WS3-01.2).
//!
//! Two superblock slots live at blocks 0 (A) and 1 (B). Each carries a
//! monotone `generation` and a BLAKE3-keyed self-MAC over its own bytes. A
//! commit writes the *new* generation to the slot `generation & 1` — the
//! opposite slot from the one it supersedes — then flushes and records the
//! commit point. A crash mid-write therefore leaves the previous generation's
//! slot intact, and [`mount`] simply selects the highest generation whose
//! self-MAC verifies. This is the atomic root-commit the rest of the v3 format
//! builds on (ADR-0051 D6).

// Byte-packing the superblock: `BLOCK_SIZE`/length casts are range-bounded.
#![allow(clippy::cast_possible_truncation)]

use super::{BLOCK_SIZE, Block, V3Error, blockdev::BlockDevice, zero_block};

/// v3 superblock magic (`"NCFSV3\0\0"`).
pub const MAGIC: [u8; 8] = *b"NCFSV3\0\0";
/// On-disk format version this module writes.
pub const VERSION: u32 = 3;
/// Length of the superblock self-MAC.
pub const MAC_LEN: usize = 16;
/// Offset of the self-MAC within the block (covers bytes `0..MAC_OFFSET`).
pub const MAC_OFFSET: usize = BLOCK_SIZE - MAC_LEN;

/// Block index of superblock slot A.
pub const SLOT_A: u64 = 0;
/// Block index of superblock slot B.
pub const SLOT_B: u64 = 1;

/// A 32-byte volume key used to derive the superblock self-MAC.
pub type MacKey = [u8; 32];

/// The decoded v3 superblock: global volume metadata + the committed roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperblockV3 {
    /// Commit generation (monotone; the higher valid slot is the mount point).
    pub generation: u64,
    /// Total addressable blocks on the volume.
    pub total_blocks: u64,
    /// Inode number of the root directory.
    pub root_dir_inode: u64,
    /// Root of the BLAKE3-keyed Merkle integrity tree at this generation.
    pub merkle_root: [u8; 32],
    /// Crypto erasure epoch (bumping it makes prior data unrecoverable).
    pub key_epoch: u64,
    /// Blocks not currently allocated.
    pub free_blocks: u64,
    /// Number of inodes in use.
    pub inode_count: u64,
    /// Block index of the allocation map.
    pub alloc_map_block: u64,
    /// Block index of the snapshot table (`0` if none yet).
    pub snapshot_table_block: u64,
}

fn put_u32(block: &mut Block, off: usize, v: u32) {
    if let Some(s) = block.get_mut(off..off + 4) {
        s.copy_from_slice(&v.to_le_bytes());
    }
}

fn put_u64(block: &mut Block, off: usize, v: u64) {
    if let Some(s) = block.get_mut(off..off + 8) {
        s.copy_from_slice(&v.to_le_bytes());
    }
}

fn get_u32(block: &Block, off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        block.get(off..off + 4)?.try_into().ok()?,
    ))
}

fn get_u64(block: &Block, off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        block.get(off..off + 8)?.try_into().ok()?,
    ))
}

fn self_mac(block: &Block, key: &MacKey) -> [u8; MAC_LEN] {
    let digest = blake3::keyed_hash(key, block.get(..MAC_OFFSET).unwrap_or(&[]));
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&digest.as_bytes()[..MAC_LEN]);
    mac
}

impl SuperblockV3 {
    /// Encode the superblock into a 4 KiB block, stamping the self-MAC with
    /// `key`.
    #[must_use]
    pub fn encode(&self, key: &MacKey) -> Block {
        let mut b = zero_block();
        if let Some(s) = b.get_mut(0..8) {
            s.copy_from_slice(&MAGIC);
        }
        put_u32(&mut b, 8, VERSION);
        put_u32(&mut b, 12, BLOCK_SIZE as u32);
        put_u64(&mut b, 16, self.generation);
        put_u64(&mut b, 24, self.total_blocks);
        put_u64(&mut b, 32, self.root_dir_inode);
        if let Some(s) = b.get_mut(40..72) {
            s.copy_from_slice(&self.merkle_root);
        }
        put_u64(&mut b, 72, self.key_epoch);
        put_u64(&mut b, 80, self.free_blocks);
        put_u64(&mut b, 88, self.inode_count);
        put_u64(&mut b, 96, self.alloc_map_block);
        put_u64(&mut b, 104, self.snapshot_table_block);
        let mac = self_mac(&b, key);
        if let Some(s) = b.get_mut(MAC_OFFSET..BLOCK_SIZE) {
            s.copy_from_slice(&mac);
        }
        b
    }

    /// Decode and authenticate a superblock block. Returns
    /// [`V3Error::Corrupt`] on a bad magic/version or a failed self-MAC.
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] on a bad magic, wrong version, or a self-MAC
    /// mismatch (wrong key or tampered block).
    pub fn decode(block: &Block, key: &MacKey) -> Result<Self, V3Error> {
        if block.get(0..8) != Some(&MAGIC) {
            return Err(V3Error::Corrupt);
        }
        if get_u32(block, 8) != Some(VERSION) {
            return Err(V3Error::Corrupt);
        }
        let stored_mac = block.get(MAC_OFFSET..BLOCK_SIZE).ok_or(V3Error::Corrupt)?;
        let computed = self_mac(block, key);
        if stored_mac != computed {
            return Err(V3Error::Corrupt);
        }
        let merkle_root: [u8; 32] = block
            .get(40..72)
            .ok_or(V3Error::Corrupt)?
            .try_into()
            .map_err(|_| V3Error::Corrupt)?;
        Ok(Self {
            generation: get_u64(block, 16).ok_or(V3Error::Corrupt)?,
            total_blocks: get_u64(block, 24).ok_or(V3Error::Corrupt)?,
            root_dir_inode: get_u64(block, 32).ok_or(V3Error::Corrupt)?,
            merkle_root,
            key_epoch: get_u64(block, 72).ok_or(V3Error::Corrupt)?,
            free_blocks: get_u64(block, 80).ok_or(V3Error::Corrupt)?,
            inode_count: get_u64(block, 88).ok_or(V3Error::Corrupt)?,
            alloc_map_block: get_u64(block, 96).ok_or(V3Error::Corrupt)?,
            snapshot_table_block: get_u64(block, 104).ok_or(V3Error::Corrupt)?,
        })
    }

    /// The slot a superblock of this generation is written to (`generation & 1`).
    #[must_use]
    pub const fn slot_for_generation(generation: u64) -> u64 {
        generation & 1
    }
}

/// Commit `sb` (with its already-incremented `generation`) to its A/B slot,
/// then flush and record the commit point — the atomic root commit.
///
/// # Errors
/// Propagates [`BlockDevice`] errors.
pub fn commit<D: BlockDevice>(dev: &mut D, sb: &SuperblockV3, key: &MacKey) -> Result<(), V3Error> {
    let slot = SuperblockV3::slot_for_generation(sb.generation);
    let block = sb.encode(key);
    dev.write_block(slot, &block)?;
    dev.flush()?;
    dev.commit_root(sb.generation)?;
    Ok(())
}

/// Mount: read both slots and return the valid superblock with the highest
/// generation.
///
/// # Errors
/// [`V3Error::NoValidSuperblock`] if neither slot authenticates, or a
/// [`BlockDevice`] error.
pub fn mount<D: BlockDevice>(dev: &D, key: &MacKey) -> Result<SuperblockV3, V3Error> {
    let mut best: Option<SuperblockV3> = None;
    for slot in [SLOT_A, SLOT_B] {
        let mut block = zero_block();
        dev.read_block(slot, &mut block)?;
        if let Ok(sb) = SuperblockV3::decode(&block, key) {
            if best.is_none_or(|b| sb.generation > b.generation) {
                best = Some(sb);
            }
        }
    }
    best.ok_or(V3Error::NoValidSuperblock)
}

#[cfg(test)]
mod tests {
    use super::{super::blockdev::MemBlockDevice, *};

    fn sample(g: u64) -> SuperblockV3 {
        SuperblockV3 {
            generation: g,
            total_blocks: 1024,
            root_dir_inode: 1,
            merkle_root: [g as u8; 32],
            key_epoch: 0,
            free_blocks: 1000,
            inode_count: 1,
            alloc_map_block: 2,
            snapshot_table_block: 0,
        }
    }

    #[test]
    fn encode_decode_round_trips() {
        let key = [0x11u8; 32];
        let sb = sample(5);
        let block = sb.encode(&key);
        let back = SuperblockV3::decode(&block, &key).unwrap();
        assert_eq!(back, sb);
    }

    #[test]
    fn wrong_key_fails_mac() {
        let sb = sample(1);
        let block = sb.encode(&[0x11; 32]);
        assert_eq!(
            SuperblockV3::decode(&block, &[0x22; 32]),
            Err(V3Error::Corrupt)
        );
    }

    #[test]
    fn tampered_block_fails_mac() {
        let key = [7u8; 32];
        let mut block = sample(3).encode(&key);
        block[50] ^= 0xFF; // flip a byte in the merkle_root region
        assert_eq!(SuperblockV3::decode(&block, &key), Err(V3Error::Corrupt));
    }

    #[test]
    fn slots_alternate_by_generation() {
        assert_eq!(SuperblockV3::slot_for_generation(2), SLOT_A);
        assert_eq!(SuperblockV3::slot_for_generation(3), SLOT_B);
    }

    #[test]
    fn mount_picks_highest_generation() {
        let key = [9u8; 32];
        let mut dev = MemBlockDevice::new(16);
        // gen 4 → slot A(0), gen 5 → slot B(1).
        commit(&mut dev, &sample(4), &key).unwrap();
        commit(&mut dev, &sample(5), &key).unwrap();
        let sb = mount(&dev, &key).unwrap();
        assert_eq!(sb.generation, 5);
        assert_eq!(dev.committed_generation(), 5);
    }

    #[test]
    fn crash_during_new_commit_keeps_previous_generation() {
        let key = [3u8; 32];
        let mut dev = MemBlockDevice::new(16);
        // Establish gen 4 (slot A) and gen 5 (slot B).
        commit(&mut dev, &sample(4), &key).unwrap();
        commit(&mut dev, &sample(5), &key).unwrap();
        // A "crash" while writing gen 6 (slot A) → slot A becomes garbage.
        let mut garbage = zero_block();
        garbage[0] = 0xFF;
        dev.write_block(SuperblockV3::slot_for_generation(6), &garbage)
            .unwrap();
        // Mount still finds the last good generation (5, slot B).
        let sb = mount(&dev, &key).unwrap();
        assert_eq!(sb.generation, 5);
    }

    #[test]
    fn mount_with_no_valid_slot_errors() {
        let dev = MemBlockDevice::new(4); // all zero → no magic
        assert_eq!(mount(&dev, &[0; 32]), Err(V3Error::NoValidSuperblock));
    }
}

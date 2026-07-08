//! `mkfs.ncfs` — format a block device with an initial NCFS v3 volume
//! (WS3-01.9).
//!
//! [`format`] lays out the minimal mountable volume: superblock slots A/B, the
//! allocation map, and an empty root directory object, then commits the first
//! generation. After it returns, [`super::superblock::mount`] succeeds and the
//! root directory decodes empty.
//!
//! Block layout written here:
//!
//! | block | contents              |
//! |-------|-----------------------|
//! | 0     | superblock slot A     |
//! | 1     | superblock slot B     |
//! | 2     | allocation map        |
//! | 3     | root directory object |
//!
//! The full inode table is the CoW object tree (WS3-01.3); this minimal format
//! establishes the superblock, the allocation map and the root directory so the
//! volume mounts.

// Block indices fit usize on 64-bit targets; the casts are bounded by the map.
// `BLOCK_SIZE / 4` is an exact element count; `map`/`max` read as similar.
#![allow(
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::similar_names
)]

use super::{
    BLOCK_SIZE, V3Error,
    blockdev::BlockDevice,
    dirent::Directory,
    extent::AllocMap,
    merkle,
    superblock::{MacKey, SuperblockV3, commit},
    zero_block,
};

/// Block index of the allocation map.
pub const ALLOC_MAP_BLOCK: u64 = 2;
/// Block index of the root directory object.
pub const ROOT_DIR_BLOCK: u64 = 3;
/// Inode number of the root directory.
pub const ROOT_INODE: u64 = 1;
/// Blocks reserved by [`format`] before any user data.
pub const RESERVED_BLOCKS: u64 = 4;
/// Smallest volume `format` will accept.
pub const MIN_BLOCKS: u64 = RESERVED_BLOCKS;

/// The two 32-byte keys a formatted volume is bound to.
#[derive(Debug, Clone, Copy)]
pub struct VolumeKeys {
    /// Key for the superblock self-MAC.
    pub mac: MacKey,
    /// Key for the BLAKE3-keyed Merkle integrity tree.
    pub merkle: merkle::MerkleKey,
}

/// Format `dev` as a fresh NCFS v3 volume and return the committed superblock.
///
/// # Errors
/// [`V3Error::BlockOutOfRange`] if the device is smaller than [`MIN_BLOCKS`], or
/// a propagated [`BlockDevice`] error.
pub fn format<D: BlockDevice>(dev: &mut D, keys: &VolumeKeys) -> Result<SuperblockV3, V3Error> {
    let total = dev.block_count();
    if total < MIN_BLOCKS {
        return Err(V3Error::BlockOutOfRange);
    }

    // Empty root directory object at block 3.
    let root_dir = Directory::new();
    let mut root_block = zero_block();
    let encoded = root_dir.encode();
    if encoded.len() > BLOCK_SIZE {
        return Err(V3Error::Overflow);
    }
    if let Some(slot) = root_block.get_mut(..encoded.len()) {
        slot.copy_from_slice(&encoded);
    }
    dev.write_block(ROOT_DIR_BLOCK, &root_block)?;

    // Allocation map with the reserved blocks pinned, serialised to block 2.
    let alloc = AllocMap::new(total, RESERVED_BLOCKS);
    let mut map_block = zero_block();
    write_alloc_map(&alloc, &mut map_block);
    dev.write_block(ALLOC_MAP_BLOCK, &map_block)?;

    // Merkle root over the initial data blocks (just the root directory here).
    let merkle_root = merkle::root_over_blocks(&keys.merkle, &[&root_block]);

    let sb = SuperblockV3 {
        generation: 1,
        total_blocks: total,
        root_dir_inode: ROOT_INODE,
        merkle_root,
        key_epoch: 0,
        free_blocks: total - RESERVED_BLOCKS,
        inode_count: 1,
        alloc_map_block: ALLOC_MAP_BLOCK,
        snapshot_table_block: 0,
    };
    commit(dev, &sb, &keys.mac)?;
    Ok(sb)
}

/// Serialise an allocation map's refcounts into a single block as little-endian
/// `u32`s (one block holds up to `BLOCK_SIZE / 4` entries; larger volumes use a
/// multi-block map — WS3-01.3 follow-up).
fn write_alloc_map(map: &AllocMap, block: &mut super::Block) {
    let max = BLOCK_SIZE / 4;
    for (i, chunk) in block.chunks_mut(4).take(max).enumerate() {
        let rc = map.refcount(i as u64);
        chunk.copy_from_slice(&rc.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{blockdev::MemBlockDevice, superblock::mount},
        *,
    };

    fn keys() -> VolumeKeys {
        VolumeKeys {
            mac: [0x11; 32],
            merkle: [0x22; 32],
        }
    }

    #[test]
    fn format_produces_mountable_volume() {
        let mut dev = MemBlockDevice::new(64);
        let sb = format(&mut dev, &keys()).unwrap();
        assert_eq!(sb.generation, 1);
        assert_eq!(sb.root_dir_inode, ROOT_INODE);
        assert_eq!(sb.free_blocks, 64 - RESERVED_BLOCKS);

        // It mounts and matches what we wrote.
        let mounted = mount(&dev, &keys().mac).unwrap();
        assert_eq!(mounted, sb);
    }

    #[test]
    fn formatted_root_dir_is_empty() {
        let mut dev = MemBlockDevice::new(32);
        format(&mut dev, &keys()).unwrap();
        let mut block = zero_block();
        dev.read_block(ROOT_DIR_BLOCK, &mut block).unwrap();
        let dir = Directory::decode(&block).unwrap();
        assert!(dir.is_empty());
    }

    #[test]
    fn merkle_root_matches_written_root_dir() {
        let mut dev = MemBlockDevice::new(16);
        let sb = format(&mut dev, &keys()).unwrap();
        let mut block = zero_block();
        dev.read_block(ROOT_DIR_BLOCK, &mut block).unwrap();
        let expected = merkle::root_over_blocks(&keys().merkle, &[&block]);
        assert_eq!(sb.merkle_root, expected);
    }

    #[test]
    fn too_small_device_is_rejected() {
        let mut dev = MemBlockDevice::new(MIN_BLOCKS - 1);
        assert_eq!(format(&mut dev, &keys()), Err(V3Error::BlockOutOfRange));
    }

    #[test]
    fn alloc_map_persists_reserved_blocks() {
        let mut dev = MemBlockDevice::new(16);
        format(&mut dev, &keys()).unwrap();
        let mut block = zero_block();
        dev.read_block(ALLOC_MAP_BLOCK, &mut block).unwrap();
        // Reserved blocks 0..4 have refcount 1; block 4 is free (0).
        for i in 0..RESERVED_BLOCKS as usize {
            let rc = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
            assert_eq!(rc, 1, "reserved block {i}");
        }
        let rc4 = u32::from_le_bytes(block[16..20].try_into().unwrap());
        assert_eq!(rc4, 0, "first data block is free");
    }
}

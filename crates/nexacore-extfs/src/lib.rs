//! # `nexacore-extfs`
//!
//! Read-only reader for the ext2/3/4 filesystem family, WS3-05.2/.3.
//!
//! Linux images and disks are overwhelmingly ext4. This crate is the
//! host-testable, dependency-free, strictly **read-only** half of mounting them:
//! it parses the [`Superblock`], locates a group's inode table through the
//! block-group descriptors, reads an [`Inode`] (WS3-05.2), and resolves its data
//! through the ext4 extent tree to list directories ([`ExtFs::read_dir`]) and
//! read files ([`ExtFs::read_file`]) (WS3-05.3).
//!
//! ## Read-only by construction
//!
//! The reader borrows an immutable image (`&[u8]`) and never exposes a write
//! path. Exposing it as a capability-gated (`READONLY_COMPAT_FS`, WS3-05.1) VFS
//! service is WS3-05.8; FAT ([`nexacore-fatfs`](https://docs.rs)) and NTFS are
//! sibling members of the WS3-05 compat set.
//!
//! ## `no_std` + `alloc`
//!
//! `#![no_std]` pulling only `alloc` (no crypto, no `std`), so it builds for
//! `x86_64-unknown-none` as well as the developer host.

#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
        // The test builds a synthetic ext image byte-by-byte.
        clippy::cast_possible_truncation,
        clippy::integer_division,
    )
)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

/// The ext superblock magic (`s_magic`).
pub const EXT_MAGIC: u16 = 0xEF53;
/// The ext superblock lives 1024 bytes into the volume.
pub const SUPERBLOCK_OFFSET: usize = 1024;
/// The root directory is always inode 2.
pub const ROOT_INODE: u32 = 2;
/// `EXT4_EXTENTS_FL` — the inode's `i_block` holds an extent tree.
pub const EXTENTS_FLAG: u32 = 0x0008_0000;

/// Errors from reading an ext volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtError {
    /// The image is shorter than the structure being read requires.
    Truncated,
    /// The superblock magic did not match [`EXT_MAGIC`].
    BadMagic,
    /// A structural field was invalid (zero geometry, out-of-range block, …).
    Corrupt,
    /// An inode number was zero or beyond the filesystem's inode count.
    BadInode,
    /// A directory operation was attempted on a non-directory inode.
    NotADirectory,
    /// A feature required to read the structure is not implemented.
    Unsupported,
}

/// The ext4 extent-header magic (`eh_magic`).
pub const EXTENT_MAGIC: u16 = 0xF30A;
/// Bound on extent-tree depth (index-node recursion) to reject hostile trees.
const MAX_EXTENT_DEPTH: u32 = 5;

/// A directory entry (`ext4_dir_entry_2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The referenced inode number.
    pub inode: u32,
    /// The entry name.
    pub name: String,
    /// The `file_type` byte (1 = regular file, 2 = directory, …).
    pub file_type: u8,
}

impl DirEntry {
    /// Whether the entry names a subdirectory (`file_type == 2`).
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.file_type == 2
    }
}

/// Read a little-endian `u16` at `off`, bounds-checked.
fn u16_at(buf: &[u8], off: usize) -> Result<u16, ExtError> {
    let b: [u8; 2] = buf
        .get(off..off + 2)
        .ok_or(ExtError::Truncated)?
        .try_into()
        .map_err(|_| ExtError::Truncated)?;
    Ok(u16::from_le_bytes(b))
}

/// Read a little-endian `u32` at `off`, bounds-checked.
fn u32_at(buf: &[u8], off: usize) -> Result<u32, ExtError> {
    let b: [u8; 4] = buf
        .get(off..off + 4)
        .ok_or(ExtError::Truncated)?
        .try_into()
        .map_err(|_| ExtError::Truncated)?;
    Ok(u32::from_le_bytes(b))
}

/// The parsed ext superblock (the fields the reader needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    /// Total inode count.
    pub inodes_count: u32,
    /// Total block count (low 32 bits).
    pub blocks_count: u32,
    /// Block size in bytes (`1024 << s_log_block_size`).
    pub block_size: u32,
    /// Blocks per group.
    pub blocks_per_group: u32,
    /// Inodes per group.
    pub inodes_per_group: u32,
    /// Inode size in bytes (128 for legacy revisions).
    pub inode_size: u16,
    /// First non-reserved inode.
    pub first_inode: u32,
    /// `s_feature_incompat` flags.
    pub feature_incompat: u32,
    /// Block-group-descriptor size in bytes (32, or 64 with the 64-bit feature).
    pub desc_size: u16,
}

/// `INCOMPAT_64BIT` — block-group descriptors are 64 bytes.
const INCOMPAT_64BIT: u32 = 0x0080;

impl Superblock {
    /// Parse the superblock from a whole-volume image.
    ///
    /// # Errors
    /// [`ExtError::Truncated`] if the image is too short, [`ExtError::BadMagic`]
    /// if `s_magic` is wrong, or [`ExtError::Corrupt`] on invalid geometry.
    pub fn parse(image: &[u8]) -> Result<Self, ExtError> {
        let sb = image.get(SUPERBLOCK_OFFSET..).ok_or(ExtError::Truncated)?;
        if u16_at(sb, 56)? != EXT_MAGIC {
            return Err(ExtError::BadMagic);
        }
        let log_block_size = u32_at(sb, 24)?;
        if log_block_size > 6 {
            // 1024 << 6 = 64 KiB is the largest sane block size.
            return Err(ExtError::Corrupt);
        }
        let block_size = 1024u32 << log_block_size;
        let inodes_per_group = u32_at(sb, 40)?;
        let blocks_per_group = u32_at(sb, 32)?;
        if inodes_per_group == 0 || blocks_per_group == 0 {
            return Err(ExtError::Corrupt);
        }
        let raw_inode_size = u16_at(sb, 88)?;
        let inode_size = if raw_inode_size == 0 {
            128
        } else {
            raw_inode_size
        };
        if inode_size < 128 {
            return Err(ExtError::Corrupt);
        }
        let feature_incompat = u32_at(sb, 96)?;
        let raw_desc_size = u16_at(sb, 254)?;
        let desc_size = if feature_incompat & INCOMPAT_64BIT != 0 {
            if raw_desc_size < 64 {
                64
            } else {
                raw_desc_size
            }
        } else {
            32
        };
        Ok(Self {
            inodes_count: u32_at(sb, 0)?,
            blocks_count: u32_at(sb, 4)?,
            block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            first_inode: u32_at(sb, 84)?,
            feature_incompat,
            desc_size,
        })
    }

    /// The block number where the block-group-descriptor table begins.
    ///
    /// The superblock always starts at byte 1024, so with a 1024-byte block it
    /// occupies block 1 (descriptors follow in block 2); with a larger block the
    /// superblock sits inside block 0 and descriptors are in block 1.
    #[must_use]
    pub fn gdt_block(&self) -> u32 {
        if self.block_size == 1024 { 2 } else { 1 }
    }
}

/// A mounted ext volume: the superblock plus the borrowed image.
#[derive(Debug, Clone, Copy)]
pub struct ExtFs<'a> {
    image: &'a [u8],
    sb: Superblock,
}

/// A read ext inode (the fields the reader needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    /// `i_mode` — type + permission bits.
    pub mode: u16,
    /// File size in bytes (assembled from the low/high halves for regular files).
    pub size: u64,
    /// `i_flags`.
    pub flags: u32,
    /// The raw 60-byte `i_block` area (extent tree or classic block map).
    pub block: [u8; 60],
}

impl Inode {
    /// Whether this inode is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }

    /// Whether this inode is a regular file.
    #[must_use]
    pub fn is_regular(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }

    /// Whether the inode stores its data through an ext4 extent tree.
    #[must_use]
    pub fn uses_extents(&self) -> bool {
        self.flags & EXTENTS_FLAG != 0
    }
}

impl<'a> ExtFs<'a> {
    /// Mount an ext volume by parsing its superblock.
    ///
    /// # Errors
    /// As [`Superblock::parse`].
    pub fn open(image: &'a [u8]) -> Result<Self, ExtError> {
        let sb = Superblock::parse(image)?;
        Ok(Self { image, sb })
    }

    /// The parsed superblock.
    #[must_use]
    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// Read the `bg_inode_table` block number for block group `group`.
    ///
    /// # Errors
    /// [`ExtError::Corrupt`] if `group` is out of range, or [`ExtError::Truncated`].
    pub fn inode_table_block(&self, group: u32) -> Result<u64, ExtError> {
        let gdt_byte = u64::from(self.sb.gdt_block()) * u64::from(self.sb.block_size);
        let desc_off = gdt_byte + u64::from(group) * u64::from(self.sb.desc_size);
        let base = usize::try_from(desc_off).map_err(|_| ExtError::Corrupt)?;
        let lo = u32_at(self.image, base + 8)?;
        // With 64-bit descriptors the high half lives at offset 40.
        let hi = if self.sb.desc_size >= 64 {
            u32_at(self.image, base + 40)?
        } else {
            0
        };
        Ok((u64::from(hi) << 32) | u64::from(lo))
    }

    /// Read inode number `ino` (1-based; [`ROOT_INODE`] is the root directory).
    ///
    /// # Errors
    /// [`ExtError::BadInode`] if `ino` is zero or beyond the filesystem,
    /// [`ExtError::Truncated`] on a short image.
    #[allow(clippy::integer_division, reason = "inode-to-group is exact division")]
    pub fn read_inode(&self, ino: u32) -> Result<Inode, ExtError> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(ExtError::BadInode);
        }
        let group = (ino - 1) / self.sb.inodes_per_group;
        let index = (ino - 1) % self.sb.inodes_per_group;
        let table_block = self.inode_table_block(group)?;
        let byte = table_block * u64::from(self.sb.block_size)
            + u64::from(index) * u64::from(self.sb.inode_size);
        let base = usize::try_from(byte).map_err(|_| ExtError::Corrupt)?;
        let mode = u16_at(self.image, base)?;
        let size_lo = u32_at(self.image, base + 4)?;
        let flags = u32_at(self.image, base + 32)?;
        let size_hi = u32_at(self.image, base + 108)?;
        let raw = self
            .image
            .get(base + 40..base + 100)
            .ok_or(ExtError::Truncated)?;
        let mut block = [0u8; 60];
        block.copy_from_slice(raw);
        // The high half of the size only applies to regular files.
        let size = if mode & 0xF000 == 0x8000 {
            (u64::from(size_hi) << 32) | u64::from(size_lo)
        } else {
            u64::from(size_lo)
        };
        Ok(Inode {
            mode,
            size,
            flags,
            block,
        })
    }

    /// Read the root directory inode.
    ///
    /// # Errors
    /// As [`ExtFs::read_inode`].
    pub fn root(&self) -> Result<Inode, ExtError> {
        self.read_inode(ROOT_INODE)
    }

    /// The `block_size` bytes of physical block `block`.
    fn block_slice(&self, block: u64) -> Result<&'a [u8], ExtError> {
        let bs = usize::try_from(self.sb.block_size).map_err(|_| ExtError::Corrupt)?;
        let start = usize::try_from(block.saturating_mul(u64::from(self.sb.block_size)))
            .map_err(|_| ExtError::Corrupt)?;
        self.image
            .get(start..start.checked_add(bs).ok_or(ExtError::Corrupt)?)
            .ok_or(ExtError::Truncated)
    }

    /// Map a `logical` file block to its physical block via the extent tree
    /// (`node` is an extent header + entries), recursing through index nodes.
    fn extent_lookup(
        &self,
        node: &[u8],
        logical: u32,
        depth_budget: u32,
    ) -> Result<Option<u64>, ExtError> {
        if depth_budget == 0 {
            return Err(ExtError::Unsupported);
        }
        if u16_at(node, 0)? != EXTENT_MAGIC {
            return Err(ExtError::Corrupt);
        }
        let entries = u16_at(node, 2)?;
        let depth = u16_at(node, 6)?;
        if depth == 0 {
            for i in 0..u32::from(entries) {
                let off = 12 + (i as usize) * 12;
                let ee_block = u32_at(node, off)?;
                let raw_len = u16_at(node, off + 4)?;
                // ee_len > 32768 flags an uninitialised extent; the real length
                // is ee_len - 32768.
                let len = u32::from(if raw_len > 32_768 {
                    raw_len - 32_768
                } else {
                    raw_len
                });
                if logical >= ee_block && logical < ee_block.saturating_add(len) {
                    let start_hi = u16_at(node, off + 6)?;
                    let start_lo = u32_at(node, off + 8)?;
                    let phys = (u64::from(start_hi) << 32) | u64::from(start_lo);
                    return Ok(Some(phys + u64::from(logical - ee_block)));
                }
            }
            return Ok(None);
        }
        // Index node: descend into the child covering `logical` (the entry with
        // the largest ei_block <= logical).
        let mut chosen: Option<u64> = None;
        let mut chosen_block = 0u32;
        for i in 0..u32::from(entries) {
            let off = 12 + (i as usize) * 12;
            let ei_block = u32_at(node, off)?;
            if ei_block <= logical && (chosen.is_none() || ei_block >= chosen_block) {
                let leaf_lo = u32_at(node, off + 4)?;
                let leaf_hi = u16_at(node, off + 8)?;
                chosen = Some((u64::from(leaf_hi) << 32) | u64::from(leaf_lo));
                chosen_block = ei_block;
            }
        }
        match chosen {
            Some(child) => {
                let block = self.block_slice(child)?;
                self.extent_lookup(block, logical, depth_budget - 1)
            }
            None => Ok(None),
        }
    }

    /// Map a `logical` file block of `inode` to a physical block (`None` = hole).
    fn resolve_block(&self, inode: &Inode, logical: u32) -> Result<Option<u64>, ExtError> {
        if inode.uses_extents() {
            return self.extent_lookup(&inode.block, logical, MAX_EXTENT_DEPTH);
        }
        // Classic block map: only the 12 direct blocks are supported here.
        if logical >= 12 {
            return Err(ExtError::Unsupported);
        }
        let phys = u32_at(&inode.block, (logical as usize) * 4)?;
        Ok(if phys == 0 {
            None
        } else {
            Some(u64::from(phys))
        })
    }

    /// Read an inode's full data (holes read as zeros), truncated to its size.
    ///
    /// # Errors
    /// [`ExtError::Corrupt`] if the recorded size exceeds the image, or a read
    /// error while resolving blocks.
    pub fn read_data(&self, inode: &Inode) -> Result<Vec<u8>, ExtError> {
        if inode.size > self.image.len() as u64 {
            return Err(ExtError::Corrupt);
        }
        let bs = u64::from(self.sb.block_size);
        let nblocks = inode.size.div_ceil(bs);
        let mut out = Vec::new();
        for l in 0..nblocks {
            let logical = u32::try_from(l).map_err(|_| ExtError::Corrupt)?;
            let remaining = inode.size - l * bs;
            let take = usize::try_from(remaining.min(bs)).map_err(|_| ExtError::Corrupt)?;
            match self.resolve_block(inode, logical)? {
                Some(phys) => {
                    let data = self.block_slice(phys)?;
                    out.extend_from_slice(data.get(..take).ok_or(ExtError::Truncated)?);
                }
                None => out.resize(out.len() + take, 0),
            }
        }
        Ok(out)
    }

    /// Read a regular file's contents by inode number.
    ///
    /// # Errors
    /// As [`ExtFs::read_data`].
    pub fn read_file(&self, ino: u32) -> Result<Vec<u8>, ExtError> {
        let inode = self.read_inode(ino)?;
        self.read_data(&inode)
    }

    /// List the entries of a directory inode.
    ///
    /// # Errors
    /// [`ExtError::NotADirectory`] if `inode` is not a directory, or a read error.
    pub fn read_dir(&self, inode: &Inode) -> Result<Vec<DirEntry>, ExtError> {
        if !inode.is_dir() {
            return Err(ExtError::NotADirectory);
        }
        let data = self.read_data(inode)?;
        let mut entries = Vec::new();
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let ino = u32_at(&data, off)?;
            let rec_len = u16_at(&data, off + 4)? as usize;
            if rec_len < 8 {
                break; // malformed record length; stop rather than loop
            }
            let name_len = *data.get(off + 6).ok_or(ExtError::Truncated)? as usize;
            let file_type = *data.get(off + 7).ok_or(ExtError::Truncated)?;
            if ino != 0 {
                let name_bytes = data
                    .get(off + 8..off + 8 + name_len)
                    .ok_or(ExtError::Truncated)?;
                entries.push(DirEntry {
                    inode: ino,
                    name: String::from_utf8_lossy(name_bytes).into_owned(),
                    file_type,
                });
            }
            off += rec_len;
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    const BS: usize = 1024;

    fn put16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Write a single-extent tree into an inode's 60-byte `i_block` at `ib`,
    /// mapping logical block 0 → physical `phys` (length 1).
    fn put_extent(img: &mut [u8], ib: usize, phys: u32) {
        put16(img, ib, EXTENT_MAGIC); // eh_magic
        put16(img, ib + 2, 1); // eh_entries
        put16(img, ib + 4, 4); // eh_max
        put16(img, ib + 6, 0); // eh_depth (leaf)
        put32(img, ib + 12, 0); // ee_block
        put16(img, ib + 16, 1); // ee_len
        put16(img, ib + 18, 0); // ee_start_hi
        put32(img, ib + 20, phys); // ee_start_lo
    }

    fn dir_entry(img: &mut [u8], off: usize, inode: u32, rec_len: u16, ft: u8, name: &str) {
        put32(img, off, inode);
        put16(img, off + 4, rec_len);
        img[off + 6] = name.len() as u8;
        img[off + 7] = ft;
        img[off + 8..off + 8 + name.len()].copy_from_slice(name.as_bytes());
    }

    /// Build an ext4-style image: superblock + BGD + inode table (blocks 3-4) +
    /// a root directory (block 5) listing `hello.txt` (inode 12), whose data is
    /// in block 6. Covers WS3-05.2 metadata and WS3-05.3 extent/dir/file reads.
    fn build_image() -> Vec<u8> {
        // 7 blocks: 0 boot, 1 SB, 2 BGD, 3-4 inode table (16×128B), 5 root dir,
        // 6 file data.
        let mut img = vec![0u8; BS * 7];

        // Superblock at byte 1024.
        let sb = SUPERBLOCK_OFFSET;
        put32(&mut img, sb, 32); // s_inodes_count
        put32(&mut img, sb + 4, 7); // s_blocks_count_lo
        put32(&mut img, sb + 24, 0); // s_log_block_size → 1024
        put32(&mut img, sb + 32, 8192); // s_blocks_per_group
        put32(&mut img, sb + 40, 16); // s_inodes_per_group
        put16(&mut img, sb + 56, EXT_MAGIC);
        put32(&mut img, sb + 84, 11); // s_first_ino
        put16(&mut img, sb + 88, 128); // s_inode_size

        // Block-group descriptor 0 at block 2: inode table at block 3.
        put32(&mut img, BS * 2 + 8, 3); // bg_inode_table_lo

        // Root inode 2 (index 1, block 3): directory, one block, extent → 5.
        let root = BS * 3 + 128;
        put16(&mut img, root, 0x41ED); // dir, 0755
        put32(&mut img, root + 4, 1024); // i_size_lo (one dir block)
        put32(&mut img, root + 32, EXTENTS_FLAG); // i_flags
        put_extent(&mut img, root + 40, 5); // dir data in block 5

        // File inode 12 (index 11, block 4): regular, 13 bytes, extent → 6.
        let file = BS * 3 + 11 * 128;
        put16(&mut img, file, 0x81A4); // regular, 0644
        put32(&mut img, file + 4, 13); // i_size_lo
        put32(&mut img, file + 32, EXTENTS_FLAG);
        put_extent(&mut img, file + 40, 6); // file data in block 6

        // Root directory data (block 5): ".", "..", "hello.txt" → inode 12.
        let dir = BS * 5;
        dir_entry(&mut img, dir, 2, 12, 2, ".");
        dir_entry(&mut img, dir + 12, 2, 12, 2, "..");
        dir_entry(&mut img, dir + 24, 12, (BS - 24) as u16, 1, "hello.txt");

        // File data (block 6).
        img[BS * 6..BS * 6 + 13].copy_from_slice(b"hello, ext4!\n");
        img
    }

    #[test]
    fn superblock_geometry() {
        let sb = Superblock::parse(&build_image()).unwrap();
        assert_eq!(sb.block_size, 1024);
        assert_eq!(sb.inodes_per_group, 16);
        assert_eq!(sb.inode_size, 128);
        assert_eq!(sb.inodes_count, 32);
        assert_eq!(sb.gdt_block(), 2); // 1024-byte block → descriptors in block 2
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut img = build_image();
        img[SUPERBLOCK_OFFSET + 56] = 0; // clobber magic
        assert_eq!(Superblock::parse(&img).err(), Some(ExtError::BadMagic));
    }

    #[test]
    fn reads_the_root_inode() {
        let img = build_image();
        let fs = ExtFs::open(&img).unwrap();
        assert_eq!(fs.inode_table_block(0).unwrap(), 3);
        let root = fs.root().unwrap();
        assert!(root.is_dir());
        assert!(!root.is_regular());
        assert!(root.uses_extents());
        assert_eq!(root.size, 1024);
    }

    #[test]
    fn inode_zero_and_overflow_are_rejected() {
        let img = build_image();
        let fs = ExtFs::open(&img).unwrap();
        assert_eq!(fs.read_inode(0).err(), Some(ExtError::BadInode));
        assert_eq!(fs.read_inode(999).err(), Some(ExtError::BadInode));
    }

    #[test]
    fn reads_root_directory_via_extent() {
        let img = build_image();
        let fs = ExtFs::open(&img).unwrap();
        let root = fs.root().unwrap();
        let entries = fs.read_dir(&root).unwrap();
        // ".", "..", "hello.txt".
        assert_eq!(entries.len(), 3);
        let hello = entries.iter().find(|e| e.name == "hello.txt").unwrap();
        assert_eq!(hello.inode, 12);
        assert!(!hello.is_dir()); // regular file
        assert!(entries.iter().any(|e| e.name == ".." && e.is_dir()));
    }

    #[test]
    fn reads_file_contents_via_extent() {
        let img = build_image();
        let fs = ExtFs::open(&img).unwrap();
        let data = fs.read_file(12).unwrap();
        assert_eq!(data, b"hello, ext4!\n");
        assert_eq!(data.len(), 13); // truncated to i_size, not the whole block
    }

    #[test]
    fn read_dir_on_a_file_is_rejected() {
        let img = build_image();
        let fs = ExtFs::open(&img).unwrap();
        let file = fs.read_inode(12).unwrap();
        assert_eq!(fs.read_dir(&file).err(), Some(ExtError::NotADirectory));
    }
}

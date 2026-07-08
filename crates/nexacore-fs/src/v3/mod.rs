//! NCFS **v3** on-disk format core (WS3-01).
//!
//! The v3 format supersedes the whole-volume v0–v2 layout
//! ([`crate::ondisk`]) with the structure mandated by the WS3-01 workstream and
//! ADR-0051: a lazy [`blockdev::BlockDevice`] (no 128-block cap), a
//! dual-superblock A/B atomic CoW root commit ([`superblock`]), copy-on-write
//! metadata objects (256-byte [`inode::InodeV3`], [`extent`] maps with reflink
//! refcounts, [`dirent`] directory objects), and a BLAKE3-keyed Merkle
//! integrity tree ([`merkle`]).
//!
//! Per ADR-0051 D6 the modules are layered in the binding order
//! *block-device → atomic commit → objects → integrity*; higher features
//! (crypto, snapshots, compression) build on this base in later sub-tasks.
//!
//! The byte layouts here are this crate's concrete realisation of the format;
//! authoring and freezing `NCIP-FS-Wire-027` to *Active* is WS3-01.15. The v2
//! format stays for the one-way migration path (WS3-01.16).

pub mod block_crypto;
pub mod blockdev;
pub mod cache;
pub mod compress;
pub mod dirent;
pub mod extent;
pub mod fde;
pub mod inode;
pub mod inode_tree;
pub mod merkle;
pub mod mkfs;
pub mod policy;
pub mod snapshot;
pub mod superblock;

/// Block size in bytes — every v3 object is block-aligned.
pub const BLOCK_SIZE: usize = 4096;

/// A single 4 KiB block.
pub type Block = [u8; BLOCK_SIZE];

/// A zeroed block.
#[must_use]
pub const fn zero_block() -> Block {
    [0u8; BLOCK_SIZE]
}

/// Errors raised across the v3 format layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum V3Error {
    /// A block index was outside the device.
    BlockOutOfRange,
    /// A backing-store read/write failed.
    Io,
    /// A structure did not parse (bad magic / version / length / field).
    Corrupt,
    /// Neither superblock slot held a valid committed generation.
    NoValidSuperblock,
    /// A name was empty, too long, not UTF-8, or not NFC.
    InvalidName,
    /// An object would not fit its block.
    Overflow,
    /// An AEAD seal/open failed (bad tag, wrong key, or truncated ciphertext).
    Crypto,
}

impl core::fmt::Display for V3Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::BlockOutOfRange => "v3: block index out of range",
            Self::Io => "v3: backing store I/O error",
            Self::Corrupt => "v3: structure failed to parse",
            Self::NoValidSuperblock => "v3: no valid committed superblock",
            Self::InvalidName => "v3: invalid directory entry name",
            Self::Overflow => "v3: object exceeds its block",
            Self::Crypto => "v3: AEAD seal/open failed",
        };
        f.write_str(s)
    }
}

impl core::error::Error for V3Error {}

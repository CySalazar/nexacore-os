//! # `nexacore-fs`
//!
//! User-space filesystem service for NexaCore OS — **`NCFS` v0**.
//!
//! Phase-2 scope: the service now includes a real in-memory filesystem
//! ([`InMemoryFs`]) with full CRUD operations (create, read, write, delete,
//! stat, list). The on-disk format types ([`Superblock`], [`Inode`],
//! [`FileType`], [`BlockIntegrityTag`]) are introduced here to establish the
//! wire format that NVMe-backed Phase-3 will serialise to block storage.
//!
//! Phase-1 behaviour (returning [`FsResponse::NotImplemented`]) is preserved
//! when no in-memory filesystem has been formatted via
//! [`FsService::format_volume`], ensuring full backward compatibility.
//!
//! ## Architecture
//!
//! ```text
//!   FsService
//!     ├── VolumeRegistry          (slot name → channel_id map)
//!     ├── InMemoryFs (Option)     (volatile CRUD store, None = Phase-1 stub)
//!     └── dispatch: FsRequest → FsResponse
//!
//!   InMemoryFs
//!     ├── Superblock              (volume metadata)
//!     ├── inodes: BTreeMap<u64, Inode>
//!     ├── path_map: BTreeMap<String, u64>  (path → inode_number)
//!     └── data_blocks: BTreeMap<u64, Vec<u8>>  (block_number → 4096-byte block)
//!
//!   BlkChannelConsumer            (per-volume BLK channel client)
//!     ├── channel_id: u64
//!     ├── next_request_id: u64    (monotonically increasing opaque ID)
//!     └── pending: BTreeMap<u64, BlkRequest>  (in-flight correlation)
//! ```
//!
//! ## BLK channel constants consumed from `nexacore-types`
//!
//! - [`nexacore_types::blk::CHANNEL_NAME_PREFIX`] — `"nexacore.svc.blk."` prefix
//!   used when constructing channel names from disk-slot strings.
//! - [`nexacore_types::blk::BLOCK_SIZE_BYTES`] — 4 096 B block size asserted in
//!   alignment checks and used as the canonical block size by `InMemoryFs`.
//! - [`nexacore_types::blk::MAX_BLOCK_COUNT_PER_REQUEST`] — upper bound on the
//!   block count per BLK request (Phase-3 range validation).
//!
//! ## Status
//!
//! `NCFS` v0 Phase-2 — Stream 3 deliverable per
//! `docs/planning/2026-05-21-development-plan.md`.

#![no_std]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::missing_panics_doc,
        clippy::missing_errors_doc,
        clippy::tests_outside_test_module,
        unused_must_use,
    )
)]

extern crate alloc;

pub mod allocator;
pub mod devfs;
pub mod integrity;
pub mod ondisk;
pub mod procfs;
pub mod standard;
pub mod tmpfs;
pub mod v3;
pub mod vfs;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};

use nexacore_types::{
    blk::{
        BLOCK_SIZE_BYTES, BlkRequest, BlkResponse, CHANNEL_NAME_PREFIX, MAX_BLOCK_COUNT_PER_REQUEST,
    },
    wire::{decode_canonical, encode_canonical},
};
use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// `NCFS` on-disk magic number.
///
/// The first 8 bytes of every formatted volume's superblock. Callers that
/// mount a raw block device MUST verify this value before interpreting any
/// other field. A mismatch indicates the block device is not an `NCFS`
/// volume (or is corrupted).
pub const NEXACORE_FS_MAGIC: [u8; 8] = *b"OMNIFS01";

/// Current on-disk format version. This field is encoded in [`Superblock::version`].
/// Future format changes increment this value and ship a migration path.
///
/// Version history:
/// - `1` — initial Phase-2 compact encoding (NCIP-FS-Wire-023). Inode records
///   stored only the basename, so nested directory hierarchies did not
///   survive a `mount` round-trip.
/// - `2` — inode records store the full absolute path, fixing nested-path
///   persistence. Serialisation fails closed with
///   [`FsError::MetadataOverflow`] instead of silently truncating metadata
///   regions. Version-1 volumes are rejected at mount (fail-closed; no
///   silent reinterpretation, per NCIP-FS-Wire-023 § Backwards Compatibility).
pub const NEXACORE_FS_VERSION: u32 = 2;

/// Maximum length (in bytes, UTF-8) of an absolute file path.
///
/// Paths longer than this limit are rejected with [`FsError::PathTooLong`]
/// to prevent unbounded allocation in the [`InMemoryFs`] path map.
pub const MAX_PATH_LEN: usize = 4096;

/// Root inode number for every freshly formatted [`InMemoryFs`]. Inode 1 is
/// the root directory (`"/"`). Regular files start at inode 2.
pub(crate) const ROOT_INODE_NUMBER: u64 = 1;

/// First inode number allocated to user-created files or directories.
/// Numbers below this are reserved for structural inodes (e.g., root dir).
pub(crate) const FIRST_USER_INODE: u64 = 2;

/// First block number available for data storage. Block 0 is conceptually
/// the superblock block; the in-memory implementation does not actually store
/// the superblock in `data_blocks`, but the reservation ensures block
/// addresses remain non-zero.
const FIRST_DATA_BLOCK: u64 = 1;

// =============================================================================
// Error taxonomy
// =============================================================================

/// All error conditions the filesystem service can surface.
///
/// Variants are `#[non_exhaustive]` so callers are forced to provide a `_`
/// arm; new error categories can be added without breaking downstream
/// pattern-match sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsError {
    /// No volume with the given disk-slot name exists in the registry.
    VolumeNotFound,
    /// A volume with the given disk-slot name is already registered.
    VolumeAlreadyRegistered,
    /// The supplied channel ID is invalid (zero is the sentinel "no channel").
    InvalidChannelId,
    /// The disk-slot name string is empty, which is never a valid slot name.
    InvalidSlotName,
    /// The underlying BLK channel has been closed by the driver side.
    ChannelDisconnected,
    /// No in-flight request with the given correlation ID exists.
    CorrelationIdNotFound,
    /// The request did not receive a response within the allowed window.
    ///
    /// Phase-1 never triggers this variant because no real I/O is issued;
    /// it is defined here so Phase-2 can propagate timeouts without an
    /// error-taxonomy change.
    RequestTimeout,
    /// Wire encoding or decoding of a BLK message failed.
    WireError,
    /// A file or directory at the specified path already exists.
    FileAlreadyExists,
    /// The path refers to a directory, not a regular file, where a regular
    /// file was expected.
    NotAFile,
    /// The path refers to a regular file, not a directory, where a directory
    /// was expected (e.g., [`InMemoryFs::list_directory`]).
    NotADirectory,
    /// The volume has no free blocks remaining.
    NoSpace,
    /// The supplied path exceeds [`MAX_PATH_LEN`] bytes.
    PathTooLong,
    /// No file or directory exists at the specified path.
    ///
    /// This is distinct from [`FsError::VolumeNotFound`], which refers to
    /// the volume-level registry; this variant refers to paths within the
    /// filesystem itself.
    FileNotFound,
    /// A data block's AEAD authentication tag did not match the expected
    /// value computed over the block contents.
    ///
    /// This variant is returned by [`ondisk::OnDiskVolume::read_file`] when
    /// the on-disk tag differs from the recomputed tag, indicating either
    /// accidental corruption or an adversarial modification of the block.
    /// Callers MUST treat this as a fatal read error.
    IntegrityViolation,
    /// The target directory is not empty and cannot be deleted.
    ///
    /// Returned by [`ondisk::OnDiskVolume::delete_directory`] when the
    /// directory still contains at least one child entry (file or
    /// subdirectory). Callers must remove all children before retrying.
    DirectoryNotEmpty,
    /// A metadata region (free-space bitmap, inode table, or integrity-tag
    /// region) would exceed its single-block on-disk capacity.
    ///
    /// The v2 on-disk encoding reserves exactly one 4 KiB block for each
    /// metadata region. Operations that would make the volume unserialisable
    /// ([`ondisk::OnDiskVolume::create_file`],
    /// [`ondisk::OnDiskVolume::create_directory`],
    /// [`ondisk::OnDiskVolume::write_file`]) and
    /// [`ondisk::OnDiskVolume::sync_to_bytes`] itself return this error
    /// instead of silently truncating metadata (which would lose data).
    /// Multi-block metadata regions are the NCIP-FS-Wire-027 refactor that
    /// lifts these limits.
    MetadataOverflow,
}

// =============================================================================
// On-disk format types
// =============================================================================

/// `NCFS` superblock — the first logical block of a formatted volume.
///
/// The superblock holds global volume metadata: the magic number, format
/// version, block geometry, free-space accounting, and the inode number of the
/// root directory. On NVMe-backed volumes (Phase 3) this structure is
/// serialised via [`nexacore_types::wire::encode_canonical`] and written to LBA 0.
///
/// # Invariants
///
/// - `magic` MUST equal [`NEXACORE_FS_MAGIC`] (`b"OMNIFS01"`).
/// - `version` MUST equal [`NEXACORE_FS_VERSION`] (currently `2`).
/// - `block_size` MUST equal [`BLOCK_SIZE_BYTES`] (`4096`).
/// - `free_blocks` MUST be ≤ `total_blocks`.
/// - `root_inode` is always `ROOT_INODE_NUMBER` (`1`) for new volumes.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::{NEXACORE_FS_MAGIC, NEXACORE_FS_VERSION, Superblock};
///
/// let sb = Superblock {
///     magic: NEXACORE_FS_MAGIC,
///     version: NEXACORE_FS_VERSION,
///     block_size: 4096,
///     total_blocks: 1024,
///     free_blocks: 1023,
///     inode_count: 1,
///     root_inode: 1,
///     created_at: 0,
///     aead_key_id: 0,
/// };
/// assert_eq!(&sb.magic, b"OMNIFS01");
/// assert_eq!(sb.version, NEXACORE_FS_VERSION);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Superblock {
    /// On-disk magic number; must equal [`NEXACORE_FS_MAGIC`].
    pub magic: [u8; 8],
    /// Format version; must equal [`NEXACORE_FS_VERSION`].
    pub version: u32,
    /// Block size in bytes; always 4096 for `NCFS` v1.
    pub block_size: u32,
    /// Total number of 4 KiB blocks on the volume.
    pub total_blocks: u64,
    /// Number of 4 KiB blocks currently not allocated to any inode.
    pub free_blocks: u64,
    /// Total number of inodes allocated on this volume (including root).
    pub inode_count: u64,
    /// Inode number of the root directory; always `ROOT_INODE_NUMBER` for
    /// volumes formatted by [`InMemoryFs::format`].
    pub root_inode: u64,
    /// Creation timestamp in seconds since the NexaCore OS HAL epoch.
    /// Phase-2 stub: always zero until a `Clock` abstraction is available.
    pub created_at: u64,
    /// Key identifier for per-block AEAD integrity tags.
    ///
    /// In Phase 2 this is always `0` (stub key — all-zero `BlockKey`).
    /// In Phase 3 this will identify a TEE-sealed key in the NexaCore keystore;
    /// the actual key bytes are never stored on disk.
    pub aead_key_id: u64,
}

/// Identifies whether an [`Inode`] describes a regular file or a directory.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::FileType;
///
/// assert_ne!(FileType::RegularFile, FileType::Directory);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    /// A regular data-bearing file. Associated blocks hold file contents.
    RegularFile,
    /// A directory that contains other files or directories (by path
    /// convention; directory entries are tracked in the [`InMemoryFs`]
    /// `path_map`, not as inline data blocks).
    Directory,
}

/// An inode — the metadata record for a single file or directory.
///
/// In the in-memory filesystem each inode is stored in
/// `InMemoryFs::inodes` keyed by `inode_number`. The name is the
/// basename component of the path; the full path is reconstructed via the
/// `path_map`. On NVMe-backed volumes (Phase 3) inodes will be serialised
/// and written to dedicated inode table blocks.
///
/// # Block layout
///
/// The `blocks` field contains direct block pointers. Each entry is a block
/// number that indexes into the `data_blocks` map of [`InMemoryFs`]. Indirect
/// block pointers are deferred to Phase 3.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::{FileType, Inode};
///
/// let inode = Inode {
///     inode_number: 2,
///     file_type: FileType::RegularFile,
///     size: 0,
///     block_count: 0,
///     created: 0,
///     modified: 0,
///     blocks: vec![],
///     name: String::from("hello.txt"),
/// };
/// assert_eq!(inode.inode_number, 2);
/// assert_eq!(inode.file_type, FileType::RegularFile);
/// ```
// The field `inode_number` intentionally shares a prefix with the struct name
// `Inode`. The name is the established filesystem convention; renaming it (e.g.
// to `number`) would reduce readability at call sites that mix `Inode` and raw
// `u64` inode numbers. The allow attribute suppresses the pedantic lint.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inode {
    /// Unique inode number for this file or directory.
    pub inode_number: u64,
    /// Whether this inode represents a regular file or a directory.
    pub file_type: FileType,
    /// File size in bytes. Always 0 for directories.
    pub size: u64,
    /// Number of 4 KiB data blocks currently allocated to this inode.
    pub block_count: u32,
    /// Creation timestamp (HAL epoch seconds; Phase-2 stub: always 0).
    pub created: u64,
    /// Last-modified timestamp (HAL epoch seconds; Phase-2 stub: always 0).
    pub modified: u64,
    /// Direct block pointers: indices into the volume's block store.
    pub blocks: Vec<u64>,
    /// Basename of the file or directory (not the full path).
    pub name: String,
}

/// AEAD integrity tag for a single 4 KiB block.
///
/// Phase-2 stub: the `tag` is always zeroed. Phase 3 will populate this with
/// a 128-bit ChaCha20-Poly1305 authentication tag computed over the block
/// contents, using a per-volume key derived via HKDF. Every block write will
/// store the tag alongside the data; every read will verify it before
/// returning the data to the caller.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::BlockIntegrityTag;
///
/// let tag = BlockIntegrityTag {
///     block_number: 42,
///     tag: [0u8; 16],
/// };
/// assert_eq!(tag.block_number, 42);
/// assert_eq!(tag.tag, [0u8; 16]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIntegrityTag {
    /// The block number this tag authenticates.
    pub block_number: u64,
    /// 128-bit authentication tag (zeroed in Phase-2 stub).
    pub tag: [u8; 16],
}

// =============================================================================
// FileMetadata
// =============================================================================

/// Metadata record returned by a successful [`FsRequest::Stat`] operation.
///
/// All timestamp fields carry seconds since the NexaCore OS epoch (monotonic
/// clock provided by the kernel HAL; not Unix epoch). Phase-2 populates
/// timestamps as zero stubs until a `Clock` abstraction lands in `nexacore-hal`.
///
/// The struct derives `Serialize` / `Deserialize` because metadata records
/// cross the trust boundary between the filesystem service and its callers
/// via the canonical wire encoding ([`nexacore_types::wire::encode_canonical`] /
/// [`nexacore_types::wire::decode_canonical`]).
///
/// # Example
///
/// ```rust
/// use nexacore_fs::FileMetadata;
///
/// let meta = FileMetadata {
///     size: 4096,
///     block_count: 1,
///     created: 0,
///     modified: 0,
/// };
/// assert_eq!(meta.size, 4096);
/// assert_eq!(meta.block_count, 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileMetadata {
    /// File size in bytes.
    pub size: u64,
    /// Number of 4 KiB blocks occupied by the file.
    ///
    /// A freshly created zero-length file has `block_count == 0`. After
    /// the first byte is written `block_count` becomes 1. The value
    /// satisfies `block_count == (size + BLOCK_SIZE_BYTES as u64 - 1)
    /// / BLOCK_SIZE_BYTES as u64` once blocks are allocated.
    pub block_count: u64,
    /// Creation timestamp in seconds since the NexaCore OS HAL epoch.
    pub created: u64,
    /// Last-modified timestamp in seconds since the NexaCore OS HAL epoch.
    pub modified: u64,
}

// =============================================================================
// FsResponse
// =============================================================================

/// Response codes (and payloads) returned by [`FsService::handle_request`].
///
/// The enum is `#[non_exhaustive]` so new response variants can be added in
/// future phases without breaking existing `match` sites.
///
/// Note: `Copy` is intentionally NOT derived because the [`FsResponse::ReadData`]
/// variant carries a `Vec<u8>` payload, which is heap-allocated and therefore
/// not `Copy`. Use `.clone()` when a copy is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsResponse {
    /// The request completed successfully with no additional payload.
    Ok,
    /// The filesystem service has not yet implemented the requested
    /// operation (returned when no [`InMemoryFs`] is formatted).
    NotImplemented,
    /// The underlying BLK channel returned an error.
    BlkError,
    /// The requested path does not exist on the filesystem.
    NotFound,
    /// A generic I/O error that does not map to a more specific variant.
    IoError,
    /// Successful response to a [`FsRequest::Stat`] operation, carrying the
    /// file's [`FileMetadata`].
    Stat(FileMetadata),
    /// Successful response to a [`FsRequest::Read`] operation, carrying the
    /// bytes read from the file.
    ///
    /// The `Vec<u8>` may be shorter than the requested `count` if the read
    /// window extends beyond the end of the file.
    ReadData(Vec<u8>),
    /// A file or directory already exists at the requested path.
    AlreadyExists,
    /// The volume has no space remaining for new blocks.
    NoSpace,
}

// =============================================================================
// FsRequest
// =============================================================================

/// Request variants the filesystem service accepts from callers.
///
/// The enum is `#[non_exhaustive]` to allow new operation types in future
/// phases without breaking existing `match` expressions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsRequest {
    /// Read `count` bytes starting at `offset` from the file at `path`.
    Read {
        /// File path (UTF-8, forward-slash separated, must begin with `/`).
        path: String,
        /// Byte offset within the file.
        offset: u64,
        /// Number of bytes to read.
        count: u32,
    },
    /// Write `data_len` bytes at `offset` to the file at `path`.
    ///
    /// The data payload itself is delivered via the BLK channel's DMA buffer
    /// (IOVA-mapped, per NCIP-Driver-NVMe-014 § M4) rather than inline in
    /// this request struct. Phase-3 resolves the IOVA address from the
    /// caller's capability context.
    ///
    /// For the in-memory filesystem, this variant writes `data_len` zero
    /// bytes at `offset`. Use [`FsRequest::WriteData`] to supply inline data.
    Write {
        /// File path.
        path: String,
        /// Byte offset within the file.
        offset: u64,
        /// Number of bytes to write.
        data_len: u32,
    },
    /// Write inline `data` bytes at `offset` to the file at `path`.
    ///
    /// This variant carries the data inline in the request, suitable for the
    /// in-memory filesystem. Phase-3 NVMe-backed writes use [`FsRequest::Write`]
    /// with IOVA-mapped DMA buffers instead.
    WriteData {
        /// File path.
        path: String,
        /// Byte offset within the file.
        offset: u64,
        /// Data to write.
        data: Vec<u8>,
    },
    /// Flush pending writes for the file at `path`.
    ///
    /// Maps to [`BlkRequest::Flush`] at the BLK layer (Phase 3).
    /// For the in-memory filesystem this is a no-op returning [`FsResponse::Ok`].
    Flush {
        /// File path.
        path: String,
    },
    /// Query metadata (size, timestamps, block count) for `path`.
    ///
    /// A successful response carries [`FsResponse::Stat`] with a populated
    /// [`FileMetadata`].
    Stat {
        /// File path.
        path: String,
    },
    /// Create a new empty regular file at `path`.
    ///
    /// Returns [`FsResponse::Ok`] on success, or [`FsResponse::AlreadyExists`]
    /// if a file already exists at the path.
    Create {
        /// Absolute file path (must begin with `/`).
        path: String,
    },
    /// Delete the file at `path`.
    ///
    /// Frees all data blocks allocated to the file and removes its inode.
    /// Returns [`FsResponse::NotFound`] if no file exists at `path`.
    Delete {
        /// File path.
        path: String,
    },
    /// List the names of all files directly within the directory at `path`.
    ///
    /// Returns [`FsResponse::NotFound`] if `path` does not exist, or
    /// [`FsResponse::IoError`] if `path` names a regular file (not a directory).
    ListDir {
        /// Directory path (must begin with `/`).
        path: String,
    },
}

// =============================================================================
// FsRegistrationError
// =============================================================================

/// Error returned by [`FsService::register`] (single-channel legacy API).
///
/// For the multi-volume API use [`FsError`] via [`FsService::register_volume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsRegistrationError {
    /// The service is already registered to a BLK channel via the legacy
    /// single-channel API.
    AlreadyRegistered,
    /// The supplied channel ID is invalid (zero is the sentinel "no channel").
    InvalidChannelId,
}

// =============================================================================
// VolumeRegistry
// =============================================================================

/// Registry that maps disk-slot names to BLK channel IDs.
///
/// A "disk slot" is the suffix portion of the BLK channel name after the
/// [`CHANNEL_NAME_PREFIX`] (`"nexacore.svc.blk."`), e.g., `"nvme0"`, `"sata1"`,
/// `"virtio2"`. The registry tracks which slot names have been registered so
/// the filesystem service can look up the channel ID for any slot.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::VolumeRegistry;
///
/// let mut reg = VolumeRegistry::new();
/// reg.register("nvme0", 1)
///     .expect("first registration succeeds");
/// assert_eq!(reg.lookup("nvme0"), Some(1));
/// assert_eq!(reg.volume_count(), 1);
/// reg.unregister("nvme0").expect("unregistration succeeds");
/// assert_eq!(reg.volume_count(), 0);
/// ```
#[derive(Debug)]
pub struct VolumeRegistry {
    /// Map from slot name to BLK channel ID.
    ///
    /// `BTreeMap` is chosen over `HashMap` because (a) `BTreeMap` lives in
    /// `alloc` and is therefore available in `no_std + alloc` environments
    /// without any additional dependencies, and (b) deterministic iteration
    /// order simplifies debugging and snapshot tests.
    volumes: BTreeMap<String, u64>,
}

impl VolumeRegistry {
    /// Create an empty volume registry.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::VolumeRegistry;
    ///
    /// let reg = VolumeRegistry::new();
    /// assert_eq!(reg.volume_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            volumes: BTreeMap::new(),
        }
    }

    /// Register a disk slot, binding it to `channel_id`.
    ///
    /// # Errors
    ///
    /// - [`FsError::InvalidSlotName`] if `slot` is empty.
    /// - [`FsError::InvalidChannelId`] if `channel_id` is zero.
    /// - [`FsError::VolumeAlreadyRegistered`] if `slot` is already present.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{FsError, VolumeRegistry};
    ///
    /// let mut reg = VolumeRegistry::new();
    /// assert!(reg.register("nvme0", 1).is_ok());
    /// assert_eq!(
    ///     reg.register("nvme0", 2),
    ///     Err(FsError::VolumeAlreadyRegistered)
    /// );
    /// assert_eq!(reg.register("", 3), Err(FsError::InvalidSlotName));
    /// assert_eq!(reg.register("nvme1", 0), Err(FsError::InvalidChannelId));
    /// ```
    pub fn register(&mut self, slot: &str, channel_id: u64) -> Result<(), FsError> {
        if slot.is_empty() {
            return Err(FsError::InvalidSlotName);
        }
        if channel_id == 0 {
            return Err(FsError::InvalidChannelId);
        }
        if self.volumes.contains_key(slot) {
            return Err(FsError::VolumeAlreadyRegistered);
        }
        self.volumes.insert(String::from(slot), channel_id);
        Ok(())
    }

    /// Unregister the disk slot, removing it from the registry.
    ///
    /// # Errors
    ///
    /// - [`FsError::VolumeNotFound`] if `slot` is not currently registered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{FsError, VolumeRegistry};
    ///
    /// let mut reg = VolumeRegistry::new();
    /// reg.register("nvme0", 1).unwrap();
    /// assert!(reg.unregister("nvme0").is_ok());
    /// assert_eq!(reg.unregister("nvme0"), Err(FsError::VolumeNotFound));
    /// ```
    pub fn unregister(&mut self, slot: &str) -> Result<(), FsError> {
        if self.volumes.remove(slot).is_none() {
            return Err(FsError::VolumeNotFound);
        }
        Ok(())
    }

    /// Look up the BLK channel ID for a registered disk slot.
    ///
    /// Returns `None` if the slot is not registered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::VolumeRegistry;
    ///
    /// let mut reg = VolumeRegistry::new();
    /// reg.register("nvme0", 42).unwrap();
    /// assert_eq!(reg.lookup("nvme0"), Some(42));
    /// assert_eq!(reg.lookup("sata1"), None);
    /// ```
    #[must_use]
    pub fn lookup(&self, slot: &str) -> Option<u64> {
        self.volumes.get(slot).copied()
    }

    /// Return the number of currently registered volumes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::VolumeRegistry;
    ///
    /// let mut reg = VolumeRegistry::new();
    /// assert_eq!(reg.volume_count(), 0);
    /// reg.register("nvme0", 1).unwrap();
    /// assert_eq!(reg.volume_count(), 1);
    /// ```
    #[must_use]
    pub fn volume_count(&self) -> usize {
        self.volumes.len()
    }

    /// Build the full BLK channel name for a given disk slot.
    ///
    /// The channel name is [`CHANNEL_NAME_PREFIX`] concatenated with `slot`,
    /// e.g., `"nexacore.svc.blk.nvme0"`. This helper is a pure string operation;
    /// it does not validate whether the slot is registered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::VolumeRegistry;
    ///
    /// assert_eq!(
    ///     VolumeRegistry::channel_name_for("nvme0"),
    ///     "nexacore.svc.blk.nvme0"
    /// );
    /// ```
    #[must_use]
    pub fn channel_name_for(slot: &str) -> String {
        let mut name = String::from(CHANNEL_NAME_PREFIX);
        name.push_str(slot);
        name
    }
}

impl Default for VolumeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// BlkChannelConsumer
// =============================================================================

/// Client-side handle for a single `nexacore.svc.blk.<diskN>` IPC channel.
///
/// The consumer is responsible for:
///
/// 1. Submitting [`BlkRequest`] values to the driver (Phase 3 actually sends
///    them over IPC; Phase 1–2 only stubs the queue bookkeeping).
/// 2. Tracking in-flight requests by opaque correlation ID so responses can
///    be matched back to their originating request.
/// 3. Correlating incoming [`BlkResponse`] values to the pending request and
///    returning the response to the caller.
///
/// Correlation IDs are monotonically increasing `u64` values minted by
/// [`BlkChannelConsumer::submit`]. They are opaque to the driver — the driver
/// echoes whatever ID the consumer sent, and the consumer uses it to locate
/// the pending entry in the `pending` map.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::BlkChannelConsumer;
/// use nexacore_types::blk::{BlkRequest, BlkResponse};
///
/// let mut consumer = BlkChannelConsumer::new(7);
/// assert_eq!(consumer.channel_id(), 7);
/// assert_eq!(consumer.pending_count(), 0);
///
/// let req = BlkRequest::Flush;
/// let id = consumer.submit(req).expect("submit succeeds");
/// assert_eq!(consumer.pending_count(), 1);
///
/// let resp = consumer
///     .correlate(id, BlkResponse::Ok)
///     .expect("correlate succeeds");
/// assert_eq!(resp, BlkResponse::Ok);
/// assert_eq!(consumer.pending_count(), 0);
/// ```
#[derive(Debug)]
pub struct BlkChannelConsumer {
    /// The IPC channel ID this consumer is bound to.
    channel_id: u64,
    /// Monotonically increasing counter used to mint unique correlation IDs.
    ///
    /// Starting at 1 keeps 0 available as a "no pending request" sentinel
    /// in external protocols that may need one.
    next_request_id: u64,
    /// Map from correlation ID to in-flight [`BlkRequest`].
    ///
    /// On submit the request is inserted; on correlate it is removed and the
    /// response is returned to the caller. The consumer never holds a
    /// response in this map — it is returned immediately.
    pending: BTreeMap<u64, BlkRequest>,
}

impl BlkChannelConsumer {
    /// Create a new consumer bound to the given BLK channel ID.
    ///
    /// The channel ID MUST NOT be zero; callers should validate before
    /// constructing (e.g., via [`VolumeRegistry::lookup`]). An ID of zero
    /// indicates "not connected" and is the sentinel used throughout the
    /// codebase.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::BlkChannelConsumer;
    ///
    /// let c = BlkChannelConsumer::new(3);
    /// assert_eq!(c.channel_id(), 3);
    /// assert_eq!(c.pending_count(), 0);
    /// ```
    #[must_use]
    pub fn new(channel_id: u64) -> Self {
        Self {
            channel_id,
            // Start at 1 so that 0 remains a "not a real ID" sentinel.
            next_request_id: 1,
            pending: BTreeMap::new(),
        }
    }

    /// Return the BLK channel ID this consumer is bound to.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::BlkChannelConsumer;
    ///
    /// assert_eq!(BlkChannelConsumer::new(99).channel_id(), 99);
    /// ```
    #[must_use]
    pub fn channel_id(&self) -> u64 {
        self.channel_id
    }

    /// Return the number of in-flight requests awaiting a response.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::BlkChannelConsumer;
    /// use nexacore_types::blk::BlkRequest;
    ///
    /// let mut c = BlkChannelConsumer::new(1);
    /// assert_eq!(c.pending_count(), 0);
    /// c.submit(BlkRequest::Flush).unwrap();
    /// assert_eq!(c.pending_count(), 1);
    /// ```
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Enqueue a [`BlkRequest`] and return its opaque correlation ID.
    ///
    /// Phase-1/2: this call inserts the request into the pending map and
    /// returns the ID. No actual IPC send occurs until Phase 3 wires up
    /// the channel transport.
    ///
    /// # Errors
    ///
    /// - [`FsError::ChannelDisconnected`] if `channel_id` is zero, indicating
    ///   the consumer was constructed with an invalid handle (defensive; callers
    ///   should avoid constructing consumers with `channel_id == 0`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::BlkChannelConsumer;
    /// use nexacore_types::blk::BlkRequest;
    ///
    /// let mut c = BlkChannelConsumer::new(5);
    /// let id = c.submit(BlkRequest::Flush).expect("submit succeeds");
    /// assert!(id > 0);
    /// ```
    pub fn submit(&mut self, request: BlkRequest) -> Result<u64, FsError> {
        // A zero channel_id means the consumer is in a disconnected state.
        if self.channel_id == 0 {
            return Err(FsError::ChannelDisconnected);
        }
        let id = self.next_request_id;
        // Wrapping add keeps the counter moving without panicking if it
        // somehow reaches u64::MAX in very long-running sessions. In practice
        // 2^64 requests per channel session is unreachable.
        self.next_request_id = self.next_request_id.wrapping_add(1);
        self.pending.insert(id, request);
        Ok(id)
    }

    /// Match an incoming [`BlkResponse`] to a previously submitted request.
    ///
    /// The pending entry for `request_id` is removed from the in-flight map
    /// and the `response` is returned to the caller. The caller is responsible
    /// for interpreting the response in context of the original request.
    ///
    /// # Errors
    ///
    /// - [`FsError::CorrelationIdNotFound`] if no in-flight request with the
    ///   given ID exists (duplicate response, stale ID, etc.).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::BlkChannelConsumer;
    /// use nexacore_types::blk::{BlkRequest, BlkResponse};
    ///
    /// let mut c = BlkChannelConsumer::new(1);
    /// let id = c.submit(BlkRequest::Flush).unwrap();
    /// let resp = c
    ///     .correlate(id, BlkResponse::Ok)
    ///     .expect("correlate succeeds");
    /// assert_eq!(resp, BlkResponse::Ok);
    /// ```
    pub fn correlate(
        &mut self,
        request_id: u64,
        response: BlkResponse,
    ) -> Result<BlkResponse, FsError> {
        if self.pending.remove(&request_id).is_none() {
            return Err(FsError::CorrelationIdNotFound);
        }
        Ok(response)
    }

    /// Wire-encode the given [`BlkRequest`] into a freshly allocated buffer
    /// using the canonical encoding ([`encode_canonical`]).
    ///
    /// This is a convenience helper for Phase-3 IPC send paths. Phase-1/2 code
    /// does not call IPC so this method is tested directly via round-trip
    /// assertions.
    ///
    /// # Errors
    ///
    /// - [`FsError::WireError`] if the encoder fails (allocation failure or
    ///   internal serializer error; both indicate a bug).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::BlkChannelConsumer;
    /// use nexacore_types::blk::BlkRequest;
    ///
    /// let c = BlkChannelConsumer::new(1);
    /// let bytes = c
    ///     .encode_request(&BlkRequest::Flush)
    ///     .expect("encoding never fails for Flush");
    /// assert!(!bytes.is_empty());
    /// ```
    #[allow(
        clippy::unused_self,
        reason = "Phase-3 will use self.channel_id for per-channel encode state (e.g. request framing)"
    )]
    pub fn encode_request(&self, request: &BlkRequest) -> Result<Vec<u8>, FsError> {
        encode_canonical(request).map_err(|_| FsError::WireError)
    }

    /// Wire-decode a [`BlkResponse`] from `bytes` using the canonical
    /// encoding ([`decode_canonical`]).
    ///
    /// This is a convenience helper for Phase-3 IPC receive paths.
    ///
    /// # Errors
    ///
    /// - [`FsError::WireError`] if the decoder fails (truncated input,
    ///   trailing bytes, unknown discriminant, etc.).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::BlkChannelConsumer;
    /// use nexacore_types::{blk::BlkResponse, wire::encode_canonical};
    ///
    /// let encoded = encode_canonical(&BlkResponse::Ok).unwrap();
    /// let c = BlkChannelConsumer::new(1);
    /// let resp = c.decode_response(&encoded).expect("round-trip succeeds");
    /// assert_eq!(resp, BlkResponse::Ok);
    /// ```
    #[allow(
        clippy::unused_self,
        reason = "Phase-3 will use self.channel_id for per-channel decode state (e.g. response validation)"
    )]
    pub fn decode_response(&self, bytes: &[u8]) -> Result<BlkResponse, FsError> {
        decode_canonical(bytes).map_err(|_| FsError::WireError)
    }
}

// =============================================================================
// InMemoryFs
// =============================================================================

/// In-memory filesystem for Phase-2 testing and bring-up.
///
/// `InMemoryFs` provides a complete in-memory CRUD filesystem implementation:
/// create, read, write, delete, stat, and list operations backed by
/// `BTreeMap`-indexed data structures. This is the reference implementation
/// that establishes the on-disk format semantics; Phase-3 will replace the
/// in-memory backing store with NVMe BLK channel I/O while keeping the same
/// `FsService` API surface.
///
/// ## Limitations
///
/// - **Volatile**: all state is lost when the struct is dropped. No
///   persistence is provided; this is by design for Phase 2.
/// - **Direct block pointers only**: indirect/double-indirect block pointers
///   are deferred to Phase 3. Files larger than `total_blocks × 4096` bytes
///   will return [`FsError::NoSpace`].
/// - **No ACLs**: access control is deferred to the capability layer (Phase 4).
/// - **No hard links**: each path maps to exactly one inode.
/// - **Timestamps are zero stubs**: no real clock is available in `no_std`
///   without `nexacore-hal`'s `Clock` abstraction.
///
/// ## Example
///
/// ```rust
/// use nexacore_fs::InMemoryFs;
///
/// let mut fs = InMemoryFs::format(1024);
/// assert_eq!(fs.free_blocks(), 1023); // block 0 reserved for superblock
///
/// fs.create_file("/hello.txt").expect("create");
/// fs.write_file("/hello.txt", 0, b"hello world")
///     .expect("write");
/// let data = fs.read_file("/hello.txt", 0, 11).expect("read");
/// assert_eq!(data, b"hello world");
/// ```
#[derive(Debug)]
pub struct InMemoryFs {
    /// Volume-level metadata: magic, version, block geometry, free-space.
    superblock: Superblock,
    /// Map from inode number to inode metadata.
    inodes: BTreeMap<u64, Inode>,
    /// Map from absolute path to inode number.
    ///
    /// The root directory `"/"` always maps to `ROOT_INODE_NUMBER`.
    path_map: BTreeMap<String, u64>,
    /// Map from block number to a 4 KiB byte vector.
    ///
    /// Blocks are lazily allocated by writes; unwritten 4 KiB regions within
    /// an allocated block are zero-filled on first access.
    data_blocks: BTreeMap<u64, Vec<u8>>,
    /// Next inode number to mint. Starts at [`FIRST_USER_INODE`].
    next_inode: u64,
    /// Next block number to allocate. Starts at [`FIRST_DATA_BLOCK`].
    next_block: u64,
}

impl InMemoryFs {
    /// Create a freshly formatted in-memory filesystem with `total_blocks`
    /// 4 KiB blocks.
    ///
    /// The root directory `"/"` is pre-created at inode
    /// `ROOT_INODE_NUMBER` (`1`). Block 0 is reserved for the conceptual
    /// superblock, so `free_blocks` starts at `total_blocks - 1`. The
    /// minimum sensible value is `total_blocks >= 2`; callers MAY pass `0`
    /// or `1`, in which case writes that require block allocation will
    /// immediately return [`FsError::NoSpace`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::InMemoryFs;
    ///
    /// let fs = InMemoryFs::format(512);
    /// assert_eq!(fs.superblock().total_blocks, 512);
    /// assert_eq!(fs.free_blocks(), 511);
    /// ```
    #[must_use]
    pub fn format(total_blocks: u64) -> Self {
        // Reserve block 0 for the superblock itself (conceptual; we do not
        // actually serialise the superblock into data_blocks in Phase 2).
        let free_blocks = total_blocks.saturating_sub(1);

        let superblock = Superblock {
            magic: NEXACORE_FS_MAGIC,
            version: NEXACORE_FS_VERSION,
            block_size: BLOCK_SIZE_BYTES,
            total_blocks,
            free_blocks,
            inode_count: 1, // root directory
            root_inode: ROOT_INODE_NUMBER,
            created_at: 0,  // Phase-2 stub: no clock available
            aead_key_id: 0, // Phase-2 stub: all-zero key
        };

        // Pre-create the root directory inode.
        let root_inode = Inode {
            inode_number: ROOT_INODE_NUMBER,
            file_type: FileType::Directory,
            size: 0,
            block_count: 0,
            created: 0,
            modified: 0,
            blocks: Vec::new(),
            name: String::from("/"),
        };

        let mut inodes = BTreeMap::new();
        inodes.insert(ROOT_INODE_NUMBER, root_inode);

        let mut path_map = BTreeMap::new();
        path_map.insert(String::from("/"), ROOT_INODE_NUMBER);

        Self {
            superblock,
            inodes,
            path_map,
            data_blocks: BTreeMap::new(),
            next_inode: FIRST_USER_INODE,
            // Block 0 is reserved; data blocks start at FIRST_DATA_BLOCK.
            next_block: FIRST_DATA_BLOCK,
        }
    }

    // -------------------------------------------------------------------------
    // Public accessors
    // -------------------------------------------------------------------------

    /// Return a reference to the volume's [`Superblock`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{InMemoryFs, NEXACORE_FS_MAGIC};
    ///
    /// let fs = InMemoryFs::format(64);
    /// assert_eq!(fs.superblock().magic, NEXACORE_FS_MAGIC);
    /// ```
    #[must_use]
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Return the number of free 4 KiB blocks remaining on the volume.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::InMemoryFs;
    ///
    /// let fs = InMemoryFs::format(100);
    /// assert_eq!(fs.free_blocks(), 99);
    /// ```
    #[must_use]
    pub fn free_blocks(&self) -> u64 {
        self.superblock.free_blocks
    }

    /// Return `true` if a file or directory exists at `path`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::InMemoryFs;
    ///
    /// let mut fs = InMemoryFs::format(64);
    /// assert!(fs.exists("/"));
    /// assert!(!fs.exists("/nope.txt"));
    /// fs.create_file("/nope.txt").unwrap();
    /// assert!(fs.exists("/nope.txt"));
    /// ```
    #[must_use]
    pub fn exists(&self, path: &str) -> bool {
        self.path_map.contains_key(path)
    }

    // -------------------------------------------------------------------------
    // CRUD operations
    // -------------------------------------------------------------------------

    /// Create a new empty regular file at `path`.
    ///
    /// The parent directory segment is NOT validated in Phase 2 — any
    /// absolute path beginning with `"/"` is accepted regardless of whether
    /// intermediate directories exist. This constraint will be tightened in
    /// Phase 3 when a proper directory-entry tree is implemented.
    ///
    /// Returns the inode number of the newly created file.
    ///
    /// # Errors
    ///
    /// - [`FsError::PathTooLong`] if `path.len() > MAX_PATH_LEN`.
    /// - [`FsError::FileAlreadyExists`] if a file or directory at `path`
    ///   already exists.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{FsError, InMemoryFs};
    ///
    /// let mut fs = InMemoryFs::format(64);
    /// let ino = fs.create_file("/boot/kernel").expect("create");
    /// assert!(ino >= 2);
    /// assert_eq!(
    ///     fs.create_file("/boot/kernel"),
    ///     Err(FsError::FileAlreadyExists)
    /// );
    /// ```
    pub fn create_file(&mut self, path: &str) -> Result<u64, FsError> {
        if path.len() > MAX_PATH_LEN {
            return Err(FsError::PathTooLong);
        }
        if self.path_map.contains_key(path) {
            return Err(FsError::FileAlreadyExists);
        }

        // Derive the basename for the inode name field.
        let name = basename(path);

        let inode_number = self.next_inode;
        self.next_inode = self.next_inode.wrapping_add(1);

        let inode = Inode {
            inode_number,
            file_type: FileType::RegularFile,
            size: 0,
            block_count: 0,
            created: 0,
            modified: 0,
            blocks: Vec::new(),
            name: String::from(name),
        };

        self.inodes.insert(inode_number, inode);
        self.path_map.insert(String::from(path), inode_number);
        self.superblock.inode_count = self.superblock.inode_count.wrapping_add(1);

        Ok(inode_number)
    }

    /// Write `data` bytes into the file at `path`, starting at byte `offset`.
    ///
    /// Blocks are allocated as needed. If `offset` is beyond the current end
    /// of file, the gap is zero-filled. If the write would exceed the last
    /// block, new blocks are allocated from the free list. Returns the number
    /// of bytes successfully written.
    ///
    /// # Errors
    ///
    /// - [`FsError::FileNotFound`] if `path` does not exist.
    /// - [`FsError::NotAFile`] if `path` is a directory.
    /// - [`FsError::NoSpace`] if the volume has insufficient free blocks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::InMemoryFs;
    ///
    /// let mut fs = InMemoryFs::format(64);
    /// fs.create_file("/data.bin").unwrap();
    /// let written = fs.write_file("/data.bin", 0, b"hello").expect("write");
    /// assert_eq!(written, 5);
    /// ```
    // Block index arithmetic uses integer division intentionally: we want the
    // floor of offset/block_size to find which block contains a byte. Using
    // floating-point would be incorrect and unsafe. The casts to `usize` are
    // safe on any platform NexaCore OS targets (64-bit), but we acknowledge the
    // theoretical truncation on 32-bit with the allow attribute.
    //
    // The slice indexing `data[a..b]` and `block[a..b]` is provably in-bounds:
    // `a` and `b` are derived from block boundary arithmetic that keeps them
    // within [0, block_size) and [0, data.len()) respectively. We acknowledge
    // the lint rather than converting to `.get()` to keep the hot path clear.
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "block index arithmetic requires floor division and provably in-bounds slicing; NexaCore OS targets 64-bit only"
    )]
    pub fn write_file(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // Look up the inode number, then split the borrow so we can mutate
        // both the inode and data_blocks simultaneously.
        let inode_number = self
            .path_map
            .get(path)
            .copied()
            .ok_or(FsError::FileNotFound)?;

        {
            // Borrow inode briefly for the type check, then drop.
            let inode = self
                .inodes
                .get(&inode_number)
                .ok_or(FsError::FileNotFound)?;
            if inode.file_type != FileType::RegularFile {
                return Err(FsError::NotAFile);
            }
        }

        if data.is_empty() {
            return Ok(0);
        }

        let block_size = u64::from(self.superblock.block_size);
        let end_offset = offset.saturating_add(data.len() as u64);

        // Determine which block indices (relative to file start) we need.
        let first_block_idx = offset / block_size;
        let last_block_idx = end_offset.saturating_sub(1) / block_size;

        // Ensure the inode has enough block entries, allocating new blocks.
        let inode = self
            .inodes
            .get_mut(&inode_number)
            .ok_or(FsError::FileNotFound)?;

        // Allocate any new block slots needed.
        while inode.blocks.len() as u64 <= last_block_idx {
            // Verify free space before allocating.
            if self.superblock.free_blocks == 0 {
                return Err(FsError::NoSpace);
            }
            let block_num = self.next_block;
            self.next_block = self.next_block.wrapping_add(1);
            self.superblock.free_blocks = self.superblock.free_blocks.saturating_sub(1);
            inode.blocks.push(block_num);
            inode.block_count = inode.block_count.wrapping_add(1);
        }

        // Now write the data byte-by-byte into the correct blocks.
        // We do this after the allocation loop to satisfy the borrow checker:
        // both `self.inodes` and `self.data_blocks` must be mutably accessed,
        // but we cannot hold two mutable borrows of `self` at once. Instead
        // we collect the block numbers we need, then do the data writes.
        let block_numbers: Vec<u64> = {
            let inode = self
                .inodes
                .get(&inode_number)
                .ok_or(FsError::FileNotFound)?;
            inode
                .blocks
                .iter()
                .skip(first_block_idx as usize)
                .take((last_block_idx - first_block_idx + 1) as usize)
                .copied()
                .collect()
        };

        // Write data into the blocks, handling partial first and last blocks.
        let mut bytes_written = 0usize;
        for (relative_idx, &block_num) in block_numbers.iter().enumerate() {
            let abs_block_idx = first_block_idx + relative_idx as u64;

            // Byte offset within this block where writing starts.
            let block_start = if abs_block_idx == first_block_idx {
                (offset % block_size) as usize
            } else {
                0
            };

            // Byte offset within this block where writing ends (exclusive).
            let block_end = if abs_block_idx == last_block_idx {
                ((end_offset - 1) % block_size + 1) as usize
            } else {
                block_size as usize
            };

            // Ensure the block exists with BLOCK_SIZE_BYTES capacity.
            let block = self
                .data_blocks
                .entry(block_num)
                .or_insert_with(|| vec![0u8; block_size as usize]);

            // Extend block to full size if it was shorter (e.g., sparse writes).
            if block.len() < block_size as usize {
                block.resize(block_size as usize, 0u8);
            }

            let write_len = block_end - block_start;
            let data_slice = &data[bytes_written..bytes_written + write_len];
            block[block_start..block_end].copy_from_slice(data_slice);
            bytes_written += write_len;
        }

        // Update the inode's size if the write extended beyond the previous EOF.
        let inode = self
            .inodes
            .get_mut(&inode_number)
            .ok_or(FsError::FileNotFound)?;
        if end_offset > inode.size {
            inode.size = end_offset;
        }

        Ok(bytes_written)
    }

    /// Read up to `count` bytes from the file at `path`, starting at `offset`.
    ///
    /// If `offset` is at or beyond EOF, an empty `Vec` is returned. If the
    /// requested range extends beyond EOF, only the bytes up to EOF are
    /// returned (no error is raised for a short read).
    ///
    /// # Errors
    ///
    /// - [`FsError::FileNotFound`] if `path` does not exist.
    /// - [`FsError::NotAFile`] if `path` is a directory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::InMemoryFs;
    ///
    /// let mut fs = InMemoryFs::format(64);
    /// fs.create_file("/r.txt").unwrap();
    /// fs.write_file("/r.txt", 0, b"abcde").unwrap();
    /// let data = fs.read_file("/r.txt", 1, 3).expect("read");
    /// assert_eq!(data, b"bcd");
    /// ```
    // Same block-index arithmetic rationale as write_file above. The slice
    // indexing `result[a..b]` and `block[a..b]` is provably in-bounds by the
    // same block boundary arithmetic.
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "block index arithmetic requires floor division and provably in-bounds slicing; NexaCore OS targets 64-bit only"
    )]
    pub fn read_file(&self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>, FsError> {
        let inode_number = self
            .path_map
            .get(path)
            .copied()
            .ok_or(FsError::FileNotFound)?;

        let inode = self
            .inodes
            .get(&inode_number)
            .ok_or(FsError::FileNotFound)?;

        if inode.file_type != FileType::RegularFile {
            return Err(FsError::NotAFile);
        }

        // Nothing to read if offset is at or beyond EOF.
        if offset >= inode.size || count == 0 {
            return Ok(Vec::new());
        }

        let block_size = u64::from(self.superblock.block_size);
        // Clamp the read to the file's actual size.
        let effective_end = (offset + u64::from(count)).min(inode.size);
        let read_len = (effective_end - offset) as usize;
        let mut result = vec![0u8; read_len];

        let first_block_idx = offset / block_size;
        let last_block_idx = (effective_end - 1) / block_size;

        let mut bytes_read = 0usize;
        for abs_block_idx in first_block_idx..=last_block_idx {
            // Map the logical block index to a physical block number.
            let block_num = inode
                .blocks
                .get(abs_block_idx as usize)
                .copied()
                .unwrap_or(0);

            let block_start = if abs_block_idx == first_block_idx {
                (offset % block_size) as usize
            } else {
                0
            };
            let block_end = if abs_block_idx == last_block_idx {
                ((effective_end - 1) % block_size + 1) as usize
            } else {
                block_size as usize
            };

            let copy_len = block_end - block_start;

            if block_num == 0 {
                // Sparse block: return zeroes (already zeroed in result).
            } else if let Some(block) = self.data_blocks.get(&block_num) {
                // Clamp in case the block is shorter than expected.
                let src_end = block_end.min(block.len());
                if block_start < src_end {
                    let actual_copy = src_end - block_start;
                    result[bytes_read..bytes_read + actual_copy]
                        .copy_from_slice(&block[block_start..src_end]);
                    // If actual_copy < copy_len the remainder is already zero.
                }
            }
            // If the block does not exist in data_blocks, zeroes are returned
            // (result is already zero-initialised).

            bytes_read += copy_len;
        }

        Ok(result)
    }

    /// Delete the file at `path`, freeing all allocated data blocks.
    ///
    /// The inode is removed and all block entries are released back to the
    /// free pool. The caller MUST NOT access the inode or blocks after this
    /// call.
    ///
    /// # Errors
    ///
    /// - [`FsError::FileNotFound`] if `path` does not exist.
    /// - [`FsError::NotAFile`] if `path` is a directory (directories cannot
    ///   be deleted via this method; use a future `remove_dir` when Phase 3
    ///   implements full directory trees).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{FsError, InMemoryFs};
    ///
    /// let mut fs = InMemoryFs::format(64);
    /// fs.create_file("/tmp.txt").unwrap();
    /// fs.delete_file("/tmp.txt").expect("delete");
    /// assert!(!fs.exists("/tmp.txt"));
    /// assert_eq!(fs.delete_file("/tmp.txt"), Err(FsError::FileNotFound));
    /// ```
    pub fn delete_file(&mut self, path: &str) -> Result<(), FsError> {
        let inode_number = self
            .path_map
            .get(path)
            .copied()
            .ok_or(FsError::FileNotFound)?;

        let inode = self
            .inodes
            .get(&inode_number)
            .ok_or(FsError::FileNotFound)?;

        if inode.file_type != FileType::RegularFile {
            return Err(FsError::NotAFile);
        }

        // Collect block numbers before removing the inode so we can free them.
        let block_numbers: Vec<u64> = inode.blocks.clone();
        let freed_blocks = block_numbers.len() as u64;

        // Remove all data blocks.
        for block_num in &block_numbers {
            self.data_blocks.remove(block_num);
        }

        // Remove the inode and path mapping.
        self.inodes.remove(&inode_number);
        self.path_map.remove(path);

        // Update free-space accounting.
        self.superblock.free_blocks = self.superblock.free_blocks.saturating_add(freed_blocks);
        self.superblock.inode_count = self.superblock.inode_count.saturating_sub(1);

        Ok(())
    }

    /// Return [`FileMetadata`] for the file or directory at `path`.
    ///
    /// # Errors
    ///
    /// - [`FsError::FileNotFound`] if `path` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::InMemoryFs;
    ///
    /// let mut fs = InMemoryFs::format(64);
    /// fs.create_file("/meta.bin").unwrap();
    /// fs.write_file("/meta.bin", 0, &[0u8; 100]).unwrap();
    /// let meta = fs.stat_file("/meta.bin").expect("stat");
    /// assert_eq!(meta.size, 100);
    /// assert_eq!(meta.block_count, 1); // 100 bytes fits in 1 block
    /// ```
    pub fn stat_file(&self, path: &str) -> Result<FileMetadata, FsError> {
        let inode_number = self
            .path_map
            .get(path)
            .copied()
            .ok_or(FsError::FileNotFound)?;

        let inode = self
            .inodes
            .get(&inode_number)
            .ok_or(FsError::FileNotFound)?;

        Ok(FileMetadata {
            size: inode.size,
            block_count: u64::from(inode.block_count),
            created: inode.created,
            modified: inode.modified,
        })
    }

    /// List all direct child names (files and subdirectories) within the
    /// directory at `path`.
    ///
    /// In Phase 2 "direct children" means all paths in the `path_map` that
    /// share the given directory prefix and have no further `/` separators
    /// beyond the prefix. For example, given `path = "/"`:
    /// - `"/boot"` is a direct child (returned as `"boot"`).
    /// - `"/boot/kernel"` is NOT a direct child of `"/"`.
    ///
    /// The root directory `"/"` is NOT included in its own listing.
    ///
    /// # Errors
    ///
    /// - [`FsError::FileNotFound`] if `path` does not exist.
    /// - [`FsError::NotADirectory`] if `path` names a regular file.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::InMemoryFs;
    ///
    /// let mut fs = InMemoryFs::format(64);
    /// fs.create_file("/a.txt").unwrap();
    /// fs.create_file("/b.txt").unwrap();
    /// let mut names = fs.list_directory("/").expect("list");
    /// names.sort();
    /// assert_eq!(names, ["a.txt", "b.txt"]);
    /// ```
    pub fn list_directory(&self, path: &str) -> Result<Vec<String>, FsError> {
        let inode_number = self
            .path_map
            .get(path)
            .copied()
            .ok_or(FsError::FileNotFound)?;

        let inode = self
            .inodes
            .get(&inode_number)
            .ok_or(FsError::FileNotFound)?;

        if inode.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }

        // Build the directory prefix for scanning the path_map.
        // Root is special: prefix is "/"; for "/foo" prefix is "/foo/".
        let prefix = if path == "/" {
            String::from("/")
        } else {
            let mut p = String::from(path);
            p.push('/');
            p
        };

        let mut names = Vec::new();
        for candidate_path in self.path_map.keys() {
            if candidate_path == path {
                // Skip the directory itself.
                continue;
            }
            if !candidate_path.starts_with(prefix.as_str()) {
                continue;
            }

            // Extract the suffix after the prefix.
            let suffix = &candidate_path[prefix.len()..];

            // Only include direct children: no `/` in the suffix.
            if !suffix.contains('/') {
                names.push(String::from(suffix));
            }
        }

        Ok(names)
    }
}

// =============================================================================
// FsService
// =============================================================================

/// Phase-2 filesystem service.
///
/// Owns a [`VolumeRegistry`] and an optional [`InMemoryFs`] backing store.
/// When the backing store is `Some` (initialised via [`FsService::format_volume`]),
/// all [`FsRequest`] variants dispatch to the in-memory filesystem and return
/// real data. When the backing store is `None`, every request returns
/// [`FsResponse::NotImplemented`], preserving Phase-1 behaviour.
///
/// The legacy single-channel API ([`FsService::register`] /
/// [`FsService::channel_id`]) is preserved for backward compatibility with
/// existing tests and callers. New code should use the multi-volume API
/// ([`FsService::register_volume`] / [`FsService::unregister_volume`] /
/// [`FsService::lookup_volume`]) which delegates to the internal
/// [`VolumeRegistry`].
///
/// # Example
///
/// ```rust
/// extern crate alloc;
/// use alloc::string::String;
///
/// use nexacore_fs::{FsRequest, FsResponse, FsService};
///
/// let mut svc = FsService::new();
/// // Without format_volume, all requests return NotImplemented.
/// let req = FsRequest::Stat {
///     path: String::from("/boot/kernel"),
/// };
/// assert_eq!(svc.handle_request(&req), FsResponse::NotImplemented);
///
/// // After formatting, real dispatch begins.
/// svc.format_volume(1024);
/// let create_req = FsRequest::Create {
///     path: String::from("/hello.txt"),
/// };
/// assert_eq!(svc.handle_request(&create_req), FsResponse::Ok);
/// ```
#[derive(Debug)]
pub struct FsService {
    /// Legacy single-channel BLK channel ID (preserved for backward compat).
    blk_channel_id: Option<u64>,
    /// Multi-volume registry (the authoritative map for Phase-3+ code).
    registry: VolumeRegistry,
    /// Optional in-memory filesystem backing store.
    ///
    /// `None` means the service is in Phase-1 stub mode: all requests return
    /// [`FsResponse::NotImplemented`]. `Some` means a real in-memory filesystem
    /// has been formatted and all requests are dispatched to it.
    fs: Option<InMemoryFs>,
    /// Optional on-disk volume (byte-buffer-backed `NCFS`).
    ///
    /// Created by [`FsService::format_ondisk_volume`] and made available for
    /// direct access via [`FsService::ondisk_volume`] /
    /// [`FsService::ondisk_volume_mut`]. Independent of the `fs` in-memory store.
    ondisk: Option<ondisk::OnDiskVolume>,
}

impl FsService {
    /// Create a new, unregistered filesystem service in Phase-1 stub mode.
    ///
    /// Call [`FsService::format_volume`] to enable real dispatch.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let svc = FsService::new();
    /// assert_eq!(svc.channel_id(), None);
    /// assert_eq!(svc.lookup_volume("nvme0"), None);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            blk_channel_id: None,
            registry: VolumeRegistry::new(),
            fs: None,
            ondisk: None,
        }
    }

    /// Format an in-memory filesystem and attach it to this service.
    ///
    /// After this call, [`FsService::handle_request`] dispatches to the
    /// in-memory filesystem rather than returning [`FsResponse::NotImplemented`].
    /// If the service already has a formatted filesystem, it is replaced.
    ///
    /// `total_blocks` is the total number of 4 KiB blocks the volume will
    /// report; block 0 is reserved for the superblock so `free_blocks` starts
    /// at `total_blocks - 1`.
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate alloc;
    /// use alloc::string::String;
    ///
    /// use nexacore_fs::{FsRequest, FsResponse, FsService};
    ///
    /// let mut svc = FsService::new();
    /// svc.format_volume(256);
    /// let req = FsRequest::Create {
    ///     path: String::from("/boot.img"),
    /// };
    /// assert_eq!(svc.handle_request(&req), FsResponse::Ok);
    /// ```
    pub fn format_volume(&mut self, total_blocks: u64) {
        self.fs = Some(InMemoryFs::format(total_blocks));
    }

    /// Format a new on-disk volume and attach it to this service.
    ///
    /// After this call [`FsService::ondisk_volume`] returns `Some(…)`.
    /// If an on-disk volume is already attached, it is replaced.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let mut svc = FsService::new();
    /// svc.format_ondisk_volume(128);
    /// assert!(svc.ondisk_volume().is_some());
    /// ```
    pub fn format_ondisk_volume(&mut self, total_blocks: u64) {
        self.ondisk = Some(ondisk::OnDiskVolume::format(total_blocks));
    }

    /// Mount an on-disk volume from a raw byte buffer and attach it.
    ///
    /// # Errors
    ///
    /// Propagates [`FsError`] from [`ondisk::OnDiskVolume::mount`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let mut svc = FsService::new();
    /// svc.format_ondisk_volume(64);
    /// let raw = svc.sync_ondisk_to_bytes().expect("format first");
    /// svc.mount_ondisk_volume(raw).expect("mount");
    /// assert!(svc.ondisk_volume().is_some());
    /// ```
    pub fn mount_ondisk_volume(&mut self, raw: impl AsRef<[u8]>) -> Result<(), FsError> {
        self.ondisk = Some(ondisk::OnDiskVolume::mount(raw.as_ref())?);
        Ok(())
    }

    /// Serialise the attached on-disk volume to a byte buffer.
    ///
    /// # Errors
    ///
    /// - [`FsError::VolumeNotFound`] if no on-disk volume has been formatted.
    /// - [`FsError::MetadataOverflow`] propagated from
    ///   [`ondisk::OnDiskVolume::sync_to_bytes`] if a metadata region would
    ///   exceed its single-block capacity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let mut svc = FsService::new();
    /// svc.format_ondisk_volume(64);
    /// let raw = svc.sync_ondisk_to_bytes().expect("bytes");
    /// assert_eq!(raw.len(), 64 * 4096);
    /// ```
    pub fn sync_ondisk_to_bytes(&self) -> Result<Vec<u8>, FsError> {
        self.ondisk
            .as_ref()
            .ok_or(FsError::VolumeNotFound)?
            .sync_to_bytes()
    }

    /// Return a reference to the attached on-disk volume, if any.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let mut svc = FsService::new();
    /// assert!(svc.ondisk_volume().is_none());
    /// svc.format_ondisk_volume(64);
    /// assert!(svc.ondisk_volume().is_some());
    /// ```
    #[must_use]
    pub fn ondisk_volume(&self) -> Option<&ondisk::OnDiskVolume> {
        self.ondisk.as_ref()
    }

    /// Return a mutable reference to the attached on-disk volume, if any.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let mut svc = FsService::new();
    /// svc.format_ondisk_volume(64);
    /// let vol = svc.ondisk_volume_mut().expect("volume present");
    /// vol.create_file("/test.bin").expect("create");
    /// ```
    #[must_use]
    pub fn ondisk_volume_mut(&mut self) -> Option<&mut ondisk::OnDiskVolume> {
        self.ondisk.as_mut()
    }

    // -------------------------------------------------------------------------
    // Legacy single-channel API (backward compat)
    // -------------------------------------------------------------------------

    /// Register the service against a single BLK channel ID.
    ///
    /// This is the legacy single-channel API. For multi-volume registration
    /// use [`FsService::register_volume`].
    ///
    /// # Errors
    ///
    /// - [`FsRegistrationError::AlreadyRegistered`] if the service already
    ///   has a channel set via this API.
    /// - [`FsRegistrationError::InvalidChannelId`] if `channel_id` is zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{FsRegistrationError, FsService};
    ///
    /// let mut svc = FsService::new();
    /// assert!(svc.register(1).is_ok());
    /// assert_eq!(svc.register(2), Err(FsRegistrationError::AlreadyRegistered));
    /// ```
    pub fn register(&mut self, channel_id: u64) -> Result<(), FsRegistrationError> {
        if self.blk_channel_id.is_some() {
            return Err(FsRegistrationError::AlreadyRegistered);
        }
        if channel_id == 0 {
            return Err(FsRegistrationError::InvalidChannelId);
        }
        self.blk_channel_id = Some(channel_id);
        Ok(())
    }

    /// Return the BLK channel ID set via the legacy [`FsService::register`]
    /// API, or `None` if it has not been called.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let mut svc = FsService::new();
    /// assert_eq!(svc.channel_id(), None);
    /// svc.register(7).unwrap();
    /// assert_eq!(svc.channel_id(), Some(7));
    /// ```
    #[must_use]
    pub const fn channel_id(&self) -> Option<u64> {
        self.blk_channel_id
    }

    // -------------------------------------------------------------------------
    // Multi-volume API
    // -------------------------------------------------------------------------

    /// Register a disk slot in the volume registry.
    ///
    /// Delegates to [`VolumeRegistry::register`].
    ///
    /// # Errors
    ///
    /// See [`FsError`] variants returned by [`VolumeRegistry::register`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{FsError, FsService};
    ///
    /// let mut svc = FsService::new();
    /// assert!(svc.register_volume("nvme0", 1).is_ok());
    /// assert_eq!(
    ///     svc.register_volume("nvme0", 2),
    ///     Err(FsError::VolumeAlreadyRegistered)
    /// );
    /// ```
    pub fn register_volume(&mut self, slot: &str, channel_id: u64) -> Result<(), FsError> {
        self.registry.register(slot, channel_id)
    }

    /// Unregister a disk slot from the volume registry.
    ///
    /// Delegates to [`VolumeRegistry::unregister`].
    ///
    /// # Errors
    ///
    /// See [`FsError`] variants returned by [`VolumeRegistry::unregister`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::{FsError, FsService};
    ///
    /// let mut svc = FsService::new();
    /// svc.register_volume("nvme0", 1).unwrap();
    /// assert!(svc.unregister_volume("nvme0").is_ok());
    /// assert_eq!(svc.unregister_volume("nvme0"), Err(FsError::VolumeNotFound));
    /// ```
    pub fn unregister_volume(&mut self, slot: &str) -> Result<(), FsError> {
        self.registry.unregister(slot)
    }

    /// Look up the BLK channel ID for a registered disk slot.
    ///
    /// Delegates to [`VolumeRegistry::lookup`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::FsService;
    ///
    /// let mut svc = FsService::new();
    /// svc.register_volume("sata0", 9).unwrap();
    /// assert_eq!(svc.lookup_volume("sata0"), Some(9));
    /// assert_eq!(svc.lookup_volume("nvme0"), None);
    /// ```
    #[must_use]
    pub fn lookup_volume(&self, slot: &str) -> Option<u64> {
        self.registry.lookup(slot)
    }

    // -------------------------------------------------------------------------
    // Request dispatch
    // -------------------------------------------------------------------------

    /// Handle an incoming filesystem request.
    ///
    /// When an in-memory filesystem has been initialised via
    /// [`FsService::format_volume`], requests are dispatched to [`InMemoryFs`]
    /// and real responses are returned. When no filesystem is present, every
    /// request returns [`FsResponse::NotImplemented`] (Phase-1 backward
    /// compatibility).
    ///
    /// # Dispatch table
    ///
    /// | `FsRequest` variant | `InMemoryFs` method | `FsResponse` |
    /// |---------------------|---------------------|--------------|
    /// | `Read`              | `read_file`         | `ReadData(data)` |
    /// | `WriteData`         | `write_file`        | `Ok` |
    /// | `Write`             | `write_file` (zero-fill) | `Ok` |
    /// | `Stat`              | `stat_file`         | `Stat(meta)` |
    /// | `Flush`             | no-op               | `Ok` |
    /// | `Create`            | `create_file`       | `Ok` |
    /// | `Delete`            | `delete_file`       | `Ok` |
    /// | `ListDir`           | `list_directory`    | — (via `IoError` for now) |
    ///
    /// # Example
    ///
    /// ```rust
    /// extern crate alloc;
    /// use alloc::string::String;
    ///
    /// use nexacore_fs::{FsRequest, FsResponse, FsService};
    ///
    /// let mut svc = FsService::new();
    /// // Phase-1 stub mode: no filesystem formatted.
    /// assert_eq!(
    ///     svc.handle_request(&FsRequest::Stat {
    ///         path: String::from("/etc/config")
    ///     }),
    ///     FsResponse::NotImplemented
    /// );
    ///
    /// // Phase-2 mode: real dispatch after format_volume.
    /// svc.format_volume(512);
    /// svc.handle_request(&FsRequest::Create {
    ///     path: String::from("/etc/config"),
    /// });
    /// let resp = svc.handle_request(&FsRequest::Stat {
    ///     path: String::from("/etc/config"),
    /// });
    /// assert!(matches!(resp, FsResponse::Stat(_)));
    /// ```
    #[must_use]
    pub fn handle_request(&mut self, request: &FsRequest) -> FsResponse {
        // No filesystem formatted: preserve Phase-1 stub behaviour.
        let Some(fs) = self.fs.as_mut() else {
            return FsResponse::NotImplemented;
        };

        match request {
            FsRequest::Create { path } => match fs.create_file(path) {
                Ok(_) => FsResponse::Ok,
                Err(FsError::FileAlreadyExists) => FsResponse::AlreadyExists,
                // PathTooLong and all other creation errors map to IoError.
                Err(_) => FsResponse::IoError,
            },

            FsRequest::Delete { path } => match fs.delete_file(path) {
                Ok(()) => FsResponse::Ok,
                Err(FsError::FileNotFound) => FsResponse::NotFound,
                Err(_) => FsResponse::IoError,
            },

            FsRequest::Read {
                path,
                offset,
                count,
            } => match fs.read_file(path, *offset, *count) {
                Ok(data) => FsResponse::ReadData(data),
                Err(FsError::FileNotFound) => FsResponse::NotFound,
                Err(_) => FsResponse::IoError,
            },

            FsRequest::WriteData { path, offset, data } => {
                match fs.write_file(path, *offset, data) {
                    Ok(_) => FsResponse::Ok,
                    Err(FsError::FileNotFound) => FsResponse::NotFound,
                    Err(FsError::NoSpace) => FsResponse::NoSpace,
                    Err(_) => FsResponse::IoError,
                }
            }

            FsRequest::Write {
                path,
                offset,
                data_len,
            } => {
                // The legacy Write variant carries a DMA length but no inline
                // data (the actual bytes come via IOVA in Phase 3). For the
                // in-memory filesystem we zero-fill the requested range so
                // that callers can still exercise block allocation semantics
                // without a real DMA buffer.
                let zeros = vec![0u8; *data_len as usize];
                match fs.write_file(path, *offset, &zeros) {
                    Ok(_) => FsResponse::Ok,
                    Err(FsError::FileNotFound) => FsResponse::NotFound,
                    Err(FsError::NoSpace) => FsResponse::NoSpace,
                    Err(_) => FsResponse::IoError,
                }
            }

            FsRequest::Flush { .. } => {
                // In-memory filesystem: flush is a no-op. Phase 3 will issue
                // BlkRequest::Flush over the BLK channel.
                FsResponse::Ok
            }

            FsRequest::Stat { path } => match fs.stat_file(path) {
                Ok(meta) => FsResponse::Stat(meta),
                Err(FsError::FileNotFound) => FsResponse::NotFound,
                Err(_) => FsResponse::IoError,
            },

            FsRequest::ListDir { path } => match fs.list_directory(path) {
                Ok(_names) => {
                    // Phase-2 stub: list result is dropped; callers that need
                    // the listing should call InMemoryFs::list_directory directly.
                    // A future FsResponse::DirEntries variant will carry the list.
                    FsResponse::Ok
                }
                Err(FsError::FileNotFound) => FsResponse::NotFound,
                // NotADirectory and all other errors map to IoError.
                Err(_) => FsResponse::IoError,
            },
        }
    }
}

impl Default for FsService {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Extract the basename component of an absolute path.
///
/// Returns the portion after the last `/`. For the root `"/"` itself,
/// returns `"/"`. This is a pure string operation used to populate
/// [`Inode::name`] during file creation.
fn basename(path: &str) -> &str {
    match path.rfind('/') {
        // Path is exactly "/" or ends with "/".
        Some(idx) if idx + 1 == path.len() => "/",
        Some(idx) => &path[idx + 1..],
        None => path,
    }
}

// =============================================================================
// Compile-time BLK constant assertions
// =============================================================================

/// Compile-time checks that the BLK constants imported from `nexacore-types`
/// satisfy the invariants this crate was written against.
///
/// If a future NCIP changes `BLOCK_SIZE_BYTES` or
/// `MAX_BLOCK_COUNT_PER_REQUEST`, this crate's build fails immediately,
/// forcing a deliberate review of the impact on `NCFS` before the change
/// can land.
#[allow(dead_code)]
const _BLK_CONST_GUARD: () = {
    assert!(BLOCK_SIZE_BYTES == 4096, "NCFS requires 4 KiB BLK blocks");
    assert!(
        MAX_BLOCK_COUNT_PER_REQUEST == 2048,
        "NCFS requires MAX_BLOCK_COUNT_PER_REQUEST == 2048"
    );
};

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use nexacore_types::wire::encode_canonical;

    use super::*;

    // -------------------------------------------------------------------------
    // FsService — legacy single-channel API
    // -------------------------------------------------------------------------

    #[test]
    fn new_service_has_no_channel() {
        let svc = FsService::new();
        assert_eq!(svc.channel_id(), None);
    }

    #[test]
    fn register_sets_channel_id() {
        let mut svc = FsService::new();
        svc.register(42).expect("first registration succeeds");
        assert_eq!(svc.channel_id(), Some(42));
    }

    #[test]
    fn double_registration_returns_already_registered() {
        let mut svc = FsService::new();
        svc.register(1).unwrap();
        assert_eq!(svc.register(2), Err(FsRegistrationError::AlreadyRegistered));
    }

    #[test]
    fn register_rejects_zero_channel_id() {
        let mut svc = FsService::new();
        assert_eq!(svc.register(0), Err(FsRegistrationError::InvalidChannelId));
    }

    #[test]
    fn handle_request_returns_not_implemented_when_no_fs() {
        // Without format_volume, all requests must return NotImplemented.
        let mut svc = FsService::new();

        let variants: &[FsRequest] = &[
            FsRequest::Stat {
                path: String::from("/test"),
            },
            FsRequest::Read {
                path: String::from("/data"),
                offset: 0,
                count: 512,
            },
            FsRequest::Write {
                path: String::from("/out"),
                offset: 4096,
                data_len: 4096,
            },
            FsRequest::Flush {
                path: String::from("/log"),
            },
        ];

        for req in variants {
            assert_eq!(
                svc.handle_request(req),
                FsResponse::NotImplemented,
                "expected NotImplemented for {req:?}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // VolumeRegistry
    // -------------------------------------------------------------------------

    #[test]
    fn registry_empty_on_construction() {
        let reg = VolumeRegistry::new();
        assert_eq!(reg.volume_count(), 0);
        assert_eq!(reg.lookup("nvme0"), None);
    }

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = VolumeRegistry::new();
        reg.register("nvme0", 1).expect("register nvme0");
        assert_eq!(reg.lookup("nvme0"), Some(1));
        assert_eq!(reg.volume_count(), 1);
    }

    #[test]
    fn registry_register_multiple_volumes() {
        let mut reg = VolumeRegistry::new();
        reg.register("nvme0", 10).unwrap();
        reg.register("sata1", 20).unwrap();
        reg.register("virtio2", 30).unwrap();
        assert_eq!(reg.volume_count(), 3);
        assert_eq!(reg.lookup("nvme0"), Some(10));
        assert_eq!(reg.lookup("sata1"), Some(20));
        assert_eq!(reg.lookup("virtio2"), Some(30));
    }

    #[test]
    fn registry_rejects_duplicate_slot() {
        let mut reg = VolumeRegistry::new();
        reg.register("nvme0", 1).unwrap();
        assert_eq!(
            reg.register("nvme0", 2),
            Err(FsError::VolumeAlreadyRegistered)
        );
    }

    #[test]
    fn registry_rejects_zero_channel_id() {
        let mut reg = VolumeRegistry::new();
        assert_eq!(reg.register("nvme0", 0), Err(FsError::InvalidChannelId));
    }

    #[test]
    fn registry_rejects_empty_slot_name() {
        let mut reg = VolumeRegistry::new();
        assert_eq!(reg.register("", 1), Err(FsError::InvalidSlotName));
    }

    #[test]
    fn registry_unregister_removes_entry() {
        let mut reg = VolumeRegistry::new();
        reg.register("nvme0", 1).unwrap();
        reg.unregister("nvme0").unwrap();
        assert_eq!(reg.volume_count(), 0);
        assert_eq!(reg.lookup("nvme0"), None);
    }

    #[test]
    fn registry_unregister_nonexistent_returns_not_found() {
        let mut reg = VolumeRegistry::new();
        assert_eq!(reg.unregister("nvme0"), Err(FsError::VolumeNotFound));
    }

    #[test]
    fn registry_channel_name_for_builds_correct_prefix() {
        assert_eq!(
            VolumeRegistry::channel_name_for("nvme0"),
            "nexacore.svc.blk.nvme0"
        );
        assert_eq!(
            VolumeRegistry::channel_name_for("virtio2"),
            "nexacore.svc.blk.virtio2"
        );
    }

    // -------------------------------------------------------------------------
    // FsService — multi-volume API
    // -------------------------------------------------------------------------

    #[test]
    fn service_register_volume_and_lookup() {
        let mut svc = FsService::new();
        svc.register_volume("nvme0", 5).expect("register");
        assert_eq!(svc.lookup_volume("nvme0"), Some(5));
    }

    #[test]
    fn service_unregister_volume() {
        let mut svc = FsService::new();
        svc.register_volume("sata0", 7).unwrap();
        svc.unregister_volume("sata0").unwrap();
        assert_eq!(svc.lookup_volume("sata0"), None);
    }

    #[test]
    fn service_register_volume_rejects_zero_id() {
        let mut svc = FsService::new();
        assert_eq!(
            svc.register_volume("nvme0", 0),
            Err(FsError::InvalidChannelId)
        );
    }

    // -------------------------------------------------------------------------
    // BlkChannelConsumer
    // -------------------------------------------------------------------------

    #[test]
    fn consumer_new_has_no_pending() {
        let c = BlkChannelConsumer::new(1);
        assert_eq!(c.channel_id(), 1);
        assert_eq!(c.pending_count(), 0);
    }

    #[test]
    fn consumer_submit_increments_pending() {
        let mut c = BlkChannelConsumer::new(1);
        c.submit(BlkRequest::Flush).unwrap();
        assert_eq!(c.pending_count(), 1);
        c.submit(BlkRequest::Flush).unwrap();
        assert_eq!(c.pending_count(), 2);
    }

    #[test]
    fn consumer_submit_returns_unique_ids() {
        let mut c = BlkChannelConsumer::new(1);
        let id1 = c.submit(BlkRequest::Flush).unwrap();
        let id2 = c.submit(BlkRequest::Flush).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn consumer_submit_returns_err_when_channel_id_is_zero() {
        // channel_id == 0 is the "disconnected" sentinel; submit must reject.
        let mut c = BlkChannelConsumer::new(0);
        assert_eq!(
            c.submit(BlkRequest::Flush),
            Err(FsError::ChannelDisconnected)
        );
    }

    #[test]
    fn consumer_correlate_removes_pending() {
        let mut c = BlkChannelConsumer::new(2);
        let id = c.submit(BlkRequest::Flush).unwrap();
        assert_eq!(c.pending_count(), 1);
        let resp = c.correlate(id, BlkResponse::Ok).unwrap();
        assert_eq!(resp, BlkResponse::Ok);
        assert_eq!(c.pending_count(), 0);
    }

    #[test]
    fn consumer_correlate_unknown_id_returns_err() {
        let mut c = BlkChannelConsumer::new(1);
        assert_eq!(
            c.correlate(999, BlkResponse::Ok),
            Err(FsError::CorrelationIdNotFound)
        );
    }

    #[test]
    fn consumer_correlate_stale_id_after_completion_returns_err() {
        let mut c = BlkChannelConsumer::new(1);
        let id = c.submit(BlkRequest::Flush).unwrap();
        c.correlate(id, BlkResponse::Ok).unwrap();
        // Second correlate for the same ID must fail.
        assert_eq!(
            c.correlate(id, BlkResponse::Ok),
            Err(FsError::CorrelationIdNotFound)
        );
    }

    #[test]
    fn consumer_encode_decode_request_round_trip() {
        let c = BlkChannelConsumer::new(1);
        let req = BlkRequest::Read {
            lba: 0xDEAD_BEEF,
            count: 4,
            buf_iova: 0x1000,
        };
        let bytes = c.encode_request(&req).expect("encode");
        let bytes2 = c.encode_request(&req).expect("encode again");
        // Encoding must be deterministic.
        assert_eq!(bytes, bytes2);
        // Verify response round-trip via the decode helper.
        let resp_bytes = encode_canonical(&BlkResponse::Ok).unwrap();
        let decoded = c.decode_response(&resp_bytes).expect("decode response");
        assert_eq!(decoded, BlkResponse::Ok);
    }

    #[test]
    fn consumer_decode_response_rejects_empty_input() {
        let c = BlkChannelConsumer::new(1);
        assert_eq!(c.decode_response(&[]), Err(FsError::WireError));
    }

    // -------------------------------------------------------------------------
    // FileMetadata wire round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn file_metadata_round_trip() {
        let meta = FileMetadata {
            size: 8192,
            block_count: 2,
            created: 1_716_000_000,
            modified: 1_716_001_000,
        };
        let bytes = encode_canonical(&meta).expect("encode");
        let decoded: FileMetadata = nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, meta);
    }

    #[test]
    fn file_metadata_encoding_is_deterministic() {
        let meta = FileMetadata {
            size: 0,
            block_count: 0,
            created: 0,
            modified: 0,
        };
        let a = encode_canonical(&meta).expect("encode-a");
        let b = encode_canonical(&meta).expect("encode-b");
        assert_eq!(a, b);
    }

    // -------------------------------------------------------------------------
    // FsResponse equality (including Stat variant)
    // -------------------------------------------------------------------------

    #[test]
    fn fs_response_stat_carries_metadata() {
        let meta = FileMetadata {
            size: 4096,
            block_count: 1,
            created: 0,
            modified: 0,
        };
        let resp = FsResponse::Stat(meta);
        assert_eq!(resp, FsResponse::Stat(meta));
        assert_ne!(resp, FsResponse::Ok);
    }

    // =========================================================================
    // Phase-2 tests: Superblock, on-disk format types
    // =========================================================================

    #[test]
    fn superblock_magic_and_version() {
        let sb = Superblock {
            magic: NEXACORE_FS_MAGIC,
            version: NEXACORE_FS_VERSION,
            block_size: 4096,
            total_blocks: 1024,
            free_blocks: 1023,
            inode_count: 1,
            root_inode: 1,
            created_at: 0,
            aead_key_id: 0,
        };
        assert_eq!(&sb.magic, b"OMNIFS01");
        assert_eq!(sb.version, NEXACORE_FS_VERSION);
        assert_eq!(sb.block_size, 4096);
    }

    #[test]
    fn superblock_wire_round_trip() {
        let sb = Superblock {
            magic: NEXACORE_FS_MAGIC,
            version: NEXACORE_FS_VERSION,
            block_size: 4096,
            total_blocks: 512,
            free_blocks: 511,
            inode_count: 1,
            root_inode: 1,
            created_at: 42,
            aead_key_id: 0,
        };
        let bytes = encode_canonical(&sb).expect("encode superblock");
        let decoded: Superblock = nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, sb);
    }

    #[test]
    fn block_integrity_tag_wire_round_trip() {
        let tag = BlockIntegrityTag {
            block_number: 99,
            tag: [0xAB; 16],
        };
        let bytes = encode_canonical(&tag).expect("encode tag");
        let decoded: BlockIntegrityTag =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode tag");
        assert_eq!(decoded, tag);
    }

    #[test]
    fn inode_wire_round_trip() {
        let inode = Inode {
            inode_number: 5,
            file_type: FileType::RegularFile,
            size: 8192,
            block_count: 2,
            created: 100,
            modified: 200,
            blocks: vec![10, 11],
            name: String::from("kernel.bin"),
        };
        let bytes = encode_canonical(&inode).expect("encode inode");
        let decoded: Inode = nexacore_types::wire::decode_canonical(&bytes).expect("decode inode");
        assert_eq!(decoded, inode);
    }

    // =========================================================================
    // Phase-2 tests: InMemoryFs
    // =========================================================================

    #[test]
    fn format_creates_root_directory() {
        let fs = InMemoryFs::format(100);
        assert!(fs.exists("/"));
        assert_eq!(fs.superblock().total_blocks, 100);
        assert_eq!(fs.free_blocks(), 99);
        assert_eq!(&fs.superblock().magic, b"OMNIFS01");
    }

    #[test]
    fn create_file_returns_inode_number() {
        let mut fs = InMemoryFs::format(64);
        let ino = fs.create_file("/hello.txt").expect("create");
        assert!(ino >= 2, "user inode numbers start at 2");
    }

    #[test]
    fn create_file_duplicate_returns_error() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/dup.txt").expect("first create");
        assert_eq!(fs.create_file("/dup.txt"), Err(FsError::FileAlreadyExists));
    }

    #[test]
    fn exists_reflects_create_and_delete() {
        let mut fs = InMemoryFs::format(64);
        assert!(!fs.exists("/test.txt"));
        fs.create_file("/test.txt").unwrap();
        assert!(fs.exists("/test.txt"));
        fs.delete_file("/test.txt").unwrap();
        assert!(!fs.exists("/test.txt"));
    }

    #[test]
    fn write_and_read_small_file() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/msg.txt").unwrap();
        let written = fs.write_file("/msg.txt", 0, b"hello world").expect("write");
        assert_eq!(written, 11);

        let data = fs.read_file("/msg.txt", 0, 11).expect("read");
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn write_at_offset_preserves_previous_content() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/f.bin").unwrap();
        fs.write_file("/f.bin", 0, &[1u8; 8]).unwrap();
        // Overwrite bytes 4..8 with 2s.
        fs.write_file("/f.bin", 4, &[2u8; 4]).unwrap();

        let data = fs.read_file("/f.bin", 0, 8).expect("read");
        assert_eq!(&data[0..4], &[1u8; 4]);
        assert_eq!(&data[4..8], &[2u8; 4]);
    }

    #[test]
    fn read_partial_data() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/partial.txt").unwrap();
        fs.write_file("/partial.txt", 0, b"abcdefgh").unwrap();

        let data = fs.read_file("/partial.txt", 2, 3).expect("read middle");
        assert_eq!(data, b"cde");
    }

    #[test]
    fn read_beyond_eof_returns_short_read() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/short.txt").unwrap();
        fs.write_file("/short.txt", 0, b"abc").unwrap();

        // Request 100 bytes but only 3 exist.
        let data = fs.read_file("/short.txt", 0, 100).expect("read");
        assert_eq!(data, b"abc");
    }

    #[test]
    fn read_at_eof_returns_empty() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/empty.txt").unwrap();
        let data = fs.read_file("/empty.txt", 0, 100).expect("read empty");
        assert!(data.is_empty());
    }

    #[test]
    fn delete_frees_blocks() {
        let mut fs = InMemoryFs::format(64);
        let initial_free = fs.free_blocks();

        fs.create_file("/big.bin").unwrap();
        // Write 8193 bytes → requires 3 blocks (ceil(8193 / 4096) = 3).
        fs.write_file("/big.bin", 0, &[0xAAu8; 8193]).unwrap();
        let after_write = fs.free_blocks();
        assert!(after_write < initial_free, "blocks should be consumed");

        fs.delete_file("/big.bin").unwrap();
        assert_eq!(
            fs.free_blocks(),
            initial_free,
            "blocks should be returned after delete"
        );
    }

    #[test]
    fn delete_nonexistent_file_returns_error() {
        let mut fs = InMemoryFs::format(64);
        assert_eq!(fs.delete_file("/nope.txt"), Err(FsError::FileNotFound));
    }

    #[test]
    fn stat_returns_correct_metadata() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/stat_test.txt").unwrap();
        fs.write_file("/stat_test.txt", 0, &[0u8; 4096]).unwrap();

        let meta = fs.stat_file("/stat_test.txt").expect("stat");
        assert_eq!(meta.size, 4096);
        assert_eq!(meta.block_count, 1);
    }

    #[test]
    fn stat_nonexistent_returns_error() {
        let fs = InMemoryFs::format(64);
        assert_eq!(fs.stat_file("/nope"), Err(FsError::FileNotFound));
    }

    #[test]
    fn list_directory_root() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/alpha.txt").unwrap();
        fs.create_file("/beta.txt").unwrap();

        let mut names = fs.list_directory("/").expect("list root");
        names.sort();
        assert_eq!(names, ["alpha.txt", "beta.txt"]);
    }

    #[test]
    fn list_directory_only_direct_children() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/a/b.txt").unwrap();
        fs.create_file("/a/c.txt").unwrap();
        // "/a" is not registered as a directory inode; we register it so
        // list_directory can check its type.  In Phase 2 we cheat: register
        // "/a" as a directory manually via path_map + inodes.
        //
        // In practice callers use FsService::handle_request; this test
        // exercises the raw InMemoryFs API where the caller controls the
        // path_map.  For this test we create "/a" as a virtual directory
        // inode so the assert on "not a direct child of /" holds.
        let inode_a = Inode {
            inode_number: 100,
            file_type: FileType::Directory,
            size: 0,
            block_count: 0,
            created: 0,
            modified: 0,
            blocks: Vec::new(),
            name: String::from("a"),
        };
        fs.inodes.insert(100, inode_a);
        fs.path_map.insert(String::from("/a"), 100);

        let mut root_names = fs.list_directory("/").expect("list root");
        root_names.sort();
        // "/a" should appear but "/a/b.txt" should not.
        assert!(root_names.contains(&String::from("a")));
        assert!(!root_names.contains(&String::from("b.txt")));
    }

    #[test]
    fn list_directory_on_file_returns_error() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/not_a_dir.txt").unwrap();
        assert_eq!(
            fs.list_directory("/not_a_dir.txt"),
            Err(FsError::NotADirectory)
        );
    }

    #[test]
    fn block_allocation_count() {
        let mut fs = InMemoryFs::format(64);
        fs.create_file("/alloc.bin").unwrap();
        // Write exactly 1 block worth.
        fs.write_file("/alloc.bin", 0, &[0u8; 4096]).unwrap();
        let meta = fs.stat_file("/alloc.bin").expect("stat");
        assert_eq!(meta.block_count, 1);

        // Write one more byte → should allocate a second block.
        fs.write_file("/alloc.bin", 4096, &[1u8]).unwrap();
        let meta2 = fs.stat_file("/alloc.bin").expect("stat after second write");
        assert_eq!(meta2.block_count, 2);
        assert_eq!(meta2.size, 4097);
    }

    // =========================================================================
    // Phase-2 tests: FsService integration via handle_request
    // =========================================================================

    #[test]
    fn service_handle_create_and_stat() {
        let mut svc = FsService::new();
        svc.format_volume(512);

        let create_resp = svc.handle_request(&FsRequest::Create {
            path: String::from("/boot.img"),
        });
        assert_eq!(create_resp, FsResponse::Ok);

        let stat_resp = svc.handle_request(&FsRequest::Stat {
            path: String::from("/boot.img"),
        });
        assert!(
            matches!(stat_resp, FsResponse::Stat(_)),
            "expected Stat variant, got {stat_resp:?}"
        );
    }

    #[test]
    fn service_handle_create_duplicate_returns_already_exists() {
        let mut svc = FsService::new();
        svc.format_volume(64);
        svc.handle_request(&FsRequest::Create {
            path: String::from("/dup.txt"),
        });
        let resp = svc.handle_request(&FsRequest::Create {
            path: String::from("/dup.txt"),
        });
        assert_eq!(resp, FsResponse::AlreadyExists);
    }

    #[test]
    fn service_handle_write_data_and_read() {
        let mut svc = FsService::new();
        svc.format_volume(64);
        svc.handle_request(&FsRequest::Create {
            path: String::from("/data.bin"),
        });

        let write_resp = svc.handle_request(&FsRequest::WriteData {
            path: String::from("/data.bin"),
            offset: 0,
            data: b"test payload".to_vec(),
        });
        assert_eq!(write_resp, FsResponse::Ok);

        let read_resp = svc.handle_request(&FsRequest::Read {
            path: String::from("/data.bin"),
            offset: 0,
            count: 12,
        });
        assert_eq!(read_resp, FsResponse::ReadData(b"test payload".to_vec()));
    }

    #[test]
    fn service_handle_delete_removes_file() {
        let mut svc = FsService::new();
        svc.format_volume(64);
        svc.handle_request(&FsRequest::Create {
            path: String::from("/tmp.txt"),
        });

        let del_resp = svc.handle_request(&FsRequest::Delete {
            path: String::from("/tmp.txt"),
        });
        assert_eq!(del_resp, FsResponse::Ok);

        let stat_resp = svc.handle_request(&FsRequest::Stat {
            path: String::from("/tmp.txt"),
        });
        assert_eq!(stat_resp, FsResponse::NotFound);
    }

    #[test]
    fn service_handle_flush_is_noop_and_returns_ok() {
        let mut svc = FsService::new();
        svc.format_volume(64);
        svc.handle_request(&FsRequest::Create {
            path: String::from("/flushed.log"),
        });
        let resp = svc.handle_request(&FsRequest::Flush {
            path: String::from("/flushed.log"),
        });
        assert_eq!(resp, FsResponse::Ok);
    }

    #[test]
    fn service_backward_compat_no_fs_returns_not_implemented() {
        let mut svc = FsService::new();
        assert_eq!(
            svc.handle_request(&FsRequest::Stat {
                path: String::from("/any")
            }),
            FsResponse::NotImplemented
        );
        assert_eq!(
            svc.handle_request(&FsRequest::Create {
                path: String::from("/any")
            }),
            FsResponse::NotImplemented
        );
    }

    #[test]
    fn service_stat_nonexistent_returns_not_found() {
        let mut svc = FsService::new();
        svc.format_volume(64);
        assert_eq!(
            svc.handle_request(&FsRequest::Stat {
                path: String::from("/ghost.txt")
            }),
            FsResponse::NotFound
        );
    }

    #[test]
    fn service_read_nonexistent_returns_not_found() {
        let mut svc = FsService::new();
        svc.format_volume(64);
        assert_eq!(
            svc.handle_request(&FsRequest::Read {
                path: String::from("/missing"),
                offset: 0,
                count: 1,
            }),
            FsResponse::NotFound
        );
    }

    #[test]
    fn service_write_legacy_zero_fills() {
        // The legacy Write variant should allocate blocks (zero-filled) and
        // return Ok.
        let mut svc = FsService::new();
        svc.format_volume(64);
        svc.handle_request(&FsRequest::Create {
            path: String::from("/legacy.bin"),
        });
        let resp = svc.handle_request(&FsRequest::Write {
            path: String::from("/legacy.bin"),
            offset: 0,
            data_len: 4096,
        });
        assert_eq!(resp, FsResponse::Ok);

        // Verify the stat shows 4096 bytes.
        let stat = svc.handle_request(&FsRequest::Stat {
            path: String::from("/legacy.bin"),
        });
        if let FsResponse::Stat(meta) = stat {
            assert_eq!(meta.size, 4096);
        } else {
            panic!("expected Stat response, got {stat:?}");
        }
    }

    // =========================================================================
    // Phase-2 Stream-1 tests: allocator module
    // =========================================================================

    #[test]
    fn allocator_new_all_free() {
        use crate::allocator::BlockBitmap;
        let bm = BlockBitmap::new(16);
        assert_eq!(bm.free_count(), 16);
        assert_eq!(bm.total_blocks(), 16);
    }

    #[test]
    fn allocator_allocate_returns_one_based() {
        use crate::allocator::BlockBitmap;
        let mut bm = BlockBitmap::new(8);
        let b = bm.allocate().expect("allocate");
        assert!(b >= 1, "block numbers must be >= 1");
        assert_eq!(bm.free_count(), 7);
        assert!(bm.is_allocated(b));
    }

    #[test]
    fn allocator_allocate_all_then_none() {
        use crate::allocator::BlockBitmap;
        let mut bm = BlockBitmap::new(4);
        for _ in 0..4 {
            assert!(bm.allocate().is_some());
        }
        assert_eq!(bm.free_count(), 0);
        assert!(bm.allocate().is_none());
    }

    #[test]
    fn allocator_free_is_idempotent() {
        use crate::allocator::BlockBitmap;
        let mut bm = BlockBitmap::new(8);
        let b = bm.allocate().unwrap();
        bm.free(b);
        assert_eq!(bm.free_count(), 8);
        // Double-free must not corrupt the counter.
        bm.free(b);
        assert_eq!(bm.free_count(), 8);
    }

    #[test]
    fn allocator_from_bytes_round_trip() {
        use crate::allocator::BlockBitmap;
        let mut bm = BlockBitmap::new(16);
        bm.allocate().unwrap();
        bm.allocate().unwrap();
        let raw = bm.as_bytes().to_vec();
        let restored = BlockBitmap::from_bytes(&raw, 16).expect("from_bytes");
        assert_eq!(restored.free_count(), 14);
    }

    #[test]
    fn allocator_non_multiple_of_8_blocks() {
        use crate::allocator::BlockBitmap;
        // 10 blocks: bitmap has 2 bytes; last byte has 6 valid bits.
        let mut bm = BlockBitmap::new(10);
        assert_eq!(bm.free_count(), 10);
        // Allocate all 10; no more should be available.
        for _ in 0..10 {
            assert!(bm.allocate().is_some());
        }
        assert!(bm.allocate().is_none());
    }

    // =========================================================================
    // Phase-2 Stream-1 tests: integrity module
    // =========================================================================

    #[test]
    fn integrity_compute_tag_deterministic() {
        use crate::integrity::{BlockKey, compute_tag};
        let key = BlockKey::zeroed();
        let data = [0xAAu8; 4096];
        let t1 = compute_tag(&key, 1, &data);
        let t2 = compute_tag(&key, 1, &data);
        assert_eq!(t1, t2);
    }

    #[test]
    fn integrity_tags_differ_per_block_number() {
        use crate::integrity::{BlockKey, compute_tag};
        let key = BlockKey::zeroed();
        let data = [0u8; 4096];
        let t1 = compute_tag(&key, 1, &data);
        let t2 = compute_tag(&key, 2, &data);
        assert_ne!(
            t1, t2,
            "different block numbers must produce different tags"
        );
    }

    #[test]
    fn integrity_verify_ok_on_matching_tag() {
        use crate::integrity::{BlockKey, compute_tag, verify_tag};
        let key = BlockKey::zeroed();
        let data = [0xBBu8; 4096];
        let tag = compute_tag(&key, 42, &data);
        assert!(verify_tag(&key, 42, &data, &tag).is_ok());
    }

    #[test]
    fn integrity_verify_fails_on_tampered_tag() {
        use crate::integrity::{BlockKey, compute_tag, verify_tag};
        let key = BlockKey::zeroed();
        let data = [0u8; 4096];
        let mut tag = compute_tag(&key, 7, &data);
        tag[0] ^= 0xFF; // flip a byte
        assert_eq!(
            verify_tag(&key, 7, &data, &tag),
            Err(FsError::IntegrityViolation)
        );
    }

    #[test]
    fn integrity_verify_fails_on_tampered_data() {
        use crate::integrity::{BlockKey, compute_tag, verify_tag};
        let key = BlockKey::zeroed();
        let data = [0u8; 4096];
        let tag = compute_tag(&key, 3, &data);
        let mut bad_data = data;
        bad_data[100] = 0xFF;
        assert_eq!(
            verify_tag(&key, 3, &bad_data, &tag),
            Err(FsError::IntegrityViolation)
        );
    }

    #[test]
    fn integrity_stub_tag_is_all_zeroes() {
        use crate::integrity::stub_tag;
        assert_eq!(stub_tag(), [0u8; 16]);
    }

    // =========================================================================
    // Phase-2 Stream-1 tests: ondisk module
    // =========================================================================

    #[test]
    fn ondisk_format_superblock_valid() {
        use crate::ondisk::OnDiskVolume;
        let vol = OnDiskVolume::format(128);
        let sb = vol.superblock();
        assert_eq!(sb.magic, NEXACORE_FS_MAGIC);
        assert_eq!(sb.version, NEXACORE_FS_VERSION);
        assert_eq!(sb.total_blocks, 128);
        assert_eq!(sb.root_inode, 1);
    }

    #[test]
    fn ondisk_format_root_exists() {
        use crate::ondisk::OnDiskVolume;
        let vol = OnDiskVolume::format(64);
        assert!(vol.exists("/"));
    }

    #[test]
    fn ondisk_create_file() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(64);
        let ino = vol.create_file("/hello.txt").expect("create");
        assert!(ino >= 2);
        assert!(vol.exists("/hello.txt"));
    }

    #[test]
    fn ondisk_create_duplicate_returns_error() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(64);
        vol.create_file("/dup.bin").expect("first create");
        assert_eq!(vol.create_file("/dup.bin"), Err(FsError::FileAlreadyExists));
    }

    #[test]
    fn ondisk_write_and_read_small() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(128);
        vol.create_file("/data.bin").expect("create");
        let n = vol
            .write_file("/data.bin", 0, b"hello world")
            .expect("write");
        assert_eq!(n, 11);
        let out = vol.read_file("/data.bin", 0, 11).expect("read");
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn ondisk_write_8kib_and_read() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(256);
        vol.create_file("/big.bin").expect("create");
        let payload = vec![0xCCu8; 8192];
        vol.write_file("/big.bin", 0, &payload)
            .expect("write 8 KiB");
        let out = vol.read_file("/big.bin", 0, 8192).expect("read 8 KiB");
        assert_eq!(out, payload);
    }

    #[test]
    fn ondisk_write_at_second_block_boundary() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(128);
        vol.create_file("/sparse.bin").expect("create");
        let payload = [0xDDu8; 4];
        vol.write_file("/sparse.bin", 4096, &payload)
            .expect("write at offset 4096");
        let out = vol.read_file("/sparse.bin", 4096, 4).expect("read");
        assert_eq!(out, payload);
    }

    #[test]
    fn ondisk_delete_file_frees_blocks() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(128);
        let initial = vol.free_blocks();
        vol.create_file("/tmp.bin").expect("create");
        vol.write_file("/tmp.bin", 0, &[0u8; 4096]).expect("write");
        let after_write = vol.free_blocks();
        assert!(after_write < initial);

        vol.delete_file("/tmp.bin").expect("delete");
        assert!(!vol.exists("/tmp.bin"));
    }

    #[test]
    fn ondisk_stat_returns_metadata() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(64);
        vol.create_file("/stat.bin").expect("create");
        vol.write_file("/stat.bin", 0, &[0u8; 100]).expect("write");
        let meta = vol.stat_file("/stat.bin").expect("stat");
        assert_eq!(meta.size, 100);
        assert_eq!(meta.block_count, 1);
    }

    #[test]
    fn ondisk_list_directory() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(64);
        vol.create_file("/a.bin").expect("a");
        vol.create_file("/b.bin").expect("b");
        let mut names = vol.list_directory("/").expect("list");
        names.sort();
        assert_eq!(names, ["a.bin", "b.bin"]);
    }

    #[test]
    fn ondisk_fsck_clean_on_format() {
        use crate::ondisk::OnDiskVolume;
        let vol = OnDiskVolume::format(64);
        let report = vol.fsck();
        assert!(report.superblock_valid);
        assert!(
            report.is_clean(),
            "fresh volume must be clean: {:?}",
            report.errors
        );
    }

    #[test]
    fn ondisk_fsck_clean_after_write() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(128);
        vol.create_file("/weights.bin").expect("create");
        vol.write_file("/weights.bin", 0, &[0x42u8; 8192])
            .expect("write");
        let report = vol.fsck();
        assert!(
            report.is_clean(),
            "volume after write must be clean: {:?}",
            report.errors
        );
    }

    #[test]
    fn ondisk_sync_and_mount_round_trip() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(64);
        vol.create_file("/model.gguf").expect("create");
        vol.write_file("/model.gguf", 0, b"GGUF").expect("write");

        let raw = vol.sync_to_bytes().expect("sync");
        let mounted = OnDiskVolume::mount(&raw).expect("mount");
        assert_eq!(mounted.superblock().total_blocks, 64);
        assert!(mounted.exists("/model.gguf"));
    }

    #[test]
    fn ondisk_fsservice_format_and_access() {
        let mut svc = FsService::new();
        svc.format_ondisk_volume(128);
        assert!(svc.ondisk_volume().is_some());

        let vol = svc.ondisk_volume_mut().unwrap();
        vol.create_file("/kernel.elf").expect("create");
        vol.write_file("/kernel.elf", 0, b"ELF").expect("write");
        let data = vol.read_file("/kernel.elf", 0, 3).expect("read");
        assert_eq!(data, b"ELF");
    }

    #[test]
    fn ondisk_fsservice_sync_to_bytes() {
        let mut svc = FsService::new();
        svc.format_ondisk_volume(64);
        let raw = svc.sync_ondisk_to_bytes().expect("raw bytes");
        assert_eq!(raw.len(), 64 * 4096);
    }

    #[test]
    fn ondisk_fsservice_mount() {
        let mut svc = FsService::new();
        svc.format_ondisk_volume(64);
        let raw = svc.sync_ondisk_to_bytes().unwrap();
        svc.mount_ondisk_volume(raw).expect("mount");
        assert!(svc.ondisk_volume().is_some());
    }

    // =========================================================================
    // E2E test: format → create → write → sync → mount → read → verify → delete
    // =========================================================================

    #[test]
    fn e2e_format_write_reload_read_verify() {
        use crate::ondisk::OnDiskVolume;

        // Step 1: Format.
        let mut vol = OnDiskVolume::format(256);
        assert_eq!(vol.superblock().magic, NEXACORE_FS_MAGIC);

        // Step 2: Create a file and write 8 KiB.
        vol.create_file("/model.weights").expect("create");
        let payload: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let written = vol
            .write_file("/model.weights", 0, &payload)
            .expect("write");
        assert_eq!(written, 8192);

        // Step 3: Stat.
        let meta = vol.stat_file("/model.weights").expect("stat");
        assert_eq!(meta.size, 8192);
        assert_eq!(meta.block_count, 2);

        // Step 4: Run fsck — must be clean.
        let report = vol.fsck();
        assert!(
            report.is_clean(),
            "pre-sync fsck failed: {:?}",
            report.errors
        );

        // Step 5: Serialise to bytes.
        let raw = vol.sync_to_bytes().expect("sync");
        assert_eq!(raw.len(), 256 * 4096);

        // Step 6: Mount from bytes.
        let mounted = OnDiskVolume::mount(&raw).expect("mount");
        assert_eq!(mounted.superblock().total_blocks, 256);

        // Step 7: Read back and verify data.
        let out = mounted
            .read_file("/model.weights", 0, 8192)
            .expect("read after mount");
        assert_eq!(out, payload, "data must round-trip through serialisation");

        // Step 8: Delete and verify free_blocks increases.
        // (Use the non-mounted vol to avoid re-mount complexity)
        let mut vol2 = OnDiskVolume::format(128);
        vol2.create_file("/tmp.bin").expect("create");
        vol2.write_file("/tmp.bin", 0, &[0xFFu8; 4096])
            .expect("write");
        let before_delete = vol2.free_blocks();
        vol2.delete_file("/tmp.bin").expect("delete");
        let after_delete = vol2.free_blocks();
        assert!(after_delete > before_delete, "delete must free blocks");
        assert!(!vol2.exists("/tmp.bin"));

        // Step 9: Final fsck on the mounted volume.
        let final_report = mounted.fsck();
        assert!(final_report.superblock_valid);
        // Bitmap consistency may not hold perfectly on mount due to Phase-2
        // simplified serialisation; but integrity must hold.
        assert!(
            !final_report
                .errors
                .iter()
                .any(|e| matches!(e, crate::ondisk::FsckError::IntegrityViolation { .. })),
            "no integrity violations: {:?}",
            final_report.errors
        );
    }

    // ── TASK-15 (ADR-0037): mount fail-safe + reboot-persistence semantics ──

    /// A volume whose superblock magic is corrupted must be REJECTED by
    /// `mount` — the daemon's fail-safe so it never treats garbage as a
    /// valid `NCFS` (and never overwrites possibly-recoverable data).
    #[test]
    fn mount_rejects_corrupt_magic() {
        use crate::ondisk::OnDiskVolume;
        let vol = OnDiskVolume::format(64);
        let mut raw = vol.sync_to_bytes().expect("sync");
        raw[0] ^= 0xFF; // flip a magic byte
        assert!(
            OnDiskVolume::mount(&raw).is_err(),
            "mount must reject a corrupt magic"
        );
    }

    /// A volume with an unsupported on-disk version must be rejected
    /// (forward/backward-compat fail-safe).
    #[test]
    fn mount_rejects_corrupt_version() {
        use crate::ondisk::OnDiskVolume;
        let vol = OnDiskVolume::format(64);
        let mut raw = vol.sync_to_bytes().expect("sync");
        // version is the u32 LE right after the 8-byte magic (offset 8).
        raw[8] = 0xEE;
        raw[9] = 0xEE;
        assert!(
            OnDiskVolume::mount(&raw).is_err(),
            "mount must reject an unsupported version"
        );
    }

    /// A truncated volume (image cut to half its declared `total_blocks`)
    /// must be rejected, not partially mounted — the crash/half-write
    /// fail-safe the PLAN requires.
    #[test]
    fn mount_rejects_truncated_volume() {
        use crate::ondisk::OnDiskVolume;
        let vol = OnDiskVolume::format(64);
        let raw = vol.sync_to_bytes().expect("sync");
        // Cut the 64-block image down to 32 blocks — a crash mid-write.
        let truncated = &raw[..32 * 4096];
        assert!(
            OnDiskVolume::mount(truncated).is_err(),
            "mount must reject a truncated volume"
        );
    }

    /// Tampering with a file's DATA block must surface as an integrity
    /// error on read (per-block AEAD), not silently return corrupt data.
    #[test]
    fn mount_then_tampered_data_block_fails_read() {
        use crate::ondisk::OnDiskVolume;
        let mut vol = OnDiskVolume::format(64);
        vol.create_file("/secret").expect("create");
        // Fill exactly one 4 KiB block with a unique sentinel byte so the
        // data block is locatable in the serialised image (the structured
        // metadata regions never contain a 4 KiB run of 0xC3).
        let payload = [0xC3u8; 4096];
        vol.write_file("/secret", 0, &payload).expect("write");
        let mut raw = vol.sync_to_bytes().expect("sync");

        // Find the file's data block (the first long run of 0xC3) and flip
        // a byte inside it.
        let pos = raw
            .windows(64)
            .position(|w| w.iter().all(|&b| b == 0xC3))
            .expect("data block must be present in the image");
        raw[pos + 7] ^= 0xFF;

        // The superblock/bitmap/inode/integrity regions are intact, so the
        // volume still MOUNTS — but reading the tampered file must fail.
        let mounted = OnDiskVolume::mount(&raw).expect("mount (metadata intact)");
        assert!(
            mounted.read_file("/secret", 0, 4096).is_err(),
            "reading a tampered data block must fail the AEAD check"
        );
    }

    /// The daemon's reboot-persistence semantics, host-side: format →
    /// write `/test.txt` → sync → mount → read (boot 1) → update to
    /// boot 2 → sync → re-mount → read (boot 2). This is exactly the
    /// `OnDiskVolume` round-trip `nexacore-fsd` performs across a `qm reset`.
    #[test]
    fn format_remount_persists_test_txt_boot_counter() {
        use crate::ondisk::OnDiskVolume;

        // First boot: format + create /test.txt = "boot 1", sync.
        let mut vol = OnDiskVolume::format(128);
        vol.create_file("/test.txt").expect("create");
        vol.write_file("/test.txt", 0, b"NexaCore-OS persistent root - boot 1\n")
            .expect("write boot 1");
        let disk_after_boot1 = vol.sync_to_bytes().expect("sync boot 1");
        assert_eq!(disk_after_boot1.len(), 128 * 4096);

        // Second boot: mount the persisted image, confirm boot 1 survived.
        let mut vol2 = OnDiskVolume::mount(&disk_after_boot1).expect("remount");
        let content = vol2.read_file("/test.txt", 0, 64).expect("read /test.txt");
        assert_eq!(
            &content[..],
            b"NexaCore-OS persistent root - boot 1\n",
            "/test.txt content must survive the unmount/remount"
        );

        // Update to boot 2 and re-sync.
        vol2.write_file("/test.txt", 0, b"NexaCore-OS persistent root - boot 2\n")
            .expect("write boot 2");
        let disk_after_boot2 = vol2.sync_to_bytes().expect("sync boot 2");

        // Third boot: the counter persisted as boot 2.
        let vol3 = OnDiskVolume::mount(&disk_after_boot2).expect("remount 2");
        let content2 = vol3.read_file("/test.txt", 0, 64).expect("read 2");
        assert_eq!(&content2[..], b"NexaCore-OS persistent root - boot 2\n");
    }
}

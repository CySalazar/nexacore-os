//! `NCFS` service IPC wire protocol (client ⇄ FS service).
//!
//! TASK-22 (DE-D1/DE-D4, ADR-0044) promotes the `NCFS` daemon
//! (`nexacore-fsd`) from a one-shot persistence proof into a long-running
//! **FS service** that owns the on-disk `NCFS` volume and answers file
//! requests over an IPC channel registered as [`CHANNEL_NAME`] (via
//! `NetRegister`; clients resolve it with `NetLookup`). The text editor
//! and any future file-aware app (file manager, TASK-23) speak this
//! protocol; the service is the SINGLE writer of the volume, so reboot
//! persistence (TASK-15) is preserved without multi-writer conflicts.
//!
//! ## Why a separate `nexacore-types` module
//!
//! Both the FS service and every client need to encode/decode these
//! types, so they live in the foundational `nexacore-types` layer and route
//! through [`crate::wire::encode_canonical`] (the single serialization
//! audit point, NCIP-Serde-004), like [`crate::blk`] and
//! [`crate::display_channel`].
//!
//! ## Size bound + durability
//!
//! A request or response MUST fit one 4 KiB IPC message. File payloads
//! are therefore capped at [`FS_MAX_INLINE_BYTES`] in v1 (the text
//! editor's buffer is small); a `WriteChunk`/`DataChunk` continuation
//! protocol for larger files is a documented follow-up. A
//! [`FsRequest::Write`] only updates the in-memory volume; the client
//! MUST send [`FsRequest::Sync`] to flush the volume to NVMe — that is
//! the durability point that makes a save survive reboot.
//!
//! ## Backward-compatibility
//!
//! [`FsRequest`] and [`FsResponse`] are `#[non_exhaustive]`; new
//! variants may be added via PR without breaking source-level `match`
//! consumers (which must carry a `_ =>` arm).

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

/// Name the FS service registers its request channel under (`NetRegister`).
/// Clients resolve it with `NetLookup`.
///
/// NOTE: `NetRegister` interface names are restricted to `[A-Za-z0-9_-]`,
/// ≤ 16 bytes (kernel `services::net`), so this is `ncfs` — NOT a dotted
/// `nexacore.fs` (the dotted form is the BLK registry's convention, a different
/// syscall with different name rules).
pub const CHANNEL_NAME: &str = "ncfs";

/// Name the FS service registers its REPLY channel under. Clients send
/// `FsRequest`s on [`CHANNEL_NAME`] and receive `FsResponse`s here.
/// Same `[A-Za-z0-9_-]`, ≤ 16-byte constraint as [`CHANNEL_NAME`].
pub const REPLY_CHANNEL_NAME: &str = "ncfs-reply";

/// Maximum inline file payload (bytes) for a single [`FsRequest::Write`]
/// or [`FsResponse::Data`].
///
/// Chosen so the encoded message — payload + path + offset + the postcard
/// envelope — stays well under the 4 KiB IPC cap. Files larger than this
/// need the (follow-up) chunk-continuation protocol.
pub const FS_MAX_INLINE_BYTES: usize = 3072;

/// Maximum path length the service accepts (bytes).
pub const FS_MAX_PATH: usize = 256;

/// Error categories returned by the FS service.
///
/// Opaque, PII-free — they mirror the on-disk `nexacore-fs` error kinds
/// reduced to a stable wire vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FsErrno {
    /// No such file or directory.
    NotFound,
    /// The file already exists (on a create that must be exclusive).
    AlreadyExists,
    /// Malformed request (path too long, bad offset, empty path, …).
    InvalidArgument,
    /// Payload exceeds [`FS_MAX_INLINE_BYTES`].
    TooLarge,
    /// Integrity check failed (AEAD tag mismatch) — the volume or a
    /// block is corrupt.
    Integrity,
    /// Underlying block I/O to the NVMe service failed.
    Io,
    /// The service is not mounted (no valid volume) — fail-closed.
    NotMounted,
    /// A directory delete was refused because the directory is not empty
    /// (TASK-23: the file manager's "delete di non-vuoto" error).
    DirectoryNotEmpty,
}

/// A request from a client to the `NCFS` service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FsRequest {
    /// Create an empty regular file at `path`. Idempotent-friendly: the
    /// service MAY return [`FsResponse::Created`] or, if it already
    /// exists, [`FsResponse::Error`]`(AlreadyExists)`.
    Create {
        /// Absolute path (`/notes.txt`).
        path: String,
    },
    /// Write `data` into `path` starting at `offset`. Updates the
    /// in-memory volume only; a later [`FsRequest::Sync`] flushes to
    /// NVMe. `data.len()` MUST be ≤ [`FS_MAX_INLINE_BYTES`].
    Write {
        /// Absolute path.
        path: String,
        /// Byte offset to write at.
        offset: u64,
        /// Bytes to write (≤ [`FS_MAX_INLINE_BYTES`]).
        data: Vec<u8>,
    },
    /// Read up to `len` bytes from `path` starting at `offset`. `len`
    /// MUST be ≤ [`FS_MAX_INLINE_BYTES`]; the reply is
    /// [`FsResponse::Data`].
    Read {
        /// Absolute path.
        path: String,
        /// Byte offset to read from.
        offset: u64,
        /// Number of bytes to read (≤ [`FS_MAX_INLINE_BYTES`]).
        len: u64,
    },
    /// Create a directory at `path` (TASK-23, file manager). Replies
    /// [`FsResponse::Created`], or [`FsResponse::Error`] on a bad name /
    /// existing path.
    Mkdir {
        /// Absolute directory path.
        path: String,
    },
    /// Delete the file OR empty directory at `path`. A non-empty directory
    /// is refused with [`FsErrno::DirectoryNotEmpty`]; the service
    /// dispatches on the inode type.
    Delete {
        /// Absolute path.
        path: String,
    },
    /// List the entries of the directory at `path`
    /// ([`FsResponse::Listing`]).
    ListDir {
        /// Absolute directory path.
        path: String,
    },
    /// Stat `path` ([`FsResponse::Stat`]).
    Stat {
        /// Absolute path.
        path: String,
    },
    /// Flush the whole in-memory volume to NVMe. This is the durability
    /// point — after a successful `Sync`, prior `Write`s survive reboot.
    Sync,
}

/// A response from the `NCFS` service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FsResponse {
    /// Generic success with no payload (e.g. `Write`, `Delete`, `Sync`).
    Ok,
    /// The file was created.
    Created,
    /// Read data (≤ [`FS_MAX_INLINE_BYTES`]).
    Data {
        /// The bytes read (may be shorter than the requested `len` at EOF).
        bytes: Vec<u8>,
    },
    /// Directory listing (entry basenames).
    Listing {
        /// Entry names (not full paths).
        names: Vec<String>,
    },
    /// File metadata.
    Stat {
        /// Size in bytes.
        size: u64,
        /// `true` for a directory.
        is_dir: bool,
    },
    /// The request failed.
    Error(FsErrno),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    #[test]
    fn write_request_round_trips() {
        let req = FsRequest::Write {
            path: String::from("/notes.txt"),
            offset: 0,
            data: alloc::vec![1, 2, 3, 4, 5],
        };
        let bytes = encode_canonical(&req).expect("encode");
        let back: FsRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn read_request_round_trips() {
        let req = FsRequest::Read {
            path: String::from("/notes.txt"),
            offset: 16,
            len: 256,
        };
        let bytes = encode_canonical(&req).expect("encode");
        assert_eq!(decode_canonical::<FsRequest>(&bytes).expect("decode"), req);
    }

    #[test]
    fn sync_and_responses_round_trip() {
        for req in [FsRequest::Sync, FsRequest::ListDir { path: "/".into() }] {
            let bytes = encode_canonical(&req).expect("encode");
            assert_eq!(decode_canonical::<FsRequest>(&bytes).expect("decode"), req);
        }
        let resp = FsResponse::Data {
            bytes: alloc::vec![9u8; 100],
        };
        let bytes = encode_canonical(&resp).expect("encode");
        assert_eq!(
            decode_canonical::<FsResponse>(&bytes).expect("decode"),
            resp
        );
        let err = FsResponse::Error(FsErrno::NotFound);
        let bytes = encode_canonical(&err).expect("encode");
        assert_eq!(decode_canonical::<FsResponse>(&bytes).expect("decode"), err);
    }

    #[test]
    fn max_inline_write_fits_one_ipc_message() {
        // A maximal Write must encode within the 4 KiB IPC envelope.
        let req = FsRequest::Write {
            path: String::from("/some/reasonably/deep/path/notes.txt"),
            offset: u64::MAX,
            data: alloc::vec![0xABu8; FS_MAX_INLINE_BYTES],
        };
        let bytes = encode_canonical(&req).expect("encode");
        assert!(
            bytes.len() <= 4096,
            "max inline write encodes to {} B, must be <= 4096",
            bytes.len()
        );
    }
}

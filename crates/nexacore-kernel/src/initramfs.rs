//! Initramfs — flat archive of userspace binaries.
//!
//! ## Archive format
//!
//! The archive is a sequence of entries with no header or trailer:
//!
//! ```text
//! [name_len : u16 LE] [name : [u8; name_len]] [elf_len : u32 LE] [elf : [u8; elf_len]]
//! ```
//!
//! All multi-byte integers are little-endian. An empty archive (zero bytes)
//! is valid and contains no entries.
//!
//! ## Boot integration
//!
//! At boot the kernel calls [`crate::initramfs::parse_initramfs`] on the raw
//! archive blob, then [`crate::initramfs::load_into_vfs`] to populate
//! [`crate::vfs::InMemoryVfs`] under `/bin/`. The shell binary is expected at
//! `/bin/nexacore-shell` and is located by [`crate::init_process`] during PID-1
//! setup.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::vfs::InMemoryVfs;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An entry parsed from the initramfs archive.
///
/// Each entry corresponds to one binary that will be written to
/// `/bin/<name>` inside [`InMemoryVfs`] by [`load_into_vfs`].
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::initramfs::{build_archive, parse_initramfs};
///
/// let archive = build_archive(&[("ls", b"\x7fELF" as &[u8])]);
/// let entries = parse_initramfs(&archive).unwrap();
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].name, "ls");
/// assert_eq!(&entries[0].data, b"\x7fELF");
/// ```
#[derive(Debug, Clone)]
pub struct InitramfsEntry {
    /// Filename, e.g. `"ls"` or `"cat"`.
    ///
    /// No path component is stored — the loader always places the binary at
    /// `/bin/<name>`.
    pub name: String,
    /// Raw ELF bytes for this binary.
    pub data: Vec<u8>,
}

/// Errors that can occur during initramfs parsing or loading.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::initramfs::{InitramfsError, parse_initramfs};
///
/// // A single byte — name_len field needs 2 bytes — archive is truncated.
/// let err = parse_initramfs(&[0x01]).unwrap_err();
/// assert_eq!(err, InitramfsError::Truncated);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitramfsError {
    /// The archive ended before all expected bytes were available.
    Truncated,
    /// A file name in the archive is not valid UTF-8.
    InvalidName,
    /// A VFS operation (`create_directory`, `create_file`, `write_file`) failed.
    ///
    /// Produced by [`load_into_vfs`]. The underlying [`crate::vfs::VfsError`]
    /// is not propagated to keep this type `no_std`-compatible.
    VfsError,
}

impl core::fmt::Display for InitramfsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("initramfs archive is truncated"),
            Self::InvalidName => f.write_str("initramfs entry name is not valid UTF-8"),
            Self::VfsError => f.write_str("initramfs VFS operation failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// parse_initramfs
// ---------------------------------------------------------------------------

/// Parse a flat initramfs archive into a list of [`InitramfsEntry`] values.
///
/// The archive is consumed linearly. An empty archive (zero bytes) returns
/// an empty list — not an error.
///
/// # Errors
///
/// - [`InitramfsError::Truncated`] — the archive ends before all expected
///   bytes are available.
/// - [`InitramfsError::InvalidName`] — a name field is not valid UTF-8.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::initramfs::{build_archive, parse_initramfs};
///
/// // Empty archive yields an empty list.
/// assert!(parse_initramfs(&[]).unwrap().is_empty());
///
/// // Round-trip a single entry.
/// let archive = build_archive(&[("sh", b"ELF_DATA" as &[u8])]);
/// let entries = parse_initramfs(&archive).unwrap();
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].name, "sh");
/// ```
// Bounds are verified explicitly before every index/slice operation in this
// function; the early-return `Truncated` path prevents any out-of-bounds
// access. The allow attribute is localised here and does not affect any other
// function in the module.
#[allow(
    clippy::indexing_slicing,
    reason = "every access is preceded by an explicit length check that returns Truncated; no out-of-bounds is reachable"
)]
pub fn parse_initramfs(archive: &[u8]) -> Result<Vec<InitramfsEntry>, InitramfsError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos < archive.len() {
        // name_len : u16 LE — 2 bytes
        if pos + 2 > archive.len() {
            return Err(InitramfsError::Truncated);
        }
        let name_len = u16::from_le_bytes([archive[pos], archive[pos + 1]]) as usize;
        pos += 2;

        // name : [u8; name_len]
        if pos + name_len > archive.len() {
            return Err(InitramfsError::Truncated);
        }
        let name = core::str::from_utf8(&archive[pos..pos + name_len])
            .map_err(|_| InitramfsError::InvalidName)?
            .to_string();
        pos += name_len;

        // elf_len : u32 LE — 4 bytes
        if pos + 4 > archive.len() {
            return Err(InitramfsError::Truncated);
        }
        let elf_len = u32::from_le_bytes([
            archive[pos],
            archive[pos + 1],
            archive[pos + 2],
            archive[pos + 3],
        ]) as usize;
        pos += 4;

        // elf : [u8; elf_len]
        if pos + elf_len > archive.len() {
            return Err(InitramfsError::Truncated);
        }
        let data = archive[pos..pos + elf_len].to_vec();
        pos += elf_len;

        entries.push(InitramfsEntry { name, data });
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// load_into_vfs
// ---------------------------------------------------------------------------

/// Load parsed initramfs entries into the VFS under `/bin/<name>`.
///
/// If `/bin` does not exist it is created automatically. Entries that already
/// exist at `/bin/<name>` are silently skipped (idempotent). Returns the
/// number of files actually written (skipped entries are not counted).
///
/// # Errors
///
/// Returns [`InitramfsError::VfsError`] if creating `/bin` or writing a new
/// file fails for any VFS-level reason other than `AlreadyExists` (which is
/// treated as a skip via the [`InMemoryVfs::exists`] guard).
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::{
///     initramfs::{build_archive, load_into_vfs, parse_initramfs},
///     vfs::InMemoryVfs,
/// };
///
/// let archive = build_archive(&[("cat", b"\x7fELF" as &[u8])]);
/// let entries = parse_initramfs(&archive).unwrap();
/// let mut vfs = InMemoryVfs::new();
/// let written = load_into_vfs(&entries, &mut vfs).unwrap();
/// assert_eq!(written, 1);
/// assert!(vfs.exists("/bin/cat"));
/// ```
pub fn load_into_vfs(
    entries: &[InitramfsEntry],
    vfs: &mut InMemoryVfs,
) -> Result<usize, InitramfsError> {
    // Create /bin if it does not yet exist.
    if !vfs.exists("/bin") {
        vfs.create_directory("/bin")
            .map_err(|_| InitramfsError::VfsError)?;
    }

    let mut count = 0usize;
    for entry in entries {
        let path = alloc::format!("/bin/{}", entry.name);

        // Skip files already present — load_into_vfs is idempotent.
        if vfs.exists(&path) {
            continue;
        }

        let inode = vfs
            .create_file(&path)
            .map_err(|_| InitramfsError::VfsError)?;

        vfs.write_file(inode, 0, &entry.data)
            .map_err(|_| InitramfsError::VfsError)?;

        count += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// build_archive
// ---------------------------------------------------------------------------

/// Build an initramfs archive from a list of `(name, data)` pairs.
///
/// This is the inverse of [`parse_initramfs`] and is primarily intended for
/// tests and offline tooling. Every name must be no longer than `u16::MAX`
/// bytes; every data slice must be no longer than `u32::MAX` bytes.
///
/// # Panics
///
/// Panics if a name exceeds `u16::MAX` bytes or a data slice exceeds
/// `u32::MAX` bytes. In practice neither limit is reachable (names are
/// short command identifiers; ELF images are bounded by available RAM).
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::initramfs::{build_archive, parse_initramfs};
///
/// let archive = build_archive(&[("ls", b"ELF1"), ("cat", b"ELF2")]);
/// let entries = parse_initramfs(&archive).unwrap();
/// assert_eq!(entries.len(), 2);
/// assert_eq!(entries[0].name, "ls");
/// assert_eq!(entries[1].name, "cat");
/// ```
// `expect` is intentional here: a name longer than u16::MAX or a data slice
// larger than u32::MAX is a caller programming error, not a recoverable
// condition. The `expect` message encodes the violated invariant.
#[allow(
    clippy::expect_used,
    reason = "u16/u32 overflow of name/data length is a caller programming error; panic is the appropriate response"
)]
#[must_use]
pub fn build_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, data) in entries {
        let name_bytes = name.as_bytes();
        let name_len =
            u16::try_from(name_bytes.len()).expect("initramfs name exceeds u16::MAX bytes");
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(name_bytes);

        let data_len = u32::try_from(data.len()).expect("initramfs data exceeds u32::MAX bytes");
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use direct indexing for clarity; panics are the desired failure mode in tests"
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_initramfs: empty archive → empty vec
    // -----------------------------------------------------------------------

    #[test]
    fn parse_empty_archive_returns_empty_vec() {
        let result = parse_initramfs(&[]).unwrap();
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_initramfs: single entry
    // -----------------------------------------------------------------------

    #[test]
    fn parse_single_entry() {
        let archive = build_archive(&[("hello", b"\x7fELF")]);
        let entries = parse_initramfs(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello");
        assert_eq!(entries[0].data, b"\x7fELF");
    }

    // -----------------------------------------------------------------------
    // parse_initramfs: multiple entries
    // -----------------------------------------------------------------------

    #[test]
    fn parse_multiple_entries() {
        let archive = build_archive(&[("ls", b"elf1"), ("cat", b"elf2"), ("sh", b"elf3")]);
        let entries = parse_initramfs(&archive).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "ls");
        assert_eq!(entries[1].name, "cat");
        assert_eq!(entries[2].name, "sh");
        assert_eq!(entries[0].data, b"elf1");
        assert_eq!(entries[1].data, b"elf2");
        assert_eq!(entries[2].data, b"elf3");
    }

    // -----------------------------------------------------------------------
    // parse_initramfs: truncated — only 1 byte (name_len needs 2)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_truncated_name_len_partial() {
        let err = parse_initramfs(&[0x01]).unwrap_err();
        assert_eq!(err, InitramfsError::Truncated);
    }

    // -----------------------------------------------------------------------
    // parse_initramfs: truncated mid-name
    // -----------------------------------------------------------------------

    #[test]
    fn parse_truncated_mid_name() {
        // name_len = 5, but only 2 name bytes follow.
        let mut archive = Vec::new();
        archive.extend_from_slice(&5u16.to_le_bytes());
        archive.extend_from_slice(b"ab");
        let err = parse_initramfs(&archive).unwrap_err();
        assert_eq!(err, InitramfsError::Truncated);
    }

    // -----------------------------------------------------------------------
    // parse_initramfs: truncated after full name (missing elf_len)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_truncated_missing_elf_len() {
        // Complete name "ls" but no elf_len bytes at all.
        let mut archive = Vec::new();
        archive.extend_from_slice(&2u16.to_le_bytes());
        archive.extend_from_slice(b"ls");
        let err = parse_initramfs(&archive).unwrap_err();
        assert_eq!(err, InitramfsError::Truncated);
    }

    // -----------------------------------------------------------------------
    // parse_initramfs: truncated mid-data
    // -----------------------------------------------------------------------

    #[test]
    fn parse_truncated_mid_data() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&2u16.to_le_bytes());
        archive.extend_from_slice(b"ls");
        archive.extend_from_slice(&10u32.to_le_bytes()); // claims 10 bytes
        archive.extend_from_slice(b"SHOR"); // only 4 bytes
        let err = parse_initramfs(&archive).unwrap_err();
        assert_eq!(err, InitramfsError::Truncated);
    }

    // -----------------------------------------------------------------------
    // parse_initramfs: invalid UTF-8 name
    // -----------------------------------------------------------------------

    #[test]
    fn parse_invalid_utf8_name() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&2u16.to_le_bytes());
        archive.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        archive.extend_from_slice(&0u32.to_le_bytes());
        let err = parse_initramfs(&archive).unwrap_err();
        assert_eq!(err, InitramfsError::InvalidName);
    }

    // -----------------------------------------------------------------------
    // build + parse round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn build_parse_roundtrip() {
        let inputs: &[(&str, &[u8])] = &[
            ("nexacore-shell", b"\x7fELF_SHELL"),
            ("ls", b"\x7fELF_LS"),
            ("cat", b"\x7fELF_CAT"),
        ];
        let archive = build_archive(inputs);
        let entries = parse_initramfs(&archive).unwrap();
        assert_eq!(entries.len(), inputs.len());
        for (i, (name, data)) in inputs.iter().enumerate() {
            assert_eq!(entries[i].name, *name);
            assert_eq!(entries[i].data, *data);
        }
    }

    // -----------------------------------------------------------------------
    // load_into_vfs: creates /bin directory
    // -----------------------------------------------------------------------

    #[test]
    fn load_creates_bin_directory() {
        let mut vfs = InMemoryVfs::new();
        assert!(!vfs.exists("/bin"));
        // Load with no entries — just ensure /bin is created.
        load_into_vfs(&[], &mut vfs).unwrap();
        assert!(vfs.exists("/bin"));
    }

    // -----------------------------------------------------------------------
    // load_into_vfs: writes files correctly
    // -----------------------------------------------------------------------

    #[test]
    fn load_writes_files_into_vfs() {
        let archive = build_archive(&[("ls", b"\x7fELF_LS"), ("cat", b"\x7fELF_CAT")]);
        let entries = parse_initramfs(&archive).unwrap();
        let mut vfs = InMemoryVfs::new();
        let count = load_into_vfs(&entries, &mut vfs).unwrap();
        assert_eq!(count, 2);
        assert!(vfs.exists("/bin/ls"));
        assert!(vfs.exists("/bin/cat"));
    }

    // -----------------------------------------------------------------------
    // load_into_vfs: file content matches the archive
    // -----------------------------------------------------------------------

    #[test]
    fn load_file_content_matches() {
        let elf_data: &[u8] = b"\x7fELF\x02\x01\x01\x00";
        let archive = build_archive(&[("mybin", elf_data)]);
        let entries = parse_initramfs(&archive).unwrap();
        let mut vfs = InMemoryVfs::new();
        load_into_vfs(&entries, &mut vfs).unwrap();

        let stat = vfs.stat("/bin/mybin").unwrap();
        let content = vfs.read_file(stat.inode, 0, elf_data.len()).unwrap();
        assert_eq!(content, elf_data);
    }

    // -----------------------------------------------------------------------
    // load_into_vfs: skips existing files (idempotent second call)
    // -----------------------------------------------------------------------

    #[test]
    fn load_skips_existing_files() {
        let archive = build_archive(&[("ls", b"ELF_V1")]);
        let entries = parse_initramfs(&archive).unwrap();
        let mut vfs = InMemoryVfs::new();

        // First call writes the file.
        let first = load_into_vfs(&entries, &mut vfs).unwrap();
        assert_eq!(first, 1);

        // Second call with the same entries must skip.
        let second = load_into_vfs(&entries, &mut vfs).unwrap();
        assert_eq!(second, 0);

        // Original content is unchanged.
        let stat = vfs.stat("/bin/ls").unwrap();
        let content = vfs.read_file(stat.inode, 0, 6).unwrap();
        assert_eq!(content, b"ELF_V1");
    }

    // -----------------------------------------------------------------------
    // load_into_vfs: pre-existing /bin directory is reused, not recreated
    // -----------------------------------------------------------------------

    #[test]
    fn load_reuses_existing_bin_directory() {
        let archive = build_archive(&[("sh", b"ELF_SH")]);
        let entries = parse_initramfs(&archive).unwrap();
        let mut vfs = InMemoryVfs::new();
        vfs.create_directory("/bin").unwrap();
        let count = load_into_vfs(&entries, &mut vfs).unwrap();
        assert_eq!(count, 1);
        assert!(vfs.exists("/bin/sh"));
    }

    // -----------------------------------------------------------------------
    // build_archive: empty input list → empty byte slice
    // -----------------------------------------------------------------------

    #[test]
    fn build_archive_empty_produces_empty_bytes() {
        let archive = build_archive(&[]);
        assert!(archive.is_empty());
    }

    // -----------------------------------------------------------------------
    // InitramfsError: Display is non-empty for every variant
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_is_non_empty() {
        use alloc::string::ToString;
        assert!(!InitramfsError::Truncated.to_string().is_empty());
        assert!(!InitramfsError::InvalidName.to_string().is_empty());
        assert!(!InitramfsError::VfsError.to_string().is_empty());
    }
}

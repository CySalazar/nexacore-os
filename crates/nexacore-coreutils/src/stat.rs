//! `stat` — format an entry's [`Metadata`] into human-readable lines (WS8-10.2).
//!
//! Reads metadata through the [`FileSystem`] seam and renders it as a small
//! block of `Key: value` lines. Permissions are shown as the abstract
//! capability grant (see [`Capabilities`]), not Unix mode bits, because NexaCore
//! maps access to capability tokens.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::{
    fs::{Capabilities, FileKind, FileSystem, FsError, Metadata},
    path,
};

/// Read and format the metadata of `path` into display lines.
///
/// # Errors
///
/// Propagates [`FsError`] from the seam ([`FsError::NotFound`],
/// [`FsError::InvalidPath`], …).
pub fn stat<F: FileSystem>(fs: &F, path: &str) -> Result<Vec<String>, FsError> {
    let meta = fs.metadata(path)?;
    Ok(format_metadata(path, &meta))
}

/// Format `meta` for `path` into `Key: value` lines (pure; no filesystem).
#[must_use]
pub fn format_metadata(path: &str, meta: &Metadata) -> Vec<String> {
    let name = path::file_name(path).unwrap_or_else(|| path.to_string());
    vec![
        format!("Path: {}", path::normalize(path)),
        format!("Name: {name}"),
        format!("Kind: {}", kind_name(meta.kind)),
        format!("Size: {} bytes", meta.len),
        format!("Access: {}", caps_line(meta.capabilities)),
    ]
}

/// Human name of a [`FileKind`].
const fn kind_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::File => "regular file",
        FileKind::Dir => "directory",
        FileKind::Symlink => "symbolic link",
    }
}

/// Render capabilities as `rwx (read, write, execute)`-style text.
fn caps_line(caps: Capabilities) -> String {
    let mut grants: Vec<&str> = Vec::new();
    if caps.read {
        grants.push("read");
    }
    if caps.write {
        grants.push("write");
    }
    if caps.execute {
        grants.push("execute");
    }
    let list = if grants.is_empty() {
        String::from("none")
    } else {
        grants.join(", ")
    };
    let mut out = caps.as_rwx();
    out.push_str(" (");
    out.push_str(&list);
    out.push(')');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    #[test]
    fn stat_regular_file() {
        let fs = MemFs::new().with_text_file("/etc/hosts", "127.0.0.1\n");
        let out = stat(&fs, "/etc/hosts").unwrap();
        assert_eq!(out[0], "Path: /etc/hosts");
        assert_eq!(out[1], "Name: hosts");
        assert_eq!(out[2], "Kind: regular file");
        assert_eq!(out[3], "Size: 10 bytes");
        assert_eq!(out[4], "Access: rw- (read, write)");
    }

    #[test]
    fn stat_directory() {
        let fs = MemFs::new().with_dir("/d");
        let out = stat(&fs, "/d").unwrap();
        assert_eq!(out[2], "Kind: directory");
        assert_eq!(out[4], "Access: rwx (read, write, execute)");
    }

    #[test]
    fn stat_symlink() {
        let fs = MemFs::new().with_symlink("/link", "/target");
        let out = stat(&fs, "/link").unwrap();
        assert_eq!(out[2], "Kind: symbolic link");
    }

    #[test]
    fn stat_normalizes_path() {
        let fs = MemFs::new().with_text_file("/a/b.txt", "x");
        let out = stat(&fs, "/a/./b.txt").unwrap();
        assert_eq!(out[0], "Path: /a/b.txt");
    }

    #[test]
    fn stat_missing_errors() {
        let fs = MemFs::new();
        assert_eq!(stat(&fs, "/nope"), Err(FsError::NotFound));
    }

    #[test]
    fn caps_none_renders_none() {
        let caps = Capabilities {
            read: false,
            write: false,
            execute: false,
        };
        assert_eq!(caps_line(caps), "--- (none)");
    }
}

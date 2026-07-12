//! `mkdir` / `rmdir` / `touch` / `ln` — directory-entry operations (WS8-10.2).
//!
//! All go through the [`FileSystem`] seam and are fail-closed:
//!
//! - `mkdir` creates a directory; with `-p` it creates missing parents and is
//!   silent if the target already exists as a directory.
//! - `rmdir` removes an **empty** directory ([`FsError::NotEmpty`] otherwise).
//! - `touch` creates an empty file, or is a no-op if the path already exists (the
//!   seam has no modification timestamp to bump).
//! - `ln` creates a symbolic link with `-s`. A hard link (no `-s`) is modeled as
//!   an eager content copy of the target file — the seam has no inode identity to
//!   share, so this is a documented simplification, not a shared-inode hard link.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    fs::{FileKind, FileSystem, FsError},
    path,
};

/// Options for [`mkdir`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MkdirOptions {
    /// `-p`: create missing parent directories, and do not error if the target
    /// already exists as a directory.
    pub parents: bool,
}

/// Options for [`ln`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LnOptions {
    /// `-s`: create a symbolic link instead of a (copy-modeled) hard link.
    pub symbolic: bool,
}

/// Create the directory `path`.
///
/// # Errors
///
/// Without `opts.parents`: [`FsError::AlreadyExists`] if the path exists,
/// [`FsError::NotFound`]/[`FsError::NotADirectory`] if the parent is missing or
/// not a directory. With `opts.parents`: only [`FsError::NotADirectory`] if a
/// path component is an existing non-directory.
pub fn mkdir<F: FileSystem>(fs: &mut F, path: &str, opts: &MkdirOptions) -> Result<(), FsError> {
    if !opts.parents {
        return fs.create_dir(path);
    }

    // `-p`: walk the components, creating each missing directory in turn.
    let normalized = if path::is_absolute(path) {
        path::normalize(path)
    } else {
        return Err(FsError::InvalidPath);
    };

    let mut current = String::from("/");
    for component in normalized.split('/') {
        if component.is_empty() {
            continue;
        }
        current = path::join(&current, component);
        match fs.metadata(&current) {
            Ok(meta) => {
                if meta.kind != FileKind::Dir {
                    return Err(FsError::NotADirectory);
                }
            }
            Err(FsError::NotFound) => fs.create_dir(&current)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Remove the empty directory `path`.
///
/// # Errors
///
/// [`FsError::NotEmpty`] if it still has entries, [`FsError::NotADirectory`] if
/// `path` is not a directory, [`FsError::NotFound`] if it does not exist.
pub fn rmdir<F: FileSystem>(fs: &mut F, path: &str) -> Result<(), FsError> {
    fs.remove_dir(path)
}

/// `touch path`: create an empty file, or do nothing if `path` already exists.
///
/// # Errors
///
/// [`FsError::NotFound`]/[`FsError::NotADirectory`] if the parent directory is
/// missing or not a directory.
pub fn touch<F: FileSystem>(fs: &mut F, path: &str) -> Result<(), FsError> {
    match fs.metadata(path) {
        // Already exists: a real `touch` would bump mtime; the seam has none, so
        // this is a no-op.
        Ok(_) => Ok(()),
        Err(FsError::NotFound) => fs.write(path, &[]),
        Err(e) => Err(e),
    }
}

/// `ln [-s] target link`: link `link` to `target`.
///
/// With `opts.symbolic` a symlink is created. Without it, a hard link is modeled
/// by copying the target file's current bytes to `link` (see the module note).
///
/// # Errors
///
/// [`FsError::AlreadyExists`] if `link` exists, [`FsError::NotFound`] if a hard
/// link's `target` is missing, [`FsError::IsADirectory`] if a hard link targets a
/// directory, plus any seam error.
pub fn ln<F: FileSystem>(
    fs: &mut F,
    target: &str,
    link: &str,
    opts: &LnOptions,
) -> Result<(), FsError> {
    if opts.symbolic {
        return fs.symlink(target, link);
    }

    // Hard link (copy-modeled): refuse to clobber, refuse directories.
    if fs.exists(link) {
        return Err(FsError::AlreadyExists);
    }
    let meta = fs.metadata(target)?;
    if meta.kind == FileKind::Dir {
        return Err(FsError::IsADirectory);
    }
    let bytes = fs.read(target)?;
    fs.write(link, &bytes)
}

/// The path components of `path`, for callers building incremental paths.
/// Returns non-empty, non-`.` components in order (mirrors [`crate::path`]).
#[must_use]
pub fn components(path: &str) -> Vec<String> {
    path::normalize(path)
        .split('/')
        .filter(|c| !c.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    #[test]
    fn mkdir_creates_single_dir() {
        let mut fs = MemFs::new();
        mkdir(&mut fs, "/a", &MkdirOptions::default()).unwrap();
        assert_eq!(fs.metadata("/a").unwrap().kind, FileKind::Dir);
    }

    #[test]
    fn mkdir_without_parents_fails_on_missing_parent() {
        let mut fs = MemFs::new();
        assert_eq!(
            mkdir(&mut fs, "/a/b/c", &MkdirOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn mkdir_without_parents_rejects_existing() {
        let mut fs = MemFs::new().with_dir("/a");
        assert_eq!(
            mkdir(&mut fs, "/a", &MkdirOptions::default()),
            Err(FsError::AlreadyExists)
        );
    }

    #[test]
    fn mkdir_parents_creates_chain() {
        let mut fs = MemFs::new();
        mkdir(&mut fs, "/a/b/c", &MkdirOptions { parents: true }).unwrap();
        assert_eq!(fs.metadata("/a").unwrap().kind, FileKind::Dir);
        assert_eq!(fs.metadata("/a/b").unwrap().kind, FileKind::Dir);
        assert_eq!(fs.metadata("/a/b/c").unwrap().kind, FileKind::Dir);
    }

    #[test]
    fn mkdir_parents_is_silent_on_existing() {
        let mut fs = MemFs::new().with_dir("/a/b");
        assert_eq!(
            mkdir(&mut fs, "/a/b", &MkdirOptions { parents: true }),
            Ok(())
        );
    }

    #[test]
    fn mkdir_parents_rejects_non_dir_component() {
        let mut fs = MemFs::new().with_text_file("/a", "iamafile");
        assert_eq!(
            mkdir(&mut fs, "/a/b", &MkdirOptions { parents: true }),
            Err(FsError::NotADirectory)
        );
    }

    #[test]
    fn rmdir_removes_empty_dir() {
        let mut fs = MemFs::new().with_dir("/a");
        rmdir(&mut fs, "/a").unwrap();
        assert!(!fs.exists("/a"));
    }

    #[test]
    fn rmdir_refuses_non_empty() {
        let mut fs = MemFs::new().with_text_file("/a/f.txt", "x");
        assert_eq!(rmdir(&mut fs, "/a"), Err(FsError::NotEmpty));
    }

    #[test]
    fn touch_creates_empty_file() {
        let mut fs = MemFs::new();
        touch(&mut fs, "/f").unwrap();
        assert_eq!(fs.read("/f").unwrap(), b"");
    }

    #[test]
    fn touch_is_noop_on_existing() {
        let mut fs = MemFs::new().with_text_file("/f", "keep");
        touch(&mut fs, "/f").unwrap();
        assert_eq!(fs.read_to_string("/f").unwrap(), "keep");
    }

    #[test]
    fn touch_missing_parent_fails() {
        let mut fs = MemFs::new();
        assert_eq!(touch(&mut fs, "/no/where"), Err(FsError::NotFound));
    }

    #[test]
    fn ln_symbolic_creates_symlink() {
        let mut fs = MemFs::new().with_text_file("/t", "data");
        ln(&mut fs, "/t", "/link", &LnOptions { symbolic: true }).unwrap();
        assert_eq!(fs.metadata("/link").unwrap().kind, FileKind::Symlink);
    }

    #[test]
    fn ln_hard_copies_bytes() {
        let mut fs = MemFs::new().with_text_file("/t", "data");
        ln(&mut fs, "/t", "/link", &LnOptions::default()).unwrap();
        assert_eq!(fs.metadata("/link").unwrap().kind, FileKind::File);
        assert_eq!(fs.read_to_string("/link").unwrap(), "data");
    }

    #[test]
    fn ln_hard_rejects_directory() {
        let mut fs = MemFs::new().with_dir("/d");
        assert_eq!(
            ln(&mut fs, "/d", "/link", &LnOptions::default()),
            Err(FsError::IsADirectory)
        );
    }

    #[test]
    fn ln_refuses_existing_link() {
        let mut fs = MemFs::new()
            .with_text_file("/t", "data")
            .with_text_file("/link", "already");
        assert_eq!(
            ln(&mut fs, "/t", "/link", &LnOptions::default()),
            Err(FsError::AlreadyExists)
        );
    }

    #[test]
    fn components_splits_normalized() {
        assert_eq!(components("/a/b/../c"), ["a", "c"]);
        assert!(components("/").is_empty());
    }
}

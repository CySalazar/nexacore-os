//! `cp` / `mv` / `rm` — copy, move, and remove over the seam (WS8-10.1).
//!
//! All three go through the [`FileSystem`] trait and are fail-closed:
//!
//! - `cp` copies a file's bytes; with `-r` it copies a directory subtree. Copying
//!   a directory without `-r` is [`FsError::IsADirectory`]. If the destination is
//!   an existing directory, the source is copied *into* it under its own name.
//! - `mv` renames/moves via the seam; into an existing directory it moves under
//!   the source's name.
//! - `rm` removes a file; with `-r` it removes a directory subtree; with `-f` a
//!   missing target is ignored (no error).

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    fs::{FileKind, FileSystem, FsError},
    path,
};

/// Options for [`cp`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpOptions {
    /// `-r`: copy directories recursively.
    pub recursive: bool,
}

/// Options for [`rm`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RmOptions {
    /// `-r`: remove directories and their contents recursively.
    pub recursive: bool,
    /// `-f`: ignore a missing target instead of erroring.
    pub force: bool,
}

/// If `dst` is an existing directory in `fs`, return the path *inside* it named
/// after `src`'s final component; otherwise return `dst` unchanged.
fn dst_into_dir<F: FileSystem>(fs: &F, src: &str, dst: &str) -> String {
    let dst_is_dir = matches!(
        fs.metadata(dst),
        Ok(m) if m.kind == FileKind::Dir
    );
    if dst_is_dir {
        if let Some(name) = path::file_name(src) {
            return path::join(dst, &name);
        }
    }
    dst.to_string()
}

/// Copy `src` to `dst` in `fs`.
///
/// # Errors
///
/// [`FsError::NotFound`] if `src` is missing, [`FsError::IsADirectory`] if `src`
/// is a directory and `opts.recursive` is not set, plus any seam error while
/// writing the destination.
pub fn cp<F: FileSystem>(
    fs: &mut F,
    src: &str,
    dst: &str,
    opts: &CpOptions,
) -> Result<(), FsError> {
    let final_dst = dst_into_dir(fs, src, dst);
    copy_entry(fs, src, &final_dst, opts)
}

/// Recursive worker for [`cp`], copying the entry at `src` to exactly `dst`.
fn copy_entry<F: FileSystem>(
    fs: &mut F,
    src: &str,
    dst: &str,
    opts: &CpOptions,
) -> Result<(), FsError> {
    let meta = fs.metadata(src)?;
    match meta.kind {
        FileKind::File => {
            let bytes = fs.read(src)?;
            fs.write(dst, &bytes)
        }
        FileKind::Symlink => {
            // Re-create the link at the destination; the seam does not expose
            // its target through metadata, so copy it as a fresh dangling link
            // pointing at the source path (documented simplification).
            fs.symlink(src, dst)
        }
        FileKind::Dir => {
            if !opts.recursive {
                return Err(FsError::IsADirectory);
            }
            fs.create_dir(dst)?;
            // Snapshot names first so we do not iterate while mutating.
            let names: Vec<String> = fs.read_dir(src)?.into_iter().map(|e| e.name).collect();
            for name in names {
                let child_src = path::join(src, &name);
                let child_dst = path::join(dst, &name);
                copy_entry(fs, &child_src, &child_dst, opts)?;
            }
            Ok(())
        }
    }
}

/// Move/rename `src` to `dst` in `fs`.
///
/// # Errors
///
/// [`FsError::NotFound`] if `src` is missing, [`FsError::AlreadyExists`] if the
/// resolved destination exists, plus any seam error.
pub fn mv<F: FileSystem>(fs: &mut F, src: &str, dst: &str) -> Result<(), FsError> {
    let final_dst = dst_into_dir(fs, src, dst);
    fs.rename(src, &final_dst)
}

/// Remove `path` from `fs`.
///
/// # Errors
///
/// [`FsError::NotFound`] if `path` is missing and `opts.force` is not set,
/// [`FsError::IsADirectory`] if it is a directory and `opts.recursive` is not
/// set, plus any seam error.
pub fn rm<F: FileSystem>(fs: &mut F, path: &str, opts: &RmOptions) -> Result<(), FsError> {
    let meta = match fs.metadata(path) {
        Ok(m) => m,
        Err(FsError::NotFound) if opts.force => return Ok(()),
        Err(e) => return Err(e),
    };
    match meta.kind {
        FileKind::File | FileKind::Symlink => fs.remove_file(path),
        FileKind::Dir => {
            if !opts.recursive {
                return Err(FsError::IsADirectory);
            }
            remove_tree(fs, path)
        }
    }
}

/// Recursively remove the directory subtree rooted at `dir`.
fn remove_tree<F: FileSystem>(fs: &mut F, dir: &str) -> Result<(), FsError> {
    let entries = fs.read_dir(dir)?;
    for entry in entries {
        let child = path::join(dir, &entry.name);
        match entry.metadata.kind {
            FileKind::Dir => remove_tree(fs, &child)?,
            FileKind::File | FileKind::Symlink => fs.remove_file(&child)?,
        }
    }
    fs.remove_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    fn fs() -> MemFs {
        MemFs::new()
            .with_text_file("/src/a.txt", "alpha")
            .with_text_file("/src/sub/b.txt", "beta")
            .with_dir("/dst")
    }

    #[test]
    fn cp_file_to_new_path() {
        let mut f = fs();
        cp(&mut f, "/src/a.txt", "/copy.txt", &CpOptions::default()).unwrap();
        assert_eq!(f.read_to_string("/copy.txt").unwrap(), "alpha");
        // Source is untouched.
        assert_eq!(f.read_to_string("/src/a.txt").unwrap(), "alpha");
    }

    #[test]
    fn cp_file_into_existing_dir_uses_basename() {
        let mut f = fs();
        cp(&mut f, "/src/a.txt", "/dst", &CpOptions::default()).unwrap();
        assert_eq!(f.read_to_string("/dst/a.txt").unwrap(), "alpha");
    }

    #[test]
    fn cp_directory_requires_recursive() {
        let mut f = fs();
        assert_eq!(
            cp(&mut f, "/src", "/dst/src", &CpOptions::default()),
            Err(FsError::IsADirectory)
        );
    }

    #[test]
    fn cp_recursive_copies_subtree() {
        let mut f = fs();
        cp(&mut f, "/src", "/copy", &CpOptions { recursive: true }).unwrap();
        assert_eq!(f.read_to_string("/copy/a.txt").unwrap(), "alpha");
        assert_eq!(f.read_to_string("/copy/sub/b.txt").unwrap(), "beta");
        // Original remains.
        assert_eq!(f.read_to_string("/src/sub/b.txt").unwrap(), "beta");
    }

    #[test]
    fn cp_missing_source_errors() {
        let mut f = fs();
        assert_eq!(
            cp(&mut f, "/nope", "/x", &CpOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn mv_renames_file() {
        let mut f = fs();
        mv(&mut f, "/src/a.txt", "/moved.txt").unwrap();
        assert!(!f.exists("/src/a.txt"));
        assert_eq!(f.read_to_string("/moved.txt").unwrap(), "alpha");
    }

    #[test]
    fn mv_into_existing_dir() {
        let mut f = fs();
        mv(&mut f, "/src/a.txt", "/dst").unwrap();
        assert_eq!(f.read_to_string("/dst/a.txt").unwrap(), "alpha");
    }

    #[test]
    fn mv_missing_source_errors() {
        let mut f = fs();
        assert_eq!(mv(&mut f, "/nope", "/x"), Err(FsError::NotFound));
    }

    #[test]
    fn rm_file() {
        let mut f = fs();
        rm(&mut f, "/src/a.txt", &RmOptions::default()).unwrap();
        assert!(!f.exists("/src/a.txt"));
    }

    #[test]
    fn rm_directory_requires_recursive() {
        let mut f = fs();
        assert_eq!(
            rm(&mut f, "/src", &RmOptions::default()),
            Err(FsError::IsADirectory)
        );
    }

    #[test]
    fn rm_recursive_removes_subtree() {
        let mut f = fs();
        rm(
            &mut f,
            "/src",
            &RmOptions {
                recursive: true,
                force: false,
            },
        )
        .unwrap();
        assert!(!f.exists("/src"));
        assert!(!f.exists("/src/sub/b.txt"));
    }

    #[test]
    fn rm_missing_without_force_errors() {
        let mut f = fs();
        assert_eq!(
            rm(&mut f, "/nope", &RmOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn rm_missing_with_force_is_ok() {
        let mut f = fs();
        assert_eq!(
            rm(
                &mut f,
                "/nope",
                &RmOptions {
                    recursive: false,
                    force: true,
                },
            ),
            Ok(())
        );
    }
}

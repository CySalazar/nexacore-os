//! `cat` — concatenate file contents over the seam (WS8-10.1).
//!
//! Reads each named file through the [`FileSystem`] and joins their contents in
//! order. Fail-closed: a missing file is [`FsError::NotFound`], a directory is
//! [`FsError::IsADirectory`], and non-UTF-8 bytes are [`FsError::InvalidData`].
//! No implicit newline is inserted between files — the bytes are concatenated
//! exactly as `cat` does.

use alloc::string::String;

use crate::fs::{FileSystem, FsError};

/// Concatenate the contents of `paths`, in order, into one string.
///
/// # Errors
///
/// Propagates the first [`FsError`] encountered (missing path, directory,
/// non-absolute path, or non-UTF-8 content).
pub fn cat<F, S>(fs: &F, paths: &[S]) -> Result<String, FsError>
where
    F: FileSystem,
    S: AsRef<str>,
{
    let mut out = String::new();
    for path in paths {
        let text = fs.read_to_string(path.as_ref())?;
        out.push_str(&text);
    }
    Ok(out)
}

/// Concatenate a single file's contents (convenience for the common case).
///
/// # Errors
///
/// Propagates any [`FsError`] from reading `path`.
pub fn cat_one<F: FileSystem>(fs: &F, path: &str) -> Result<String, FsError> {
    fs.read_to_string(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    fn fs() -> MemFs {
        MemFs::new()
            .with_text_file("/a.txt", "alpha\n")
            .with_text_file("/b.txt", "beta\n")
            .with_dir("/d")
    }

    #[test]
    fn concatenates_in_order() {
        let out = cat(&fs(), &["/a.txt", "/b.txt"]).unwrap();
        assert_eq!(out, "alpha\nbeta\n");
    }

    #[test]
    fn single_file() {
        assert_eq!(cat_one(&fs(), "/a.txt").unwrap(), "alpha\n");
    }

    #[test]
    fn missing_file_errors() {
        assert_eq!(cat(&fs(), &["/a.txt", "/nope"]), Err(FsError::NotFound));
    }

    #[test]
    fn directory_errors() {
        assert_eq!(cat(&fs(), &["/d"]), Err(FsError::IsADirectory));
    }

    #[test]
    fn non_utf8_errors() {
        let bad = MemFs::new().with_file("/x", &[0xFF, 0xFE]);
        assert_eq!(cat(&bad, &["/x"]), Err(FsError::InvalidData));
    }

    #[test]
    fn empty_list_yields_empty_string() {
        let empty: [&str; 0] = [];
        assert_eq!(cat(&fs(), &empty).unwrap(), "");
    }
}

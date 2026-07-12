//! `which` - locate an executable on a search path (WS8-10.9).
//!
//! `which name` walks a list of directories (a `PATH`) in order and reports the
//! first entry named `name` that is a regular file carrying the *execute*
//! capability. The directories are resolved through the [`fs::FileSystem`](crate::fs)
//! seam, so the search is fully host-testable against [`MemFs`](crate::fs::MemFs).
//!
//! ## Capability-aware executability
//!
//! On a Unix system `which` tests the `x` mode bit. NexaCore has no mode bits, so
//! "executable" here means the entry's [`Capabilities`](crate::fs::Capabilities)
//! grant carries `execute`. A file present on the `PATH` but lacking the execute
//! capability is skipped, exactly as a non-`+x` file is on Unix.
//!
//! ## Not found is non-zero
//!
//! [`which`] returns `None` when no match exists - the caller maps that to a
//! non-zero exit status, as the real tool does. [`which_all`] (`which -a`)
//! returns every match in `PATH` order and is empty when there is none.

use alloc::{string::String, vec::Vec};

use crate::{
    fs::{FileKind, FileSystem},
    path,
};

/// Split a `PATH`-style string into its directory components on `:`.
///
/// Empty components (from a leading, trailing, or doubled `:`) are dropped
/// rather than being treated as the current directory, because this crate's
/// filesystem seam only accepts absolute paths.
#[must_use]
pub fn split_path(path_var: &str) -> Vec<&str> {
    path_var.split(':').filter(|d| !d.is_empty()).collect()
}

/// Whether `dir/name` names an executable regular file in `fs`.
fn is_executable_at<F: FileSystem>(fs: &F, dir: &str, name: &str) -> bool {
    let candidate = path::join(dir, name);
    fs.metadata(&candidate)
        .is_ok_and(|meta| meta.kind == FileKind::File && meta.capabilities.execute)
}

/// Find the first directory in `dirs` that holds an executable named `name`,
/// returning the full normalized path, or `None` if there is no match.
///
/// This is `which name`: search order is the order of `dirs`, and only regular
/// files carrying the execute capability count.
#[must_use]
pub fn which<F: FileSystem>(fs: &F, dirs: &[&str], name: &str) -> Option<String> {
    for dir in dirs {
        if is_executable_at(fs, dir, name) {
            return Some(path::join(dir, name));
        }
    }
    None
}

/// Find **every** executable named `name` across `dirs`, in `PATH` order - this
/// is `which -a name`.
///
/// The result is empty when there is no match. Duplicate directory entries
/// yield duplicate results, matching the real tool's behaviour.
#[must_use]
pub fn which_all<F: FileSystem>(fs: &F, dirs: &[&str], name: &str) -> Vec<String> {
    let mut hits: Vec<String> = Vec::new();
    for dir in dirs {
        if is_executable_at(fs, dir, name) {
            hits.push(path::join(dir, name));
        }
    }
    hits
}

/// Convenience over a `PATH` string: [`which`] after [`split_path`].
#[must_use]
pub fn which_in_path<F: FileSystem>(fs: &F, path_var: &str, name: &str) -> Option<String> {
    which(fs, &split_path(path_var), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    /// A filesystem with `/bin/ls` and `/usr/bin/ls` executable, `/bin/data`
    /// non-executable, and a second executable `/usr/bin/only`.
    fn fs() -> MemFs {
        MemFs::new()
            .with_executable_file("/bin/ls", b"elf")
            .with_executable_file("/usr/bin/ls", b"elf")
            // `/bin/data` is a plain (non-executable) file.
            .with_text_file("/bin/data", "text")
            .with_executable_file("/usr/bin/only", b"elf")
    }

    #[test]
    fn split_path_drops_empty() {
        assert_eq!(split_path("/bin::/usr/bin:"), ["/bin", "/usr/bin"]);
        assert!(split_path("").is_empty());
    }

    #[test]
    fn which_returns_first_match() {
        let fs = fs();
        assert_eq!(
            which(&fs, &["/bin", "/usr/bin"], "ls"),
            Some(String::from("/bin/ls"))
        );
        // Reversed search order finds the other one first.
        assert_eq!(
            which(&fs, &["/usr/bin", "/bin"], "ls"),
            Some(String::from("/usr/bin/ls"))
        );
    }

    #[test]
    fn which_skips_non_executable() {
        let fs = fs();
        assert_eq!(which(&fs, &["/bin"], "data"), None);
    }

    #[test]
    fn which_missing_is_none() {
        let fs = fs();
        assert_eq!(which(&fs, &["/bin", "/usr/bin"], "nope"), None);
    }

    #[test]
    fn which_all_lists_every_match_in_order() {
        let fs = fs();
        assert_eq!(
            which_all(&fs, &["/bin", "/usr/bin"], "ls"),
            ["/bin/ls", "/usr/bin/ls"]
        );
    }

    #[test]
    fn which_all_empty_when_none() {
        let fs = fs();
        assert!(which_all(&fs, &["/bin"], "nope").is_empty());
    }

    #[test]
    fn which_in_path_uses_colon_string() {
        let fs = fs();
        assert_eq!(
            which_in_path(&fs, "/bin:/usr/bin", "only"),
            Some(String::from("/usr/bin/only"))
        );
    }

    #[test]
    fn missing_directory_is_skipped_not_fatal() {
        let fs = fs();
        assert_eq!(
            which(&fs, &["/nonexistent", "/bin"], "ls"),
            Some(String::from("/bin/ls"))
        );
    }
}

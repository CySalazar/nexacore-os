//! `find` — walk a directory subtree over the seam and emit matching paths
//! (WS8-10.4).
//!
//! Walks the tree rooted at a starting path through the
//! [`fs::FileSystem`](crate::fs) seam, applying a conjunction of predicates and
//! emitting the absolute path of every entry that satisfies them all:
//!
//! - `-name <glob>` ([`FindOptions::name`]): the entry's *basename* matches a
//!   glob using a small `*`/`?` matcher (see [`glob_match`]).
//! - `-type f|d|l` ([`FindOptions::type_filter`]): the entry is a regular file,
//!   directory, or symlink.
//! - `-maxdepth N` ([`FindOptions::max_depth`]): descend no deeper than `N`
//!   levels below the start (which is depth 0).
//!
//! ## Termination & cycles
//!
//! Recursion is bounded by [`FindOptions::max_depth`] (default
//! [`DEFAULT_MAX_DEPTH`]), so a pathological layout can never spin forever.
//! Symlinks are treated as non-followed leaves: they are reported (and can match
//! `-type l`) but are never descended into, which makes symlink cycles
//! impossible by construction. Entries are emitted in pre-order (each directory
//! before its sorted children).

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    fs::{FileKind, FileSystem, FsError},
    path,
};

/// The default recursion cap when a caller does not set one.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// The `-type` predicate: match a single kind of entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindType {
    /// `-type f`: a regular file.
    File,
    /// `-type d`: a directory.
    Dir,
    /// `-type l`: a symbolic link.
    Symlink,
}

impl FindType {
    /// Whether this predicate accepts `kind`.
    #[must_use]
    pub fn accepts(self, kind: FileKind) -> bool {
        matches!(
            (self, kind),
            (Self::File, FileKind::File)
                | (Self::Dir, FileKind::Dir)
                | (Self::Symlink, FileKind::Symlink)
        )
    }
}

/// The conjunction of predicates controlling [`find`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindOptions {
    /// `-name`: glob matched against each entry's basename. `None` matches any.
    pub name: Option<String>,
    /// `-type`: kind filter. `None` matches any kind.
    pub type_filter: Option<FindType>,
    /// `-maxdepth`: maximum depth below the start path (start is depth 0).
    pub max_depth: usize,
}

impl Default for FindOptions {
    fn default() -> Self {
        Self {
            name: None,
            type_filter: None,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

/// Walk the subtree rooted at `root`, returning matching absolute paths.
///
/// The start path itself is a candidate (at depth 0). Directories are descended
/// in sorted order up to [`FindOptions::max_depth`]; symlinks are leaves.
///
/// # Errors
///
/// [`FsError::NotFound`] if `root` does not exist, [`FsError::InvalidPath`] if it
/// is not absolute, plus any seam error encountered while listing a directory.
pub fn find<F: FileSystem>(fs: &F, root: &str, opts: &FindOptions) -> Result<Vec<String>, FsError> {
    let meta = fs.metadata(root)?;
    let start = path::normalize(root);
    let mut out: Vec<String> = Vec::new();
    if matches(&start, meta.kind, opts) {
        out.push(start.clone());
    }
    if meta.kind == FileKind::Dir {
        walk(fs, &start, 1, opts, &mut out)?;
    }
    Ok(out)
}

/// Recursive worker: visit the children of `dir` at `depth`.
fn walk<F: FileSystem>(
    fs: &F,
    dir: &str,
    depth: usize,
    opts: &FindOptions,
    out: &mut Vec<String>,
) -> Result<(), FsError> {
    if depth > opts.max_depth {
        return Ok(());
    }
    let mut entries = fs.read_dir(dir)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    for entry in entries {
        let child = path::join(dir, &entry.name);
        if matches(&child, entry.metadata.kind, opts) {
            out.push(child.clone());
        }
        // Descend into real directories only; symlinks are non-followed leaves.
        if entry.metadata.kind == FileKind::Dir {
            walk(fs, &child, depth.saturating_add(1), opts, out)?;
        }
    }
    Ok(())
}

/// Whether the entry at `full_path` of the given `kind` satisfies every set
/// predicate.
fn matches(full_path: &str, kind: FileKind, opts: &FindOptions) -> bool {
    if let Some(ft) = opts.type_filter {
        if !ft.accepts(kind) {
            return false;
        }
    }
    if let Some(pattern) = opts.name.as_deref() {
        let base = path::file_name(full_path).unwrap_or_else(|| full_path.to_string());
        if !glob_match(pattern, &base) {
            return false;
        }
    }
    true
}

/// Match `name` against a glob `pattern` supporting `*` (zero or more of any
/// character) and `?` (exactly one character); every other character is literal.
///
/// The matcher is a small, allocation-light, recursion-bounded routine over
/// `char` slices; it uses no indexing or slicing operators (only `split_first`).
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = name.chars().collect();
    match_chars(&pat, &txt)
}

/// Core glob matcher over `char` slices.
fn match_chars(pat: &[char], txt: &[char]) -> bool {
    match pat.split_first() {
        None => txt.is_empty(),
        Some((&'*', rest)) => {
            // `*` matches zero characters (rest against all of txt) or one more
            // character (pat again against txt's tail).
            if match_chars(rest, txt) {
                return true;
            }
            match txt.split_first() {
                Some((_, txt_rest)) => match_chars(pat, txt_rest),
                None => false,
            }
        }
        Some((&'?', rest)) => match txt.split_first() {
            Some((_, txt_rest)) => match_chars(rest, txt_rest),
            None => false,
        },
        Some((&pc, rest)) => match txt.split_first() {
            Some((&tc, txt_rest)) if tc == pc => match_chars(rest, txt_rest),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    fn fs() -> MemFs {
        MemFs::new()
            .with_text_file("/root/a.txt", "1")
            .with_text_file("/root/b.log", "2")
            .with_text_file("/root/sub/c.txt", "3")
            .with_text_file("/root/sub/deep/d.txt", "4")
            .with_symlink("/root/link", "/root/a.txt")
    }

    #[test]
    fn glob_matches_star_and_question() {
        assert!(glob_match("*.txt", "a.txt"));
        assert!(!glob_match("*.txt", "a.log"));
        assert!(glob_match("?.txt", "a.txt"));
        assert!(!glob_match("?.txt", "ab.txt"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*c", "abbbc"));
    }

    #[test]
    fn glob_literal_and_empty() {
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn finds_all_entries_by_default() {
        let out = find(&fs(), "/root", &FindOptions::default()).unwrap();
        assert_eq!(
            out,
            [
                "/root",
                "/root/a.txt",
                "/root/b.log",
                "/root/link",
                "/root/sub",
                "/root/sub/c.txt",
                "/root/sub/deep",
                "/root/sub/deep/d.txt",
            ]
        );
    }

    #[test]
    fn name_glob_filters_by_basename() {
        let opts = FindOptions {
            name: Some("*.txt".to_string()),
            ..FindOptions::default()
        };
        let out = find(&fs(), "/root", &opts).unwrap();
        assert_eq!(
            out,
            ["/root/a.txt", "/root/sub/c.txt", "/root/sub/deep/d.txt",]
        );
    }

    #[test]
    fn type_file_excludes_dirs_and_links() {
        let opts = FindOptions {
            type_filter: Some(FindType::File),
            ..FindOptions::default()
        };
        let out = find(&fs(), "/root", &opts).unwrap();
        assert_eq!(
            out,
            [
                "/root/a.txt",
                "/root/b.log",
                "/root/sub/c.txt",
                "/root/sub/deep/d.txt",
            ]
        );
    }

    #[test]
    fn type_dir_selects_directories() {
        let opts = FindOptions {
            type_filter: Some(FindType::Dir),
            ..FindOptions::default()
        };
        let out = find(&fs(), "/root", &opts).unwrap();
        assert_eq!(out, ["/root", "/root/sub", "/root/sub/deep"]);
    }

    #[test]
    fn type_symlink_selects_links_only() {
        let opts = FindOptions {
            type_filter: Some(FindType::Symlink),
            ..FindOptions::default()
        };
        let out = find(&fs(), "/root", &opts).unwrap();
        assert_eq!(out, ["/root/link"]);
    }

    #[test]
    fn maxdepth_zero_yields_only_start() {
        let opts = FindOptions {
            max_depth: 0,
            ..FindOptions::default()
        };
        let out = find(&fs(), "/root", &opts).unwrap();
        assert_eq!(out, ["/root"]);
    }

    #[test]
    fn maxdepth_one_lists_direct_children_only() {
        let opts = FindOptions {
            max_depth: 1,
            ..FindOptions::default()
        };
        let out = find(&fs(), "/root", &opts).unwrap();
        assert_eq!(
            out,
            [
                "/root",
                "/root/a.txt",
                "/root/b.log",
                "/root/link",
                "/root/sub"
            ]
        );
    }

    #[test]
    fn combined_name_and_type_predicates() {
        let opts = FindOptions {
            name: Some("*.txt".to_string()),
            type_filter: Some(FindType::File),
            max_depth: 1,
        };
        let out = find(&fs(), "/root", &opts).unwrap();
        assert_eq!(out, ["/root/a.txt"]);
    }

    #[test]
    fn symlink_is_not_descended() {
        // A symlink whose target is a directory is still a leaf: nothing under
        // the target appears via the link path.
        let fs = MemFs::new()
            .with_text_file("/d/inside.txt", "x")
            .with_symlink("/start/link", "/d");
        let out = find(&fs, "/start", &FindOptions::default()).unwrap();
        assert_eq!(out, ["/start", "/start/link"]);
    }

    #[test]
    fn find_on_file_yields_the_file() {
        let out = find(&fs(), "/root/a.txt", &FindOptions::default()).unwrap();
        assert_eq!(out, ["/root/a.txt"]);
    }

    #[test]
    fn find_missing_root_is_not_found() {
        assert_eq!(
            find(&fs(), "/nope", &FindOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn find_relative_root_is_invalid_path() {
        assert_eq!(
            find(&fs(), "root", &FindOptions::default()),
            Err(FsError::InvalidPath)
        );
    }
}

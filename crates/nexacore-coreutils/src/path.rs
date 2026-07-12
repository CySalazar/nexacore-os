//! Pure path-string logic for the filesystem utilities (WS8-10.1).
//!
//! NexaCore's filesystem seam speaks in **absolute, normalized** path strings.
//! This module provides the string arithmetic the shell-style utilities need —
//! joining a relative target onto a base, collapsing `.`/`..`, and splitting a
//! path into its parent and final component — without pulling in `std::path`
//! (which is unavailable in `no_std`) and without any integer division.
//!
//! ## Rules
//!
//! - A path is **absolute** iff it begins with `/`.
//! - Normalization drops empty components and `.`, and resolves `..` by popping
//!   the previous component. `..` at the root is **clamped** to the root (the
//!   root's parent is itself), exactly as a real filesystem behaves — there is
//!   no way to escape above `/`.
//! - The canonical root is the single string `"/"`.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Returns `true` if `path` is absolute (begins with `/`).
#[must_use]
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// Normalize an **absolute** path, collapsing `.`/`..` and redundant slashes.
///
/// The input is treated as absolute regardless of a leading slash; callers that
/// need to reject relative input should gate on [`is_absolute`] first. `..` at
/// the root is clamped to the root. The result is always canonical: it begins
/// with `/`, has no `.`/`..`/empty components, and has no trailing slash (except
/// the root itself, which is `"/"`).
#[must_use]
pub fn normalize(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let mut out = String::from("/");
    let mut first = true;
    for comp in stack {
        if first {
            first = false;
        } else {
            out.push('/');
        }
        out.push_str(comp);
    }
    out
}

/// Join `rel` onto the absolute base directory `base`, returning a normalized
/// absolute path.
///
/// If `rel` is itself absolute it replaces `base` entirely (matching how a shell
/// resolves an absolute argument); otherwise it is appended to `base`. Either
/// way the result is normalized.
#[must_use]
pub fn join(base: &str, rel: &str) -> String {
    if is_absolute(rel) {
        return normalize(rel);
    }
    let mut combined = String::from(base);
    combined.push('/');
    combined.push_str(rel);
    normalize(&combined)
}

/// The normalized parent directory of `path`, or `None` for the root.
///
/// `path` is normalized first, so `parent("/a/b/..")` is `Some("/")`.
#[must_use]
pub fn parent(path: &str) -> Option<String> {
    let norm = normalize(path);
    if norm == "/" {
        return None;
    }
    match norm.rsplit_once('/') {
        Some(("", _)) | None => Some(String::from("/")),
        Some((head, _)) => Some(head.to_string()),
    }
}

/// The final component (file/directory name) of `path`, or `None` for the root.
///
/// `path` is normalized first, so `file_name("/a/b/")` is `Some("b")`.
#[must_use]
pub fn file_name(path: &str) -> Option<String> {
    let norm = normalize(path);
    if norm == "/" {
        return None;
    }
    norm.rsplit('/').next().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_detection() {
        assert!(is_absolute("/a"));
        assert!(!is_absolute("a/b"));
        assert!(!is_absolute(""));
    }

    #[test]
    fn normalize_collapses_dot_and_slashes() {
        assert_eq!(normalize("/a/./b//c"), "/a/b/c");
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("///"), "/");
    }

    #[test]
    fn normalize_resolves_dotdot() {
        assert_eq!(normalize("/a/b/../c"), "/a/c");
        assert_eq!(normalize("/a/../.."), "/");
    }

    #[test]
    fn dotdot_clamps_at_root() {
        assert_eq!(normalize("/../../x"), "/x");
    }

    #[test]
    fn join_relative_and_absolute() {
        assert_eq!(join("/home/user", "docs"), "/home/user/docs");
        assert_eq!(join("/home/user", "../root"), "/home/root");
        assert_eq!(join("/home/user", "/etc"), "/etc");
        assert_eq!(join("/home/user", "."), "/home/user");
    }

    #[test]
    fn parent_of_paths() {
        assert_eq!(parent("/a/b/c"), Some(String::from("/a/b")));
        assert_eq!(parent("/a"), Some(String::from("/")));
        assert_eq!(parent("/"), None);
    }

    #[test]
    fn file_name_of_paths() {
        assert_eq!(file_name("/a/b/c"), Some(String::from("c")));
        assert_eq!(file_name("/a/b/"), Some(String::from("b")));
        assert_eq!(file_name("/"), None);
    }
}

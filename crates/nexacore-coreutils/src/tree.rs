//! `tree` — recursive indented directory listing over the seam (WS8-10.2).
//!
//! Walks a directory subtree through the [`FileSystem`] and returns one line per
//! entry, indented by depth. A **depth guard** ([`TreeOptions::max_depth`]) caps
//! recursion so a pathological or cyclic layout can never spin forever; symlinks
//! are shown as leaves and never followed, which also prevents link cycles.

use alloc::{string::String, vec::Vec};

use crate::{
    fs::{FileKind, FileSystem, FsError},
    path,
};

/// The default recursion cap for [`tree`] when a caller does not set one.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Options controlling [`tree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeOptions {
    /// Maximum depth to descend below the root (the root is depth 0). Entries
    /// deeper than this are not listed. Guards against runaway recursion.
    pub max_depth: usize,
    /// Include entries whose name begins with `.` (like `ls -a`).
    pub all: bool,
}

impl Default for TreeOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            all: false,
        }
    }
}

/// Build an indented listing of the subtree rooted at `path`.
///
/// The first line is `path` itself (normalized); each descendant is indented two
/// spaces per level. Directories are suffixed with `/`, symlinks with `@`.
///
/// # Errors
///
/// [`FsError::NotADirectory`] if `path` is not a directory, plus any seam error
/// while reading it.
pub fn tree<F: FileSystem>(fs: &F, path: &str, opts: &TreeOptions) -> Result<Vec<String>, FsError> {
    let meta = fs.metadata(path)?;
    if meta.kind != FileKind::Dir {
        return Err(FsError::NotADirectory);
    }
    let mut lines: Vec<String> = Vec::new();
    lines.push(path::normalize(path));
    walk(fs, path, 1, opts, &mut lines)?;
    Ok(lines)
}

/// Recursive worker: list the children of `dir` at indentation `depth`.
fn walk<F: FileSystem>(
    fs: &F,
    dir: &str,
    depth: usize,
    opts: &TreeOptions,
    lines: &mut Vec<String>,
) -> Result<(), FsError> {
    if depth > opts.max_depth {
        return Ok(());
    }
    let mut entries = fs.read_dir(dir)?;
    if !opts.all {
        entries.retain(|e| !e.name.starts_with('.'));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    for entry in entries {
        lines.push(indented(depth, &entry.name, entry.metadata.kind));
        if entry.metadata.kind == FileKind::Dir {
            let child = path::join(dir, &entry.name);
            walk(fs, &child, depth.saturating_add(1), opts, lines)?;
        }
    }
    Ok(())
}

/// Format one indented entry line: `<2*depth spaces><name><suffix>`.
fn indented(depth: usize, name: &str, kind: FileKind) -> String {
    let mut line = String::new();
    let mut pad = depth;
    while pad > 0 {
        line.push_str("  ");
        pad -= 1;
    }
    line.push_str(name);
    match kind {
        FileKind::Dir => line.push('/'),
        FileKind::Symlink => line.push('@'),
        FileKind::File => {}
    }
    line
}

/// Convenience: join a [`tree`] result into a single newline-terminated string.
///
/// # Errors
///
/// Propagates any [`FsError`] from [`tree`].
pub fn tree_string<F: FileSystem>(
    fs: &F,
    path: &str,
    opts: &TreeOptions,
) -> Result<String, FsError> {
    let lines = tree(fs, path, opts)?;
    let mut out = String::new();
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// The full path components below `root` for an entry `name` — helper for
/// callers extending the walk. Mirrors [`crate::path::join`].
#[must_use]
pub fn child_path(dir: &str, name: &str) -> String {
    path::join(dir, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::MemFs;

    fn fs() -> MemFs {
        MemFs::new()
            .with_text_file("/root/a.txt", "1")
            .with_text_file("/root/sub/b.txt", "2")
            .with_text_file("/root/sub/deep/c.txt", "3")
            .with_text_file("/root/.hidden", "h")
            .with_symlink("/root/link", "/root/a.txt")
    }

    #[test]
    fn lists_indented_subtree() {
        let out = tree(&fs(), "/root", &TreeOptions::default()).unwrap();
        assert_eq!(
            out,
            [
                "/root",
                "  a.txt",
                "  link@",
                "  sub/",
                "    b.txt",
                "    deep/",
                "      c.txt",
            ]
        );
    }

    #[test]
    fn all_includes_dotfiles() {
        let opts = TreeOptions {
            all: true,
            ..TreeOptions::default()
        };
        let out = tree(&fs(), "/root", &opts).unwrap();
        assert_eq!(out.get(1).map(String::as_str), Some("  .hidden"));
    }

    #[test]
    fn depth_guard_limits_recursion() {
        let opts = TreeOptions {
            max_depth: 1,
            all: false,
        };
        let out = tree(&fs(), "/root", &opts).unwrap();
        // Depth 1 lists /root's direct children but does not descend into `sub`.
        assert_eq!(out, ["/root", "  a.txt", "  link@", "  sub/"]);
    }

    #[test]
    fn depth_zero_lists_only_root() {
        let opts = TreeOptions {
            max_depth: 0,
            all: false,
        };
        let out = tree(&fs(), "/root", &opts).unwrap();
        assert_eq!(out, ["/root"]);
    }

    #[test]
    fn tree_on_file_errors() {
        assert_eq!(
            tree(&fs(), "/root/a.txt", &TreeOptions::default()),
            Err(FsError::NotADirectory)
        );
    }

    #[test]
    fn tree_missing_errors() {
        assert_eq!(
            tree(&fs(), "/nope", &TreeOptions::default()),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn tree_string_joins_with_newlines() {
        let s = tree_string(
            &fs(),
            "/root",
            &TreeOptions {
                max_depth: 1,
                all: false,
            },
        )
        .unwrap();
        assert_eq!(s, "/root\n  a.txt\n  link@\n  sub/\n");
    }

    #[test]
    fn child_path_helper() {
        assert_eq!(child_path("/root", "sub"), "/root/sub");
    }
}

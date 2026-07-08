//! Filesystem information commands: df, find.
//!
//! `find` is fully functional, performing a recursive directory walk using
//! the [`crate::glob::FsQuery::list_dir`] interface. Optional `-name` filtering
//! uses the glob engine from [`crate::glob::glob_match`].
//!
//! `df` is a Phase 1 stub that prints a static representative output. Full
//! disk-usage data requires the kernel VFS mount table, which is not yet
//! exposed.

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

use crate::executor::{BuiltinFn, ExecContext};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Register all filesystem-information commands into `map`.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{commands::fs_info, executor::BuiltinFn};
///
/// let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
/// fs_info::register(&mut map);
/// assert!(map.contains_key("df"));
/// assert!(map.contains_key("find"));
/// ```
pub fn register(map: &mut BTreeMap<String, BuiltinFn>) {
    map.insert("df".into(), cmd_df as BuiltinFn);
    map.insert("find".into(), cmd_find as BuiltinFn);
}

// ── df ────────────────────────────────────────────────────────────────────────

/// Report filesystem disk-space usage (Phase 1 stub).
///
/// Prints a static representative output. Full disk-usage data requires the
/// kernel VFS mount table. Returns exit code `0`.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{env::ShellEnv, executor::ExecContext, glob::FsQuery};
///
/// struct NoFs;
/// impl FsQuery for NoFs {
///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
///         Ok(vec![])
///     }
/// }
///
/// let mut env = ShellEnv::new();
/// let fs = NoFs;
/// let mut ctx = ExecContext {
///     env: &mut env,
///     last_exit_code: 0,
///     cwd: "/".into(),
///     fs: &fs,
///     net: &nexacore_shell::netquery::NoNet,
///     output: Vec::new(),
///     audit_log: nexacore_shell::audit::AuditLog::new(),
/// };
/// let code = nexacore_shell::commands::fs_info::cmd_df_pub(&["df".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("Filesystem"));
/// ```
pub fn cmd_df_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_df(args, ctx)
}

fn cmd_df(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    ctx.output.extend_from_slice(
        b"Filesystem     Size  Used  Avail  Use%  Mounted on\n\
          nexacore-fs        N/A   N/A   N/A    N/A   /\n",
    );
    0
}

// ── find ──────────────────────────────────────────────────────────────────────

/// Walk a directory tree and print matching entries.
///
/// # Arguments
///
/// - `[path]` — root of the search tree (defaults to the current working
///   directory when omitted).
/// - `-name <pattern>` — filter entries by [`crate::glob::glob_match`] against
///   the base name. Patterns follow the NexaCore shell glob syntax.
/// - `-type f|d` — accepted but not yet implemented; silently consumed so that
///   scripts using this flag do not error.
///
/// Output is one absolute path per line. Entries that cannot be recursed
/// (i.e. leaf files) are silently skipped. Returns exit code `0`.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{env::ShellEnv, executor::ExecContext, glob::FsQuery};
///
/// struct TreeFs;
/// impl FsQuery for TreeFs {
///     fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
///         match path {
///             "/" => Ok(vec!["bin".into()]),
///             "/bin" => Ok(vec!["ls".into()]),
///             _ => Ok(vec![]),
///         }
///     }
/// }
///
/// let mut env = ShellEnv::new();
/// let fs = TreeFs;
/// let mut ctx = ExecContext {
///     env: &mut env,
///     last_exit_code: 0,
///     cwd: "/".into(),
///     fs: &fs,
///     net: &nexacore_shell::netquery::NoNet,
///     output: Vec::new(),
///     audit_log: nexacore_shell::audit::AuditLog::new(),
/// };
/// let code = nexacore_shell::commands::fs_info::cmd_find_pub(&["find".into(), "/".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("/bin"));
/// assert!(out.contains("/bin/ls"));
/// ```
pub fn cmd_find_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_find(args, ctx)
}

fn cmd_find(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    // Parse arguments: find [path] [-name pattern] [-type f|d]
    let mut path = ctx.cwd.clone();
    let mut name_pattern: Option<String> = None;
    let mut i = 1usize;

    while i < args.len() {
        // Use get() to avoid indexing_slicing lint; bounds are guaranteed by
        // the while condition (i < args.len()) and the guard (i + 1 < args.len()).
        let current = match args.get(i) {
            Some(s) => s.as_str(),
            None => break,
        };
        match current {
            "-name" if i + 1 < args.len() => {
                // SAFETY of get(): i + 1 < args.len() checked in match guard.
                name_pattern = args.get(i + 1).cloned();
                i += 2;
            }
            // -type is accepted but not yet used; consume both tokens.
            "-type" if i + 1 < args.len() => {
                i += 2;
            }
            _ => {
                if let Some(s) = args.get(i) {
                    path.clone_from(s);
                }
                i += 1;
            }
        }
    }

    walk(&path, ctx, name_pattern.as_deref());
    0
}

/// Recursively walk `dir`, printing entries that satisfy `name_filter`.
///
/// Entries that produce an error from `list_dir` (e.g. plain files) are
/// silently skipped, which is the correct behaviour for a recursive walk that
/// encounters leaf nodes.
///
/// `name_filter` is applied to the *base name* only (not the full path), using
/// [`crate::glob::glob_match`].
fn walk(dir: &str, ctx: &mut ExecContext<'_>, name_filter: Option<&str>) {
    // let...else: skip this directory silently if list_dir returns an error.
    let Ok(entries) = ctx.fs.list_dir(dir) else {
        return;
    };

    for entry in &entries {
        // Build the full path for this entry.
        let full = if dir == "/" {
            format!("/{entry}")
        } else {
            format!("{dir}/{entry}")
        };

        // Apply optional name filter against the base name.
        let matches = name_filter.is_none_or(|pat| crate::glob::glob_match(pat, entry));

        if matches {
            ctx.output.extend_from_slice(format!("{full}\n").as_bytes());
        }

        // Recurse unconditionally; errors in sub-directories are silently ignored.
        walk(&full, ctx, name_filter);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env::ShellEnv, glob::FsQuery, netquery::NoNet};

    /// A two-level tree: / → {bin, etc}; /bin → {ls, cat}; others → empty.
    struct TestFs;
    impl FsQuery for TestFs {
        fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
            match path {
                "/" => Ok(vec!["bin".into(), "etc".into()]),
                "/bin" => Ok(vec!["ls".into(), "cat".into()]),
                _ => Ok(vec![]),
            }
        }
    }

    fn make_ctx(env: &mut ShellEnv) -> ExecContext<'_> {
        ExecContext {
            env,
            last_exit_code: 0,
            cwd: "/".to_string(),
            fs: &TestFs,
            net: &NoNet,
            output: Vec::new(),
            audit_log: crate::audit::AuditLog::new(),
        }
    }

    fn out(ctx: &ExecContext<'_>) -> String {
        String::from_utf8_lossy(&ctx.output).into_owned()
    }

    // ── register ──────────────────────────────────────────────────────────

    #[test]
    fn register_adds_two_commands() {
        let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
        register(&mut map);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn register_adds_df_and_find() {
        let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
        register(&mut map);
        assert!(map.contains_key("df"), "missing df");
        assert!(map.contains_key("find"), "missing find");
    }

    // ── df ────────────────────────────────────────────────────────────────

    #[test]
    fn df_prints_header() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_df(&["df".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("Filesystem"), "output: {}", out(&ctx));
    }

    #[test]
    fn df_prints_nexacore_fs_entry() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        cmd_df(&["df".into()], &mut ctx);
        assert!(out(&ctx).contains("nexacore-fs"), "output: {}", out(&ctx));
    }

    // ── find ──────────────────────────────────────────────────────────────

    #[test]
    fn find_walks_tree() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_find(&["find".into(), "/".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("/bin"), "output: {o}");
        assert!(o.contains("/bin/ls"), "output: {o}");
        assert!(o.contains("/etc"), "output: {o}");
    }

    #[test]
    fn find_name_filter_exact() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        cmd_find(
            &["find".into(), "/".into(), "-name".into(), "ls".into()],
            &mut ctx,
        );
        let o = out(&ctx);
        assert!(o.contains("/bin/ls"), "output: {o}");
        assert!(!o.contains("/bin/cat"), "output: {o}");
    }

    #[test]
    fn find_name_filter_glob() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        cmd_find(
            &["find".into(), "/".into(), "-name".into(), "*at*".into()],
            &mut ctx,
        );
        let o = out(&ctx);
        assert!(o.contains("/bin/cat"), "output: {o}");
        assert!(!o.contains("/bin/ls"), "output: {o}");
    }

    #[test]
    fn find_type_flag_is_accepted_without_error() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_find(
            &["find".into(), "/".into(), "-type".into(), "f".into()],
            &mut ctx,
        );
        // -type is accepted; exit code must be 0.
        assert_eq!(code, 0);
    }

    #[test]
    fn find_default_path_uses_cwd() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        ctx.cwd = "/bin".to_string();
        // No explicit path: should walk /bin.
        cmd_find(&["find".into()], &mut ctx);
        let o = out(&ctx);
        assert!(
            o.contains("/bin/ls") || o.contains("/bin/cat"),
            "output: {o}"
        );
    }
}

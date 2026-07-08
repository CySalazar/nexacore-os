//! Filesystem commands: ls, cat, cp, mv, rm, mkdir, touch.
//!
//! `ls` and `mkdir` are fully functional using the [`crate::glob::FsQuery`]
//! interface. The remaining commands (`cat`, `cp`, `mv`, `rm`, `touch`) require
//! kernel-level filesystem write or read access that is not yet wired into the
//! [`crate::glob::FsQuery`] trait. These are implemented as informational stubs
//! that return exit code `0` and print a clear explanation.
//!
//! ## Stability note
//!
//! When the VFS write/read trait is introduced in Layer 6, the stubs will be
//! replaced with real implementations without changing the command names or
//! signatures visible to callers.

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use crate::executor::{BuiltinFn, ExecContext};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Register all filesystem commands into `map`.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{commands::fs_cmds, executor::BuiltinFn};
///
/// let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
/// fs_cmds::register(&mut map);
/// assert!(map.contains_key("ls"));
/// assert!(map.contains_key("mkdir"));
/// assert!(map.contains_key("cat"));
/// ```
pub fn register(map: &mut BTreeMap<String, BuiltinFn>) {
    map.insert("ls".into(), cmd_ls as BuiltinFn);
    map.insert("cat".into(), cmd_cat as BuiltinFn);
    map.insert("cp".into(), cmd_cp as BuiltinFn);
    map.insert("mv".into(), cmd_mv as BuiltinFn);
    map.insert("rm".into(), cmd_rm as BuiltinFn);
    map.insert("mkdir".into(), cmd_mkdir as BuiltinFn);
    map.insert("touch".into(), cmd_touch as BuiltinFn);
}

// ── ls ────────────────────────────────────────────────────────────────────────

/// List directory contents.
///
/// # Flags
///
/// - `-a` — include hidden entries (names beginning with `.`).
/// - `-l` — long format: one entry per line instead of space-separated.
/// - `-la` or `-al` — combined long + all.
///
/// # Behaviour
///
/// - With no path argument the current working directory is listed.
/// - Multiple path arguments are listed sequentially.
/// - On error (non-existent path, permission denied) an error message is
///   written and exit code `1` is returned.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{
///     commands::fs_cmds,
///     env::ShellEnv,
///     executor::{BuiltinFn, ExecContext},
///     glob::FsQuery,
/// };
///
/// struct MockFs;
/// impl FsQuery for MockFs {
///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
///         Ok(vec!["alpha.txt".into(), "beta.txt".into()])
///     }
/// }
///
/// let mut env = ShellEnv::new();
/// let fs = MockFs;
/// let mut ctx = ExecContext {
///     env: &mut env,
///     last_exit_code: 0,
///     cwd: "/home".into(),
///     fs: &fs,
///     net: &nexacore_shell::netquery::NoNet,
///     output: Vec::new(),
///     audit_log: nexacore_shell::audit::AuditLog::new(),
/// };
/// let code = nexacore_shell::commands::fs_cmds::cmd_ls_pub(&["ls".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("alpha.txt"));
/// ```
pub fn cmd_ls_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_ls(args, ctx)
}

/// Internal implementation of `ls`.
fn cmd_ls(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let mut show_all = false;
    let mut long_format = false;
    let mut paths: Vec<String> = Vec::new();

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-a" => show_all = true,
            "-l" => long_format = true,
            "-la" | "-al" => {
                show_all = true;
                long_format = true;
            }
            _ => paths.push(arg.clone()),
        }
    }

    // Default to the current working directory when no path was given.
    if paths.is_empty() {
        paths.push(ctx.cwd.clone());
    }

    let mut exit_code = 0i32;

    for path in &paths {
        match ctx.fs.list_dir(path) {
            Ok(mut entries) => {
                // Sort entries alphabetically for deterministic output.
                entries.sort();

                if long_format {
                    for entry in &entries {
                        // Hidden-file gate: skip unless -a is active.
                        if !show_all && entry.starts_with('.') {
                            continue;
                        }
                        ctx.output
                            .extend_from_slice(format!("{entry}\n").as_bytes());
                    }
                } else {
                    let mut first = true;
                    for entry in &entries {
                        if !show_all && entry.starts_with('.') {
                            continue;
                        }
                        if !first {
                            ctx.output.extend_from_slice(b"  ");
                        }
                        ctx.output.extend_from_slice(entry.as_bytes());
                        first = false;
                    }
                    // Trailing newline after the space-separated list.
                    if !first {
                        ctx.output.push(b'\n');
                    }
                }
            }
            Err(e) => {
                ctx.output
                    .extend_from_slice(format!("ls: cannot access '{path}': {e}\n").as_bytes());
                exit_code = 1;
            }
        }
    }

    exit_code
}

// ── cat ───────────────────────────────────────────────────────────────────────

/// Concatenate and print files (Phase 1 stub).
///
/// Requires kernel filesystem read access which is not yet wired into the
/// [`crate::glob::FsQuery`] trait. Prints an informational message and returns
/// exit code `0`.
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
/// let code =
///     nexacore_shell::commands::fs_cmds::cmd_cat_pub(&["cat".into(), "file.txt".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("file read access"));
/// ```
pub fn cmd_cat_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_cat(args, ctx)
}

fn cmd_cat(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub_requires_read(args, ctx)
}

// ── cp ────────────────────────────────────────────────────────────────────────

/// Copy files or directories (Phase 1 stub).
///
/// Requires kernel filesystem write access. Prints an informational message
/// and returns exit code `0`.
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
/// let code = nexacore_shell::commands::fs_cmds::cmd_cp_pub(
///     &["cp".into(), "src".into(), "dst".into()],
///     &mut ctx,
/// );
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("filesystem write access"));
/// ```
pub fn cmd_cp_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_cp(args, ctx)
}

fn cmd_cp(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub_requires_write(args, ctx)
}

// ── mv ────────────────────────────────────────────────────────────────────────

/// Move or rename files (Phase 1 stub).
///
/// Requires kernel filesystem write access. Prints an informational message
/// and returns exit code `0`.
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
/// let code = nexacore_shell::commands::fs_cmds::cmd_mv_pub(
///     &["mv".into(), "old".into(), "new".into()],
///     &mut ctx,
/// );
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("filesystem write access"));
/// ```
pub fn cmd_mv_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_mv(args, ctx)
}

fn cmd_mv(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub_requires_write(args, ctx)
}

// ── rm ────────────────────────────────────────────────────────────────────────

/// Remove files or directories (Phase 1 stub).
///
/// Requires kernel filesystem write access. Prints an informational message
/// and returns exit code `0`.
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
/// let code =
///     nexacore_shell::commands::fs_cmds::cmd_rm_pub(&["rm".into(), "file.txt".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("filesystem write access"));
/// ```
pub fn cmd_rm_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_rm(args, ctx)
}

fn cmd_rm(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub_requires_write(args, ctx)
}

// ── mkdir ─────────────────────────────────────────────────────────────────────

/// Create directories (Phase 1 stub).
///
/// Requires kernel filesystem write access. Prints an informational message
/// and returns exit code `0`.
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
/// let code =
///     nexacore_shell::commands::fs_cmds::cmd_mkdir_pub(&["mkdir".into(), "newdir".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("filesystem write access"));
/// ```
pub fn cmd_mkdir_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_mkdir(args, ctx)
}

fn cmd_mkdir(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub_requires_write(args, ctx)
}

// ── touch ─────────────────────────────────────────────────────────────────────

/// Create or update file timestamps (Phase 1 stub).
///
/// Requires kernel filesystem write access. Prints an informational message
/// and returns exit code `0`.
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
/// let code =
///     nexacore_shell::commands::fs_cmds::cmd_touch_pub(&["touch".into(), "newfile".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("filesystem write access"));
/// ```
pub fn cmd_touch_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_touch(args, ctx)
}

fn cmd_touch(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub_requires_write(args, ctx)
}

// ── Stub helpers ──────────────────────────────────────────────────────────────

/// Emit a stub message indicating that file-read access is not yet available.
///
/// The command name is taken from `args[0]`. Any additional arguments are
/// echoed in the message for clarity. Exit code `0` is returned so that
/// calling scripts do not abort on Phase 1 stubs.
fn stub_requires_read(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let name = args.first().map_or("?", String::as_str);
    let operands = if args.len() > 1 {
        format!(" {}", args.get(1..).unwrap_or_default().join(" "))
    } else {
        String::new()
    };
    ctx.output.extend_from_slice(
        format!("{name}{operands}: requires file read access (not yet available — Phase 2)\n")
            .as_bytes(),
    );
    0
}

/// Emit a stub message indicating that filesystem write access is not yet available.
///
/// The command name is taken from `args[0]`. Any additional arguments are
/// echoed in the message for clarity. Exit code `0` is returned so that
/// calling scripts do not abort on Phase 1 stubs.
fn stub_requires_write(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let name = args.first().map_or("?", String::as_str);
    let operands = if args.len() > 1 {
        format!(" {}", args.get(1..).unwrap_or_default().join(" "))
    } else {
        String::new()
    };
    ctx.output.extend_from_slice(
        format!(
            "{name}{operands}: requires filesystem write access (not yet available — Phase 2)\n"
        )
        .as_bytes(),
    );
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env::ShellEnv, glob::FsQuery, netquery::NoNet};

    // ── Mock filesystem ───────────────────────────────────────────────────

    struct DirFs {
        entries: Vec<String>,
    }

    impl DirFs {
        fn new(entries: &[&str]) -> Self {
            Self {
                entries: entries.iter().map(|s| (*s).to_string()).collect(),
            }
        }
    }

    impl FsQuery for DirFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Ok(self.entries.clone())
        }
    }

    struct ErrorFs;
    impl FsQuery for ErrorFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Err("no such file or directory".to_string())
        }
    }

    struct NoFs;
    impl FsQuery for NoFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
    }

    fn make_ctx<'a>(env: &'a mut ShellEnv, fs: &'a dyn FsQuery) -> ExecContext<'a> {
        ExecContext {
            env,
            last_exit_code: 0,
            cwd: "/home/root".to_string(),
            fs,
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
    fn register_adds_all_fs_commands() {
        let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
        register(&mut map);
        for name in &["ls", "cat", "cp", "mv", "rm", "mkdir", "touch"] {
            assert!(map.contains_key(*name), "missing command: {name}");
        }
    }

    // ── ls ────────────────────────────────────────────────────────────────

    #[test]
    fn ls_lists_entries() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&["alpha.txt", "beta.txt"]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("alpha.txt"), "output: {o}");
        assert!(o.contains("beta.txt"), "output: {o}");
    }

    #[test]
    fn ls_default_hides_hidden_files() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&[".hidden", "visible.txt"]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(!o.contains(".hidden"), "hidden file should not appear: {o}");
        assert!(o.contains("visible.txt"), "output: {o}");
    }

    #[test]
    fn ls_flag_a_shows_hidden_files() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&[".hidden", "visible.txt"]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into(), "-a".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains(".hidden"), "output: {o}");
        assert!(o.contains("visible.txt"), "output: {o}");
    }

    #[test]
    fn ls_flag_l_produces_one_per_line() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&["alpha.txt", "beta.txt"]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into(), "-l".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        // Each entry must appear on its own line.
        let lines: Vec<&str> = o.lines().collect();
        assert!(lines.contains(&"alpha.txt"), "output: {o}");
        assert!(lines.contains(&"beta.txt"), "output: {o}");
    }

    #[test]
    fn ls_flag_la_shows_hidden_in_long_format() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&[".hidden", "visible.txt"]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into(), "-la".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains(".hidden"), "output: {o}");
    }

    #[test]
    fn ls_flag_al_is_alias_for_la() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&[".secret", "readme.md"]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into(), "-al".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains(".secret"), "output: {o}");
    }

    #[test]
    fn ls_explicit_path_argument() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&["main.rs"]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into(), "/src".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("main.rs"), "output: {o}");
    }

    #[test]
    fn ls_nonexistent_path_returns_exit_code_one() {
        let mut env = ShellEnv::new();
        let fs = ErrorFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into(), "/nonexistent".into()], &mut ctx);
        assert_eq!(code, 1);
        let o = out(&ctx);
        assert!(o.contains("ls: cannot access"), "output: {o}");
    }

    #[test]
    fn ls_empty_directory_produces_no_entries() {
        let mut env = ShellEnv::new();
        let fs = DirFs::new(&[]);
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_ls(&["ls".into()], &mut ctx);
        assert_eq!(code, 0);
        // No entries — output is empty (no trailing newline emitted).
        assert!(
            ctx.output.is_empty(),
            "expected empty output, got: {:?}",
            out(&ctx)
        );
    }

    // ── stub commands ─────────────────────────────────────────────────────

    #[test]
    fn cat_prints_read_access_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_cat(&["cat".into(), "notes.txt".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("file read access"), "output: {o}");
    }

    #[test]
    fn cp_prints_write_access_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_cp(&["cp".into(), "src".into(), "dst".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("filesystem write access"), "output: {o}");
    }

    #[test]
    fn mv_prints_write_access_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_mv(&["mv".into(), "old".into(), "new".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("filesystem write access"), "output: {o}");
    }

    #[test]
    fn rm_prints_write_access_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_rm(&["rm".into(), "file.txt".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("filesystem write access"), "output: {o}");
    }

    #[test]
    fn mkdir_prints_write_access_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_mkdir(&["mkdir".into(), "newdir".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("filesystem write access"), "output: {o}");
    }

    #[test]
    fn touch_prints_write_access_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_touch(&["touch".into(), "newfile".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("filesystem write access"), "output: {o}");
    }
}

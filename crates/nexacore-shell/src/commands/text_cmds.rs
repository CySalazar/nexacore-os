//! Text processing commands: grep, head, tail, wc.
//!
//! All four commands require kernel-level file-read access that is not yet
//! wired into the [`crate::glob::FsQuery`] trait. Each is a Phase 1 stub
//! that prints an informational message and returns exit code `0`.
//!
//! When the VFS read interface is introduced in Layer 6 these stubs will be
//! replaced with real implementations without changing command names or
//! registration.

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

use crate::executor::{BuiltinFn, ExecContext};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Register all text-processing commands into `map`.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{commands::text_cmds, executor::BuiltinFn};
///
/// let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
/// text_cmds::register(&mut map);
/// assert!(map.contains_key("grep"));
/// assert!(map.contains_key("head"));
/// assert!(map.contains_key("tail"));
/// assert!(map.contains_key("wc"));
/// ```
pub fn register(map: &mut BTreeMap<String, BuiltinFn>) {
    map.insert("grep".into(), cmd_grep as BuiltinFn);
    map.insert("head".into(), cmd_head as BuiltinFn);
    map.insert("tail".into(), cmd_tail as BuiltinFn);
    map.insert("wc".into(), cmd_wc as BuiltinFn);
}

// ── grep ──────────────────────────────────────────────────────────────────────

/// Search for lines matching a pattern (Phase 1 stub).
///
/// Requires kernel filesystem read access. Prints an informational message
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
///     stdin: Vec::new(),
///     stderr: Vec::new(),
/// };
/// let code = nexacore_shell::commands::text_cmds::cmd_grep_pub(
///     &["grep".into(), "pattern".into(), "file.txt".into()],
///     &mut ctx,
/// );
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("grep"));
/// ```
pub fn cmd_grep_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_grep(args, ctx)
}

fn cmd_grep(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub("grep", args, ctx)
}

// ── head ──────────────────────────────────────────────────────────────────────

/// Print the first lines of a file (Phase 1 stub).
///
/// Requires kernel filesystem read access. Prints an informational message
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
///     stdin: Vec::new(),
///     stderr: Vec::new(),
/// };
/// let code = nexacore_shell::commands::text_cmds::cmd_head_pub(
///     &["head".into(), "file.txt".into()],
///     &mut ctx,
/// );
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("head"));
/// ```
pub fn cmd_head_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_head(args, ctx)
}

fn cmd_head(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub("head", args, ctx)
}

// ── tail ──────────────────────────────────────────────────────────────────────

/// Print the last lines of a file (Phase 1 stub).
///
/// Requires kernel filesystem read access. Prints an informational message
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
///     stdin: Vec::new(),
///     stderr: Vec::new(),
/// };
/// let code = nexacore_shell::commands::text_cmds::cmd_tail_pub(
///     &["tail".into(), "file.txt".into()],
///     &mut ctx,
/// );
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("tail"));
/// ```
pub fn cmd_tail_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_tail(args, ctx)
}

fn cmd_tail(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub("tail", args, ctx)
}

// ── wc ────────────────────────────────────────────────────────────────────────

/// Count lines, words, and bytes in files (Phase 1 stub).
///
/// Requires kernel filesystem read access. Prints an informational message
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
///     stdin: Vec::new(),
///     stderr: Vec::new(),
/// };
/// let code = nexacore_shell::commands::text_cmds::cmd_wc_pub(
///     &["wc".into(), "file.txt".into()],
///     &mut ctx,
/// );
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("wc"));
/// ```
pub fn cmd_wc_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_wc(args, ctx)
}

fn cmd_wc(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    stub("wc", args, ctx)
}

// ── Stub helper ───────────────────────────────────────────────────────────────

/// Emit a stub message for a command that requires kernel filesystem access.
///
/// Formats: `<name>[ <args...>]: (requires kernel filesystem access)`.
/// Returns exit code `0`.
fn stub(name: &str, args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    ctx.output.extend_from_slice(format!("{name}: ").as_bytes());
    if args.len() > 1 {
        ctx.output
            .extend_from_slice(args.get(1..).unwrap_or_default().join(" ").as_bytes());
        ctx.output.push(b' ');
    }
    ctx.output
        .extend_from_slice(b"(requires kernel filesystem access)\n");
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env::ShellEnv, glob::FsQuery, netquery::NoNet};

    struct NoFs;
    impl FsQuery for NoFs {
        fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
    }

    fn make_ctx<'a>(env: &'a mut ShellEnv, fs: &'a dyn FsQuery) -> ExecContext<'a> {
        ExecContext {
            env,
            last_exit_code: 0,
            cwd: "/".to_string(),
            fs,
            net: &NoNet,
            output: Vec::new(),
            audit_log: crate::audit::AuditLog::new(),
            stdin: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn out(ctx: &ExecContext<'_>) -> String {
        String::from_utf8_lossy(&ctx.output).into_owned()
    }

    // ── register ──────────────────────────────────────────────────────────

    #[test]
    fn register_adds_four_commands() {
        let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
        register(&mut map);
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn register_adds_all_text_commands() {
        let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
        register(&mut map);
        for name in &["grep", "head", "tail", "wc"] {
            assert!(map.contains_key(*name), "missing command: {name}");
        }
    }

    // ── grep ──────────────────────────────────────────────────────────────

    #[test]
    fn grep_prints_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_grep(&["grep".into(), "pat".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("grep"), "output: {}", out(&ctx));
    }

    #[test]
    fn grep_returns_zero_and_includes_arg() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_grep(
            &["grep".into(), "pattern".into(), "file.txt".into()],
            &mut ctx,
        );
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("pattern"), "output: {}", out(&ctx));
    }

    // ── head ──────────────────────────────────────────────────────────────

    #[test]
    fn head_returns_zero_and_prints_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_head(
            &["head".into(), "-n".into(), "5".into(), "file.txt".into()],
            &mut ctx,
        );
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("head"), "output: {}", out(&ctx));
    }

    // ── tail ──────────────────────────────────────────────────────────────

    #[test]
    fn tail_returns_zero_and_prints_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_tail(&["tail".into(), "file.txt".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("tail"), "output: {}", out(&ctx));
    }

    // ── wc ────────────────────────────────────────────────────────────────

    #[test]
    fn wc_returns_zero_and_prints_stub() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let mut ctx = make_ctx(&mut env, &fs);
        let code = cmd_wc(&["wc".into(), "-l".into(), "file.txt".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("wc"), "output: {}", out(&ctx));
    }
}

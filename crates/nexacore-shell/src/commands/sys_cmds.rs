//! System information commands: uname, whoami, hostname, ps, kill.
//!
//! `uname`, `whoami`, and `hostname` are fully functional using environment
//! variables available through [`crate::executor::ExecContext`].
//!
//! `ps` and `kill` are implemented as Phase 1 stubs that print a representative
//! process table header / signal acknowledgement and return exit code `0`.
//! Full kernel process-table integration arrives in Layer 6.

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::executor::{BuiltinFn, ExecContext};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Register all system-information commands into `map`.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{commands::sys_cmds, executor::BuiltinFn};
///
/// let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
/// sys_cmds::register(&mut map);
/// assert!(map.contains_key("uname"));
/// assert!(map.contains_key("whoami"));
/// assert!(map.contains_key("hostname"));
/// assert!(map.contains_key("ps"));
/// assert!(map.contains_key("kill"));
/// ```
pub fn register(map: &mut BTreeMap<String, BuiltinFn>) {
    map.insert("uname".into(), cmd_uname as BuiltinFn);
    map.insert("whoami".into(), cmd_whoami as BuiltinFn);
    map.insert("hostname".into(), cmd_hostname as BuiltinFn);
    map.insert("ps".into(), cmd_ps as BuiltinFn);
    map.insert("kill".into(), cmd_kill as BuiltinFn);
}

// ── uname ─────────────────────────────────────────────────────────────────────

/// Print system information.
///
/// # Flags
///
/// - No flags — print the OS name only (`NexaCore OS`).
/// - `-a` — print all fields: sysname, nodename, release, machine.
/// - `-s` — print the OS name (`NexaCore OS`).
/// - `-n` — print the node name from `$HOSTNAME` (default: `"nexacore"`).
/// - `-r` — print the release version (`0.2.0`).
/// - `-m` — print the machine hardware name (`x86_64`).
///
/// Fields are emitted in POSIX order (s, n, r, m) separated by spaces on a
/// single line terminated by `\n`. Unknown flags are silently ignored,
/// matching GNU `uname` behaviour.
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
/// let code = nexacore_shell::commands::sys_cmds::cmd_uname_pub(&["uname".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.trim() == "NexaCore OS");
/// ```
pub fn cmd_uname_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_uname(args, ctx)
}

fn cmd_uname(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let mut show_all = false;
    // Default: show OS name when called without flags.
    let mut show_sys = args.len() <= 1;
    let mut show_node = false;
    let mut show_rel = false;
    let mut show_mach = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-a" => show_all = true,
            "-s" => show_sys = true,
            "-n" => show_node = true,
            "-r" => show_rel = true,
            "-m" => show_mach = true,
            // Unknown flags are silently ignored.
            _ => {}
        }
    }

    // Collect all fields into owned Strings to avoid simultaneous borrow of ctx
    // (env is borrowed immutably while output needs a mutable borrow).
    let mut parts: Vec<String> = Vec::new();

    if show_all || show_sys {
        parts.push("NexaCore OS".to_string());
    }
    if show_all || show_node {
        // Resolve hostname before we borrow ctx.output mutably.
        let host = ctx.env.get("HOSTNAME").unwrap_or("nexacore").to_string();
        parts.push(host);
    }
    if show_all || show_rel {
        parts.push("0.2.0".to_string());
    }
    if show_all || show_mach {
        parts.push("x86_64".to_string());
    }

    // Safety fallback: unknown flag combination produced no parts.
    if parts.is_empty() {
        parts.push("NexaCore OS".to_string());
    }

    ctx.output.extend_from_slice(parts.join(" ").as_bytes());
    ctx.output.push(b'\n');
    0
}

// ── whoami ────────────────────────────────────────────────────────────────────

/// Print the current user name.
///
/// Reads `$USER` from the environment. Falls back to `"root"` if the variable
/// is not set, which matches the default NexaCore OS root session.
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
/// env.set("USER", "alice");
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
/// let code = nexacore_shell::commands::sys_cmds::cmd_whoami_pub(&["whoami".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert_eq!(out.trim(), "alice");
/// ```
pub fn cmd_whoami_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_whoami(args, ctx)
}

fn cmd_whoami(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    // Resolve to owned String before borrowing output mutably.
    let user = ctx.env.get("USER").unwrap_or("root").to_string();
    ctx.output.extend_from_slice(format!("{user}\n").as_bytes());
    0
}

// ── hostname ──────────────────────────────────────────────────────────────────

/// Print the system hostname.
///
/// Reads `$HOSTNAME` from the environment. Falls back to `"nexacore"` if the
/// variable is not set.
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
/// env.set("HOSTNAME", "mybox");
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
/// let code = nexacore_shell::commands::sys_cmds::cmd_hostname_pub(&["hostname".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert_eq!(out.trim(), "mybox");
/// ```
pub fn cmd_hostname_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_hostname(args, ctx)
}

fn cmd_hostname(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    // Resolve to owned String before borrowing output mutably.
    let host = ctx.env.get("HOSTNAME").unwrap_or("nexacore").to_string();
    ctx.output.extend_from_slice(format!("{host}\n").as_bytes());
    0
}

// ── ps ────────────────────────────────────────────────────────────────────────

/// List running processes (Phase 1 stub).
///
/// Prints a minimal representative process table header and one entry for the
/// current shell session. Full kernel process-table integration arrives in
/// Layer 6. Returns exit code `0`.
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
/// let code = nexacore_shell::commands::sys_cmds::cmd_ps_pub(&["ps".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("PID"));
/// ```
pub fn cmd_ps_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_ps(args, ctx)
}

fn cmd_ps(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    ctx.output
        .extend_from_slice(b"  PID STATE    NAME\n    1 Running  nexacore-shell\n");
    0
}

// ── kill ──────────────────────────────────────────────────────────────────────

/// Send a signal to a process (Phase 1 stub).
///
/// Validates that a PID argument is provided and prints an acknowledgement.
/// Full kernel signal delivery arrives in Layer 6.
///
/// Returns exit code `1` when no PID argument is given, `0` otherwise.
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
/// let code =
///     nexacore_shell::commands::sys_cmds::cmd_kill_pub(&["kill".into(), "1234".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("1234"));
/// ```
pub fn cmd_kill_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_kill(args, ctx)
}

fn cmd_kill(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    // Use get(1) to satisfy the indexing_slicing lint; the early-return guard
    // also enforces the same invariant at runtime.
    let Some(pid) = args.get(1) else {
        ctx.output.extend_from_slice(b"kill: usage: kill <pid>\n");
        return 1;
    };
    ctx.output
        .extend_from_slice(format!("kill: sending signal to {pid}\n").as_bytes());
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

    fn make_ctx(env: &mut ShellEnv) -> ExecContext<'_> {
        ExecContext {
            env,
            last_exit_code: 0,
            cwd: "/".to_string(),
            fs: &NoFs,
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
    fn register_adds_five_commands() {
        let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
        register(&mut map);
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn register_adds_all_sys_commands() {
        let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
        register(&mut map);
        for name in &["uname", "whoami", "hostname", "ps", "kill"] {
            assert!(map.contains_key(*name), "missing command: {name}");
        }
    }

    // ── uname ─────────────────────────────────────────────────────────────

    #[test]
    fn uname_default_prints_nexacore_os() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_uname(&["uname".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("NexaCore OS"), "output: {}", out(&ctx));
    }

    #[test]
    fn uname_s_prints_os_name() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_uname(&["uname".into(), "-s".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("NexaCore OS"), "output: {}", out(&ctx));
    }

    #[test]
    fn uname_r_prints_version() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_uname(&["uname".into(), "-r".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("0.2.0"), "output: {}", out(&ctx));
    }

    #[test]
    fn uname_m_prints_machine() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_uname(&["uname".into(), "-m".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("x86_64"), "output: {}", out(&ctx));
    }

    #[test]
    fn uname_n_prints_hostname_from_env() {
        let mut env = ShellEnv::new();
        env.set("HOSTNAME", "testbox");
        let mut ctx = make_ctx(&mut env);
        let code = cmd_uname(&["uname".into(), "-n".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("testbox"), "output: {}", out(&ctx));
    }

    #[test]
    fn uname_all() {
        let mut env = ShellEnv::new();
        env.set("HOSTNAME", "myhost");
        let mut ctx = make_ctx(&mut env);
        let code = cmd_uname(&["uname".into(), "-a".into()], &mut ctx);
        assert_eq!(code, 0);
        let o = out(&ctx);
        assert!(o.contains("NexaCore OS"), "output: {o}");
        assert!(o.contains("myhost"), "output: {o}");
        assert!(o.contains("0.2.0"), "output: {o}");
        assert!(o.contains("x86_64"), "output: {o}");
    }

    #[test]
    fn uname_output_ends_with_newline() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        cmd_uname(&["uname".into()], &mut ctx);
        assert!(ctx.output.ends_with(b"\n"));
    }

    // ── whoami ────────────────────────────────────────────────────────────

    #[test]
    fn whoami_prints_user() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        // ShellEnv default sets USER=root.
        cmd_whoami(&["whoami".into()], &mut ctx);
        assert!(out(&ctx).contains("root"), "output: {}", out(&ctx));
    }

    #[test]
    fn whoami_prints_custom_user() {
        let mut env = ShellEnv::new();
        env.set("USER", "alice");
        let mut ctx = make_ctx(&mut env);
        cmd_whoami(&["whoami".into()], &mut ctx);
        assert_eq!(out(&ctx).trim(), "alice");
    }

    #[test]
    fn whoami_falls_back_to_root_when_user_unset() {
        let mut env = ShellEnv::new();
        env.unset("USER");
        let mut ctx = make_ctx(&mut env);
        cmd_whoami(&["whoami".into()], &mut ctx);
        assert_eq!(out(&ctx).trim(), "root");
    }

    // ── hostname ──────────────────────────────────────────────────────────

    #[test]
    fn hostname_prints_hostname() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        cmd_hostname(&["hostname".into()], &mut ctx);
        assert!(!ctx.output.is_empty());
    }

    #[test]
    fn hostname_prints_hostname_from_env() {
        let mut env = ShellEnv::new();
        env.set("HOSTNAME", "serverA");
        let mut ctx = make_ctx(&mut env);
        let code = cmd_hostname(&["hostname".into()], &mut ctx);
        assert_eq!(code, 0);
        assert_eq!(out(&ctx).trim(), "serverA");
    }

    #[test]
    fn hostname_falls_back_to_nexacore_when_unset() {
        let mut env = ShellEnv::new();
        env.unset("HOSTNAME");
        let mut ctx = make_ctx(&mut env);
        cmd_hostname(&["hostname".into()], &mut ctx);
        assert_eq!(out(&ctx).trim(), "nexacore");
    }

    // ── ps ────────────────────────────────────────────────────────────────

    #[test]
    fn ps_prints_header() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_ps(&["ps".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(out(&ctx).contains("PID"), "output: {}", out(&ctx));
    }

    #[test]
    fn ps_returns_zero() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        assert_eq!(cmd_ps(&["ps".into()], &mut ctx), 0);
    }

    // ── kill ──────────────────────────────────────────────────────────────

    #[test]
    fn kill_no_arg_returns_error() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_kill(&["kill".into()], &mut ctx);
        assert_eq!(code, 1);
    }

    #[test]
    fn kill_with_pid_returns_zero() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = cmd_kill(&["kill".into(), "1234".into()], &mut ctx);
        assert_eq!(code, 0);
    }

    #[test]
    fn kill_includes_pid_in_output() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        cmd_kill(&["kill".into(), "9999".into()], &mut ctx);
        assert!(out(&ctx).contains("9999"), "output: {}", out(&ctx));
    }
}

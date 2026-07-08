//! Built-in shell commands.
//!
//! Each built-in is a function with the [`crate::executor::BuiltinFn`]
//! signature: it receives the full `argv` slice (including `argv[0]`, the
//! command name) and a mutable [`crate::executor::ExecContext`], and it
//! returns an integer exit code.
//!
//! Built-ins are registered into a [`alloc::collections::BTreeMap`] by
//! [`crate::command::register_builtins`], which is called by the executor before each
//! pipeline run. Using `BTreeMap` ensures deterministic iteration order for
//! commands like `help` and `alias` that print all known names.
//!
//! ## Implemented built-ins
//!
//! | Command   | POSIX-compatible | Notes |
//! |-----------|-----------------|-------|
//! | `cd`      | yes | Supports `cd -` (return to `$OLDPWD`). |
//! | `pwd`     | yes | Prints `$PWD`. |
//! | `echo`    | yes | Supports `-n` flag. |
//! | `exit`    | yes | Accepts optional numeric code. |
//! | `export`  | yes | `export VAR=val` and bare `export VAR`. |
//! | `unset`   | yes | Removes one or more variables. |
//! | `env`     | yes | Lists exported variables. |
//! | `alias`   | yes | Defines or lists aliases. |
//! | `type`    | partial | Identifies builtins; PATH search deferred. |
//! | `history` | no | Placeholder — history lives in `LineEditor`. |
//! | `help`    | no | Prints the built-in command reference. |
//! | `clear`   | no | Emits ANSI clear-screen sequence. |
//! | `source`  | yes | Phase 1 stub — reads and executes a file. |
//! | `true`    | yes | Returns exit code 0. |
//! | `false`   | yes | Returns exit code 1. |

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
};

use crate::executor::{BuiltinFn, ExecContext};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Build and return the complete built-in command registry.
///
/// The returned map associates every built-in name with its handler function.
/// Callers (typically [`crate::executor::execute_pipeline`]) use the map for
/// O(log n) lookup by command name.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::command::register_builtins;
///
/// let builtins = register_builtins();
/// assert!(builtins.contains_key("echo"));
/// assert!(builtins.contains_key("cd"));
/// assert!(builtins.contains_key("true"));
/// assert!(builtins.contains_key("false"));
/// ```
pub fn register_builtins() -> BTreeMap<String, BuiltinFn> {
    let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
    map.insert("cd".into(), builtin_cd as BuiltinFn);
    map.insert("pwd".into(), builtin_pwd as BuiltinFn);
    map.insert("echo".into(), builtin_echo as BuiltinFn);
    map.insert("exit".into(), builtin_exit as BuiltinFn);
    map.insert("export".into(), builtin_export as BuiltinFn);
    map.insert("unset".into(), builtin_unset as BuiltinFn);
    map.insert("env".into(), builtin_env as BuiltinFn);
    map.insert("alias".into(), builtin_alias as BuiltinFn);
    map.insert("type".into(), builtin_type as BuiltinFn);
    map.insert("history".into(), builtin_history as BuiltinFn);
    map.insert("help".into(), builtin_help as BuiltinFn);
    map.insert("clear".into(), builtin_clear as BuiltinFn);
    map.insert("source".into(), builtin_source as BuiltinFn);
    map.insert("true".into(), builtin_true as BuiltinFn);
    map.insert("false".into(), builtin_false as BuiltinFn);
    crate::commands::register_external_commands(&mut map);
    map
}

// ── cd ────────────────────────────────────────────────────────────────────────

/// Change the current working directory.
///
/// Supports:
/// - `cd` with no arguments: navigate to `$HOME`.
/// - `cd -`: return to `$OLDPWD` (the previous directory).
/// - `cd <path>`: navigate to the given path.
///
/// Updates `$OLDPWD` and `$PWD` in the environment on success.
/// Path normalisation (`.`, `..`) is handled by
/// [`crate::glob::normalize_path_simple`].
///
/// Returns exit code `0` on success.
fn builtin_cd(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let target = match args.get(1).map(String::as_str) {
        Some("-") => {
            // `cd -` navigates to the previous directory.
            ctx.env.get("OLDPWD").unwrap_or("/").to_string()
        }
        Some(path) => path.to_string(),
        None => {
            // No argument: go to $HOME.
            ctx.env.get("HOME").unwrap_or("/").to_string()
        }
    };

    let new_cwd = crate::glob::normalize_path_simple(&ctx.cwd, &target);
    // Save and replace cwd in one move to avoid a redundant clone.
    let old_cwd = core::mem::replace(&mut ctx.cwd, new_cwd);
    ctx.env.set("OLDPWD", &old_cwd);
    ctx.env.set("PWD", &ctx.cwd.clone());
    0
}

// ── pwd ───────────────────────────────────────────────────────────────────────

/// Print the current working directory followed by a newline.
///
/// The value is sourced from [`ExecContext::cwd`] (which is kept in sync with
/// `$PWD`).
///
/// Returns exit code `0`.
fn builtin_pwd(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    ctx.output.extend_from_slice(ctx.cwd.as_bytes());
    ctx.output.push(b'\n');
    0
}

// ── echo ──────────────────────────────────────────────────────────────────────

/// Print arguments separated by spaces.
///
/// Supports the `-n` flag (suppress the trailing newline). All other arguments
/// are joined with a single space and written to the output buffer.
///
/// Returns exit code `0`.
fn builtin_echo(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let (no_newline, text_args) = match args.get(1).map(String::as_str) {
        Some("-n") => (true, args.get(2..).unwrap_or_default()),
        _ => (false, args.get(1..).unwrap_or_default()),
    };
    let text = text_args.join(" ");
    ctx.output.extend_from_slice(text.as_bytes());
    if !no_newline {
        ctx.output.push(b'\n');
    }
    0
}

// ── exit ──────────────────────────────────────────────────────────────────────

/// Signal the shell to exit.
///
/// Accepts an optional numeric exit code; if omitted or unparseable, code `0`
/// is used. In Phase 1 the REPL checks for this return code and terminates the
/// loop.
///
/// Returns the requested exit code.
fn builtin_exit(args: &[String], _ctx: &mut ExecContext<'_>) -> i32 {
    args.get(1).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0)
}

// ── export ────────────────────────────────────────────────────────────────────

/// Mark one or more variables as exported, optionally assigning values.
///
/// Usage:
/// - `export` (no args): print all exported variables in `export VAR="val"`
///   format.
/// - `export VAR=value`: set and export `VAR`.
/// - `export VAR`: mark an existing (or new empty) variable as exported.
///
/// Returns exit code `0`.
fn builtin_export(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    if args.len() <= 1 {
        // No arguments: list all exported variables.
        for (k, v) in ctx.env.exported_pairs() {
            ctx.output
                .extend_from_slice(format!("export {k}=\"{v}\"\n").as_bytes());
        }
        return 0;
    }
    for arg in args.iter().skip(1) {
        if let Some(eq) = arg.find('=') {
            let name = &arg[..eq];
            let val = &arg[eq + 1..];
            ctx.env.set(name, val);
            ctx.env.export(name);
        } else {
            // No `=`: export an existing or new-empty variable.
            ctx.env.export(arg);
        }
    }
    0
}

// ── unset ─────────────────────────────────────────────────────────────────────

/// Remove one or more shell variables from the environment.
///
/// Each named variable is removed from both the variable store and the export
/// set (if it was exported). Attempting to unset a variable that does not exist
/// is a no-op and does not cause an error.
///
/// Returns exit code `0`.
fn builtin_unset(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    for arg in args.iter().skip(1) {
        ctx.env.unset(arg);
    }
    0
}

// ── env ───────────────────────────────────────────────────────────────────────

/// List all exported environment variables in `KEY=value` format.
///
/// One `KEY=value` pair is printed per line, sorted alphabetically by key.
///
/// Returns exit code `0`.
fn builtin_env(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    for (k, v) in ctx.env.exported_pairs() {
        ctx.output
            .extend_from_slice(format!("{k}={v}\n").as_bytes());
    }
    0
}

// ── alias ─────────────────────────────────────────────────────────────────────

/// Define or list command aliases.
///
/// Usage:
/// - `alias` (no args): print all defined aliases in `alias name='value'`
///   format.
/// - `alias name=value`: define (or overwrite) an alias.
///
/// Returns exit code `0`.
fn builtin_alias(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    if args.len() <= 1 {
        // No arguments: list all aliases.
        for (k, v) in ctx.env.aliases() {
            ctx.output
                .extend_from_slice(format!("alias {k}='{v}'\n").as_bytes());
        }
        return 0;
    }
    for arg in args.iter().skip(1) {
        if let Some(eq) = arg.find('=') {
            ctx.env.set_alias(&arg[..eq], &arg[eq + 1..]);
        }
        // If there is no `=`, this is a query; we could print the alias, but
        // for Phase 1 we silently ignore queries without `=`.
    }
    0
}

// ── type ──────────────────────────────────────────────────────────────────────

/// Identify the type of each named command.
///
/// Checks (in order): built-in registry, then the alias table. PATH search is
/// not yet wired in Phase 1.
///
/// Returns exit code `0` if all names were resolved, `1` if any was not found.
fn builtin_type(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let builtins = register_builtins();
    let mut exit_code = 0i32;

    for name in args.iter().skip(1) {
        if builtins.contains_key(name.as_str()) {
            ctx.output
                .extend_from_slice(format!("{name} is a shell builtin\n").as_bytes());
        } else if let Some(target) = ctx.env.get_alias(name) {
            ctx.output
                .extend_from_slice(format!("{name} is aliased to '{target}'\n").as_bytes());
        } else {
            ctx.output
                .extend_from_slice(format!("{name}: not found\n").as_bytes());
            exit_code = 1;
        }
    }
    exit_code
}

// ── history ───────────────────────────────────────────────────────────────────

/// Print the command history.
///
/// In Phase 1 the history is owned by [`crate::line_editor::LineEditor`] which
/// is not accessible from `ExecContext`. This is a placeholder that prints an
/// informational message.
///
/// Returns exit code `0`.
fn builtin_history(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    ctx.output
        .extend_from_slice(b"(history not available in this context)\n");
    0
}

// ── help ──────────────────────────────────────────────────────────────────────

/// Print a reference card of all built-in commands.
///
/// Returns exit code `0`.
fn builtin_help(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let help_text = "NexaCore Shell built-in commands:\n\
        \n\
        cd [dir]          Change directory (cd - returns to previous dir)\n\
        pwd               Print working directory\n\
        echo [-n] args    Print arguments (suppress newline with -n)\n\
        exit [code]       Exit shell with optional exit code\n\
        export [VAR=val]  Export variable to environment\n\
        unset VAR         Remove variable from environment\n\
        env               List all exported variables\n\
        alias [n=v]       Define or list command aliases\n\
        type cmd          Show type of command (builtin, alias, etc.)\n\
        history           Show command history\n\
        help [cmd]        Show this help text\n\
        clear             Clear the terminal screen\n\
        source file       Execute commands from file\n\
        true              Return success (exit code 0)\n\
        false             Return failure (exit code 1)\n";
    ctx.output.extend_from_slice(help_text.as_bytes());
    0
}

// ── clear ─────────────────────────────────────────────────────────────────────

/// Clear the terminal screen using ANSI escape sequences.
///
/// Emits `ESC[2J` (erase entire display) followed by `ESC[H` (move cursor to
/// the home position). This is the standard VT100/ANSI clear-screen idiom.
///
/// Returns exit code `0`.
fn builtin_clear(_args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    // ESC[2J clears the screen; ESC[H moves cursor to top-left.
    ctx.output.extend_from_slice(b"\x1b[2J\x1b[H");
    0
}

// ── source ────────────────────────────────────────────────────────────────────

/// Execute commands from a file in the current shell environment.
///
/// In Phase 1 this is a stub: it validates that a filename argument is present
/// but does not yet read or execute the file. Full implementation requires
/// access to the filesystem from the shell process.
///
/// Returns exit code `0` on success, `1` if no filename was given.
fn builtin_source(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    if args.len() <= 1 {
        ctx.output
            .extend_from_slice(b"source: filename argument required\n");
        return 1;
    }
    // Phase 1 stub: filename accepted but not executed.
    // Future implementation: open args[1], read lines, call process_line.
    // Using get(1) instead of index to avoid a potential panic on empty slice.
    let _ = args.get(1);
    0
}

// ── true / false ──────────────────────────────────────────────────────────────

/// Return success (exit code `0`).
///
/// Equivalent to the POSIX `true` utility.
fn builtin_true(_args: &[String], _ctx: &mut ExecContext<'_>) -> i32 {
    0
}

/// Return failure (exit code `1`).
///
/// Equivalent to the POSIX `false` utility.
fn builtin_false(_args: &[String], _ctx: &mut ExecContext<'_>) -> i32 {
    1
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env::ShellEnv, glob::FsQuery, netquery::NoNet};

    // ── Mock filesystem (minimal) ─────────────────────────────────────────

    struct NoFs;
    impl FsQuery for NoFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
    }

    // ── Helper ────────────────────────────────────────────────────────────

    fn make_ctx(env: &mut ShellEnv) -> ExecContext<'_> {
        ExecContext {
            env,
            last_exit_code: 0,
            cwd: "/home/root".to_string(),
            fs: &NoFs,
            net: &NoNet,
            output: Vec::new(),
            audit_log: crate::audit::AuditLog::new(),
        }
    }

    fn output_str(ctx: &ExecContext<'_>) -> String {
        String::from_utf8_lossy(&ctx.output).into_owned()
    }

    // ── register_builtins ─────────────────────────────────────────────────

    #[test]
    fn register_builtins_contains_all_expected_names() {
        let map = register_builtins();
        for name in &[
            "cd", "pwd", "echo", "exit", "export", "unset", "env", "alias", "type", "history",
            "help", "clear", "source", "true", "false",
        ] {
            assert!(map.contains_key(*name), "missing builtin: {name}");
        }
    }

    // ── cd ────────────────────────────────────────────────────────────────

    #[test]
    fn cd_changes_cwd() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["cd".into(), "/tmp".into()];
        let code = builtin_cd(&args, &mut ctx);
        assert_eq!(code, 0);
        assert_eq!(ctx.cwd, "/tmp");
        assert_eq!(ctx.env.get("PWD"), Some("/tmp"));
    }

    #[test]
    fn cd_dash_returns_to_oldpwd() {
        let mut env = ShellEnv::new();
        env.set("OLDPWD", "/var");
        let mut ctx = make_ctx(&mut env);
        ctx.cwd = "/home/root".into();
        let args = vec!["cd".into(), "-".into()];
        let code = builtin_cd(&args, &mut ctx);
        assert_eq!(code, 0);
        assert_eq!(ctx.cwd, "/var");
    }

    #[test]
    fn cd_no_arg_goes_to_home() {
        let mut env = ShellEnv::new();
        env.set("HOME", "/home/alice");
        let mut ctx = make_ctx(&mut env);
        let args = vec!["cd".into()];
        builtin_cd(&args, &mut ctx);
        assert_eq!(ctx.cwd, "/home/alice");
    }

    // ── pwd ───────────────────────────────────────────────────────────────

    #[test]
    fn pwd_prints_cwd() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        ctx.cwd = "/etc".into();
        let code = builtin_pwd(&["pwd".into()], &mut ctx);
        assert_eq!(code, 0);
        assert_eq!(output_str(&ctx).trim(), "/etc");
    }

    #[test]
    fn pwd_output_ends_with_newline() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        builtin_pwd(&["pwd".into()], &mut ctx);
        assert!(ctx.output.ends_with(b"\n"));
    }

    // ── echo ──────────────────────────────────────────────────────────────

    #[test]
    fn echo_prints_args_with_newline() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["echo".into(), "hello".into(), "world".into()];
        let code = builtin_echo(&args, &mut ctx);
        assert_eq!(code, 0);
        assert_eq!(output_str(&ctx), "hello world\n");
    }

    #[test]
    fn echo_n_suppresses_newline() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["echo".into(), "-n".into(), "no newline".into()];
        builtin_echo(&args, &mut ctx);
        assert_eq!(output_str(&ctx), "no newline");
        assert!(!ctx.output.ends_with(b"\n"));
    }

    // ── exit ──────────────────────────────────────────────────────────────

    #[test]
    fn exit_returns_given_code() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["exit".into(), "42".into()];
        let code = builtin_exit(&args, &mut ctx);
        assert_eq!(code, 42);
    }

    #[test]
    fn exit_no_arg_returns_zero() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["exit".into()];
        let code = builtin_exit(&args, &mut ctx);
        assert_eq!(code, 0);
    }

    // ── export ────────────────────────────────────────────────────────────

    #[test]
    fn export_sets_and_marks_variable_exported() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["export".into(), "MY_VAR=hello".into()];
        let code = builtin_export(&args, &mut ctx);
        assert_eq!(code, 0);
        assert_eq!(ctx.env.get("MY_VAR"), Some("hello"));
        assert!(ctx.env.is_exported("MY_VAR"));
    }

    #[test]
    fn export_no_arg_lists_exported_vars() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["export".into()];
        builtin_export(&args, &mut ctx);
        let out = output_str(&ctx);
        // Default env has HOME, PATH, USER, PWD all exported.
        assert!(out.contains("export HOME="));
    }

    // ── unset ─────────────────────────────────────────────────────────────

    #[test]
    fn unset_removes_variable() {
        let mut env = ShellEnv::new();
        env.set("TOREMOVE", "val");
        let mut ctx = make_ctx(&mut env);
        let args = vec!["unset".into(), "TOREMOVE".into()];
        let code = builtin_unset(&args, &mut ctx);
        assert_eq!(code, 0);
        assert!(ctx.env.get("TOREMOVE").is_none());
    }

    #[test]
    fn unset_nonexistent_is_noop() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["unset".into(), "DOES_NOT_EXIST".into()];
        let code = builtin_unset(&args, &mut ctx);
        assert_eq!(code, 0);
    }

    // ── env ───────────────────────────────────────────────────────────────

    #[test]
    fn env_lists_exported_variables() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        builtin_env(&["env".into()], &mut ctx);
        let out = output_str(&ctx);
        assert!(out.contains("HOME=/"));
    }

    #[test]
    fn env_does_not_list_unexported_variables() {
        let mut env = ShellEnv::new();
        env.set("SECRET", "hunter2"); // not exported
        let mut ctx = make_ctx(&mut env);
        builtin_env(&["env".into()], &mut ctx);
        let out = output_str(&ctx);
        assert!(!out.contains("SECRET"));
    }

    // ── alias ─────────────────────────────────────────────────────────────

    #[test]
    fn alias_defines_new_alias() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["alias".into(), "ll=ls -la".into()];
        let code = builtin_alias(&args, &mut ctx);
        assert_eq!(code, 0);
        assert_eq!(ctx.env.get_alias("ll"), Some("ls -la"));
    }

    #[test]
    fn alias_no_arg_lists_all_aliases() {
        let mut env = ShellEnv::new();
        env.set_alias("grep", "grep --color=auto");
        let mut ctx = make_ctx(&mut env);
        builtin_alias(&["alias".into()], &mut ctx);
        let out = output_str(&ctx);
        assert!(out.contains("alias grep="));
    }

    // ── type ──────────────────────────────────────────────────────────────

    #[test]
    fn type_identifies_builtin() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["type".into(), "echo".into()];
        let code = builtin_type(&args, &mut ctx);
        assert_eq!(code, 0);
        assert!(output_str(&ctx).contains("builtin"));
    }

    #[test]
    fn type_not_found_returns_one() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["type".into(), "totally_unknown_xyz".into()];
        let code = builtin_type(&args, &mut ctx);
        assert_eq!(code, 1);
        assert!(output_str(&ctx).contains("not found"));
    }

    // ── history ───────────────────────────────────────────────────────────

    #[test]
    fn history_returns_zero() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = builtin_history(&["history".into()], &mut ctx);
        assert_eq!(code, 0);
    }

    #[test]
    fn history_prints_informational_message() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        builtin_history(&["history".into()], &mut ctx);
        // Should print something (not silently empty).
        assert!(!ctx.output.is_empty());
    }

    // ── help ──────────────────────────────────────────────────────────────

    #[test]
    fn help_prints_non_empty_text() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = builtin_help(&["help".into()], &mut ctx);
        assert_eq!(code, 0);
        assert!(!ctx.output.is_empty());
    }

    #[test]
    fn help_text_contains_key_commands() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        builtin_help(&["help".into()], &mut ctx);
        let out = output_str(&ctx);
        assert!(out.contains("echo"));
        assert!(out.contains("export"));
        assert!(out.contains("cd"));
    }

    // ── clear ─────────────────────────────────────────────────────────────

    #[test]
    fn clear_emits_ansi_escape() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let code = builtin_clear(&["clear".into()], &mut ctx);
        assert_eq!(code, 0);
        // Output must start with ESC (0x1b).
        assert_eq!(ctx.output[0], 0x1b);
    }

    #[test]
    fn clear_contains_erase_sequence() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        builtin_clear(&["clear".into()], &mut ctx);
        let out = output_str(&ctx);
        // Must contain the erase-display sequence.
        assert!(out.contains("\x1b[2J"), "missing ESC[2J in: {out:?}");
    }

    // ── source ────────────────────────────────────────────────────────────

    #[test]
    fn source_no_arg_returns_one() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["source".into()];
        let code = builtin_source(&args, &mut ctx);
        assert_eq!(code, 1);
    }

    #[test]
    fn source_with_filename_returns_zero() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        let args = vec!["source".into(), "/etc/profile".into()];
        let code = builtin_source(&args, &mut ctx);
        assert_eq!(code, 0);
    }

    // ── true / false ──────────────────────────────────────────────────────

    #[test]
    fn true_returns_zero() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        assert_eq!(builtin_true(&["true".into()], &mut ctx), 0);
    }

    #[test]
    fn false_returns_one() {
        let mut env = ShellEnv::new();
        let mut ctx = make_ctx(&mut env);
        assert_eq!(builtin_false(&["false".into()], &mut ctx), 1);
    }
}

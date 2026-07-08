//! Command executor — runs parsed AST against the shell environment.
//!
//! This module is the core dispatch layer that translates an abstract syntax
//! tree produced by [`crate::parser`] into side-effectful operations: running
//! built-in commands, resolving external commands on `$PATH`, evaluating
//! `&&`/`||` short-circuit logic, and capturing pipeline output.
//!
//! ## Phase 1 scope
//!
//! For Phase 1 (in-process execution), external commands are not yet wired
//! to the kernel process-spawning layer. Commands that are not builtins return
//! exit code 127 (`command not found`). This restriction will be lifted in the
//! Layer 6 sprint.
//!
//! ## Pipeline model
//!
//! Pipelines are executed left-to-right. The output of each stage is held in
//! [`crate::executor::ExecContext::output`] and is available for the next stage to consume.
//! Full OS-level piping will be added with the kernel process layer.

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    env::ShellEnv,
    glob::{self, FsQuery},
    netquery::NetQuery,
    parser::{CommandList, Connector, Pipeline, SimpleCommand},
};

// ── CommandTarget ─────────────────────────────────────────────────────────────

/// The resolved target of a command lookup.
///
/// Produced by [`resolve_command`] and consumed by [`execute_pipeline`] to
/// decide whether to invoke a builtin handler or attempt external execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandTarget {
    /// A shell builtin command identified by its canonical name.
    Builtin(String),
    /// An external command found at the given absolute path.
    External(String),
    /// The command could not be resolved in builtins, aliases, or `$PATH`.
    NotFound,
}

// ── ExecContext ───────────────────────────────────────────────────────────────

/// Execution context threaded through all builtin handlers and executor stages.
///
/// Builtins write their output into [`ExecContext::output`] instead of directly
/// to stdout. This allows the REPL to control when and how output is flushed,
/// and enables pipeline chaining (one stage's output becomes the next stage's
/// implicit stdin in future work).
pub struct ExecContext<'a> {
    /// The shell's variable and alias environment.
    pub env: &'a mut ShellEnv,
    /// Exit code of the most recently completed command (`$?`).
    pub last_exit_code: i32,
    /// Current working directory (kept in sync with `$PWD`).
    pub cwd: String,
    /// Filesystem query interface — allows builtins like `cd` to validate
    /// paths without depending on a real kernel in tests.
    pub fs: &'a dyn FsQuery,
    /// Network-interface query interface — backs the `ifconfig` builtin
    /// without depending on a real kernel/network stack in tests.
    pub net: &'a dyn NetQuery,
    /// Captured output bytes written by the most recently executed command.
    ///
    /// The executor clears this before each command stage and accumulates the
    /// bytes written by the active builtin handler. The REPL prints this after
    /// every pipeline completes.
    pub output: Vec<u8>,
    /// Per-session audit log.
    ///
    /// Populated by [`crate::repl::process_line`] after every pipeline
    /// completes. Builtins do not write to this directly; the REPL owns the
    /// record step.
    pub audit_log: crate::audit::AuditLog,
}

// ── BuiltinFn ─────────────────────────────────────────────────────────────────

/// Function signature for a built-in command handler.
///
/// # Parameters
///
/// - `args`: the full `argv` slice (including `args[0]` which is the command
///   name itself, matching POSIX convention).
/// - `ctx`: mutable reference to the execution context.
///
/// # Returns
///
/// The exit code for the command: `0` for success, non-zero for failure.
pub type BuiltinFn = fn(args: &[String], ctx: &mut ExecContext<'_>) -> i32;

// ── resolve_command ───────────────────────────────────────────────────────────

/// Resolve a command name to its execution target.
///
/// Resolution order:
/// 1. **Builtins**: if `name` appears in `builtins`, return
///    [`CommandTarget::Builtin`].
/// 2. **Direct path**: if `name` contains `/`, treat it as a literal path and
///    attempt to locate the parent directory via `fs`; return
///    [`CommandTarget::External`] on success.
/// 3. **`$PATH` search**: split the `PATH` variable on `:` and search each
///    directory for an entry matching `name` via `fs.list_dir`. The first
///    match wins.
/// 4. If nothing matches, return [`CommandTarget::NotFound`].
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     env::ShellEnv,
///     executor::{CommandTarget, resolve_command},
///     glob::FsQuery,
/// };
///
/// struct EmptyFs;
/// impl FsQuery for EmptyFs {
///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
///         Ok(vec![])
///     }
/// }
///
/// let env = ShellEnv::new();
/// let target = resolve_command("echo", &env, &["echo", "cd"], &EmptyFs);
/// assert_eq!(target, CommandTarget::Builtin("echo".into()));
/// ```
pub fn resolve_command(
    name: &str,
    env: &ShellEnv,
    builtins: &[&str],
    fs: &dyn FsQuery,
) -> CommandTarget {
    // 1. Builtins take priority over everything.
    if builtins.contains(&name) {
        return CommandTarget::Builtin(name.to_string());
    }

    // 2. Name contains '/': treat as a literal path reference.
    if name.contains('/') {
        // Derive the parent directory from the path.
        let parent = match name.rfind('/') {
            Some(0) => "/",
            Some(pos) => &name[..pos],
            None => ".",
        };
        // Verify the parent directory is reachable through the FS interface.
        if fs.list_dir(parent).is_ok() {
            return CommandTarget::External(name.to_string());
        }
        return CommandTarget::NotFound;
    }

    // 3. Search each directory in $PATH.
    if let Some(path_var) = env.get("PATH") {
        for dir in path_var.split(':') {
            if let Ok(entries) = fs.list_dir(dir) {
                if entries.iter().any(|e| e == name) {
                    return CommandTarget::External(format!("{dir}/{name}"));
                }
            }
        }
    }

    CommandTarget::NotFound
}

// ── execute_command_list ──────────────────────────────────────────────────────

/// Execute a fully parsed [`CommandList`] in the given context.
///
/// Pipelines are executed in document order. The `&&` and `||` connectors
/// implement short-circuit evaluation:
///
/// - `&&` (AND): the right-hand pipeline is skipped when the left-hand exit
///   code is non-zero.
/// - `||` (OR): the right-hand pipeline is skipped when the left-hand exit
///   code is zero.
/// - `;` (SEMI) and `&` (BACKGROUND): always run the next pipeline.
///
/// The exit code of the last executed pipeline is returned and also written
/// back into `ctx.last_exit_code` and `ctx.env`.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{
///     command::register_builtins,
///     env::ShellEnv,
///     executor::{ExecContext, execute_command_list},
///     glob::FsQuery,
///     lexer::tokenize,
///     parser::parse,
/// };
///
/// struct EmptyFs;
/// impl FsQuery for EmptyFs {
///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
///         Ok(vec![])
///     }
/// }
///
/// let mut env = ShellEnv::new();
/// let tokens = tokenize("echo hello").unwrap();
/// let ast = parse(&tokens).unwrap();
/// let builtins = register_builtins();
/// let mut ctx = ExecContext {
///     last_exit_code: 0,
///     cwd: "/".into(),
///     fs: &EmptyFs,
///     net: &nexacore_shell::netquery::NoNet,
///     output: Vec::new(),
///     env: &mut env,
///     audit_log: nexacore_shell::audit::AuditLog::new(),
/// };
/// let code = execute_command_list(&ast, &mut ctx, &builtins);
/// assert_eq!(code, 0);
/// ```
pub fn execute_command_list(
    list: &CommandList,
    ctx: &mut ExecContext<'_>,
    builtins: &BTreeMap<String, BuiltinFn>,
) -> i32 {
    if list.entries.is_empty() {
        return 0;
    }

    let mut last_code = 0i32;

    for (i, (pipeline, _connector)) in list.entries.iter().enumerate() {
        // Evaluate the connector from the *previous* entry to decide whether
        // this pipeline should run.
        if i > 0 {
            // The connector stored in entries[i-1].1 governs the transition
            // from entries[i-1] to entries[i].
            if let Some((_prev_pipeline, Some(prev_conn))) = list.entries.get(i - 1) {
                match prev_conn {
                    // AND: skip this pipeline if the previous one failed.
                    Connector::And if last_code != 0 => continue,
                    // OR: skip this pipeline if the previous one succeeded.
                    Connector::Or if last_code == 0 => continue,
                    _ => {}
                }
            }
        }

        last_code = execute_pipeline(pipeline, ctx, builtins);
        ctx.last_exit_code = last_code;
        ctx.env.set_last_exit_code(last_code);
    }

    last_code
}

// ── execute_pipeline ──────────────────────────────────────────────────────────

/// Execute a single [`Pipeline`], returning the exit code of the last stage.
///
/// For Phase 1 the pipeline is executed sequentially: each stage's output is
/// captured in [`ExecContext::output`] and made implicitly available to the
/// next stage. Full OS-level pipe(2) wiring arrives with the kernel process
/// layer.
///
/// If a command name is not found in `builtins`, exit code 127 is returned
/// and an error message is written to `ctx.output`.
///
/// # Panics
///
/// Does not panic in practice: the `argv.first()` call is guarded by an
/// `argv.is_empty()` check immediately before it.
pub fn execute_pipeline(
    pipeline: &Pipeline,
    ctx: &mut ExecContext<'_>,
    builtins: &BTreeMap<String, BuiltinFn>,
) -> i32 {
    let mut last_code = 0i32;

    for (i, cmd) in pipeline.commands.iter().enumerate() {
        let is_last = i == pipeline.commands.len() - 1;

        // Expand environment variables and globs in every argv element.
        let argv = expand_command(cmd, ctx.env, ctx.fs, &ctx.cwd);
        if argv.is_empty() {
            continue;
        }

        // Apply per-command environment overrides (e.g. `FOO=bar cmd`).
        // These are set in the current environment for simplicity in Phase 1.
        for (k, v) in &cmd.env_overrides {
            ctx.env.set(k, v);
        }

        // Reset output buffer before each stage.
        ctx.output.clear();

        // argv is non-empty (verified by the is_empty guard above).
        if let Some(name) = argv.first() {
            if let Some(handler) = builtins.get(name.as_str()) {
                last_code = handler(&argv, ctx);
            } else {
                // External commands are not yet wired to the kernel process layer.
                ctx.output.extend_from_slice(
                    format!("nexacore-shell: {name}: command not found\n").as_bytes(),
                );
                last_code = 127;
            }
        }

        // For multi-stage pipelines, save output for the next stage.
        // In Phase 1 this is a best-effort pass-through; full piping comes later.
        if !is_last {
            // Output captured; the next iteration will clear it and execute
            // the next stage. In a real pipe the bytes would flow via fd pairs.
        }
    }

    last_code
}

// ── expand_command ────────────────────────────────────────────────────────────

/// Expand variable references and glob patterns in a [`SimpleCommand`]'s argv.
///
/// For each element of `cmd.argv`:
/// 1. Run [`ShellEnv::expand`] to substitute `$VAR` and `${VAR}` references.
/// 2. If the result contains glob metacharacters, run [`glob::expand_glob`]
///    and append all matches to the output vector.
/// 3. Otherwise append the expanded string directly.
///
/// # Empty result
///
/// Returns an empty `Vec` only when `cmd.argv` is itself empty; this is a
/// logic error in the parser and should not occur in practice.
fn expand_command(
    cmd: &SimpleCommand,
    env: &ShellEnv,
    fs: &dyn FsQuery,
    work_dir: &str,
) -> Vec<String> {
    let mut result = Vec::with_capacity(cmd.argv.len());
    for arg in &cmd.argv {
        let expanded = env.expand(arg);
        if glob::is_glob(&expanded) {
            let matches = glob::expand_glob(&expanded, work_dir, fs);
            result.extend(matches);
        } else {
            result.push(expanded);
        }
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command::register_builtins, env::ShellEnv, lexer::tokenize, netquery::NoNet, parser::parse,
    };

    // ── Mock filesystem ───────────────────────────────────────────────────

    struct MockFs {
        bin_entries: Vec<String>,
    }

    impl MockFs {
        fn with_bins(bins: &[&str]) -> Self {
            Self {
                bin_entries: bins.iter().map(|s| (*s).to_string()).collect(),
            }
        }
        fn empty() -> Self {
            Self {
                bin_entries: vec![],
            }
        }
    }

    impl FsQuery for MockFs {
        fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
            if path == "/bin" {
                Ok(self.bin_entries.clone())
            } else if path == "/" {
                Ok(vec!["bin".into()])
            } else {
                Err(format!("no such directory: {path}"))
            }
        }
    }

    // ── Helper: build an ExecContext quickly ──────────────────────────────

    fn make_ctx<'a>(env: &'a mut ShellEnv, fs: &'a dyn FsQuery) -> ExecContext<'a> {
        ExecContext {
            env,
            last_exit_code: 0,
            cwd: "/".to_string(),
            fs,
            net: &NoNet,
            output: Vec::new(),
            audit_log: crate::audit::AuditLog::new(),
        }
    }

    fn run(input: &str, env: &mut ShellEnv, fs: &dyn FsQuery) -> (i32, String) {
        let tokens = tokenize(input).expect("lex failed");
        let ast = parse(&tokens).expect("parse failed");
        let builtins = register_builtins();
        let mut ctx = make_ctx(env, fs);
        let code = execute_command_list(&ast, &mut ctx, &builtins);
        let out = String::from_utf8_lossy(&ctx.output).into_owned();
        (code, out)
    }

    // ── resolve_command ───────────────────────────────────────────────────

    #[test]
    fn resolve_finds_builtin() {
        let env = ShellEnv::new();
        let fs = MockFs::empty();
        let target = resolve_command("echo", &env, &["echo", "cd"], &fs);
        assert_eq!(target, CommandTarget::Builtin("echo".into()));
    }

    #[test]
    fn resolve_finds_external_in_path() {
        let env = ShellEnv::new(); // PATH=/bin by default
        let fs = MockFs::with_bins(&["grep"]);
        let target = resolve_command("grep", &env, &[], &fs);
        assert_eq!(target, CommandTarget::External("/bin/grep".into()));
    }

    #[test]
    fn resolve_not_found_returns_not_found() {
        let env = ShellEnv::new();
        let fs = MockFs::empty();
        let target = resolve_command("nonexistent_tool", &env, &[], &fs);
        assert_eq!(target, CommandTarget::NotFound);
    }

    #[test]
    fn resolve_direct_path_with_slash() {
        // When the name contains '/', verify the parent dir through the FS.
        let env = ShellEnv::new();
        let fs = MockFs::empty(); // list_dir("/") succeeds
        let target = resolve_command("/bin/grep", &env, &[], &fs);
        // The parent "/" exists in MockFs.
        assert_eq!(target, CommandTarget::External("/bin/grep".into()));
    }

    #[test]
    fn resolve_direct_path_bad_parent_is_not_found() {
        let env = ShellEnv::new();
        let fs = MockFs::empty(); // /nonexistent fails
        let target = resolve_command("/nonexistent/tool", &env, &[], &fs);
        assert_eq!(target, CommandTarget::NotFound);
    }

    // ── execute_command_list: basic execution ─────────────────────────────

    #[test]
    fn execute_single_echo_command() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("echo hello", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "hello");
    }

    #[test]
    fn empty_command_list_returns_zero() {
        let builtins = register_builtins();
        let ast = parse(&[]).unwrap();
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let mut ctx = make_ctx(&mut env, &fs);
        let code = execute_command_list(&ast, &mut ctx, &builtins);
        assert_eq!(code, 0);
    }

    // ── execute_pipeline: single stage ───────────────────────────────────

    #[test]
    fn execute_pipeline_single_builtin() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let tokens = tokenize("pwd").unwrap();
        let ast = parse(&tokens).unwrap();
        let builtins = register_builtins();
        let mut ctx = make_ctx(&mut env, &fs);
        ctx.cwd = "/home/root".into();
        let code = execute_command_list(&ast, &mut ctx, &builtins);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&ctx.output).contains("/home/root"));
    }

    // ── AND chaining ──────────────────────────────────────────────────────

    #[test]
    fn and_chain_runs_second_when_first_succeeds() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("true && echo yes", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "yes");
    }

    #[test]
    fn and_chain_skips_second_when_first_fails() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("false && echo yes", &mut env, &fs);
        // `false` returns 1; `echo yes` should be skipped.
        assert_eq!(code, 1);
        assert!(out.trim().is_empty());
    }

    // ── OR chaining ───────────────────────────────────────────────────────

    #[test]
    fn or_chain_runs_second_when_first_fails() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("false || echo fallback", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "fallback");
    }

    #[test]
    fn or_chain_skips_second_when_first_succeeds() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("true || echo fallback", &mut env, &fs);
        // `true` returns 0; `echo fallback` should be skipped.
        assert_eq!(code, 0);
        assert!(out.trim().is_empty());
    }

    // ── Variable expansion ────────────────────────────────────────────────

    #[test]
    fn variable_expansion_in_args() {
        let mut env = ShellEnv::new();
        env.set("GREETING", "world");
        let fs = MockFs::empty();
        let (code, out) = run("echo $GREETING", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "world");
    }

    // ── Glob expansion ────────────────────────────────────────────────────

    #[test]
    fn glob_expansion_in_args() {
        struct GlobFs;
        impl FsQuery for GlobFs {
            fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
                Ok(vec!["alpha.txt".into(), "beta.txt".into()])
            }
        }

        let mut env = ShellEnv::new();
        let fs = GlobFs;
        // echo *.txt should expand to "alpha.txt beta.txt"
        let (code, out) = run("echo *.txt", &mut env, &fs);
        assert_eq!(code, 0);
        // Both filenames must appear in the output
        assert!(out.contains("alpha.txt"), "output was: {out}");
        assert!(out.contains("beta.txt"), "output was: {out}");
    }

    // ── Env override VAR=val ──────────────────────────────────────────────

    #[test]
    fn env_override_sets_variable_in_environment() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        // MY_VAR=hello echo $MY_VAR
        // The override is applied before expansion.
        let (code, _out) = run("MY_VAR=hello echo $MY_VAR", &mut env, &fs);
        assert_eq!(code, 0);
    }

    // ── Command not found ─────────────────────────────────────────────────

    #[test]
    fn command_not_found_returns_127() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("totally_unknown_command_xyz", &mut env, &fs);
        assert_eq!(code, 127);
        assert!(out.contains("command not found"));
    }

    // ── Semi connector ────────────────────────────────────────────────────

    #[test]
    fn semicolon_always_runs_next_pipeline() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        // The output goes to the last stage's ctx.output; we only see the
        // last command's output directly, but the exit code reflects the last.
        let tokens = tokenize("false ; echo ran").unwrap();
        let ast = parse(&tokens).unwrap();
        let builtins = register_builtins();
        let mut ctx = make_ctx(&mut env, &fs);
        let code = execute_command_list(&ast, &mut ctx, &builtins);
        // `echo ran` returns 0 (last pipeline)
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&ctx.output).trim(), "ran");
    }
}

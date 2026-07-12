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
//!
//! ## I/O redirections
//!
//! Each command's `<`, `>`, `>>`, and `2>` redirections are **executed** (not
//! merely parsed) against the injected [`crate::glob::FsQuery`] filesystem seam:
//!
//! - `<` reads the target file and feeds it as the command's stdin
//!   ([`ExecContext::stdin`]).
//! - `>` / `>>` write / append the command's captured stdout
//!   ([`ExecContext::output`]) to the target file, and the bytes do **not**
//!   flow further down the pipeline.
//! - `2>` writes the command's captured stderr ([`ExecContext::stderr`]) to the
//!   target file.
//!
//! Redirections are applied in the order written; for a given stream the last
//! redirection wins (earlier ones to the same stream are still created but
//! receive no bytes). A redirection whose target cannot be opened fails the
//! command closed: a non-zero exit code with a diagnostic on the normal output
//! channel, never a panic. This still operates in the Phase 1 in-process model
//! — redirections go through the injected seam, not real kernel syscalls.

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
    lexer::{Token, tokenize},
    netquery::NetQuery,
    parser::{CommandList, Connector, Pipeline, Redirect, RedirectKind, SimpleCommand, parse},
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
    /// every pipeline completes. A `>` / `>>` redirect drains this buffer into a
    /// file instead of propagating it down the pipeline.
    pub output: Vec<u8>,
    /// Standard-input bytes fed to the current command.
    ///
    /// Populated by the executor from a `<` redirect before the command runs;
    /// empty when the command has no input redirect. Builtins that consume
    /// stdin (e.g. `cat` with no file operands) read from here. The executor
    /// clears this before each command stage.
    pub stdin: Vec<u8>,
    /// Captured standard-error bytes written by the most recently executed
    /// command.
    ///
    /// Kept separate from [`ExecContext::output`] (stdout) so a `2>` redirect
    /// can route error text independently. The executor clears this before each
    /// command stage.
    pub stderr: Vec<u8>,
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
///     stdin: Vec::new(),
///     stderr: Vec::new(),
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

// ── Command substitution ──────────────────────────────────────────────────────

/// Maximum command-substitution nesting depth.
///
/// Command substitution terminates naturally because each level operates on a
/// strictly shorter inner string, but a defensive cap guards against
/// pathological nesting causing unbounded stack growth. Beyond this depth a
/// substitution yields empty output and exit code 2.
const MAX_SUBST_DEPTH: usize = 64;

/// Resolve every command substitution `$(...)` in a token stream.
///
/// Each [`Token::CommandSubst`] is replaced by a [`Token::Word`] holding the
/// captured standard output of the inner command, with trailing newlines
/// stripped POSIX-style. Every other token is passed through unchanged — in
/// particular a `$(...)` that appeared literally inside single quotes arrives as
/// a [`Token::SingleQuoted`] and is therefore left untouched.
///
/// The inner command runs through the full `lex → substitute → parse → execute`
/// path against `ctx`, so nested substitutions such as `$(echo $(echo x))`
/// resolve recursively. The inner command's captured output does not leak into
/// `ctx.output`, and `ctx.cwd` is restored afterwards so a `$(cd …)` cannot move
/// the surrounding shell. The exit status of the last substitution executed is
/// recorded as `$?`.
///
/// This is the seam that gives expansion access to the executor: callers run it
/// on the token stream after [`crate::lexer::tokenize`] and before
/// [`crate::parser::parse`].
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     command::register_builtins,
///     env::ShellEnv,
///     executor::{ExecContext, substitute_tokens},
///     glob::FsQuery,
///     lexer::{Token, tokenize},
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
/// let builtins = register_builtins();
/// let mut ctx = ExecContext {
///     last_exit_code: 0,
///     cwd: "/".into(),
///     fs: &EmptyFs,
///     net: &nexacore_shell::netquery::NoNet,
///     output: Vec::new(),
///     env: &mut env,
///     audit_log: nexacore_shell::audit::AuditLog::new(),
///     stdin: Vec::new(),
///     stderr: Vec::new(),
/// };
/// let tokens = tokenize("echo $(echo hi)").unwrap();
/// let resolved = substitute_tokens(tokens, &mut ctx, &builtins);
/// assert_eq!(
///     resolved,
///     vec![Token::Word("echo".into()), Token::Word("hi".into())]
/// );
/// ```
pub fn substitute_tokens(
    tokens: Vec<Token>,
    ctx: &mut ExecContext<'_>,
    builtins: &BTreeMap<String, BuiltinFn>,
) -> Vec<Token> {
    substitute_tokens_at(tokens, ctx, builtins, 0)
}

/// Depth-tracked implementation of [`substitute_tokens`].
fn substitute_tokens_at(
    tokens: Vec<Token>,
    ctx: &mut ExecContext<'_>,
    builtins: &BTreeMap<String, BuiltinFn>,
    depth: usize,
) -> Vec<Token> {
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        match token {
            Token::CommandSubst(inner) => {
                let (captured, code) = run_and_capture(&inner, ctx, builtins, depth);
                // `$?` reflects the exit status of the last substitution run.
                ctx.last_exit_code = code;
                ctx.env.set_last_exit_code(code);
                out.push(Token::Word(captured));
            }
            other => out.push(other),
        }
    }
    out
}

/// Run an inner command string and capture its standard output.
///
/// Returns the captured output (trailing newlines stripped) and the inner exit
/// code. Lexer or parser errors in the inner command yield empty output and
/// exit code 2. The caller's `ctx.output` and `ctx.cwd` are preserved.
///
/// Because Phase 1 does not separate stdout from stderr, diagnostic text from a
/// failing inner command (e.g. `command not found`) is captured as its output —
/// this is a documented limitation of the current single-stream model.
fn run_and_capture(
    inner: &str,
    ctx: &mut ExecContext<'_>,
    builtins: &BTreeMap<String, BuiltinFn>,
    depth: usize,
) -> (String, i32) {
    // Fail closed on pathological nesting rather than risk a stack overflow.
    if depth >= MAX_SUBST_DEPTH {
        return (String::new(), 2);
    }

    let Ok(tokens) = tokenize(inner) else {
        return (String::new(), 2);
    };
    // Resolve any nested substitutions before parsing the inner command.
    let tokens = substitute_tokens_at(tokens, ctx, builtins, depth + 1);
    let Ok(ast) = parse(&tokens) else {
        return (String::new(), 2);
    };

    // Execute with an isolated output buffer and a restorable working
    // directory, so the surrounding shell's state is not disturbed.
    let saved_output = core::mem::take(&mut ctx.output);
    let saved_cwd = ctx.cwd.clone();
    let code = execute_command_list(&ast, ctx, builtins);
    let captured = core::mem::replace(&mut ctx.output, saved_output);
    ctx.cwd = saved_cwd;

    let text = String::from_utf8_lossy(&captured);
    (strip_trailing_newlines(&text), code)
}

/// Strip trailing newline characters from command-substitution output.
///
/// POSIX removes any run of trailing `\n` from the result of a command
/// substitution; interior newlines are preserved.
fn strip_trailing_newlines(s: &str) -> String {
    s.trim_end_matches('\n').to_string()
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

        // Reset the per-stage stream buffers.
        ctx.output.clear();
        ctx.stderr.clear();
        ctx.stdin.clear();

        // Apply input (`<`) redirects before the command runs. The last `<`
        // wins; a target that cannot be read fails the command closed (non-zero
        // exit, diagnostic on the output channel) and the command is skipped.
        match resolve_stdin(&cmd.redirects, ctx.fs) {
            Ok(Some(bytes)) => ctx.stdin = bytes,
            Ok(None) => {}
            Err(msg) => {
                ctx.output
                    .extend_from_slice(format!("nexacore-shell: {msg}\n").as_bytes());
                last_code = 1;
                continue;
            }
        }

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

        // Apply output (`>`, `>>`, `2>`) redirects after the command runs. A
        // redirected stream is drained to its file and cleared so it does not
        // propagate down the pipeline. A write failure fails the command closed.
        match apply_output_redirects(&cmd.redirects, &ctx.output, &ctx.stderr, ctx.fs) {
            Ok(disposition) => {
                if disposition.stdout_redirected {
                    ctx.output.clear();
                }
                if disposition.stderr_redirected {
                    ctx.stderr.clear();
                }
            }
            Err(msg) => {
                ctx.output
                    .extend_from_slice(format!("nexacore-shell: {msg}\n").as_bytes());
                last_code = 1;
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

// ── Redirection application ────────────────────────────────────────────────────

/// Whether a command's captured stdout / stderr were consumed by a redirect and
/// must therefore be cleared instead of propagated down the pipeline.
struct RedirectDisposition {
    /// A `>` or `>>` redirect drained the stdout buffer.
    stdout_redirected: bool,
    /// A `2>` redirect drained the stderr buffer.
    stderr_redirected: bool,
}

/// Resolve the standard-input bytes selected by a command's `<` redirects.
///
/// Only the last `<` redirect takes effect — matching the POSIX "last
/// redirection wins" rule for a stream — and earlier input redirects are
/// superseded (their targets are not opened). Returns `Ok(None)` when the
/// command has no input redirect.
///
/// # Errors
///
/// Returns `Err(String)` when the selected target cannot be read, so the caller
/// can fail the command closed rather than run it with the wrong input.
fn resolve_stdin(redirects: &[Redirect], fs: &dyn FsQuery) -> Result<Option<Vec<u8>>, String> {
    redirects
        .iter()
        .rev()
        .find(|r| r.kind == RedirectKind::In)
        .map_or(Ok(None), |r| {
            fs.read_file(&r.target)
                .map(Some)
                .map_err(|e| format!("{}: {e}", r.target))
        })
}

/// Apply a command's output redirects (`>`, `>>`, `2>`) to its captured
/// `stdout` / `stderr` buffers, writing through the injected filesystem seam.
///
/// Redirections are applied in the order written. For each stream — stdout via
/// `>` / `>>`, stderr via `2>` — the *last* redirection to that stream receives
/// the captured bytes; any earlier redirection to the same stream is still
/// created (truncated for `>`, created-if-absent for `>>`) but receives no
/// bytes, matching the observable end state of a POSIX shell. `<` entries are
/// ignored here (handled by [`resolve_stdin`]).
///
/// # Errors
///
/// Returns `Err(String)` on the first target that cannot be opened / written,
/// so the caller can surface a non-zero exit code.
fn apply_output_redirects(
    redirects: &[Redirect],
    stdout: &[u8],
    stderr: &[u8],
    fs: &dyn FsQuery,
) -> Result<RedirectDisposition, String> {
    // Index of the last redirect targeting each stream (the one that receives
    // the captured bytes). `>` / `>>` share the stdout stream; `2>` owns stderr.
    let last_stdout = redirects
        .iter()
        .rposition(|r| matches!(r.kind, RedirectKind::Out | RedirectKind::Append));
    let last_stderr = redirects.iter().rposition(|r| r.kind == RedirectKind::Err);

    for (idx, r) in redirects.iter().enumerate() {
        match r.kind {
            RedirectKind::Out => {
                let payload: &[u8] = if Some(idx) == last_stdout {
                    stdout
                } else {
                    &[]
                };
                fs.write_file(&r.target, payload)
                    .map_err(|e| format!("{}: {e}", r.target))?;
            }
            RedirectKind::Append => {
                let payload: &[u8] = if Some(idx) == last_stdout {
                    stdout
                } else {
                    &[]
                };
                fs.append_file(&r.target, payload)
                    .map_err(|e| format!("{}: {e}", r.target))?;
            }
            RedirectKind::Err => {
                let payload: &[u8] = if Some(idx) == last_stderr {
                    stderr
                } else {
                    &[]
                };
                fs.write_file(&r.target, payload)
                    .map_err(|e| format!("{}: {e}", r.target))?;
            }
            RedirectKind::In => {}
        }
    }

    Ok(RedirectDisposition {
        stdout_redirected: last_stdout.is_some(),
        stderr_redirected: last_stderr.is_some(),
    })
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
    use crate::{command::register_builtins, env::ShellEnv, netquery::NoNet};

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
            stdin: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn run(input: &str, env: &mut ShellEnv, fs: &dyn FsQuery) -> (i32, String) {
        let tokens = tokenize(input).expect("lex failed");
        let builtins = register_builtins();
        let mut ctx = make_ctx(env, fs);
        // Resolve `$(...)` before parsing, mirroring the real REPL pipeline.
        let tokens = substitute_tokens(tokens, &mut ctx, &builtins);
        let ast = parse(&tokens).expect("parse failed");
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

    // ── Command substitution ──────────────────────────────────────────────

    #[test]
    fn command_subst_simple() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("echo $(echo hi)", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "hi");
    }

    #[test]
    fn command_subst_nested() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("echo $(echo $(echo x))", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "x");
    }

    #[test]
    fn command_subst_inside_double_quotes() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("echo \"$(echo hi)\"", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "hi");
    }

    #[test]
    fn command_subst_single_quotes_are_literal() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        // Inside single quotes the substitution is NOT performed.
        let (code, out) = run("echo '$(echo hi)'", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "$(echo hi)");
    }

    #[test]
    fn command_subst_result_used_as_argument() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("echo pre $(echo mid) post", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), "pre mid post");
    }

    #[test]
    fn command_subst_strips_trailing_newlines() {
        // `pwd` emits a trailing newline; substitution must strip it so the
        // result splices cleanly. Assert the exact output (no trim) so a
        // retained newline would fail the test.
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let (code, out) = run("echo a $(pwd) b", &mut env, &fs);
        assert_eq!(code, 0);
        assert_eq!(out, "a / b\n");
    }

    #[test]
    fn command_subst_failing_inner_sets_last_exit_code() {
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let builtins = register_builtins();
        let mut ctx = make_ctx(&mut env, &fs);
        let tokens = tokenize("echo $(false)").unwrap();
        let resolved = substitute_tokens(tokens, &mut ctx, &builtins);
        // The substitution ran `false`, so `$?` reflects exit code 1.
        assert_eq!(ctx.env.last_exit_code(), 1);
        // `false` produced no stdout, so the substitution collapses to an empty
        // word argument.
        assert_eq!(
            resolved,
            vec![Token::Word("echo".into()), Token::Word(String::new())]
        );
    }

    #[test]
    fn command_subst_does_not_leak_cwd() {
        // A `cd` inside a substitution must not move the surrounding shell.
        let mut env = ShellEnv::new();
        let fs = MockFs::empty();
        let builtins = register_builtins();
        let mut ctx = make_ctx(&mut env, &fs);
        ctx.cwd = "/start".into();
        let tokens = tokenize("echo $(cd /elsewhere)").unwrap();
        let _ = substitute_tokens(tokens, &mut ctx, &builtins);
        assert_eq!(ctx.cwd, "/start");
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

    // ── I/O redirections ──────────────────────────────────────────────────

    use core::cell::RefCell;

    /// In-memory, I/O-capable filesystem double for redirect tests.
    ///
    /// Records writes so tests can assert on file contents, and can be put into
    /// a mode where every write fails (to exercise the fail-closed path).
    struct MemFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        fail_write: bool,
    }

    impl MemFs {
        fn new() -> Self {
            Self {
                files: RefCell::new(BTreeMap::new()),
                fail_write: false,
            }
        }

        fn with_file(path: &str, contents: &[u8]) -> Self {
            let mut map = BTreeMap::new();
            map.insert(path.to_string(), contents.to_vec());
            Self {
                files: RefCell::new(map),
                fail_write: false,
            }
        }

        fn failing() -> Self {
            Self {
                files: RefCell::new(BTreeMap::new()),
                fail_write: true,
            }
        }

        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }
    }

    impl FsQuery for MemFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }

        fn supports_io(&self) -> bool {
            true
        }

        fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| format!("no such file: {path}"))
        }

        fn write_file(&self, path: &str, contents: &[u8]) -> Result<(), String> {
            if self.fail_write {
                return Err("permission denied".to_string());
            }
            self.files
                .borrow_mut()
                .insert(path.to_string(), contents.to_vec());
            Ok(())
        }

        fn append_file(&self, path: &str, contents: &[u8]) -> Result<(), String> {
            if self.fail_write {
                return Err("permission denied".to_string());
            }
            self.files
                .borrow_mut()
                .entry(path.to_string())
                .or_default()
                .extend_from_slice(contents);
            Ok(())
        }
    }

    fn run_with(input: &str, fs: &dyn FsQuery) -> (i32, Vec<u8>) {
        let mut env = ShellEnv::new();
        let tokens = tokenize(input).expect("lex failed");
        let ast = parse(&tokens).expect("parse failed");
        let builtins = register_builtins();
        let mut ctx = make_ctx(&mut env, fs);
        let code = execute_command_list(&ast, &mut ctx, &builtins);
        (code, ctx.output)
    }

    #[test]
    fn redirect_out_writes_and_truncates_stdout() {
        let fs = MemFs::with_file("out.txt", b"STALE CONTENT");
        let (code, output) = run_with("echo hello > out.txt", &fs);
        assert_eq!(code, 0);
        // File is truncated then filled with the command's stdout.
        assert_eq!(fs.get("out.txt").as_deref(), Some(&b"hello\n"[..]));
        // Redirected stdout does not remain on the output channel.
        assert!(output.is_empty());
    }

    #[test]
    fn redirect_append_appends_stdout() {
        let fs = MemFs::with_file("log.txt", b"line1\n");
        let (code, output) = run_with("echo line2 >> log.txt", &fs);
        assert_eq!(code, 0);
        assert_eq!(fs.get("log.txt").as_deref(), Some(&b"line1\nline2\n"[..]));
        assert!(output.is_empty());
    }

    #[test]
    fn redirect_append_creates_missing_file() {
        let fs = MemFs::new();
        let (code, _output) = run_with("echo first >> fresh.txt", &fs);
        assert_eq!(code, 0);
        assert_eq!(fs.get("fresh.txt").as_deref(), Some(&b"first\n"[..]));
    }

    #[test]
    fn redirect_in_feeds_stdin_to_cat() {
        let fs = MemFs::with_file("input.txt", b"piped via stdin\n");
        let (code, output) = run_with("cat < input.txt", &fs);
        assert_eq!(code, 0);
        // `cat` with no operands echoes the stdin the executor fed it.
        assert_eq!(String::from_utf8_lossy(&output), "piped via stdin\n");
    }

    #[test]
    fn redirect_err_captures_stderr() {
        // `cat` on a missing file writes to stderr, which `2>` routes to a file.
        let fs = MemFs::new();
        let (code, output) = run_with("cat missing.txt 2> err.log", &fs);
        assert_eq!(code, 1);
        let err = fs.get("err.log").unwrap_or_default();
        assert!(
            String::from_utf8_lossy(&err).contains("missing.txt"),
            "err.log was: {err:?}"
        );
        // Stderr was routed to the file, not left on stdout.
        assert!(output.is_empty());
    }

    #[test]
    fn multiple_redirects_last_stdout_wins() {
        let fs = MemFs::new();
        let (code, _output) = run_with("echo hi > first.txt > second.txt", &fs);
        assert_eq!(code, 0);
        // The last stdout redirect receives the bytes; the earlier one is
        // created but truncated empty.
        assert_eq!(fs.get("second.txt").as_deref(), Some(&b"hi\n"[..]));
        assert_eq!(fs.get("first.txt").as_deref(), Some(&b""[..]));
    }

    #[test]
    fn multiple_redirects_stdin_and_stdout_together() {
        let fs = MemFs::with_file("in.txt", b"through\n");
        let (code, output) = run_with("cat < in.txt > out.txt", &fs);
        assert_eq!(code, 0);
        // stdin feeds cat; cat's stdout is redirected to the file, not returned.
        assert_eq!(fs.get("out.txt").as_deref(), Some(&b"through\n"[..]));
        assert!(output.is_empty());
    }

    #[test]
    fn redirect_output_target_error_is_nonzero() {
        let fs = MemFs::failing();
        let (code, output) = run_with("echo hi > /root/protected", &fs);
        assert_eq!(code, 1);
        // The failure is surfaced through the normal channel, not a panic.
        assert!(String::from_utf8_lossy(&output).contains("protected"));
    }

    #[test]
    fn redirect_input_missing_file_is_nonzero() {
        let fs = MemFs::new();
        let (code, output) = run_with("cat < nope.txt", &fs);
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&output).contains("nope.txt"));
    }

    #[test]
    fn redirected_stdout_does_not_flow_into_pipeline() {
        // A redirected stage's stdout must not linger in the shared buffer that
        // a downstream stage would read.
        let fs = MemFs::new();
        let (_code, output) = run_with("echo secret > out.txt", &fs);
        assert!(!String::from_utf8_lossy(&output).contains("secret"));
        assert_eq!(fs.get("out.txt").as_deref(), Some(&b"secret\n"[..]));
    }

    #[test]
    fn apply_output_redirects_routes_streams_independently() {
        let fs = MemFs::new();
        let redirects = vec![
            Redirect {
                kind: RedirectKind::Out,
                target: "o.txt".to_string(),
            },
            Redirect {
                kind: RedirectKind::Err,
                target: "e.txt".to_string(),
            },
        ];
        let disposition =
            apply_output_redirects(&redirects, b"stdout-bytes", b"stderr-bytes", &fs).unwrap();
        assert!(disposition.stdout_redirected);
        assert!(disposition.stderr_redirected);
        assert_eq!(fs.get("o.txt").as_deref(), Some(&b"stdout-bytes"[..]));
        assert_eq!(fs.get("e.txt").as_deref(), Some(&b"stderr-bytes"[..]));
    }

    #[test]
    fn resolve_stdin_none_without_input_redirect() {
        let fs = MemFs::new();
        let redirects = vec![Redirect {
            kind: RedirectKind::Out,
            target: "o.txt".to_string(),
        }];
        assert_eq!(resolve_stdin(&redirects, &fs), Ok(None));
    }
}

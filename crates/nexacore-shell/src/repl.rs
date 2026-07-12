//! Read-eval-print loop (REPL).
//!
//! This module drives the interactive shell session. It provides two public
//! entry points:
//!
//! - [`crate::repl::format_prompt`]: formats the shell prompt string by expanding `PS1`
//!   escape sequences.
//! - [`crate::repl::process_line`]: runs a single input line through the full shell
//!   pipeline — tokenise → expand aliases → parse → execute.
//!
//! The [`crate::repl::Shell`] struct bundles the environment, line editor, and current
//! working directory. In a live session the REPL owner calls [`crate::repl::process_line`]
//! for every line obtained from the line editor, destructures the returned
//! `(exit_code, output)` tuple, writes `output` to the console, and uses
//! `exit_code` to update `$?`.
//!
//! ## Pipeline
//!
//! ```text
//! raw &str
//!   ──► lexer::tokenize           →  Vec<Token>
//!   ──► parser::parse             →  CommandList (AST)
//!   ──► executor::execute_command_list  →  i32 (exit code)
//!       (builtins run in-process; env/glob expansion happens inside executor)
//! ```
//!
//! ## Comments and blank lines
//!
//! Lines that are empty (after trimming) or that begin with `#` are treated as
//! no-ops and return exit code `0` immediately.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    command,
    env::ShellEnv,
    executor::{self, ExecContext},
    glob::FsQuery,
    history::History,
    job::JobTable,
    lexer,
    line_editor::LineEditor,
    netquery::NetQuery,
    parser,
};

/// Default command-history capacity for a [`Shell`] session.
const DEFAULT_HISTORY_CAPACITY: usize = 1000;

// ── format_prompt ─────────────────────────────────────────────────────────────

/// Format the shell prompt string.
///
/// If the `PS1` environment variable is set, its value is used as the template
/// with the following escape sequences expanded:
///
/// | Sequence | Expansion |
/// |----------|-----------|
/// | `\u` | Value of `$USER` (or `?` if unset). |
/// | `\h` | Value of `$HOSTNAME` (or `nexacore` if unset). |
/// | `\w` | Current working directory (`cwd`). |
/// | `\$` | `$` (allows `PS1` to include a literal dollar sign). |
///
/// If `PS1` is not set, the default prompt format is used:
/// `<USER>@<HOSTNAME>:<cwd>$ `.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{env::ShellEnv, repl::format_prompt};
///
/// let env = ShellEnv::new();
/// let prompt = format_prompt(&env, "/home/root");
/// assert!(prompt.contains("root@"));
/// assert!(prompt.contains("/home/root"));
/// assert!(prompt.ends_with("$ "));
/// ```
pub fn format_prompt(env: &ShellEnv, cwd: &str) -> String {
    env.get("PS1").map_or_else(
        || {
            format!(
                "{}@{}:{}$ ",
                env.get("USER").unwrap_or("root"),
                env.get("HOSTNAME").unwrap_or("nexacore"),
                cwd
            )
        },
        |ps1| {
            ps1.replace("\\u", env.get("USER").unwrap_or("?"))
                .replace("\\h", env.get("HOSTNAME").unwrap_or("nexacore"))
                .replace("\\w", cwd)
                .replace("\\$", "$")
        },
    )
}

// ── process_line ──────────────────────────────────────────────────────────────

/// Process a single input line through the complete shell pipeline.
///
/// Steps performed:
/// 1. Trim leading and trailing whitespace.
/// 2. Skip empty lines and comments (`#`-prefixed) — return `(0, vec![])`.
/// 3. Tokenise via [`lexer::tokenize`]; syntax errors return `(1, vec![])`.
/// 4. Parse via [`parser::parse`]; parse errors return `(1, vec![])`.
/// 5. Execute via [`executor::execute_command_list`].
/// 6. Flush captured output to stdout via `print!` (only under the `std`
///    feature).
/// 7. Update `*cwd` from the execution context (the `cd` builtin may have
///    changed it).
///
/// # Returns
///
/// A `(exit_code, output)` tuple where:
/// - `exit_code` is the exit code of the last executed pipeline, `0` for
///   blank/comment lines, or `1` on tokenisation/parse failure.
/// - `output` contains the raw bytes of captured pipeline output. Under the
///   `std` feature this function also flushes those bytes to stdout. On
///   bare-metal targets the caller is responsible for writing `output` to the
///   console via the kernel syscall layer.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{env::ShellEnv, glob::FsQuery, netquery::NoNet, repl::process_line};
///
/// struct EmptyFs;
/// impl FsQuery for EmptyFs {
///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
///         Ok(vec![])
///     }
/// }
///
/// let mut env = ShellEnv::new();
/// let mut cwd = "/".to_string();
/// let (code, _output) = process_line("echo hello", &mut env, &mut cwd, &EmptyFs, &NoNet);
/// assert_eq!(code, 0);
/// ```
#[allow(
    clippy::cognitive_complexity,
    reason = "REPL line dispatch: branch count mirrors the builtin command set"
)]
pub fn process_line(
    input: &str,
    env: &mut ShellEnv,
    cwd: &mut String,
    fs: &dyn FsQuery,
    net: &dyn NetQuery,
) -> (i32, Vec<u8>) {
    let trimmed = input.trim();

    // Empty lines and comments are no-ops — return immediately with no output.
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return (0, Vec::new());
    }

    // Expand a leading alias (first word only; quoted/non-first tokens are left
    // untouched, recursive chains are loop-guarded). The alias table lives in
    // `env`; expansion runs before tokenisation so the rest of the pipeline sees
    // the resolved command line. Intent classification and the audit record keep
    // using the original `trimmed` input the user actually typed.
    let expanded = crate::alias::expand_line(trimmed, env);

    // Tokenise.
    let tokens = match lexer::tokenize(&expanded) {
        Ok(t) => t,
        Err(e) => {
            // Tracing is only available when the `std` feature is enabled.
            // On bare-metal targets the REPL caller handles error reporting.
            #[cfg(feature = "std")]
            tracing::warn!(error = %e, "nexacore-shell: syntax error");
            let _ = e;
            return (1, Vec::new());
        }
    };
    if tokens.is_empty() {
        return (0, Vec::new());
    }

    // Classify intent before execution so the label can be prepended to output
    // and the class is available for the audit record.
    let intent = crate::intent::classify_intent(trimmed);

    // Build the execution context up-front: command substitution needs executor
    // access (to run `$(...)` inner commands and capture their output) before
    // the outer command is parsed.
    let builtins = command::register_builtins();
    let mut ctx = ExecContext {
        env,
        last_exit_code: 0,
        cwd: cwd.clone(),
        fs,
        net,
        output: Vec::new(),
        audit_log: crate::audit::AuditLog::new(),
        stdin: Vec::new(),
        stderr: Vec::new(),
    };

    // Resolve command substitutions `$(...)`, replacing each with the captured
    // output of its inner command before parsing the outer command line.
    let tokens = executor::substitute_tokens(tokens, &mut ctx, &builtins);

    // Parse.
    let ast = match parser::parse(&tokens) {
        Ok(a) => a,
        Err(e) => {
            #[cfg(feature = "std")]
            tracing::warn!(error = %e, "nexacore-shell: parse error");
            let _ = e;
            return (1, Vec::new());
        }
    };
    if ast.entries.is_empty() {
        return (0, Vec::new());
    }

    // Execute (reuses the context built up-front for command substitution).
    let code = executor::execute_command_list(&ast, &mut ctx, &builtins);

    // Propagate cwd changes (the `cd` builtin updates ctx.cwd).
    *cwd = ctx.cwd;

    // Flush captured output to stdout when running on a host with std.
    // On bare-metal targets the caller receives the raw bytes in the returned
    // Vec<u8> and dispatches them via the kernel console/syscall layer.
    #[cfg(feature = "std")]
    if !ctx.output.is_empty() {
        // When NEXACORE_AGENT=1 is set in the shell environment, prepend the
        // intent label so the user can see which agent handled the request.
        if ctx.env.get("NEXACORE_AGENT") == Some("1") {
            print!(
                "{} {}",
                crate::intent::agent_label(intent),
                String::from_utf8_lossy(&ctx.output)
            );
        } else {
            print!("{}", String::from_utf8_lossy(&ctx.output));
        }
    }

    // When NEXACORE_MODE=high-risk is set and the intent is sensitive, emit a
    // structured warning via tracing so the operator is aware of potentially
    // dangerous operations before execution completes.
    #[cfg(feature = "std")]
    if ctx.env.get("NEXACORE_MODE") == Some("high-risk") {
        match intent {
            crate::intent::IntentClass::Administration | crate::intent::IntentClass::Security => {
                tracing::warn!(
                    intent = crate::intent::agent_label(intent),
                    "high-risk mode: sensitive intent detected — review before proceeding"
                );
            }
            _ => {}
        }
    }

    // Record in audit log. Timestamp is 0 in Phase 1 (no HAL clock yet).
    ctx.audit_log.record(trimmed.into(), intent, code, 0);

    (code, ctx.output)
}

// ── Startup script (~/.ossrc) ───────────────────────────────────────────────

/// File name of the per-user shell startup script, resolved under `$HOME`.
const OSSRC_FILENAME: &str = ".ossrc";

/// Outcome of running the `~/.ossrc` startup script.
///
/// Returned by [`run_startup_script`] so the session owner can log or surface a
/// summary of what happened during initialisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupOutcome {
    /// No `~/.ossrc` file was present under the resolved `HOME`. Nothing ran —
    /// this is the normal, silent case for users without a startup script.
    Absent,
    /// The startup script was found and every non-blank, non-comment line was
    /// executed in order against the shared session environment.
    Executed {
        /// Number of command lines that were actually executed (blank lines and
        /// `#` comments are skipped and not counted).
        commands_run: usize,
        /// How many of the executed lines returned a non-zero exit code. Under
        /// the fail-soft policy these do not abort startup.
        failures: usize,
        /// Exit code of the last executed command line (`0` if none ran).
        last_exit_code: i32,
    },
    /// The file was reported present by the directory listing but could not be
    /// read through the [`FsQuery::read_file`] seam. The wrapped string is the
    /// backend diagnostic. Startup fails closed: no lines are executed.
    Unreadable(String),
}

/// Execute the shell startup script `~/.ossrc` against the shared session state.
///
/// This is the host implementation of WS8-10.18. On session init the REPL owner
/// calls this once so that aliases, variables, and exports defined in the user's
/// `~/.ossrc` persist into the interactive session (the same `env` and `cwd` are
/// threaded through, so every side effect is visible afterwards).
///
/// # Resolution
///
/// The script path is `<home>/.ossrc`, where `home` is supplied by the caller
/// (typically `env.get("HOME")`). Presence is probed through the mandatory
/// [`FsQuery::list_dir`] seam; the contents are read through the optional
/// [`FsQuery::read_file`] seam. Both keep this crate kernel-agnostic and fully
/// testable with an in-memory mock.
///
/// # What executes today
///
/// Each line is run as **shell input** through the existing
/// lexer → parser → executor pipeline via [`process_line`], reusing the same
/// grammar and builtins as the interactive prompt. The plan classifies `.ossrc`
/// as an ncScript (WS18) script; full ncScript semantics are **deferred** and
/// intentionally not wired here — this brick does not depend on
/// `nexacore-script`. When ncScript execution lands it can be introduced behind
/// an injectable seam without changing this function's contract.
///
/// # Error policy (POSIX rc-like, fail-soft)
///
/// - **File absent** → clean no-op ([`StartupOutcome::Absent`]).
/// - **File present but unreadable** → fail closed: no lines run, a diagnostic
///   is emitted, and [`StartupOutcome::Unreadable`] is returned (never panics).
/// - **A line fails** (non-zero exit, syntax, or parse error) → a diagnostic is
///   emitted and startup **continues** with the next line, mirroring how POSIX
///   shells treat their rc files. The failure is counted in
///   [`StartupOutcome::Executed::failures`] but does not abort the run.
///
/// Blank lines and `#`-comment lines are skipped (they are also no-ops inside
/// [`process_line`], but skipping them here keeps the executed-line count exact).
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     env::ShellEnv,
///     glob::FsQuery,
///     netquery::NoNet,
///     repl::{StartupOutcome, run_startup_script},
/// };
///
/// struct RcFs;
/// impl FsQuery for RcFs {
///     fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
///         if path == "/home/root" {
///             Ok(vec![".ossrc".into()])
///         } else {
///             Ok(vec![])
///         }
///     }
///     fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
///         if path == "/home/root/.ossrc" {
///             Ok(b"alias ll=ls\nexport EDITOR=nano\n".to_vec())
///         } else {
///             Err("not found".into())
///         }
///     }
/// }
///
/// let mut env = ShellEnv::new();
/// let mut cwd = "/home/root".to_string();
/// let outcome = run_startup_script(&mut env, &mut cwd, &RcFs, &NoNet, "/home/root");
/// assert_eq!(
///     outcome,
///     StartupOutcome::Executed {
///         commands_run: 2,
///         failures: 0,
///         last_exit_code: 0
///     }
/// );
/// // Side effects persist into the shared session environment.
/// assert_eq!(env.get_alias("ll"), Some("ls"));
/// assert_eq!(env.get("EDITOR"), Some("nano"));
/// ```
#[must_use]
pub fn run_startup_script(
    env: &mut ShellEnv,
    cwd: &mut String,
    fs: &dyn FsQuery,
    net: &dyn NetQuery,
    home: &str,
) -> StartupOutcome {
    let path = ossrc_path(home);

    // Probe presence via the directory-listing seam so an absent rc file is a
    // silent no-op (and is distinguishable from a present-but-unreadable file).
    let present = fs
        .list_dir(home)
        .map(|entries| entries.iter().any(|e| e == OSSRC_FILENAME))
        .unwrap_or(false);
    if !present {
        return StartupOutcome::Absent;
    }

    // Read the file through the I/O seam. Fail closed on any read error.
    let bytes = match fs.read_file(&path) {
        Ok(b) => b,
        Err(e) => {
            #[cfg(feature = "std")]
            tracing::warn!(path = %path, error = %e, "nexacore-shell: cannot read ~/.ossrc");
            return StartupOutcome::Unreadable(e);
        }
    };

    let content = String::from_utf8_lossy(&bytes);
    let mut commands_run = 0usize;
    let mut failures = 0usize;
    let mut last_exit_code = 0i32;

    for line in content.lines() {
        let trimmed = line.trim();
        // Skip blanks and comments without counting them as executed commands.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (code, _output) = process_line(line, env, cwd, fs, net);
        commands_run += 1;
        last_exit_code = code;

        if code != 0 {
            failures += 1;
            // Fail-soft: report the offending line but continue with the rest,
            // matching POSIX shell rc-file semantics.
            #[cfg(feature = "std")]
            tracing::warn!(
                line = %trimmed,
                exit_code = code,
                "nexacore-shell: ~/.ossrc line failed; continuing"
            );
        }
    }

    StartupOutcome::Executed {
        commands_run,
        failures,
        last_exit_code,
    }
}

/// Join `home` and [`OSSRC_FILENAME`] into an absolute `~/.ossrc` path.
///
/// A trailing `/` on `home` is normalised away so that a root `HOME` of `"/"`
/// yields `"/.ossrc"` rather than `"//.ossrc"`.
fn ossrc_path(home: &str) -> String {
    let base = home.trim_end_matches('/');
    format!("{base}/{OSSRC_FILENAME}")
}

// ── Shell ─────────────────────────────────────────────────────────────────────

/// The interactive shell instance.
///
/// Bundles together:
/// - The runtime environment ([`crate::env::ShellEnv`]).
/// - The interactive line editor ([`crate::line_editor::LineEditor`]).
/// - The current working directory.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::repl::Shell;
///
/// let shell = Shell::new();
/// assert_eq!(shell.cwd, "/");
/// ```
pub struct Shell {
    /// The shell's variable, alias, and export environment.
    pub env: ShellEnv,
    /// The interactive line editor (history, key bindings, rendering).
    pub editor: LineEditor,
    /// Current working directory; kept in sync with `$PWD`.
    pub cwd: String,
    /// Session command history (bounded ring buffer).
    pub history: History,
    /// Background job table.
    pub jobs: JobTable,
}

impl Shell {
    /// Create a new shell with default environment, a fresh line editor, and
    /// the root directory as the initial working directory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::repl::Shell;
    ///
    /// let shell = Shell::new();
    /// assert_eq!(shell.cwd, "/");
    /// assert_eq!(shell.env.get("HOME"), Some("/"));
    /// ```
    pub fn new() -> Self {
        Self {
            env: ShellEnv::new(),
            editor: LineEditor::new(),
            cwd: String::from("/"),
            history: History::new(DEFAULT_HISTORY_CAPACITY),
            jobs: JobTable::new(),
        }
    }

    /// Run one input line through the shell, recording it in the session
    /// history first.
    ///
    /// This is the session-level entry point that wires the [`History`] ring
    /// buffer into the pipeline: non-blank, non-comment lines are pushed into
    /// [`Shell::history`] (with consecutive-duplicate dedup) before being
    /// dispatched through [`process_line`] against the shell's own `env`/`cwd`.
    /// Blank lines and `#`-comments are neither stored nor executed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::{glob::FsQuery, netquery::NoNet, repl::Shell};
    ///
    /// struct EmptyFs;
    /// impl FsQuery for EmptyFs {
    ///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
    ///         Ok(vec![])
    ///     }
    /// }
    ///
    /// let mut shell = Shell::new();
    /// let (code, _out) = shell.run_line("echo hi", &EmptyFs, &NoNet);
    /// assert_eq!(code, 0);
    /// assert_eq!(shell.history.get(0), Some("echo hi"));
    /// ```
    pub fn run_line(
        &mut self,
        input: &str,
        fs: &dyn FsQuery,
        net: &dyn NetQuery,
    ) -> (i32, Vec<u8>) {
        let trimmed = input.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            self.history.push(trimmed);
        }
        process_line(input, &mut self.env, &mut self.cwd, fs, net)
    }

    /// Run the `~/.ossrc` startup script once, at the start of a live session.
    ///
    /// This is the opt-in init hook for WS8-10.18. A real interactive session
    /// calls it exactly once after constructing the [`Shell`] and before reading
    /// the first prompt line, so that startup aliases/variables/exports are in
    /// effect for the session. Non-interactive callers and tests that do not
    /// want startup side effects simply do not call it (the constructor stays
    /// side-effect free).
    ///
    /// `HOME` is read from the shell environment (falling back to `/`), and the
    /// script is executed against `self.env`/`self.cwd` via
    /// [`run_startup_script`]. See that function for the full error policy.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::{
    ///     glob::FsQuery,
    ///     netquery::NoNet,
    ///     repl::{Shell, StartupOutcome},
    /// };
    ///
    /// struct EmptyFs;
    /// impl FsQuery for EmptyFs {
    ///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
    ///         Ok(vec![])
    ///     }
    /// }
    ///
    /// let mut shell = Shell::new();
    /// // No ~/.ossrc under the default HOME ("/") → clean no-op.
    /// assert_eq!(shell.run_startup(&EmptyFs, &NoNet), StartupOutcome::Absent);
    /// ```
    #[must_use]
    pub fn run_startup(&mut self, fs: &dyn FsQuery, net: &dyn NetQuery) -> StartupOutcome {
        let home = self.env.get("HOME").unwrap_or("/").to_string();
        run_startup_script(&mut self.env, &mut self.cwd, fs, net, &home)
    }
}

impl Default for Shell {
    /// Create a default shell identical to [`Shell::new`].
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{glob::FsQuery, netquery::NoNet};

    // ── Mock filesystem ───────────────────────────────────────────────────

    struct EmptyFs;
    impl FsQuery for EmptyFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
    }

    /// A mock filesystem holding a single `~/.ossrc` under a known home dir.
    ///
    /// `home` is the directory that lists `.ossrc`; `contents` is what
    /// `read_file` returns for `<home>/.ossrc`. When `contents` is `None` the
    /// file is listed as present but reading it fails (unreadable case).
    struct RcFs {
        home: &'static str,
        contents: Option<&'static str>,
    }

    impl FsQuery for RcFs {
        fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
            if path == self.home {
                Ok(vec![".ossrc".into(), "notes.txt".into()])
            } else {
                Ok(vec![])
            }
        }

        fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
            let expected = if self.home == "/" {
                "/.ossrc".to_string()
            } else {
                format!("{}/.ossrc", self.home)
            };
            if path == expected {
                self.contents
                    .map(|c| c.as_bytes().to_vec())
                    .ok_or_else(|| "permission denied".to_string())
            } else {
                Err(format!("no such file: {path}"))
            }
        }
    }

    // ── format_prompt ─────────────────────────────────────────────────────

    #[test]
    fn format_prompt_default_format() {
        let env = ShellEnv::new(); // USER=root, no HOSTNAME, no PS1
        let prompt = format_prompt(&env, "/home/root");
        assert!(prompt.starts_with("root@"), "prompt was: {prompt:?}");
        assert!(prompt.contains("/home/root"), "prompt was: {prompt:?}");
        assert!(prompt.ends_with("$ "), "prompt was: {prompt:?}");
    }

    #[test]
    fn format_prompt_with_ps1_variable() {
        let mut env = ShellEnv::new();
        env.set("PS1", "\\u@\\h:\\w\\$ ");
        env.set("USER", "alice");
        env.set("HOSTNAME", "box");
        let prompt = format_prompt(&env, "/tmp");
        assert_eq!(prompt, "alice@box:/tmp$ ");
    }

    #[test]
    fn format_prompt_ps1_partial_escapes() {
        let mut env = ShellEnv::new();
        env.set("PS1", "[\\w]\\$ ");
        let prompt = format_prompt(&env, "/srv");
        assert_eq!(prompt, "[/srv]$ ");
    }

    // ── process_line ──────────────────────────────────────────────────────

    #[test]
    fn process_line_empty_returns_zero() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, output) = process_line("", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert!(output.is_empty());
    }

    #[test]
    fn process_line_whitespace_only_returns_zero() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, output) = process_line("   \t  ", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert!(output.is_empty());
    }

    #[test]
    fn process_line_comment_returns_zero() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, output) =
            process_line("# this is a comment", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert!(output.is_empty());
    }

    #[test]
    fn process_line_echo_returns_zero() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, output) = process_line("echo hello", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        // echo writes to the output buffer; the buffer should contain the word.
        assert!(String::from_utf8_lossy(&output).contains("hello"));
    }

    #[test]
    fn process_line_true_returns_zero() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, _output) = process_line("true", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
    }

    #[test]
    fn process_line_false_returns_one() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, _output) = process_line("false", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 1);
    }

    #[test]
    fn process_line_cd_changes_cwd() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, _output) = process_line("cd /tmp", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert_eq!(cwd, "/tmp");
    }

    #[test]
    fn process_line_unknown_command_returns_127() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, _output) = process_line(
            "totally_unknown_cmd_xyz",
            &mut env,
            &mut cwd,
            &EmptyFs,
            &NoNet,
        );
        assert_eq!(code, 127);
    }

    #[test]
    fn process_line_with_variable_expansion() {
        let mut env = ShellEnv::new();
        env.set("MYVAR", "expanded");
        let mut cwd = "/".to_string();
        // echo $MYVAR — the value is expanded before execution.
        let (code, output) = process_line("echo $MYVAR", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&output).contains("expanded"));
    }

    #[test]
    fn process_line_and_chaining() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        // true && true should return 0.
        let (code, _output) = process_line("true && true", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
    }

    #[test]
    fn process_line_or_chaining_after_failure() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        // false || true should return 0.
        let (code, _output) = process_line("false || true", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
    }

    #[test]
    fn process_line_expands_leading_alias() {
        let mut env = ShellEnv::new();
        env.set_alias("say", "echo");
        let mut cwd = "/".to_string();
        let (code, output) = process_line("say hello", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&output).contains("hello"));
    }

    #[test]
    fn process_line_does_not_expand_quoted_alias() {
        let mut env = ShellEnv::new();
        env.set_alias("say", "echo");
        let mut cwd = "/".to_string();
        // A quoted first word is not an alias reference, so `say` runs as a
        // (missing) command → 127, proving no expansion happened.
        let (code, _output) = process_line("'say' hello", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 127);
    }

    #[test]
    fn process_line_command_substitution() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let (code, output) = process_line("echo $(echo hi)", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&output).trim(), "hi");
    }

    #[test]
    fn process_line_command_substitution_single_quoted_literal() {
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        // Single quotes keep `$(...)` literal.
        let (code, output) =
            process_line("echo '$(echo hi)'", &mut env, &mut cwd, &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&output).trim(), "$(echo hi)");
    }

    // ── Shell struct ──────────────────────────────────────────────────────

    #[test]
    fn shell_new_has_root_cwd() {
        let shell = Shell::new();
        assert_eq!(shell.cwd, "/");
    }

    #[test]
    fn shell_new_has_empty_history_and_jobs() {
        let shell = Shell::new();
        assert!(shell.history.is_empty());
        assert!(shell.jobs.jobs().is_empty());
    }

    #[test]
    fn shell_run_line_records_history() {
        let mut shell = Shell::new();
        let (code, _output) = shell.run_line("echo hi", &EmptyFs, &NoNet);
        assert_eq!(code, 0);
        assert_eq!(shell.history.len(), 1);
        assert_eq!(shell.history.get(0), Some("echo hi"));
    }

    #[test]
    fn shell_run_line_skips_blank_and_comment_from_history() {
        let mut shell = Shell::new();
        shell.run_line("   ", &EmptyFs, &NoNet);
        shell.run_line("# a comment", &EmptyFs, &NoNet);
        assert!(shell.history.is_empty());
    }

    #[test]
    fn shell_new_has_default_home() {
        let shell = Shell::new();
        assert_eq!(shell.env.get("HOME"), Some("/"));
    }

    #[test]
    fn shell_default_equals_new() {
        let a = Shell::new();
        let b = Shell::default();
        assert_eq!(a.cwd, b.cwd);
        assert_eq!(a.env.get("USER"), b.env.get("USER"));
    }

    // ── run_startup_script (~/.ossrc) ─────────────────────────────────────

    #[test]
    fn ossrc_absent_is_clean_noop() {
        let mut env = ShellEnv::new();
        let mut cwd = "/home/root".to_string();
        // EmptyFs never lists ".ossrc", so the file is absent.
        let outcome = run_startup_script(&mut env, &mut cwd, &EmptyFs, &NoNet, "/home/root");
        assert_eq!(outcome, StartupOutcome::Absent);
    }

    #[test]
    fn ossrc_present_sets_alias_and_var_that_persist() {
        let fs = RcFs {
            home: "/home/root",
            contents: Some("alias ll=ls\nexport EDITOR=nano\nexport MYVAR=42\n"),
        };
        let mut env = ShellEnv::new();
        let mut cwd = "/home/root".to_string();
        let outcome = run_startup_script(&mut env, &mut cwd, &fs, &NoNet, "/home/root");
        assert_eq!(
            outcome,
            StartupOutcome::Executed {
                commands_run: 3,
                failures: 0,
                last_exit_code: 0,
            }
        );
        // Side effects persist into the shared session environment.
        assert_eq!(env.get_alias("ll"), Some("ls"));
        assert_eq!(env.get("EDITOR"), Some("nano"));
        assert!(env.is_exported("EDITOR"));
        assert_eq!(env.get("MYVAR"), Some("42"));
    }

    #[test]
    fn ossrc_skips_blank_and_comment_lines() {
        let fs = RcFs {
            home: "/home/root",
            contents: Some("# a comment\n\n   \nexport TZ=UTC\n# trailing comment\n"),
        };
        let mut env = ShellEnv::new();
        let mut cwd = "/home/root".to_string();
        let outcome = run_startup_script(&mut env, &mut cwd, &fs, &NoNet, "/home/root");
        // Only the single `export` line counts as an executed command.
        assert_eq!(
            outcome,
            StartupOutcome::Executed {
                commands_run: 1,
                failures: 0,
                last_exit_code: 0,
            }
        );
        assert_eq!(env.get("TZ"), Some("UTC"));
    }

    #[test]
    fn ossrc_bad_line_reports_but_continues() {
        // First line fails (unknown command → 127); the second must still run.
        let fs = RcFs {
            home: "/home/root",
            contents: Some("totally_unknown_cmd_xyz\nexport SURVIVED=yes\n"),
        };
        let mut env = ShellEnv::new();
        let mut cwd = "/home/root".to_string();
        let outcome = run_startup_script(&mut env, &mut cwd, &fs, &NoNet, "/home/root");
        assert_eq!(
            outcome,
            StartupOutcome::Executed {
                commands_run: 2,
                failures: 1,
                last_exit_code: 0,
            }
        );
        // Fail-soft: the line after the failing one still took effect.
        assert_eq!(env.get("SURVIVED"), Some("yes"));
    }

    #[test]
    fn ossrc_unreadable_file_fails_closed() {
        let fs = RcFs {
            home: "/home/root",
            contents: None, // listed as present, but read_file errors.
        };
        let mut env = ShellEnv::new();
        let mut cwd = "/home/root".to_string();
        let outcome = run_startup_script(&mut env, &mut cwd, &fs, &NoNet, "/home/root");
        assert_eq!(
            outcome,
            StartupOutcome::Unreadable("permission denied".to_string())
        );
    }

    #[test]
    fn ossrc_respects_provided_home() {
        // The file lives under /custom/home; a different HOME must not find it.
        let fs = RcFs {
            home: "/custom/home",
            contents: Some("alias g=grep\n"),
        };
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();

        // Wrong home → absent.
        let wrong = run_startup_script(&mut env, &mut cwd, &fs, &NoNet, "/home/root");
        assert_eq!(wrong, StartupOutcome::Absent);
        assert_eq!(env.get_alias("g"), None);

        // Correct home → executes and the alias persists.
        let right = run_startup_script(&mut env, &mut cwd, &fs, &NoNet, "/custom/home");
        assert_eq!(
            right,
            StartupOutcome::Executed {
                commands_run: 1,
                failures: 0,
                last_exit_code: 0,
            }
        );
        assert_eq!(env.get_alias("g"), Some("grep"));
    }

    #[test]
    fn ossrc_root_home_resolves_without_double_slash() {
        // HOME="/" must resolve the script to "/.ossrc", not "//.ossrc".
        let fs = RcFs {
            home: "/",
            contents: Some("export ROOTRC=1\n"),
        };
        let mut env = ShellEnv::new();
        let mut cwd = "/".to_string();
        let outcome = run_startup_script(&mut env, &mut cwd, &fs, &NoNet, "/");
        assert_eq!(
            outcome,
            StartupOutcome::Executed {
                commands_run: 1,
                failures: 0,
                last_exit_code: 0,
            }
        );
        assert_eq!(env.get("ROOTRC"), Some("1"));
    }

    #[test]
    fn shell_run_startup_reads_home_from_env() {
        let fs = RcFs {
            home: "/home/alice",
            contents: Some("alias la=ls\n"),
        };
        let mut shell = Shell::new();
        shell.env.set("HOME", "/home/alice");
        let outcome = shell.run_startup(&fs, &NoNet);
        assert_eq!(
            outcome,
            StartupOutcome::Executed {
                commands_run: 1,
                failures: 0,
                last_exit_code: 0,
            }
        );
        assert_eq!(shell.env.get_alias("la"), Some("ls"));
    }

    #[test]
    fn default_fsquery_read_file_fails_closed() {
        // EmptyFs does not override read_file → default returns Err.
        let result = EmptyFs.read_file("/anything");
        assert!(result.is_err());
    }
}

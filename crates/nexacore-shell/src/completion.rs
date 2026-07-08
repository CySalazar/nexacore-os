//! Tab-completion engine.
//!
//! Provides context-sensitive completion for command names, filesystem paths,
//! and environment-variable names. The engine is consumed by the REPL, which
//! passes raw buffer/cursor state and wires together the environment and
//! filesystem query.
//!
//! ## Completion contexts
//!
//! | Context | Triggered when |
//! |---|---|
//! | [`crate::completion::CompletionContext::Command`] | The word under the cursor is the first token on the line. |
//! | [`crate::completion::CompletionContext::FilePath`] | Any subsequent word position. |
//! | [`crate::completion::CompletionContext::Variable`] | The word starts with `$`. |
//!
//! ## Algorithm
//!
//! 1. [`crate::completion::detect_context`] scans backwards from `cursor` to find the current
//!    word and classify it.
//! 2. [`crate::completion::complete`] dispatches to the appropriate completion strategy and
//!    collects candidates:
//!    - **Command**: built-ins list + each directory on `$PATH` (via
//!      [`crate::glob::FsQuery::list_dir`]).
//!    - **FilePath**: split `partial` into directory/prefix, list the
//!      directory, filter by prefix.
//!    - **Variable**: iterate environment variable names, filter by prefix.
//! 3. Candidates are sorted and deduplicated before being returned.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{env::ShellEnv, glob::FsQuery};

// ── CompletionContext ─────────────────────────────────────────────────────────

/// The semantic context in which tab completion is being requested.
///
/// [`detect_context`] derives this from the buffer content and cursor position.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::completion::{CompletionContext, detect_context};
///
/// // First word → command context.
/// let (ctx, partial) = detect_context("ls", 2);
/// assert_eq!(ctx, CompletionContext::Command);
/// assert_eq!(partial, "ls");
///
/// // Second word → file path context.
/// let (ctx2, partial2) = detect_context("ls /sr", 6);
/// assert_eq!(ctx2, CompletionContext::FilePath);
/// assert_eq!(partial2, "/sr");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionContext {
    /// Completing a command name — the first token on the current line.
    Command,
    /// Completing a file or directory path — any token after the first.
    FilePath,
    /// Completing an environment-variable name — word starts with `$`.
    Variable,
}

// ── CompletionResult ──────────────────────────────────────────────────────────

/// The outcome of a [`complete`] call.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     completion::{CompletionContext, CompletionResult, complete},
///     env::ShellEnv,
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
/// let result = complete(
///     "xyz_nonexistent",
///     CompletionContext::Command,
///     &env,
///     &[],
///     &EmptyFs,
///     "/",
/// );
/// assert_eq!(result, CompletionResult::None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionResult {
    /// No completions matched the partial input.
    None,
    /// Exactly one completion was found — the REPL should insert it.
    Single(String),
    /// Multiple completions are available — the REPL should display the list.
    Multiple(Vec<String>),
}

// ── detect_context ────────────────────────────────────────────────────────────

/// Determine the completion context and the partial word at `cursor`.
///
/// Scans the `buffer` backwards from `cursor` to extract the word being
/// completed and classify it:
///
/// - If the word starts with `$`, returns [`CompletionContext::Variable`] and
///   the rest of the word after `$` as the partial string.
/// - If there are no non-whitespace characters before the word on the current
///   line (i.e., it is the first token), returns [`CompletionContext::Command`].
/// - Otherwise returns [`CompletionContext::FilePath`].
///
/// "Word" is defined as a maximal sequence of non-whitespace, non-operator
/// characters ending at `cursor`. The set of operator characters is
/// `|`, `&`, `;`, `<`, `>` — the same characters that the lexer emits as
/// operator tokens.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::completion::{CompletionContext, detect_context};
///
/// // First token → Command.
/// let (ctx, p) = detect_context("ec", 2);
/// assert_eq!(ctx, CompletionContext::Command);
/// assert_eq!(p, "ec");
///
/// // Second token → FilePath.
/// let (ctx2, p2) = detect_context("cat /etc/pa", 11);
/// assert_eq!(ctx2, CompletionContext::FilePath);
/// assert_eq!(p2, "/etc/pa");
///
/// // Dollar sign → Variable.
/// let (ctx3, p3) = detect_context("echo $HO", 8);
/// assert_eq!(ctx3, CompletionContext::Variable);
/// assert_eq!(p3, "HO");
/// ```
pub fn detect_context(buffer: &str, cursor: usize) -> (CompletionContext, String) {
    // Clamp cursor to buffer length to avoid panics on out-of-range input.
    let cursor = cursor.min(buffer.len());
    let slice = &buffer[..cursor];

    // Walk backwards to find the start of the current word.
    let word_start = slice
        .rfind(|c: char| c.is_whitespace() || is_operator_char(c))
        .map_or(0, |i| i + 1);

    let partial: String = slice[word_start..].to_string();

    // Check for variable context: word starts with '$'.
    if partial.starts_with('$') {
        let var_partial = partial.trim_start_matches('$').to_string();
        return (CompletionContext::Variable, var_partial);
    }

    // Check if this is the first non-whitespace token on the (logical) line.
    // We look for whether there is any non-whitespace content before `word_start`
    // since the last operator or line boundary.
    let before_word = &slice[..word_start];
    let is_first_token = before_word
        .chars()
        .rev()
        .take_while(|&c| !is_operator_char(c))
        .all(char::is_whitespace);

    if is_first_token {
        (CompletionContext::Command, partial)
    } else {
        (CompletionContext::FilePath, partial)
    }
}

// ── complete ──────────────────────────────────────────────────────────────────

/// Perform tab completion for `partial` in the given `context`.
///
/// # Parameters
///
/// - `partial` — the word fragment being completed (already extracted by
///   [`detect_context`]).
/// - `context` — the semantic context (command, file path, or variable).
/// - `env` — shell environment; used for `$PATH` resolution and variable names.
/// - `builtins` — list of built-in command names (e.g. `&["cd", "exit"]`).
/// - `fs` — filesystem query implementation.
/// - `cwd` — current working directory; used as the base for relative paths.
///
/// # Returns
///
/// - [`CompletionResult::None`] if no candidates match.
/// - [`CompletionResult::Single`] if exactly one candidate matches.
/// - [`CompletionResult::Multiple`] if more than one candidate matches,
///   containing all candidates sorted alphabetically.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     completion::{CompletionContext, CompletionResult, complete},
///     env::ShellEnv,
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
/// // Single builtin match.
/// let result = complete(
///     "ex",
///     CompletionContext::Command,
///     &env,
///     &["exit", "export"],
///     &EmptyFs,
///     "/",
/// );
/// assert_eq!(
///     result,
///     CompletionResult::Multiple(vec!["exit".into(), "export".into()])
/// );
///
/// // Exact single match.
/// let single = complete(
///     "exi",
///     CompletionContext::Command,
///     &env,
///     &["exit", "export"],
///     &EmptyFs,
///     "/",
/// );
/// assert_eq!(single, CompletionResult::Single("exit".into()));
/// ```
pub fn complete(
    partial: &str,
    context: CompletionContext,
    env: &ShellEnv,
    builtins: &[&str],
    fs: &dyn FsQuery,
    cwd: &str,
) -> CompletionResult {
    let candidates = match context {
        CompletionContext::Command => complete_command(partial, env, builtins, fs),
        CompletionContext::FilePath => complete_filepath(partial, env, fs, cwd),
        CompletionContext::Variable => complete_variable(partial, env),
    };

    to_result(candidates)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `c` is a shell operator character that delimits words.
#[inline]
fn is_operator_char(c: char) -> bool {
    matches!(c, '|' | '&' | ';' | '<' | '>')
}

/// Collect command completion candidates.
///
/// Searches:
/// 1. The built-ins list.
/// 2. Every directory listed in `$PATH` (colon-separated), querying
///    [`FsQuery::list_dir`] for each.
///
/// All candidates that start with `partial` (case-sensitive) are included.
/// Results are sorted and deduplicated.
fn complete_command(
    partial: &str,
    env: &ShellEnv,
    builtins: &[&str],
    fs: &dyn FsQuery,
) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();

    // Built-ins.
    for &b in builtins {
        if b.starts_with(partial) {
            candidates.push(b.to_string());
        }
    }

    // PATH directories.
    let path_var = env.get("PATH").unwrap_or("");
    for dir in path_var.split(':').filter(|d| !d.is_empty()) {
        if let Ok(entries) = fs.list_dir(dir) {
            for entry in entries {
                if entry.starts_with(partial) {
                    candidates.push(entry);
                }
            }
        }
    }

    // Sort and deduplicate.
    candidates.sort();
    candidates.dedup();
    candidates
}

/// Collect file-path completion candidates.
///
/// Splits `partial` into a directory component and a filename prefix:
/// - If `partial` contains `/`, the directory is everything up to (and
///   including) the last `/`, and the prefix is everything after.
/// - Otherwise the directory is `cwd`.
///
/// The directory is listed via [`FsQuery::list_dir`] and entries are filtered
/// by prefix match. Full paths are returned (directory + filename).
fn complete_filepath(partial: &str, _env: &ShellEnv, fs: &dyn FsQuery, cwd: &str) -> Vec<String> {
    let (dir, prefix) = partial.rfind('/').map_or_else(
        || {
            (
                format!("{}/", cwd.trim_end_matches('/')),
                partial.to_string(),
            )
        },
        |slash_pos| {
            let dir_part = &partial[..=slash_pos]; // includes the trailing '/'
            let file_prefix = &partial[slash_pos + 1..];
            (dir_part.to_string(), file_prefix.to_string())
        },
    );

    // Trim the trailing slash for the FS query (some implementations may not want it).
    let query_dir = dir.trim_end_matches('/');
    let query_dir = if query_dir.is_empty() { "/" } else { query_dir };

    let Ok(entries) = fs.list_dir(query_dir) else {
        return Vec::new();
    };

    let mut candidates: Vec<String> = entries
        .into_iter()
        .filter(|name| name.starts_with(prefix.as_str()))
        .map(|name| format!("{dir}{name}"))
        .collect();

    candidates.sort();
    candidates
}

/// Collect environment-variable name completion candidates.
///
/// Filters variable names from `env` that start with `partial`.
fn complete_variable(partial: &str, env: &ShellEnv) -> Vec<String> {
    let mut candidates: Vec<String> = env
        .all_vars()
        .keys()
        .filter(|name| name.starts_with(partial))
        .cloned()
        .collect();

    candidates.sort();
    candidates
}

/// Convert a sorted candidate list into a [`CompletionResult`].
fn to_result(mut candidates: Vec<String>) -> CompletionResult {
    match candidates.len() {
        0 => CompletionResult::None,
        // `candidates.len() == 1` is verified above; `remove(0)` is safe.
        1 => CompletionResult::Single(candidates.remove(0)),
        _ => CompletionResult::Multiple(candidates),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{env::ShellEnv, glob::FsQuery};

    // ── Mock filesystem ───────────────────────────────────────────────────────

    struct MockFs {
        entries: Vec<(String, Vec<String>)>,
    }

    impl MockFs {
        /// Build a mock FS. Pass pairs of `(directory, [entries...])`.
        fn new(dirs: &[(&str, &[&str])]) -> Self {
            Self {
                entries: dirs
                    .iter()
                    .map(|(d, es)| {
                        (
                            (*d).to_string(),
                            es.iter().map(|e| (*e).to_string()).collect(),
                        )
                    })
                    .collect(),
            }
        }
    }

    impl FsQuery for MockFs {
        fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
            for (dir, entries) in &self.entries {
                if dir == path {
                    return Ok(entries.clone());
                }
            }
            Err(format!("not found: {path}"))
        }
    }

    // ── detect_context ────────────────────────────────────────────────────────

    #[test]
    fn detect_context_first_token_is_command() {
        let (ctx, partial) = detect_context("ls", 2);
        assert_eq!(ctx, CompletionContext::Command);
        assert_eq!(partial, "ls");
    }

    #[test]
    fn detect_context_second_token_is_filepath() {
        let (ctx, partial) = detect_context("ls /sr", 6);
        assert_eq!(ctx, CompletionContext::FilePath);
        assert_eq!(partial, "/sr");
    }

    #[test]
    fn detect_context_variable_after_dollar() {
        let (ctx, partial) = detect_context("echo $HO", 8);
        assert_eq!(ctx, CompletionContext::Variable);
        assert_eq!(partial, "HO");
    }

    #[test]
    fn detect_context_empty_buffer_is_command() {
        let (ctx, partial) = detect_context("", 0);
        assert_eq!(ctx, CompletionContext::Command);
        assert_eq!(partial, "");
    }

    #[test]
    fn detect_context_after_pipe_is_command() {
        // After `|` the next word is a command.
        let buf = "ls | gr";
        let (ctx, partial) = detect_context(buf, buf.len());
        assert_eq!(ctx, CompletionContext::Command);
        assert_eq!(partial, "gr");
    }

    #[test]
    fn detect_context_after_semicolon_is_command() {
        let buf = "cd /tmp; ec";
        let (ctx, partial) = detect_context(buf, buf.len());
        assert_eq!(ctx, CompletionContext::Command);
        assert_eq!(partial, "ec");
    }

    #[test]
    fn detect_context_cursor_in_middle_of_buffer() {
        // Cursor at position 7 → before = "ls /src", partial = "/src".
        let buf = "ls /src/main.rs";
        let (ctx, partial) = detect_context(buf, 7);
        assert_eq!(ctx, CompletionContext::FilePath);
        assert_eq!(partial, "/src");
    }

    // ── complete: Command ─────────────────────────────────────────────────────

    #[test]
    fn complete_command_matches_builtin_prefix() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete(
            "exi",
            CompletionContext::Command,
            &env,
            &["exit", "export"],
            &fs,
            "/",
        );
        assert_eq!(result, CompletionResult::Single("exit".into()));
    }

    #[test]
    fn complete_command_multiple_builtin_matches() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete(
            "ex",
            CompletionContext::Command,
            &env,
            &["exit", "export", "echo"],
            &fs,
            "/",
        );
        assert_eq!(
            result,
            CompletionResult::Multiple(vec!["exit".into(), "export".into()])
        );
    }

    #[test]
    fn complete_command_no_match_returns_none() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete(
            "xyz_nope",
            CompletionContext::Command,
            &env,
            &["exit", "cd"],
            &fs,
            "/",
        );
        assert_eq!(result, CompletionResult::None);
    }

    #[test]
    fn complete_command_searches_path_directories() {
        let mut env = ShellEnv::new();
        env.set("PATH", "/bin");
        let fs = MockFs::new(&[("/bin", &["ls", "lsblk", "cat"])]);
        let result = complete("ls", CompletionContext::Command, &env, &[], &fs, "/");
        assert_eq!(
            result,
            CompletionResult::Multiple(vec!["ls".into(), "lsblk".into()])
        );
    }

    #[test]
    fn complete_command_empty_partial_matches_all_builtins() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete(
            "",
            CompletionContext::Command,
            &env,
            &["cd", "exit", "pwd"],
            &fs,
            "/",
        );
        match result {
            CompletionResult::Multiple(v) => {
                assert!(v.contains(&"cd".to_string()));
                assert!(v.contains(&"exit".to_string()));
                assert!(v.contains(&"pwd".to_string()));
            }
            _ => panic!("expected Multiple"),
        }
    }

    // ── complete: FilePath ────────────────────────────────────────────────────

    #[test]
    fn complete_filepath_matches_prefix_in_cwd() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[("/home", &["alpha.txt", "beta.txt", "gamma.rs"])]);
        let result = complete("al", CompletionContext::FilePath, &env, &[], &fs, "/home");
        assert_eq!(
            result,
            CompletionResult::Single("/home/al".to_string() + "pha.txt")
        );
    }

    #[test]
    fn complete_filepath_absolute_path_split() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[("/etc", &["passwd", "profile", "hosts"])]);
        let result = complete("/etc/pa", CompletionContext::FilePath, &env, &[], &fs, "/");
        assert_eq!(result, CompletionResult::Single("/etc/passwd".into()));
    }

    #[test]
    fn complete_filepath_multiple_matches() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[("/src", &["main.rs", "lib.rs", "util.rs"])]);
        let result = complete("/src/", CompletionContext::FilePath, &env, &[], &fs, "/");
        match result {
            CompletionResult::Multiple(v) => {
                assert_eq!(v.len(), 3);
                assert!(v.contains(&"/src/main.rs".to_string()));
            }
            _ => panic!("expected Multiple"),
        }
    }

    #[test]
    fn complete_filepath_no_match_returns_none() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[("/src", &["main.rs"])]);
        let result = complete(
            "/src/no_match",
            CompletionContext::FilePath,
            &env,
            &[],
            &fs,
            "/",
        );
        assert_eq!(result, CompletionResult::None);
    }

    // ── complete: Variable ────────────────────────────────────────────────────

    #[test]
    fn complete_variable_matches_prefix() {
        let mut env = ShellEnv::new();
        env.set("HOME", "/root");
        env.set("HOSTNAME", "nexacore");
        env.set("USER", "root");
        let fs = MockFs::new(&[]);
        let result = complete("HO", CompletionContext::Variable, &env, &[], &fs, "/");
        match result {
            CompletionResult::Multiple(v) => {
                assert!(v.contains(&"HOME".to_string()));
                assert!(v.contains(&"HOSTNAME".to_string()));
                assert!(!v.contains(&"USER".to_string()));
            }
            _ => panic!("expected Multiple"),
        }
    }

    #[test]
    fn complete_variable_single_match() {
        let mut env = ShellEnv::new();
        // Remove defaults that might interfere, set only our test var.
        env.set("MYVAR", "value");
        // Remove all default env vars that start with "MY" — there are none
        // by default, so this test is clean.
        let fs = MockFs::new(&[]);
        let result = complete("MYVAR", CompletionContext::Variable, &env, &[], &fs, "/");
        assert_eq!(result, CompletionResult::Single("MYVAR".into()));
    }

    #[test]
    fn complete_variable_no_match() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete(
            "ZZZNOTEXIST",
            CompletionContext::Variable,
            &env,
            &[],
            &fs,
            "/",
        );
        assert_eq!(result, CompletionResult::None);
    }

    #[test]
    fn complete_variable_empty_partial_matches_all() {
        let mut env = ShellEnv::new();
        env.set("ALPHA", "a");
        env.set("BETA", "b");
        let fs = MockFs::new(&[]);
        let result = complete("", CompletionContext::Variable, &env, &[], &fs, "/");
        match result {
            CompletionResult::Multiple(v) => {
                assert!(v.contains(&"ALPHA".to_string()));
                assert!(v.contains(&"BETA".to_string()));
            }
            CompletionResult::Single(s) => {
                // Acceptable if only one var is present (from defaults or the two set above).
                // The ShellEnv::new() sets HOME, PATH, USER, PWD — so we have at least 6 vars.
                // This arm should not be reached.
                panic!("unexpected single: {s}");
            }
            CompletionResult::None => panic!("expected some results"),
        }
    }

    // ── CompletionResult variants ─────────────────────────────────────────────

    #[test]
    fn single_result_is_returned_as_single() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete(
            "exit",
            CompletionContext::Command,
            &env,
            &["exit"],
            &fs,
            "/",
        );
        assert_eq!(result, CompletionResult::Single("exit".into()));
    }

    #[test]
    fn no_result_is_returned_as_none() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete("zzz", CompletionContext::Command, &env, &[], &fs, "/");
        assert_eq!(result, CompletionResult::None);
    }

    #[test]
    fn multiple_results_are_sorted() {
        let env = ShellEnv::new();
        let fs = MockFs::new(&[]);
        let result = complete(
            "e",
            CompletionContext::Command,
            &env,
            &["exit", "echo", "export", "eval"],
            &fs,
            "/",
        );
        match result {
            CompletionResult::Multiple(v) => {
                let sorted = {
                    let mut s = v.clone();
                    s.sort();
                    s
                };
                assert_eq!(v, sorted);
            }
            _ => panic!("expected Multiple"),
        }
    }
}

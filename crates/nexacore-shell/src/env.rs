//! Environment variable resolution and expansion for the NexaCore shell.
//!
//! This module provides [`crate::env::ShellEnv`], the runtime variable store for an
//! interactive shell session. It tracks:
//!
//! - Named shell variables (exported or not).
//! - The exit code of the most recently completed command (`$?`).
//! - A fixed PID placeholder (`$$` → `"1"`) until process management lands.
//! - Command aliases.
//!
//! ## Variable expansion
//!
//! [`crate::env::ShellEnv::expand`] performs `$VAR`, `${VAR}`, and `${VAR:-default}`
//! substitution on arbitrary strings. It is intentionally focused on variable
//! expansion: it does not itself perform arithmetic expansion or nested braces.
//!
//! Command substitution `$(...)` **is** supported by the shell, but is resolved
//! one stage earlier — at the token level by
//! [`crate::executor::substitute_tokens`], which runs each inner command and
//! captures its output. By the time a string reaches `expand`, any bare or
//! double-quoted `$(...)` has already been replaced with its result; a `$(...)`
//! that survives into `expand` is a single-quoted literal and is copied through
//! verbatim (`expand` does not treat `$(` specially).
//!
//! ## Ordering
//!
//! Internal collections use [`alloc::collections::BTreeMap`] /
//! [`alloc::collections::BTreeSet`] so that iteration order is deterministic
//! (alphabetical). This makes tests and serialised output reproducible
//! without sorting.

use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

// ── ShellEnv ──────────────────────────────────────────────────────────────────

/// The runtime environment for a shell session.
///
/// Stores named variables, tracks which of them are exported to child
/// processes, maintains a command-alias table, and records the exit code of
/// the last foreground command.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::env::ShellEnv;
///
/// let mut env = ShellEnv::new();
/// env.set("GREETING", "hello");
/// assert_eq!(env.expand("$GREETING world"), "hello world");
/// ```
#[derive(Debug, Clone)]
pub struct ShellEnv {
    /// All shell variables (exported and unexported).
    vars: BTreeMap<String, String>,
    /// Names of variables that should be propagated to child processes.
    exported: BTreeSet<String>,
    /// Command aliases (`alias ls='ls --color=auto'`).
    aliases: BTreeMap<String, String>,
    /// Exit code of the most recently completed foreground command.
    last_exit_code: i32,
}

impl ShellEnv {
    /// Create a new shell environment pre-populated with minimal default
    /// variables.
    ///
    /// Default variables:
    ///
    /// | Name   | Value   |
    /// |--------|---------|
    /// | `HOME` | `"/"`   |
    /// | `PATH` | `"/bin"`|
    /// | `USER` | `"root"`|
    /// | `PWD`  | `"/"`   |
    ///
    /// All four defaults are automatically exported (they must be visible to
    /// child processes).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let env = ShellEnv::new();
    /// assert_eq!(env.get("HOME"), Some("/"));
    /// assert_eq!(env.get("USER"), Some("root"));
    /// ```
    pub fn new() -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("HOME".to_owned(), "/".to_owned());
        vars.insert("PATH".to_owned(), "/bin".to_owned());
        vars.insert("USER".to_owned(), "root".to_owned());
        vars.insert("PWD".to_owned(), "/".to_owned());

        let mut exported = BTreeSet::new();
        exported.insert("HOME".to_owned());
        exported.insert("PATH".to_owned());
        exported.insert("USER".to_owned());
        exported.insert("PWD".to_owned());

        Self {
            vars,
            exported,
            aliases: BTreeMap::new(),
            last_exit_code: 0,
        }
    }

    // ── Variable access ───────────────────────────────────────────────────

    /// Look up a variable by name.
    ///
    /// Returns `Some(&str)` if the variable is set (even to an empty string),
    /// or `None` if it has never been set or was [`unset`](Self::unset).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// assert!(env.get("MISSING").is_none());
    /// env.set("X", "42");
    /// assert_eq!(env.get("X"), Some("42"));
    /// ```
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// Set a shell variable to `value`.
    ///
    /// If `name` was previously exported, it remains exported after this call.
    /// If `name` did not exist, it is created but *not* automatically exported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set("FOO", "bar");
    /// assert_eq!(env.get("FOO"), Some("bar"));
    /// // Overwriting keeps the same value.
    /// env.set("FOO", "baz");
    /// assert_eq!(env.get("FOO"), Some("baz"));
    /// ```
    pub fn set(&mut self, name: &str, value: &str) {
        self.vars.insert(name.to_owned(), value.to_owned());
    }

    /// Mark a variable as exported so it is visible to child processes.
    ///
    /// If the variable does not yet exist, it is created with an empty value
    /// and then exported. This matches the behaviour of `export VAR` before
    /// assignment in POSIX shells.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set("SECRET", "hunter2");
    /// assert!(!env.is_exported("SECRET"));
    /// env.export("SECRET");
    /// assert!(env.is_exported("SECRET"));
    /// ```
    pub fn export(&mut self, name: &str) {
        // Ensure the variable exists (POSIX: `export VAR` creates it as empty).
        self.vars.entry(name.to_owned()).or_default();
        self.exported.insert(name.to_owned());
    }

    /// Remove a variable from the environment entirely.
    ///
    /// After `unset`, [`get`](Self::get) returns `None` for `name`. If the
    /// variable was exported, it is also removed from the export set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set("TMP", "value");
    /// env.unset("TMP");
    /// assert!(env.get("TMP").is_none());
    /// ```
    pub fn unset(&mut self, name: &str) {
        self.vars.remove(name);
        self.exported.remove(name);
    }

    /// Return `true` if `name` is currently marked for export.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let env = ShellEnv::new();
    /// assert!(env.is_exported("HOME")); // default variables are exported
    /// assert!(!env.is_exported("NONEXISTENT"));
    /// ```
    pub fn is_exported(&self, name: &str) -> bool {
        self.exported.contains(name)
    }

    /// Return all exported `(name, value)` pairs, sorted alphabetically.
    ///
    /// This is used when spawning child processes: the returned pairs are
    /// passed as the child's environment.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set("HIDDEN", "nope"); // not exported
    /// let pairs = env.exported_pairs();
    /// assert!(pairs.iter().all(|(k, _)| k != "HIDDEN"));
    /// assert!(pairs.iter().any(|(k, _)| k == "HOME"));
    /// ```
    pub fn exported_pairs(&self) -> Vec<(String, String)> {
        self.exported
            .iter()
            .filter_map(|name| self.vars.get(name).map(|val| (name.clone(), val.clone())))
            .collect()
    }

    /// Return a reference to the complete variable map (exported and
    /// unexported).
    ///
    /// Useful for introspection (e.g. the `set` built-in command).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let env = ShellEnv::new();
    /// assert!(env.all_vars().contains_key("PATH"));
    /// ```
    pub fn all_vars(&self) -> &BTreeMap<String, String> {
        &self.vars
    }

    // ── Exit code ─────────────────────────────────────────────────────────

    /// Return the exit code of the most recently completed foreground command.
    ///
    /// This is the value that `$?` expands to.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// assert_eq!(env.last_exit_code(), 0); // fresh shell exits with 0
    /// env.set_last_exit_code(127);
    /// assert_eq!(env.last_exit_code(), 127);
    /// ```
    pub fn last_exit_code(&self) -> i32 {
        self.last_exit_code
    }

    /// Record the exit code of the most recently completed foreground command.
    ///
    /// The executor calls this after every pipeline completes.
    pub fn set_last_exit_code(&mut self, code: i32) {
        self.last_exit_code = code;
    }

    // ── Aliases ───────────────────────────────────────────────────────────

    /// Register a command alias.
    ///
    /// If `name` already exists as an alias, the value is overwritten.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set_alias("ll", "ls -la");
    /// assert_eq!(env.get_alias("ll"), Some("ls -la"));
    /// ```
    pub fn set_alias(&mut self, name: &str, value: &str) {
        self.aliases.insert(name.to_owned(), value.to_owned());
    }

    /// Look up an alias by name.
    ///
    /// Returns `Some(&str)` if the alias exists, or `None` if it does not.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let env = ShellEnv::new();
    /// assert!(env.get_alias("nonexistent").is_none());
    /// ```
    pub fn get_alias(&self, name: &str) -> Option<&str> {
        self.aliases.get(name).map(String::as_str)
    }

    /// Remove an alias by name.
    ///
    /// If the alias did not exist, this is a no-op.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set_alias("ll", "ls -la");
    /// env.remove_alias("ll");
    /// assert!(env.get_alias("ll").is_none());
    /// ```
    pub fn remove_alias(&mut self, name: &str) {
        self.aliases.remove(name);
    }

    /// Return a reference to the complete alias map.
    ///
    /// Useful for implementing the `alias` built-in (listing all aliases).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set_alias("grep", "grep --color=auto");
    /// assert!(env.aliases().contains_key("grep"));
    /// ```
    pub fn aliases(&self) -> &BTreeMap<String, String> {
        &self.aliases
    }

    // ── Variable expansion ────────────────────────────────────────────────

    /// Expand shell variable references in `input` and return the result.
    ///
    /// Supported forms:
    ///
    /// | Syntax              | Expansion                                        |
    /// |---------------------|--------------------------------------------------|
    /// | `$VAR`              | Value of `VAR`, or `""` if unset.                |
    /// | `${VAR}`            | Same as `$VAR`.                                  |
    /// | `${VAR:-default}`   | Value of `VAR`, or `"default"` if unset/empty.   |
    /// | `$?`                | Exit code of the last command as a decimal string.|
    /// | `$$`                | Shell PID placeholder — always `"1"`.            |
    ///
    /// Characters that are not part of a `$` sequence are copied verbatim.
    /// Single-quoted strings are not passed through this function (the lexer
    /// handles them as literals); callers are responsible for invoking
    /// `expand` only on strings that should be subject to substitution.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::env::ShellEnv;
    ///
    /// let mut env = ShellEnv::new();
    /// env.set("NAME", "NexaCore");
    /// assert_eq!(env.expand("Hello, $NAME!"), "Hello, NexaCore!");
    /// assert_eq!(env.expand("${NAME} OS"), "NexaCore OS");
    /// assert_eq!(env.expand("${MISSING:-world}"), "world");
    /// assert_eq!(env.expand("exit: $?"), "exit: 0");
    /// assert_eq!(env.expand("pid: $$"), "pid: 1");
    /// assert_eq!(env.expand("no dollars here"), "no dollars here");
    /// ```
    pub fn expand(&self, input: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let mut pos = 0usize;
        let mut out = String::with_capacity(input.len());

        while let Some(&ch) = chars.get(pos) {
            if ch != '$' {
                out.push(ch);
                pos += 1;
                continue;
            }

            // We have a `$`. Consume it and look at what follows.
            pos += 1;

            match chars.get(pos).copied() {
                None => {
                    // Trailing `$` — emit literally.
                    out.push('$');
                }
                // `$$` — PID placeholder.
                Some('$') => {
                    out.push('1');
                    pos += 1;
                }
                // `$?` — last exit code.
                Some('?') => {
                    out.push_str(&self.last_exit_code.to_string());
                    pos += 1;
                }
                // `${...}` — braced form.
                Some('{') => {
                    pos += 1; // consume `{`
                    let mut spec = String::new();
                    while let Some(&c) = chars.get(pos) {
                        if c == '}' {
                            break;
                        }
                        spec.push(c);
                        pos += 1;
                    }
                    // Consume the closing `}` if present.
                    if chars.get(pos) == Some(&'}') {
                        pos += 1;
                    }
                    out.push_str(&self.expand_spec(&spec));
                }
                // `$VAR` — bare identifier.
                Some(c) if is_ident_first(c) => {
                    let mut name = String::new();
                    while let Some(&ic) = chars.get(pos) {
                        if !is_ident_char(ic) {
                            break;
                        }
                        name.push(ic);
                        pos += 1;
                    }
                    out.push_str(self.get(&name).unwrap_or(""));
                }
                // Any other character after `$` — emit `$` literally and
                // do NOT consume the character (re-process it next iteration).
                Some(_) => {
                    out.push('$');
                }
            }
        }

        out
    }

    /// Resolve a brace-specifier (the content between `${` and `}`).
    ///
    /// Handles:
    /// - `VAR` → value or `""`
    /// - `VAR:-default` → value or `"default"` if unset or empty
    ///
    /// Unknown operators are treated as plain variable names to be lenient.
    fn expand_spec(&self, spec: &str) -> String {
        // `${VAR:-default}` — the `:-` operator.
        spec.find(":-").map_or_else(
            || {
                // Plain `${VAR}`.
                self.get(spec).unwrap_or("").to_owned()
            },
            |idx| {
                let name = &spec[..idx];
                let default_val = &spec[idx + 2..];
                match self.get(name) {
                    Some(v) if !v.is_empty() => v.to_owned(),
                    _ => default_val.to_owned(),
                }
            },
        )
    }
}

// ── Default ───────────────────────────────────────────────────────────────────

impl Default for ShellEnv {
    /// Create a default shell environment identical to [`ShellEnv::new`].
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return `true` if `c` may be the *first* character of a POSIX variable name.
///
/// POSIX: `[A-Za-z_]`.
#[inline]
fn is_ident_first(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

/// Return `true` if `c` may appear anywhere in a POSIX variable name.
///
/// POSIX: `[A-Za-z0-9_]`.
#[inline]
fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction / defaults ───────────────────────────────────────────

    #[test]
    fn new_has_default_variables() {
        let env = ShellEnv::new();
        assert_eq!(env.get("HOME"), Some("/"));
        assert_eq!(env.get("PATH"), Some("/bin"));
        assert_eq!(env.get("USER"), Some("root"));
        assert_eq!(env.get("PWD"), Some("/"));
    }

    #[test]
    fn default_impl_equals_new() {
        let a = ShellEnv::new();
        let b = ShellEnv::default();
        // Compare variable maps as a proxy for equality.
        assert_eq!(a.all_vars(), b.all_vars());
    }

    // ── get / set ─────────────────────────────────────────────────────────

    #[test]
    fn get_set_roundtrip() {
        let mut env = ShellEnv::new();
        env.set("MY_VAR", "hello");
        assert_eq!(env.get("MY_VAR"), Some("hello"));
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let env = ShellEnv::new();
        assert!(env.get("DEFINITELY_NOT_SET_XYZ").is_none());
    }

    #[test]
    fn set_overwrites_existing_value() {
        let mut env = ShellEnv::new();
        env.set("X", "first");
        env.set("X", "second");
        assert_eq!(env.get("X"), Some("second"));
    }

    #[test]
    fn set_empty_value_is_retrievable() {
        let mut env = ShellEnv::new();
        env.set("EMPTY", "");
        assert_eq!(env.get("EMPTY"), Some(""));
    }

    // ── unset ─────────────────────────────────────────────────────────────

    #[test]
    fn unset_removes_variable() {
        let mut env = ShellEnv::new();
        env.set("TMP", "value");
        env.unset("TMP");
        assert!(env.get("TMP").is_none());
    }

    #[test]
    fn unset_nonexistent_is_noop() {
        let mut env = ShellEnv::new();
        // Should not panic.
        env.unset("DOES_NOT_EXIST");
    }

    #[test]
    fn unset_removes_from_exported_set() {
        let mut env = ShellEnv::new();
        env.set("VAR", "val");
        env.export("VAR");
        assert!(env.is_exported("VAR"));
        env.unset("VAR");
        assert!(!env.is_exported("VAR"));
    }

    // ── export / is_exported ──────────────────────────────────────────────

    #[test]
    fn default_variables_are_exported() {
        let env = ShellEnv::new();
        assert!(env.is_exported("HOME"));
        assert!(env.is_exported("PATH"));
        assert!(env.is_exported("USER"));
        assert!(env.is_exported("PWD"));
    }

    #[test]
    fn new_variable_is_not_automatically_exported() {
        let mut env = ShellEnv::new();
        env.set("SECRET", "hunter2");
        assert!(!env.is_exported("SECRET"));
    }

    #[test]
    fn export_marks_variable_as_exported() {
        let mut env = ShellEnv::new();
        env.set("VAR", "val");
        env.export("VAR");
        assert!(env.is_exported("VAR"));
    }

    #[test]
    fn export_nonexistent_creates_empty_variable() {
        let mut env = ShellEnv::new();
        env.export("BRAND_NEW");
        assert!(env.is_exported("BRAND_NEW"));
        assert_eq!(env.get("BRAND_NEW"), Some(""));
    }

    // ── exported_pairs ────────────────────────────────────────────────────

    #[test]
    fn exported_pairs_returns_only_exported() {
        let mut env = ShellEnv::new();
        env.set("HIDDEN", "secret");
        env.set("VISIBLE", "public");
        env.export("VISIBLE");
        let pairs = env.exported_pairs();
        let names: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!names.contains(&"HIDDEN"));
        assert!(names.contains(&"VISIBLE"));
        assert!(names.contains(&"HOME")); // default
    }

    // ── all_vars ──────────────────────────────────────────────────────────

    #[test]
    fn all_vars_contains_all_variables() {
        let mut env = ShellEnv::new();
        env.set("HIDDEN", "nope");
        env.set("VISIBLE", "yep");
        env.export("VISIBLE");
        assert!(env.all_vars().contains_key("HIDDEN"));
        assert!(env.all_vars().contains_key("VISIBLE"));
    }

    // ── exit code ─────────────────────────────────────────────────────────

    #[test]
    fn initial_exit_code_is_zero() {
        let env = ShellEnv::new();
        assert_eq!(env.last_exit_code(), 0);
    }

    #[test]
    fn set_last_exit_code_roundtrip() {
        let mut env = ShellEnv::new();
        env.set_last_exit_code(127);
        assert_eq!(env.last_exit_code(), 127);
    }

    // ── aliases ───────────────────────────────────────────────────────────

    #[test]
    fn set_get_alias_roundtrip() {
        let mut env = ShellEnv::new();
        env.set_alias("ll", "ls -la");
        assert_eq!(env.get_alias("ll"), Some("ls -la"));
    }

    #[test]
    fn get_nonexistent_alias_returns_none() {
        let env = ShellEnv::new();
        assert!(env.get_alias("nonexistent").is_none());
    }

    #[test]
    fn remove_alias_works() {
        let mut env = ShellEnv::new();
        env.set_alias("ll", "ls -la");
        env.remove_alias("ll");
        assert!(env.get_alias("ll").is_none());
    }

    #[test]
    fn aliases_map_contains_registered_aliases() {
        let mut env = ShellEnv::new();
        env.set_alias("grep", "grep --color=auto");
        assert!(env.aliases().contains_key("grep"));
    }

    // ── expand: basic substitution ────────────────────────────────────────

    #[test]
    fn expand_bare_var() {
        let mut env = ShellEnv::new();
        env.set("NAME", "world");
        assert_eq!(env.expand("hello $NAME"), "hello world");
    }

    #[test]
    fn expand_unset_var_is_empty() {
        let env = ShellEnv::new();
        assert_eq!(env.expand("$UNSET_VAR_XYZ"), "");
    }

    #[test]
    fn expand_braced_var() {
        let mut env = ShellEnv::new();
        env.set("FOO", "bar");
        assert_eq!(env.expand("${FOO}baz"), "barbaz");
    }

    #[test]
    fn expand_braced_var_with_default_when_set() {
        let mut env = ShellEnv::new();
        env.set("VAR", "actual");
        assert_eq!(env.expand("${VAR:-default}"), "actual");
    }

    #[test]
    fn expand_braced_var_with_default_when_unset() {
        let env = ShellEnv::new();
        assert_eq!(env.expand("${UNSET_VAR:-fallback}"), "fallback");
    }

    #[test]
    fn expand_braced_var_with_default_when_empty() {
        let mut env = ShellEnv::new();
        env.set("EMPTY_VAR", "");
        assert_eq!(env.expand("${EMPTY_VAR:-used_default}"), "used_default");
    }

    #[test]
    fn expand_question_mark_gives_exit_code() {
        let mut env = ShellEnv::new();
        env.set_last_exit_code(42);
        assert_eq!(env.expand("code: $?"), "code: 42");
    }

    #[test]
    fn expand_double_dollar_gives_pid_placeholder() {
        let env = ShellEnv::new();
        assert_eq!(env.expand("$$"), "1");
    }

    #[test]
    fn expand_no_dollar_returns_input_unchanged() {
        let env = ShellEnv::new();
        assert_eq!(env.expand("no dollars here"), "no dollars here");
    }

    #[test]
    fn expand_multiple_vars_in_one_string() {
        let mut env = ShellEnv::new();
        env.set("USER", "alice");
        env.set("HOME", "/home/alice");
        assert_eq!(
            env.expand("hello $USER at $HOME"),
            "hello alice at /home/alice"
        );
    }

    #[test]
    fn expand_var_embedded_in_longer_string() {
        let mut env = ShellEnv::new();
        env.set("PATH", "/usr/bin");
        assert_eq!(
            env.expand("PATH=${PATH}:/opt/bin"),
            "PATH=/usr/bin:/opt/bin"
        );
    }

    #[test]
    fn expand_trailing_dollar_is_literal() {
        let env = ShellEnv::new();
        // A lone `$` at end of string is emitted verbatim.
        assert_eq!(env.expand("cost is $"), "cost is $");
    }

    #[test]
    fn expand_dollar_followed_by_nonident_is_literal() {
        let env = ShellEnv::new();
        // `$!` — not a special variable, not an ident start; `$` and `!` both literal.
        assert_eq!(env.expand("$!"), "$!");
    }

    #[test]
    fn expand_default_home() {
        let env = ShellEnv::new();
        assert_eq!(env.expand("$HOME"), "/");
    }
}

//! `env` / `export` - environment-variable model and rendering (WS8-10.9).
//!
//! There is **no global environment**: everything operates on an explicit
//! [`Env`] value (a name -> value map plus an *exported* set) or on a borrowed
//! `BTreeMap`. This mirrors the crate-wide rule that external facts are injected
//! values, not ambient state, so a shell can thread its environment through
//! commands as a pure, testable value.
//!
//! ## What each piece models
//!
//! - [`render_map`] turns any `BTreeMap<String, String>` into sorted
//!   `KEY=value` lines - the plain listing form of `env` with no arguments.
//! - [`Env`] adds *export* semantics: [`Env::set`] defines a shell variable,
//!   [`Env::export`] marks it for inheritance by child processes, and
//!   [`Env::unexport`] withdraws that mark without deleting the variable. Only
//!   exported variables appear in [`Env::render_exported`] - the environment a
//!   launched command actually sees.
//! - [`parse_invocation`] splits the `env [-i] [-u NAME].. [NAME=val].. [cmd ..]`
//!   command line into its option / unset / assignment / command parts, and
//!   [`build_child_env`] applies that invocation to a base [`Env`] to produce
//!   the environment the command runs with (the "set-then-run" split).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Returns `true` if `name` is a valid environment-variable name: a non-empty
/// string whose first character is an ASCII letter or `_` and whose remaining
/// characters are ASCII alphanumerics or `_`.
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Render a raw environment map as sorted `KEY=value` lines.
///
/// The `BTreeMap` already iterates in key order, so the output is deterministic
/// and lexically sorted, matching how `env` with no arguments lists variables.
#[must_use]
pub fn render_map(map: &BTreeMap<String, String>) -> Vec<String> {
    map.iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// An environment model: a set of variables plus the subset marked *exported*.
///
/// A plain variable is visible to the current shell only; an *exported*
/// variable is additionally inherited by launched commands. This split is the
/// distinction between a shell assignment (`NAME=val`) and `export NAME`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    /// All defined variables, `name -> value`.
    vars: BTreeMap<String, String>,
    /// Names of the variables that are exported to child processes.
    exported: BTreeSet<String>,
}

impl Env {
    /// An empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an environment from `pairs`, with **every** variable exported
    /// (the usual shape of an inherited process environment).
    #[must_use]
    pub fn from_exported_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut env = Self::new();
        for (name, value) in pairs {
            env.set(name, value);
            env.export(name);
        }
        env
    }

    /// Define (or overwrite) a variable. This does not, on its own, export it -
    /// it stays local to the shell until [`Env::export`] marks it.
    pub fn set(&mut self, name: &str, value: &str) {
        self.vars.insert(name.to_string(), value.to_string());
    }

    /// Remove a variable entirely, including its export mark if present.
    pub fn unset(&mut self, name: &str) {
        self.vars.remove(name);
        self.exported.remove(name);
    }

    /// The value of `name`, if defined.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// Mark `name` for export to child processes. If `name` is not yet defined
    /// it is created with an empty value, matching `export NAME` on an unset
    /// variable.
    pub fn export(&mut self, name: &str) {
        self.vars.entry(name.to_string()).or_default();
        self.exported.insert(name.to_string());
    }

    /// Withdraw the export mark from `name`. The variable itself is kept; it
    /// simply stops being inherited by child processes (`export -n NAME`).
    pub fn unexport(&mut self, name: &str) {
        self.exported.remove(name);
    }

    /// Whether `name` is currently exported.
    #[must_use]
    pub fn is_exported(&self, name: &str) -> bool {
        self.exported.contains(name)
    }

    /// Number of defined variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Whether no variables are defined.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Render **all** defined variables as sorted `KEY=value` lines (the shell's
    /// full view, as `set` would show).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        render_map(&self.vars)
    }

    /// Render only the **exported** variables as sorted `KEY=value` lines - the
    /// environment a launched command inherits, as `env` prints it.
    #[must_use]
    pub fn render_exported(&self) -> Vec<String> {
        self.vars
            .iter()
            .filter(|(name, _)| self.exported.contains(name.as_str()))
            .map(|(k, v)| format!("{k}={v}"))
            .collect()
    }
}

/// A parsed `env` command line, split into its constituent parts.
///
/// The `env` utility runs as `env [-i] [-u NAME].. [NAME=value].. [command ..]`:
/// leading options, then zero or more assignments, then an optional command to
/// run with the resulting environment. Everything from the first non-option,
/// non-assignment token onward is the command (even if a later token happens to
/// contain `=`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvInvocation {
    /// `-i`: start from an empty environment instead of inheriting the base.
    pub ignore_environment: bool,
    /// `-u NAME`: names to remove from the environment before running.
    pub unset: Vec<String>,
    /// Leading `NAME=value` assignments, in order.
    pub assignments: Vec<(String, String)>,
    /// The command and its arguments, empty if `env` was given none (in which
    /// case it simply prints the environment).
    pub command: Vec<String>,
}

/// Parse an `env` argument list into an [`EnvInvocation`].
///
/// Options (`-i`, `-u NAME`) are recognised only before the first assignment or
/// command token. A token is an assignment if it contains `=` and the part
/// before the first `=` is a [valid name](is_valid_name); the first token that
/// is neither an option nor an assignment begins the command.
///
/// A lone `--` terminates option parsing, so a following `NAME=value`-looking
/// token is still treated as an assignment but no further `-..` tokens are.
///
/// # Errors
///
/// [`crate::CoreError::MissingValue`] if a trailing `-u` has no name argument.
pub fn parse_invocation(args: &[&str]) -> Result<EnvInvocation, crate::CoreError> {
    let mut inv = EnvInvocation::default();
    let mut idx = 0;
    let mut options_done = false;

    // Phase 1: options and assignments.
    while idx < args.len() {
        let Some(&arg) = args.get(idx) else { break };
        if !options_done && arg == "--" {
            options_done = true;
            idx += 1;
            continue;
        }
        if !options_done && arg == "-i" {
            inv.ignore_environment = true;
            idx += 1;
            continue;
        }
        if !options_done && arg == "-u" {
            let Some(&name) = args.get(idx + 1) else {
                return Err(crate::CoreError::MissingValue);
            };
            inv.unset.push(name.to_string());
            idx += 2;
            continue;
        }
        if let Some((name, value)) = split_assignment(arg) {
            inv.assignments.push((name.to_string(), value.to_string()));
            options_done = true;
            idx += 1;
            continue;
        }
        // First non-option, non-assignment token: the command starts here.
        break;
    }

    // Phase 2: the remaining tokens are the command verbatim.
    while let Some(&arg) = args.get(idx) {
        inv.command.push(arg.to_string());
        idx += 1;
    }
    Ok(inv)
}

/// Split `token` into `(name, value)` if it is a `NAME=value` assignment with a
/// valid name, else `None`.
fn split_assignment(token: &str) -> Option<(&str, &str)> {
    let (name, value) = token.split_once('=')?;
    if is_valid_name(name) {
        Some((name, value))
    } else {
        None
    }
}

/// Apply an [`EnvInvocation`] to `base`, producing the environment the command
/// runs with.
///
/// With `-i` the result starts empty; otherwise it starts as a clone of `base`.
/// Each `-u NAME` is then removed, and each `NAME=value` assignment is set and
/// exported (an `env` assignment is always visible to the launched command).
#[must_use]
pub fn build_child_env(base: &Env, inv: &EnvInvocation) -> Env {
    let mut env = if inv.ignore_environment {
        Env::new()
    } else {
        base.clone()
    };
    for name in &inv.unset {
        env.unset(name);
    }
    for (name, value) in &inv.assignments {
        env.set(name, value);
        env.export(name);
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(is_valid_name("PATH"));
        assert!(is_valid_name("_x1"));
        assert!(!is_valid_name("1BAD"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("a-b"));
    }

    #[test]
    fn render_map_is_sorted_key_value() {
        let mut map = BTreeMap::new();
        map.insert(String::from("B"), String::from("2"));
        map.insert(String::from("A"), String::from("1"));
        assert_eq!(render_map(&map), ["A=1", "B=2"]);
    }

    #[test]
    fn set_get_unset() {
        let mut env = Env::new();
        env.set("HOME", "/home/user");
        assert_eq!(env.get("HOME"), Some("/home/user"));
        env.unset("HOME");
        assert_eq!(env.get("HOME"), None);
    }

    #[test]
    fn export_marks_and_creates_empty() {
        let mut env = Env::new();
        env.export("FOO");
        assert_eq!(env.get("FOO"), Some(""));
        assert!(env.is_exported("FOO"));
    }

    #[test]
    fn unexport_keeps_variable() {
        let mut env = Env::new();
        env.set("K", "v");
        env.export("K");
        env.unexport("K");
        assert!(!env.is_exported("K"));
        assert_eq!(env.get("K"), Some("v"));
    }

    #[test]
    fn render_vs_render_exported() {
        let mut env = Env::new();
        env.set("LOCAL", "1");
        env.set("SHARED", "2");
        env.export("SHARED");
        assert_eq!(env.render(), ["LOCAL=1", "SHARED=2"]);
        assert_eq!(env.render_exported(), ["SHARED=2"]);
    }

    #[test]
    fn len_and_empty() {
        let mut env = Env::new();
        assert!(env.is_empty());
        env.set("X", "y");
        assert!(!env.is_empty());
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn from_exported_pairs_exports_all() {
        let env = Env::from_exported_pairs(&[("A", "1"), ("B", "2")]);
        assert_eq!(env.render_exported(), ["A=1", "B=2"]);
    }

    #[test]
    fn parse_assignments_then_command() {
        let inv = parse_invocation(&["A=1", "B=2", "run", "--flag", "C=3"]).unwrap();
        assert_eq!(
            inv.assignments,
            [
                (String::from("A"), String::from("1")),
                (String::from("B"), String::from("2")),
            ]
        );
        // `C=3` after the command word is a command argument, not an assignment.
        assert_eq!(inv.command, ["run", "--flag", "C=3"]);
    }

    #[test]
    fn parse_options_ignore_and_unset() {
        let inv = parse_invocation(&["-i", "-u", "PATH", "X=1", "cmd"]).unwrap();
        assert!(inv.ignore_environment);
        assert_eq!(inv.unset, ["PATH"]);
        assert_eq!(inv.assignments, [(String::from("X"), String::from("1"))]);
        assert_eq!(inv.command, ["cmd"]);
    }

    #[test]
    fn parse_double_dash_ends_options() {
        let inv = parse_invocation(&["--", "-i", "cmd"]).unwrap();
        // After `--`, `-i` is not an option; it is neither an assignment, so it
        // starts the command.
        assert!(!inv.ignore_environment);
        assert_eq!(inv.command, ["-i", "cmd"]);
    }

    #[test]
    fn parse_trailing_unset_without_name_errors() {
        assert_eq!(
            parse_invocation(&["-u"]),
            Err(crate::CoreError::MissingValue)
        );
    }

    #[test]
    fn parse_empty_is_all_default() {
        let inv = parse_invocation(&[]).unwrap();
        assert_eq!(inv, EnvInvocation::default());
    }

    #[test]
    fn parse_invalid_name_is_command_not_assignment() {
        // `1BAD=x` has an invalid name, so it is not an assignment; it begins
        // the command.
        let inv = parse_invocation(&["1BAD=x"]).unwrap();
        assert!(inv.assignments.is_empty());
        assert_eq!(inv.command, ["1BAD=x"]);
    }

    #[test]
    fn build_child_applies_unset_and_assignments() {
        let base = Env::from_exported_pairs(&[("PATH", "/bin"), ("HOME", "/root")]);
        let inv = parse_invocation(&["-u", "HOME", "TERM=xterm", "sh"]).unwrap();
        let child = build_child_env(&base, &inv);
        assert_eq!(child.get("HOME"), None);
        assert_eq!(child.get("PATH"), Some("/bin"));
        assert_eq!(child.get("TERM"), Some("xterm"));
        assert!(child.is_exported("TERM"));
    }

    #[test]
    fn build_child_ignore_environment_starts_empty() {
        let base = Env::from_exported_pairs(&[("PATH", "/bin")]);
        let inv = parse_invocation(&["-i", "ONLY=1", "cmd"]).unwrap();
        let child = build_child_env(&base, &inv);
        assert_eq!(child.get("PATH"), None);
        assert_eq!(child.render_exported(), ["ONLY=1"]);
    }
}

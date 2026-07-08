//! Config-as-code: a declarative, versionable configuration layer over the
//! typed [`ConfigStore`] (WS17-02).
//!
//! A text document of `key = value` lines describes a **desired** configuration
//! state. The engine:
//!
//! - defines a typed declarative format and parses it ([`parse`], WS17-02.1/.2),
//! - computes a [`diff`](DesiredConfig::diff) against the live store
//!   (WS17-02.4),
//! - [`apply`](DesiredConfig::apply)s it atomically via the store's
//!   all-or-nothing transaction (WS17-02.3), returning a [`Snapshot`] for atomic
//!   [`rollback`] (WS17-02.5),
//! - is idempotent: re-applying the same document is a no-op and the diff is
//!   empty (WS17-02.6),
//! - and [`compose`]s documents into layered profiles, last-layer-wins
//!   (WS17-02.7).
//!
//! This is the authoring base for agentic automations (WS16-04) and the
//! alternative ncScript authoring path (WS18-05), per WS17-02.8.
//!
//! ## Format
//!
//! ```text
//! # comments start with `#`
//! desktop.theme.mode = dark        # bareword → string (enum value)
//! desktop.theme.density = 2        # integer
//! desktop.animations = true        # boolean
//! net.tcp.rto_scale = 1.5          # float
//! greeting = "hello, world"        # quoted string (keeps spaces / `#`)
//! ```
//!
//! Values are typed by literal shape: `true`/`false` → bool; an integer literal
//! → int; a float literal → float; a `"…"` quoted or bare token → string. Quote
//! a value to force a string (e.g. `"true"` or `"42"`). Each value is validated
//! against the key's schema when applied, exactly like a direct store write.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{ConfigBackend, ConfigError, ConfigStore, ConfigValue, Key, WriteAuthorizer};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// What went wrong while parsing a config-as-code document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A non-blank line had no `=` separator.
    MissingAssignment,
    /// The key (left of `=`) is not a valid dotted [`Key`].
    InvalidKey,
    /// A quoted string value was not closed.
    UnterminatedString,
    /// A `\` escape in a quoted string was invalid or dangling.
    InvalidEscape,
}

impl core::fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MissingAssignment => "missing `=` assignment",
            Self::InvalidKey => "invalid configuration key",
            Self::UnterminatedString => "unterminated string literal",
            Self::InvalidEscape => "invalid string escape",
        })
    }
}

/// An error from the config-as-code engine: either a parse error (with line) or
/// a store error surfaced by `apply`/`diff`/`rollback`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeError {
    /// A parse error on a specific 1-based line.
    Parse {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        kind: ParseErrorKind,
    },
    /// An error from the underlying store (unknown key, validation, auth).
    Store(ConfigError),
}

impl core::fmt::Display for CodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse { line, kind } => write!(f, "line {line}: {kind}"),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for CodeError {}

impl From<ConfigError> for CodeError {
    fn from(e: ConfigError) -> Self {
        Self::Store(e)
    }
}

// ---------------------------------------------------------------------------
// Desired state + diff
// ---------------------------------------------------------------------------

/// A parsed desired-configuration document: deduplicated `(key, value)`
/// assignments (last assignment of a key wins).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DesiredConfig {
    entries: Vec<(Key, ConfigValue)>,
}

/// One key whose live value differs from the desired document (WS17-02.4).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigChange {
    /// The key that would change.
    pub key: Key,
    /// The current effective value in the store.
    pub from: ConfigValue,
    /// The value the document wants.
    pub to: ConfigValue,
}

/// The prior effective values of the keys an [`apply`](DesiredConfig::apply)
/// touched, captured for atomic [`rollback`] (WS17-02.5).
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    prior: Vec<(Key, ConfigValue)>,
}

impl Snapshot {
    /// The captured `(key, prior value)` pairs.
    #[must_use]
    pub fn entries(&self) -> &[(Key, ConfigValue)] {
        &self.prior
    }
}

impl DesiredConfig {
    /// Build directly from `(key, value)` pairs (last-wins deduplicated).
    #[must_use]
    pub fn from_entries(entries: Vec<(Key, ConfigValue)>) -> Self {
        Self {
            entries: dedup_last_wins(entries),
        }
    }

    /// The deduplicated `(key, value)` assignments, in document order.
    #[must_use]
    pub fn entries(&self) -> &[(Key, ConfigValue)] {
        &self.entries
    }

    /// Whether the document is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the set of keys whose live value differs from this document
    /// (WS17-02.4). An empty result means the store already matches.
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnknownKey`] if the document names a key with no schema.
    pub fn diff<B: ConfigBackend>(
        &self,
        store: &ConfigStore<B>,
    ) -> Result<Vec<ConfigChange>, ConfigError> {
        let mut changes = Vec::new();
        for (key, desired) in &self.entries {
            let live = store.get(key, None)?;
            if live != *desired {
                changes.push(ConfigChange {
                    key: key.clone(),
                    from: live,
                    to: desired.clone(),
                });
            }
        }
        Ok(changes)
    }

    /// Apply the document atomically (WS17-02.3): every assignment is validated
    /// and authorized first; if any fails, the store is left unchanged.
    ///
    /// Returns a [`Snapshot`] of the prior effective values, suitable for
    /// [`rollback`] (WS17-02.5).
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] (unknown key, validation, or authorization) — in which
    /// case nothing was written.
    pub fn apply<B: ConfigBackend>(
        &self,
        store: &mut ConfigStore<B>,
        auth: &dyn WriteAuthorizer,
    ) -> Result<Snapshot, ConfigError> {
        // Capture prior effective values before mutating, for rollback. This
        // also surfaces UnknownKey up-front, before any write.
        let mut prior = Vec::with_capacity(self.entries.len());
        for (key, _) in &self.entries {
            prior.push((key.clone(), store.get(key, None)?));
        }
        store.transaction(&self.entries, auth)?;
        Ok(Snapshot { prior })
    }

    /// Serialize to a config-as-code document — the inverse of [`parse`]
    /// (WS17-05.1).
    ///
    /// Entries are emitted sorted by key for deterministic, diff-friendly
    /// output. Strings are always quoted (and escaped) and floats always carry a
    /// fraction, so every value round-trips back to the same type via [`parse`].
    #[must_use]
    pub fn to_code(&self) -> String {
        let mut sorted: Vec<&(Key, ConfigValue)> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        let mut out = String::new();
        for (key, value) in sorted {
            out.push_str(key.as_str());
            out.push_str(" = ");
            out.push_str(&format_value(value));
            out.push('\n');
        }
        out
    }
}

/// Restore the store to a [`Snapshot`] captured by a prior `apply`, atomically
/// (WS17-02.5).
///
/// # Errors
///
/// As [`ConfigStore::transaction`]; on error the store is unchanged.
pub fn rollback<B: ConfigBackend>(
    snapshot: &Snapshot,
    store: &mut ConfigStore<B>,
    auth: &dyn WriteAuthorizer,
) -> Result<(), ConfigError> {
    store.transaction(&snapshot.prior, auth)
}

/// Compose several documents into one layered profile: later layers override
/// earlier ones on a per-key basis (last-layer-wins, WS17-02.7).
#[must_use]
pub fn compose(layers: &[DesiredConfig]) -> DesiredConfig {
    let mut merged: Vec<(Key, ConfigValue)> = Vec::new();
    for layer in layers {
        for (k, v) in &layer.entries {
            merged.push((k.clone(), v.clone()));
        }
    }
    DesiredConfig {
        entries: dedup_last_wins(merged),
    }
}

/// Capture a store's current effective configuration as a profile (WS17-05.1).
///
/// Every schema-registered key whose effective (global, user-`None`) value can
/// be read is included. The result can be serialized with
/// [`DesiredConfig::to_code`] and later re-applied with [`import_profile`].
#[must_use]
pub fn export_profile<B: ConfigBackend>(store: &ConfigStore<B>) -> DesiredConfig {
    let mut entries = Vec::new();
    for key in store.schema().keys() {
        if let Ok(value) = store.get(key, None) {
            entries.push((key.clone(), value));
        }
    }
    DesiredConfig::from_entries(entries)
}

/// Parse a config-as-code profile and apply it atomically (WS17-05.2).
///
/// Equivalent to `parse(text)?.apply(store, auth)`, returning the prior-state
/// [`Snapshot`] for [`rollback`].
///
/// # Errors
///
/// [`CodeError::Parse`] on malformed input, or a wrapped [`ConfigError`]
/// (unknown key / validation / authorization) — in which case nothing was
/// written.
pub fn import_profile<B: ConfigBackend>(
    text: &str,
    store: &mut ConfigStore<B>,
    auth: &dyn WriteAuthorizer,
) -> Result<Snapshot, CodeError> {
    Ok(parse(text)?.apply(store, auth)?)
}

/// Serialize one value to its config-as-code literal form.
fn format_value(value: &ConfigValue) -> String {
    match value {
        ConfigValue::Bool(true) => String::from("true"),
        ConfigValue::Bool(false) => String::from("false"),
        ConfigValue::Int(i) => i.to_string(),
        ConfigValue::Float(x) => {
            let mut s = x.to_string();
            // Re-add a fraction so the value re-parses as a float, not an int.
            // Non-finite renderings ("inf"/"NaN") contain letters and are left
            // as-is (they still re-parse via `f64::from_str`).
            if !s.bytes().any(|c| c.is_ascii_alphabetic() || c == b'.') {
                s.push_str(".0");
            }
            s
        }
        ConfigValue::Str(s) => {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\t' => out.push_str("\\t"),
                    _ => out.push(ch),
                }
            }
            out.push('"');
            out
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing (WS17-02.1/.2)
// ---------------------------------------------------------------------------

/// Parse a config-as-code document into a [`DesiredConfig`] (WS17-02.2).
///
/// Blank lines and `#` comments are ignored. Duplicate keys are deduplicated
/// last-wins.
///
/// # Errors
///
/// A [`CodeError::Parse`] tagged with the offending 1-based line.
pub fn parse(text: &str) -> Result<DesiredConfig, CodeError> {
    let mut entries = Vec::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return Err(CodeError::Parse {
                line: line_no,
                kind: ParseErrorKind::MissingAssignment,
            });
        };
        let key = Key::new(raw_key.trim()).map_err(|_| CodeError::Parse {
            line: line_no,
            kind: ParseErrorKind::InvalidKey,
        })?;
        let value = parse_value(raw_value.trim(), line_no)?;
        entries.push((key, value));
    }
    Ok(DesiredConfig {
        entries: dedup_last_wins(entries),
    })
}

/// Strip an unquoted trailing `#` comment, leaving quoted `#` intact.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut prev_backslash = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' if !prev_backslash => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..i],
            _ => {}
        }
        prev_backslash = ch == '\\' && !prev_backslash;
    }
    line
}

/// Parse a single value literal, typed by its shape.
fn parse_value(s: &str, line: usize) -> Result<ConfigValue, CodeError> {
    match s {
        "true" => return Ok(ConfigValue::Bool(true)),
        "false" => return Ok(ConfigValue::Bool(false)),
        _ => {}
    }
    if let Some(rest) = s.strip_prefix('"') {
        let inner = rest.strip_suffix('"').ok_or(CodeError::Parse {
            line,
            kind: ParseErrorKind::UnterminatedString,
        })?;
        // A lone closing quote (`"`) leaves `rest` empty and no suffix; guard
        // the degenerate single-quote case where prefix == whole string.
        if rest.is_empty() {
            return Err(CodeError::Parse {
                line,
                kind: ParseErrorKind::UnterminatedString,
            });
        }
        return Ok(ConfigValue::Str(unescape(inner, line)?));
    }
    if let Ok(i) = s.parse::<i64>() {
        return Ok(ConfigValue::Int(i));
    }
    if let Ok(x) = s.parse::<f64>() {
        return Ok(ConfigValue::Float(x));
    }
    // Bareword → string (e.g. an enum variant like `dark`).
    Ok(ConfigValue::Str(String::from(s)))
}

/// Unescape the interior of a quoted string: `\"`, `\\`, `\n`, `\t`.
fn unescape(s: &str, line: usize) -> Result<String, CodeError> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            _ => {
                return Err(CodeError::Parse {
                    line,
                    kind: ParseErrorKind::InvalidEscape,
                });
            }
        }
    }
    Ok(out)
}

/// Deduplicate `(key, value)` pairs keeping the last assignment of each key,
/// preserving first-seen order of the surviving keys.
fn dedup_last_wins(entries: Vec<(Key, ConfigValue)>) -> Vec<(Key, ConfigValue)> {
    let mut out: Vec<(Key, ConfigValue)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        if let Some(slot) = out.iter_mut().find(|(ek, _)| *ek == k) {
            slot.1 = v;
        } else {
            out.push((k, v));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::{
        AllowAll, DenyAll, MemoryBackend, PrefixAuthorizer,
        schema::{KeySchema, SchemaRegistry},
        value::ValueType,
    };

    fn registry() -> SchemaRegistry {
        let mut reg = SchemaRegistry::new();
        reg.register(
            Key::new("desktop.theme.mode").unwrap(),
            KeySchema::new(
                ValueType::Enum(&["light", "dark", "auto"]),
                ConfigValue::Str("auto".to_string()),
                "theme mode",
            )
            .unwrap(),
        );
        reg.register(
            Key::new("desktop.theme.density").unwrap(),
            KeySchema::new(
                ValueType::Int { min: 0, max: 2 },
                ConfigValue::Int(1),
                "ui density",
            )
            .unwrap(),
        );
        reg.register(
            Key::new("desktop.animations").unwrap(),
            KeySchema::new(ValueType::Bool, ConfigValue::Bool(false), "animations").unwrap(),
        );
        reg.register(
            Key::new("net.rto_scale").unwrap(),
            KeySchema::new(
                ValueType::Float {
                    min: 0.0,
                    max: 10.0,
                },
                ConfigValue::Float(1.0),
                "rto scale",
            )
            .unwrap(),
        );
        reg.register(
            Key::new("desktop.greeting").unwrap(),
            KeySchema::new(
                ValueType::Str { max_len: 64 },
                ConfigValue::Str(String::new()),
                "greeting",
            )
            .unwrap(),
        );
        reg
    }

    fn store() -> ConfigStore<MemoryBackend> {
        ConfigStore::new(registry(), MemoryBackend::new())
    }

    fn key(s: &str) -> Key {
        Key::new(s).unwrap()
    }

    #[test]
    fn parses_typed_values_comments_and_blanks() {
        let doc = parse(
            "\
            # a comment\n\
            \n\
            desktop.theme.mode = dark   # trailing comment\n\
            desktop.theme.density = 2\n\
            desktop.animations = true\n\
            net.rto_scale = 1.5\n\
            desktop.greeting = \"hi # there\"\n",
        )
        .unwrap();
        let e = doc.entries();
        assert_eq!(e.len(), 5);
        assert_eq!(
            e[0],
            (key("desktop.theme.mode"), ConfigValue::Str("dark".into()))
        );
        assert_eq!(e[1], (key("desktop.theme.density"), ConfigValue::Int(2)));
        assert_eq!(e[2], (key("desktop.animations"), ConfigValue::Bool(true)));
        assert!(matches!(e[3].1, ConfigValue::Float(_)));
        // The `#` inside quotes is preserved, not treated as a comment.
        assert_eq!(e[4].1, ConfigValue::Str("hi # there".into()));
    }

    #[test]
    fn quoting_forces_string_type() {
        let doc = parse("desktop.greeting = \"42\"").unwrap();
        assert_eq!(doc.entries()[0].1, ConfigValue::Str("42".into()));
    }

    #[test]
    fn parse_errors_are_located() {
        assert_eq!(
            parse("desktop.theme.mode dark"),
            Err(CodeError::Parse {
                line: 1,
                kind: ParseErrorKind::MissingAssignment
            })
        );
        assert_eq!(
            parse("Bad.Key = 1"),
            Err(CodeError::Parse {
                line: 1,
                kind: ParseErrorKind::InvalidKey
            })
        );
        assert_eq!(
            parse("desktop.greeting = \"unterminated"),
            Err(CodeError::Parse {
                line: 1,
                kind: ParseErrorKind::UnterminatedString
            })
        );
    }

    #[test]
    fn duplicate_keys_are_last_wins() {
        let doc = parse("desktop.theme.density = 0\ndesktop.theme.density = 2").unwrap();
        assert_eq!(doc.entries().len(), 1);
        assert_eq!(doc.entries()[0].1, ConfigValue::Int(2));
    }

    #[test]
    fn apply_then_get_reflects_desired_state() {
        let mut s = store();
        let doc = parse("desktop.theme.mode = dark\ndesktop.theme.density = 2").unwrap();
        doc.apply(&mut s, &AllowAll).unwrap();
        assert_eq!(
            s.get(&key("desktop.theme.mode"), None).unwrap(),
            ConfigValue::Str("dark".into())
        );
        assert_eq!(
            s.get(&key("desktop.theme.density"), None).unwrap(),
            ConfigValue::Int(2)
        );
    }

    #[test]
    fn apply_is_atomic_on_invalid_value() {
        let mut s = store();
        // density 9 > max 2 → the whole apply fails and nothing is written.
        let doc = parse("desktop.theme.mode = dark\ndesktop.theme.density = 9").unwrap();
        assert_eq!(doc.apply(&mut s, &AllowAll), Err(ConfigError::OutOfRange));
        assert_eq!(
            s.get(&key("desktop.theme.mode"), None).unwrap(),
            ConfigValue::Str("auto".into())
        );
    }

    #[test]
    fn diff_is_nonempty_before_and_empty_after_apply_idempotent() {
        let mut s = store();
        let doc = parse("desktop.theme.mode = dark\ndesktop.theme.density = 2").unwrap();
        // Before apply: both keys differ from defaults.
        assert_eq!(doc.diff(&s).unwrap().len(), 2);
        doc.apply(&mut s, &AllowAll).unwrap();
        // After apply: in sync (WS17-02.6 idempotence).
        assert!(doc.diff(&s).unwrap().is_empty());
        // Re-apply is a clean no-op; diff stays empty.
        doc.apply(&mut s, &AllowAll).unwrap();
        assert!(doc.diff(&s).unwrap().is_empty());
    }

    #[test]
    fn rollback_restores_prior_state() {
        let mut s = store();
        // Establish a baseline different from the schema default.
        let base = parse("desktop.theme.mode = light").unwrap();
        base.apply(&mut s, &AllowAll).unwrap();

        let change = parse("desktop.theme.mode = dark").unwrap();
        let snap = change.apply(&mut s, &AllowAll).unwrap();
        assert_eq!(
            s.get(&key("desktop.theme.mode"), None).unwrap(),
            ConfigValue::Str("dark".into())
        );
        rollback(&snap, &mut s, &AllowAll).unwrap();
        assert_eq!(
            s.get(&key("desktop.theme.mode"), None).unwrap(),
            ConfigValue::Str("light".into())
        );
    }

    #[test]
    fn compose_layers_last_wins() {
        let base = parse("desktop.theme.mode = light\ndesktop.theme.density = 0").unwrap();
        let overlay = parse("desktop.theme.mode = dark").unwrap();
        let merged = compose(&[base, overlay]);
        assert_eq!(merged.entries().len(), 2);
        // overlay wins for mode; base survives for density.
        let mode = merged
            .entries()
            .iter()
            .find(|(k, _)| k.as_str() == "desktop.theme.mode")
            .unwrap();
        assert_eq!(mode.1, ConfigValue::Str("dark".into()));
        let density = merged
            .entries()
            .iter()
            .find(|(k, _)| k.as_str() == "desktop.theme.density")
            .unwrap();
        assert_eq!(density.1, ConfigValue::Int(0));
    }

    #[test]
    fn apply_is_capability_gated_default_deny() {
        let mut s = store();
        let doc = parse("desktop.theme.mode = dark").unwrap();
        // DenyAll → nothing applied.
        assert_eq!(doc.apply(&mut s, &DenyAll), Err(ConfigError::Unauthorized));
        assert_eq!(
            s.get(&key("desktop.theme.mode"), None).unwrap(),
            ConfigValue::Str("auto".into())
        );
        // A prefix-scoped grant only its namespace lets it through.
        let cap = PrefixAuthorizer::new().grant("desktop.theme");
        assert!(doc.apply(&mut s, &cap).is_ok());
    }

    #[test]
    fn diff_unknown_key_errors() {
        let s = store();
        let doc = parse("nope.missing = 1").unwrap();
        assert_eq!(doc.diff(&s), Err(ConfigError::UnknownKey));
    }

    // -----------------------------------------------------------------------
    // Profile export / import (WS17-05.1/.2)
    // -----------------------------------------------------------------------

    #[test]
    fn to_code_round_trips_and_preserves_types() {
        let cfg = DesiredConfig::from_entries(alloc::vec![
            (key("desktop.animations"), ConfigValue::Bool(true)),
            (key("desktop.theme.density"), ConfigValue::Int(2)),
            (key("net.rto_scale"), ConfigValue::Float(2.0)),
            // A string that *looks* like an int must stay a string after a
            // round-trip — verifying the serializer quotes it.
            (
                key("desktop.greeting"),
                ConfigValue::Str("42 # not a comment".into())
            ),
        ]);
        let code = cfg.to_code();
        let reparsed = parse(&code).unwrap();
        // Serialization is stable (idempotent) ...
        assert_eq!(reparsed.to_code(), code);
        // ... and every value survives with its original type.
        for (k, v) in cfg.entries() {
            let got = reparsed
                .entries()
                .iter()
                .find(|(rk, _)| rk == k)
                .map(|(_, rv)| rv);
            assert_eq!(got, Some(v), "value for {} changed", k.as_str());
        }
        // The integral float kept a fraction so it did not collapse to an int.
        assert!(code.contains("net.rto_scale = 2.0"));
        // The numeric-looking string was quoted.
        assert!(code.contains("desktop.greeting = \"42 # not a comment\""));
    }

    #[test]
    fn export_captures_applied_values() {
        let mut s = store();
        import_profile(
            "desktop.theme.mode = dark\ndesktop.theme.density = 1",
            &mut s,
            &AllowAll,
        )
        .unwrap();
        let profile = export_profile(&s);
        // The exported profile contains the applied values (among the defaults).
        assert!(
            profile
                .entries()
                .contains(&(key("desktop.theme.mode"), ConfigValue::Str("dark".into())))
        );
        assert!(
            profile
                .entries()
                .contains(&(key("desktop.theme.density"), ConfigValue::Int(1)))
        );
    }

    #[test]
    fn export_then_import_into_fresh_store_reproduces_state() {
        let mut s = store();
        import_profile(
            "desktop.theme.mode = dark\nnet.rto_scale = 1.5\ndesktop.greeting = \"hi there\"",
            &mut s,
            &AllowAll,
        )
        .unwrap();

        // Round-trip the whole config through serialized config-as-code.
        let code = export_profile(&s).to_code();
        let mut fresh = store();
        import_profile(&code, &mut fresh, &AllowAll).unwrap();

        assert_eq!(
            fresh.get(&key("desktop.theme.mode"), None).unwrap(),
            ConfigValue::Str("dark".into())
        );
        assert_eq!(
            fresh.get(&key("net.rto_scale"), None).unwrap(),
            ConfigValue::Float(1.5)
        );
        assert_eq!(
            fresh.get(&key("desktop.greeting"), None).unwrap(),
            ConfigValue::Str("hi there".into())
        );
    }

    #[test]
    fn import_profile_rejects_malformed_and_is_atomic() {
        let mut s = store();
        // Malformed line → parse error, nothing applied.
        assert!(matches!(
            import_profile("desktop.theme.mode dark", &mut s, &AllowAll),
            Err(CodeError::Parse { .. })
        ));
        // An out-of-range value → store error, nothing applied (atomic).
        let before = s.get(&key("desktop.theme.density"), None).unwrap();
        assert!(import_profile("desktop.theme.density = 9", &mut s, &AllowAll).is_err());
        assert_eq!(s.get(&key("desktop.theme.density"), None).unwrap(), before);
    }
}

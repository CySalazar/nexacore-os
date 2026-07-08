//! `nexacore-config` — the NexaCore OS typed system configuration store (WS17-01).
//!
//! A unified, schema-driven configuration store in the spirit of dconf /
//! gsettings, but capability-gated and typed end to end:
//!
//! - **Schema per key** ([`KeySchema`]): type, default, valid range, and a
//!   human description ([`schema`], WS17-01.1).
//! - **Typed store** ([`ConfigStore`]) over a pluggable persistence backend
//!   ([`ConfigBackend`]; the production backend is VFS-backed per WS3-02, with
//!   [`MemoryBackend`] for host tests). (WS17-01.2)
//! - **Hierarchical namespacing** of keys ([`Key`], dot-separated). (WS17-01.3)
//! - **Validation** of every value against its schema type + range. (WS17-01.4)
//! - **Watch / notify** in real time on key changes ([`ConfigStore::watch`] /
//!   [`ConfigStore::poll`]). (WS17-01.5)
//! - **Atomic multi-key transactions** ([`ConfigStore::transaction`]):
//!   all-or-nothing, validated and authorized before any write. (WS17-01.6)
//! - **Per-user overrides** layered over system defaults. (WS17-01.7)
//! - **Capability-gated writes** ([`WriteAuthorizer`]): default-deny; the
//!   production authorizer verifies an `nexacore-capability` token. (WS17-01.8)
//! - **Config-as-code** ([`declarative`]): a typed, versionable declarative
//!   document with atomic `apply`, `diff`, `rollback`, idempotence and
//!   composable profiles. (WS17-02)
//!
//! `no_std + alloc`, zero production dependencies — it builds for the host and
//! for `x86_64-unknown-none`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

extern crate alloc;

use alloc::string::String;

pub mod declarative;
pub mod schema;
pub mod store;
pub mod tunable;
pub mod value;

pub use declarative::{CodeError, ConfigChange, DesiredConfig, ParseErrorKind, Snapshot};
pub use schema::{KeySchema, SchemaRegistry};
pub use store::{
    AllowAll, ChangeEvent, ConfigBackend, ConfigStore, DenyAll, MemoryBackend, PrefixAuthorizer,
    UserId, WatcherId, WriteAuthorizer,
};
pub use value::{ConfigValue, ValueType};

// ---------------------------------------------------------------------------
// Key — hierarchical, dot-separated configuration key
// ---------------------------------------------------------------------------

/// A hierarchical configuration key, e.g. `desktop.theme.accent` (WS17-01.3).
///
/// A key is one or more dot-separated **segments**; each segment is non-empty
/// and contains only ASCII lowercase letters, digits, `_` or `-`. The dotted
/// form gives a namespace tree (`desktop`, `desktop.theme`, …) used by
/// prefix-scoped watchers and authorizers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(String);

impl Key {
    /// Parse and validate a dotted key.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidKey`] if the string is empty, has an empty
    /// segment (leading/trailing/double dot), or contains a character outside
    /// `[a-z0-9_-.]`.
    pub fn new(s: &str) -> Result<Self, ConfigError> {
        if s.is_empty() {
            return Err(ConfigError::InvalidKey);
        }
        let mut segment_len = 0usize;
        for ch in s.bytes() {
            if ch == b'.' {
                if segment_len == 0 {
                    return Err(ConfigError::InvalidKey); // empty segment
                }
                segment_len = 0;
            } else if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'_' || ch == b'-' {
                segment_len += 1;
            } else {
                return Err(ConfigError::InvalidKey);
            }
        }
        if segment_len == 0 {
            return Err(ConfigError::InvalidKey); // trailing dot / empty tail
        }
        Ok(Self(String::from(s)))
    }

    /// The key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Iterator over the dot-separated namespace segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// Whether this key is within the namespace `prefix`.
    ///
    /// Matching is on segment boundaries: prefix `desktop.theme` matches
    /// `desktop.theme` and `desktop.theme.accent`, but NOT `desktop.themer`.
    /// An empty prefix matches every key (the root namespace).
    #[must_use]
    pub fn is_in_namespace(&self, prefix: &str) -> bool {
        if prefix.is_empty() {
            return true;
        }
        self.0
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by the configuration store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The key string is not a valid dotted namespace key.
    InvalidKey,
    /// No schema is registered for the key.
    UnknownKey,
    /// The value's type does not match the key's schema type.
    TypeMismatch {
        /// The schema's declared type name.
        expected: &'static str,
        /// The supplied value's type name.
        found: &'static str,
    },
    /// A numeric value is outside the schema's `[min, max]` range.
    OutOfRange,
    /// A string value exceeds the schema's maximum length.
    TooLong,
    /// A value is not one of an enum schema's allowed variants.
    NotAllowedValue,
    /// A schema's declared default does not satisfy its own type/range.
    DefaultInvalid,
    /// The write was rejected by the capability authorizer (default-deny).
    Unauthorized,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("invalid configuration key"),
            Self::UnknownKey => f.write_str("no schema registered for key"),
            Self::TypeMismatch { expected, found } => {
                write!(f, "type mismatch: expected {expected}, found {found}")
            }
            Self::OutOfRange => f.write_str("value out of range"),
            Self::TooLong => f.write_str("string value too long"),
            Self::NotAllowedValue => f.write_str("value not an allowed enum variant"),
            Self::DefaultInvalid => f.write_str("schema default violates its own type/range"),
            Self::Unauthorized => f.write_str("write rejected: missing capability"),
        }
    }
}

impl core::error::Error for ConfigError {}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn valid_dotted_keys_parse() {
        assert!(Key::new("desktop").is_ok());
        assert!(Key::new("desktop.theme.accent").is_ok());
        assert!(Key::new("net.tcp.rto_ms").is_ok());
        assert!(Key::new("a-b.c_d.e9").is_ok());
    }

    #[test]
    fn invalid_keys_are_rejected() {
        for bad in ["", ".", "a.", ".a", "a..b", "Desktop", "a.b!", "a b", "a.B"] {
            assert_eq!(Key::new(bad), Err(ConfigError::InvalidKey), "{bad:?}");
        }
    }

    #[test]
    fn namespace_matching_is_on_segment_boundaries() {
        let k = Key::new("desktop.theme.accent").unwrap();
        assert!(k.is_in_namespace(""));
        assert!(k.is_in_namespace("desktop"));
        assert!(k.is_in_namespace("desktop.theme"));
        assert!(k.is_in_namespace("desktop.theme.accent"));
        assert!(!k.is_in_namespace("desktop.them"));
        assert!(!k.is_in_namespace("desktop.themer"));
        assert!(!k.is_in_namespace("net"));
    }

    #[test]
    fn segments_split_on_dots() {
        let k = Key::new("desktop.theme.accent").unwrap();
        let parts: alloc::vec::Vec<&str> = k.segments().collect();
        assert_eq!(parts, ["desktop", "theme", "accent"]);
    }
}

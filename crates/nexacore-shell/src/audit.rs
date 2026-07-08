//! Per-session audit log for shell commands.
//!
//! This module provides [`crate::audit::AuditLog`], a lightweight append-only log that
//! records every command processed by the REPL along with its classified
//! intent, exit code, and a caller-supplied monotonic timestamp.
//!
//! The log lives inside [`crate::executor::ExecContext`] and is populated by
//! [`crate::repl::process_line`] after every pipeline completes.
//!
//! ## Design rationale
//!
//! - **`no_std` / `alloc`-only**: no dependency on `std::time`. The timestamp
//!   is an opaque `u64` supplied by the caller (e.g. a kernel tick counter or a
//!   HAL clock abstraction). This keeps the module portable across bare-metal
//!   targets.
//! - **Append-only**: entries are never removed or modified, which makes the log
//!   tamper-evident within the session.
//! - **No serialisation in Phase 1**: the log is held in memory for the
//!   duration of the shell session. Persistence will be added in a later sprint.

use alloc::{string::String, vec::Vec};

use crate::intent::IntentClass;

// ── AuditEntry ────────────────────────────────────────────────────────────────

/// A single entry in the per-session audit log.
///
/// Every command that passes through [`crate::repl::process_line`] generates
/// exactly one `AuditEntry` — even commands that fail (non-zero exit code) or
/// are not found (exit code 127).
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{
///     audit::{AuditEntry, AuditLog},
///     intent::IntentClass,
/// };
///
/// let mut log = AuditLog::new();
/// log.record("echo hello".into(), IntentClass::Task, 0, 1_000_000);
/// let entry = log.iter().next().unwrap();
/// assert_eq!(entry.command, "echo hello");
/// assert_eq!(entry.exit_code, 0);
/// ```
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// The raw command string exactly as received by the REPL.
    pub command: String,
    /// The intent category assigned by [`crate::intent::classify_intent`].
    pub intent_class: IntentClass,
    /// The exit code returned by the last pipeline in the command.
    pub exit_code: i32,
    /// Opaque monotonic timestamp (caller-supplied; units are platform-defined).
    ///
    /// On hosted builds this will be `0` until a HAL clock abstraction is
    /// wired in. On kernel builds this will be a hardware tick counter value.
    pub timestamp: u64,
}

// ── AuditLog ──────────────────────────────────────────────────────────────────

/// Append-only, in-memory audit log for a single shell session.
///
/// Entries are recorded in the order commands are executed. The log grows
/// without bound for the lifetime of the session; there is no eviction policy
/// in Phase 1.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::{audit::AuditLog, intent::IntentClass};
///
/// let mut log = AuditLog::new();
/// assert!(log.is_empty());
///
/// log.record("ls /".into(), IntentClass::Task, 0, 0);
/// log.record("audit logs".into(), IntentClass::Security, 0, 1);
///
/// assert_eq!(log.len(), 2);
/// assert_eq!(log.iter().nth(1).unwrap().command, "audit logs");
/// ```
#[derive(Debug, Default)]
pub struct AuditLog {
    /// All recorded entries in insertion order.
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create a new, empty audit log.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::audit::AuditLog;
    ///
    /// let log = AuditLog::new();
    /// assert!(log.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a new entry to the audit log.
    ///
    /// # Parameters
    ///
    /// - `command`: the raw command string.
    /// - `intent_class`: the intent as classified by [`crate::intent::classify_intent`].
    /// - `exit_code`: the exit code of the last pipeline in the command.
    /// - `timestamp`: opaque monotonic timestamp (caller-supplied).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::{audit::AuditLog, intent::IntentClass};
    ///
    /// let mut log = AuditLog::new();
    /// log.record("install pkg".into(), IntentClass::Administration, 0, 42);
    /// assert_eq!(log.len(), 1);
    /// ```
    pub fn record(
        &mut self,
        command: String,
        intent_class: IntentClass,
        exit_code: i32,
        timestamp: u64,
    ) {
        self.entries.push(AuditEntry {
            command,
            intent_class,
            exit_code,
            timestamp,
        });
    }

    /// Return the number of entries currently in the log.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::{audit::AuditLog, intent::IntentClass};
    ///
    /// let mut log = AuditLog::new();
    /// assert_eq!(log.len(), 0);
    /// log.record("echo hi".into(), IntentClass::Task, 0, 0);
    /// assert_eq!(log.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the log contains no entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::audit::AuditLog;
    ///
    /// let log = AuditLog::new();
    /// assert!(log.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return an iterator over all audit entries in insertion order.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nexacore_shell::{audit::AuditLog, intent::IntentClass};
    ///
    /// let mut log = AuditLog::new();
    /// log.record("cmd1".into(), IntentClass::Task, 0, 0);
    /// log.record("cmd2".into(), IntentClass::Guidance, 0, 1);
    ///
    /// let commands: Vec<&str> = log.iter().map(|e| e.command.as_str()).collect();
    /// assert_eq!(commands, ["cmd1", "cmd2"]);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::IntentClass;

    #[test]
    fn test_audit_log_empty() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_audit_log_len() {
        let mut log = AuditLog::new();
        log.record("echo a".into(), IntentClass::Task, 0, 0);
        assert_eq!(log.len(), 1);
        log.record("install b".into(), IntentClass::Administration, 1, 1);
        assert_eq!(log.len(), 2);
        // is_empty reflects the populated state.
        assert!(!log.is_empty());
    }

    #[test]
    fn test_audit_log_record_and_iterate() {
        let mut log = AuditLog::new();
        log.record("find /tmp".into(), IntentClass::Task, 0, 100);
        log.record("audit perms".into(), IntentClass::Security, 0, 200);
        log.record("reboot".into(), IntentClass::Administration, 0, 300);

        let entries: Vec<&AuditEntry> = log.iter().collect();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].command, "find /tmp");
        assert_eq!(entries[0].intent_class, IntentClass::Task);
        assert_eq!(entries[0].exit_code, 0);
        assert_eq!(entries[0].timestamp, 100);

        assert_eq!(entries[1].command, "audit perms");
        assert_eq!(entries[1].intent_class, IntentClass::Security);
        assert_eq!(entries[1].timestamp, 200);

        assert_eq!(entries[2].command, "reboot");
        assert_eq!(entries[2].intent_class, IntentClass::Administration);
        assert_eq!(entries[2].timestamp, 300);
    }
}

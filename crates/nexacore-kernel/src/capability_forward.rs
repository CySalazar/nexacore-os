//! Capability forwarding — shell attenuates capabilities for child commands.
//!
//! When the NexaCore shell spawns an external command, it creates an _attenuated_
//! capability token granting the minimum scope required by that command.
//! This enforces the principle of least privilege at the IPC boundary: a
//! read-only tool such as `ls` cannot receive a write capability even if
//! the parent shell holds one.
//!
//! ## Registry
//!
//! [`crate::capability_forward::CapabilityForwardRegistry`] contains the
//! static per-command scope table. The shell queries it with the bare
//! command name (no path) before spawning. Unknown commands are denied by
//! the shell layer until an explicit scope entry is added.
//!
//! ## Phase 1 scope
//!
//! Phase 1 uses a hard-coded registry. Phase 2 will replace it with a
//! policy file loaded from the VFS (e.g. `/etc/capability-policy`).

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

// ---------------------------------------------------------------------------
// CommandScope
// ---------------------------------------------------------------------------

/// The minimum capability scope required by a specific command.
///
/// A `CommandScope` is a `(resource, action)` pair. The resource pattern
/// uses a hierarchical dot-separated namespace; `*` is a glob suffix only
/// (no mid-string wildcards in Phase 1).
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::capability_forward::CommandScope;
///
/// let scope = CommandScope {
///     resource: String::from("Filesystem:*"),
///     action: String::from("Read"),
/// };
/// assert_eq!(scope.resource, "Filesystem:*");
/// assert_eq!(scope.action, "Read");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandScope {
    /// Resource pattern, e.g. `"Filesystem:*"` or `"Process:*"`.
    pub resource: String,
    /// Action, e.g. `"Read"`, `"Write"`, or `"Execute"`.
    pub action: String,
}

// ---------------------------------------------------------------------------
// CapabilityForwardRegistry
// ---------------------------------------------------------------------------

/// Registry that maps command names to required [`CommandScope`] values.
///
/// The registry is populated at construction with a well-known set of
/// standard NexaCore commands. Commands not present in the registry are
/// considered unknown; the shell must deny them until a scope entry is
/// added.
///
/// ## Thread safety
///
/// `CapabilityForwardRegistry` is not `Sync`. In the bare-metal kernel it
/// must live behind a spinlock. In host-side tests each test owns its own
/// local instance.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::capability_forward::CapabilityForwardRegistry;
///
/// let reg = CapabilityForwardRegistry::new();
/// assert!(reg.is_known("ls"));
/// assert!(!reg.is_known("unknown-tool"));
/// let scope = reg.get_scope("ls").unwrap();
/// assert_eq!(scope.action, "Read");
/// ```
#[derive(Debug)]
pub struct CapabilityForwardRegistry {
    /// Maps bare command name → required scope.
    scopes: BTreeMap<String, CommandScope>,
}

impl CapabilityForwardRegistry {
    /// Create the default registry populated with all known commands.
    ///
    /// Pre-registered commands:
    ///
    /// | Group              | Commands                                   | Action    |
    /// |--------------------|--------------------------------------------|-----------|
    /// | Filesystem readers | `ls`, `cat`, `head`, `tail`, `wc`, `find`, `df` | `Read` |
    /// | Filesystem writers | `cp`, `mv`, `rm`, `mkdir`, `touch`         | `Write`   |
    /// | Process ops        | `ps`, `kill`, `uname`, `whoami`, `hostname`| `Execute` |
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::capability_forward::CapabilityForwardRegistry;
    ///
    /// let reg = CapabilityForwardRegistry::new();
    /// assert!(reg.is_known("cat"));
    /// assert!(reg.is_known("rm"));
    /// assert!(reg.is_known("ps"));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let mut scopes: BTreeMap<String, CommandScope> = BTreeMap::new();

        // Read-only filesystem commands.
        for cmd in &["ls", "cat", "head", "tail", "wc", "find", "df"] {
            scopes.insert(
                (*cmd).to_string(),
                CommandScope {
                    resource: String::from("Filesystem:*"),
                    action: String::from("Read"),
                },
            );
        }

        // Write filesystem commands.
        for cmd in &["cp", "mv", "rm", "mkdir", "touch"] {
            scopes.insert(
                (*cmd).to_string(),
                CommandScope {
                    resource: String::from("Filesystem:*"),
                    action: String::from("Write"),
                },
            );
        }

        // Process / system commands.
        for cmd in &["ps", "kill", "uname", "whoami", "hostname"] {
            scopes.insert(
                (*cmd).to_string(),
                CommandScope {
                    resource: String::from("Process:*"),
                    action: String::from("Execute"),
                },
            );
        }

        Self { scopes }
    }

    /// Look up the required scope for `command`.
    ///
    /// Returns `None` if the command has no registered scope.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::capability_forward::CapabilityForwardRegistry;
    ///
    /// let reg = CapabilityForwardRegistry::new();
    /// let scope = reg.get_scope("ls").unwrap();
    /// assert_eq!(scope.resource, "Filesystem:*");
    /// assert!(reg.get_scope("nonexistent").is_none());
    /// ```
    #[must_use]
    pub fn get_scope(&self, command: &str) -> Option<&CommandScope> {
        self.scopes.get(command)
    }

    /// Return `true` if `command` has a registered scope.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::capability_forward::CapabilityForwardRegistry;
    ///
    /// let reg = CapabilityForwardRegistry::new();
    /// assert!(reg.is_known("kill"));
    /// assert!(!reg.is_known("curl"));
    /// ```
    #[must_use]
    pub fn is_known(&self, command: &str) -> bool {
        self.scopes.contains_key(command)
    }

    /// Return a sorted list of all registered command names.
    ///
    /// The order is lexicographic — the natural order of the inner
    /// [`BTreeMap`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::capability_forward::CapabilityForwardRegistry;
    ///
    /// let reg = CapabilityForwardRegistry::new();
    /// let cmds = reg.commands();
    /// assert!(cmds.contains(&"ls"));
    /// assert!(cmds.contains(&"ps"));
    /// ```
    #[must_use]
    pub fn commands(&self) -> Vec<&str> {
        self.scopes.keys().map(String::as_str).collect()
    }
}

impl Default for CapabilityForwardRegistry {
    /// Create the default registry — same as [`CapabilityForwardRegistry::new`].
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Filesystem reader commands have Read scope
    // -----------------------------------------------------------------------

    #[test]
    fn ls_has_filesystem_read_scope() {
        let reg = CapabilityForwardRegistry::new();
        let scope = reg.get_scope("ls").unwrap();
        assert_eq!(scope.resource, "Filesystem:*");
        assert_eq!(scope.action, "Read");
    }

    #[test]
    fn cat_has_filesystem_read_scope() {
        let reg = CapabilityForwardRegistry::new();
        let scope = reg.get_scope("cat").unwrap();
        assert_eq!(scope.action, "Read");
    }

    // -----------------------------------------------------------------------
    // Filesystem writer commands have Write scope
    // -----------------------------------------------------------------------

    #[test]
    fn cp_has_filesystem_write_scope() {
        let reg = CapabilityForwardRegistry::new();
        let scope = reg.get_scope("cp").unwrap();
        assert_eq!(scope.resource, "Filesystem:*");
        assert_eq!(scope.action, "Write");
    }

    #[test]
    fn rm_has_filesystem_write_scope() {
        let reg = CapabilityForwardRegistry::new();
        let scope = reg.get_scope("rm").unwrap();
        assert_eq!(scope.action, "Write");
    }

    // -----------------------------------------------------------------------
    // Process / system commands have Execute scope
    // -----------------------------------------------------------------------

    #[test]
    fn ps_has_process_execute_scope() {
        let reg = CapabilityForwardRegistry::new();
        let scope = reg.get_scope("ps").unwrap();
        assert_eq!(scope.resource, "Process:*");
        assert_eq!(scope.action, "Execute");
    }

    #[test]
    fn kill_has_process_execute_scope() {
        let reg = CapabilityForwardRegistry::new();
        let scope = reg.get_scope("kill").unwrap();
        assert_eq!(scope.action, "Execute");
    }

    // -----------------------------------------------------------------------
    // Unknown command returns None
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_command_returns_none() {
        let reg = CapabilityForwardRegistry::new();
        assert!(reg.get_scope("nonexistent").is_none());
        assert!(reg.get_scope("ssh").is_none());
        assert!(reg.get_scope("curl").is_none());
    }

    // -----------------------------------------------------------------------
    // is_known: true for every registered command
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_true_for_all_reader_commands() {
        let reg = CapabilityForwardRegistry::new();
        for cmd in &["ls", "cat", "head", "tail", "wc", "find", "df"] {
            assert!(reg.is_known(cmd), "expected {cmd} to be known");
        }
    }

    #[test]
    fn is_known_true_for_all_writer_commands() {
        let reg = CapabilityForwardRegistry::new();
        for cmd in &["cp", "mv", "rm", "mkdir", "touch"] {
            assert!(reg.is_known(cmd), "expected {cmd} to be known");
        }
    }

    #[test]
    fn is_known_true_for_all_process_commands() {
        let reg = CapabilityForwardRegistry::new();
        for cmd in &["ps", "kill", "uname", "whoami", "hostname"] {
            assert!(reg.is_known(cmd), "expected {cmd} to be known");
        }
    }

    // -----------------------------------------------------------------------
    // is_known: false for unknown commands
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_false_for_unknown_command() {
        let reg = CapabilityForwardRegistry::new();
        assert!(!reg.is_known("ssh"));
        assert!(!reg.is_known(""));
    }

    // -----------------------------------------------------------------------
    // commands() returns all 17 registered entries
    // -----------------------------------------------------------------------

    #[test]
    fn commands_returns_all_registered() {
        let reg = CapabilityForwardRegistry::new();
        let cmds = reg.commands();
        // 7 readers + 5 writers + 5 process = 17
        assert_eq!(cmds.len(), 17);
        assert!(cmds.contains(&"ls"));
        assert!(cmds.contains(&"cp"));
        assert!(cmds.contains(&"ps"));
    }

    // -----------------------------------------------------------------------
    // Default impl matches new()
    // -----------------------------------------------------------------------

    #[test]
    fn default_same_as_new() {
        let r1 = CapabilityForwardRegistry::new();
        let r2 = CapabilityForwardRegistry::default();
        assert_eq!(r1.commands(), r2.commands());
    }

    // -----------------------------------------------------------------------
    // No read-scope command accidentally has write action
    // -----------------------------------------------------------------------

    #[test]
    fn read_commands_do_not_have_write_action() {
        let reg = CapabilityForwardRegistry::new();
        for cmd in &["ls", "cat", "head", "tail", "wc", "find", "df"] {
            let scope = reg.get_scope(cmd).unwrap();
            assert_ne!(scope.action, "Write", "{cmd} must not have Write action");
        }
    }
}

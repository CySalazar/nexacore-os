//! Init process wiring — spawn the shell as PID 1.
//!
//! This module describes the boot sequence executed after the initramfs is
//! loaded into [`crate::vfs::InMemoryVfs`]:
//!
//! 1. Verify `/bin/nexacore-shell` exists in the VFS (placed by
//!    [`crate::initramfs::load_into_vfs`]).
//! 2. Build an [`crate::init_process::InitProcessArgs`] with the canonical argv and envp.
//! 3. Hand the args to the process-spawner, which creates PID 1.
//!
//! The module is **not** gated behind `bare-metal` — the argument
//! construction logic is testable on host builds without page-table or
//! ELF-loader infrastructure.

use alloc::{string::String, vec, vec::Vec};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default `$PATH` exported to every user process.
///
/// Phase 1 only exposes a single binary directory. Additional paths (e.g.
/// `/usr/bin`, `/usr/local/bin`) will be added when the on-disk filesystem
/// lands in Phase 2.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::init_process::DEFAULT_PATH;
/// assert_eq!(DEFAULT_PATH, "/bin");
/// ```
pub const DEFAULT_PATH: &str = "/bin";

// ---------------------------------------------------------------------------
// InitProcessArgs
// ---------------------------------------------------------------------------

/// Arguments for spawning the init process (PID 1).
///
/// The spawner uses these fields to:
/// - locate and map the shell ELF from the VFS,
/// - set up the initial argument vector on the user stack,
/// - populate the process environment.
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::init_process::InitProcessArgs;
///
/// let args = InitProcessArgs::default_shell();
/// assert_eq!(args.shell_path, "/bin/nexacore-shell");
/// assert!(!args.argv.is_empty());
/// assert!(!args.envp.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct InitProcessArgs {
    /// Path to the shell binary inside the VFS, e.g. `"/bin/nexacore-shell"`.
    pub shell_path: String,
    /// Argument vector passed to the process. `argv[0]` is conventionally the
    /// binary path.
    pub argv: Vec<String>,
    /// Environment variables as `(key, value)` pairs. Keys are upper-case
    /// POSIX names; values are UTF-8 strings.
    pub envp: Vec<(String, String)>,
}

impl InitProcessArgs {
    /// Create the canonical init process arguments for the NexaCore shell.
    ///
    /// The returned value sets:
    /// - `shell_path` = `"/bin/nexacore-shell"`
    /// - `argv` = `["/bin/nexacore-shell"]`
    /// - `envp` with `PATH`, `HOME`, `USER`, `HOSTNAME`, `SHELL`, and `TERM`
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_kernel::init_process::InitProcessArgs;
    ///
    /// let args = InitProcessArgs::default_shell();
    /// assert_eq!(args.shell_path, "/bin/nexacore-shell");
    /// assert_eq!(args.argv[0], "/bin/nexacore-shell");
    /// ```
    #[must_use]
    pub fn default_shell() -> Self {
        Self {
            shell_path: String::from("/bin/nexacore-shell"),
            argv: vec![String::from("/bin/nexacore-shell")],
            envp: default_envp(),
        }
    }
}

// ---------------------------------------------------------------------------
// default_envp
// ---------------------------------------------------------------------------

/// Build the default environment variable list for the init process.
///
/// Returns six canonical variables:
///
/// | Key        | Value              |
/// |------------|--------------------|
/// | `PATH`     | `/bin`             |
/// | `HOME`     | `/`                |
/// | `USER`     | `root`             |
/// | `HOSTNAME` | `nexacore`             |
/// | `SHELL`    | `/bin/nexacore-shell`  |
/// | `TERM`     | `vt100`            |
///
/// # Example
///
/// ```rust
/// use nexacore_kernel::init_process::default_envp;
///
/// let env = default_envp();
/// assert!(env.iter().any(|(k, v)| k == "PATH" && v == "/bin"));
/// assert!(env.iter().any(|(k, v)| k == "TERM" && v == "vt100"));
/// ```
#[must_use]
pub fn default_envp() -> Vec<(String, String)> {
    vec![
        (String::from("PATH"), String::from("/bin")),
        (String::from("HOME"), String::from("/")),
        (String::from("USER"), String::from("root")),
        (String::from("HOSTNAME"), String::from("nexacore")),
        (String::from("SHELL"), String::from("/bin/nexacore-shell")),
        (String::from("TERM"), String::from("vt100")),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use direct indexing for clarity; panics are the desired failure mode in tests"
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DEFAULT_PATH constant
    // -----------------------------------------------------------------------

    #[test]
    fn default_path_constant_is_slash_bin() {
        assert_eq!(DEFAULT_PATH, "/bin");
    }

    // -----------------------------------------------------------------------
    // InitProcessArgs::default_shell — shell_path
    // -----------------------------------------------------------------------

    #[test]
    fn default_shell_path_is_nexacore_shell() {
        let args = InitProcessArgs::default_shell();
        assert_eq!(args.shell_path, "/bin/nexacore-shell");
    }

    // -----------------------------------------------------------------------
    // InitProcessArgs::default_shell — argv
    // -----------------------------------------------------------------------

    #[test]
    fn default_shell_argv_is_single_element() {
        let args = InitProcessArgs::default_shell();
        assert_eq!(args.argv.len(), 1);
        assert_eq!(args.argv[0], "/bin/nexacore-shell");
    }

    // -----------------------------------------------------------------------
    // default_envp — PATH variable
    // -----------------------------------------------------------------------

    #[test]
    fn default_envp_contains_path() {
        let env = default_envp();
        assert!(env.iter().any(|(k, v)| k == "PATH" && v == "/bin"));
    }

    // -----------------------------------------------------------------------
    // default_envp — USER variable
    // -----------------------------------------------------------------------

    #[test]
    fn default_envp_contains_user_root() {
        let env = default_envp();
        assert!(env.iter().any(|(k, v)| k == "USER" && v == "root"));
    }

    // -----------------------------------------------------------------------
    // default_envp — SHELL variable
    // -----------------------------------------------------------------------

    #[test]
    fn default_envp_contains_shell() {
        let env = default_envp();
        assert!(
            env.iter()
                .any(|(k, v)| k == "SHELL" && v == "/bin/nexacore-shell")
        );
    }

    // -----------------------------------------------------------------------
    // default_envp — TERM variable
    // -----------------------------------------------------------------------

    #[test]
    fn default_envp_contains_term_vt100() {
        let env = default_envp();
        assert!(env.iter().any(|(k, v)| k == "TERM" && v == "vt100"));
    }

    // -----------------------------------------------------------------------
    // default_envp — exactly 6 entries
    // -----------------------------------------------------------------------

    #[test]
    fn default_envp_has_six_entries() {
        let env = default_envp();
        assert_eq!(env.len(), 6);
    }

    // -----------------------------------------------------------------------
    // default_envp — no duplicate keys
    // -----------------------------------------------------------------------

    #[test]
    fn default_envp_has_no_duplicate_keys() {
        use alloc::collections::BTreeSet;
        let env = default_envp();
        let keys: BTreeSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys.len(), env.len(), "duplicate env keys detected");
    }

    // -----------------------------------------------------------------------
    // InitProcessArgs::default_shell — envp matches default_envp()
    // -----------------------------------------------------------------------

    #[test]
    fn default_shell_envp_matches_default_envp() {
        let args = InitProcessArgs::default_shell();
        let env = default_envp();
        assert_eq!(args.envp.len(), env.len());
        for (a, b) in args.envp.iter().zip(env.iter()) {
            assert_eq!(a, b);
        }
    }
}

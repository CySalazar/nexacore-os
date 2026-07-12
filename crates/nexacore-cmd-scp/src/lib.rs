//! # `nexacore-cmd-scp`
//!
//! SCP file transfer command scaffold for NexaCore OS.
//!
//! Provides path type definitions and argument parsing for the `scp` command.
//! Actual file transfer logic depends on the SSH transport layer scaffold
//! (`nexacore-cmd-ssh`) and is deferred to a future sprint.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`ScpPath`] | Local or remote file path |
//! | [`ScpConfig`] | Source and destination for the copy |
//! | [`parse_scp_path`] | Parse `[[user@]host:]path` into [`ScpPath`] |
//! | [`parse_args`] | Parse `scp <source> <destination>` |
//! | [`ScpError`] | Typed errors |
//! | [`protocol`] | rcp/SCP transfer protocol state machine over a stream seam |

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
    )
)]

extern crate alloc;

pub mod protocol;

use alloc::string::{String, ToString};

use nexacore_types::net::Ipv4Addr;

// =============================================================================
// ScpPath
// =============================================================================

/// A file path that is either local to the running machine or remote.
///
/// The string representation of a remote path is `[[user@]host:]path`.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_scp::{ScpPath, parse_scp_path};
/// use nexacore_types::net::Ipv4Addr;
///
/// let local = parse_scp_path("/tmp/file.txt").unwrap();
/// assert!(matches!(local, ScpPath::Local(_)));
///
/// let remote = parse_scp_path("root@192.168.1.1:/etc/hosts").unwrap();
/// assert!(matches!(remote, ScpPath::Remote { .. }));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpPath {
    /// A path on the local filesystem.
    Local(String),
    /// A path on a remote host, accessible via SSH.
    Remote {
        /// Username for the SSH connection.
        user: String,
        /// Remote host `IPv4` address.
        host: Ipv4Addr,
        /// Absolute or relative path on the remote host.
        path: String,
    },
}

// =============================================================================
// ScpConfig
// =============================================================================

/// Source and destination configuration for an `scp` transfer.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_scp::{ScpConfig, parse_args};
///
/// let cfg = parse_args(&["/local/file", "root@192.168.1.1:/remote/dest"]).unwrap();
/// assert!(matches!(cfg.source, nexacore_cmd_scp::ScpPath::Local(_)));
/// assert!(matches!(
///     cfg.destination,
///     nexacore_cmd_scp::ScpPath::Remote { .. }
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScpConfig {
    /// Source file path (local or remote).
    pub source: ScpPath,
    /// Destination file path (local or remote).
    pub destination: ScpPath,
}

// =============================================================================
// ScpError
// =============================================================================

/// Errors returned by [`parse_scp_path`] and [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpError {
    /// The remote host string could not be parsed as an `IPv4` address.
    InvalidHost,
    /// A required source or destination argument was missing.
    MissingArgument,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Path parsing
// =============================================================================

/// Parse an SCP path string into a [`ScpPath`].
///
/// The path is treated as **remote** when it contains a `:` character (which
/// separates the host specification from the file path).  Everything before
/// the `:` is the `[user@]host` portion; everything after is the remote path.
///
/// If no `:` is present the path is treated as **local**.
///
/// The host must be a dotted-decimal `IPv4` address.  Hostname resolution is
/// not performed in this scaffold.
///
/// # Errors
///
/// - [`ScpError::InvalidHost`] — the host portion is not a valid `IPv4` address.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_scp::{ScpError, ScpPath, parse_scp_path};
/// use nexacore_types::net::Ipv4Addr;
///
/// // Local path.
/// let p = parse_scp_path("/tmp/file.txt").unwrap();
/// assert_eq!(p, ScpPath::Local(String::from("/tmp/file.txt")));
///
/// // Remote path with user.
/// let p = parse_scp_path("root@192.168.1.1:/etc/hosts").unwrap();
/// assert_eq!(
///     p,
///     ScpPath::Remote {
///         user: String::from("root"),
///         host: Ipv4Addr([192, 168, 1, 1]),
///         path: String::from("/etc/hosts"),
///     }
/// );
///
/// // Remote path without user.
/// let p = parse_scp_path("192.168.1.1:/tmp/out").unwrap();
/// assert!(matches!(p, ScpPath::Remote { .. }));
///
/// // Invalid host.
/// assert_eq!(parse_scp_path("badhost:/path"), Err(ScpError::InvalidHost));
/// ```
pub fn parse_scp_path(s: &str) -> Result<ScpPath, ScpError> {
    // Remote paths contain exactly one `:` that is not inside the leading
    // scheme (we don't support Windows drive letters in this scaffold).
    match s.find(':') {
        None => Ok(ScpPath::Local(s.to_string())),
        Some(colon_pos) => {
            let authority = s.get(..colon_pos).unwrap_or("");
            let path = s.get(colon_pos + 1..).unwrap_or("").to_string();

            // Split authority on `@` for user / host.
            let (user, host_str) = authority.find('@').map_or_else(
                || (String::new(), authority),
                |at| {
                    let u = authority.get(..at).unwrap_or("").to_string();
                    let h = authority.get(at + 1..).unwrap_or("");
                    (u, h)
                },
            );

            let host = host_str
                .parse::<Ipv4Addr>()
                .map_err(|_| ScpError::InvalidHost)?;

            Ok(ScpPath::Remote { user, host, path })
        }
    }
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `scp` command.
///
/// Expects exactly two non-flag positional arguments: source and destination.
///
/// # Errors
///
/// Returns an [`ScpError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_scp::{ScpPath, parse_args};
///
/// let cfg = parse_args(&["/local/file", "root@192.168.1.1:/tmp/dest"]).unwrap();
/// assert!(matches!(cfg.source, ScpPath::Local(_)));
/// assert!(matches!(cfg.destination, ScpPath::Remote { .. }));
///
/// assert!(parse_args(&["/local/only"]).is_err());
/// ```
pub fn parse_args(args: &[&str]) -> Result<ScpConfig, ScpError> {
    let mut positional: alloc::vec::Vec<&str> = alloc::vec::Vec::new();

    for &arg in args {
        if arg.starts_with('-') {
            return Err(ScpError::UnknownFlag);
        }
        positional.push(arg);
    }

    let src_str = positional.first().ok_or(ScpError::MissingArgument)?;
    let dst_str = positional.get(1).ok_or(ScpError::MissingArgument)?;

    let source = parse_scp_path(src_str)?;
    let destination = parse_scp_path(dst_str)?;

    Ok(ScpConfig {
        source,
        destination,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::*;

    // -------------------------------------------------------------------------
    // Path parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_local_path() {
        let p = parse_scp_path("/tmp/file.txt").unwrap();
        assert_eq!(p, ScpPath::Local(String::from("/tmp/file.txt")));
    }

    #[test]
    fn parse_remote_path_with_user() {
        let p = parse_scp_path("root@192.168.1.1:/etc/hosts").unwrap();
        assert_eq!(
            p,
            ScpPath::Remote {
                user: String::from("root"),
                host: Ipv4Addr([192, 168, 1, 1]),
                path: String::from("/etc/hosts"),
            }
        );
    }

    #[test]
    fn parse_remote_path_without_user() {
        let p = parse_scp_path("10.0.0.1:/tmp/out").unwrap();
        match p {
            ScpPath::Remote { user, host, path } => {
                assert_eq!(user, "");
                assert_eq!(host, Ipv4Addr([10, 0, 0, 1]));
                assert_eq!(path, "/tmp/out");
            }
            ScpPath::Local(_) => panic!("expected Remote"),
        }
    }

    #[test]
    fn parse_invalid_host() {
        assert_eq!(parse_scp_path("badhost:/path"), Err(ScpError::InvalidHost));
    }

    #[test]
    fn parse_relative_local_path() {
        let p = parse_scp_path("./file.txt").unwrap();
        assert_eq!(p, ScpPath::Local(String::from("./file.txt")));
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_local_to_remote() {
        let cfg = parse_args(&["/local/file", "root@192.168.1.1:/remote/"]).unwrap();
        assert!(matches!(cfg.source, ScpPath::Local(_)));
        assert!(matches!(cfg.destination, ScpPath::Remote { .. }));
    }

    #[test]
    fn parse_args_missing_destination() {
        assert_eq!(parse_args(&["/only/one"]), Err(ScpError::MissingArgument));
    }

    #[test]
    fn parse_args_missing_all() {
        assert_eq!(parse_args(&[]), Err(ScpError::MissingArgument));
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(
            parse_args(&["-r", "/src", "root@1.1.1.1:/dst"]),
            Err(ScpError::UnknownFlag)
        );
    }
}

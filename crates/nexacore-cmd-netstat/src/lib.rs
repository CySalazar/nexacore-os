//! # `nexacore-cmd-netstat`
//!
//! Network connection listing command for NexaCore OS.
//!
//! Provides type definitions, tabular formatting, and command-line argument
//! parsing for the `netstat` utility.  No I/O is performed; the caller
//! supplies connection data from the kernel.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`ConnectionDisplay`] | Snapshot of a single network connection |
//! | [`NetstatConfig`] | Filter/display options parsed from arguments |
//! | [`format_netstat`] | Format a connection list as a text table |
//! | [`parse_args`] | Parse `netstat [-a] [-n] [-p <proto>]` arguments |
//! | [`NetstatError`] | Typed errors from [`parse_args`] |

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

use alloc::{
    format,
    string::{String, ToString},
};

// =============================================================================
// ConnectionDisplay
// =============================================================================

/// A display snapshot of a single network connection or socket.
///
/// Fields are `String`-typed to remain independent of any specific address
/// representation and to support both `IPv4` and `IPv6` addresses.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_netstat::ConnectionDisplay;
///
/// let conn = ConnectionDisplay {
///     protocol: String::from("TCP"),
///     local_addr: String::from("0.0.0.0:80"),
///     remote_addr: String::from("0.0.0.0:0"),
///     state: String::from("LISTEN"),
/// };
/// assert_eq!(conn.protocol, "TCP");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDisplay {
    /// Protocol name (`"TCP"`, `"UDP"`, etc.).
    pub protocol: String,
    /// Local socket address in `address:port` format.
    pub local_addr: String,
    /// Remote socket address in `address:port` format.
    pub remote_addr: String,
    /// Connection state (`"LISTEN"`, `"ESTABLISHED"`, `"TIME_WAIT"`, etc.).
    pub state: String,
}

// =============================================================================
// NetstatConfig
// =============================================================================

/// Configuration for a `netstat` query.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_netstat::{NetstatConfig, parse_args};
///
/// let cfg = parse_args(&["-a"]).unwrap();
/// assert!(cfg.show_all);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetstatConfig {
    /// Show all sockets including listening sockets.
    pub show_all: bool,
    /// Suppress hostname lookup — display numeric addresses.
    pub numeric: bool,
    /// Filter to a specific protocol (e.g. `Some("TCP")`).
    pub protocol_filter: Option<String>,
}

// =============================================================================
// Output formatting
// =============================================================================

/// Format a list of connection snapshots as a columnar text table.
///
/// Produces output of the form:
///
/// ```text
/// Proto  Local Address         Foreign Address       State
/// TCP    0.0.0.0:80            0.0.0.0:0             LISTEN
/// TCP    192.168.1.5:54320     93.184.216.34:80      ESTABLISHED
/// ```
///
/// # Examples
///
/// ```
/// use nexacore_cmd_netstat::{ConnectionDisplay, format_netstat};
///
/// let conns = vec![ConnectionDisplay {
///     protocol: String::from("TCP"),
///     local_addr: String::from("0.0.0.0:80"),
///     remote_addr: String::from("0.0.0.0:0"),
///     state: String::from("LISTEN"),
/// }];
/// let out = format_netstat(&conns);
/// assert!(out.contains("Proto"));
/// assert!(out.contains("LISTEN"));
/// ```
#[must_use]
pub fn format_netstat(connections: &[ConnectionDisplay]) -> String {
    let mut out = format!(
        "{:<8} {:<22} {:<22} {}\n",
        "Proto", "Local Address", "Foreign Address", "State"
    );
    for c in connections {
        out.push_str(&format!(
            "{:<8} {:<22} {:<22} {}\n",
            c.protocol, c.local_addr, c.remote_addr, c.state
        ));
    }
    out
}

// =============================================================================
// NetstatError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetstatError {
    /// A required argument was missing after a flag.
    MissingArgument,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `netstat` command.
///
/// Supported flags:
///
/// | Flag | Effect |
/// |------|--------|
/// | `-a` | Show all sockets (including listening) |
/// | `-n` | Numeric output (no hostname resolution) |
/// | `-p <proto>` | Filter by protocol (e.g. `TCP`) |
///
/// # Errors
///
/// Returns a [`NetstatError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_netstat::{NetstatConfig, parse_args};
///
/// let cfg = parse_args(&["-a", "-n"]).unwrap();
/// assert!(cfg.show_all);
/// assert!(cfg.numeric);
///
/// let cfg = parse_args(&["-p", "UDP"]).unwrap();
/// assert_eq!(cfg.protocol_filter, Some(String::from("UDP")));
///
/// assert_eq!(parse_args(&[]), Ok(NetstatConfig::default()));
/// ```
pub fn parse_args(args: &[&str]) -> Result<NetstatConfig, NetstatError> {
    let mut cfg = NetstatConfig::default();
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = args.get(idx).copied().unwrap_or("");
        match arg {
            "-a" => cfg.show_all = true,
            "-n" => cfg.numeric = true,
            "-p" => {
                idx += 1;
                let proto = (*args.get(idx).ok_or(NetstatError::MissingArgument)?).to_string();
                cfg.protocol_filter = Some(proto);
            }
            s if s.starts_with('-') => return Err(NetstatError::UnknownFlag),
            _ => {} // ignore positional args for future extension
        }
        idx += 1;
    }
    Ok(cfg)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use super::*;

    fn listen_conn() -> ConnectionDisplay {
        ConnectionDisplay {
            protocol: String::from("TCP"),
            local_addr: String::from("0.0.0.0:80"),
            remote_addr: String::from("0.0.0.0:0"),
            state: String::from("LISTEN"),
        }
    }

    // -------------------------------------------------------------------------
    // Formatting
    // -------------------------------------------------------------------------

    #[test]
    fn format_netstat_has_header() {
        let out = format_netstat(&[]);
        assert!(out.contains("Proto"), "got: {out}");
        assert!(out.contains("Local Address"), "got: {out}");
        assert!(out.contains("State"), "got: {out}");
    }

    #[test]
    fn format_netstat_shows_connection() {
        let out = format_netstat(&[listen_conn()]);
        assert!(out.contains("TCP"), "got: {out}");
        assert!(out.contains("LISTEN"), "got: {out}");
        assert!(out.contains("0.0.0.0:80"), "got: {out}");
    }

    #[test]
    fn format_netstat_multiple_connections() {
        let conns = vec![
            listen_conn(),
            ConnectionDisplay {
                protocol: String::from("UDP"),
                local_addr: String::from("0.0.0.0:53"),
                remote_addr: String::from("0.0.0.0:0"),
                state: String::new(),
            },
        ];
        let out = format_netstat(&conns);
        assert!(out.contains("UDP"), "got: {out}");
        assert!(out.contains("0.0.0.0:53"), "got: {out}");
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_no_flags_returns_default() {
        assert_eq!(parse_args(&[]).unwrap(), NetstatConfig::default());
    }

    #[test]
    fn parse_args_show_all() {
        let cfg = parse_args(&["-a"]).unwrap();
        assert!(cfg.show_all);
    }

    #[test]
    fn parse_args_numeric() {
        let cfg = parse_args(&["-n"]).unwrap();
        assert!(cfg.numeric);
    }

    #[test]
    fn parse_args_protocol_filter() {
        let cfg = parse_args(&["-p", "TCP"]).unwrap();
        assert_eq!(cfg.protocol_filter, Some(String::from("TCP")));
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(parse_args(&["-z"]), Err(NetstatError::UnknownFlag));
    }

    #[test]
    fn parse_args_combined_flags() {
        let cfg = parse_args(&["-a", "-n", "-p", "UDP"]).unwrap();
        assert!(cfg.show_all);
        assert!(cfg.numeric);
        assert_eq!(cfg.protocol_filter, Some(String::from("UDP")));
    }
}

//! # `nexacore-cmd-nc`
//!
//! Netcat (`nc`) command for NexaCore OS — TCP/UDP network utility.
//!
//! Provides mode types and argument parsing for the `nc` command.  No I/O is
//! performed here; the caller implements the actual socket operations and
//! passes mode information obtained via [`parse_args`].
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`NcMode`] | Connect vs. listen mode |
//! | [`NcConfig`] | Full configuration including protocol selection |
//! | [`parse_args`] | Parse `nc [-u] [-l] [host] <port>` arguments |
//! | [`NcError`] | Typed errors from [`parse_args`] |

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

use nexacore_types::net::Ipv4Addr;

// =============================================================================
// NcMode
// =============================================================================

/// The operating mode of the `nc` command.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_nc::{NcConfig, NcMode, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = parse_args(&["192.168.1.1", "8080"]).unwrap();
/// assert!(matches!(cfg.mode, NcMode::Connect { port: 8080, .. }));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcMode {
    /// Connect to a remote host and port.
    Connect {
        /// Remote host `IPv4` address.
        host: Ipv4Addr,
        /// Remote TCP/UDP port.
        port: u16,
    },
    /// Listen for incoming connections on a local port.
    Listen {
        /// Local TCP/UDP port to bind.
        port: u16,
    },
}

// =============================================================================
// NcConfig
// =============================================================================

/// Configuration for the `nc` command.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_nc::{NcConfig, NcMode, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// let cfg = parse_args(&["-l", "9000"]).unwrap();
/// assert!(matches!(cfg.mode, NcMode::Listen { port: 9000 }));
/// assert!(!cfg.udp);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NcConfig {
    /// Operating mode: connect or listen.
    pub mode: NcMode,
    /// When `true`, use UDP instead of TCP.
    pub udp: bool,
}

// =============================================================================
// NcError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NcError {
    /// No port number was provided.
    MissingPort,
    /// The port value could not be parsed as a `u16`.
    InvalidPort,
    /// The host address could not be parsed as an `IPv4` address.
    InvalidHost,
    /// An unrecognised flag was encountered.
    UnknownFlag,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `nc` command.
///
/// Supported flags:
///
/// | Flag | Effect |
/// |------|--------|
/// | `-l` | Listen mode (bind to the port instead of connecting) |
/// | `-u` | Use UDP instead of TCP |
///
/// In connect mode the argument order is `[<host>] <port>` where `host`
/// defaults to `0.0.0.0` when omitted.  In listen mode only `<port>` is used.
///
/// # Errors
///
/// Returns an [`NcError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_nc::{NcError, NcMode, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// // Connect mode.
/// let cfg = parse_args(&["192.168.1.1", "80"]).unwrap();
/// assert_eq!(
///     cfg.mode,
///     NcMode::Connect {
///         host: Ipv4Addr([192, 168, 1, 1]),
///         port: 80
///     }
/// );
///
/// // Listen mode.
/// let cfg = parse_args(&["-l", "9000"]).unwrap();
/// assert_eq!(cfg.mode, NcMode::Listen { port: 9000 });
///
/// // UDP flag.
/// let cfg = parse_args(&["-u", "10.0.0.1", "53"]).unwrap();
/// assert!(cfg.udp);
///
/// assert_eq!(parse_args(&[]), Err(NcError::MissingPort));
/// ```
pub fn parse_args(args: &[&str]) -> Result<NcConfig, NcError> {
    let mut listen = false;
    let mut udp = false;
    let mut positional: alloc::vec::Vec<&str> = alloc::vec::Vec::new();

    for &arg in args {
        match arg {
            "-l" => listen = true,
            "-u" => udp = true,
            s if s.starts_with('-') => return Err(NcError::UnknownFlag),
            s => positional.push(s),
        }
    }

    if listen {
        // Listen mode: expect exactly one positional (port).
        let port_str = positional.first().ok_or(NcError::MissingPort)?;
        let port = port_str.parse::<u16>().map_err(|_| NcError::InvalidPort)?;
        return Ok(NcConfig {
            mode: NcMode::Listen { port },
            udp,
        });
    }

    // Connect mode.
    match positional.len() {
        0 => Err(NcError::MissingPort),
        1 => {
            // Only port given; default host to 0.0.0.0.
            let port_str = positional.first().ok_or(NcError::MissingPort)?;
            let port = port_str.parse::<u16>().map_err(|_| NcError::InvalidPort)?;
            Ok(NcConfig {
                mode: NcMode::Connect {
                    host: Ipv4Addr::UNSPECIFIED,
                    port,
                },
                udp,
            })
        }
        _ => {
            // Host + port.
            let host_str = positional.first().ok_or(NcError::MissingPort)?;
            let port_str = positional.get(1).ok_or(NcError::MissingPort)?;
            let host = host_str
                .parse::<Ipv4Addr>()
                .map_err(|_| NcError::InvalidHost)?;
            let port = port_str.parse::<u16>().map_err(|_| NcError::InvalidPort)?;
            Ok(NcConfig {
                mode: NcMode::Connect { host, port },
                udp,
            })
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_connect_host_and_port() {
        let cfg = parse_args(&["192.168.1.1", "80"]).unwrap();
        assert_eq!(
            cfg.mode,
            NcMode::Connect {
                host: Ipv4Addr([192, 168, 1, 1]),
                port: 80
            }
        );
        assert!(!cfg.udp);
    }

    #[test]
    fn parse_args_connect_port_only() {
        let cfg = parse_args(&["443"]).unwrap();
        assert!(matches!(cfg.mode, NcMode::Connect { port: 443, .. }));
    }

    #[test]
    fn parse_args_listen_mode() {
        let cfg = parse_args(&["-l", "9000"]).unwrap();
        assert_eq!(cfg.mode, NcMode::Listen { port: 9000 });
    }

    #[test]
    fn parse_args_udp_flag() {
        let cfg = parse_args(&["-u", "10.0.0.1", "53"]).unwrap();
        assert!(cfg.udp);
    }

    #[test]
    fn parse_args_no_args_returns_missing_port() {
        assert_eq!(parse_args(&[]), Err(NcError::MissingPort));
    }

    #[test]
    fn parse_args_invalid_port() {
        assert_eq!(parse_args(&["abc"]), Err(NcError::InvalidPort));
    }

    #[test]
    fn parse_args_unknown_flag() {
        assert_eq!(parse_args(&["-z", "80"]), Err(NcError::UnknownFlag));
    }
}

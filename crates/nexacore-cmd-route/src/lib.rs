//! # `nexacore-cmd-route`
//!
//! Routing table management command for NexaCore OS.
//!
//! Provides type definitions, routing-table formatting, and command-line
//! argument parsing for the `route` utility.  No I/O is performed; the caller
//! queries the kernel routing table and supplies the results to the formatting
//! helpers.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`RouteCommand`] | Discriminated union of route sub-commands |
//! | [`RouteDisplay`] | Display snapshot for a single routing-table entry |
//! | [`format_route_table`] | Format a complete routing table for display |
//! | [`parse_args`] | Parse `route [show|add|delete|default] ...` |
//! | [`RouteError`] | Typed errors from [`parse_args`] |

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

use alloc::{format, string::String};

use nexacore_types::net::{Cidr, Ipv4Addr};

// =============================================================================
// Internal helpers
// =============================================================================

/// Parse a CIDR string of the form `a.b.c.d/prefix` into a [`Cidr`].
///
/// Returns `None` when the format is invalid or the prefix length exceeds 32.
fn parse_cidr(s: &str) -> Option<Cidr> {
    let slash = s.find('/')?;
    let addr_str = s.get(..slash)?;
    let prefix_str = s.get(slash + 1..)?;
    let addr = addr_str.parse::<Ipv4Addr>().ok()?;
    let prefix_len = prefix_str.parse::<u8>().ok()?;
    Cidr::new(addr, prefix_len)
}

// =============================================================================
// RouteCommand
// =============================================================================

/// A parsed `route` sub-command.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_route::{RouteCommand, parse_args};
///
/// assert_eq!(parse_args(&["show"]).unwrap(), RouteCommand::Show);
/// assert_eq!(parse_args(&[]).unwrap(), RouteCommand::Show);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCommand {
    /// Display the current routing table.
    Show,
    /// Add a route: packets for `destination` will be forwarded via `gateway`.
    Add {
        /// Destination CIDR prefix (e.g. `10.0.0.0/8`).
        destination: Cidr,
        /// Next-hop gateway `IPv4` address.
        gateway: Ipv4Addr,
    },
    /// Delete the route for `destination`.
    Delete {
        /// Destination CIDR prefix to remove.
        destination: Cidr,
    },
    /// Set the default gateway (adds/replaces the `0.0.0.0/0` route).
    AddDefault {
        /// Default gateway `IPv4` address.
        gateway: Ipv4Addr,
    },
}

// =============================================================================
// RouteDisplay
// =============================================================================

/// A display snapshot of a single routing-table entry.
///
/// All fields are `String`-typed so the struct is independent of any specific
/// address representation crate used by the kernel.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_route::RouteDisplay;
///
/// let r = RouteDisplay {
///     destination: String::from("0.0.0.0/0"),
///     gateway: String::from("192.168.1.1"),
///     interface: String::from("eth0"),
///     metric: 100,
/// };
/// assert_eq!(r.metric, 100);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDisplay {
    /// Destination prefix in CIDR notation (e.g. `"0.0.0.0/0"`).
    pub destination: String,
    /// Next-hop gateway address (e.g. `"192.168.1.1"`).
    pub gateway: String,
    /// Output interface name (e.g. `"eth0"`).
    pub interface: String,
    /// Route metric (lower = preferred).
    pub metric: u32,
}

// =============================================================================
// Output formatting
// =============================================================================

/// Format a routing table as a columnar text table.
///
/// Produces output of the form:
///
/// ```text
/// Destination      Gateway          Iface     Metric
/// 0.0.0.0/0        192.168.1.1      eth0      100
/// 192.168.1.0/24   0.0.0.0          eth0      0
/// ```
///
/// # Examples
///
/// ```
/// use nexacore_cmd_route::{RouteDisplay, format_route_table};
///
/// let routes = vec![RouteDisplay {
///     destination: String::from("0.0.0.0/0"),
///     gateway: String::from("192.168.1.1"),
///     interface: String::from("eth0"),
///     metric: 100,
/// }];
/// let out = format_route_table(&routes);
/// assert!(out.contains("Destination"));
/// assert!(out.contains("192.168.1.1"));
/// ```
#[must_use]
pub fn format_route_table(routes: &[RouteDisplay]) -> String {
    let mut out = format!(
        "{:<20} {:<20} {:<12} {}\n",
        "Destination", "Gateway", "Iface", "Metric"
    );
    for r in routes {
        out.push_str(&format!(
            "{:<20} {:<20} {:<12} {}\n",
            r.destination, r.gateway, r.interface, r.metric
        ));
    }
    out
}

// =============================================================================
// RouteError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// An `IPv4` address string could not be parsed.
    InvalidAddress,
    /// A CIDR prefix string could not be parsed.
    InvalidCidr,
    /// A required positional argument was missing.
    MissingArgument,
    /// An unrecognised sub-command was given.
    UnknownCommand,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `route` command.
///
/// Supported sub-command patterns:
///
/// | Arguments | Result |
/// |-----------|--------|
/// | *(none)* or `show` | [`RouteCommand::Show`] |
/// | `add <cidr> <gateway>` | [`RouteCommand::Add`] |
/// | `delete <cidr>` | [`RouteCommand::Delete`] |
/// | `default <gateway>` | [`RouteCommand::AddDefault`] |
///
/// # Errors
///
/// Returns a [`RouteError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_route::{RouteCommand, RouteError, parse_args};
/// use nexacore_types::net::{Cidr, Ipv4Addr};
///
/// assert_eq!(parse_args(&[]).unwrap(), RouteCommand::Show);
/// assert_eq!(parse_args(&["show"]).unwrap(), RouteCommand::Show);
///
/// let cmd = parse_args(&["default", "192.168.1.1"]).unwrap();
/// assert_eq!(
///     cmd,
///     RouteCommand::AddDefault {
///         gateway: Ipv4Addr([192, 168, 1, 1])
///     }
/// );
///
/// assert_eq!(parse_args(&["bogus"]), Err(RouteError::UnknownCommand));
/// ```
pub fn parse_args(args: &[&str]) -> Result<RouteCommand, RouteError> {
    let sub = args.first().copied().unwrap_or("show");
    match sub {
        "show" | "" => Ok(RouteCommand::Show),
        "add" => {
            let cidr_str = args.get(1).ok_or(RouteError::MissingArgument)?;
            let gw_str = args.get(2).ok_or(RouteError::MissingArgument)?;
            let destination = parse_cidr(cidr_str).ok_or(RouteError::InvalidCidr)?;
            let gateway = gw_str
                .parse::<Ipv4Addr>()
                .map_err(|_| RouteError::InvalidAddress)?;
            Ok(RouteCommand::Add {
                destination,
                gateway,
            })
        }
        "delete" => {
            let cidr_str = args.get(1).ok_or(RouteError::MissingArgument)?;
            let destination = parse_cidr(cidr_str).ok_or(RouteError::InvalidCidr)?;
            Ok(RouteCommand::Delete { destination })
        }
        "default" => {
            let gw_str = args.get(1).ok_or(RouteError::MissingArgument)?;
            let gateway = gw_str
                .parse::<Ipv4Addr>()
                .map_err(|_| RouteError::InvalidAddress)?;
            Ok(RouteCommand::AddDefault { gateway })
        }
        _ => Err(RouteError::UnknownCommand),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use super::*;

    fn sample_route() -> RouteDisplay {
        RouteDisplay {
            destination: String::from("0.0.0.0/0"),
            gateway: String::from("192.168.1.1"),
            interface: String::from("eth0"),
            metric: 100,
        }
    }

    // -------------------------------------------------------------------------
    // Formatting
    // -------------------------------------------------------------------------

    #[test]
    fn format_route_table_has_header() {
        let out = format_route_table(&[]);
        assert!(out.contains("Destination"), "got: {out}");
        assert!(out.contains("Gateway"), "got: {out}");
    }

    #[test]
    fn format_route_table_shows_route() {
        let out = format_route_table(&[sample_route()]);
        assert!(out.contains("0.0.0.0/0"), "got: {out}");
        assert!(out.contains("192.168.1.1"), "got: {out}");
        assert!(out.contains("eth0"), "got: {out}");
        assert!(out.contains("100"), "got: {out}");
    }

    #[test]
    fn format_route_table_multiple_routes() {
        let routes = vec![
            sample_route(),
            RouteDisplay {
                destination: String::from("10.0.0.0/8"),
                gateway: String::from("10.0.0.1"),
                interface: String::from("eth1"),
                metric: 200,
            },
        ];
        let out = format_route_table(&routes);
        assert!(out.contains("10.0.0.0/8"), "got: {out}");
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_no_args_is_show() {
        assert_eq!(parse_args(&[]).unwrap(), RouteCommand::Show);
    }

    #[test]
    fn parse_args_show_explicit() {
        assert_eq!(parse_args(&["show"]).unwrap(), RouteCommand::Show);
    }

    #[test]
    fn parse_args_default_gateway() {
        let cmd = parse_args(&["default", "10.0.0.1"]).unwrap();
        assert_eq!(
            cmd,
            RouteCommand::AddDefault {
                gateway: Ipv4Addr([10, 0, 0, 1])
            }
        );
    }

    #[test]
    fn parse_args_delete() {
        let cmd = parse_args(&["delete", "192.168.1.0/24"]).unwrap();
        assert!(matches!(cmd, RouteCommand::Delete { .. }));
    }

    #[test]
    fn parse_args_add() {
        let cmd = parse_args(&["add", "10.0.0.0/8", "10.0.0.1"]).unwrap();
        assert!(matches!(cmd, RouteCommand::Add { .. }));
    }

    #[test]
    fn parse_args_unknown_subcommand() {
        assert_eq!(parse_args(&["bogus"]), Err(RouteError::UnknownCommand));
    }
}

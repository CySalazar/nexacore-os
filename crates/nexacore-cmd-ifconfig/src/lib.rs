//! # `nexacore-cmd-ifconfig`
//!
//! Network interface configuration command for NexaCore OS.
//!
//! Provides type definitions, output formatting, and command-line argument
//! parsing for the `ifconfig` utility.  No I/O is performed; the caller
//! queries the kernel and passes the data to the formatting helpers.
//!
//! ## Modules / responsibilities
//!
//! | Item | Description |
//! |------|-------------|
//! | [`IfconfigCommand`] | Discriminated union of ifconfig sub-commands |
//! | [`InterfaceDisplay`] | Snapshot of one network interface |
//! | [`format_interface`] | Format a single interface in ifconfig style |
//! | [`parse_args`] | Parse `ifconfig [<iface> [<cmd> ...]]` arguments |
//! | [`IfconfigError`] | Typed errors from [`parse_args`] |

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
    vec::Vec,
};

use nexacore_types::net::{Ipv4Addr, MacAddress};

// =============================================================================
// IfconfigCommand
// =============================================================================

/// A parsed `ifconfig` sub-command.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ifconfig::{IfconfigCommand, parse_args};
///
/// // No arguments → list all interfaces.
/// assert_eq!(parse_args(&[]).unwrap(), IfconfigCommand::ListAll);
///
/// // Interface name only → show that interface.
/// let cmd = parse_args(&["eth0"]).unwrap();
/// assert!(matches!(cmd, IfconfigCommand::ShowInterface { .. }));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfconfigCommand {
    /// List all network interfaces with their status.
    ListAll,
    /// Display the configuration of a specific interface.
    ShowInterface {
        /// Name of the interface to display (e.g. `"eth0"`).
        name: String,
    },
    /// Assign an `IPv4` address and netmask to an interface.
    SetAddress {
        /// Interface name.
        name: String,
        /// `IPv4` address to assign.
        ip: Ipv4Addr,
        /// Subnet netmask.
        netmask: Ipv4Addr,
    },
    /// Bring an interface up (enable it).
    BringUp {
        /// Interface name.
        name: String,
    },
    /// Bring an interface down (disable it).
    BringDown {
        /// Interface name.
        name: String,
    },
}

// =============================================================================
// InterfaceDisplay
// =============================================================================

/// A snapshot of a network interface for display purposes.
///
/// All fields are owned so the struct can be constructed without a lifetime
/// tied to any kernel data structure.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ifconfig::InterfaceDisplay;
/// use nexacore_types::net::{Ipv4Addr, MacAddress};
///
/// let iface = InterfaceDisplay {
///     name: String::from("eth0"),
///     mac: MacAddress([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
///     ip: Some(Ipv4Addr([192, 168, 1, 10])),
///     netmask: Some(Ipv4Addr([255, 255, 255, 0])),
///     link_up: true,
///     rx_bytes: 1024,
///     tx_bytes: 2048,
/// };
/// assert_eq!(iface.name, "eth0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDisplay {
    /// Kernel interface name (e.g. `"eth0"`, `"lo"`).
    pub name: String,
    /// Hardware (MAC) address.
    pub mac: MacAddress,
    /// `IPv4` address, if configured.
    pub ip: Option<Ipv4Addr>,
    /// `IPv4` subnet mask, if configured.
    pub netmask: Option<Ipv4Addr>,
    /// `true` if the interface link is currently up.
    pub link_up: bool,
    /// Total bytes received since last reset.
    pub rx_bytes: u64,
    /// Total bytes transmitted since last reset.
    pub tx_bytes: u64,
}

// =============================================================================
// Output formatting
// =============================================================================

/// Format a network interface snapshot in the style of classic `ifconfig`
/// output.
///
/// Produces multi-line output such as:
///
/// ```text
/// eth0: flags=UP  mtu 1500
///         ether 00:1a:2b:3c:4d:5e
///         inet 192.168.1.10  netmask 255.255.255.0
///         RX bytes 1024  TX bytes 2048
/// ```
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ifconfig::{InterfaceDisplay, format_interface};
/// use nexacore_types::net::{Ipv4Addr, MacAddress};
///
/// let iface = InterfaceDisplay {
///     name: String::from("lo"),
///     mac: MacAddress([0, 0, 0, 0, 0, 0]),
///     ip: Some(Ipv4Addr([127, 0, 0, 1])),
///     netmask: Some(Ipv4Addr([255, 0, 0, 0])),
///     link_up: true,
///     rx_bytes: 0,
///     tx_bytes: 0,
/// };
/// let out = format_interface(&iface);
/// assert!(out.contains("lo:"));
/// assert!(out.contains("127.0.0.1"));
/// ```
#[must_use]
pub fn format_interface(iface: &InterfaceDisplay) -> String {
    let flags = if iface.link_up { "UP" } else { "DOWN" };
    let mut out = format!("{}: flags={flags}  mtu 1500\n", iface.name);
    out.push_str(&format!("        ether {}\n", iface.mac));
    if let (Some(ip), Some(nm)) = (iface.ip, iface.netmask) {
        out.push_str(&format!("        inet {ip}  netmask {nm}\n"));
    }
    out.push_str(&format!(
        "        RX bytes {}  TX bytes {}",
        iface.rx_bytes, iface.tx_bytes
    ));
    out
}

/// Format a collection of interface snapshots separated by blank lines.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ifconfig::{InterfaceDisplay, format_all_interfaces};
/// use nexacore_types::net::{Ipv4Addr, MacAddress};
///
/// let ifaces = vec![InterfaceDisplay {
///     name: String::from("eth0"),
///     mac: MacAddress([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
///     ip: None,
///     netmask: None,
///     link_up: false,
///     rx_bytes: 0,
///     tx_bytes: 0,
/// }];
/// let out = format_all_interfaces(&ifaces);
/// assert!(out.contains("eth0:"));
/// ```
#[must_use]
pub fn format_all_interfaces(ifaces: &[InterfaceDisplay]) -> String {
    ifaces
        .iter()
        .map(format_interface)
        .collect::<Vec<_>>()
        .join("\n\n")
}

// =============================================================================
// IfconfigError
// =============================================================================

/// Errors returned by [`parse_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfconfigError {
    /// A required argument was missing after a keyword.
    MissingArgument,
    /// A string could not be parsed as an `IPv4` address.
    InvalidAddress,
    /// An unrecognised keyword or flag was encountered.
    UnknownCommand,
}

// =============================================================================
// Argument parsing
// =============================================================================

/// Parse command-line arguments for the `ifconfig` command.
///
/// Argument patterns accepted:
///
/// | Arguments | Result |
/// |-----------|--------|
/// | *(none)* | [`IfconfigCommand::ListAll`] |
/// | `<iface>` | [`IfconfigCommand::ShowInterface`] |
/// | `<iface> <ip> <netmask>` | [`IfconfigCommand::SetAddress`] |
/// | `<iface> up` | [`IfconfigCommand::BringUp`] |
/// | `<iface> down` | [`IfconfigCommand::BringDown`] |
///
/// # Errors
///
/// Returns an [`IfconfigError`] when arguments cannot be parsed.
///
/// # Examples
///
/// ```
/// use nexacore_cmd_ifconfig::{IfconfigCommand, parse_args};
/// use nexacore_types::net::Ipv4Addr;
///
/// assert_eq!(parse_args(&[]).unwrap(), IfconfigCommand::ListAll);
///
/// let cmd = parse_args(&["eth0", "192.168.1.1", "255.255.255.0"]).unwrap();
/// assert_eq!(
///     cmd,
///     IfconfigCommand::SetAddress {
///         name: String::from("eth0"),
///         ip: Ipv4Addr([192, 168, 1, 1]),
///         netmask: Ipv4Addr([255, 255, 255, 0]),
///     }
/// );
///
/// let cmd = parse_args(&["eth0", "up"]).unwrap();
/// assert!(matches!(cmd, IfconfigCommand::BringUp { .. }));
/// ```
pub fn parse_args(args: &[&str]) -> Result<IfconfigCommand, IfconfigError> {
    match args.len() {
        0 => Ok(IfconfigCommand::ListAll),
        1 => {
            let name = args.first().copied().unwrap_or("").to_string();
            Ok(IfconfigCommand::ShowInterface { name })
        }
        2 => {
            let name = args.first().copied().unwrap_or("").to_string();
            let cmd = args.get(1).copied().unwrap_or("");
            match cmd {
                "up" => Ok(IfconfigCommand::BringUp { name }),
                "down" => Ok(IfconfigCommand::BringDown { name }),
                _ => Err(IfconfigError::UnknownCommand),
            }
        }
        3 => {
            let name = args.first().copied().unwrap_or("").to_string();
            let ip_str = args.get(1).copied().unwrap_or("");
            let nm_str = args.get(2).copied().unwrap_or("");
            let ip = ip_str
                .parse::<Ipv4Addr>()
                .map_err(|_| IfconfigError::InvalidAddress)?;
            let netmask = nm_str
                .parse::<Ipv4Addr>()
                .map_err(|_| IfconfigError::InvalidAddress)?;
            Ok(IfconfigCommand::SetAddress { name, ip, netmask })
        }
        _ => Err(IfconfigError::UnknownCommand),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use super::*;

    fn sample_iface() -> InterfaceDisplay {
        InterfaceDisplay {
            name: String::from("eth0"),
            mac: MacAddress([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
            ip: Some(Ipv4Addr([192, 168, 1, 10])),
            netmask: Some(Ipv4Addr([255, 255, 255, 0])),
            link_up: true,
            rx_bytes: 1024,
            tx_bytes: 2048,
        }
    }

    // -------------------------------------------------------------------------
    // Formatting
    // -------------------------------------------------------------------------

    #[test]
    fn format_interface_contains_name_and_mac() {
        let out = format_interface(&sample_iface());
        assert!(out.contains("eth0:"), "got: {out}");
        assert!(out.contains("00:1a:2b:3c:4d:5e"), "got: {out}");
    }

    #[test]
    fn format_interface_shows_ip_and_netmask() {
        let out = format_interface(&sample_iface());
        assert!(out.contains("192.168.1.10"), "got: {out}");
        assert!(out.contains("255.255.255.0"), "got: {out}");
    }

    #[test]
    fn format_interface_shows_rx_tx() {
        let out = format_interface(&sample_iface());
        assert!(out.contains("RX bytes 1024"), "got: {out}");
        assert!(out.contains("TX bytes 2048"), "got: {out}");
    }

    #[test]
    fn format_interface_down_shows_down_flag() {
        let mut iface = sample_iface();
        iface.link_up = false;
        let out = format_interface(&iface);
        assert!(out.contains("DOWN"), "got: {out}");
    }

    #[test]
    fn format_interface_no_ip_omits_inet_line() {
        let mut iface = sample_iface();
        iface.ip = None;
        iface.netmask = None;
        let out = format_interface(&iface);
        assert!(!out.contains("inet"), "got: {out}");
    }

    #[test]
    fn format_all_interfaces_joins_with_blank_line() {
        let ifaces = vec![sample_iface(), sample_iface()];
        let out = format_all_interfaces(&ifaces);
        assert!(out.contains("\n\n"), "got: {out}");
    }

    // -------------------------------------------------------------------------
    // Argument parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_args_no_args_list_all() {
        assert_eq!(parse_args(&[]).unwrap(), IfconfigCommand::ListAll);
    }

    #[test]
    fn parse_args_single_iface_shows_interface() {
        let cmd = parse_args(&["eth0"]).unwrap();
        assert_eq!(
            cmd,
            IfconfigCommand::ShowInterface {
                name: String::from("eth0")
            }
        );
    }

    #[test]
    fn parse_args_up_command() {
        let cmd = parse_args(&["eth0", "up"]).unwrap();
        assert_eq!(
            cmd,
            IfconfigCommand::BringUp {
                name: String::from("eth0")
            }
        );
    }

    #[test]
    fn parse_args_down_command() {
        let cmd = parse_args(&["eth0", "down"]).unwrap();
        assert_eq!(
            cmd,
            IfconfigCommand::BringDown {
                name: String::from("eth0")
            }
        );
    }

    #[test]
    fn parse_args_set_address() {
        let cmd = parse_args(&["eth0", "10.0.0.1", "255.0.0.0"]).unwrap();
        assert_eq!(
            cmd,
            IfconfigCommand::SetAddress {
                name: String::from("eth0"),
                ip: Ipv4Addr([10, 0, 0, 1]),
                netmask: Ipv4Addr([255, 0, 0, 0]),
            }
        );
    }

    #[test]
    fn parse_args_invalid_ip() {
        assert_eq!(
            parse_args(&["eth0", "not-an-ip", "255.0.0.0"]),
            Err(IfconfigError::InvalidAddress)
        );
    }

    #[test]
    fn parse_args_unknown_two_arg_command() {
        assert_eq!(
            parse_args(&["eth0", "restart"]),
            Err(IfconfigError::UnknownCommand)
        );
    }

    #[test]
    fn parse_args_too_many_args() {
        assert_eq!(
            parse_args(&["a", "b", "c", "d"]),
            Err(IfconfigError::UnknownCommand)
        );
    }
}

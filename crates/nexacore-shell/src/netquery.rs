//! Network-interface query trait — enables testing without a real kernel.
//!
//! Mirrors [`crate::glob::FsQuery`]: the shell's `ifconfig` builtin
//! ([`crate::commands::net_cmds`]) uses this trait instead of talking IPC
//! directly, so this crate stays IPC-agnostic (no dependency on
//! `nexacore-net`'s heavier TCP/IP wire types). Production code passes an
//! implementation that resolves and queries the real
//! `nexacore.svc.net.config` service; test code passes a mock.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use nexacore_cmd_ifconfig::InterfaceDisplay;

/// Trait for network-interface queries, enabling testing without a real
/// kernel or network stack.
///
/// # Examples
///
/// ```rust
/// use nexacore_cmd_ifconfig::InterfaceDisplay;
/// use nexacore_shell::netquery::NetQuery;
/// use nexacore_types::net::MacAddress;
///
/// struct MockNet;
/// impl NetQuery for MockNet {
///     fn list_interfaces(&self) -> Result<Vec<InterfaceDisplay>, String> {
///         Ok(vec![InterfaceDisplay {
///             name: "eth0".into(),
///             mac: MacAddress([0; 6]),
///             ip: None,
///             netmask: None,
///             link_up: true,
///             rx_bytes: 0,
///             tx_bytes: 0,
///         }])
///     }
///     fn get_interface(&self, name: &str) -> Result<InterfaceDisplay, String> {
///         Err(format!("{name}: not found"))
///     }
/// }
///
/// let net = MockNet;
/// assert_eq!(net.list_interfaces().unwrap().len(), 1);
/// ```
pub trait NetQuery {
    /// List every known network interface.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if the network configuration service is
    /// unreachable. The error string is for diagnostics only.
    fn list_interfaces(&self) -> Result<Vec<InterfaceDisplay>, String>;

    /// Query a single interface by name.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `name` does not match a known interface, or
    /// if the network configuration service is unreachable.
    fn get_interface(&self, name: &str) -> Result<InterfaceDisplay, String>;
}

/// A [`NetQuery`] implementation with no interfaces — used by callers (or
/// test/doctest fixtures) that have no real network stack to query.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoNet;

impl NetQuery for NoNet {
    fn list_interfaces(&self) -> Result<Vec<InterfaceDisplay>, String> {
        Ok(Vec::new())
    }

    fn get_interface(&self, name: &str) -> Result<InterfaceDisplay, String> {
        Err(alloc::format!("{name}: no network service available"))
    }
}

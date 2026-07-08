//! Network interface configuration API (N6.1).
//!
//! This module defines the IPC request/response types for the network
//! configuration service, reachable on the
//! [`nexacore_types::socket::NET_CONFIG_CHANNEL`] IPC channel
//! (`"nexacore.svc.net.config"`).
//!
//! Privileged administrative clients use these types to:
//! - List all network interfaces and their statistics.
//! - Query or set IP address, netmask, and gateway.
//! - Configure DNS servers.
//! - Bring interfaces up or down.
//!
//! ## Encoding
//!
//! All types implement `serde::{Serialize, Deserialize}` and are intended to
//! be encoded with `nexacore_types::wire::encode_canonical` (postcard) before
//! being written to the IPC channel.
//!
//! ## Extensibility
//!
//! Both [`NetConfigRequest`] and [`NetConfigResponse`] carry `#[non_exhaustive]`
//! so future variants can be added without breaking existing compiled clients.
//! Removing or renaming a variant is a breaking change requiring a
//! Standards-Track NCIP.
//!
//! ## Example
//!
//! ```
//! use nexacore_net::ifconfig::{NetConfigRequest, NetConfigResponse};
//!
//! let req = NetConfigRequest::ListInterfaces;
//! // In production, encode with nexacore_types::wire::encode_canonical(&req).
//! let _req = req;
//!
//! let resp = NetConfigResponse::Ok;
//! let _resp = resp;
//! ```

use alloc::{string::String, vec::Vec};

use nexacore_types::net::{Cidr, Ipv4Addr, MacAddress};
use serde::{Deserialize, Serialize};

// =============================================================================
// InterfaceInfo
// =============================================================================

/// Runtime state and cumulative statistics for a single network interface.
///
/// Returned inside [`NetConfigResponse::Interfaces`] or
/// [`NetConfigResponse::Interface`]. All counter fields (`rx_*`, `tx_*`) are
/// monotonically increasing since the interface was last reset; callers that
/// want rate information must compute deltas between two successive queries.
///
/// # Examples
///
/// ```
/// use nexacore_net::ifconfig::InterfaceInfo;
/// use nexacore_types::net::{Cidr, Ipv4Addr, MacAddress};
///
/// let info = InterfaceInfo {
///     name: "eth0".into(),
///     mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
///     ip: Some(Ipv4Addr([10, 0, 0, 1])),
///     netmask: Cidr::new(Ipv4Addr([10, 0, 0, 0]), 8),
///     gateway: None,
///     link_up: true,
///     speed_mbps: 1000,
///     rx_bytes: 0,
///     tx_bytes: 0,
///     rx_packets: 0,
///     tx_packets: 0,
///     rx_errors: 0,
///     tx_errors: 0,
/// };
/// assert_eq!(info.name, "eth0");
/// assert!(info.link_up);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// Kernel interface name (e.g., `"eth0"`, `"lo"`).
    pub name: String,
    /// Hardware MAC address of the interface.
    pub mac: MacAddress,
    /// Assigned `IPv4` address, if any.
    pub ip: Option<Ipv4Addr>,
    /// Network mask expressed as a CIDR block, if set.
    pub netmask: Option<Cidr>,
    /// Default gateway for this interface, if configured.
    pub gateway: Option<Ipv4Addr>,
    /// `true` when the physical link is detected (carrier present).
    pub link_up: bool,
    /// Reported link speed in megabits per second. `0` if unknown.
    pub speed_mbps: u32,
    /// Total bytes received since last reset.
    pub rx_bytes: u64,
    /// Total bytes transmitted since last reset.
    pub tx_bytes: u64,
    /// Total packets received since last reset.
    pub rx_packets: u64,
    /// Total packets transmitted since last reset.
    pub tx_packets: u64,
    /// Total receive errors (frame check failures, overruns, etc.) since last reset.
    pub rx_errors: u64,
    /// Total transmit errors (carrier loss, FIFO underruns, etc.) since last reset.
    pub tx_errors: u64,
}

// =============================================================================
// NetConfigRequest
// =============================================================================

/// A request from a privileged client to the network configuration service.
///
/// Sent on the [`nexacore_types::socket::NET_CONFIG_CHANNEL`]
/// (`"nexacore.svc.net.config"`) IPC channel. The service processes requests
/// sequentially and replies with exactly one [`NetConfigResponse`].
///
/// # Examples
///
/// ```
/// use nexacore_net::ifconfig::NetConfigRequest;
/// use nexacore_types::net::{Cidr, Ipv4Addr};
///
/// let req = NetConfigRequest::SetAddress {
///     name: "eth0".into(),
///     ip: Ipv4Addr([192, 168, 1, 100]),
///     netmask: Cidr::new(Ipv4Addr([192, 168, 1, 0]), 24).unwrap(),
/// };
/// let _req = req;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetConfigRequest {
    /// Return information about all known network interfaces.
    ///
    /// The service replies with [`NetConfigResponse::Interfaces`].
    ListInterfaces,

    /// Return information about a single interface identified by `name`.
    ///
    /// The service replies with [`NetConfigResponse::Interface`] on success
    /// or [`NetConfigResponse::Error`] if no interface with that name exists.
    GetInterface {
        /// Interface name, e.g. `"eth0"`.
        name: String,
    },

    /// Assign a static `IPv4` address and netmask to an interface.
    ///
    /// The service replies with [`NetConfigResponse::Ok`] on success or
    /// [`NetConfigResponse::Error`] on failure.
    SetAddress {
        /// Target interface name.
        name: String,
        /// `IPv4` address to assign.
        ip: Ipv4Addr,
        /// Network mask expressed as a CIDR block.
        netmask: Cidr,
    },

    /// Set the default gateway for outbound traffic.
    ///
    /// The service replies with [`NetConfigResponse::Ok`] on success or
    /// [`NetConfigResponse::Error`] on failure.
    SetGateway {
        /// `IPv4` address of the gateway router.
        gateway: Ipv4Addr,
    },

    /// Replace the list of upstream DNS resolver addresses.
    ///
    /// The service replies with [`NetConfigResponse::Ok`] on success or
    /// [`NetConfigResponse::Error`] on failure.
    SetDns {
        /// Ordered list of DNS server `IPv4` addresses. The first entry is
        /// queried first; subsequent entries are tried in order on failure.
        servers: Vec<Ipv4Addr>,
    },

    /// Bring a network interface up (enable carrier and start transmitting).
    ///
    /// The service replies with [`NetConfigResponse::Ok`] on success or
    /// [`NetConfigResponse::Error`] if the interface name is unknown.
    BringUp {
        /// Interface name to bring up.
        name: String,
    },

    /// Bring a network interface down (disable carrier and stop transmitting).
    ///
    /// The service replies with [`NetConfigResponse::Ok`] on success or
    /// [`NetConfigResponse::Error`] if the interface name is unknown.
    BringDown {
        /// Interface name to bring down.
        name: String,
    },
}

// =============================================================================
// NetConfigResponse
// =============================================================================

/// A response from the network configuration service to a privileged client.
///
/// Every [`NetConfigRequest`] receives exactly one [`NetConfigResponse`]. The
/// mapping is documented per [`NetConfigRequest`] variant.
///
/// # Examples
///
/// ```
/// extern crate alloc;
/// use nexacore_net::ifconfig::{InterfaceInfo, NetConfigResponse};
/// use nexacore_types::net::MacAddress;
///
/// let resp = NetConfigResponse::Interfaces(alloc::vec![]);
/// match resp {
///     NetConfigResponse::Interfaces(list) => assert!(list.is_empty()),
///     _ => panic!("unexpected variant"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetConfigResponse {
    /// A list of all network interfaces (reply to [`NetConfigRequest::ListInterfaces`]).
    Interfaces(Vec<InterfaceInfo>),

    /// A single interface (reply to [`NetConfigRequest::GetInterface`]).
    Interface(InterfaceInfo),

    /// The request completed successfully with no data to return.
    Ok,

    /// The request failed; the inner string describes the error.
    Error(String),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use alloc::{string::ToString, vec};

    use super::*;

    // Helper: a default InterfaceInfo for reuse across tests.
    fn eth0() -> InterfaceInfo {
        InterfaceInfo {
            name: "eth0".to_string(),
            mac: MacAddress([0x02, 0xAB, 0xCD, 0xEF, 0x01, 0x02]),
            ip: Some(Ipv4Addr([192, 168, 1, 10])),
            netmask: Cidr::new(Ipv4Addr([192, 168, 1, 0]), 24),
            gateway: Some(Ipv4Addr([192, 168, 1, 1])),
            link_up: true,
            speed_mbps: 1000,
            rx_bytes: 123_456_789,
            tx_bytes: 987_654_321,
            rx_packets: 10_000,
            tx_packets: 9_000,
            rx_errors: 5,
            tx_errors: 0,
        }
    }

    // Encode/decode round-trip via the workspace-mandated canonical encoding.
    // All call sites MUST use nexacore_types::wire — never invoke postcard directly.
    fn roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let bytes = nexacore_types::wire::encode_canonical(value).expect("encode");
        nexacore_types::wire::decode_canonical(&bytes).expect("decode")
    }

    // -------------------------------------------------------------------------
    // InterfaceInfo
    // -------------------------------------------------------------------------

    #[test]
    fn interface_info_roundtrip_full() {
        let original = eth0();
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn interface_info_roundtrip_minimal() {
        let original = InterfaceInfo {
            name: "lo".to_string(),
            mac: MacAddress([0x00; 6]),
            ip: None,
            netmask: None,
            gateway: None,
            link_up: false,
            speed_mbps: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    // -------------------------------------------------------------------------
    // NetConfigRequest — one test per variant
    // -------------------------------------------------------------------------

    #[test]
    fn request_list_interfaces_roundtrip() {
        let original = NetConfigRequest::ListInterfaces;
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_get_interface_roundtrip() {
        let original = NetConfigRequest::GetInterface {
            name: "eth0".to_string(),
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_set_address_roundtrip() {
        let original = NetConfigRequest::SetAddress {
            name: "eth0".to_string(),
            ip: Ipv4Addr([10, 0, 0, 5]),
            netmask: Cidr::new(Ipv4Addr([10, 0, 0, 0]), 8).unwrap(),
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_set_gateway_roundtrip() {
        let original = NetConfigRequest::SetGateway {
            gateway: Ipv4Addr([192, 168, 0, 1]),
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_set_dns_roundtrip() {
        let original = NetConfigRequest::SetDns {
            servers: vec![Ipv4Addr([8, 8, 8, 8]), Ipv4Addr([1, 1, 1, 1])],
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_set_dns_empty_roundtrip() {
        let original = NetConfigRequest::SetDns { servers: vec![] };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_bring_up_roundtrip() {
        let original = NetConfigRequest::BringUp {
            name: "eth1".to_string(),
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn request_bring_down_roundtrip() {
        let original = NetConfigRequest::BringDown {
            name: "wlan0".to_string(),
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    // -------------------------------------------------------------------------
    // NetConfigResponse — one test per variant
    // -------------------------------------------------------------------------

    #[test]
    fn response_interfaces_roundtrip() {
        let original = NetConfigResponse::Interfaces(vec![eth0()]);
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn response_interfaces_empty_roundtrip() {
        let original = NetConfigResponse::Interfaces(vec![]);
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn response_interface_roundtrip() {
        let original = NetConfigResponse::Interface(eth0());
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn response_ok_roundtrip() {
        let original = NetConfigResponse::Ok;
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    #[test]
    fn response_error_roundtrip() {
        let original = NetConfigResponse::Error("interface not found".to_string());
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
    }

    // -------------------------------------------------------------------------
    // Encoding determinism
    // -------------------------------------------------------------------------

    #[test]
    fn encoding_is_deterministic() {
        let value = NetConfigRequest::SetAddress {
            name: "eth0".to_string(),
            ip: Ipv4Addr([172, 16, 0, 1]),
            netmask: Cidr::new(Ipv4Addr([172, 16, 0, 0]), 12).unwrap(),
        };
        let a = nexacore_types::wire::encode_canonical(&value).expect("encode-a");
        let b = nexacore_types::wire::encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }
}

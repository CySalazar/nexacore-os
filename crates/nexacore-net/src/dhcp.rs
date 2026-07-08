//! DHCP v4 client implementation (N6.2).
//!
//! Implements a DHCP version 4 client state machine per RFC 2131 and
//! RFC 2132 (DHCP options).
//!
//! ## State machine
//!
//! ```text
//!                  +--------+
//!              +-->|  Init  |<--+
//!              |   +---+----+   |
//!              |       | build_discover / DISCOVER sent
//!              |       v
//!              |   +-----------+
//!              |   | Selecting |  waiting for OFFER
//!              |   +-----+-----+
//!              |         | OFFER received → build_request / REQUEST sent
//!              |         v
//!              |   +-----------+
//!              |   | Requesting|  waiting for ACK/NAK
//!              |   +-----+-----+
//!              |         |  ACK received
//!              |         v
//!              |   +-------+
//!              |   | Bound |  lease valid
//!              |   +---+---+
//!              |       | should_renew() == true (T1 = 50 % lease)
//!              |       v
//!              |   +----------+
//!              |   | Renewing |  unicast REQUEST to server
//!              |   +----+-----+
//!              |        |  ACK → Bound / NAK or T2 expiry →
//!              |        v
//!              |   +-----------+
//!              +---| Rebinding |  broadcast REQUEST
//!                  +-----------+
//! ```
//!
//! ## Wire format
//!
//! DHCP messages follow the fixed-header format defined in RFC 2131 §2,
//! beginning with a 236-byte base header, followed by the four-byte magic
//! cookie `[99, 130, 83, 99]`, and then a variable-length options field.
//!
//! ```text
//! Offset  Len  Field
//! ------  ---  -----
//!  0       1   op       (1 = BOOTREQUEST, 2 = BOOTREPLY)
//!  1       1   htype    (1 = Ethernet)
//!  2       1   hlen     (6 for MAC)
//!  3       1   hops     (0 for client)
//!  4       4   xid      (transaction ID, big-endian)
//!  8       2   secs     (seconds since begin of process)
//! 10       2   flags    (bit 15 = broadcast flag)
//! 12       4   ciaddr   (client IP, 0.0.0.0 in DISCOVER/REQUEST before bound)
//! 16       4   yiaddr   (your IP — server-assigned)
//! 20       4   siaddr   (server IP)
//! 24       4   giaddr   (relay agent IP)
//! 28      16   chaddr   (client hardware address, MAC in first 6 bytes)
//! 44     192   sname+file (ignored by this implementation)
//! 236     4    magic cookie [99,130,83,99]
//! 240+    ?    options (TLV, terminated by 0xFF)
//! ```
//!
//! ## Packet construction
//!
//! [`DhcpClient::build_discover`] and [`DhcpClient::build_request`] return the
//! UDP payload bytes (i.e. everything above). The caller is responsible for
//! wrapping this in a UDP datagram (source port [`DHCP_CLIENT_PORT`],
//! destination port [`DHCP_SERVER_PORT`]) and an IP/Ethernet frame.

use alloc::vec::Vec;

use nexacore_types::net::Ipv4Addr;

// =============================================================================
// Constants
// =============================================================================

/// DHCP server well-known UDP port (RFC 2131 §4.1).
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client well-known UDP port (RFC 2131 §4.1).
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP magic cookie (RFC 2131 §3, RFC 951): `[99, 130, 83, 99]`.
///
/// Must be present at byte offset 236 of every DHCP message.
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Total fixed-header length (236 bytes) before the magic cookie.
const DHCP_FIXED_HDR_LEN: usize = 236;

/// Minimum valid DHCP message size (fixed header + magic cookie).
const DHCP_MIN_LEN: usize = DHCP_FIXED_HDR_LEN + 4;

/// DHCP `op` code for a client-to-server message (BOOTREQUEST).
const OP_BOOTREQUEST: u8 = 1;

/// DHCP `op` code for a server-to-client message (BOOTREPLY).
const OP_BOOTREPLY: u8 = 2;

// =============================================================================
// DHCP option codes
// =============================================================================

/// Well-known DHCP option codes from RFC 2132.
///
/// Each constant is the one-byte TLV tag that precedes the option length and
/// data in the options field.
pub mod option_code {
    /// Subnet mask (4 bytes, `IPv4`).
    pub const SUBNET_MASK: u8 = 1;
    /// Router / default gateway (4 bytes per entry, `IPv4`).
    pub const ROUTER: u8 = 3;
    /// DNS server list (4 bytes per entry, `IPv4`).
    pub const DNS_SERVER: u8 = 6;
    /// Requested IP address (4 bytes, `IPv4`).
    pub const REQUESTED_IP: u8 = 50;
    /// IP address lease time in seconds (4 bytes, big-endian u32).
    pub const LEASE_TIME: u8 = 51;
    /// DHCP message type (1 byte).
    pub const MESSAGE_TYPE: u8 = 53;
    /// DHCP server identifier (4 bytes, `IPv4`).
    pub const SERVER_ID: u8 = 54;
    /// Parameter Request List (the options the client asks the server to send).
    ///
    /// Without it, many servers reply with only the mandatory options
    /// (server-id, lease-time) and OMIT router/DNS/subnet (observed on the test VM —
    /// the offer carried no gateway/DNS until TASK-25 started requesting them).
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    /// End-of-options sentinel — no length byte follows.
    pub const END: u8 = 255;
    /// Pad byte — no length byte follows; skipped by parsers.
    pub const PAD: u8 = 0;
}

// =============================================================================
// Enums
// =============================================================================

/// Client-side DHCP state machine states (RFC 2131 §4.4).
///
/// # Examples
///
/// ```
/// use nexacore_net::dhcp::{DhcpClient, DhcpState};
///
/// let client = DhcpClient::new([0x02, 0xAB, 0xCD, 0xEF, 0x01, 0x02], 0xDEAD_BEEF);
/// assert_eq!(client.state, DhcpState::Init);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// Initial state — no transaction in progress.
    Init,
    /// DISCOVER sent; waiting for at least one OFFER.
    Selecting,
    /// REQUEST sent to selected server; waiting for ACK or NAK.
    Requesting,
    /// Lease obtained and still valid.
    Bound,
    /// Unicast REQUEST sent to renewing server (T1 elapsed).
    Renewing,
    /// Broadcast REQUEST sent; T2 elapsed or unicast renewal failed.
    Rebinding,
}

/// DHCP message type option values (option 53, RFC 2132 §9.6).
///
/// # Examples
///
/// ```
/// use nexacore_net::dhcp::DhcpMessageType;
///
/// assert_eq!(DhcpMessageType::Discover as u8, 1);
/// assert_eq!(DhcpMessageType::Ack as u8, 5);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    /// Client broadcast to discover available servers.
    Discover = 1,
    /// Server to client in response to DISCOVER.
    Offer = 2,
    /// Client to server requesting offered parameters.
    Request = 3,
    /// Client declining an offered address.
    Decline = 4,
    /// Server to client confirming the assignment.
    Ack = 5,
    /// Server to client refusing the request.
    Nak = 6,
    /// Client relinquishing its address.
    Release = 7,
}

impl DhcpMessageType {
    /// Parse a raw byte into a `DhcpMessageType`, returning `None` for
    /// unrecognised values.
    #[must_use]
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            _ => None,
        }
    }
}

// =============================================================================
// DhcpOption
// =============================================================================

/// A single parsed DHCP option (TLV form, RFC 2132).
///
/// # Examples
///
/// ```
/// extern crate alloc;
/// use nexacore_net::dhcp::{DhcpOption, option_code};
///
/// let opt = DhcpOption {
///     code: option_code::SUBNET_MASK,
///     data: alloc::vec![255, 255, 255, 0],
/// };
/// assert_eq!(opt.code, 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption {
    /// Option code byte.
    pub code: u8,
    /// Option data bytes (length prefix not included).
    pub data: Vec<u8>,
}

// =============================================================================
// DhcpLease
// =============================================================================

/// Lease information obtained from a successful DHCP negotiation.
///
/// All IP fields are in network byte order (big-endian).
///
/// # Examples
///
/// ```
/// extern crate alloc;
/// use nexacore_net::dhcp::DhcpLease;
/// use nexacore_types::net::Ipv4Addr;
///
/// let lease = DhcpLease {
///     client_ip: Ipv4Addr([192, 168, 1, 100]),
///     subnet_mask: Ipv4Addr([255, 255, 255, 0]),
///     gateway: Some(Ipv4Addr([192, 168, 1, 1])),
///     dns_servers: alloc::vec![Ipv4Addr([8, 8, 8, 8])],
///     server_ip: Ipv4Addr([192, 168, 1, 1]),
///     lease_time_secs: 86400,
///     obtained_at: 1_000_000,
/// };
/// assert_eq!(lease.lease_time_secs, 86400);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpLease {
    /// The `IPv4` address assigned to this client.
    pub client_ip: Ipv4Addr,
    /// Subnet mask for the assigned address.
    pub subnet_mask: Ipv4Addr,
    /// Default gateway for the assigned network, if offered.
    pub gateway: Option<Ipv4Addr>,
    /// DNS server addresses, in preference order.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Identifier of the DHCP server that granted this lease.
    pub server_ip: Ipv4Addr,
    /// Lease duration in seconds (T expiry).
    pub lease_time_secs: u32,
    /// Monotonic timestamp (ms) at which the lease was obtained.
    /// Used to compute T1 (50 %) and T2 (87.5 %) renewal thresholds.
    pub obtained_at: u64,
}

// =============================================================================
// DhcpResult
// =============================================================================

/// Outcome returned by [`DhcpClient::handle_message`].
///
/// The caller inspects this value to decide what to transmit next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpResult {
    /// The client is still in `Init`; caller should send this DISCOVER packet.
    SendDiscover(Vec<u8>),
    /// An OFFER was accepted; caller should send this REQUEST packet.
    SendRequest(Vec<u8>),
    /// An ACK was received; the enclosed lease is now active.
    Bound(DhcpLease),
    /// The server sent a NAK; the client has returned to `Init`.
    Rejected,
    /// The message was ignored (wrong XID, unknown type, or malformed).
    Ignored,
}

// =============================================================================
// DhcpMessage
// =============================================================================

/// Parsed fields from a received DHCP message.
///
/// Only the fields relevant to client-side processing are extracted; the rest
/// of the fixed header (sname, file, etc.) is discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    /// `op` field: `1` = BOOTREQUEST, `2` = BOOTREPLY.
    pub op: u8,
    /// Transaction ID that ties this message to the originating DISCOVER or
    /// REQUEST.
    pub xid: u32,
    /// `yiaddr` — "your" IP address offered/assigned by the server.
    pub yiaddr: Ipv4Addr,
    /// `siaddr` — next server IP (used for TFTP boot, informational here).
    pub siaddr: Ipv4Addr,
    /// Decoded options list.
    pub options: Vec<DhcpOption>,
}

// =============================================================================
// DhcpClient
// =============================================================================

/// DHCP v4 client state machine.
///
/// The client does not perform any I/O itself.  Instead, callers feed raw
/// incoming UDP payloads via [`handle_message`] and transmit whatever bytes
/// the result asks for.
///
/// # Examples
///
/// ```
/// use nexacore_net::dhcp::{DhcpClient, DhcpState};
///
/// let mut client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0x1234_5678);
/// assert_eq!(client.state, DhcpState::Init);
/// let discover = client.build_discover();
/// assert!(!discover.is_empty());
/// ```
///
/// [`handle_message`]: DhcpClient::handle_message
pub struct DhcpClient {
    /// Current state of the DHCP state machine.
    pub state: DhcpState,
    /// Transaction ID for the current negotiation (random, set by the caller).
    pub xid: u32,
    /// Client hardware (MAC) address.
    pub mac: [u8; 6],
    /// Active lease, present only in the [`DhcpState::Bound`] (and renewal)
    /// states.
    pub lease: Option<DhcpLease>,
    /// Gateway parsed from the most recent OFFER. Many DHCP servers send a
    /// MINIMAL ACK (only IP + lease-time + server-id, omitting Router/DNS), so
    /// the OFFER's network configuration is retained here and used as the lease
    /// fallback when the ACK omits it (TASK-25, observed on the test VM).
    offered_gateway: Option<Ipv4Addr>,
    /// DNS servers parsed from the most recent OFFER (see `offered_gateway`).
    offered_dns: alloc::vec::Vec<Ipv4Addr>,
    /// Subnet mask parsed from the most recent OFFER (see `offered_gateway`).
    offered_subnet: Option<Ipv4Addr>,
}

impl DhcpClient {
    /// Create a new DHCP client in the [`DhcpState::Init`] state.
    ///
    /// `mac` is the client's hardware address.  `xid` is the caller-supplied
    /// transaction identifier; in production this should be a random `u32`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_net::dhcp::{DhcpClient, DhcpState};
    ///
    /// let client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 42);
    /// assert_eq!(client.state, DhcpState::Init);
    /// assert_eq!(client.xid, 42);
    /// ```
    #[must_use]
    pub fn new(mac: [u8; 6], xid: u32) -> Self {
        Self {
            state: DhcpState::Init,
            xid,
            mac,
            lease: None,
            offered_gateway: None,
            offered_dns: alloc::vec::Vec::new(),
            offered_subnet: None,
        }
    }

    /// Build a DHCP DISCOVER packet (UDP payload bytes).
    ///
    /// Transitions the client from [`DhcpState::Init`] to
    /// [`DhcpState::Selecting`].
    ///
    /// The returned `Vec<u8>` is the entire DHCP message starting from the
    /// `op` field.  The caller wraps it in a UDP datagram with source port
    /// [`DHCP_CLIENT_PORT`] and destination port [`DHCP_SERVER_PORT`], sent
    /// as a broadcast.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_net::dhcp::{DHCP_MAGIC_COOKIE, DhcpClient, DhcpState};
    ///
    /// let mut client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 1);
    /// let pkt = client.build_discover();
    /// // Magic cookie at offset 236.
    /// assert_eq!(&pkt[236..240], &DHCP_MAGIC_COOKIE);
    /// assert_eq!(client.state, DhcpState::Selecting);
    /// ```
    pub fn build_discover(&mut self) -> Vec<u8> {
        self.state = DhcpState::Selecting;
        let options = [
            DhcpOption {
                code: option_code::MESSAGE_TYPE,
                data: alloc::vec![DhcpMessageType::Discover as u8],
            },
            // Ask the server to include subnet/router/DNS/lease in its reply.
            DhcpOption {
                code: option_code::PARAMETER_REQUEST_LIST,
                data: alloc::vec![
                    option_code::SUBNET_MASK,
                    option_code::ROUTER,
                    option_code::DNS_SERVER,
                    option_code::LEASE_TIME,
                ],
            },
        ];
        encode_dhcp_message(DhcpMessageType::Discover, self.xid, self.mac, &options)
    }

    /// Build a DHCP REQUEST packet in response to an OFFER.
    ///
    /// Transitions the client from [`DhcpState::Selecting`] to
    /// [`DhcpState::Requesting`].
    ///
    /// `server_ip` is the [`option_code::SERVER_ID`] from the OFFER;
    /// `offered_ip` is the `yiaddr` from the OFFER.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_net::dhcp::{DHCP_MAGIC_COOKIE, DhcpClient, DhcpState};
    /// use nexacore_types::net::Ipv4Addr;
    ///
    /// let mut client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 1);
    /// client.build_discover();
    /// let pkt = client.build_request(Ipv4Addr([192, 168, 1, 1]), Ipv4Addr([192, 168, 1, 100]));
    /// assert_eq!(&pkt[236..240], &DHCP_MAGIC_COOKIE);
    /// assert_eq!(client.state, DhcpState::Requesting);
    /// ```
    pub fn build_request(&mut self, server_ip: Ipv4Addr, offered_ip: Ipv4Addr) -> Vec<u8> {
        self.state = DhcpState::Requesting;
        let options = [
            DhcpOption {
                code: option_code::MESSAGE_TYPE,
                data: alloc::vec![DhcpMessageType::Request as u8],
            },
            DhcpOption {
                code: option_code::SERVER_ID,
                data: server_ip.0.to_vec(),
            },
            DhcpOption {
                code: option_code::REQUESTED_IP,
                data: offered_ip.0.to_vec(),
            },
            // Ask the server to include subnet/router/DNS/lease in the ACK.
            DhcpOption {
                code: option_code::PARAMETER_REQUEST_LIST,
                data: alloc::vec![
                    option_code::SUBNET_MASK,
                    option_code::ROUTER,
                    option_code::DNS_SERVER,
                    option_code::LEASE_TIME,
                ],
            },
        ];
        encode_dhcp_message(DhcpMessageType::Request, self.xid, self.mac, &options)
    }

    /// Parse `(subnet_mask, gateway, dns_servers)` from a message's DHCP
    /// options. Shared by the OFFER path (to retain config when the ACK is
    /// minimal) and the ACK path (with the OFFER values as fallback) — TASK-25.
    fn parse_net_config(
        options: &[DhcpOption],
    ) -> (
        Option<Ipv4Addr>,
        Option<Ipv4Addr>,
        alloc::vec::Vec<Ipv4Addr>,
    ) {
        let subnet = options
            .iter()
            .find(|o| o.code == option_code::SUBNET_MASK)
            .and_then(|o| ipv4_from_option_data(&o.data));
        let gateway = options
            .iter()
            .find(|o| o.code == option_code::ROUTER)
            .and_then(|o| ipv4_from_option_data(&o.data));
        let dns = options
            .iter()
            .find(|o| o.code == option_code::DNS_SERVER)
            .map(|o| ipv4_list_from_option_data(&o.data))
            .unwrap_or_default();
        (subnet, gateway, dns)
    }

    /// Process a raw DHCP message received from the network.
    ///
    /// `data` is the UDP payload.  `now` is the current monotonic timestamp in
    /// milliseconds; it is stored in any resulting [`DhcpLease`] to enable
    /// later calls to [`is_lease_expired`] and [`should_renew`].
    ///
    /// Returns a [`DhcpResult`] describing the action the caller should take:
    /// - [`DhcpResult::SendRequest`] — send the enclosed REQUEST packet (OFFER
    ///   accepted).
    /// - [`DhcpResult::Bound`] — ACK received; enclosed lease is now active.
    /// - [`DhcpResult::Rejected`] — NAK received; client reset to `Init`.
    /// - [`DhcpResult::Ignored`] — message not relevant (wrong XID, opcode, or
    ///   unrecognised type in this state).
    ///
    /// [`is_lease_expired`]: DhcpClient::is_lease_expired
    /// [`should_renew`]: DhcpClient::should_renew
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_net::dhcp::{DhcpClient, DhcpResult, DhcpState};
    ///
    /// let mut client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0xAABB_CCDD);
    /// client.build_discover();
    /// // Feed an empty/malformed packet — should be ignored.
    /// let result = client.handle_message(&[], 0);
    /// assert_eq!(result, DhcpResult::Ignored);
    /// ```
    pub fn handle_message(&mut self, data: &[u8], now: u64) -> DhcpResult {
        let Some(msg) = decode_dhcp_message(data) else {
            return DhcpResult::Ignored;
        };

        // Only process BOOTREPLY messages with our XID.
        if msg.op != OP_BOOTREPLY || msg.xid != self.xid {
            return DhcpResult::Ignored;
        }

        // Extract message type option.
        let msg_type_byte = msg
            .options
            .iter()
            .find(|o| o.code == option_code::MESSAGE_TYPE)
            .and_then(|o| o.data.first().copied());

        let Some(msg_type_byte) = msg_type_byte else {
            return DhcpResult::Ignored;
        };

        let Some(msg_type) = DhcpMessageType::from_u8(msg_type_byte) else {
            return DhcpResult::Ignored;
        };

        match (self.state, msg_type) {
            // Accept OFFER while Selecting — send REQUEST.
            (DhcpState::Selecting, DhcpMessageType::Offer) => {
                let server_ip = msg
                    .options
                    .iter()
                    .find(|o| o.code == option_code::SERVER_ID)
                    .and_then(|o| ipv4_from_option_data(&o.data))
                    .unwrap_or(msg.siaddr);

                // Retain the OFFER's network config: the ACK is often minimal
                // (no Router/DNS/Subnet), so these become the lease fallback.
                let (subnet, gateway, dns) = Self::parse_net_config(&msg.options);
                self.offered_subnet = subnet;
                self.offered_gateway = gateway;
                self.offered_dns = dns;

                let pkt = self.build_request(server_ip, msg.yiaddr);
                DhcpResult::SendRequest(pkt)
            }

            // Accept ACK while Requesting or Renewing/Rebinding.
            (
                DhcpState::Requesting | DhcpState::Renewing | DhcpState::Rebinding,
                DhcpMessageType::Ack,
            ) => {
                // For each field, prefer the ACK's value, falling back to the
                // value retained from the OFFER (minimal ACKs omit these —
                // TASK-25).
                let (ack_subnet, ack_gateway, ack_dns) = Self::parse_net_config(&msg.options);
                let subnet_mask = ack_subnet
                    .or(self.offered_subnet)
                    .unwrap_or(Ipv4Addr([255, 255, 255, 0]));
                let gateway = ack_gateway.or(self.offered_gateway);
                let dns_servers = if ack_dns.is_empty() {
                    self.offered_dns.clone()
                } else {
                    ack_dns
                };

                let server_ip = msg
                    .options
                    .iter()
                    .find(|o| o.code == option_code::SERVER_ID)
                    .and_then(|o| ipv4_from_option_data(&o.data))
                    .unwrap_or(msg.siaddr);

                let lease_time_secs = msg
                    .options
                    .iter()
                    .find(|o| o.code == option_code::LEASE_TIME)
                    .and_then(|o| u32_from_option_data(&o.data))
                    .unwrap_or(3600);

                let lease = DhcpLease {
                    client_ip: msg.yiaddr,
                    subnet_mask,
                    gateway,
                    dns_servers,
                    server_ip,
                    lease_time_secs,
                    obtained_at: now,
                };
                self.state = DhcpState::Bound;
                self.lease = Some(lease.clone());
                DhcpResult::Bound(lease)
            }

            // NAK in any active state — reset.
            (_, DhcpMessageType::Nak) => {
                self.state = DhcpState::Init;
                self.lease = None;
                DhcpResult::Rejected
            }

            // Everything else is ignored.
            _ => DhcpResult::Ignored,
        }
    }

    /// Returns `true` if the current lease has expired at time `now` (ms).
    ///
    /// Always returns `false` when no lease is held (i.e., state != Bound).
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_net::dhcp::{DhcpClient, DhcpLease};
    /// use nexacore_types::net::Ipv4Addr;
    ///
    /// let mut client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 1);
    /// // No lease — never expired.
    /// assert!(!client.is_lease_expired(u64::MAX));
    /// ```
    #[must_use]
    pub fn is_lease_expired(&self, now: u64) -> bool {
        let Some(lease) = &self.lease else {
            return false;
        };
        // Lease duration converted to milliseconds.
        let lease_ms = u64::from(lease.lease_time_secs) * 1_000;
        now.saturating_sub(lease.obtained_at) >= lease_ms
    }

    /// Returns `true` if the lease should be renewed at time `now` (ms).
    ///
    /// Per RFC 2131 §4.4.5, the client SHOULD renew at T1 = 0.5 × lease time.
    /// Returns `false` when no lease is held.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate alloc;
    /// use nexacore_net::dhcp::{DhcpClient, DhcpLease, DhcpState};
    /// use nexacore_types::net::Ipv4Addr;
    ///
    /// let mut client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 1);
    /// client.state = DhcpState::Bound;
    /// client.lease = Some(DhcpLease {
    ///     client_ip: Ipv4Addr([10, 0, 0, 5]),
    ///     subnet_mask: Ipv4Addr([255, 255, 255, 0]),
    ///     gateway: None,
    ///     dns_servers: alloc::vec![],
    ///     server_ip: Ipv4Addr([10, 0, 0, 1]),
    ///     lease_time_secs: 3600,
    ///     obtained_at: 0,
    /// });
    /// // Before T1 (< 1 800 000 ms): should not renew.
    /// assert!(!client.should_renew(1_000_000));
    /// // After T1 (>= 1 800 000 ms): should renew.
    /// assert!(client.should_renew(1_800_000));
    /// ```
    #[must_use]
    pub fn should_renew(&self, now: u64) -> bool {
        let Some(lease) = &self.lease else {
            return false;
        };
        // T1 = 50 % of lease time, in milliseconds.
        let t1_ms = u64::from(lease.lease_time_secs) * 500;
        now.saturating_sub(lease.obtained_at) >= t1_ms
    }
}

// =============================================================================
// Free functions
// =============================================================================

/// Encode a DHCP message into a byte vector (UDP payload).
///
/// Produces a complete DHCP message starting with the `op` field and ending
/// with the `END` option sentinel. `msg_type`, `xid`, and `mac` are written
/// into the fixed header. `options` are appended after the magic cookie;
/// an explicit [`option_code::MESSAGE_TYPE`] option MUST be included by the
/// caller in `options` — this function does not inject it.
///
/// # Examples
///
/// ```
/// extern crate alloc;
/// use nexacore_net::dhcp::{
///     DHCP_MAGIC_COOKIE, DhcpMessageType, DhcpOption, encode_dhcp_message, option_code,
/// };
///
/// let opts = [DhcpOption {
///     code: option_code::MESSAGE_TYPE,
///     data: alloc::vec![DhcpMessageType::Discover as u8],
/// }];
/// let pkt = encode_dhcp_message(DhcpMessageType::Discover, 1, [0x02; 6], &opts);
/// assert_eq!(&pkt[236..240], &DHCP_MAGIC_COOKIE);
/// ```
#[must_use]
pub fn encode_dhcp_message(
    _msg_type: DhcpMessageType,
    xid: u32,
    mac: [u8; 6],
    options: &[DhcpOption],
) -> Vec<u8> {
    // Pre-allocate: fixed header (236) + magic cookie (4) + options (variable)
    // + END sentinel (1).
    let options_len: usize = options
        .iter()
        .map(|o| {
            if o.code == option_code::PAD || o.code == option_code::END {
                1
            } else {
                2 + o.data.len()
            }
        })
        .sum();
    let capacity = DHCP_FIXED_HDR_LEN + 4 + options_len + 1;
    let mut buf: Vec<u8> = Vec::with_capacity(capacity);

    // --- Fixed header (236 bytes) ---

    // op (1=BOOTREQUEST)
    buf.push(OP_BOOTREQUEST);
    // htype (1=Ethernet)
    buf.push(1);
    // hlen (6 for MAC-48)
    buf.push(6);
    // hops (0, client doesn't increment)
    buf.push(0);
    // xid (big-endian u32)
    buf.extend_from_slice(&xid.to_be_bytes());
    // secs (0 — not tracking elapsed time in this implementation)
    buf.extend_from_slice(&0u16.to_be_bytes());
    // flags (0 — unicast; the server sends to yiaddr at the client's chaddr).
    // NOTE: broadcast-flag (0x8000) was tried but the virtio driver did not
    // deliver the broadcast OFFER/ACK on the test VM, so unicast is retained; the
    // ACK-delivery delay is handled by a time-based receive window in the
    // image's `run_dhcp` (TASK-25).
    buf.extend_from_slice(&0u16.to_be_bytes());
    // ciaddr (0.0.0.0 — client doesn't know its IP yet)
    buf.extend_from_slice(&[0u8; 4]);
    // yiaddr (0.0.0.0 — filled by server in replies)
    buf.extend_from_slice(&[0u8; 4]);
    // siaddr (0.0.0.0)
    buf.extend_from_slice(&[0u8; 4]);
    // giaddr (0.0.0.0 — no relay agent)
    buf.extend_from_slice(&[0u8; 4]);
    // chaddr (16 bytes — MAC in first 6, rest zero-padded)
    buf.extend_from_slice(&mac);
    buf.extend_from_slice(&[0u8; 10]); // padding to 16 bytes
    // sname (64 bytes, zero-filled)
    buf.extend_from_slice(&[0u8; 64]);
    // file (128 bytes, zero-filled)
    buf.extend_from_slice(&[0u8; 128]);

    // Sanity: we must be at exactly DHCP_FIXED_HDR_LEN bytes here.
    debug_assert_eq!(
        buf.len(),
        DHCP_FIXED_HDR_LEN,
        "DHCP fixed header length mismatch"
    );

    // --- Magic cookie ---
    buf.extend_from_slice(&DHCP_MAGIC_COOKIE);

    // --- Options ---
    for opt in options {
        // All options begin with the code byte.
        buf.push(opt.code);
        if opt.code != option_code::PAD && opt.code != option_code::END {
            // Multi-byte options: code + length + data.
            // Length is capped to u8::MAX (255); any option data > 255 bytes
            // is a programming error and is silently truncated here.
            // This is acceptable for a no-alloc/no-panic environment.
            let len = opt.data.len().min(255);
            #[allow(clippy::cast_possible_truncation)]
            buf.push(len as u8);
            // get(..) is used instead of direct indexing to satisfy
            // clippy::indexing_slicing; len <= opt.data.len() is guaranteed
            // by the min(255) above, so this will never return None.
            if let Some(data) = opt.data.get(..len) {
                buf.extend_from_slice(data);
            }
        }
    }

    // END sentinel.
    buf.push(option_code::END);

    buf
}

/// Decode a raw DHCP UDP payload into a [`DhcpMessage`].
///
/// Returns `None` if the buffer is too short, the magic cookie is absent,
/// or the buffer is otherwise malformed.
///
/// # Examples
///
/// ```
/// extern crate alloc;
/// use nexacore_net::dhcp::{
///     DhcpMessageType, DhcpOption, decode_dhcp_message, encode_dhcp_message, option_code,
/// };
///
/// let opts = [DhcpOption {
///     code: option_code::MESSAGE_TYPE,
///     data: alloc::vec![DhcpMessageType::Discover as u8],
/// }];
/// let pkt = encode_dhcp_message(DhcpMessageType::Discover, 0xDEAD_BEEF, [0x02; 6], &opts);
/// let msg = decode_dhcp_message(&pkt).unwrap();
/// assert_eq!(msg.xid, 0xDEAD_BEEF);
/// ```
#[must_use]
pub fn decode_dhcp_message(data: &[u8]) -> Option<DhcpMessage> {
    if data.len() < DHCP_MIN_LEN {
        return None;
    }

    let op = *data.first()?;
    // htype at [1], hlen at [2], hops at [3] — not used after decode.

    let xid = u32::from_be_bytes([*data.get(4)?, *data.get(5)?, *data.get(6)?, *data.get(7)?]);

    // yiaddr at offset 16.
    let yiaddr = Ipv4Addr([
        *data.get(16)?,
        *data.get(17)?,
        *data.get(18)?,
        *data.get(19)?,
    ]);

    // siaddr at offset 20.
    let siaddr = Ipv4Addr([
        *data.get(20)?,
        *data.get(21)?,
        *data.get(22)?,
        *data.get(23)?,
    ]);

    // Verify magic cookie at offset 236.
    let cookie = data.get(236..240)?;
    if cookie != DHCP_MAGIC_COOKIE {
        return None;
    }

    // Options start at offset 240.
    let options_data = data.get(240..)?;
    let options = parse_dhcp_options(options_data);

    Some(DhcpMessage {
        op,
        xid,
        yiaddr,
        siaddr,
        options,
    })
}

/// Parse the options field of a DHCP message into a [`Vec<DhcpOption>`].
///
/// Stops at the first [`option_code::END`] byte or at the end of `data`.
/// Pad bytes ([`option_code::PAD`]) are skipped without consuming a length
/// byte.  Malformed options (length byte missing or truncated data) cause
/// parsing to stop early.
///
/// # Examples
///
/// ```
/// extern crate alloc;
/// use nexacore_net::dhcp::{option_code, parse_dhcp_options};
///
/// // Manually encoded: type=53, len=1, data=0x01 (DISCOVER), then END.
/// let raw = [53u8, 1, 1, 255];
/// let opts = parse_dhcp_options(&raw);
/// assert_eq!(opts.len(), 1);
/// assert_eq!(opts[0].code, option_code::MESSAGE_TYPE);
/// assert_eq!(opts[0].data, alloc::vec![1]);
/// ```
#[must_use]
pub fn parse_dhcp_options(data: &[u8]) -> Vec<DhcpOption> {
    let mut options = Vec::new();
    let mut i = 0;

    while let Some(&code) = data.get(i) {
        i += 1;

        match code {
            option_code::END => break,
            option_code::PAD => continue,
            _ => {
                // Next byte is the length.
                let Some(&len) = data.get(i) else {
                    // Truncated option — stop parsing.
                    break;
                };
                i += 1;
                let end = i + usize::from(len);
                let Some(opt_data) = data.get(i..end) else {
                    // Truncated data — stop parsing.
                    break;
                };
                options.push(DhcpOption {
                    code,
                    data: opt_data.to_vec(),
                });
                i = end;
            }
        }
    }

    options
}

// =============================================================================
// Private helpers
// =============================================================================

/// Extract a single `IPv4` address from option data.
/// Returns `None` if `data` is shorter than 4 bytes.
fn ipv4_from_option_data(data: &[u8]) -> Option<Ipv4Addr> {
    if data.len() < 4 {
        return None;
    }
    Some(Ipv4Addr([
        *data.first()?,
        *data.get(1)?,
        *data.get(2)?,
        *data.get(3)?,
    ]))
}

/// Extract a list of `IPv4` addresses from option data (4 bytes each).
fn ipv4_list_from_option_data(data: &[u8]) -> Vec<Ipv4Addr> {
    data.chunks(4)
        .filter_map(|chunk| {
            // Only accept complete 4-byte chunks; use get() to avoid panics.
            let a = *chunk.first()?;
            let b = *chunk.get(1)?;
            let c = *chunk.get(2)?;
            let d = *chunk.get(3)?;
            Some(Ipv4Addr([a, b, c, d]))
        })
        .collect()
}

/// Extract a big-endian u32 from option data.
fn u32_from_option_data(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([
        *data.first()?,
        *data.get(1)?,
        *data.get(2)?,
        *data.get(3)?,
    ]))
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
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::bool_assert_comparison,
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        clippy::similar_names
    )]
    use alloc::vec;

    use super::*;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Build a minimal BOOTREPLY packet with a given message type and XID,
    /// optionally carrying `yiaddr`.
    fn make_reply(xid: u32, yiaddr: Ipv4Addr, siaddr: Ipv4Addr, options: &[DhcpOption]) -> Vec<u8> {
        // Start from a DISCOVER packet (which gives us the right structure)
        // but overwrite the op byte and addresses to turn it into a BOOTREPLY.
        let mut pkt = encode_dhcp_message(DhcpMessageType::Offer, xid, [0u8; 6], options);
        // op → BOOTREPLY
        if let Some(b) = pkt.get_mut(0) {
            *b = OP_BOOTREPLY;
        }
        // yiaddr at offset 16
        if let Some(slice) = pkt.get_mut(16..20) {
            slice.copy_from_slice(&yiaddr.0);
        }
        // siaddr at offset 20
        if let Some(slice) = pkt.get_mut(20..24) {
            slice.copy_from_slice(&siaddr.0);
        }
        pkt
    }

    fn offer_options(server: Ipv4Addr) -> Vec<DhcpOption> {
        vec![
            DhcpOption {
                code: option_code::MESSAGE_TYPE,
                data: vec![DhcpMessageType::Offer as u8],
            },
            DhcpOption {
                code: option_code::SERVER_ID,
                data: server.0.to_vec(),
            },
            DhcpOption {
                code: option_code::LEASE_TIME,
                data: 3600u32.to_be_bytes().to_vec(),
            },
            DhcpOption {
                code: option_code::SUBNET_MASK,
                data: vec![255, 255, 255, 0],
            },
            DhcpOption {
                code: option_code::ROUTER,
                data: vec![192, 168, 1, 1],
            },
            DhcpOption {
                code: option_code::DNS_SERVER,
                data: vec![8, 8, 8, 8, 1, 1, 1, 1],
            },
        ]
    }

    fn ack_options(server: Ipv4Addr) -> Vec<DhcpOption> {
        vec![
            DhcpOption {
                code: option_code::MESSAGE_TYPE,
                data: vec![DhcpMessageType::Ack as u8],
            },
            DhcpOption {
                code: option_code::SERVER_ID,
                data: server.0.to_vec(),
            },
            DhcpOption {
                code: option_code::LEASE_TIME,
                data: 3600u32.to_be_bytes().to_vec(),
            },
            DhcpOption {
                code: option_code::SUBNET_MASK,
                data: vec![255, 255, 255, 0],
            },
            DhcpOption {
                code: option_code::ROUTER,
                data: vec![192, 168, 1, 1],
            },
        ]
    }

    fn nak_options() -> Vec<DhcpOption> {
        vec![DhcpOption {
            code: option_code::MESSAGE_TYPE,
            data: vec![DhcpMessageType::Nak as u8],
        }]
    }

    // -------------------------------------------------------------------------
    // Magic cookie
    // -------------------------------------------------------------------------

    #[test]
    fn discover_contains_magic_cookie() {
        let mut client = DhcpClient::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0xDEAD_BEEF);
        let pkt = client.build_discover();
        assert_eq!(pkt.len() >= 240, true);
        assert_eq!(&pkt[236..240], &DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn decode_rejects_wrong_magic_cookie() {
        let mut client = DhcpClient::new([0x02; 6], 1);
        let mut pkt = client.build_discover();
        // Corrupt the magic cookie.
        if let Some(b) = pkt.get_mut(236) {
            *b ^= 0xFF;
        }
        assert!(decode_dhcp_message(&pkt).is_none());
    }

    #[test]
    fn decode_rejects_too_short_packet() {
        assert!(decode_dhcp_message(&[]).is_none());
        assert!(decode_dhcp_message(&[0u8; 10]).is_none());
        assert!(decode_dhcp_message(&[0u8; DHCP_MIN_LEN - 1]).is_none());
    }

    // -------------------------------------------------------------------------
    // DISCOVER construction
    // -------------------------------------------------------------------------

    #[test]
    fn discover_sets_client_state_to_selecting() {
        let mut client = DhcpClient::new([0x02; 6], 0x1234_5678);
        assert_eq!(client.state, DhcpState::Init);
        client.build_discover();
        assert_eq!(client.state, DhcpState::Selecting);
    }

    #[test]
    fn discover_encodes_correct_xid() {
        let xid: u32 = 0xCAFE_BABE;
        let mut client = DhcpClient::new([0x02; 6], xid);
        let pkt = client.build_discover();
        let decoded_xid = u32::from_be_bytes(pkt[4..8].try_into().unwrap());
        assert_eq!(decoded_xid, xid);
    }

    #[test]
    fn discover_encodes_mac_in_chaddr() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut client = DhcpClient::new(mac, 1);
        let pkt = client.build_discover();
        assert_eq!(&pkt[28..34], &mac);
    }

    // -------------------------------------------------------------------------
    // REQUEST construction
    // -------------------------------------------------------------------------

    #[test]
    fn request_sets_client_state_to_requesting() {
        let mut client = DhcpClient::new([0x02; 6], 1);
        client.build_discover();
        client.build_request(Ipv4Addr([192, 168, 1, 1]), Ipv4Addr([192, 168, 1, 100]));
        assert_eq!(client.state, DhcpState::Requesting);
    }

    #[test]
    fn request_contains_magic_cookie() {
        let mut client = DhcpClient::new([0x02; 6], 1);
        client.build_discover();
        let pkt = client.build_request(Ipv4Addr([10, 0, 0, 1]), Ipv4Addr([10, 0, 0, 100]));
        assert_eq!(&pkt[236..240], &DHCP_MAGIC_COOKIE);
    }

    // -------------------------------------------------------------------------
    // Option parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_options_single_message_type() {
        let raw = [
            option_code::MESSAGE_TYPE,
            1,
            DhcpMessageType::Discover as u8,
            option_code::END,
        ];
        let opts = parse_dhcp_options(&raw);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].code, option_code::MESSAGE_TYPE);
        assert_eq!(opts[0].data, vec![1u8]);
    }

    #[test]
    fn parse_options_skips_pad_bytes() {
        // PAD, PAD, MESSAGE_TYPE(1,1), END
        let raw = [
            option_code::PAD,
            option_code::PAD,
            option_code::MESSAGE_TYPE,
            1,
            DhcpMessageType::Offer as u8,
            option_code::END,
        ];
        let opts = parse_dhcp_options(&raw);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].code, option_code::MESSAGE_TYPE);
    }

    #[test]
    fn parse_options_stops_at_end_sentinel() {
        let raw = [
            option_code::MESSAGE_TYPE,
            1,
            DhcpMessageType::Discover as u8,
            option_code::END,
            // Garbage after END — must not be parsed.
            option_code::SUBNET_MASK,
            4,
            255,
            255,
            255,
            0,
        ];
        let opts = parse_dhcp_options(&raw);
        assert_eq!(opts.len(), 1);
    }

    #[test]
    fn parse_options_handles_truncated_data_gracefully() {
        // SUBNET_MASK claims 4 bytes but only 2 are present.
        let raw = [option_code::SUBNET_MASK, 4, 255, 255];
        let opts = parse_dhcp_options(&raw);
        // Parser should stop without panicking.
        assert!(opts.is_empty());
    }

    #[test]
    fn parse_options_empty_input() {
        let opts = parse_dhcp_options(&[]);
        assert!(opts.is_empty());
    }

    // -------------------------------------------------------------------------
    // State machine — OFFER handling
    // -------------------------------------------------------------------------

    #[test]
    fn handle_offer_transitions_to_requesting() {
        let xid = 0xBEEF_CAFE;
        let server = Ipv4Addr([192, 168, 1, 1]);
        let offered = Ipv4Addr([192, 168, 1, 100]);

        let mut client = DhcpClient::new([0x02; 6], xid);
        client.build_discover();

        let pkt = make_reply(xid, offered, server, &offer_options(server));
        let result = client.handle_message(&pkt, 0);

        assert!(matches!(result, DhcpResult::SendRequest(_)));
        assert_eq!(client.state, DhcpState::Requesting);
    }

    #[test]
    fn handle_offer_with_wrong_xid_is_ignored() {
        let xid = 0x1111_2222;
        let server = Ipv4Addr([192, 168, 1, 1]);
        let offered = Ipv4Addr([192, 168, 1, 100]);

        let mut client = DhcpClient::new([0x02; 6], xid);
        client.build_discover();

        // Reply with a different XID.
        let pkt = make_reply(0x9999_8888, offered, server, &offer_options(server));
        let result = client.handle_message(&pkt, 0);
        assert_eq!(result, DhcpResult::Ignored);
        assert_eq!(client.state, DhcpState::Selecting);
    }

    // -------------------------------------------------------------------------
    // State machine — ACK handling
    // -------------------------------------------------------------------------

    #[test]
    fn handle_ack_transitions_to_bound() {
        let xid = 0xDEAD_BEEF;
        let server = Ipv4Addr([10, 0, 0, 1]);
        let offered = Ipv4Addr([10, 0, 0, 50]);

        let mut client = DhcpClient::new([0x02; 6], xid);
        client.build_discover();
        // Feed OFFER first to move to Requesting.
        let offer_pkt = make_reply(xid, offered, server, &offer_options(server));
        client.handle_message(&offer_pkt, 0);
        assert_eq!(client.state, DhcpState::Requesting);

        // Feed ACK.
        let ack_pkt = make_reply(xid, offered, server, &ack_options(server));
        let result = client.handle_message(&ack_pkt, 1000);
        assert!(matches!(result, DhcpResult::Bound(_)));
        assert_eq!(client.state, DhcpState::Bound);
        assert!(client.lease.is_some());
    }

    #[test]
    fn bound_lease_fields_are_correct() {
        let xid = 0x1234;
        let server = Ipv4Addr([10, 0, 0, 1]);
        let offered = Ipv4Addr([10, 0, 0, 55]);

        let mut client = DhcpClient::new([0x02; 6], xid);
        client.build_discover();
        let offer_pkt = make_reply(xid, offered, server, &offer_options(server));
        client.handle_message(&offer_pkt, 0);
        let ack_pkt = make_reply(xid, offered, server, &ack_options(server));
        let result = client.handle_message(&ack_pkt, 5000);

        if let DhcpResult::Bound(lease) = result {
            assert_eq!(lease.client_ip, offered);
            assert_eq!(lease.server_ip, server);
            assert_eq!(lease.lease_time_secs, 3600);
            assert_eq!(lease.obtained_at, 5000);
        } else {
            panic!("expected Bound result");
        }
    }

    // -------------------------------------------------------------------------
    // State machine — NAK handling
    // -------------------------------------------------------------------------

    #[test]
    fn handle_nak_resets_to_init() {
        let xid = 0x5678;
        let server = Ipv4Addr([10, 0, 0, 1]);
        let offered = Ipv4Addr([10, 0, 0, 10]);

        let mut client = DhcpClient::new([0x02; 6], xid);
        client.build_discover();
        let offer_pkt = make_reply(xid, offered, server, &offer_options(server));
        client.handle_message(&offer_pkt, 0);

        let nak_pkt = make_reply(xid, Ipv4Addr([0; 4]), server, &nak_options());
        let result = client.handle_message(&nak_pkt, 0);
        assert_eq!(result, DhcpResult::Rejected);
        assert_eq!(client.state, DhcpState::Init);
        assert!(client.lease.is_none());
    }

    // -------------------------------------------------------------------------
    // Lease renewal timing
    // -------------------------------------------------------------------------

    #[test]
    fn should_renew_false_before_t1() {
        let mut client = DhcpClient::new([0x02; 6], 1);
        client.state = DhcpState::Bound;
        client.lease = Some(DhcpLease {
            client_ip: Ipv4Addr([10, 0, 0, 5]),
            subnet_mask: Ipv4Addr([255, 255, 255, 0]),
            gateway: None,
            dns_servers: vec![],
            server_ip: Ipv4Addr([10, 0, 0, 1]),
            lease_time_secs: 3600,
            obtained_at: 0,
        });
        // T1 = 1 800 000 ms; at 1 799 999 ms we should NOT renew.
        assert!(!client.should_renew(1_799_999));
    }

    #[test]
    fn should_renew_true_at_t1() {
        let mut client = DhcpClient::new([0x02; 6], 1);
        client.state = DhcpState::Bound;
        client.lease = Some(DhcpLease {
            client_ip: Ipv4Addr([10, 0, 0, 5]),
            subnet_mask: Ipv4Addr([255, 255, 255, 0]),
            gateway: None,
            dns_servers: vec![],
            server_ip: Ipv4Addr([10, 0, 0, 1]),
            lease_time_secs: 3600,
            obtained_at: 0,
        });
        // T1 = 1 800 000 ms exactly.
        assert!(client.should_renew(1_800_000));
    }

    #[test]
    fn is_lease_expired_false_before_expiry() {
        let mut client = DhcpClient::new([0x02; 6], 1);
        client.state = DhcpState::Bound;
        client.lease = Some(DhcpLease {
            client_ip: Ipv4Addr([10, 0, 0, 5]),
            subnet_mask: Ipv4Addr([255, 255, 255, 0]),
            gateway: None,
            dns_servers: vec![],
            server_ip: Ipv4Addr([10, 0, 0, 1]),
            lease_time_secs: 3600,
            obtained_at: 0,
        });
        // Full lease = 3 600 000 ms; at 3 599 999 ms not expired.
        assert!(!client.is_lease_expired(3_599_999));
    }

    #[test]
    fn is_lease_expired_true_at_expiry() {
        let mut client = DhcpClient::new([0x02; 6], 1);
        client.state = DhcpState::Bound;
        client.lease = Some(DhcpLease {
            client_ip: Ipv4Addr([10, 0, 0, 5]),
            subnet_mask: Ipv4Addr([255, 255, 255, 0]),
            gateway: None,
            dns_servers: vec![],
            server_ip: Ipv4Addr([10, 0, 0, 1]),
            lease_time_secs: 3600,
            obtained_at: 0,
        });
        assert!(client.is_lease_expired(3_600_000));
    }

    #[test]
    fn no_lease_never_expired_or_renewing() {
        let client = DhcpClient::new([0x02; 6], 1);
        assert!(!client.is_lease_expired(u64::MAX));
        assert!(!client.should_renew(u64::MAX));
    }

    // -------------------------------------------------------------------------
    // encode_dhcp_message / decode_dhcp_message roundtrip
    // -------------------------------------------------------------------------

    #[test]
    fn encode_decode_roundtrip_discover() {
        let xid: u32 = 0xABCD_EF01;
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let opts = [DhcpOption {
            code: option_code::MESSAGE_TYPE,
            data: vec![DhcpMessageType::Discover as u8],
        }];
        let pkt = encode_dhcp_message(DhcpMessageType::Discover, xid, mac, &opts);
        let msg = decode_dhcp_message(&pkt).expect("decode");
        assert_eq!(msg.xid, xid);
        assert_eq!(msg.op, OP_BOOTREQUEST);
        assert_eq!(msg.options.len(), 1);
        assert_eq!(msg.options[0].code, option_code::MESSAGE_TYPE);
        assert_eq!(msg.options[0].data, vec![DhcpMessageType::Discover as u8]);
    }
}

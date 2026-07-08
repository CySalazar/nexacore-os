//! UDP socket table and packet construction (N2.4).
//!
//! Provides a lightweight, in-memory UDP socket table with:
//! - [`UdpSocketTable::bind`] — reserve a local port
//! - [`UdpSocketTable::allocate_ephemeral`] — pick a port in 49152–65535
//! - [`UdpSocketTable::sendto`] — build a complete UDP+IPv4 packet
//! - [`UdpSocketTable::handle_packet`] — demultiplex an arriving datagram
//! - [`UdpSocketTable::recvfrom`] — consume the next buffered datagram
//! - [`UdpSocketTable::close`] — release the port
//!
//! ## Free function
//!
//! [`build_udp_packet`] constructs a raw UDP packet (header + payload) with
//! the correct checksum over the `IPv4` pseudo-header.

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};

use nexacore_types::{
    net::{IpProtocol, Ipv4Addr, UdpHeader, UdpPseudoHeader},
    socket::{NetError, SocketApiAddr},
};

use crate::ip::build_ipv4_packet;

// =============================================================================
// Constants
// =============================================================================

/// First port in the ephemeral (dynamic/private) range (RFC 6335).
pub const EPHEMERAL_PORT_MIN: u16 = 49_152;

/// Last port in the ephemeral range.
pub const EPHEMERAL_PORT_MAX: u16 = 65_535;

// =============================================================================
// Types
// =============================================================================

/// A single UDP socket — a bound local port plus an optional connected peer.
#[derive(Debug)]
pub struct UdpSocket {
    /// The local port this socket is bound to.
    pub local_port: u16,
    /// Optional connected remote address (set by `connect`-style usage).
    pub remote: Option<SocketApiAddr>,
    /// Buffered incoming datagrams `(sender_address, payload)`.
    pub recv_queue: VecDeque<(SocketApiAddr, Vec<u8>)>,
}

/// Socket table for UDP.
///
/// # Examples
///
/// ```
/// use nexacore_net::udp::UdpSocketTable;
/// use nexacore_types::{net::Ipv4Addr, socket::SocketApiAddr};
///
/// let mut table = UdpSocketTable::new();
/// assert!(table.bind(53).is_ok());
/// // Binding the same port again returns AddrInUse.
/// assert!(table.bind(53).is_err());
/// ```
#[derive(Debug, Default)]
pub struct UdpSocketTable {
    /// Map from local port → socket.
    sockets: BTreeMap<u16, UdpSocket>,
    /// Next candidate ephemeral port; wraps at [`EPHEMERAL_PORT_MAX`].
    next_ephemeral: u16,
}

impl UdpSocketTable {
    /// Construct an empty UDP socket table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            next_ephemeral: EPHEMERAL_PORT_MIN,
        }
    }

    /// Bind `port`.
    ///
    /// Returns the bound port on success, or [`NetError::AddrInUse`] if
    /// the port is already occupied.
    ///
    /// # Errors
    ///
    /// Returns `Err(NetError::AddrInUse)` if `port` is already bound.
    pub fn bind(&mut self, port: u16) -> Result<u16, NetError> {
        if self.sockets.contains_key(&port) {
            return Err(NetError::AddrInUse);
        }
        self.sockets.insert(
            port,
            UdpSocket {
                local_port: port,
                remote: None,
                recv_queue: VecDeque::new(),
            },
        );
        Ok(port)
    }

    /// Allocate an unused ephemeral port in the range 49 152–65 535.
    ///
    /// Scans linearly from the last-allocated position.  In a worst-case
    /// fully-saturated range this is O(16 384), but in practice the table
    /// will be nearly empty.
    ///
    /// # Errors
    ///
    /// Returns `Err(NetError::AddrInUse)` if all ephemeral ports are in use.
    pub fn allocate_ephemeral(&mut self) -> Result<u16, NetError> {
        let range_len = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1;
        for i in 0..range_len {
            // Compute candidate, wrapping within the ephemeral range.
            let candidate =
                EPHEMERAL_PORT_MIN + (self.next_ephemeral - EPHEMERAL_PORT_MIN + i) % range_len;
            if !self.sockets.contains_key(&candidate) {
                self.next_ephemeral =
                    EPHEMERAL_PORT_MIN + (candidate - EPHEMERAL_PORT_MIN + 1) % range_len;
                return self.bind(candidate);
            }
        }
        Err(NetError::AddrInUse)
    }

    /// Build and return a UDP+IPv4 packet ready for transmission.
    ///
    /// Returns [`NetError::InvalidArgument`] if `port` is not bound.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `port` is not bound in this table.
    pub fn sendto(
        &self,
        port: u16,
        dst: SocketApiAddr,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        data: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        if !self.sockets.contains_key(&port) {
            return Err(NetError::InvalidArgument);
        }
        let udp_payload = build_udp_packet(src_ip, dst_ip, port, dst.port, data);
        let ip_packet = build_ipv4_packet(src_ip, dst_ip, IpProtocol::UDP, 64, 0, &udp_payload);
        Ok(ip_packet)
    }

    /// Deliver an incoming UDP datagram to the socket bound on `dst_port`.
    ///
    /// Silently discards the datagram if no socket is bound to `dst_port`.
    pub fn handle_packet(
        &mut self,
        header: UdpHeader,
        payload: &[u8],
        src_ip: Ipv4Addr,
        _dst_ip: Ipv4Addr,
    ) {
        let Some(socket) = self.sockets.get_mut(&header.dst_port) else {
            return;
        };
        let sender = SocketApiAddr {
            ip: src_ip.0,
            port: header.src_port,
        };
        socket.recv_queue.push_back((sender, payload.to_vec()));
    }

    /// Remove and return the next datagram from `port`'s receive queue.
    ///
    /// Returns `None` if no socket is bound on `port` or the queue is empty.
    pub fn recvfrom(&mut self, port: u16) -> Option<(SocketApiAddr, Vec<u8>)> {
        self.sockets.get_mut(&port)?.recv_queue.pop_front()
    }

    /// Release the socket bound to `port`.
    ///
    /// Any buffered datagrams are discarded.
    pub fn close(&mut self, port: u16) {
        self.sockets.remove(&port);
    }
}

// =============================================================================
// Free function: build_udp_packet
// =============================================================================

/// Build a UDP packet (header + payload) with the correct checksum.
///
/// The returned bytes are the raw UDP datagram only — no `IPv4` header.
/// Wrap with [`crate::ip::build_ipv4_packet`] for a complete IP datagram.
///
/// # Examples
///
/// ```
/// use nexacore_net::udp::build_udp_packet;
/// use nexacore_types::net::{Ipv4Addr, UdpHeader, UdpPseudoHeader};
///
/// let bytes = build_udp_packet(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, 1234, 5678, b"hello");
/// let (hdr, payload) = UdpHeader::parse(&bytes).unwrap();
/// let pseudo = UdpPseudoHeader {
///     src_ip: Ipv4Addr::LOOPBACK,
///     dst_ip: Ipv4Addr::LOOPBACK,
///     zero: 0,
///     protocol: 17,
///     udp_length: hdr.length,
/// };
/// assert!(hdr.verify_checksum(pseudo, payload));
/// ```
#[must_use]
pub fn build_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    // UDP total length fits in u16: header (8) + payload (≤ 65527).
    let udp_len = u16::try_from(UdpHeader::HEADER_LEN + payload.len()).unwrap_or(u16::MAX);
    let pseudo = UdpPseudoHeader {
        src_ip,
        dst_ip,
        zero: 0,
        protocol: IpProtocol::UDP.0,
        udp_length: udp_len,
    };
    let mut hdr = UdpHeader {
        src_port,
        dst_port,
        length: udp_len,
        checksum: 0,
    };
    hdr.checksum = hdr.compute_checksum(pseudo, payload);

    let mut out = alloc::vec![0u8; UdpHeader::HEADER_LEN + payload.len()];
    if let Some(hdr_slot) = out.get_mut(..UdpHeader::HEADER_LEN) {
        let _ = hdr.serialize(hdr_slot);
    }
    if let Some(dst) = out.get_mut(UdpHeader::HEADER_LEN..) {
        dst.copy_from_slice(payload);
    }
    out
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
        clippy::integer_division,
        clippy::map_unwrap_or,
        clippy::similar_names,
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::used_underscore_binding,
        clippy::absurd_extreme_comparisons
    )]
    #[allow(clippy::wildcard_imports)]
    use super::*;

    fn loopback() -> Ipv4Addr {
        Ipv4Addr::LOOPBACK
    }

    fn addr(port: u16) -> SocketApiAddr {
        SocketApiAddr {
            ip: [127, 0, 0, 1],
            port,
        }
    }

    // -------------------------------------------------------------------------
    // UdpSocketTable
    // -------------------------------------------------------------------------

    #[test]
    fn new_table_is_empty() {
        let table = UdpSocketTable::new();
        assert!(table.sockets.is_empty());
    }

    #[test]
    fn bind_success() {
        let mut table = UdpSocketTable::new();
        assert_eq!(table.bind(53).unwrap(), 53);
    }

    #[test]
    fn bind_duplicate_returns_addr_in_use() {
        let mut table = UdpSocketTable::new();
        table.bind(1234).unwrap();
        assert!(matches!(table.bind(1234), Err(NetError::AddrInUse)));
    }

    #[test]
    fn allocate_ephemeral_returns_valid_port() {
        let mut table = UdpSocketTable::new();
        let port = table.allocate_ephemeral().unwrap();
        assert!(port >= EPHEMERAL_PORT_MIN);
        assert!(port <= EPHEMERAL_PORT_MAX);
    }

    #[test]
    fn allocate_ephemeral_advances_next_pointer() {
        let mut table = UdpSocketTable::new();
        let p1 = table.allocate_ephemeral().unwrap();
        let p2 = table.allocate_ephemeral().unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn sendto_unbound_port_returns_error() {
        let table = UdpSocketTable::new();
        let result = table.sendto(9999, addr(80), loopback(), loopback(), b"data");
        assert!(matches!(result, Err(NetError::InvalidArgument)));
    }

    #[test]
    fn sendto_builds_valid_ipv4_udp_packet() {
        let mut table = UdpSocketTable::new();
        table.bind(12345).unwrap();
        let pkt = table
            .sendto(12345, addr(80), loopback(), loopback(), b"hello")
            .unwrap();
        // The outer IPv4 header should parse cleanly.
        let (ip_hdr, udp_data) = crate::ip::parse_ipv4_packet(&pkt).unwrap();
        assert_eq!(ip_hdr.protocol, IpProtocol::UDP);
        let (udp_hdr, payload) = UdpHeader::parse(udp_data).unwrap();
        assert_eq!(udp_hdr.src_port, 12345);
        assert_eq!(udp_hdr.dst_port, 80);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn handle_packet_delivers_to_bound_socket() {
        let mut table = UdpSocketTable::new();
        table.bind(53).unwrap();
        let hdr = UdpHeader {
            src_port: 40000,
            dst_port: 53,
            length: 8,
            checksum: 0,
        };
        table.handle_packet(hdr, b"query", loopback(), loopback());
        let (sender, data) = table.recvfrom(53).unwrap();
        assert_eq!(sender.port, 40000);
        assert_eq!(data, b"query");
    }

    #[test]
    fn handle_packet_drops_unbound_port() {
        let mut table = UdpSocketTable::new();
        let hdr = UdpHeader {
            src_port: 40000,
            dst_port: 9999,
            length: 8,
            checksum: 0,
        };
        // No socket bound on 9999; just ensure no panic.
        table.handle_packet(hdr, b"data", loopback(), loopback());
    }

    #[test]
    fn recvfrom_empty_queue_returns_none() {
        let mut table = UdpSocketTable::new();
        table.bind(5000).unwrap();
        assert!(table.recvfrom(5000).is_none());
    }

    #[test]
    fn recvfrom_unbound_port_returns_none() {
        let mut table = UdpSocketTable::new();
        assert!(table.recvfrom(5000).is_none());
    }

    #[test]
    fn close_removes_socket() {
        let mut table = UdpSocketTable::new();
        table.bind(7000).unwrap();
        table.close(7000);
        // After close, should be rebindable.
        assert!(table.bind(7000).is_ok());
    }

    #[test]
    fn recv_queue_fifo_order() {
        let mut table = UdpSocketTable::new();
        table.bind(8080).unwrap();
        for i in 0u8..3 {
            let hdr = UdpHeader {
                src_port: 1000 + u16::from(i),
                dst_port: 8080,
                length: 9,
                checksum: 0,
            };
            table.handle_packet(hdr, &[i], loopback(), loopback());
        }
        for i in 0u8..3 {
            let (_, data) = table.recvfrom(8080).unwrap();
            assert_eq!(data, &[i]);
        }
    }

    // -------------------------------------------------------------------------
    // build_udp_packet
    // -------------------------------------------------------------------------

    #[test]
    fn build_udp_packet_correct_checksum() {
        let bytes = build_udp_packet(
            Ipv4Addr([1, 2, 3, 4]),
            Ipv4Addr([5, 6, 7, 8]),
            1234,
            5678,
            b"test payload",
        );
        let (hdr, payload) = UdpHeader::parse(&bytes).unwrap();
        let pseudo = UdpPseudoHeader {
            src_ip: Ipv4Addr([1, 2, 3, 4]),
            dst_ip: Ipv4Addr([5, 6, 7, 8]),
            zero: 0,
            protocol: 17,
            udp_length: hdr.length,
        };
        assert!(hdr.verify_checksum(pseudo, payload));
    }

    #[test]
    fn build_udp_packet_port_fields() {
        let bytes = build_udp_packet(loopback(), loopback(), 9000, 53, &[]);
        let (hdr, _) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.src_port, 9000);
        assert_eq!(hdr.dst_port, 53);
    }

    #[test]
    fn build_udp_packet_length_field() {
        let payload = &[0u8; 10];
        let bytes = build_udp_packet(loopback(), loopback(), 1, 2, payload);
        let (hdr, _) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.length as usize, UdpHeader::HEADER_LEN + payload.len());
    }

    #[test]
    fn build_udp_packet_empty_payload() {
        let bytes = build_udp_packet(loopback(), loopback(), 1, 2, &[]);
        let (hdr, payload) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.length as usize, UdpHeader::HEADER_LEN);
        assert!(payload.is_empty());
    }

    #[test]
    fn ipv4_header_in_sendto_output() {
        let mut table = UdpSocketTable::new();
        table.bind(1025).unwrap();
        let src_ip = Ipv4Addr([10, 0, 0, 1]);
        let dst_ip = Ipv4Addr([10, 0, 0, 2]);
        let pkt = table
            .sendto(1025, addr(8080), src_ip, dst_ip, b"hi")
            .unwrap();
        let (ip_hdr, _) = crate::ip::parse_ipv4_packet(&pkt).unwrap();
        assert_eq!(ip_hdr.src, src_ip);
        assert_eq!(ip_hdr.dst, dst_ip);
    }
}

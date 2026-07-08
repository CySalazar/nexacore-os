//! Network service main loop (N2.6).
//!
//! [`NetworkService`] is the top-level orchestrator that ties together the
//! sub-systems:
//!
//! - ARP resolution ([`crate::arp`])
//! - IP routing ([`crate::ip`])
//! - ICMP echo/unreachable ([`crate::icmp`])
//! - UDP socket table ([`crate::udp`])
//! - TCP socket table ([`crate::tcp`])
//! - DNS stub resolver ([`crate::dns`])
//!
//! ## Frame ingress
//!
//! [`NetworkService::handle_frame`] parses an Ethernet frame and dispatches:
//! - `EtherType::ARP` → ARP module (update table, possibly send reply)
//! - `EtherType::IPv4`:
//!   - `IpProtocol::ICMP` → ICMP module
//!   - `IpProtocol::UDP`  → UDP socket table
//!   - `IpProtocol::TCP`  → TCP socket table
//!
//! ## Socket API ingress
//!
//! [`NetworkService::handle_socket_request`] translates a [`SocketRequest`]
//! into the appropriate sub-system call and returns a [`SocketResponse`].
//!
//! ## Timer ticks
//!
//! [`NetworkService::tick`] should be called periodically (e.g., every 100 ms)
//! to drive ARP expiry, TCP retransmission timeouts, and `TIME_WAIT` cleanup.

use alloc::{collections::BTreeMap, vec::Vec};

use nexacore_types::{
    net::{
        ArpPacket, EtherType, EthernetHeader, IcmpHeader, IpProtocol, Ipv4Addr, MacAddress,
        TcpHeader, UdpHeader,
    },
    socket::{NetError, SocketApiAddr, SocketHandle, SocketOption, SocketRequest, SocketResponse},
};

use crate::{
    arp::{ARP_TIMEOUT_SECS, ArpHandleResult, ArpResolveResult, ArpTable, PendingPacket},
    dns::DnsResolver,
    icmp::{IcmpHandleResult, IcmpHandler},
    ip::{InterfaceConfig, RoutingTable, build_ipv4_packet},
    tcp::{TcpConnectionKey, TcpOutput, TcpSocketTable},
    udp::UdpSocketTable,
};

// First ephemeral port number for outbound TCP connections (RFC 6335 §6).
const EPHEMERAL_PORT_START: u16 = 49_152;
// Last ephemeral port (inclusive); wraps back to EPHEMERAL_PORT_START.
const EPHEMERAL_PORT_END: u16 = 65_534;

// =============================================================================
// ServiceOutput
// =============================================================================

/// Cumulative per-interface traffic counters, index-aligned with
/// [`NetworkService::interfaces`].
///
/// Backs the real (non-fabricated) `rx_bytes`/`tx_bytes`/`rx_packets`/
/// `tx_packets` fields of `nexacore_net::ifconfig::InterfaceInfo` — no such
/// counters existed anywhere in the stack before this struct.
#[derive(Debug, Clone, Copy, Default)]
pub struct IfaceCounters {
    /// Bytes received on this interface (Ethernet frame length, header
    /// included), summed across every frame handed to [`NetworkService::handle_frame`].
    pub rx_bytes: u64,
    /// Bytes transmitted on this interface, summed across every
    /// [`ServiceOutput::SendFrame`] this service has emitted for it.
    pub tx_bytes: u64,
    /// Number of frames received on this interface.
    pub rx_frames: u64,
    /// Number of frames transmitted on this interface.
    pub tx_frames: u64,
}

/// Actions the service loop must perform after processing a frame or request.
#[derive(Debug)]
pub enum ServiceOutput {
    /// Transmit a raw Ethernet frame on `interface`.
    SendFrame {
        /// Index into [`NetworkService::interfaces`].
        interface: usize,
        /// Complete frame bytes (Ethernet header + payload).
        data: Vec<u8>,
    },
    /// Return a response to the userspace caller.
    SocketResponse(SocketResponse),
}

// =============================================================================
// NetworkService
// =============================================================================

/// The NexaCore OS userspace TCP/IP network stack service.
///
/// # Examples
///
/// ```
/// use nexacore_net::service::NetworkService;
///
/// let mut svc = NetworkService::new();
/// // Tick at time 0 — nothing to do yet.
/// let out = svc.tick(0);
/// assert!(out.is_empty());
/// ```
pub struct NetworkService {
    /// Network interfaces registered with this service.
    pub interfaces: Vec<InterfaceConfig>,
    /// Per-interface traffic counters, index-aligned with `interfaces`.
    counters: Vec<IfaceCounters>,
    /// ARP resolution table.
    pub arp: ArpTable,
    /// IP routing table.
    pub routing: RoutingTable,
    /// ICMP handler.
    pub icmp: IcmpHandler,
    /// UDP socket table.
    pub udp: UdpSocketTable,
    /// TCP socket table.
    pub tcp: TcpSocketTable,
    /// DNS stub resolver.
    pub dns: DnsResolver,
    /// Next socket handle to allocate.
    next_handle: u64,
    /// Maps a [`SocketHandle`]'s inner value to its TCP connection key
    /// `(local, remote)` — the real 4-tuple established during
    /// [`SocketRequest::Connect`].  Used by subsequent `Send`, `Recv`, and
    /// `Close` calls to locate the correct [`crate::tcp::TcpControlBlock`]
    /// without re-deriving the key from the opaque handle number.
    ///
    /// # Bug fixed (M0 TCB 4-tuple bug)
    ///
    /// The original implementation derived the local address as `127.0.0.1`
    /// and the local port as `handle.0` cast to `u16`.  This meant a Connect
    /// to `192.0.2.11:11434` would key the TCB on
    /// `(127.0.0.1:<handle>, 0.0.0.0:0)` — completely wrong and incompatible
    /// with the frame-ingress path in [`Self::handle_frame`] which keys on
    /// the real on-wire 4-tuple `(192.0.2.50:<ephemeral>, 192.0.2.11:11434)`.
    /// The fix records the exact `TcpConnectionKey` returned by
    /// [`crate::tcp::TcpSocketTable::connect`] and indexes it by handle.
    socket_state: BTreeMap<u64, TcpConnectionKey>,
    /// Per-socket options indexed by handle value (WS4-01.7), set via
    /// [`SocketRequest::SetSockOpt`] and dropped on `Close`.
    socket_options: BTreeMap<u64, SocketOptions>,
    /// Next ephemeral source port to assign for outbound TCP connections.
    ///
    /// Allocated in the IANA ephemeral range 49 152–65 534 (RFC 6335 §6),
    /// wrapping around to avoid collisions with well-known ports.
    next_ephemeral_port: u16,
    /// Outbound frames produced by `handle_socket_request` (which returns a
    /// single [`SocketResponse`], not a `Vec<ServiceOutput>`). A TCP `Connect`
    /// generates a SYN frame that has no return slot in that signature, so it
    /// is queued here and drained by the event loop via [`Self::take_pending_tx`]
    /// after each socket-request call. Without this, connect's SYN was silently
    /// dropped (`let _ = frame`) and never reached the NIC.
    pending_tx: Vec<ServiceOutput>,
    /// A TCP `Connect` whose userspace reply has been **deferred** until the
    /// three-way handshake completes (FU3 — truthful `NetConnect`).
    ///
    /// Stores `(handle, key)`. While set, [`Self::handle_socket_request`]
    /// returns [`SocketResponse::Pending`] for the `Connect`, and the real
    /// `Ok`/`Error` is emitted as a [`ServiceOutput::SocketResponse`] from
    /// [`Self::handle_frame`] / [`Self::tick`] once the matching connection key
    /// reaches `ESTABLISHED` (→ `Ok(0)`) or is refused/closed (→ `Error`).
    /// Only one outbound connect can be pending at a time (M0 has a single
    /// blocking relay caller); a second concurrent `Connect` is rejected with
    /// `NetError::WouldBlock`.
    pending_connect: Option<(u64, TcpConnectionKey)>,
}

impl Default for NetworkService {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-socket options set via [`SocketRequest::SetSockOpt`] (WS4-01.7).
///
/// Defaults match the documented POSIX defaults (everything off / no timeout).
/// The transport layers consult these when sizing behaviour (e.g. `no_delay`
/// disables Nagle batching); they are stored centrally so a socket's
/// configuration survives independently of its transport control block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "POSIX socket options are independent boolean flags"
)]
pub struct SocketOptions {
    /// `SO_REUSEADDR`: permit binding a port still in `TIME_WAIT`.
    pub reuse_addr: bool,
    /// `SO_KEEPALIVE`: send periodic keep-alive probes on idle connections.
    pub keep_alive: bool,
    /// `TCP_NODELAY`: send small writes immediately (disable Nagle).
    pub no_delay: bool,
    /// `SO_RCVTIMEO` in microseconds (0 = blocking, no timeout).
    pub recv_timeout_us: u64,
    /// `SO_SNDTIMEO` in microseconds (0 = blocking, no timeout).
    pub send_timeout_us: u64,
    /// `SO_BROADCAST`: permit sending to broadcast addresses.
    pub broadcast: bool,
}

impl SocketOptions {
    /// Apply one [`SocketOption`] setting to this option set.
    fn apply(&mut self, option: SocketOption) {
        match option {
            SocketOption::ReuseAddr(v) => self.reuse_addr = v,
            SocketOption::KeepAlive(v) => self.keep_alive = v,
            SocketOption::NoDelay(v) => self.no_delay = v,
            SocketOption::RecvTimeout(us) => self.recv_timeout_us = us,
            SocketOption::SendTimeout(us) => self.send_timeout_us = us,
            SocketOption::Broadcast(v) => self.broadcast = v,
            // `SocketOption` is `#[non_exhaustive]`; ignore options this build
            // does not yet model rather than failing the set.
            _ => {}
        }
    }
}

impl NetworkService {
    /// Construct an empty [`NetworkService`] with no interfaces configured.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
            counters: Vec::new(),
            arp: ArpTable::new(crate::arp::ARP_MAX_ENTRIES),
            routing: RoutingTable::new(),
            icmp: IcmpHandler::new(),
            udp: UdpSocketTable::new(),
            tcp: TcpSocketTable::new(),
            dns: DnsResolver::new(Vec::new()),
            next_handle: 1,
            socket_state: BTreeMap::new(),
            socket_options: BTreeMap::new(),
            next_ephemeral_port: EPHEMERAL_PORT_START,
            pending_tx: Vec::new(),
            pending_connect: None,
        }
    }

    /// The current [`SocketOptions`] for `handle` (WS4-01.7).
    ///
    /// Returns the defaults if no option has been set on the handle, so the
    /// transport layers can always read a complete option set.
    #[must_use]
    pub fn socket_options(&self, handle: SocketHandle) -> SocketOptions {
        self.socket_options
            .get(&handle.0)
            .copied()
            .unwrap_or_default()
    }

    /// Drain and return any outbound frames queued by `handle_socket_request`
    /// (e.g. the SYN from a TCP `Connect`). The event loop calls this after
    /// each socket request and forwards the items to the NIC driver. Empty when
    /// the last request produced no frames.
    #[must_use]
    pub fn take_pending_tx(&mut self) -> Vec<ServiceOutput> {
        core::mem::take(&mut self.pending_tx)
    }

    /// Register a network interface.
    ///
    /// Automatically adds a connected route for the interface's subnet.
    pub fn add_interface(&mut self, config: InterfaceConfig) {
        // Add connected route for the interface subnet.
        use crate::ip::Route;
        self.routing.add_route(Route {
            destination: config.netmask,
            gateway: None,
            interface: config.name.clone(),
            metric: 0,
        });
        self.interfaces.push(config);
        self.counters.push(IfaceCounters::default());
    }

    /// The cumulative traffic counters for `interfaces[idx]`, or the zero
    /// value if `idx` is out of range.
    #[must_use]
    pub fn counters(&self, idx: usize) -> IfaceCounters {
        self.counters.get(idx).copied().unwrap_or_default()
    }

    /// Records `len` received bytes on `interface_idx` (a no-op if the index
    /// is out of range — e.g. a frame handed in before `add_interface` ran).
    fn record_rx(&mut self, interface_idx: usize, len: usize) {
        if let Some(c) = self.counters.get_mut(interface_idx) {
            c.rx_frames += 1;
            c.rx_bytes = c
                .rx_bytes
                .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        }
    }

    /// Records `len` transmitted bytes on `interface_idx` (a no-op if the
    /// index is out of range).
    fn record_tx(&mut self, interface_idx: usize, len: usize) {
        if let Some(c) = self.counters.get_mut(interface_idx) {
            c.tx_frames += 1;
            c.tx_bytes = c
                .tx_bytes
                .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        }
    }

    /// Process an incoming Ethernet frame received on `interface_idx`.
    ///
    /// Returns a list of [`ServiceOutput`] items — frames to send and socket
    /// responses to deliver.
    pub fn handle_frame(
        &mut self,
        interface_idx: usize,
        frame: &[u8],
        now: u64,
    ) -> Vec<ServiceOutput> {
        let mut out = Vec::new();
        self.record_rx(interface_idx, frame.len());

        let Some((eth_hdr, payload)) = EthernetHeader::parse(frame) else {
            return out;
        };

        let our_mac = self
            .interfaces
            .get(interface_idx)
            .map_or(MacAddress([0; 6]), |iface| iface.mac);
        let our_ip = self
            .interfaces
            .get(interface_idx)
            .map_or(Ipv4Addr::UNSPECIFIED, |iface| iface.ip);

        match eth_hdr.ether_type {
            EtherType::ARP => {
                if let Some(arp_pkt) = ArpPacket::parse(payload) {
                    self.handle_arp_packet(interface_idx, &arp_pkt, our_mac, our_ip, &mut out);
                }
            }
            EtherType::IPV4 => {
                let Some((ip_hdr, ip_payload)) = crate::ip::parse_ipv4_packet(payload) else {
                    return out;
                };
                match ip_hdr.protocol {
                    IpProtocol::ICMP => {
                        if let Some((icmp_hdr, icmp_payload)) = IcmpHeader::parse(ip_payload) {
                            let result = self.icmp.handle_icmp(
                                icmp_hdr,
                                icmp_payload,
                                ip_hdr.src,
                                our_ip,
                                now,
                            );
                            match result {
                                IcmpHandleResult::Reply(reply) => {
                                    // Wrap reply in IPv4 and Ethernet.
                                    let ip_pkt = build_ipv4_packet(
                                        our_ip,
                                        ip_hdr.src,
                                        IpProtocol::ICMP,
                                        64,
                                        0,
                                        &reply.data,
                                    );
                                    if let Some(frame_data) =
                                        self.wrap_in_ethernet(ip_hdr.src, our_mac, &ip_pkt)
                                    {
                                        self.record_tx(interface_idx, frame_data.len());
                                        out.push(ServiceOutput::SendFrame {
                                            interface: interface_idx,
                                            data: frame_data,
                                        });
                                    }
                                }
                                _ => {} // Other ICMP types handled by application layer.
                            }
                        }
                    }
                    IpProtocol::UDP => {
                        if let Some((udp_hdr, udp_payload)) = UdpHeader::parse(ip_payload) {
                            self.udp
                                .handle_packet(udp_hdr, udp_payload, ip_hdr.src, ip_hdr.dst);
                        }
                    }
                    IpProtocol::TCP => {
                        if let Some((tcp_hdr, tcp_payload)) = TcpHeader::parse(ip_payload) {
                            let tcp_outs = self.tcp.handle_segment(
                                &tcp_hdr,
                                tcp_payload,
                                ip_hdr.src,
                                ip_hdr.dst,
                                now,
                            );
                            self.emit_tcp_outputs(tcp_outs, interface_idx, our_mac, &mut out);
                        }
                    }
                    _ => {} // Unhandled protocol.
                }
            }
            _ => {} // Unhandled EtherType.
        }

        out
    }

    /// Process a [`SocketRequest`] from a userspace program.
    ///
    /// Returns the appropriate [`SocketResponse`].
    ///
    /// ## 4-tuple TCB key contract
    ///
    /// Every TCP socket request that targets an active connection (`Send`,
    /// `Recv`, `Close`) looks up the connection by the **real** 4-tuple
    /// `(local_ip:local_port, remote_ip:remote_port)` stored in
    /// `socket_state` at `Connect` time.  This guarantees that
    /// [`crate::tcp::TcpSocketTable::handle_segment`], which keys on the
    /// real on-wire addresses, can find the same control block.
    // This function dispatches many socket request variants; the length is
    // inherent to the design of a socket API dispatcher.
    #[allow(clippy::too_many_lines)]
    pub fn handle_socket_request(&mut self, request: SocketRequest) -> SocketResponse {
        match request {
            SocketRequest::Socket { .. } => {
                // Allocate an opaque handle; actual socket creation happens on Bind/Connect.
                let h = SocketHandle(self.next_handle);
                self.next_handle += 1;
                SocketResponse::Handle(h)
            }
            SocketRequest::Bind { addr, .. } => {
                let port = addr.port;
                match self.udp.bind(port) {
                    Ok(p) => SocketResponse::Ok(u64::from(p)),
                    Err(e) => SocketResponse::Error(e),
                }
            }
            SocketRequest::Listen { handle, backlog } => {
                // Use the bound port stored in the socket state for passive
                // TCP listeners.  If no state exists yet, fall back to the
                // handle value cast to u16 (legacy path for pre-Bind listen).
                let port = self.socket_state.get(&handle.0).map_or_else(
                    || u16::try_from(handle.0).unwrap_or(0),
                    |(local, _remote)| local.port,
                );
                match self.tcp.listen(port, backlog as usize) {
                    Ok(()) => SocketResponse::Ok(0),
                    Err(e) => SocketResponse::Error(e),
                }
            }
            SocketRequest::Accept { handle } => {
                let port = self.socket_state.get(&handle.0).map_or_else(
                    || u16::try_from(handle.0).unwrap_or(0),
                    |(local, _remote)| local.port,
                );
                match self.tcp.accept(port) {
                    Some(_key) => {
                        let h = SocketHandle(self.next_handle);
                        self.next_handle += 1;
                        SocketResponse::Handle(h)
                    }
                    None => SocketResponse::Error(NetError::WouldBlock),
                }
            }
            SocketRequest::Connect { handle, addr } => {
                // FU3: only one outbound connect may be pending at a time (the
                // single blocking relay caller). Reject a concurrent connect so
                // its deferred reply cannot clobber the in-flight one.
                if self.pending_connect.is_some() {
                    return SocketResponse::Error(NetError::WouldBlock);
                }
                // Derive the local source IP from the first registered interface.
                // M0 always uses `192.0.2.50` (the static `eth0` config).
                let local_ip = self
                    .interfaces
                    .first()
                    .map_or(Ipv4Addr::UNSPECIFIED, |i| i.ip);

                // Allocate an ephemeral source port in the IANA range.
                let ephemeral = self.alloc_ephemeral_port();
                let local = SocketApiAddr {
                    ip: local_ip.0,
                    port: ephemeral,
                };

                let mut tcp_out = Vec::new();
                match self.tcp.connect(local, addr, &mut tcp_out) {
                    Ok(key) => {
                        // Record the real 4-tuple so subsequent Send/Recv/Close
                        // can look it up by handle without re-deriving it.
                        self.socket_state.insert(handle.0, key);
                        // FU3: defer the userspace reply until the handshake
                        // reaches ESTABLISHED (or fails). Remember which handle
                        // and connection key the deferred reply belongs to.
                        self.pending_connect = Some((handle.0, key));
                        // Emit the SYN segment(s) produced by connect().
                        let our_mac = self
                            .interfaces
                            .first()
                            .map_or(MacAddress([0; 6]), |i| i.mac);
                        for tcp_out_item in tcp_out {
                            if let TcpOutput::SendSegment { data, dst_ip } = tcp_out_item {
                                // Queue the SYN frame on `pending_tx`. The event
                                // loop drains it via `take_pending_tx()` right
                                // after this call and forwards it to the NIC
                                // driver. (Previously dropped here, so connect's
                                // SYN never reached the wire.) If ARP for the
                                // dst is unresolved, `wrap_in_ethernet` returns
                                // None and the segment is held by the ARP layer
                                // for retransmit once the reply arrives.
                                if let Some(frame) = self.wrap_in_ethernet(dst_ip, our_mac, &data) {
                                    self.record_tx(0, frame.len());
                                    self.pending_tx.push(ServiceOutput::SendFrame {
                                        interface: 0,
                                        data: frame,
                                    });
                                } else {
                                    // ARP miss: the SYN is now queued in the ARP
                                    // layer. Emit the ARP request so the reply
                                    // comes back and `handle_arp_packet` drains
                                    // the pending SYN. Without this, the SYN
                                    // would sit forever (resolve() enqueues but
                                    // does not itself send a request).
                                    if let Some(arp_frame) =
                                        Self::build_arp_request_frame(dst_ip, our_mac, local_ip)
                                    {
                                        self.record_tx(0, arp_frame.len());
                                        self.pending_tx.push(ServiceOutput::SendFrame {
                                            interface: 0,
                                            data: arp_frame,
                                        });
                                    }
                                }
                            }
                        }
                        // FU3: do NOT answer now. The blocking relay caller
                        // stays parked on the reply channel until the deferred
                        // Ok/Error is emitted from handle_frame/tick.
                        SocketResponse::Pending
                    }
                    Err(e) => SocketResponse::Error(e),
                }
            }
            SocketRequest::Send { handle, data, .. } => {
                // Look up the real 4-tuple that was recorded at Connect time.
                let Some(key) = self.socket_state.get(&handle.0).copied() else {
                    return SocketResponse::Error(NetError::NotConnected);
                };
                let mut tcp_out = Vec::new();
                match self.tcp.send(&key, &data, &mut tcp_out) {
                    Ok(n) => {
                        // Queue the PSH|ACK data segment(s) on `pending_tx`,
                        // exactly like Connect queues its SYN: the event loop
                        // drains them via `take_pending_tx()` right after this
                        // call and forwards them to the NIC driver. ARP is
                        // resolved by the time a connection is ESTABLISHED, so
                        // `wrap_in_ethernet` (inside `emit_tcp_outputs`)
                        // normally succeeds immediately; on a cold cache the
                        // segment is held by the ARP layer for transmit once
                        // the reply arrives (TASK-05).
                        let our_mac = self
                            .interfaces
                            .first()
                            .map_or(MacAddress([0; 6]), |i| i.mac);
                        let mut outs = Vec::new();
                        self.emit_tcp_outputs(tcp_out, 0, our_mac, &mut outs);
                        self.pending_tx.extend(outs);
                        SocketResponse::Ok(n as u64)
                    }
                    Err(e) => SocketResponse::Error(e),
                }
            }
            SocketRequest::Recv {
                handle, max_len, ..
            } => {
                // Look up the real 4-tuple that was recorded at Connect time.
                let Some(key) = self.socket_state.get(&handle.0).copied() else {
                    return SocketResponse::Error(NetError::NotConnected);
                };
                let mut buf = alloc::vec![0u8; max_len as usize];
                match self.tcp.recv(&key, &mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        SocketResponse::Data(buf)
                    }
                    Err(e) => SocketResponse::Error(e),
                }
            }
            SocketRequest::SendTo { handle, data, addr } => {
                let port = u16::try_from(handle.0).unwrap_or(0);
                let iface_ip = self
                    .interfaces
                    .first()
                    .map_or(Ipv4Addr::UNSPECIFIED, |i| i.ip);
                let dst_ip = Ipv4Addr(addr.ip);
                match self.udp.sendto(port, addr, iface_ip, dst_ip, &data) {
                    Ok(pkt) => SocketResponse::Ok(pkt.len() as u64),
                    Err(e) => SocketResponse::Error(e),
                }
            }
            SocketRequest::RecvFrom { handle, .. } => {
                let port = u16::try_from(handle.0).unwrap_or(0);
                match self.udp.recvfrom(port) {
                    Some((src, data)) => SocketResponse::DataFrom(data, src),
                    None => SocketResponse::Error(NetError::WouldBlock),
                }
            }
            SocketRequest::Close { handle } => {
                // Drop any per-socket options set on this handle (WS4-01.7).
                self.socket_options.remove(&handle.0);
                // If a TCP connection state exists for this handle, remove it.
                if let Some(key) = self.socket_state.remove(&handle.0) {
                    let mut out = Vec::new();
                    // Initiate TCP close; ignore errors (already closed is fine).
                    let _ = self.tcp.close(&key, &mut out);
                } else {
                    // Fall back to UDP close using handle-derived port.
                    let port = u16::try_from(handle.0).unwrap_or(0);
                    self.udp.close(port);
                }
                SocketResponse::Ok(0)
            }
            SocketRequest::Resolve { hostname } => {
                let now_secs = 0u64; // No real clock; caller must inject time.
                self.dns.resolve_cached(&hostname, now_secs).map_or(
                    SocketResponse::Error(NetError::HostUnreachable),
                    |addrs| {
                        let api_addrs: Vec<SocketApiAddr> = addrs
                            .iter()
                            .map(|a| SocketApiAddr { ip: a.0, port: 0 })
                            .collect();
                        SocketResponse::Addresses(api_addrs)
                    },
                )
            }
            SocketRequest::ListSockets => {
                // Return an empty list for now; the full implementation would
                // iterate tcp/udp socket tables.
                SocketResponse::SocketList(alloc::vec![])
            }
            SocketRequest::SetSockOpt { handle, option } => {
                // Store the option on the per-socket option set (WS4-01.7),
                // creating a default entry on first use.
                self.socket_options
                    .entry(handle.0)
                    .or_default()
                    .apply(option);
                SocketResponse::Ok(0)
            }
            // Remaining variants — return Ok(0) or meaningful defaults.
            SocketRequest::GetSockName { .. }
            | SocketRequest::GetPeerName { .. }
            | SocketRequest::Shutdown { .. } => SocketResponse::Ok(0),
            _ => SocketResponse::Error(NetError::InvalidArgument),
        }
    }

    /// Allocate the next ephemeral source port in the IANA range
    /// [49 152, 65 534] (RFC 6335 §6).
    ///
    /// Wraps around to `EPHEMERAL_PORT_START` after reaching the end.
    /// Collision detection is left to `TcpSocketTable::connect` which
    /// returns `Err(NetError::AddrInUse)` if the exact 4-tuple already exists.
    fn alloc_ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port = if self.next_ephemeral_port >= EPHEMERAL_PORT_END {
            EPHEMERAL_PORT_START
        } else {
            self.next_ephemeral_port + 1
        };
        port
    }

    /// Drive periodic timers: ARP expiry and TCP `retransmit/TIME_WAIT`.
    ///
    /// `now` is the current monotonic timestamp in milliseconds.
    pub fn tick(&mut self, now: u64) -> Vec<ServiceOutput> {
        let mut out = Vec::new();

        // ARP expiry: convert ms timestamp to seconds for the ARP table.
        // Integer division is intentional here (truncating milliseconds).
        #[allow(clippy::integer_division)]
        let now_secs = now / 1000;
        self.arp.expire_stale(now_secs, ARP_TIMEOUT_SECS);

        // ARP re-transmission (WS2-02.2): re-emit the who-has for next hops that
        // are still unresolved, so a single dropped request/reply does not stall
        // the entry for the whole pending window. Copy the interface's addresses
        // first to release the borrow before mutating the ARP table.
        if let Some((our_mac, our_ip)) = self.interfaces.first().map(|i| (i.mac, i.ip)) {
            for target_ip in self.arp.due_retransmits(now_secs) {
                if let Some(frame) = Self::build_arp_request_frame(target_ip, our_mac, our_ip) {
                    self.record_tx(0, frame.len());
                    out.push(ServiceOutput::SendFrame {
                        interface: 0,
                        data: frame,
                    });
                }
            }
        }

        // TCP tick.
        let mut tcp_outs = Vec::new();
        self.tcp.tick(now, &mut tcp_outs);
        // Emit TCP outputs without interface binding (use interface 0).
        let our_mac = self
            .interfaces
            .first()
            .map_or(MacAddress([0; 6]), |i| i.mac);
        self.emit_tcp_outputs(tcp_outs, 0, our_mac, &mut out);

        out
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Process an ARP packet and queue any reply that needs to be sent.
    fn handle_arp_packet(
        &mut self,
        interface_idx: usize,
        pkt: &ArpPacket,
        our_mac: MacAddress,
        our_ip: Ipv4Addr,
        out: &mut Vec<ServiceOutput>,
    ) {
        let result = self.arp.handle_arp_packet(pkt, our_mac, our_ip);
        match result {
            ArpHandleResult::SendReply(reply) => {
                // Wrap ARP reply in Ethernet frame.
                let mut frame =
                    alloc::vec![0u8; EthernetHeader::HEADER_LEN + ArpPacket::PACKET_LEN];
                let eth = EthernetHeader {
                    dst: pkt.sender_mac,
                    src: our_mac,
                    ether_type: EtherType::ARP,
                };
                if let Some(eth_slot) = frame.get_mut(..EthernetHeader::HEADER_LEN) {
                    eth.serialize(eth_slot);
                }
                if let Some(arp_slot) = frame.get_mut(EthernetHeader::HEADER_LEN..) {
                    reply.serialize(arp_slot);
                }
                self.record_tx(interface_idx, frame.len());
                out.push(ServiceOutput::SendFrame {
                    interface: interface_idx,
                    data: frame,
                });
                // Also drain any pending packets that were waiting for this ARP.
                let pending = self.arp.drain_pending(pkt.sender_ip);
                for pending_pkt in pending {
                    // Re-emit as a SendFrame.
                    if let Some(frame) =
                        self.wrap_in_ethernet(pending_pkt.next_hop_ip, our_mac, &pending_pkt.data)
                    {
                        self.record_tx(interface_idx, frame.len());
                        out.push(ServiceOutput::SendFrame {
                            interface: interface_idx,
                            data: frame,
                        });
                    }
                }
            }
            ArpHandleResult::UpdatedTable => {
                // Drain any packets that were waiting for this MAC.
                let sender_ip = pkt.sender_ip;
                let pending = self.arp.drain_pending(sender_ip);
                for pending_pkt in pending {
                    if let Some(frame) =
                        self.wrap_in_ethernet(pending_pkt.next_hop_ip, our_mac, &pending_pkt.data)
                    {
                        self.record_tx(interface_idx, frame.len());
                        out.push(ServiceOutput::SendFrame {
                            interface: interface_idx,
                            data: frame,
                        });
                    }
                }
            }
            ArpHandleResult::Ignored => {}
        }
    }

    /// Build a broadcast ARP-request Ethernet frame asking who-has `target_ip`.
    ///
    /// Used by `Connect` when the next hop's MAC is unresolved: the SYN is held
    /// by the ARP layer, and this request triggers the reply that
    /// [`Self::handle_arp_packet`] then uses to drain the pending SYN. Returns
    /// `None` only if Ethernet/ARP serialization of the fixed-size buffers
    /// somehow fails (never in practice).
    fn build_arp_request_frame(
        target_ip: Ipv4Addr,
        our_mac: MacAddress,
        our_ip: Ipv4Addr,
    ) -> Option<Vec<u8>> {
        let req = ArpTable::build_request(our_mac, our_ip, target_ip);
        let mut frame = alloc::vec![0u8; EthernetHeader::HEADER_LEN + ArpPacket::PACKET_LEN];
        let eth = EthernetHeader {
            dst: MacAddress([0xFF; 6]), // broadcast
            src: our_mac,
            ether_type: EtherType::ARP,
        };
        eth.serialize(frame.get_mut(..EthernetHeader::HEADER_LEN)?);
        req.serialize(frame.get_mut(EthernetHeader::HEADER_LEN..)?);
        Some(frame)
    }

    /// Wrap `ip_payload` in an Ethernet frame addressed to `dst_ip`.
    ///
    /// Returns `None` if the ARP resolution for `dst_ip` is pending (the
    /// packet has been queued internally).
    fn wrap_in_ethernet(
        &mut self,
        dst_ip: Ipv4Addr,
        our_mac: MacAddress,
        ip_payload: &[u8],
    ) -> Option<Vec<u8>> {
        let dst_mac = match self.arp.resolve(
            dst_ip,
            Some(PendingPacket {
                data: ip_payload.to_vec(),
                next_hop_ip: dst_ip,
            }),
        ) {
            ArpResolveResult::Resolved(mac) => mac,
            ArpResolveResult::Pending => return None,
        };

        let mut frame = alloc::vec![0u8; EthernetHeader::HEADER_LEN + ip_payload.len()];
        let eth = EthernetHeader {
            dst: dst_mac,
            src: our_mac,
            ether_type: EtherType::IPV4,
        };
        if let Some(eth_slot) = frame.get_mut(..EthernetHeader::HEADER_LEN) {
            eth.serialize(eth_slot);
        }
        if let Some(payload_slot) = frame.get_mut(EthernetHeader::HEADER_LEN..) {
            payload_slot.copy_from_slice(ip_payload);
        }
        Some(frame)
    }

    /// Convert `TcpOutput` items into `ServiceOutput` items.
    fn emit_tcp_outputs(
        &mut self,
        tcp_outs: Vec<TcpOutput>,
        interface_idx: usize,
        our_mac: MacAddress,
        out: &mut Vec<ServiceOutput>,
    ) {
        for tcp_out in tcp_outs {
            match tcp_out {
                TcpOutput::SendSegment { data, dst_ip } => {
                    // Attempt Ethernet wrap; if ARP pending the packet is queued.
                    if let Some(frame) = self.wrap_in_ethernet(dst_ip, our_mac, &data) {
                        self.record_tx(interface_idx, frame.len());
                        out.push(ServiceOutput::SendFrame {
                            interface: interface_idx,
                            data: frame,
                        });
                    }
                }
                // FU3: the handshake completed — release the deferred Connect
                // reply (truthful `NetConnect`: the caller unblocks only now,
                // once the connection is genuinely ESTABLISHED).
                TcpOutput::ConnectionEstablished { key } => {
                    if let Some(resp) = self.resolve_pending_connect(&key, SocketResponse::Ok(0)) {
                        out.push(resp);
                    }
                }
                // FU3: the peer refused (RST in SynSent) or the half-open
                // connection was torn down before establishing — fail the
                // deferred Connect instead of leaving the caller parked.
                TcpOutput::ConnectionRefused { key } => {
                    if let Some(resp) = self.resolve_pending_connect(
                        &key,
                        SocketResponse::Error(NetError::ConnectionRefused),
                    ) {
                        out.push(resp);
                    }
                }
                TcpOutput::ConnectionClosed { key } => {
                    // A `pending_connect` only exists while the connection is in
                    // SynSent (it is cleared the moment the handshake completes,
                    // is refused, or the reply is delivered). The only way the
                    // TCP layer emits `ConnectionClosed` for a still-pending
                    // connect is the SYN-retransmit timeout (WS2-02.3:
                    // MAX_RETRANSMIT SYNs with no SYN-ACK). So the deferred
                    // Connect must fail with `TimedOut` (ETIMEDOUT) — the
                    // connect-phase timeout (WS2-02.1) — not `ConnectionReset`.
                    if let Some(resp) = self
                        .resolve_pending_connect(&key, SocketResponse::Error(NetError::TimedOut))
                    {
                        out.push(resp);
                    }
                }
                // DataReceived and any future notification have no deferred
                // reply to satisfy; the upper application layer drains data via
                // explicit Recv requests.
                TcpOutput::DataReceived { .. } => {}
            }
        }
    }

    /// FU3 helper: if a deferred [`SocketRequest::Connect`] is pending for
    /// `key`, clear it and return the [`ServiceOutput::SocketResponse`] the
    /// service loop must deliver on the reply channel. Returns `None` when no
    /// pending connect matches (e.g. a passive/listener connection, or the
    /// reply was already delivered).
    fn resolve_pending_connect(
        &mut self,
        key: &TcpConnectionKey,
        response: SocketResponse,
    ) -> Option<ServiceOutput> {
        match self.pending_connect {
            Some((_handle, pending_key)) if pending_key == *key => {
                self.pending_connect = None;
                Some(ServiceOutput::SocketResponse(response))
            }
            _ => None,
        }
    }
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
        unused_imports
    )]
    use nexacore_types::{
        net::{Cidr, EtherType, EthernetHeader, Ipv4Addr, MacAddress},
        socket::{SocketDomain, SocketHandle, SocketRequest, SocketType},
    };

    #[allow(clippy::wildcard_imports)]
    use super::*;
    use crate::ip::{InterfaceConfig, Route};

    fn make_interface() -> InterfaceConfig {
        InterfaceConfig {
            name: "eth0".into(),
            ip: Ipv4Addr([192, 0, 2, 1]),
            netmask: Cidr::new(Ipv4Addr([192, 0, 2, 0]), 24).unwrap(),
            mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
            mtu: 1500,
        }
    }

    fn make_service() -> NetworkService {
        let mut svc = NetworkService::new();
        svc.add_interface(make_interface());
        // Pre-populate ARP for a peer so wrap_in_ethernet succeeds.
        svc.arp.insert(
            Ipv4Addr([192, 0, 2, 10]),
            MacAddress([0x02, 0, 0, 0, 0, 2]),
            0,
        );
        svc
    }

    fn make_eth_frame(payload: &[u8], ether_type: EtherType) -> Vec<u8> {
        let mut frame = alloc::vec![0u8; EthernetHeader::HEADER_LEN + payload.len()];
        let eth = EthernetHeader {
            dst: MacAddress([0x02, 0, 0, 0, 0, 1]),
            src: MacAddress([0x02, 0, 0, 0, 0, 2]),
            ether_type,
        };
        eth.serialize(&mut frame[..EthernetHeader::HEADER_LEN]);
        if let Some(dst) = frame.get_mut(EthernetHeader::HEADER_LEN..) {
            dst.copy_from_slice(payload);
        }
        frame
    }

    // -------------------------------------------------------------------------
    // Basic service construction
    // -------------------------------------------------------------------------

    #[test]
    fn new_service_has_no_interfaces() {
        let svc = NetworkService::new();
        assert!(svc.interfaces.is_empty());
    }

    #[test]
    fn add_interface_registers_interface() {
        let mut svc = NetworkService::new();
        svc.add_interface(make_interface());
        assert_eq!(svc.interfaces.len(), 1);
    }

    #[test]
    fn add_interface_adds_connected_route() {
        let mut svc = NetworkService::new();
        svc.add_interface(make_interface());
        let route = svc.routing.lookup(Ipv4Addr([192, 0, 2, 50]));
        assert!(route.is_some());
    }

    // -------------------------------------------------------------------------
    // Traffic counters
    // -------------------------------------------------------------------------

    #[test]
    fn add_interface_starts_with_zero_counters() {
        let mut svc = NetworkService::new();
        svc.add_interface(make_interface());
        let c = svc.counters(0);
        assert_eq!(c.rx_bytes, 0);
        assert_eq!(c.tx_bytes, 0);
        assert_eq!(c.rx_frames, 0);
        assert_eq!(c.tx_frames, 0);
    }

    #[test]
    fn counters_out_of_range_returns_zero_value() {
        let svc = NetworkService::new();
        let c = svc.counters(5);
        assert_eq!(c.rx_bytes, 0);
        assert_eq!(c.tx_frames, 0);
    }

    #[test]
    fn handle_frame_increments_rx_counters() {
        use nexacore_types::net::{ArpOperation, ArpPacket};

        let mut svc = make_service();
        let arp_pkt = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: MacAddress([0x02, 0, 0, 0, 0, 2]),
            sender_ip: Ipv4Addr([192, 0, 2, 10]),
            target_mac: MacAddress([0; 6]),
            target_ip: Ipv4Addr([192, 0, 2, 1]),
        };
        let mut payload = alloc::vec![0u8; ArpPacket::PACKET_LEN];
        arp_pkt.serialize(&mut payload);
        let frame = make_eth_frame(&payload, EtherType::ARP);
        let frame_len = frame.len();
        svc.handle_frame(0, &frame, 0);
        let c = svc.counters(0);
        assert_eq!(c.rx_frames, 1);
        assert_eq!(c.rx_bytes, frame_len as u64);
    }

    #[test]
    fn handle_frame_arp_reply_increments_tx_counters() {
        use nexacore_types::net::{ArpOperation, ArpPacket};

        let mut svc = make_service();
        let arp_pkt = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: MacAddress([0x02, 0, 0, 0, 0, 2]),
            sender_ip: Ipv4Addr([192, 0, 2, 10]),
            target_mac: MacAddress([0; 6]),
            target_ip: Ipv4Addr([192, 0, 2, 1]),
        };
        let mut payload = alloc::vec![0u8; ArpPacket::PACKET_LEN];
        arp_pkt.serialize(&mut payload);
        let frame = make_eth_frame(&payload, EtherType::ARP);
        svc.handle_frame(0, &frame, 0);
        let c = svc.counters(0);
        assert_eq!(c.tx_frames, 1, "the ARP reply should count as one tx frame");
        assert!(c.tx_bytes > 0);
    }

    // -------------------------------------------------------------------------
    // handle_frame: ARP
    // -------------------------------------------------------------------------

    #[test]
    fn handle_frame_arp_request_produces_reply() {
        use nexacore_types::net::{ArpOperation, ArpPacket};

        let mut svc = make_service();
        let arp_pkt = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REQUEST,
            sender_mac: MacAddress([0x02, 0, 0, 0, 0, 2]),
            sender_ip: Ipv4Addr([192, 0, 2, 10]),
            target_mac: MacAddress([0; 6]),
            target_ip: Ipv4Addr([192, 0, 2, 1]),
        };
        let mut payload = alloc::vec![0u8; ArpPacket::PACKET_LEN];
        arp_pkt.serialize(&mut payload);
        let frame = make_eth_frame(&payload, EtherType::ARP);
        let out = svc.handle_frame(0, &frame, 0);
        assert!(
            out.iter()
                .any(|o| matches!(o, ServiceOutput::SendFrame { .. }))
        );
    }

    // -------------------------------------------------------------------------
    // handle_frame: ICMP echo
    // -------------------------------------------------------------------------

    #[test]
    fn handle_frame_icmp_echo_request_produces_reply() {
        use nexacore_types::net::IpProtocol;

        use crate::{icmp::IcmpHandler, ip::build_ipv4_packet};

        let mut svc = make_service();
        let icmp_bytes = IcmpHandler::build_echo_request(1, 1, b"ping");
        let ip_pkt = build_ipv4_packet(
            Ipv4Addr([192, 0, 2, 10]),
            Ipv4Addr([192, 0, 2, 1]),
            IpProtocol::ICMP,
            64,
            0,
            &icmp_bytes,
        );
        let frame = make_eth_frame(&ip_pkt, EtherType::IPV4);
        let out = svc.handle_frame(0, &frame, 0);
        assert!(
            out.iter()
                .any(|o| matches!(o, ServiceOutput::SendFrame { .. }))
        );
    }

    // -------------------------------------------------------------------------
    // handle_frame: UDP delivery
    // -------------------------------------------------------------------------

    #[test]
    fn handle_frame_udp_delivers_to_socket() {
        use nexacore_types::net::IpProtocol;

        use crate::{ip::build_ipv4_packet, udp::build_udp_packet};

        let mut svc = make_service();
        svc.udp.bind(5000).unwrap();

        let udp_bytes = build_udp_packet(
            Ipv4Addr([192, 0, 2, 10]),
            Ipv4Addr([192, 0, 2, 1]),
            40000,
            5000,
            b"hello",
        );
        let ip_pkt = build_ipv4_packet(
            Ipv4Addr([192, 0, 2, 10]),
            Ipv4Addr([192, 0, 2, 1]),
            IpProtocol::UDP,
            64,
            0,
            &udp_bytes,
        );
        let frame = make_eth_frame(&ip_pkt, EtherType::IPV4);
        let _ = svc.handle_frame(0, &frame, 0);
        let pkt = svc.udp.recvfrom(5000);
        assert!(pkt.is_some());
        assert_eq!(pkt.unwrap().1, b"hello");
    }

    // -------------------------------------------------------------------------
    // handle_socket_request
    // -------------------------------------------------------------------------

    #[test]
    fn socket_request_socket_returns_handle() {
        let mut svc = make_service();
        let req = SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        };
        let resp = svc.handle_socket_request(req);
        assert!(matches!(resp, SocketResponse::Handle(_)));
    }

    // -------------------------------------------------------------------------
    // Socket options (WS4-01.7)
    // -------------------------------------------------------------------------

    fn new_stream_socket(svc: &mut NetworkService) -> SocketHandle {
        match svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        }) {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    fn set_opt(svc: &mut NetworkService, handle: SocketHandle, option: SocketOption) {
        assert_eq!(
            svc.handle_socket_request(SocketRequest::SetSockOpt { handle, option }),
            SocketResponse::Ok(0)
        );
    }

    #[test]
    fn set_sockopt_stores_and_accumulates_options() {
        let mut svc = make_service();
        let handle = new_stream_socket(&mut svc);
        // Defaults before any option is set.
        assert_eq!(svc.socket_options(handle), SocketOptions::default());
        // Set several distinct options; they accumulate.
        set_opt(&mut svc, handle, SocketOption::NoDelay(true));
        set_opt(&mut svc, handle, SocketOption::RecvTimeout(5_000));
        set_opt(&mut svc, handle, SocketOption::ReuseAddr(true));
        let opts = svc.socket_options(handle);
        assert!(opts.no_delay);
        assert_eq!(opts.recv_timeout_us, 5_000);
        assert!(opts.reuse_addr);
        // Untouched options keep their defaults.
        assert!(!opts.broadcast);
        assert!(!opts.keep_alive);
        assert_eq!(opts.send_timeout_us, 0);
    }

    #[test]
    fn set_sockopt_overwrites_existing_value() {
        let mut svc = make_service();
        let handle = new_stream_socket(&mut svc);
        set_opt(&mut svc, handle, SocketOption::NoDelay(true));
        assert!(svc.socket_options(handle).no_delay);
        // A later set with the opposite value overwrites.
        set_opt(&mut svc, handle, SocketOption::NoDelay(false));
        assert!(!svc.socket_options(handle).no_delay);
    }

    #[test]
    fn close_clears_socket_options() {
        let mut svc = make_service();
        let handle = new_stream_socket(&mut svc);
        set_opt(&mut svc, handle, SocketOption::KeepAlive(true));
        assert!(svc.socket_options(handle).keep_alive);
        assert_eq!(
            svc.handle_socket_request(SocketRequest::Close { handle }),
            SocketResponse::Ok(0)
        );
        // After close the handle reverts to defaults (entry dropped).
        assert_eq!(svc.socket_options(handle), SocketOptions::default());
    }

    #[test]
    fn unset_handle_returns_default_options() {
        let svc = make_service();
        assert_eq!(
            svc.socket_options(SocketHandle(4242)),
            SocketOptions::default()
        );
    }

    #[test]
    fn socket_request_bind_success() {
        let mut svc = make_service();
        let req = SocketRequest::Bind {
            handle: SocketHandle(0),
            addr: nexacore_types::socket::SocketApiAddr {
                ip: [0, 0, 0, 0],
                port: 7000,
            },
        };
        let resp = svc.handle_socket_request(req);
        assert!(matches!(resp, SocketResponse::Ok(_)));
    }

    #[test]
    fn socket_request_bind_duplicate_returns_error() {
        let mut svc = make_service();
        let bind = |svc: &mut NetworkService, port: u16| {
            svc.handle_socket_request(SocketRequest::Bind {
                handle: SocketHandle(0),
                addr: nexacore_types::socket::SocketApiAddr {
                    ip: [0, 0, 0, 0],
                    port,
                },
            })
        };
        assert!(matches!(bind(&mut svc, 8080), SocketResponse::Ok(_)));
        assert!(matches!(bind(&mut svc, 8080), SocketResponse::Error(_)));
    }

    #[test]
    fn socket_request_recv_from_empty_queue_returns_wouldblock() {
        let mut svc = make_service();
        svc.udp.bind(9000).unwrap();
        let req = SocketRequest::RecvFrom {
            handle: SocketHandle(9000),
            max_len: 512,
        };
        let resp = svc.handle_socket_request(req);
        assert!(matches!(resp, SocketResponse::Error(NetError::WouldBlock)));
    }

    #[test]
    fn socket_request_close_succeeds() {
        let mut svc = make_service();
        svc.udp.bind(6000).unwrap();
        let resp = svc.handle_socket_request(SocketRequest::Close {
            handle: SocketHandle(6000),
        });
        assert!(matches!(resp, SocketResponse::Ok(0)));
    }

    // -------------------------------------------------------------------------
    // tick
    // -------------------------------------------------------------------------

    #[test]
    fn tick_returns_empty_when_nothing_to_do() {
        let mut svc = make_service();
        let out = svc.tick(0);
        assert!(out.is_empty());
    }

    #[test]
    fn tick_retransmits_arp_request_for_unresolved_next_hop() {
        use nexacore_types::net::{ArpOperation, ArpPacket, EtherType};

        // WS2-02.2: while a next hop stays unresolved, `tick` must re-emit the
        // who-has so a single dropped request/reply does not stall it.
        let mut svc = make_m0_service();

        let handle = match svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        }) {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {other:?}"),
        };
        // Connect to a next hop on our /24 that was never pre-seeded → ARP miss.
        let _ = svc.handle_socket_request(SocketRequest::Connect {
            handle,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 99],
                port: 80,
            },
        });
        // Drain the *initial* ARP request (emitted on the miss via pending_tx)
        // so what remains can only be a re-transmission.
        let _ = svc.take_pending_tx();

        // Two seconds later the entry is still Incomplete: tick re-sends the
        // who-has for 192.0.2.99.
        let out = svc.tick(2000);
        let saw_retransmit = out.iter().any(|o| {
            let ServiceOutput::SendFrame { data, .. } = o else {
                return false;
            };
            let Some((eth, payload)) = EthernetHeader::parse(data) else {
                return false;
            };
            if eth.ether_type != EtherType::ARP {
                return false;
            }
            ArpPacket::parse(payload).is_some_and(|arp| {
                arp.operation == ArpOperation::REQUEST && arp.target_ip == Ipv4Addr([192, 0, 2, 99])
            })
        });
        assert!(
            saw_retransmit,
            "tick must re-transmit the ARP request for the unresolved next hop"
        );
    }

    #[test]
    fn handle_frame_malformed_returns_empty() {
        let mut svc = make_service();
        let out = svc.handle_frame(0, &[0xFF, 0xFF], 0);
        assert!(out.is_empty());
    }

    // -------------------------------------------------------------------------
    // M0 TCB 4-tuple integration tests
    //
    // These tests verify the fix for the bug described in the contract:
    // service.rs handle_socket_request previously hardcoded loopback and
    // derived port from handle.0, making the TCB key incompatible with
    // the key used by handle_frame (which keys on real on-wire addresses).
    // -------------------------------------------------------------------------

    /// Build a static `NetworkService` configured for the test VM (M0 topology):
    ///
    /// - eth0: 192.0.2.50/24, MAC 52:54:00:12:34:56
    /// - ARP pre-seeded: 192.0.2.11 → a synthetic MAC
    fn make_m0_service() -> NetworkService {
        use nexacore_types::net::Cidr;
        let mut svc = NetworkService::new();
        svc.add_interface(InterfaceConfig {
            name: "eth0".into(),
            ip: Ipv4Addr([192, 0, 2, 50]),
            netmask: Cidr::new(Ipv4Addr([192, 0, 2, 0]), 24).unwrap(),
            mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            mtu: 1500,
        });
        // Pre-populate ARP so wrap_in_ethernet can succeed synchronously.
        svc.arp.insert(
            Ipv4Addr([192, 0, 2, 11]),
            MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]),
            0,
        );
        svc
    }

    /// Wrap an IP packet in an Ethernet frame addressed to our MAC.
    fn wrap_eth(payload: &[u8]) -> Vec<u8> {
        use nexacore_types::net::EtherType;
        let mut frame = alloc::vec![0u8; EthernetHeader::HEADER_LEN + payload.len()];
        let eth = EthernetHeader {
            dst: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            src: MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]),
            ether_type: EtherType::IPV4,
        };
        eth.serialize(&mut frame[..EthernetHeader::HEADER_LEN]);
        if let Some(dst) = frame.get_mut(EthernetHeader::HEADER_LEN..) {
            dst.copy_from_slice(payload);
        }
        frame
    }

    /// Integration test: Connect to 192.0.2.11:11434, feed a synthetic
    /// SYN-ACK via `handle_frame`, assert the TCB reaches ESTABLISHED, then
    /// feed a data segment and assert Recv returns the buffered bytes.
    #[test]
    fn m0_connect_syn_ack_establishes_and_recv_returns_data() {
        use nexacore_types::net::{IpProtocol, TcpFlags, TcpHeader};

        use crate::{
            ip::build_ipv4_packet,
            tcp::{TcpState, build_tcp_segment},
        };

        let mut svc = make_m0_service();

        // Step 1: Socket + Connect → service sends SYN, records state.
        let h_resp = svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        });
        let handle = match h_resp {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {:?}", other),
        };

        let connect_resp = svc.handle_socket_request(SocketRequest::Connect {
            handle,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 11],
                port: 11434,
            },
        });
        // FU3: Connect is now DEFERRED — it returns Pending, not Ok, until the
        // handshake completes. The real Ok is emitted from handle_frame below.
        assert!(
            matches!(connect_resp, SocketResponse::Pending),
            "Connect should defer (Pending) until ESTABLISHED: {connect_resp:?}"
        );

        // Retrieve the ephemeral port assigned to this connection.
        let key = *svc
            .socket_state
            .get(&handle.0)
            .expect("socket_state must contain key after Connect");
        let (local_addr, remote_addr) = key;

        // Verify real 4-tuple — NOT loopback.
        assert_eq!(
            local_addr.ip,
            [192, 0, 2, 50],
            "local IP must be 192.0.2.50 (not loopback)"
        );
        assert_eq!(
            remote_addr.ip,
            [192, 0, 2, 11],
            "remote IP must be 192.0.2.11"
        );
        assert_eq!(remote_addr.port, 11434, "remote port must be 11434");
        let ephemeral_port = local_addr.port;
        assert!(
            ephemeral_port >= EPHEMERAL_PORT_START,
            "ephemeral port must be in IANA range"
        );

        // Retrieve the ISS sent in the SYN so we can build a valid SYN-ACK.
        let tcb = svc
            .tcp
            .conn_get(&key)
            .expect("TCB must exist after Connect");
        let client_iss = tcb.iss;
        assert_eq!(tcb.state, TcpState::SynSent);

        // Step 2: Feed a synthetic SYN-ACK from 192.0.2.11:11434
        // → 192.0.2.50:<ephemeral>.
        let server_iss = 0xABCD_1234_u32;
        let syn_ack_hdr = TcpHeader {
            src_port: 11434,
            dst_port: ephemeral_port,
            seq_num: server_iss,
            ack_num: client_iss.wrapping_add(1),
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        // Build the full Ethernet frame carrying the SYN-ACK.
        let syn_ack_tcp_bytes = {
            let mut buf = alloc::vec![0u8; TcpHeader::HEADER_LEN_MIN];
            let _ = syn_ack_hdr.serialize(&mut buf);
            buf
        };
        let syn_ack_ip = build_ipv4_packet(
            Ipv4Addr([192, 0, 2, 11]),
            Ipv4Addr([192, 0, 2, 50]),
            IpProtocol::TCP,
            64,
            1,
            &syn_ack_tcp_bytes,
        );
        let syn_ack_frame = wrap_eth(&syn_ack_ip);
        let out = svc.handle_frame(0, &syn_ack_frame, 0);

        // handle_frame should emit at least one SendFrame (the ACK to the SYN-ACK).
        assert!(
            out.iter()
                .any(|o| matches!(o, ServiceOutput::SendFrame { .. })),
            "expected ACK frame after SYN-ACK, got {out:?}"
        );

        // FU3: the deferred Connect reply (Ok(0)) must now be released, so the
        // blocking caller unblocks only once the connection is ESTABLISHED.
        assert!(
            out.iter()
                .any(|o| matches!(o, ServiceOutput::SocketResponse(SocketResponse::Ok(0)))),
            "expected deferred Connect Ok(0) after SYN-ACK, got {out:?}"
        );

        // TCB state must now be ESTABLISHED.
        let tcb = svc
            .tcp
            .conn_get(&key)
            .expect("TCB must still exist after SYN-ACK");
        assert_eq!(
            tcb.state,
            TcpState::Established,
            "TCB must be ESTABLISHED after SYN-ACK"
        );

        // Step 3: Feed a synthetic data segment from server → client.
        let data_payload = b"HTTP/1.1 200 OK\r\n";
        let data_seg = build_tcp_segment(
            Ipv4Addr([192, 0, 2, 11]),
            Ipv4Addr([192, 0, 2, 50]),
            11434,
            ephemeral_port,
            server_iss.wrapping_add(1), // seq after SYN
            client_iss.wrapping_add(1), // ack the SYN
            TcpFlags::ACK | TcpFlags::PSH,
            65535,
            data_payload,
        );
        let data_frame = wrap_eth(&data_seg);
        let out2 = svc.handle_frame(0, &data_frame, 0);

        // An ACK for the data should be sent.
        assert!(
            out2.iter()
                .any(|o| matches!(o, ServiceOutput::SendFrame { .. })),
            "expected ACK for data segment"
        );

        // Step 4: Recv should return the buffered data bytes.
        let recv_resp = svc.handle_socket_request(SocketRequest::Recv {
            handle,
            max_len: 256,
            flags: 0,
        });
        match recv_resp {
            SocketResponse::Data(bytes) => {
                assert_eq!(
                    bytes, data_payload,
                    "Recv must return the exact data bytes from the data segment"
                );
            }
            other => panic!("expected SocketResponse::Data, got {:?}", other),
        }
    }

    /// TASK-05 integration: once ESTABLISHED, `Send` must emit the request
    /// bytes as a PSH|ACK frame on `pending_tx` (the wire path), the peer's
    /// ACK must drain the retransmit queue, and a subsequent data segment
    /// (the HTTP response) must be drained by `Recv`.
    ///
    /// This is the host-side proof of the full
    /// `NetSend → wire → NetRecv` half of the M0 E2E chain; before TASK-05
    /// `tcp.send` only buffered bytes that nothing drained, so the GET
    /// request silently never reached the wire.
    #[test]
    #[allow(clippy::too_many_lines, reason = "full E2E sequence in one test")]
    fn m0_send_emits_http_request_frame_and_recv_drains_response() {
        use nexacore_types::net::{TcpFlags, TcpHeader};

        use crate::tcp::{TcpState, build_tcp_segment};

        let mut svc = make_m0_service();

        // ── Reach ESTABLISHED (same flow as the connect test above) ──────
        let SocketResponse::Handle(handle) = svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        }) else {
            panic!("expected Handle");
        };
        let _ = svc.handle_socket_request(SocketRequest::Connect {
            handle,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 11],
                port: 11434,
            },
        });
        let key = *svc.socket_state.get(&handle.0).expect("key after Connect");
        let (local_addr, _) = key;
        let ephemeral_port = local_addr.port;
        let client_iss = svc.tcp.conn_get(&key).expect("TCB").iss;

        let server_iss = 0x5151_0000_u32;
        let syn_ack_hdr = TcpHeader {
            src_port: 11434,
            dst_port: ephemeral_port,
            seq_num: server_iss,
            ack_num: client_iss.wrapping_add(1),
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let syn_ack_tcp_bytes = {
            let mut buf = alloc::vec![0u8; TcpHeader::HEADER_LEN_MIN];
            let _ = syn_ack_hdr.serialize(&mut buf);
            buf
        };
        let syn_ack_ip = build_ipv4_packet(
            Ipv4Addr([192, 0, 2, 11]),
            Ipv4Addr([192, 0, 2, 50]),
            IpProtocol::TCP,
            64,
            1,
            &syn_ack_tcp_bytes,
        );
        let _ = svc.handle_frame(0, &wrap_eth(&syn_ack_ip), 0);
        assert_eq!(
            svc.tcp.conn_get(&key).expect("TCB").state,
            TcpState::Established
        );
        // Clear any frames queued so far (SYN/ARP) so the next drain
        // observes ONLY the Send output.
        let _ = svc.take_pending_tx();

        // ── Step 1: Send the HTTP request ────────────────────────────────
        let request: &[u8] = b"GET /api/tags HTTP/1.1\r\nHost: 192.0.2.11:11434\r\n\r\n";
        let send_resp = svc.handle_socket_request(SocketRequest::Send {
            handle,
            data: request.to_vec(),
            flags: 0,
        });
        assert!(
            matches!(send_resp, SocketResponse::Ok(n) if n == request.len() as u64),
            "Send must accept the full request: {send_resp:?}"
        );

        // The request must be on the wire path NOW (pending_tx), as a
        // PSH|ACK TCP segment carrying exactly the request bytes.
        let pending = svc.take_pending_tx();
        let frames: Vec<&Vec<u8>> = pending
            .iter()
            .filter_map(|o| match o {
                ServiceOutput::SendFrame { data, .. } => Some(data),
                ServiceOutput::SocketResponse(_) => None,
            })
            .collect();
        assert_eq!(frames.len(), 1, "expected exactly one data frame");
        // Ethernet (14) → IPv4 → TCP.
        let eth_payload = &frames[0][14..];
        let (ip_hdr, tcp_bytes) = crate::ip::parse_ipv4_packet(eth_payload).expect("IPv4");
        assert_eq!(ip_hdr.dst, Ipv4Addr([192, 0, 2, 11]));
        let (tcp_hdr, payload) = TcpHeader::parse(tcp_bytes).expect("TCP");
        assert_eq!(tcp_hdr.dst_port, 11434);
        assert_ne!(tcp_hdr.flags() & TcpFlags::PSH, 0);
        assert_eq!(payload, request, "wire payload must be the HTTP request");
        assert_eq!(tcp_hdr.seq_num, client_iss.wrapping_add(1));

        // ── Step 2: the server ACKs our data → retransmit queue drains ───
        #[allow(clippy::cast_possible_truncation, reason = "request len < 64 KiB")]
        let req_len_u32 = request.len() as u32;
        let ack_hdr = TcpHeader {
            src_port: 11434,
            dst_port: ephemeral_port,
            seq_num: server_iss.wrapping_add(1),
            ack_num: client_iss.wrapping_add(1).wrapping_add(req_len_u32),
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let ack_tcp_bytes = {
            let mut buf = alloc::vec![0u8; TcpHeader::HEADER_LEN_MIN];
            let _ = ack_hdr.serialize(&mut buf);
            buf
        };
        let ack_ip = build_ipv4_packet(
            Ipv4Addr([192, 0, 2, 11]),
            Ipv4Addr([192, 0, 2, 50]),
            IpProtocol::TCP,
            64,
            2,
            &ack_tcp_bytes,
        );
        let _ = svc.handle_frame(0, &wrap_eth(&ack_ip), 5);
        assert!(
            svc.tcp
                .conn_get(&key)
                .expect("TCB")
                .retransmit_queue
                .is_empty(),
            "peer ACK must drain the data retransmit queue"
        );

        // ── Step 3: the HTTP response arrives → Recv drains it ───────────
        let response: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"models\":[]}";
        let resp_seg = build_tcp_segment(
            Ipv4Addr([192, 0, 2, 11]),
            Ipv4Addr([192, 0, 2, 50]),
            11434,
            ephemeral_port,
            server_iss.wrapping_add(1),
            client_iss.wrapping_add(1).wrapping_add(req_len_u32),
            TcpFlags::ACK | TcpFlags::PSH,
            65535,
            response,
        );
        let out = svc.handle_frame(0, &wrap_eth(&resp_seg), 10);
        assert!(
            out.iter()
                .any(|o| matches!(o, ServiceOutput::SendFrame { .. })),
            "the response data must be ACKed"
        );
        let recv_resp = svc.handle_socket_request(SocketRequest::Recv {
            handle,
            max_len: 1024,
            flags: 0,
        });
        match recv_resp {
            SocketResponse::Data(bytes) => assert_eq!(bytes, response),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    /// Regression test: after Connect, the TCB key must be the real
    /// `(192.0.2.50:<ephemeral>, 192.0.2.11:11434)` and NOT the old
    /// loopback-derived key `(127.0.0.1:<handle>, 0.0.0.0:0)`.
    #[test]
    fn connect_4tuple_key_is_real_addresses_not_loopback() {
        let mut svc = make_m0_service();

        let h_resp = svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        });
        let handle = match h_resp {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {:?}", other),
        };

        let _ = svc.handle_socket_request(SocketRequest::Connect {
            handle,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 11],
                port: 11434,
            },
        });

        let (local, remote) = *svc
            .socket_state
            .get(&handle.0)
            .expect("socket_state must contain key");

        // Real local IP must be the interface address, not loopback.
        assert_ne!(
            local.ip,
            [127, 0, 0, 1],
            "TCB local IP must NOT be loopback"
        );
        assert_eq!(local.ip, [192, 0, 2, 50], "TCB local IP must be 192.0.2.50");

        // Local port must be a valid ephemeral port, NOT the handle value.
        assert!(
            local.port >= EPHEMERAL_PORT_START,
            "TCB local port must be in ephemeral range, got {}",
            local.port
        );
        assert_ne!(
            u64::from(local.port),
            handle.0,
            "TCB local port must NOT equal the handle value"
        );

        // Remote must be exactly what was passed to Connect.
        assert_eq!(
            remote.ip,
            [192, 0, 2, 11],
            "TCB remote IP must be 192.0.2.11"
        );
        assert_eq!(remote.port, 11434, "TCB remote port must be 11434");

        // The old buggy key (loopback, handle-derived) must NOT exist in the table.
        let loopback_key = (
            SocketApiAddr {
                ip: [127, 0, 0, 1],
                port: handle.0 as u16,
            },
            SocketApiAddr {
                ip: [0, 0, 0, 0],
                port: 0,
            },
        );
        assert!(
            svc.tcp.conn_get(&loopback_key).is_none(),
            "no TCB should exist for the old loopback-derived key"
        );
    }

    /// Build an interface-only M0 service (eth0 192.0.2.50, no pre-seeded
    /// ARP). This faithfully reproduces the hardware boot state, where the ARP
    /// table starts empty and the next hop must be resolved on the wire.
    fn make_m0_service_no_arp() -> NetworkService {
        use nexacore_types::net::Cidr;
        let mut svc = NetworkService::new();
        svc.add_interface(InterfaceConfig {
            name: "eth0".into(),
            ip: Ipv4Addr([192, 0, 2, 50]),
            netmask: Cidr::new(Ipv4Addr([192, 0, 2, 0]), 24).unwrap(),
            mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            mtu: 1500,
        });
        svc
    }

    /// HARDWARE-FAITHFUL repro: Connect with an EMPTY ARP table (the real boot
    /// state). The SYN must be held by the ARP layer until the peer's MAC is
    /// resolved; an ARP request is emitted on `pending_tx`. Feeding the ARP
    /// reply must drain the held SYN onto the wire. Feeding the resulting
    /// SYN-ACK must drive the TCB to ESTABLISHED and emit an ACK — NOT an RST.
    ///
    /// This is the path the existing `m0_connect_syn_ack_*` test SKIPS (it
    /// pre-seeds ARP), and the suspected source of the on-wire RST observed on
    /// hardware.
    #[test]
    fn m0_arp_miss_connect_drains_syn_then_synack_establishes() {
        use nexacore_types::net::{ArpOperation, ArpPacket, IpProtocol, TcpFlags, TcpHeader};

        use crate::{ip::parse_ipv4_packet, tcp::TcpState};

        let mut svc = make_m0_service_no_arp();

        // --- Step 1: Socket + Connect (ARP table empty → ARP miss). ---
        let handle = match svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        }) {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {other:?}"),
        };

        let connect_resp = svc.handle_socket_request(SocketRequest::Connect {
            handle,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 11],
                port: 11434,
            },
        });
        // FU3: deferred until ESTABLISHED.
        assert!(
            matches!(connect_resp, SocketResponse::Pending),
            "Connect should defer (Pending): {connect_resp:?}"
        );

        let key = *svc
            .socket_state
            .get(&handle.0)
            .expect("socket_state must contain key after Connect");
        let (local_addr, _remote_addr) = key;
        let ephemeral_port = local_addr.port;
        let client_iss = svc.tcp.conn_get(&key).expect("TCB after Connect").iss;
        assert_eq!(
            svc.tcp.conn_get(&key).unwrap().state,
            TcpState::SynSent,
            "TCB must be SynSent after Connect"
        );

        // --- Step 2: pending_tx must hold the ARP REQUEST (the SYN is held by
        // the ARP layer, NOT yet on the wire). ---
        let pending = svc.take_pending_tx();
        assert_eq!(
            pending.len(),
            1,
            "expected exactly one pending frame (the ARP request), got {}",
            pending.len()
        );
        let arp_req_frame = match &pending[0] {
            ServiceOutput::SendFrame { data, .. } => data.clone(),
            other @ ServiceOutput::SocketResponse(_) => {
                panic!("expected SendFrame (ARP request), got {other:?}")
            }
        };
        let (arp_eth, arp_payload) =
            EthernetHeader::parse(&arp_req_frame).expect("parse ARP request eth");
        assert_eq!(arp_eth.ether_type, EtherType::ARP, "must be an ARP frame");
        let arp_req = ArpPacket::parse(arp_payload).expect("parse ARP request");
        assert_eq!(arp_req.operation, ArpOperation::REQUEST);
        assert_eq!(
            arp_req.target_ip,
            Ipv4Addr([192, 0, 2, 11]),
            "ARP request must target the peer"
        );

        // --- Step 3: Feed the ARP REPLY. This must drain the held SYN. ---
        let reply = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            operation: ArpOperation::REPLY,
            sender_mac: MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]),
            sender_ip: Ipv4Addr([192, 0, 2, 11]),
            target_mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            target_ip: Ipv4Addr([192, 0, 2, 50]),
        };
        let mut arp_reply_payload = alloc::vec![0u8; ArpPacket::PACKET_LEN];
        reply.serialize(&mut arp_reply_payload);
        let arp_reply_frame = {
            let mut f = alloc::vec![0u8; EthernetHeader::HEADER_LEN + ArpPacket::PACKET_LEN];
            let eth = EthernetHeader {
                dst: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
                src: MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]),
                ether_type: EtherType::ARP,
            };
            eth.serialize(&mut f[..EthernetHeader::HEADER_LEN]);
            f[EthernetHeader::HEADER_LEN..].copy_from_slice(&arp_reply_payload);
            f
        };
        let arp_out = svc.handle_frame(0, &arp_reply_frame, 0);

        // The drained SYN must now appear as a SendFrame.
        let syn_frame = arp_out
            .iter()
            .find_map(|o| match o {
                ServiceOutput::SendFrame { data, .. } => Some(data.clone()),
                ServiceOutput::SocketResponse { .. } => None,
            })
            .expect("ARP reply must drain the held SYN as a SendFrame");
        // Verify it is the SYN (IPv4/TCP, SYN flag, our 4-tuple, seq=client_iss).
        let (_syn_eth, syn_ip_pl) = EthernetHeader::parse(&syn_frame).expect("parse SYN eth");
        let (syn_ip, syn_tcp_bytes) = parse_ipv4_packet(syn_ip_pl).expect("parse SYN ipv4");
        assert_eq!(syn_ip.protocol, IpProtocol::TCP);
        let (syn_tcp, _) = TcpHeader::parse(syn_tcp_bytes).expect("parse SYN tcp");
        assert_eq!(
            syn_tcp.flags() & TcpFlags::SYN,
            TcpFlags::SYN,
            "drained frame must be a SYN"
        );
        assert_eq!(syn_tcp.flags() & TcpFlags::ACK, 0, "SYN must not carry ACK");
        assert_eq!(syn_tcp.seq_num, client_iss, "SYN seq must be client ISS");
        assert_eq!(syn_tcp.src_port, ephemeral_port);
        assert_eq!(syn_tcp.dst_port, 11434);

        // --- Step 4: Feed the SYN-ACK. Must establish + ACK, NOT RST. ---
        let server_iss = 0xABCD_1234_u32;
        let syn_ack_hdr = TcpHeader {
            src_port: 11434,
            dst_port: ephemeral_port,
            seq_num: server_iss,
            ack_num: client_iss.wrapping_add(1),
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let syn_ack_tcp_bytes = {
            let mut b = alloc::vec![0u8; TcpHeader::HEADER_LEN_MIN];
            let _ = syn_ack_hdr.serialize(&mut b);
            b
        };
        let syn_ack_ip = crate::ip::build_ipv4_packet(
            Ipv4Addr([192, 0, 2, 11]),
            Ipv4Addr([192, 0, 2, 50]),
            IpProtocol::TCP,
            64,
            1,
            &syn_ack_tcp_bytes,
        );
        let syn_ack_frame = {
            let mut f = alloc::vec![0u8; EthernetHeader::HEADER_LEN + syn_ack_ip.len()];
            let eth = EthernetHeader {
                dst: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
                src: MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]),
                ether_type: EtherType::IPV4,
            };
            eth.serialize(&mut f[..EthernetHeader::HEADER_LEN]);
            f[EthernetHeader::HEADER_LEN..].copy_from_slice(&syn_ack_ip);
            f
        };
        let out = svc.handle_frame(0, &syn_ack_frame, 0);

        // Inspect what we emitted in response to the SYN-ACK: ACK or RST?
        let mut saw_rst = false;
        let mut saw_ack = false;
        for o in &out {
            if let ServiceOutput::SendFrame { data, .. } = o {
                if let Some((_, ip_pl)) = EthernetHeader::parse(data) {
                    if let Some((ip, tcp_bytes)) = parse_ipv4_packet(ip_pl) {
                        if ip.protocol == IpProtocol::TCP {
                            if let Some((tcp, _)) = TcpHeader::parse(tcp_bytes) {
                                if tcp.flags() & TcpFlags::RST != 0 {
                                    saw_rst = true;
                                }
                                if tcp.flags() & TcpFlags::ACK != 0
                                    && tcp.flags() & TcpFlags::RST == 0
                                {
                                    saw_ack = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        let final_state = svc.tcp.conn_get(&key).map(|t| t.state);
        assert!(
            !saw_rst,
            "REGRESSION: nexacore-net emitted an RST in response to the SYN-ACK \
             (ARP-miss path). final_state={final_state:?}, outputs={out:?}"
        );
        assert!(
            saw_ack,
            "expected an ACK in response to the SYN-ACK, got {out:?}"
        );
        assert_eq!(
            final_state,
            Some(TcpState::Established),
            "TCB must be ESTABLISHED after the SYN-ACK (ARP-miss path)"
        );

        // FU3: the deferred Connect reply must be released now (truthful
        // NetConnect: unblock only at ESTABLISHED).
        assert!(
            out.iter()
                .any(|o| matches!(o, ServiceOutput::SocketResponse(SocketResponse::Ok(0)))),
            "expected deferred Connect Ok(0) after SYN-ACK, got {out:?}"
        );
        // The pending-connect slot must be cleared once the reply is released.
        assert!(
            svc.pending_connect.is_none(),
            "pending_connect must be cleared after the deferred reply"
        );
    }

    /// FU3: a second concurrent Connect while one is still pending must be
    /// rejected with `WouldBlock` (only one blocking relay caller at a time).
    #[test]
    fn m0_second_concurrent_connect_is_rejected() {
        let mut svc = make_m0_service();

        let h1 = match svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        }) {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {other:?}"),
        };
        let r1 = svc.handle_socket_request(SocketRequest::Connect {
            handle: h1,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 11],
                port: 11434,
            },
        });
        assert!(
            matches!(r1, SocketResponse::Pending),
            "first Connect defers"
        );

        let h2 = match svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        }) {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {other:?}"),
        };
        let r2 = svc.handle_socket_request(SocketRequest::Connect {
            handle: h2,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 11],
                port: 11435,
            },
        });
        assert!(
            matches!(r2, SocketResponse::Error(NetError::WouldBlock)),
            "second concurrent Connect must be rejected with WouldBlock, got {r2:?}"
        );
    }

    #[test]
    fn m0_connect_times_out_to_etimedout_when_no_syn_ack() {
        // WS2-02.1: a Connect whose SYN is never answered must not hang. The
        // SYN-retransmit machinery (WS2-02.3) times the handshake out after
        // MAX_RETRANSMIT, and the service maps the resulting ConnectionClosed
        // for the still-pending Connect to NetError::TimedOut (ETIMEDOUT).
        use crate::tcp::MAX_RETRANSMIT;

        let mut svc = make_m0_service();
        let handle = match svc.handle_socket_request(SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        }) {
            SocketResponse::Handle(h) => h,
            other => panic!("expected Handle, got {other:?}"),
        };
        let connect_resp = svc.handle_socket_request(SocketRequest::Connect {
            handle,
            addr: SocketApiAddr {
                ip: [192, 0, 2, 11],
                port: 11434,
            },
        });
        assert!(matches!(connect_resp, SocketResponse::Pending));
        assert!(svc.pending_connect.is_some(), "connect must be pending");

        // No SYN-ACK ever arrives. Drive RTO expiries (now increments dwarf the
        // 60 s RTO clamp, so each tick is one expiry) until the connect times out.
        let mut timed_out = false;
        for i in 1..=(u64::from(MAX_RETRANSMIT) + 2) {
            let outs = svc.tick(i * 100_000);
            if outs.iter().any(|o| {
                matches!(
                    o,
                    ServiceOutput::SocketResponse(SocketResponse::Error(NetError::TimedOut))
                )
            }) {
                timed_out = true;
            }
        }
        assert!(
            timed_out,
            "connect must surface NetError::TimedOut on SYN timeout"
        );
        assert!(
            svc.pending_connect.is_none(),
            "pending_connect must be cleared after the timeout"
        );
    }
}

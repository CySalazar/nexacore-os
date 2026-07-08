//! TCP state machine (N2.5).
//!
//! Implements RFC 793 TCP including:
//! - 3-way handshake (active and passive open)
//! - Bidirectional data transfer with send/receive buffers
//! - Connection teardown (FIN/FIN-ACK exchange)
//! - RST handling
//! - Retransmission with exponential backoff (up to [`MAX_RETRANSMIT`] attempts)
//! - TCP Reno congestion control (slow start, congestion avoidance, fast retransmit)
//!
//! ## Architecture
//!
//! [`TcpSocketTable`] is the top-level data structure.  Each established
//! connection is a [`TcpControlBlock`] keyed by
//! `(local_addr, remote_addr)` — the [`TcpConnectionKey`].
//!
//! The state machine is driven entirely by [`TcpSocketTable::handle_segment`],
//! which returns a `Vec<TcpOutput>` describing what the service loop needs to
//! do (send a segment, notify the application, etc.).
//!
//! ## Sequence number arithmetic
//!
//! All comparisons use wrapping arithmetic.  Helper functions `seq_lt` and
//! `seq_le` encapsulate this to prevent off-by-one or comparison errors.
//!
//! ## Limitations (v0.2)
//!
//! - No SACK, ECN, or timestamp options.
//! - Fragment reassembly is not performed; out-of-order segments within the
//!   window are dropped (a retransmit from the peer will deliver them).
//! - `TIME_WAIT` is enforced for 2 × MSL = 120 seconds but the cleanup
//!   happens via `tick`, not via a real timer wheel.

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};

use nexacore_types::{
    net::{IpProtocol, Ipv4Addr, TcpFlags, TcpHeader, TcpPseudoHeader},
    socket::{NetError, SocketApiAddr},
};

use crate::ip::build_ipv4_packet;

// =============================================================================
// Constants
// =============================================================================

/// Default MSS (Maximum Segment Size) for `IPv4` over Ethernet.
///
/// 1460 = MTU (1500) - `IPv4` header (20) - TCP header (20).
pub const DEFAULT_MSS: u16 = 1460;

/// Initial retransmission timeout in milliseconds.
pub const RTO_INITIAL_MS: u64 = 1_000;

/// Maximum number of retransmission attempts before resetting the connection.
pub const MAX_RETRANSMIT: u8 = 5;

/// `TIME_WAIT` duration in milliseconds (2 × MSL, MSL = 60 s per RFC 793).
pub const TIME_WAIT_MS: u64 = 120_000;

/// Initial slow-start threshold in bytes.
pub const INITIAL_SSTHRESH: u32 = 65_535;

/// Initial congestion window size (RFC 5681: min(4*SMSS, max(2*SMSS, 4380))).
pub const INITIAL_CWND: u32 = 4 * DEFAULT_MSS as u32;

// =============================================================================
// Types
// =============================================================================

/// All possible states of a TCP connection (RFC 793 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    /// No connection exists.
    Closed,
    /// Waiting for a connection request from any remote TCP.
    Listen,
    /// SYN has been sent; waiting for SYN+ACK.
    SynSent,
    /// SYN received, SYN+ACK sent; waiting for ACK.
    SynReceived,
    /// Connection is established; data can flow in both directions.
    Established,
    /// FIN sent; waiting for FIN+ACK or FIN from the other end.
    FinWait1,
    /// FIN+ACK received; waiting for FIN from the other end.
    FinWait2,
    /// Received FIN from remote; application has not yet sent FIN.
    CloseWait,
    /// Both sides have sent FIN simultaneously; waiting for ACKs.
    Closing,
    /// FIN sent after entering `CloseWait`; waiting for final ACK.
    LastAck,
    /// Waiting for the 2*MSL timer before fully closing.
    TimeWait,
}

/// A single entry in the retransmit queue.
#[derive(Debug, Clone)]
pub struct RetransmitEntry {
    /// Sequence number of the first byte of `data`.
    pub seq: u32,
    /// Bytes to (re)transmit.
    pub data: Vec<u8>,
    /// Monotonic timestamp (ms) when this segment was last sent.
    pub sent_at: u64,
    /// Number of times this segment has been retransmitted (0 = first send).
    pub retransmit_count: u8,
}

/// TCP Control Block — all state for one TCP connection.
#[derive(Debug)]
pub struct TcpControlBlock {
    /// Local endpoint.
    pub local: SocketApiAddr,
    /// Remote endpoint.
    pub remote: SocketApiAddr,
    /// Current connection state.
    pub state: TcpState,

    // Send sequence space (RFC 793 §3.2).
    /// Oldest unacknowledged sequence number.
    pub snd_una: u32,
    /// Next sequence number to use when sending.
    pub snd_nxt: u32,
    /// Receive window advertised by the remote peer.
    pub snd_wnd: u16,
    /// Initial send sequence number.
    pub iss: u32,

    // Receive sequence space.
    /// Next expected sequence number from the remote.
    pub rcv_nxt: u32,
    /// Receive window we advertise.
    pub rcv_wnd: u16,
    /// Initial receive sequence number.
    pub irs: u32,

    // Application buffers.
    //
    // NOTE (TASK-05): there is deliberately NO `send_buffer`. `send()` emits
    // segments immediately and the retransmit queue is the only TX-side
    // store — a buffer nothing drains is how application data silently never
    // reached the wire before TASK-05.
    /// Data received and ready for the application.
    pub recv_buffer: VecDeque<u8>,

    // Retransmission state.
    /// Segments awaiting acknowledgement.
    pub retransmit_queue: Vec<RetransmitEntry>,
    /// Current retransmission timeout (ms).
    pub rto_ms: u64,
    /// Smoothed round-trip time (ms).
    pub srtt_ms: u64,
    /// RTT variance (ms).
    pub rttvar_ms: u64,

    // Congestion control (TCP Reno).
    /// Congestion window (bytes).
    pub cwnd: u32,
    /// Slow-start threshold (bytes).
    pub ssthresh: u32,
    /// Maximum segment size negotiated with the peer.
    pub mss: u16,
    /// Number of duplicate ACKs received consecutively.
    pub dup_ack_count: u8,

    // Window scaling (RFC 7323).
    /// Shift applied to the peer's advertised window (0 = scaling not
    /// negotiated). Used when computing how much we may send.
    pub snd_wscale: u8,
    /// Shift applied to our own advertised window (0 = scaling not negotiated).
    pub rcv_wscale: u8,

    // TIME_WAIT timestamp.
    /// Time (ms) when this connection entered `TimeWait`; 0 means not in it.
    pub(crate) time_wait_started_ms: u64,
}

// =============================================================================
// TCP options / window scaling (WS4-01.2, RFC 7323)
// =============================================================================

/// TCP option kind: End of Option List.
pub const TCP_OPT_END: u8 = 0;
/// TCP option kind: No-Operation (padding).
pub const TCP_OPT_NOP: u8 = 1;
/// TCP option kind: Maximum Segment Size.
pub const TCP_OPT_MSS: u8 = 2;
/// TCP option kind: Window Scale (RFC 7323 §2.2).
pub const TCP_OPT_WSCALE: u8 = 3;

/// Maximum permitted window-scale shift count (RFC 7323 §2.2).
pub const MAX_WINDOW_SCALE: u8 = 14;

/// A decoded TCP header option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption {
    /// Maximum Segment Size.
    Mss(u16),
    /// Window Scale shift count.
    WindowScale(u8),
    /// An option kind this stack does not interpret.
    Unknown(u8),
}

/// Parse the options area of a TCP header into a list of options.
///
/// Tolerant per RFC 793: `NOP` (kind 1) is skipped, `END` (kind 0) stops the
/// walk, and a length that would run past the end stops the walk (rather than
/// panicking) so a malformed peer cannot cause an over-read.
#[must_use]
pub fn parse_tcp_options(bytes: &[u8]) -> Vec<TcpOption> {
    let mut options = Vec::new();
    let mut i = 0usize;
    while let Some(&kind) = bytes.get(i) {
        match kind {
            TCP_OPT_END => break,
            TCP_OPT_NOP => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(&len) = bytes.get(i + 1) else { break };
        let len = len as usize;
        if len < 2 || i + len > bytes.len() {
            break; // malformed length
        }
        match kind {
            TCP_OPT_MSS if len == 4 => {
                if let (Some(&hi), Some(&lo)) = (bytes.get(i + 2), bytes.get(i + 3)) {
                    options.push(TcpOption::Mss(u16::from_be_bytes([hi, lo])));
                }
            }
            TCP_OPT_WSCALE if len == 3 => {
                if let Some(&shift) = bytes.get(i + 2) {
                    options.push(TcpOption::WindowScale(shift.min(MAX_WINDOW_SCALE)));
                }
            }
            _ => options.push(TcpOption::Unknown(kind)),
        }
        i += len;
    }
    options
}

/// Encode a Window Scale option (kind 3, length 3), clamping the shift to
/// [`MAX_WINDOW_SCALE`].
#[must_use]
pub fn encode_window_scale(shift: u8) -> [u8; 3] {
    [TCP_OPT_WSCALE, 3, shift.min(MAX_WINDOW_SCALE)]
}

/// The effective window: the 16-bit header field left-shifted by `shift`
/// (saturating; RFC 7323 caps the shift at 14 so this never overflows `u32`).
#[must_use]
pub fn scaled_window(window: u16, shift: u8) -> u32 {
    u32::from(window) << u32::from(shift.min(MAX_WINDOW_SCALE))
}

/// The negotiated `(rcv_wscale, snd_wscale)` shifts. Window scaling is enabled
/// only if the peer also advertised a Window Scale option; otherwise both sides
/// use shift 0 (RFC 7323 §2.2).
#[must_use]
pub fn negotiated_scales(local_shift: u8, peer_shift: Option<u8>) -> (u8, u8) {
    peer_shift.map_or((0, 0), |peer| {
        (
            local_shift.min(MAX_WINDOW_SCALE),
            peer.min(MAX_WINDOW_SCALE),
        )
    })
}

/// A 2-tuple identifying a unique TCP connection.
///
/// Each [`SocketApiAddr`] is encoded as a `u64` (`[ip[0], ip[1], ip[2], ip[3],
/// port_hi, port_lo, 0, 0]` in big-endian order) so that the pair can serve as
/// a [`BTreeMap`] key (since [`SocketApiAddr`] itself does not implement
/// [`Ord`]).
///
/// Use `encode_addr_key` and `decode_addr_key` to convert.
pub type TcpConnectionKey = (SocketApiAddr, SocketApiAddr);

/// Encode a [`SocketApiAddr`] as a sortable `u64`.
#[inline]
fn encode_addr_key(addr: SocketApiAddr) -> u64 {
    let [a, b, c, d] = addr.ip;
    let [ph, pl] = addr.port.to_be_bytes();
    u64::from_be_bytes([a, b, c, d, ph, pl, 0, 0])
}

/// Encode a [`TcpConnectionKey`] as a `(u64, u64)` pair usable in [`BTreeMap`].
#[inline]
fn encode_conn_key(key: &TcpConnectionKey) -> (u64, u64) {
    (encode_addr_key(key.0), encode_addr_key(key.1))
}

/// Queue of connections waiting to be accepted on a listening port.
#[derive(Debug)]
pub struct ListenQueue {
    /// Completed-handshake connections ready to be returned from `accept`.
    pub backlog: VecDeque<TcpControlBlock>,
    /// Maximum number of connections we will queue.
    pub max_backlog: usize,
}

/// Events the TCP stack needs the service loop to act on.
#[derive(Debug)]
pub enum TcpOutput {
    /// Send this raw Ethernet frame (already wrapped in `IPv4`).
    SendSegment {
        /// Complete IP packet bytes.
        data: Vec<u8>,
        /// Destination `IPv4` address (for routing lookup).
        dst_ip: Ipv4Addr,
    },
    /// A connection is now fully established.
    ConnectionEstablished {
        /// Connection key.
        key: TcpConnectionKey,
    },
    /// Data is available in the receive buffer.
    DataReceived {
        /// Connection key.
        key: TcpConnectionKey,
    },
    /// The connection has been closed cleanly.
    ConnectionClosed {
        /// Connection key.
        key: TcpConnectionKey,
    },
    /// A connection attempt was refused by the remote end.
    ConnectionRefused {
        /// Connection key.
        key: TcpConnectionKey,
    },
}

// =============================================================================
// Sequence-number helpers
// =============================================================================

/// Returns `true` if sequence number `a` is strictly less than `b` in the
/// modular sequence number space (RFC 793 §3.3).
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    // Wrapping difference: if (b - a) < 2^31 and b != a, a < b.
    (b.wrapping_sub(a) < 0x8000_0000) && (a != b)
}

/// Returns `true` if sequence number `a` is less than or equal to `b`.
#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

// =============================================================================
// TcpControlBlock construction
// =============================================================================

impl TcpControlBlock {
    /// Construct an initial TCB in the `SynSent` state (active open).
    fn new_syn_sent(local: SocketApiAddr, remote: SocketApiAddr, iss: u32) -> Self {
        Self {
            local,
            remote,
            state: TcpState::SynSent,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1), // SYN consumes one sequence number
            snd_wnd: 0,
            iss,
            rcv_nxt: 0,
            rcv_wnd: 65_535,
            irs: 0,
            recv_buffer: VecDeque::new(),
            retransmit_queue: Vec::new(),
            rto_ms: RTO_INITIAL_MS,
            srtt_ms: 0,
            rttvar_ms: 0,
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            mss: DEFAULT_MSS,
            dup_ack_count: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            time_wait_started_ms: 0,
        }
    }

    /// Construct a TCB in `SynReceived` state (passive open, after receiving
    /// SYN).
    // `irs` and `iss` names are RFC 793 §3.2 canonical abbreviations.
    #[allow(clippy::similar_names)]
    fn new_syn_received(local: SocketApiAddr, remote: SocketApiAddr, irs: u32, iss: u32) -> Self {
        Self {
            local,
            remote,
            state: TcpState::SynReceived,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: 65_535,
            iss,
            rcv_nxt: irs.wrapping_add(1), // SYN consumed
            rcv_wnd: 65_535,
            irs,
            recv_buffer: VecDeque::new(),
            retransmit_queue: Vec::new(),
            rto_ms: RTO_INITIAL_MS,
            srtt_ms: 0,
            rttvar_ms: 0,
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            mss: DEFAULT_MSS,
            dup_ack_count: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            time_wait_started_ms: 0,
        }
    }

    /// Record the negotiated window-scale shifts (WS4-01.2).
    ///
    /// `peer_shift` is the shift the peer advertised in its SYN/SYN-ACK (or
    /// `None` if it offered none, disabling scaling for both directions).
    pub fn apply_window_scale(&mut self, local_shift: u8, peer_shift: Option<u8>) {
        let (rcv, snd) = negotiated_scales(local_shift, peer_shift);
        self.rcv_wscale = rcv;
        self.snd_wscale = snd;
    }

    /// The peer's effective send window: the advertised `snd_wnd` scaled by the
    /// negotiated shift (RFC 7323).
    #[must_use]
    pub fn effective_send_window(&self) -> u32 {
        scaled_window(self.snd_wnd, self.snd_wscale)
    }

    /// Update SRTT and RTO using the Jacobson/Karels algorithm (RFC 6298).
    ///
    /// Not yet called in v0.2; reserved for timestamp-option RTT measurement.
    // Integer divisions here implement RFC 6298 Jacobson/Karels estimator
    // with alpha=1/8, beta=1/4. The truncation is intentional and standard.
    #[allow(dead_code, clippy::integer_division)]
    fn update_rtt(&mut self, sample_ms: u64) {
        if self.srtt_ms == 0 {
            // First sample.
            self.srtt_ms = sample_ms;
            self.rttvar_ms = sample_ms / 2;
        } else {
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
            // SRTT   = (1 - alpha) * SRTT   + alpha * R
            // Using alpha=1/8, beta=1/4 (RFC 6298).
            let diff = if self.srtt_ms > sample_ms {
                self.srtt_ms - sample_ms
            } else {
                sample_ms - self.srtt_ms
            };
            self.rttvar_ms = (3 * self.rttvar_ms + diff) / 4;
            self.srtt_ms = (7 * self.srtt_ms + sample_ms) / 8;
        }
        // RTO = SRTT + max(G, 4 * RTTVAR); G = clock granularity ≈ 1ms.
        self.rto_ms = self.srtt_ms + self.rttvar_ms.saturating_mul(4).max(1);
        // Clamp to [200ms, 60s].
        self.rto_ms = self.rto_ms.clamp(200, 60_000);
    }
}

// =============================================================================
// TcpSocketTable
// =============================================================================

/// The TCP socket layer: connection table, listeners, and the state machine.
///
/// Internally connections are stored in a `BTreeMap<(u64, u64), TcpControlBlock>` where
/// the key is the encoded `(local, remote)` pair (see `encode_conn_key`), because
/// [`SocketApiAddr`] does not implement [`Ord`].
///
/// # Examples
///
/// ```
/// use nexacore_net::tcp::{TcpSocketTable, TcpState};
/// use nexacore_types::socket::{NetError, SocketApiAddr};
///
/// let mut table = TcpSocketTable::new();
/// table.listen(80, 128).unwrap();
/// // Binding the same port twice is an error.
/// assert!(matches!(table.listen(80, 128), Err(NetError::AddrInUse)));
/// ```
#[derive(Debug, Default)]
pub struct TcpSocketTable {
    /// Active / half-open connections keyed by encoded (local, remote) pair.
    connections: BTreeMap<(u64, u64), TcpControlBlock>,
    /// Passive listening sockets keyed by local port.
    listeners: BTreeMap<u16, ListenQueue>,
    /// Monotonically increasing ISN counter (not cryptographic; good enough
    /// for a microkernel network stack, not exposed to the network).
    next_isn: u32,
    /// Most recent `now` observed by [`Self::tick`] / [`Self::handle_segment`].
    ///
    /// [`Self::send`] has no clock parameter (its caller, the socket-API
    /// dispatch, is clockless), so freshly emitted data segments stamp their
    /// [`RetransmitEntry::sent_at`] with this value. Worst case the stamp
    /// predates the actual send by one tick interval, which can trigger a
    /// single premature retransmission — the receiver de-duplicates by
    /// sequence number, so this is benign (TASK-05).
    last_now: u64,
}

impl TcpSocketTable {
    /// Construct an empty TCP socket table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections: BTreeMap::new(),
            listeners: BTreeMap::new(),
            next_isn: 0x0100_0001,
            last_now: 0,
        }
    }

    // -------------------------------------------------------------------------
    // Private connection map helpers (key encoding shim)
    // -------------------------------------------------------------------------

    /// Look up a connection by logical key (read-only).
    pub(crate) fn conn_get(&self, key: &TcpConnectionKey) -> Option<&TcpControlBlock> {
        self.connections.get(&encode_conn_key(key))
    }

    /// Look up a connection by logical key (mutable).
    pub(crate) fn conn_get_mut(&mut self, key: &TcpConnectionKey) -> Option<&mut TcpControlBlock> {
        self.connections.get_mut(&encode_conn_key(key))
    }

    fn conn_contains(&self, key: &TcpConnectionKey) -> bool {
        self.connections.contains_key(&encode_conn_key(key))
    }

    fn conn_insert(&mut self, key: TcpConnectionKey, tcb: TcpControlBlock) {
        self.connections.insert(encode_conn_key(&key), tcb);
    }

    fn conn_remove(&mut self, key: &TcpConnectionKey) -> Option<TcpControlBlock> {
        self.connections.remove(&encode_conn_key(key))
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// Initiate a connection to `remote` from `local`.
    ///
    /// Returns the [`TcpConnectionKey`] and the SYN segment to send (via
    /// `TcpOutput::SendSegment` — this method returns the key; the segment is
    /// emitted by the caller inspecting the connection state, or via
    /// [`Self::handle_segment`] when the SYN+ACK arrives).
    ///
    /// The initial SYN is added directly to `out`; the caller should transmit
    /// it.  See the service loop in [`crate::service`].
    ///
    /// # Errors
    ///
    /// Returns `Err(NetError::AddrInUse)` if the same (local, remote) pair
    /// already exists.
    pub fn connect(
        &mut self,
        local: SocketApiAddr,
        remote: SocketApiAddr,
        out: &mut Vec<TcpOutput>,
    ) -> Result<TcpConnectionKey, NetError> {
        let key = (local, remote);
        if self.conn_contains(&key) {
            return Err(NetError::AddrInUse);
        }
        let iss = self.next_isn();
        let mut tcb = TcpControlBlock::new_syn_sent(local, remote, iss);

        // Build the SYN segment.
        let syn_seg = build_tcp_segment(
            Ipv4Addr(local.ip),
            Ipv4Addr(remote.ip),
            local.port,
            remote.port,
            iss,
            0,
            TcpFlags::SYN,
            tcb.rcv_wnd,
            &[],
        );

        // Queue the SYN for retransmission (WS2-02.3 / DE-F-RXFLAKE). Before
        // this, an active open left the connection wedged in `SynSent`
        // forever if the SYN or its SYN-ACK was lost: nothing resent the SYN
        // and nothing timed the attempt out, so `nexacore-net connect` hung
        // silently. Queuing the SYN routes it through the existing
        // `tick_connection` retransmission path, which resends it every RTO
        // and, after `MAX_RETRANSMIT` attempts, resets the connection and
        // emits `TcpOutput::ConnectionClosed` — the deterministic connect
        // timeout the socket layer maps to `ETIMEDOUT`. The SYN occupies one
        // sequence number (`seq = iss`) and is cleared from the queue when the
        // SYN-ACK acknowledges it (see the `SynSent` handler).
        tcb.retransmit_queue.push(RetransmitEntry {
            seq: iss,
            data: syn_seg.clone(),
            sent_at: self.last_now,
            retransmit_count: 0,
        });
        out.push(TcpOutput::SendSegment {
            dst_ip: Ipv4Addr(remote.ip),
            data: syn_seg,
        });

        self.conn_insert(key, tcb);
        Ok(key)
    }

    /// Mark `port` as listening with the given `backlog`.
    ///
    /// # Errors
    ///
    /// Returns `Err(NetError::AddrInUse)` if a listener already exists on
    /// `port`.
    pub fn listen(&mut self, port: u16, backlog: usize) -> Result<(), NetError> {
        if self.listeners.contains_key(&port) {
            return Err(NetError::AddrInUse);
        }
        self.listeners.insert(
            port,
            ListenQueue {
                backlog: VecDeque::new(),
                max_backlog: backlog,
            },
        );
        Ok(())
    }

    /// Accept the next pending connection from the backlog queue for `port`.
    ///
    /// Returns `Some(key)` if a completed connection was in the queue,
    /// `None` if the queue is empty or `port` is not listening.
    pub fn accept(&mut self, port: u16) -> Option<TcpConnectionKey> {
        let queue = self.listeners.get_mut(&port)?;
        let tcb = queue.backlog.pop_front()?;
        let key = (tcb.local, tcb.remote);
        self.conn_insert(key, tcb);
        Some(key)
    }

    /// Transmit `data` on the connection `key`: build `PSH|ACK` segments
    /// (chunked by the connection MSS), advance `snd_nxt`, queue each
    /// segment for retransmission, and emit them as
    /// [`TcpOutput::SendSegment`]s on `out`.
    ///
    /// Before TASK-05 this function only buffered the bytes into the (now
    /// removed) `send_buffer`, which nothing ever drained — application
    /// data never reached the wire. Emission is now immediate and
    /// deterministic: the caller (the socket-API `Send` dispatch) forwards
    /// the produced segments to the NIC driver in the same service-loop
    /// iteration.
    ///
    /// Retransmit entries are stamped with the table's `last_now` (see the
    /// field docs for the one-tick staleness trade-off).
    ///
    /// # Errors
    ///
    /// - `NotConnected` — key does not exist.
    /// - `InvalidArgument` — connection is not in a state that allows sending.
    pub fn send(
        &mut self,
        key: &TcpConnectionKey,
        data: &[u8],
        out: &mut Vec<TcpOutput>,
    ) -> Result<usize, NetError> {
        let now = self.last_now;
        let tcb = self.conn_get_mut(key).ok_or(NetError::NotConnected)?;
        if !matches!(tcb.state, TcpState::Established | TcpState::CloseWait) {
            return Err(NetError::InvalidArgument);
        }
        let mss = usize::from(tcb.mss).max(1);
        for chunk in data.chunks(mss) {
            let chunk_seq = tcb.snd_nxt;
            let segment = build_tcp_segment(
                Ipv4Addr(tcb.local.ip),
                Ipv4Addr(tcb.remote.ip),
                tcb.local.port,
                tcb.remote.port,
                chunk_seq,
                tcb.rcv_nxt,
                TcpFlags::ACK | TcpFlags::PSH,
                tcb.rcv_wnd,
                chunk,
            );
            // Chunk length ≤ MSS ≤ 1460, so the u32 cast is exact.
            #[allow(clippy::cast_possible_truncation)]
            let chunk_len_u32 = chunk.len() as u32;
            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(chunk_len_u32);
            tcb.retransmit_queue.push(RetransmitEntry {
                seq: chunk_seq,
                data: chunk.to_vec(),
                sent_at: now,
                retransmit_count: 0,
            });
            out.push(TcpOutput::SendSegment {
                dst_ip: Ipv4Addr(tcb.remote.ip),
                data: segment,
            });
        }
        Ok(data.len())
    }

    /// Drain up to `buf.len()` bytes from the receive buffer of `key`.
    ///
    /// # Errors
    ///
    /// - `NotConnected` — key does not exist.
    pub fn recv(&mut self, key: &TcpConnectionKey, buf: &mut [u8]) -> Result<usize, NetError> {
        let tcb = self.conn_get_mut(key).ok_or(NetError::NotConnected)?;
        let n = buf.len().min(tcb.recv_buffer.len());
        for slot in buf.iter_mut().take(n) {
            if let Some(b) = tcb.recv_buffer.pop_front() {
                *slot = b;
            }
        }
        Ok(n)
    }

    /// Initiate connection closure by sending FIN.
    ///
    /// # Errors
    ///
    /// - `NotConnected` — key does not exist.
    pub fn close(
        &mut self,
        key: &TcpConnectionKey,
        out: &mut Vec<TcpOutput>,
    ) -> Result<(), NetError> {
        let tcb = self.conn_get_mut(key).ok_or(NetError::NotConnected)?;
        match tcb.state {
            TcpState::Established => {
                // Send FIN and transition to FinWait1.
                let fin_seg = build_tcp_segment(
                    Ipv4Addr(tcb.local.ip),
                    Ipv4Addr(tcb.remote.ip),
                    tcb.local.port,
                    tcb.remote.port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    TcpFlags::FIN | TcpFlags::ACK,
                    tcb.rcv_wnd,
                    &[],
                );
                out.push(TcpOutput::SendSegment {
                    dst_ip: Ipv4Addr(tcb.remote.ip),
                    data: fin_seg,
                });
                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                tcb.state = TcpState::FinWait1;
            }
            TcpState::CloseWait => {
                // Application done reading; send FIN and go to LastAck.
                let fin_seg = build_tcp_segment(
                    Ipv4Addr(tcb.local.ip),
                    Ipv4Addr(tcb.remote.ip),
                    tcb.local.port,
                    tcb.remote.port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    TcpFlags::FIN | TcpFlags::ACK,
                    tcb.rcv_wnd,
                    &[],
                );
                out.push(TcpOutput::SendSegment {
                    dst_ip: Ipv4Addr(tcb.remote.ip),
                    data: fin_seg,
                });
                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                tcb.state = TcpState::LastAck;
            }
            _ => {
                // Connection is already closing or closed.
            }
        }
        Ok(())
    }

    /// The main TCP segment processing function.
    ///
    /// Dispatches the incoming segment to the correct connection or listener
    /// and returns a list of actions for the service loop.
    pub fn handle_segment(
        &mut self,
        header: &TcpHeader,
        payload: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        now: u64,
    ) -> Vec<TcpOutput> {
        self.last_now = now;
        let mut out = Vec::new();
        let local = SocketApiAddr {
            ip: dst_ip.0,
            port: header.dst_port,
        };
        let remote = SocketApiAddr {
            ip: src_ip.0,
            port: header.src_port,
        };
        let key = (local, remote);

        // --- RST handling: always reset matching connections. ---
        if header.flags() & TcpFlags::RST != 0 {
            if self.conn_contains(&key) {
                self.conn_remove(&key);
                out.push(TcpOutput::ConnectionClosed { key });
            }
            return out;
        }

        // --- Deliver to an existing connection if found. ---
        if self.conn_contains(&key) {
            self.process_segment(&key, header, payload, now, &mut out);
            return out;
        }

        // --- Check if there's a listener on dst_port. ---
        if header.flags() & TcpFlags::SYN != 0 && header.flags() & TcpFlags::ACK == 0 {
            if let Some(queue) = self.listeners.get(&header.dst_port) {
                if queue.backlog.len() >= queue.max_backlog {
                    // Backlog full; send RST.
                    let rst = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        0,
                        header.seq_num.wrapping_add(1),
                        TcpFlags::RST | TcpFlags::ACK,
                        0,
                        &[],
                    );
                    out.push(TcpOutput::SendSegment {
                        dst_ip: src_ip,
                        data: rst,
                    });
                    return out;
                }

                let iss = self.next_isn();
                let tcb = TcpControlBlock::new_syn_received(local, remote, header.seq_num, iss);

                // Send SYN+ACK.
                let syn_ack = build_tcp_segment(
                    dst_ip,
                    src_ip,
                    header.dst_port,
                    header.src_port,
                    iss,
                    tcb.rcv_nxt,
                    TcpFlags::SYN | TcpFlags::ACK,
                    tcb.rcv_wnd,
                    &[],
                );
                out.push(TcpOutput::SendSegment {
                    dst_ip: src_ip,
                    data: syn_ack,
                });

                // Store in a temporary map; move to backlog when ACK arrives.
                let syn_key = (local, remote);
                self.conn_insert(syn_key, tcb);
                return out;
            }
        }

        // --- No listener / no connection: send RST. ---
        if header.flags() & TcpFlags::RST == 0 {
            let rst = if header.flags() & TcpFlags::ACK != 0 {
                build_tcp_segment(
                    dst_ip,
                    src_ip,
                    header.dst_port,
                    header.src_port,
                    header.ack_num,
                    0,
                    TcpFlags::RST,
                    0,
                    &[],
                )
            } else {
                build_tcp_segment(
                    dst_ip,
                    src_ip,
                    header.dst_port,
                    header.src_port,
                    0,
                    header.seq_num.wrapping_add(1),
                    TcpFlags::RST | TcpFlags::ACK,
                    0,
                    &[],
                )
            };
            out.push(TcpOutput::SendSegment {
                dst_ip: src_ip,
                data: rst,
            });
        }

        out
    }

    /// Process a timer tick: retransmit timed-out segments, clean up
    /// `TIME_WAIT` connections.
    ///
    /// `now` is the current monotonic timestamp in milliseconds.
    pub fn tick(&mut self, now: u64, out: &mut Vec<TcpOutput>) {
        self.last_now = now;
        // Collect the encoded keys; we decode them back by reading the TCB.
        let encoded_keys: Vec<(u64, u64)> = self.connections.keys().copied().collect();
        for ekey in encoded_keys {
            // Reconstruct the logical key from the TCB.
            if let Some(tcb) = self.connections.get(&ekey) {
                let key = (tcb.local, tcb.remote);
                self.tick_connection(&key, now, out);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Allocate the next initial sequence number.
    fn next_isn(&mut self) -> u32 {
        let isn = self.next_isn;
        // Advance by a large prime to spread ISNs; this is not security-
        // critical (the kernel should use a better source of randomness).
        self.next_isn = self.next_isn.wrapping_add(0x0001_5EED);
        isn
    }

    /// Process a segment for an existing connection `key`.
    // This function implements the full RFC 793 TCP state machine in one place
    // for clarity; the length and complexity are inherent to the spec.
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn process_segment(
        &mut self,
        key: &TcpConnectionKey,
        header: &TcpHeader,
        payload: &[u8],
        now: u64,
        out: &mut Vec<TcpOutput>,
    ) {
        let Some(tcb) = self.conn_get_mut(key) else {
            return;
        };
        let flags = header.flags();
        let state = tcb.state;

        match state {
            TcpState::SynSent => {
                // Expecting SYN+ACK.
                if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                    if header.ack_num != tcb.snd_nxt {
                        // Bad ACK; send RST.
                        let rst = build_tcp_segment(
                            Ipv4Addr(tcb.local.ip),
                            Ipv4Addr(tcb.remote.ip),
                            tcb.local.port,
                            tcb.remote.port,
                            header.ack_num,
                            0,
                            TcpFlags::RST,
                            0,
                            &[],
                        );
                        out.push(TcpOutput::SendSegment {
                            dst_ip: Ipv4Addr(tcb.remote.ip),
                            data: rst,
                        });
                        return;
                    }
                    tcb.irs = header.seq_num;
                    tcb.rcv_nxt = header.seq_num.wrapping_add(1);
                    tcb.snd_una = header.ack_num;
                    tcb.snd_wnd = header.window;
                    tcb.state = TcpState::Established;

                    // The SYN-ACK acknowledges our SYN (ack_num == snd_nxt ==
                    // iss + 1), so the queued SYN must stop being retransmitted.
                    // It is the only segment that can be in the queue in
                    // SynSent, so clearing is exact.
                    tcb.retransmit_queue.clear();

                    // Send ACK.
                    let ack = build_tcp_segment(
                        Ipv4Addr(tcb.local.ip),
                        Ipv4Addr(tcb.remote.ip),
                        tcb.local.port,
                        tcb.remote.port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        TcpFlags::ACK,
                        tcb.rcv_wnd,
                        &[],
                    );
                    out.push(TcpOutput::SendSegment {
                        dst_ip: Ipv4Addr(tcb.remote.ip),
                        data: ack,
                    });
                    out.push(TcpOutput::ConnectionEstablished { key: *key });
                } else if flags & TcpFlags::RST != 0 {
                    self.conn_remove(key);
                    out.push(TcpOutput::ConnectionRefused { key: *key });
                }
            }

            TcpState::SynReceived => {
                // Expecting the final ACK of the 3-way handshake.
                if flags & TcpFlags::ACK != 0 && header.ack_num == tcb.snd_nxt {
                    tcb.snd_una = header.ack_num;
                    tcb.snd_wnd = header.window;
                    tcb.state = TcpState::Established;

                    // Move to listener backlog.
                    let listener_port = tcb.local.port;
                    if let Some(tcb_owned) = self.conn_remove(key) {
                        if let Some(queue) = self.listeners.get_mut(&listener_port) {
                            queue.backlog.push_back(tcb_owned);
                        }
                    }
                    out.push(TcpOutput::ConnectionEstablished { key: *key });
                }
            }

            TcpState::Established => {
                // Process ACK.
                if flags & TcpFlags::ACK != 0 {
                    self.process_ack(key, header, now, out);
                }
                // Process incoming data.
                let Some(tcb) = self.conn_get_mut(key) else {
                    return;
                };
                if !payload.is_empty() && header.seq_num == tcb.rcv_nxt {
                    tcb.recv_buffer.extend(payload.iter().copied());
                    // Cast is safe: payload.len() fits in u32 since MTU ≤ 65535.
                    #[allow(clippy::cast_possible_truncation)]
                    let payload_len_u32 = payload.len() as u32;
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len_u32);
                    // Send ACK.
                    let ack = build_tcp_segment(
                        Ipv4Addr(tcb.local.ip),
                        Ipv4Addr(tcb.remote.ip),
                        tcb.local.port,
                        tcb.remote.port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        TcpFlags::ACK,
                        tcb.rcv_wnd,
                        &[],
                    );
                    out.push(TcpOutput::SendSegment {
                        dst_ip: Ipv4Addr(tcb.remote.ip),
                        data: ack,
                    });
                    out.push(TcpOutput::DataReceived { key: *key });
                    // Out-of-order packets are dropped (peer will retransmit).
                }
                // Process FIN.
                let Some(tcb) = self.conn_get_mut(key) else {
                    return;
                };
                if flags & TcpFlags::FIN != 0 {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::CloseWait;
                    let ack = build_tcp_segment(
                        Ipv4Addr(tcb.local.ip),
                        Ipv4Addr(tcb.remote.ip),
                        tcb.local.port,
                        tcb.remote.port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        TcpFlags::ACK,
                        tcb.rcv_wnd,
                        &[],
                    );
                    out.push(TcpOutput::SendSegment {
                        dst_ip: Ipv4Addr(tcb.remote.ip),
                        data: ack,
                    });
                }
            }

            TcpState::FinWait1 => {
                if flags & TcpFlags::ACK != 0 {
                    let Some(tcb) = self.conn_get_mut(key) else {
                        return;
                    };
                    if header.ack_num == tcb.snd_nxt {
                        tcb.snd_una = header.ack_num;
                        tcb.state = TcpState::FinWait2;
                    }
                }
                // Simultaneous close: remote also sent FIN.
                let Some(tcb) = self.conn_get_mut(key) else {
                    return;
                };
                if flags & TcpFlags::FIN != 0 {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = if tcb.state == TcpState::FinWait2 {
                        TcpState::TimeWait
                    } else {
                        TcpState::Closing
                    };
                    let ack = build_tcp_segment(
                        Ipv4Addr(tcb.local.ip),
                        Ipv4Addr(tcb.remote.ip),
                        tcb.local.port,
                        tcb.remote.port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        TcpFlags::ACK,
                        tcb.rcv_wnd,
                        &[],
                    );
                    out.push(TcpOutput::SendSegment {
                        dst_ip: Ipv4Addr(tcb.remote.ip),
                        data: ack,
                    });
                    if tcb.state == TcpState::TimeWait {
                        tcb.time_wait_started_ms = now;
                    }
                }
            }

            TcpState::FinWait2 => {
                if flags & TcpFlags::FIN != 0 {
                    let Some(tcb) = self.conn_get_mut(key) else {
                        return;
                    };
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::TimeWait;
                    tcb.time_wait_started_ms = now;
                    let ack = build_tcp_segment(
                        Ipv4Addr(tcb.local.ip),
                        Ipv4Addr(tcb.remote.ip),
                        tcb.local.port,
                        tcb.remote.port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        TcpFlags::ACK,
                        tcb.rcv_wnd,
                        &[],
                    );
                    out.push(TcpOutput::SendSegment {
                        dst_ip: Ipv4Addr(tcb.remote.ip),
                        data: ack,
                    });
                }
            }

            TcpState::Closing => {
                if flags & TcpFlags::ACK != 0 {
                    let Some(tcb) = self.conn_get_mut(key) else {
                        return;
                    };
                    if header.ack_num == tcb.snd_nxt {
                        tcb.state = TcpState::TimeWait;
                        tcb.time_wait_started_ms = now;
                    }
                }
            }

            TcpState::LastAck => {
                if flags & TcpFlags::ACK != 0 {
                    let snd_nxt = match self.conn_get(key) {
                        Some(t) => t.snd_nxt,
                        None => return,
                    };
                    if header.ack_num == snd_nxt {
                        self.conn_remove(key);
                        out.push(TcpOutput::ConnectionClosed { key: *key });
                    }
                }
            }

            TcpState::TimeWait => {
                // RFC 793: restart 2*MSL timer if another FIN arrives.
                if flags & TcpFlags::FIN != 0 {
                    if let Some(tcb) = self.conn_get_mut(key) {
                        tcb.time_wait_started_ms = now;
                        let ack = build_tcp_segment(
                            Ipv4Addr(tcb.local.ip),
                            Ipv4Addr(tcb.remote.ip),
                            tcb.local.port,
                            tcb.remote.port,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            TcpFlags::ACK,
                            tcb.rcv_wnd,
                            &[],
                        );
                        out.push(TcpOutput::SendSegment {
                            dst_ip: Ipv4Addr(tcb.remote.ip),
                            data: ack,
                        });
                    }
                }
            }

            TcpState::Closed | TcpState::Listen | TcpState::CloseWait => {
                // These are handled elsewhere or are no-ops for incoming segments.
            }
        }
    }

    /// Process an ACK for outstanding send data (including retransmit queue
    /// cleanup and congestion control).
    // Integer divisions below implement TCP Reno cwnd/ssthresh calculations.
    #[allow(clippy::integer_division)]
    fn process_ack(
        &mut self,
        key: &TcpConnectionKey,
        header: &TcpHeader,
        now: u64,
        out: &mut Vec<TcpOutput>,
    ) {
        let Some(tcb) = self.conn_get_mut(key) else {
            return;
        };

        let ack = header.ack_num;

        // Duplicate ACK detection.
        if ack == tcb.snd_una && !tcb.retransmit_queue.is_empty() {
            tcb.dup_ack_count = tcb.dup_ack_count.saturating_add(1);
            if tcb.dup_ack_count == 3 {
                // Fast retransmit (TCP Reno).
                tcb.ssthresh = (tcb.cwnd / 2).max(2 * u32::from(tcb.mss));
                tcb.cwnd = tcb.ssthresh + 3 * u32::from(tcb.mss);

                // Retransmit the first segment in the queue.
                if let Some(entry) = tcb.retransmit_queue.first().cloned() {
                    let seg = build_tcp_segment(
                        Ipv4Addr(tcb.local.ip),
                        Ipv4Addr(tcb.remote.ip),
                        tcb.local.port,
                        tcb.remote.port,
                        entry.seq,
                        tcb.rcv_nxt,
                        TcpFlags::ACK | TcpFlags::PSH,
                        tcb.rcv_wnd,
                        &entry.data,
                    );
                    let remote_ip = Ipv4Addr(tcb.remote.ip);
                    out.push(TcpOutput::SendSegment {
                        dst_ip: remote_ip,
                        data: seg,
                    });
                }
            }
            return;
        }

        // New ACK: advance snd_una.
        if seq_lt(tcb.snd_una, ack) && seq_le(ack, tcb.snd_nxt) {
            tcb.dup_ack_count = 0;
            tcb.snd_una = ack;
            tcb.snd_wnd = header.window;

            // Acknowledge retransmit queue entries. A cumulative ACK names
            // the NEXT byte the peer expects, so the entry [seq, end) is
            // fully acknowledged exactly when `ack >= end` — keep it only
            // while `ack < end`. (The previous `seq_lt(ack - 1, end)` form
            // kept fully-acked segments whose `end == ack`, so the queue
            // never drained on an exact ACK and every data segment was
            // retransmitted once at RTO. Latent until TASK-05 because
            // nothing ever transmitted application data.)
            tcb.retransmit_queue.retain(|e| {
                // data.len() is bounded by MSS (≤ 1460), so u32 cast is safe.
                #[allow(clippy::cast_possible_truncation)]
                let end = e.seq.wrapping_add(e.data.len() as u32);
                seq_lt(ack, end) // keep if not fully acked
            });

            // RTT sample from the oldest fully-ACKed entry.
            // We do a simple sample if there's a sent_at value in the queue.
            // A proper implementation would use the timestamp option.
            if tcb.srtt_ms == 0 && tcb.rttvar_ms == 0 {
                // Crude initial RTT estimate.
                let sample = now.saturating_sub(1); // placeholder
                let _ = sample; // not enough info without timestamps
            }

            // Congestion window update.
            if tcb.cwnd < tcb.ssthresh {
                // Slow start: increase cwnd by one MSS per ACK.
                tcb.cwnd = tcb.cwnd.saturating_add(u32::from(tcb.mss));
            } else {
                // Congestion avoidance: increase cwnd by MSS^2/cwnd per ACK.
                let inc = u32::from(tcb.mss).saturating_mul(u32::from(tcb.mss)) / tcb.cwnd.max(1);
                tcb.cwnd = tcb.cwnd.saturating_add(inc.max(1));
            }
        }
    }

    /// Tick a single connection for retransmission and `TIME_WAIT` expiry.
    // Integer division for congestion control: cwnd/2 is standard TCP Reno.
    #[allow(clippy::integer_division)]
    fn tick_connection(&mut self, key: &TcpConnectionKey, now: u64, out: &mut Vec<TcpOutput>) {
        let Some(tcb) = self.conn_get(key) else {
            return;
        };

        // TIME_WAIT expiry: if enough time has passed since TIME_WAIT started,
        // remove the connection. The state == TimeWait check is sufficient;
        // time_wait_started_ms may be 0 if the timer started at t=0.
        if tcb.state == TcpState::TimeWait
            && now.saturating_sub(tcb.time_wait_started_ms) >= TIME_WAIT_MS
        {
            self.conn_remove(key);
            out.push(TcpOutput::ConnectionClosed { key: *key });
            return;
        }

        // Retransmission.
        let expired: Vec<RetransmitEntry> = {
            let Some(tcb) = self.conn_get(key) else {
                return;
            };
            tcb.retransmit_queue
                .iter()
                .filter(|e| now.saturating_sub(e.sent_at) >= tcb.rto_ms)
                .cloned()
                .collect()
        };

        for entry in expired {
            let Some(tcb) = self.conn_get_mut(key) else {
                return;
            };
            // Find the entry in the queue and update it.
            if let Some(q_entry) = tcb.retransmit_queue.iter_mut().find(|e| e.seq == entry.seq) {
                if q_entry.retransmit_count >= MAX_RETRANSMIT {
                    // Too many retries; reset the connection.
                    let rst = build_tcp_segment(
                        Ipv4Addr(tcb.local.ip),
                        Ipv4Addr(tcb.remote.ip),
                        tcb.local.port,
                        tcb.remote.port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        TcpFlags::RST,
                        0,
                        &[],
                    );
                    let remote_ip = Ipv4Addr(tcb.remote.ip);
                    out.push(TcpOutput::SendSegment {
                        dst_ip: remote_ip,
                        data: rst,
                    });
                    out.push(TcpOutput::ConnectionClosed { key: *key });
                    self.conn_remove(key);
                    return;
                }
                q_entry.retransmit_count += 1;
                q_entry.sent_at = now;
                // Exponential backoff.
                let new_rto = tcb.rto_ms.saturating_mul(2).min(60_000);
                let seg = build_tcp_segment(
                    Ipv4Addr(tcb.local.ip),
                    Ipv4Addr(tcb.remote.ip),
                    tcb.local.port,
                    tcb.remote.port,
                    q_entry.seq,
                    tcb.rcv_nxt,
                    TcpFlags::ACK | TcpFlags::PSH,
                    tcb.rcv_wnd,
                    &q_entry.data.clone(),
                );
                let remote_ip = Ipv4Addr(tcb.remote.ip);
                out.push(TcpOutput::SendSegment {
                    dst_ip: remote_ip,
                    data: seg,
                });
                tcb.rto_ms = new_rto;
                // Congestion: reduce ssthresh and cwnd on timeout.
                tcb.ssthresh = (tcb.cwnd / 2).max(2 * u32::from(tcb.mss));
                tcb.cwnd = u32::from(tcb.mss);
            }
        }
    }
}

// =============================================================================
// Segment builder
// =============================================================================

/// Build a complete TCP segment wrapped in an `IPv4` packet.
///
/// Computes the TCP checksum over the `IPv4` pseudo-header and returns the full
/// IP packet bytes.
///
/// # Arguments
///
/// The 9-argument signature reflects the full set of TCP/IP header fields
/// required to construct a segment; refactoring into a builder struct would
/// add complexity without safety benefit.
///
/// # Examples
///
/// ```
/// use nexacore_net::tcp::build_tcp_segment;
/// use nexacore_types::net::{IpProtocol, Ipv4Addr, TcpFlags, TcpHeader, TcpPseudoHeader};
///
/// let pkt = build_tcp_segment(
///     Ipv4Addr::LOOPBACK,
///     Ipv4Addr::LOOPBACK,
///     1234,
///     80,
///     0,
///     0,
///     TcpFlags::SYN,
///     65535,
///     &[],
/// );
/// // Parse back the IPv4 + TCP layer.
/// let (ip_hdr, tcp_bytes) = nexacore_net::ip::parse_ipv4_packet(&pkt).unwrap();
/// let (tcp_hdr, _payload) = TcpHeader::parse(tcp_bytes).unwrap();
/// let pseudo = TcpPseudoHeader {
///     src_ip: ip_hdr.src,
///     dst_ip: ip_hdr.dst,
///     zero: 0,
///     protocol: IpProtocol::TCP.0,
///     tcp_length: (tcp_bytes.len()) as u16,
/// };
/// assert!(tcp_hdr.verify_checksum(pseudo, &[]));
/// ```
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    // Total TCP length fits in u16: TCP header (20) + payload (≤ 65515 for MTU).
    #[allow(clippy::cast_possible_truncation)]
    let tcp_len = (TcpHeader::HEADER_LEN_MIN + payload.len()) as u16;
    let pseudo = TcpPseudoHeader {
        src_ip,
        dst_ip,
        zero: 0,
        protocol: IpProtocol::TCP.0,
        tcp_length: tcp_len,
    };
    let mut hdr = TcpHeader {
        src_port,
        dst_port,
        seq_num: seq,
        ack_num: ack,
        data_offset_flags: (5u16 << 12) | u16::from(flags),
        window,
        checksum: 0,
        urgent_ptr: 0,
    };
    hdr.checksum = hdr.compute_checksum(pseudo, payload);

    let mut tcp_bytes = alloc::vec![0u8; TcpHeader::HEADER_LEN_MIN + payload.len()];
    if let Some(hdr_slot) = tcp_bytes.get_mut(..TcpHeader::HEADER_LEN_MIN) {
        let _ = hdr.serialize(hdr_slot);
    }
    if let Some(dst) = tcp_bytes.get_mut(TcpHeader::HEADER_LEN_MIN..) {
        dst.copy_from_slice(payload);
    }
    build_ipv4_packet(src_ip, dst_ip, IpProtocol::TCP, 64, 0, &tcp_bytes)
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
        clippy::single_match,
        clippy::single_match_else
    )]
    use nexacore_types::net::IpProtocol;

    #[allow(clippy::wildcard_imports)]
    use super::*;

    fn client_addr() -> SocketApiAddr {
        SocketApiAddr {
            ip: [192, 168, 1, 10],
            port: 54321,
        }
    }

    fn server_addr() -> SocketApiAddr {
        SocketApiAddr {
            ip: [192, 168, 1, 1],
            port: 80,
        }
    }

    fn client_ip() -> Ipv4Addr {
        Ipv4Addr([192, 168, 1, 10])
    }

    fn server_ip() -> Ipv4Addr {
        Ipv4Addr([192, 168, 1, 1])
    }

    /// Extract the `TcpHeader` and payload from a raw IP packet built by
    /// `build_tcp_segment`.
    fn parse_tcp_from_ip(data: &[u8]) -> (TcpHeader, Vec<u8>) {
        let (_, tcp_bytes) = crate::ip::parse_ipv4_packet(data).unwrap();
        let (hdr, payload) = TcpHeader::parse(tcp_bytes).unwrap();
        (hdr, payload.to_vec())
    }

    fn make_syn_header(src_port: u16, dst_port: u16, seq: u32) -> TcpHeader {
        TcpHeader {
            src_port,
            dst_port,
            seq_num: seq,
            ack_num: 0,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    fn make_ack_header(src_port: u16, dst_port: u16, seq: u32, ack: u32) -> TcpHeader {
        TcpHeader {
            src_port,
            dst_port,
            seq_num: seq,
            ack_num: ack,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    // -------------------------------------------------------------------------
    // Passive open (server): SYN → SYN+ACK → ACK
    // -------------------------------------------------------------------------

    #[test]
    fn passive_open_sends_syn_ack() {
        let mut table = TcpSocketTable::new();
        table.listen(80, 10).unwrap();
        let syn = make_syn_header(54321, 80, 1000);
        let out = table.handle_segment(&syn, &[], client_ip(), server_ip(), 0);
        // Should produce a SendSegment containing the SYN+ACK.
        let syn_ack_pkt = out.iter().find_map(|o| {
            if let TcpOutput::SendSegment { data, .. } = o {
                Some(data.clone())
            } else {
                None
            }
        });
        let syn_ack_pkt = syn_ack_pkt.expect("expected SYN+ACK");
        let (tcp_hdr, _) = parse_tcp_from_ip(&syn_ack_pkt);
        assert_eq!(tcp_hdr.flags() & TcpFlags::SYN, TcpFlags::SYN);
        assert_eq!(tcp_hdr.flags() & TcpFlags::ACK, TcpFlags::ACK);
        assert_eq!(tcp_hdr.ack_num, 1001);
    }

    #[test]
    fn passive_open_completes_on_ack() {
        let mut table = TcpSocketTable::new();
        table.listen(80, 10).unwrap();
        let syn = make_syn_header(54321, 80, 1000);
        let out = table.handle_segment(&syn, &[], client_ip(), server_ip(), 0);

        // Find the SYN+ACK to extract ISS.
        let syn_ack_pkt = out
            .iter()
            .find_map(|o| {
                if let TcpOutput::SendSegment { data, .. } = o {
                    Some(data.clone())
                } else {
                    None
                }
            })
            .unwrap();
        let (syn_ack_hdr, _) = parse_tcp_from_ip(&syn_ack_pkt);
        let server_iss = syn_ack_hdr.seq_num;

        // Send the final ACK.
        let ack = make_ack_header(54321, 80, 1001, server_iss.wrapping_add(1));
        let out2 = table.handle_segment(&ack, &[], client_ip(), server_ip(), 0);
        let established = out2
            .iter()
            .any(|o| matches!(o, TcpOutput::ConnectionEstablished { .. }));
        assert!(established, "expected ConnectionEstablished after ACK");
    }

    #[test]
    fn passive_open_connection_available_via_accept() {
        let mut table = TcpSocketTable::new();
        table.listen(80, 10).unwrap();
        let syn = make_syn_header(54321, 80, 1000);
        let _ = table.handle_segment(&syn, &[], client_ip(), server_ip(), 0);

        // Get SYN+ACK ISS.
        let conn_key = (
            SocketApiAddr {
                ip: server_ip().0,
                port: 80,
            },
            SocketApiAddr {
                ip: client_ip().0,
                port: 54321,
            },
        );
        let tcb = table.conn_get(&conn_key).unwrap();
        let server_iss = tcb.snd_nxt.wrapping_sub(1);

        let ack = make_ack_header(54321, 80, 1001, server_iss.wrapping_add(1));
        let _ = table.handle_segment(&ack, &[], client_ip(), server_ip(), 0);

        let key = table.accept(80);
        assert!(key.is_some(), "accept should return the connection key");
    }

    // -------------------------------------------------------------------------
    // Active open (client): connect → SYN+ACK → Established
    // -------------------------------------------------------------------------

    #[test]
    fn active_open_sends_syn() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        assert!(!out.is_empty());
        let syn_pkt = match out.first().unwrap() {
            TcpOutput::SendSegment { data, .. } => data.clone(),
            _ => panic!("expected SendSegment"),
        };
        let (tcp_hdr, _) = parse_tcp_from_ip(&syn_pkt);
        assert_eq!(tcp_hdr.flags() & TcpFlags::SYN, TcpFlags::SYN);
        assert_eq!(tcp_hdr.flags() & TcpFlags::ACK, 0);
        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(tcb.state, TcpState::SynSent);
    }

    #[test]
    fn active_open_transitions_to_established_on_syn_ack() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();

        let syn_pkt = match out.first().unwrap() {
            TcpOutput::SendSegment { data, .. } => data.clone(),
            _ => panic!(),
        };
        let (syn_hdr, _) = parse_tcp_from_ip(&syn_pkt);
        let client_iss = syn_hdr.seq_num;

        // Simulate server's SYN+ACK.
        let syn_ack = TcpHeader {
            src_port: 80,
            dst_port: client_addr().port,
            seq_num: 5000,
            ack_num: client_iss.wrapping_add(1),
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let out2 = table.handle_segment(&syn_ack, &[], server_ip(), client_ip(), 0);
        let established = out2
            .iter()
            .any(|o| matches!(o, TcpOutput::ConnectionEstablished { .. }));
        assert!(established);
        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(tcb.state, TcpState::Established);
    }

    // -------------------------------------------------------------------------
    // Data transfer
    // -------------------------------------------------------------------------

    #[test]
    fn established_receives_data() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        // Fast-path to Established.
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.rcv_nxt = 1;
            tcb.snd_nxt = 100;
            tcb.irs = 0;
        }
        let data_seg = TcpHeader {
            src_port: 80,
            dst_port: client_addr().port,
            seq_num: 1,
            ack_num: 100,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::ACK) | u16::from(TcpFlags::PSH),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let out2 = table.handle_segment(&data_seg, b"hello", server_ip(), client_ip(), 0);
        let data_received = out2
            .iter()
            .any(|o| matches!(o, TcpOutput::DataReceived { .. }));
        assert!(data_received);
        let mut buf = [0u8; 5];
        let n = table.recv(&key, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    // -------------------------------------------------------------------------
    // Packet loss & reorder (WS4-01.8)
    // -------------------------------------------------------------------------

    /// Establish a connection fast-pathed to `Established` with `rcv_nxt == 1`.
    fn established_table() -> (TcpSocketTable, TcpConnectionKey) {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        let tcb = table.conn_get_mut(&key).unwrap();
        tcb.state = TcpState::Established;
        tcb.rcv_nxt = 1;
        tcb.snd_nxt = 100;
        tcb.irs = 0;
        (table, key)
    }

    /// A PSH|ACK data header from the server with the given sequence number.
    fn server_data_header(seq: u32) -> TcpHeader {
        TcpHeader {
            src_port: 80,
            dst_port: client_addr().port,
            seq_num: seq,
            ack_num: 100,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::ACK) | u16::from(TcpFlags::PSH),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    fn delivered(out: &[TcpOutput]) -> bool {
        out.iter()
            .any(|o| matches!(o, TcpOutput::DataReceived { .. }))
    }

    #[test]
    fn out_of_order_segment_is_dropped() {
        let (mut table, key) = established_table();
        // Expecting seq 1, but seq 6 arrives first (a 5-byte gap at 1..6).
        let res = table.handle_segment(
            &server_data_header(6),
            b"world",
            server_ip(),
            client_ip(),
            0,
        );
        assert!(
            !delivered(&res),
            "out-of-order data must not be delivered to the application"
        );
        assert_eq!(
            table.conn_get(&key).unwrap().rcv_nxt,
            1,
            "rcv_nxt must not advance across a gap"
        );
        let mut buf = [0u8; 16];
        assert_eq!(table.recv(&key, &mut buf).unwrap(), 0);
    }

    #[test]
    fn reorder_recovers_via_retransmission_in_order() {
        let (mut table, key) = established_table();
        // Reordered arrival: the second segment (seq 6) shows up before the
        // first and is dropped.
        assert!(!delivered(&table.handle_segment(
            &server_data_header(6),
            b"world",
            server_ip(),
            client_ip(),
            0
        )));
        // The missing in-order segment arrives and is delivered.
        assert!(delivered(&table.handle_segment(
            &server_data_header(1),
            b"hello",
            server_ip(),
            client_ip(),
            0
        )));
        assert_eq!(table.conn_get(&key).unwrap().rcv_nxt, 6);
        // The peer retransmits the previously-dropped segment, now in order.
        assert!(delivered(&table.handle_segment(
            &server_data_header(6),
            b"world",
            server_ip(),
            client_ip(),
            0
        )));
        assert_eq!(table.conn_get(&key).unwrap().rcv_nxt, 11);
        // The reassembled stream is in the correct byte order.
        let mut buf = [0u8; 16];
        let n = table.recv(&key, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"helloworld");
    }

    #[test]
    fn stale_duplicate_segment_is_not_redelivered() {
        let (mut table, key) = established_table();
        // First in-order delivery.
        assert!(delivered(&table.handle_segment(
            &server_data_header(1),
            b"hello",
            server_ip(),
            client_ip(),
            0
        )));
        assert_eq!(table.conn_get(&key).unwrap().rcv_nxt, 6);
        let mut buf = [0u8; 16];
        let n = table.recv(&key, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        // A stale retransmit of already-acknowledged data must not re-deliver.
        let res = table.handle_segment(
            &server_data_header(1),
            b"hello",
            server_ip(),
            client_ip(),
            0,
        );
        assert!(!delivered(&res), "duplicate data must not be re-delivered");
        assert_eq!(
            table.conn_get(&key).unwrap().rcv_nxt,
            6,
            "rcv_nxt must not move on a stale duplicate"
        );
        assert_eq!(table.recv(&key, &mut buf).unwrap(), 0, "no new bytes");
    }

    #[test]
    fn send_emits_psh_ack_segment_with_payload() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            // A real SYN-ACK clears the queued SYN on reaching Established;
            // model that so the queue reflects only the data segment below.
            tcb.retransmit_queue.clear();
        }
        let seq_before = table.conn_get(&key).unwrap().snd_nxt;

        let mut tx = Vec::new();
        let n = table.send(&key, b"world", &mut tx).unwrap();
        assert_eq!(n, 5);

        // Exactly one PSH|ACK segment carrying the payload, addressed to the
        // remote, with seq == snd_nxt at call time.
        assert_eq!(tx.len(), 1);
        let TcpOutput::SendSegment { dst_ip, data } = &tx[0] else {
            panic!("expected SendSegment, got {:?}", tx[0]);
        };
        assert_eq!(*dst_ip, Ipv4Addr(server_addr().ip));
        let (_ip_hdr, tcp_bytes) = crate::ip::parse_ipv4_packet(data).unwrap();
        let (hdr, payload) = TcpHeader::parse(tcp_bytes).unwrap();
        assert_eq!(payload, b"world");
        assert_ne!(hdr.flags() & TcpFlags::PSH, 0, "PSH must be set");
        assert_ne!(hdr.flags() & TcpFlags::ACK, 0, "ACK must be set");
        assert_eq!(hdr.seq_num, seq_before);

        // snd_nxt advanced by the payload length; the segment is queued for
        // retransmission with the original sequence number.
        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(tcb.snd_nxt, seq_before.wrapping_add(5));
        assert_eq!(tcb.retransmit_queue.len(), 1);
        assert_eq!(tcb.retransmit_queue[0].seq, seq_before);
        assert_eq!(tcb.retransmit_queue[0].data, b"world");
    }

    #[test]
    fn send_chunks_payload_by_mss() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.mss = 4; // force chunking with a tiny MSS
            // Model the post-handshake state: the queued SYN is cleared on
            // reaching Established, leaving only the data chunks below.
            tcb.retransmit_queue.clear();
        }
        let seq_before = table.conn_get(&key).unwrap().snd_nxt;

        let mut tx = Vec::new();
        let n = table.send(&key, b"0123456789", &mut tx).unwrap();
        assert_eq!(n, 10);
        assert_eq!(tx.len(), 3, "10 bytes at MSS 4 → 4+4+2");

        // Sequence numbers are contiguous across the chunks.
        let mut expected_seq = seq_before;
        let expected_payloads: [&[u8]; 3] = [b"0123", b"4567", b"89"];
        for (item, expected) in tx.iter().zip(expected_payloads) {
            let TcpOutput::SendSegment { data, .. } = item else {
                panic!("expected SendSegment, got {item:?}");
            };
            let (_ip_hdr, tcp_bytes) = crate::ip::parse_ipv4_packet(data).unwrap();
            let (hdr, payload) = TcpHeader::parse(tcp_bytes).unwrap();
            assert_eq!(payload, expected);
            assert_eq!(hdr.seq_num, expected_seq);
            // Truncation-safe: test payloads are ≤ 4 bytes.
            #[allow(clippy::cast_possible_truncation)]
            let adv = payload.len() as u32;
            expected_seq = expected_seq.wrapping_add(adv);
        }
        assert_eq!(
            table.conn_get(&key).unwrap().snd_nxt,
            seq_before.wrapping_add(10)
        );
        assert_eq!(table.conn_get(&key).unwrap().retransmit_queue.len(), 3);
    }

    #[test]
    fn send_before_established_is_rejected() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        // connect() leaves the connection in SynSent.
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        let mut tx = Vec::new();
        let err = table.send(&key, b"x", &mut tx).unwrap_err();
        assert_eq!(err, NetError::InvalidArgument);
        assert!(
            tx.is_empty(),
            "no segment may be emitted before ESTABLISHED"
        );
    }

    #[test]
    fn send_on_unknown_connection_is_not_connected() {
        let mut table = TcpSocketTable::new();
        let mut tx = Vec::new();
        let key = (client_addr(), server_addr());
        let err = table.send(&key, b"x", &mut tx).unwrap_err();
        assert_eq!(err, NetError::NotConnected);
    }

    // -------------------------------------------------------------------------
    // FIN / close sequence
    // -------------------------------------------------------------------------

    #[test]
    fn close_sends_fin_transitions_to_fin_wait1() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.snd_nxt = 100;
            tcb.rcv_nxt = 1;
        }
        let mut out2 = Vec::new();
        table.close(&key, &mut out2).unwrap();
        assert!(
            out2.iter()
                .any(|o| matches!(o, TcpOutput::SendSegment { .. }))
        );
        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(tcb.state, TcpState::FinWait1);
    }

    #[test]
    fn receive_fin_transitions_to_close_wait() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.rcv_nxt = 1;
            tcb.snd_nxt = 100;
        }
        let fin = TcpHeader {
            src_port: 80,
            dst_port: client_addr().port,
            seq_num: 1,
            ack_num: 100,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::FIN) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let _ = table.handle_segment(&fin, &[], server_ip(), client_ip(), 0);
        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(tcb.state, TcpState::CloseWait);
    }

    #[test]
    fn last_ack_removes_connection() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::LastAck;
            tcb.snd_nxt = 200;
        }
        let ack = make_ack_header(80, client_addr().port, 1, 200);
        let out2 = table.handle_segment(&ack, &[], server_ip(), client_ip(), 0);
        assert!(table.conn_get(&key).is_none());
        assert!(
            out2.iter()
                .any(|o| matches!(o, TcpOutput::ConnectionClosed { .. }))
        );
    }

    // -------------------------------------------------------------------------
    // RST handling
    // -------------------------------------------------------------------------

    #[test]
    fn rst_removes_established_connection() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
        }
        let rst = TcpHeader {
            src_port: 80,
            dst_port: client_addr().port,
            seq_num: 0,
            ack_num: 0,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::RST),
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
        };
        let _ = table.handle_segment(&rst, &[], server_ip(), client_ip(), 0);
        assert!(table.conn_get(&key).is_none());
    }

    #[test]
    fn connect_to_closed_port_receives_rst() {
        let mut table = TcpSocketTable::new();
        let syn = make_syn_header(54321, 9999, 1000);
        let out = table.handle_segment(&syn, &[], client_ip(), server_ip(), 0);
        let sent_rst = out.iter().any(|o| {
            if let TcpOutput::SendSegment { data, .. } = o {
                let (hdr, _) = parse_tcp_from_ip(data);
                hdr.flags() & TcpFlags::RST != 0
            } else {
                false
            }
        });
        assert!(sent_rst, "expected RST for SYN to closed port");
    }

    // -------------------------------------------------------------------------
    // TIME_WAIT expiry
    // -------------------------------------------------------------------------

    #[test]
    fn time_wait_expires_after_2msl() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::TimeWait;
            tcb.time_wait_started_ms = 0;
        }
        let mut out2 = Vec::new();
        // Tick past 2*MSL.
        table.tick(TIME_WAIT_MS + 1, &mut out2);
        assert!(table.conn_get(&key).is_none());
        assert!(
            out2.iter()
                .any(|o| matches!(o, TcpOutput::ConnectionClosed { .. }))
        );
    }

    // -------------------------------------------------------------------------
    // Retransmission
    // -------------------------------------------------------------------------

    #[test]
    fn retransmit_fires_after_rto() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.snd_nxt = 100;
            tcb.snd_una = 50;
            tcb.retransmit_queue.push(RetransmitEntry {
                seq: 50,
                data: alloc::vec![1, 2, 3],
                sent_at: 0,
                retransmit_count: 0,
            });
            tcb.rto_ms = 100;
        }
        let mut tick_out = Vec::new();
        table.tick(200, &mut tick_out);
        let retransmitted = tick_out
            .iter()
            .any(|o| matches!(o, TcpOutput::SendSegment { .. }));
        assert!(retransmitted, "expected retransmission after RTO");
    }

    #[test]
    fn max_retransmit_resets_connection() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.snd_nxt = 100;
            tcb.snd_una = 50;
            tcb.retransmit_queue.push(RetransmitEntry {
                seq: 50,
                data: alloc::vec![1],
                sent_at: 0,
                retransmit_count: MAX_RETRANSMIT, // already at max
            });
            tcb.rto_ms = 1;
        }
        let mut tick_out = Vec::new();
        table.tick(100, &mut tick_out);
        assert!(
            table.conn_get(&key).is_none(),
            "connection should be removed"
        );
        let has_closed = tick_out
            .iter()
            .any(|o| matches!(o, TcpOutput::ConnectionClosed { .. }));
        assert!(has_closed);
    }

    // -------------------------------------------------------------------------
    // SYN retransmission + connect timeout (WS2-02.3 / DE-F-RXFLAKE)
    // -------------------------------------------------------------------------

    #[test]
    fn connect_queues_syn_for_retransmit() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        let syn_pkt = match out.first().unwrap() {
            TcpOutput::SendSegment { data, .. } => data.clone(),
            _ => panic!("expected SendSegment"),
        };
        let (syn_hdr, _) = parse_tcp_from_ip(&syn_pkt);
        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(
            tcb.retransmit_queue.len(),
            1,
            "the SYN must be queued for retransmission"
        );
        assert_eq!(
            tcb.retransmit_queue[0].seq, syn_hdr.seq_num,
            "queued entry must cover the SYN's sequence number (iss)"
        );
        assert_eq!(tcb.retransmit_queue[0].retransmit_count, 0);
    }

    #[test]
    fn syn_retransmitted_after_rto() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let _key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        // No SYN-ACK arrives. Tick past the initial RTO (sent_at = 0).
        let mut tick_out = Vec::new();
        table.tick(RTO_INITIAL_MS + 1, &mut tick_out);
        let retransmitted = tick_out
            .iter()
            .any(|o| matches!(o, TcpOutput::SendSegment { .. }));
        assert!(retransmitted, "lost SYN must be retransmitted after RTO");
    }

    #[test]
    fn connect_times_out_after_max_retransmit() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        // No SYN-ACK ever arrives. Drive enough RTO expiries (now increments
        // dwarf the 60 s RTO clamp, so each tick is one expiry regardless of
        // exponential backoff) to exhaust MAX_RETRANSMIT and time the connect
        // out. The reset emits ConnectionClosed (mapped to ETIMEDOUT upstream).
        let mut closed = false;
        for i in 1..=(u64::from(MAX_RETRANSMIT) + 2) {
            let mut tick_out = Vec::new();
            table.tick(i * 100_000, &mut tick_out);
            if tick_out
                .iter()
                .any(|o| matches!(o, TcpOutput::ConnectionClosed { .. }))
            {
                closed = true;
            }
        }
        assert!(closed, "connect must time out with ConnectionClosed");
        assert!(
            table.conn_get(&key).is_none(),
            "timed-out connection must be removed"
        );
    }

    #[test]
    fn syn_ack_clears_retransmit_queue() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        let syn_pkt = match out.first().unwrap() {
            TcpOutput::SendSegment { data, .. } => data.clone(),
            _ => panic!("expected SendSegment"),
        };
        let (syn_hdr, _) = parse_tcp_from_ip(&syn_pkt);
        let client_iss = syn_hdr.seq_num;

        let syn_ack = TcpHeader {
            src_port: 80,
            dst_port: client_addr().port,
            seq_num: 5000,
            ack_num: client_iss.wrapping_add(1),
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::SYN) | u16::from(TcpFlags::ACK),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let _ = table.handle_segment(&syn_ack, &[], server_ip(), client_ip(), 0);

        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(tcb.state, TcpState::Established);
        assert!(
            tcb.retransmit_queue.is_empty(),
            "acknowledged SYN must be removed from the retransmit queue"
        );

        // And it must NOT be retransmitted after the RTO once established.
        let mut tick_out = Vec::new();
        table.tick(RTO_INITIAL_MS + 1, &mut tick_out);
        let resent = tick_out
            .iter()
            .any(|o| matches!(o, TcpOutput::SendSegment { .. }));
        assert!(!resent, "established connection must not resend the SYN");
    }

    // -------------------------------------------------------------------------
    // build_tcp_segment
    // -------------------------------------------------------------------------

    #[test]
    fn build_tcp_segment_checksum_valid() {
        let pkt = build_tcp_segment(
            client_ip(),
            server_ip(),
            client_addr().port,
            server_addr().port,
            1000,
            0,
            TcpFlags::SYN,
            65535,
            &[],
        );
        let (ip_hdr, tcp_bytes) = crate::ip::parse_ipv4_packet(&pkt).unwrap();
        let (tcp_hdr, payload) = TcpHeader::parse(tcp_bytes).unwrap();
        let pseudo = TcpPseudoHeader {
            src_ip: ip_hdr.src,
            dst_ip: ip_hdr.dst,
            zero: 0,
            protocol: IpProtocol::TCP.0,
            tcp_length: tcp_bytes.len() as u16,
        };
        assert!(tcp_hdr.verify_checksum(pseudo, payload));
    }

    #[test]
    fn build_tcp_segment_flags_embedded() {
        let pkt = build_tcp_segment(
            client_ip(),
            server_ip(),
            1234,
            80,
            0,
            0,
            TcpFlags::SYN | TcpFlags::ACK,
            1024,
            &[],
        );
        let (_, tcp_bytes) = crate::ip::parse_ipv4_packet(&pkt).unwrap();
        let (hdr, _) = TcpHeader::parse(tcp_bytes).unwrap();
        assert_eq!(hdr.flags() & TcpFlags::SYN, TcpFlags::SYN);
        assert_eq!(hdr.flags() & TcpFlags::ACK, TcpFlags::ACK);
    }

    // -------------------------------------------------------------------------
    // Sequence number helpers
    // -------------------------------------------------------------------------

    #[test]
    fn seq_lt_basic() {
        assert!(seq_lt(0, 1));
        assert!(!seq_lt(1, 0));
        assert!(!seq_lt(5, 5));
    }

    #[test]
    fn seq_lt_wrapping() {
        // Wrapping: u32::MAX + 1 = 0, so MAX < 0 in sequence space.
        assert!(seq_lt(u32::MAX, 0));
        assert!(!seq_lt(0, u32::MAX));
    }

    #[test]
    fn seq_le_reflexive() {
        assert!(seq_le(100, 100));
    }

    // -------------------------------------------------------------------------
    // Duplicate ACK / fast retransmit
    // -------------------------------------------------------------------------

    #[test]
    fn three_dup_acks_trigger_fast_retransmit() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.snd_nxt = 200;
            tcb.snd_una = 100;
            tcb.rcv_nxt = 1;
            tcb.retransmit_queue.push(RetransmitEntry {
                seq: 100,
                data: alloc::vec![0xAA, 0xBB],
                sent_at: 0,
                retransmit_count: 0,
            });
        }
        // Send 3 duplicate ACKs.
        let dup_ack = make_ack_header(80, client_addr().port, 1, 100);
        for _ in 0..3 {
            let _ = table.handle_segment(&dup_ack, &[], server_ip(), client_ip(), 0);
        }
        // After 3 dup-ACKs, ssthresh should have been halved and a retransmit queued.
        let tcb = table.conn_get(&key).unwrap();
        // ssthresh should be less than the initial value.
        assert!(tcb.ssthresh < INITIAL_SSTHRESH);
    }

    // -------------------------------------------------------------------------
    // Window update
    // -------------------------------------------------------------------------

    #[test]
    fn window_update_reflected_in_tcb() {
        let mut table = TcpSocketTable::new();
        let mut out = Vec::new();
        let key = table
            .connect(client_addr(), server_addr(), &mut out)
            .unwrap();
        {
            let tcb = table.conn_get_mut(&key).unwrap();
            tcb.state = TcpState::Established;
            tcb.snd_nxt = 100;
            tcb.snd_una = 99;
            tcb.rcv_nxt = 1;
        }
        let ack_with_window = TcpHeader {
            src_port: 80,
            dst_port: client_addr().port,
            seq_num: 1,
            ack_num: 100,
            data_offset_flags: (5 << 12) | u16::from(TcpFlags::ACK),
            window: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let _ = table.handle_segment(&ack_with_window, &[], server_ip(), client_ip(), 0);
        let tcb = table.conn_get(&key).unwrap();
        assert_eq!(tcb.snd_wnd, 4096);
    }

    // -------------------------------------------------------------------------
    // Listen / Accept edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn listen_duplicate_port_returns_error() {
        let mut table = TcpSocketTable::new();
        table.listen(443, 5).unwrap();
        assert!(matches!(table.listen(443, 5), Err(NetError::AddrInUse)));
    }

    #[test]
    fn accept_returns_none_when_backlog_empty() {
        let mut table = TcpSocketTable::new();
        table.listen(8080, 10).unwrap();
        assert!(table.accept(8080).is_none());
    }

    // --- Window scaling option (WS4-01.2) -----------------------------------

    #[test]
    fn parses_mss_and_window_scale_options() {
        // MSS 1460 (02 04 05 B4), NOP (01), Window Scale 7 (03 03 07), END (00).
        let opts = [0x02, 0x04, 0x05, 0xB4, 0x01, 0x03, 0x03, 0x07, 0x00];
        let parsed = parse_tcp_options(&opts);
        assert_eq!(parsed, [TcpOption::Mss(1460), TcpOption::WindowScale(7)]);
    }

    #[test]
    fn option_parsing_is_bounded_against_bad_lengths() {
        // A Window Scale option claiming length 3 but truncated: parsing stops.
        assert!(parse_tcp_options(&[0x03, 0x03]).is_empty());
        // A zero length would loop forever if unguarded — it stops instead.
        assert!(parse_tcp_options(&[0x02, 0x00, 0xFF]).is_empty());
        // Shift is clamped to the RFC-7323 maximum of 14.
        assert_eq!(
            parse_tcp_options(&[0x03, 0x03, 0xFF]),
            [TcpOption::WindowScale(14)]
        );
    }

    #[test]
    fn window_scale_encode_and_scale_math() {
        assert_eq!(encode_window_scale(7), [3, 3, 7]);
        assert_eq!(encode_window_scale(20), [3, 3, 14]); // clamped
        assert_eq!(scaled_window(65535, 7), 65535u32 << 7);
        assert_eq!(scaled_window(100, 0), 100);
    }

    #[test]
    fn negotiation_requires_the_peer_to_offer_scaling() {
        // Peer offered a shift → both directions scale.
        assert_eq!(negotiated_scales(7, Some(8)), (7, 8));
        // Peer offered none → scaling disabled for both.
        assert_eq!(negotiated_scales(7, None), (0, 0));
    }

    #[test]
    fn tcb_applies_and_uses_the_negotiated_scale() {
        let local = SocketApiAddr {
            ip: [10, 0, 0, 1],
            port: 1234,
        };
        let remote = SocketApiAddr {
            ip: [10, 0, 0, 2],
            port: 80,
        };
        let mut tcb = TcpControlBlock::new_syn_received(local, remote, 1000, 2000);
        tcb.snd_wnd = 500;
        // Without negotiation the effective window equals the raw window.
        assert_eq!(tcb.effective_send_window(), 500);
        // With a negotiated peer shift of 3 the send window scales up.
        tcb.apply_window_scale(7, Some(3));
        assert_eq!(tcb.snd_wscale, 3);
        assert_eq!(tcb.rcv_wscale, 7);
        assert_eq!(tcb.effective_send_window(), 500u32 << 3);
        // A peer that offered no scaling disables it.
        tcb.apply_window_scale(7, None);
        assert_eq!(tcb.effective_send_window(), 500);
    }
}

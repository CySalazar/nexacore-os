//! Socket API types (N3.1) — IPC protocol between userspace programs and the
//! `nexacore-net` network service.
//!
//! This module defines the canonical request/response shapes carried on the
//! `nexacore.svc.net.stack` IPC channel. Userspace programs issue
//! [`SocketRequest`] messages and receive [`SocketResponse`] messages;
//! the `nexacore-net` service is the sole responder.
//!
//! ## Design goals
//!
//! 1. **POSIX-adjacent, not POSIX-identical.** The request vocabulary mirrors
//!    BSD socket semantics (connect, bind, listen, accept, send, recv, etc.)
//!    because userspace consumers will mostly be porting existing software.
//!    However, the surface is deliberately minimal: no `ioctl`, no `setsockopt`
//!    level/optname pairs, no file-descriptor passing. These can be added in
//!    future variants under the `#[non_exhaustive]` policy.
//! 2. **Handles, not file descriptors.** [`SocketHandle`] is an opaque
//!    `u64` assigned by the network service. Userspace programs MUST NOT
//!    interpret it as an OS file-descriptor number; it is only meaningful
//!    on the `nexacore.svc.net.stack` channel.
//! 3. **No inline data copying in the kernel path.** Large data transfers
//!    (`Send`, `Recv`, etc.) carry `Vec<u8>` in the IPC message for the
//!    initial implementation. A future NCIP will migrate to IOVA-based
//!    zero-copy, following the same pattern as [`crate::net_channel`].
//!
//! ## Backward-compatibility policy
//!
//! Both [`SocketRequest`] and [`SocketResponse`] carry `#[non_exhaustive]`.
//! New variants MAY land via PR without an NCIP; removing or renaming a
//! variant is a breaking change requiring a Standards-Track NCIP.
//!
//! ## Channel constants
//!
//! The IPC channel name is fixed at [`SOCKET_API_CHANNEL`]
//! (`"nexacore.svc.net.stack"`). Network interface configuration goes on the
//! separate [`NET_CONFIG_CHANNEL`] (`"nexacore.svc.net.config"`).

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// IPC channel name for the socket API service.
///
/// Userspace programs open this channel to issue [`SocketRequest`] messages.
/// The `nexacore-net` network service listens on this channel and responds with
/// [`SocketResponse`] messages.
pub const SOCKET_API_CHANNEL: &str = "nexacore.svc.net.stack";

/// IPC channel name for network interface configuration.
///
/// Used by privileged administrative clients to configure network interfaces
/// (IP address assignment, routing, etc.). Distinct from [`SOCKET_API_CHANNEL`]
/// so that capability tokens can gate configuration access independently from
/// socket creation access.
pub const NET_CONFIG_CHANNEL: &str = "nexacore.svc.net.config";

/// IPC channel name for network configuration replies.
///
/// Paired with [`NET_CONFIG_CHANNEL`]: clients send `NetConfigRequest` on the
/// former and receive the matching `NetConfigResponse` on this channel —
/// mirroring the `stack`/`stack_reply` two-channel rendezvous already used by
/// [`SOCKET_API_CHANNEL`].
pub const NET_CONFIG_REPLY_CHANNEL: &str = "nexacore.svc.net.config_reply";

// =============================================================================
// Scalar types
// =============================================================================

/// Socket address family.
///
/// Determines the address format used in [`SocketApiAddr`] and the protocol
/// family the network service allocates for a new socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketDomain {
    /// `IPv4` (`AF_INET` equivalent). Addresses are 4-byte `IPv4` octets in
    /// network byte order.
    Inet,
    /// `IPv6` (`AF_INET6` equivalent, reserved for future implementation).
    ///
    /// Creating an `Inet6` socket with the current network service returns
    /// [`NetError::InvalidArgument`] until `IPv6` support lands.
    Inet6,
}

/// Socket type.
///
/// Determines the transport-layer protocol the network service associates
/// with a new socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketType {
    /// Stream socket (`SOCK_STREAM` equivalent). Uses TCP for reliable,
    /// ordered, byte-stream delivery.
    Stream,
    /// Datagram socket (`SOCK_DGRAM` equivalent). Uses UDP for unreliable,
    /// connectionless, message-boundary-preserving delivery.
    Dgram,
    /// Raw socket (`SOCK_RAW` equivalent). Exposes the raw `IPv4` payload
    /// directly, bypassing transport-layer framing. Used for ICMP and
    /// other protocols layered directly over IP. Requires elevated
    /// capability.
    Raw,
}

/// Opaque socket handle.
///
/// Assigned by the `nexacore-net` network service when a socket is successfully
/// created via [`SocketRequest::Socket`]. Valid only within the IPC session
/// that created it; MUST NOT be shared across processes or serialized into
/// persistent storage.
///
/// The inner `u64` MUST be treated as an opaque identifier. Its internal
/// structure is an implementation detail of the network service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SocketHandle(
    /// Opaque handle value assigned by the network service.
    pub u64,
);

/// Shutdown direction for [`SocketRequest::Shutdown`].
///
/// Mirrors the `how` parameter of POSIX `shutdown(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShutdownHow {
    /// Disallow further receives on this socket (`SHUT_RD`).
    Read,
    /// Disallow further sends on this socket (`SHUT_WR`).
    Write,
    /// Disallow both further sends and receives (`SHUT_RDWR`).
    Both,
}

/// Socket option values for [`SocketRequest::SetSockOpt`].
///
/// Each variant bundles the option identifier and its value so that the
/// encoding is self-describing. New options MUST be added as new variants;
/// existing variants MUST NOT be removed or reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SocketOption {
    /// Enable or disable local address reuse (`SO_REUSEADDR`).
    ///
    /// When `true`, the network service permits binding to a port that is in
    /// `TIME_WAIT` state. Default: `false`.
    ReuseAddr(bool),
    /// Enable or disable TCP keep-alive probes (`SO_KEEPALIVE`).
    ///
    /// When `true`, the TCP stack sends periodic keep-alive probes on idle
    /// connections. Only meaningful on `Stream` sockets. Default: `false`.
    KeepAlive(bool),
    /// Enable or disable the Nagle algorithm (`TCP_NODELAY`).
    ///
    /// When `true`, small writes are sent immediately without buffering.
    /// Only meaningful on `Stream` sockets. Default: `false`.
    NoDelay(bool),
    /// Set the receive timeout in microseconds (`SO_RCVTIMEO`).
    ///
    /// A value of `0` disables the timeout (blocking receive). The network
    /// service returns [`NetError::TimedOut`] when a receive blocks longer
    /// than the configured timeout.
    RecvTimeout(u64),
    /// Set the send timeout in microseconds (`SO_SNDTIMEO`).
    ///
    /// A value of `0` disables the timeout (blocking send). The network
    /// service returns [`NetError::TimedOut`] when a send blocks longer than
    /// the configured timeout.
    SendTimeout(u64),
    /// Enable or disable broadcast sends (`SO_BROADCAST`).
    ///
    /// When `true`, the socket is permitted to send to `IPv4` broadcast
    /// addresses. Only meaningful on `Dgram` sockets. Default: `false`.
    Broadcast(bool),
}

/// Network error codes returned inside [`SocketResponse::Error`].
///
/// These are deliberately modelled after POSIX `errno` semantics so that
/// existing userspace code can map them with minimal adaptation. However,
/// they are a value type on the IPC wire, not kernel integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetError {
    /// The remote endpoint actively refused the connection (`ECONNREFUSED`).
    ConnectionRefused,
    /// The connection was forcibly reset by the remote end (`ECONNRESET`).
    ConnectionReset,
    /// The connection was aborted by the local network stack (`ECONNABORTED`).
    ConnectionAborted,
    /// The network is unreachable from this host (`ENETUNREACH`).
    NetworkUnreachable,
    /// The remote host is unreachable from this host (`EHOSTUNREACH`).
    HostUnreachable,
    /// The operation timed out before completing (`ETIMEDOUT`).
    TimedOut,
    /// The requested local address is already in use (`EADDRINUSE`).
    AddrInUse,
    /// The requested local address is not available on this interface
    /// (`EADDRNOTAVAIL`).
    AddrNotAvailable,
    /// The operation would block on a non-blocking socket (`EWOULDBLOCK` /
    /// `EAGAIN`).
    WouldBlock,
    /// One of the arguments passed to the request is invalid (`EINVAL`).
    InvalidArgument,
    /// The socket is not connected (`ENOTCONN`).
    NotConnected,
    /// The socket is already connected (`EISCONN`).
    AlreadyConnected,
    /// The remote end closed its write side and data remains unread
    /// (`EPIPE`).
    BrokenPipe,
    /// The caller does not hold the capability required for this operation
    /// (`EPERM` / `EACCES`).
    PermissionDenied,
    /// The caller-supplied buffer is too small to hold the full datagram or
    /// resolved address list (`EMSGSIZE` / `ENOBUFS`).
    BufferTooSmall,
    /// The supplied [`SocketHandle`] is not valid or has already been closed
    /// (`EBADF`).
    BadFileDescriptor,
}

// =============================================================================
// SocketApiAddr
// =============================================================================

/// Socket address used in the socket API IPC protocol.
///
/// Encodes an `IPv4` endpoint as a 4-byte address in network byte order and a
/// 16-bit port in network byte order. `IPv6` support is reserved for a future
/// NCIP; the field names are intentionally unqualified to allow a v2
/// extension.
///
/// Distinct from any `SocketAddr` defined in other modules to avoid circular
/// dependencies between `nexacore-types` sub-modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SocketApiAddr {
    /// `IPv4` address as 4 bytes in network (big-endian) byte order.
    ///
    /// For the loopback address `127.0.0.1` this is `[127, 0, 0, 1]`.
    pub ip: [u8; 4],
    /// Port number in network (big-endian) byte order.
    ///
    /// Port `0` instructs the network service to assign an ephemeral port
    /// (only valid on [`SocketRequest::Bind`]).
    pub port: u16,
}

// =============================================================================
// SocketInfo
// =============================================================================

/// Compact connection information for netstat-style listings.
///
/// Returned as elements of [`SocketResponse::SocketList`] in response to
/// [`SocketRequest::ListSockets`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SocketInfo {
    /// Transport protocol of the socket.
    pub protocol: SocketType,
    /// Local endpoint address.
    pub local_addr: SocketApiAddr,
    /// Remote endpoint address. For listening or unconnected sockets this
    /// field is `[0, 0, 0, 0]:0`.
    pub remote_addr: SocketApiAddr,
    /// Human-readable connection state string (e.g., `"LISTEN"`,
    /// `"ESTABLISHED"`, `"TIME_WAIT"`).
    pub state: String,
}

// =============================================================================
// SocketRequest — userspace-facing
// =============================================================================

/// A request from a userspace program to the `nexacore-net` network service.
///
/// Every variant corresponds to one BSD socket operation. The network service
/// processes requests sequentially per client connection and MUST reply to
/// each request with exactly one [`SocketResponse`] message.
///
/// All variants use `repr(Rust)` because the canonical wire format is
/// `postcard`-encoded via [`crate::wire::encode_canonical`]; the in-memory
/// layout is irrelevant for the cross-process contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SocketRequest {
    /// Create a new socket and return a [`SocketHandle`].
    ///
    /// On success the network service replies with
    /// [`SocketResponse::Handle`]. On failure it replies with
    /// [`SocketResponse::Error`].
    Socket {
        /// Address family for the new socket.
        domain: SocketDomain,
        /// Transport type for the new socket.
        sock_type: SocketType,
    },
    /// Bind a socket to a local address.
    ///
    /// Equivalent to POSIX `bind(2)`. A `port` of `0` in `addr` requests
    /// an ephemeral port assignment; the assigned port is returned in the
    /// response's [`SocketApiAddr`].
    Bind {
        /// Socket to bind.
        handle: SocketHandle,
        /// Local address to bind to.
        addr: SocketApiAddr,
    },
    /// Mark a bound TCP socket as passive (listening).
    ///
    /// Equivalent to POSIX `listen(2)`. `backlog` is the maximum number of
    /// pending connections the kernel will queue before rejecting new
    /// connection attempts.
    Listen {
        /// Socket to mark as listening.
        handle: SocketHandle,
        /// Maximum number of pending connections in the accept queue.
        backlog: u32,
    },
    /// Accept the next pending connection from a listening socket.
    ///
    /// Equivalent to POSIX `accept(2)`. On success the network service
    /// allocates a new socket for the accepted connection and replies with
    /// [`SocketResponse::Handle`] containing its handle. The caller is
    /// responsible for closing the accepted socket when done.
    Accept {
        /// Listening socket to accept from.
        handle: SocketHandle,
    },
    /// Initiate a connection to a remote address.
    ///
    /// Equivalent to POSIX `connect(2)`. For `Stream` sockets, completes
    /// after the TCP three-way handshake. For `Dgram` sockets, sets the
    /// default remote address for subsequent `Send` calls.
    Connect {
        /// Socket to connect.
        handle: SocketHandle,
        /// Remote endpoint to connect to.
        addr: SocketApiAddr,
    },
    /// Send data on a connected socket.
    ///
    /// Equivalent to POSIX `send(2)`. The `flags` field is reserved for
    /// future use; callers MUST set it to `0`.
    Send {
        /// Socket to send on. Must be connected.
        handle: SocketHandle,
        /// Bytes to send.
        data: Vec<u8>,
        /// Send flags (reserved, must be `0`).
        flags: u32,
    },
    /// Receive data from a connected socket.
    ///
    /// Equivalent to POSIX `recv(2)`. The network service reads at most
    /// `max_len` bytes and returns them in [`SocketResponse::Data`].
    Recv {
        /// Socket to receive from. Must be connected.
        handle: SocketHandle,
        /// Maximum number of bytes to return.
        max_len: u32,
        /// Receive flags (reserved, must be `0`).
        flags: u32,
    },
    /// Send data to a specific remote address (connectionless).
    ///
    /// Equivalent to POSIX `sendto(2)`. Primarily used with `Dgram`
    /// sockets. The `flags` field is reserved; callers MUST set it to `0`.
    SendTo {
        /// Socket to send on.
        handle: SocketHandle,
        /// Bytes to send.
        data: Vec<u8>,
        /// Destination address.
        addr: SocketApiAddr,
    },
    /// Receive data and the sender's address (connectionless).
    ///
    /// Equivalent to POSIX `recvfrom(2)`. The network service returns both
    /// the payload and the sender's address in [`SocketResponse::DataFrom`].
    RecvFrom {
        /// Socket to receive from.
        handle: SocketHandle,
        /// Maximum number of bytes to return.
        max_len: u32,
    },
    /// Close a socket and release its resources.
    ///
    /// Equivalent to POSIX `close(2)` on a socket. After a `Close` the
    /// [`SocketHandle`] is invalid and MUST NOT be reused. The network
    /// service replies with [`SocketResponse::Ok`] after all resources are
    /// freed.
    Close {
        /// Socket to close.
        handle: SocketHandle,
    },
    /// Retrieve the local address bound to a socket.
    ///
    /// Equivalent to POSIX `getsockname(2)`. The network service replies
    /// with [`SocketResponse::Addr`].
    GetSockName {
        /// Socket to query.
        handle: SocketHandle,
    },
    /// Retrieve the remote address a socket is connected to.
    ///
    /// Equivalent to POSIX `getpeername(2)`. Returns
    /// [`NetError::NotConnected`] if the socket is not yet connected.
    GetPeerName {
        /// Socket to query.
        handle: SocketHandle,
    },
    /// Set a socket option.
    ///
    /// Equivalent to a subset of POSIX `setsockopt(2)`. The option and its
    /// value are bundled in the [`SocketOption`] enum so the encoding is
    /// self-describing.
    SetSockOpt {
        /// Socket to configure.
        handle: SocketHandle,
        /// Option to set.
        option: SocketOption,
    },
    /// Shut down part or all of a full-duplex connection.
    ///
    /// Equivalent to POSIX `shutdown(2)`. Does not release the socket's
    /// resources; use [`SocketRequest::Close`] for that.
    Shutdown {
        /// Socket to shut down.
        handle: SocketHandle,
        /// Which direction(s) to shut down.
        how: ShutdownHow,
    },
    /// Resolve a hostname to a list of `IPv4` addresses.
    ///
    /// The network service performs a DNS lookup and returns the results as
    /// [`SocketResponse::Addresses`]. A `hostname` with no `.` is looked up
    /// against `/etc/hosts` first.
    Resolve {
        /// Hostname to resolve (e.g., `"example.com"`, `"localhost"`).
        hostname: String,
    },
    /// List all open sockets managed by the network service.
    ///
    /// Returns [`SocketResponse::SocketList`]. Requires an elevated
    /// capability token; unprivileged clients receive
    /// [`SocketResponse::Error`] with [`NetError::PermissionDenied`].
    ListSockets,
}

// =============================================================================
// SocketResponse — service-emitted
// =============================================================================

/// A response from the `nexacore-net` network service to a userspace program.
///
/// Every [`SocketRequest`] receives exactly one [`SocketResponse`]. Callers
/// MUST NOT assume that a successful response from one variant is valid as a
/// response to a different variant; the mapping is documented per
/// [`SocketRequest`] variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SocketResponse {
    /// The request completed successfully; the inner `u64` carries the
    /// number of bytes transferred (for `Send`, `SendTo`) or `0` for
    /// operations with no byte count (`Bind`, `Listen`, `Connect`,
    /// `SetSockOpt`, `Shutdown`, `Close`).
    Ok(u64),
    /// A new socket handle was allocated successfully (returned for
    /// [`SocketRequest::Socket`] and [`SocketRequest::Accept`]).
    Handle(SocketHandle),
    /// Payload bytes received from the network (returned for
    /// [`SocketRequest::Recv`]).
    Data(Vec<u8>),
    /// A local or remote socket address (returned for
    /// [`SocketRequest::GetSockName`], [`SocketRequest::GetPeerName`]).
    Addr(SocketApiAddr),
    /// Payload bytes and sender address (returned for
    /// [`SocketRequest::RecvFrom`]).
    DataFrom(Vec<u8>, SocketApiAddr),
    /// A list of resolved addresses (returned for
    /// [`SocketRequest::Resolve`]).
    Addresses(Vec<SocketApiAddr>),
    /// The request failed; the inner [`NetError`] identifies the cause.
    Error(NetError),
    /// A compact list of open socket connections (returned for
    /// [`SocketRequest::ListSockets`]).
    SocketList(Vec<SocketInfo>),
    /// The request cannot be answered synchronously; the real response will be
    /// delivered later on the same reply path once the operation completes.
    ///
    /// Returned by [`crate::socket::SocketRequest::Connect`] when the network
    /// service defers the reply until the TCP handshake reaches `ESTABLISHED`
    /// (or fails). This variant is an **internal service ⇄ service-loop signal
    /// only**: the service loop MUST hold the userspace reply back when it sees
    /// `Pending`, and forward the later `Ok`/`Error` instead. It is therefore
    /// never delivered to a blocking syscall relay.
    Pending,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec, vec::Vec};

    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    // Convenience constructor for a loopback address.
    fn loopback(port: u16) -> SocketApiAddr {
        SocketApiAddr {
            ip: [127, 0, 0, 1],
            port,
        }
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    #[test]
    fn socket_api_channel_is_correct() {
        assert_eq!(SOCKET_API_CHANNEL, "nexacore.svc.net.stack");
    }

    #[test]
    fn net_config_channel_is_correct() {
        assert_eq!(NET_CONFIG_CHANNEL, "nexacore.svc.net.config");
    }

    #[test]
    fn net_config_reply_channel_is_correct() {
        assert_eq!(NET_CONFIG_REPLY_CHANNEL, "nexacore.svc.net.config_reply");
    }

    // -------------------------------------------------------------------------
    // Scalar type round-trips
    // -------------------------------------------------------------------------

    #[test]
    fn socket_domain_inet_round_trip() {
        let value = SocketDomain::Inet;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketDomain = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_domain_inet6_round_trip() {
        let value = SocketDomain::Inet6;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketDomain = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_type_variants_round_trip() {
        for value in [SocketType::Stream, SocketType::Dgram, SocketType::Raw] {
            let bytes = encode_canonical(&value).expect("encode");
            let decoded: SocketType = decode_canonical(&bytes).expect("decode");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn shutdown_how_variants_round_trip() {
        for value in [ShutdownHow::Read, ShutdownHow::Write, ShutdownHow::Both] {
            let bytes = encode_canonical(&value).expect("encode");
            let decoded: ShutdownHow = decode_canonical(&bytes).expect("decode");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn socket_option_reuse_addr_round_trip() {
        for &on in &[true, false] {
            let value = SocketOption::ReuseAddr(on);
            let bytes = encode_canonical(&value).expect("encode");
            let decoded: SocketOption = decode_canonical(&bytes).expect("decode");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn socket_option_keep_alive_round_trip() {
        let value = SocketOption::KeepAlive(true);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketOption = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_option_no_delay_round_trip() {
        let value = SocketOption::NoDelay(true);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketOption = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_option_recv_timeout_round_trip() {
        let value = SocketOption::RecvTimeout(5_000_000);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketOption = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_option_send_timeout_round_trip() {
        let value = SocketOption::SendTimeout(0);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketOption = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_option_broadcast_round_trip() {
        let value = SocketOption::Broadcast(false);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketOption = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // NetError round-trips
    // -------------------------------------------------------------------------

    #[test]
    fn net_error_all_variants_round_trip() {
        // Exhaustive list intentional: if a new variant is added, this test
        // must be updated, which forces the author to verify the wire
        // encoding is stable.
        let variants = [
            NetError::ConnectionRefused,
            NetError::ConnectionReset,
            NetError::ConnectionAborted,
            NetError::NetworkUnreachable,
            NetError::HostUnreachable,
            NetError::TimedOut,
            NetError::AddrInUse,
            NetError::AddrNotAvailable,
            NetError::WouldBlock,
            NetError::InvalidArgument,
            NetError::NotConnected,
            NetError::AlreadyConnected,
            NetError::BrokenPipe,
            NetError::PermissionDenied,
            NetError::BufferTooSmall,
            NetError::BadFileDescriptor,
        ];
        for value in variants {
            let bytes = encode_canonical(&value).expect("encode");
            let decoded: NetError = decode_canonical(&bytes).expect("decode");
            assert_eq!(decoded, value);
        }
    }

    // -------------------------------------------------------------------------
    // SocketApiAddr round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn socket_api_addr_round_trip() {
        let value = loopback(8080);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketApiAddr = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // SocketRequest round-trips — one per variant
    // -------------------------------------------------------------------------

    #[test]
    fn socket_request_socket_round_trip() {
        let value = SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_bind_round_trip() {
        let value = SocketRequest::Bind {
            handle: SocketHandle(42),
            addr: loopback(8080),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_listen_round_trip() {
        let value = SocketRequest::Listen {
            handle: SocketHandle(1),
            backlog: 128,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_accept_round_trip() {
        let value = SocketRequest::Accept {
            handle: SocketHandle(7),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_connect_round_trip() {
        let value = SocketRequest::Connect {
            handle: SocketHandle(3),
            addr: SocketApiAddr {
                ip: [93, 184, 216, 34],
                port: 443,
            },
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_send_round_trip() {
        let value = SocketRequest::Send {
            handle: SocketHandle(5),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            flags: 0,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_recv_round_trip() {
        let value = SocketRequest::Recv {
            handle: SocketHandle(5),
            max_len: 4096,
            flags: 0,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_send_to_round_trip() {
        let value = SocketRequest::SendTo {
            handle: SocketHandle(9),
            data: vec![1, 2, 3],
            addr: loopback(5353),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_recv_from_round_trip() {
        let value = SocketRequest::RecvFrom {
            handle: SocketHandle(11),
            max_len: 1500,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_close_round_trip() {
        let value = SocketRequest::Close {
            handle: SocketHandle(100),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_get_sock_name_round_trip() {
        let value = SocketRequest::GetSockName {
            handle: SocketHandle(2),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_get_peer_name_round_trip() {
        let value = SocketRequest::GetPeerName {
            handle: SocketHandle(2),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_set_sock_opt_round_trip() {
        let value = SocketRequest::SetSockOpt {
            handle: SocketHandle(3),
            option: SocketOption::NoDelay(true),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_shutdown_round_trip() {
        let value = SocketRequest::Shutdown {
            handle: SocketHandle(4),
            how: ShutdownHow::Both,
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_resolve_round_trip() {
        let value = SocketRequest::Resolve {
            hostname: "example.com".to_string(),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_request_list_sockets_round_trip() {
        let value = SocketRequest::ListSockets;
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // SocketResponse round-trips — one per variant
    // -------------------------------------------------------------------------

    #[test]
    fn socket_response_ok_round_trip() {
        let value = SocketResponse::Ok(0);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_ok_with_byte_count_round_trip() {
        let value = SocketResponse::Ok(1024);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_handle_round_trip() {
        let value = SocketResponse::Handle(SocketHandle(0xDEAD_BEEF_CAFE_BABE));
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_data_round_trip() {
        let value = SocketResponse::Data(vec![0xCA, 0xFE, 0xBA, 0xBE]);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_addr_round_trip() {
        let value = SocketResponse::Addr(loopback(80));
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_data_from_round_trip() {
        let value = SocketResponse::DataFrom(vec![1, 2, 3], loopback(12345));
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_addresses_round_trip() {
        let value = SocketResponse::Addresses(vec![
            SocketApiAddr {
                ip: [1, 1, 1, 1],
                port: 0,
            },
            SocketApiAddr {
                ip: [8, 8, 8, 8],
                port: 0,
            },
        ]);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_error_round_trip() {
        let value = SocketResponse::Error(NetError::ConnectionRefused);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn socket_response_socket_list_round_trip() {
        let value = SocketResponse::SocketList(vec![SocketInfo {
            protocol: SocketType::Stream,
            local_addr: loopback(8080),
            remote_addr: SocketApiAddr {
                ip: [10, 0, 0, 1],
                port: 50234,
            },
            state: "ESTABLISHED".to_string(),
        }]);
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    // -------------------------------------------------------------------------
    // Wire-format invariants
    // -------------------------------------------------------------------------

    #[test]
    fn socket_request_encoding_is_deterministic() {
        let value = SocketRequest::Connect {
            handle: SocketHandle(1),
            addr: loopback(443),
        };
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn socket_response_encoding_is_deterministic() {
        let value = SocketResponse::Error(NetError::TimedOut);
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn socket_request_decode_rejects_trailing_bytes() {
        let value = SocketRequest::ListSockets;
        let mut bytes = encode_canonical(&value).expect("encode");
        bytes.push(0x00);
        let err = decode_canonical::<SocketRequest>(&bytes).expect_err("must reject trailing");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    #[test]
    fn socket_response_decode_rejects_trailing_bytes() {
        let value = SocketResponse::Ok(0);
        let mut bytes = encode_canonical(&value).expect("encode");
        bytes.push(0xFF);
        let err = decode_canonical::<SocketResponse>(&bytes).expect_err("must reject trailing");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    #[test]
    fn socket_response_decode_rejects_empty_input() {
        let err = decode_canonical::<SocketResponse>(&[]).expect_err("must reject empty");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    #[test]
    fn socket_request_decode_rejects_truncated_input() {
        let value = SocketRequest::Send {
            handle: SocketHandle(1),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
            flags: 0,
        };
        let bytes = encode_canonical(&value).expect("encode");
        assert!(bytes.len() >= 2, "encoding sanity check");
        let truncated = &bytes[..bytes.len() - 1];
        let err = decode_canonical::<SocketRequest>(truncated).expect_err("must reject truncated");
        assert!(matches!(err, crate::NexaCoreError::Wire { .. }));
    }

    // -------------------------------------------------------------------------
    // Cross-variant integration
    // -------------------------------------------------------------------------

    #[test]
    fn request_and_response_buffers_share_no_state() {
        let req = SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Dgram,
        };
        let resp = SocketResponse::Handle(SocketHandle(99));
        let req_bytes: Vec<u8> = encode_canonical(&req).expect("encode-req");
        let resp_bytes: Vec<u8> = encode_canonical(&resp).expect("encode-resp");
        let req2: SocketRequest = decode_canonical(&req_bytes).expect("decode-req");
        let resp2: SocketResponse = decode_canonical(&resp_bytes).expect("decode-resp");
        assert_eq!(req2, req);
        assert_eq!(resp2, resp);
        assert_ne!(req_bytes, resp_bytes);
    }

    #[test]
    fn socket_info_round_trip() {
        let value = SocketInfo {
            protocol: SocketType::Dgram,
            local_addr: loopback(5353),
            remote_addr: SocketApiAddr {
                ip: [0, 0, 0, 0],
                port: 0,
            },
            state: "UNCONNECTED".to_string(),
        };
        let bytes = encode_canonical(&value).expect("encode");
        let decoded: SocketInfo = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }
}

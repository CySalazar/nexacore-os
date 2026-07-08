//! Socket API wrappers for NexaCore OS userspace programs.
//!
//! These functions map 1:1 to kernel syscall numbers 103–113.
//! In a running NexaCore OS system they are invoked by the userspace runtime
//! bootstrap via the `KernelSyscall` backend; in tests and on
//! developer hosts they operate as pure encoding/decoding helpers that can
//! be exercised without a real kernel.
//!
//! # Design
//!
//! Every public item in this module is either:
//! - A syscall number constant in [`crate::net::syscall_nr`], or
//! - A *request builder* — a free function that constructs a
//!   `SocketRequest` variant. Builders are deliberately trivial (one
//!   line each) so that callers never have to name the internal struct
//!   fields and so that the call site reads like a real POSIX function.
//! - [`crate::net::encode_socket_request`] / [`crate::net::decode_socket_response`] — canonical
//!   wire encoding wrappers that go through [`nexacore_types::wire`] (the
//!   single audit point for postcard encoding in this workspace).
//! - [`crate::net::errno_from_raw`] — maps raw `u64` errno codes from the kernel's
//!   two-register return path to the typed [`crate::net::NetErrno`] enum.
//!
//! # Feature flags
//!
//! This module is compiled unconditionally (both with and without the
//! `bare-metal` feature).  When `bare-metal` is active, `alloc::vec::Vec`
//! and `alloc::string::String` are used; otherwise the `std` versions are
//! used.  The types are re-exported from `nexacore-types` which already handles
//! this distinction, so no conditional `use` is needed here.
//!
//! # ABI note
//!
//! Kernel syscalls 103–113 are *thin capability-checked relays*: the kernel
//! validates that the caller holds the `Net` capability token, serialises
//! the arguments into a `SocketRequest` (using the same postcard encoding
//! defined in [`crate::net::encode_socket_request`]), and forwards the message to the
//! `nexacore-net` user-space network service over the `nexacore.svc.net.stack` IPC
//! channel. The service replies with a `SocketResponse` that the kernel
//! deserialises and surfaces to the calling process.
//!
//! # Examples
//!
//! Build and encode a `Socket` request:
//!
//! ```rust
//! use nexacore_types::socket::{SocketDomain, SocketType};
//! use nexacore_usys::net::{encode_socket_request, socket_request};
//!
//! let req = socket_request(SocketDomain::Inet, SocketType::Stream);
//! # #[allow(clippy::expect_used)]
//! let bytes = encode_socket_request(&req).expect("encode");
//! assert!(!bytes.is_empty());
//! ```

#[cfg(feature = "bare-metal")]
use alloc::{string::String, vec::Vec};
#[cfg(not(feature = "bare-metal"))]
use std::{string::String, vec::Vec};

use nexacore_types::{
    NexaCoreError,
    socket::{
        ShutdownHow, SocketApiAddr, SocketDomain, SocketHandle, SocketOption, SocketRequest,
        SocketResponse, SocketType,
    },
    wire,
};

// =============================================================================
// Syscall number constants
// =============================================================================

/// Kernel syscall numbers for network operations.
///
/// These constants match the `SyscallNumber` enum in
/// `crates/nexacore-kernel/src/syscall.rs` for the `100..=113` range reserved for
/// the NET service-channel registry and socket IPC relay (NCIP-Driver-Net-015
/// § S2).
///
/// Callers MUST use these constants — never hard-code literal integers — so
/// that a renumbering in the kernel ABI causes a single-point compile error
/// rather than a silent mismatch.
pub mod syscall_nr {
    /// Register an `nexacore.svc.net.<interface>` channel pair (`NetRegister`).
    pub const NET_REGISTER: u32 = 100;
    /// Remove an `nexacore.svc.net.<interface>` mapping (`NetUnregister`).
    pub const NET_UNREGISTER: u32 = 101;
    /// Resolve `nexacore.svc.net.<interface>` to its live channel id (`NetLookup`).
    pub const NET_LOOKUP: u32 = 102;
    /// Create a new socket handle via the `nexacore-net` service (`NetSocket`).
    pub const NET_SOCKET: u32 = 103;
    /// Bind a socket to a local address (`NetBind`).
    pub const NET_BIND: u32 = 104;
    /// Mark a socket as passive/listening (`NetListen`).
    pub const NET_LISTEN: u32 = 105;
    /// Accept the next pending connection (`NetAccept`).
    pub const NET_ACCEPT: u32 = 106;
    /// Initiate a connection to a remote address (`NetConnect`).
    pub const NET_CONNECT: u32 = 107;
    /// Send data on a connected socket (`NetSend`).
    pub const NET_SEND: u32 = 108;
    /// Receive data from a connected socket (`NetRecv`).
    pub const NET_RECV: u32 = 109;
    /// Send data to a specific remote address (`NetSendTo`).
    pub const NET_SENDTO: u32 = 110;
    /// Receive data and the sender's address (`NetRecvFrom`).
    pub const NET_RECVFROM: u32 = 111;
    /// Close a socket and release its resources (`NetClose`).
    pub const NET_CLOSE: u32 = 112;
    /// Shut down part or all of a full-duplex connection (`NetShutdown`).
    pub const NET_SHUTDOWN: u32 = 113;
}

// =============================================================================
// NetErrno
// =============================================================================

/// Typed network errno codes returned from kernel socket syscalls.
///
/// Numeric values are aligned with POSIX / Linux `errno-base.h` and the
/// kernel's `syscall_errno` constants (see
/// `crates/nexacore-kernel/src/syscall.rs`).  The name `NetErrno` is distinct
/// from [`crate::Errno`] (the general syscall errno type) to make call-site
/// intent unambiguous.
///
/// # Example
///
/// ```rust
/// use nexacore_usys::net::{NetErrno, errno_from_raw};
///
/// let e = errno_from_raw(111);
/// assert_eq!(e, NetErrno::ConnectionRefused);
/// let e2 = errno_from_raw(99999);
/// assert_eq!(e2, NetErrno::Unknown(99999));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetErrno {
    /// Address already in use (`EADDRINUSE = 98`).
    AddrInUse,
    /// Connection refused by remote endpoint (`ECONNREFUSED = 111`).
    ConnectionRefused,
    /// Connection timed out (`ETIMEDOUT = 110`).
    TimedOut,
    /// Network unreachable from this host (`ENETUNREACH = 101`).
    NetworkUnreachable,
    /// Remote host unreachable from this host (`EHOSTUNREACH = 113`).
    HostUnreachable,
    /// Connection reset by peer (`ECONNRESET = 104`).
    ConnectionReset,
    /// Connection aborted by local network stack (`ECONNABORTED = 103`).
    ConnectionAborted,
    /// Socket is not connected (`ENOTCONN = 107`).
    NotConnected,
    /// Socket is already connected (`EISCONN = 106`).
    AlreadyConnected,
    /// Bad file descriptor — handle is invalid or closed (`EBADF = 9`).
    BadFd,
    /// Invalid argument supplied to a socket syscall (`EINVAL = 22`).
    InvalidArgument,
    /// Permission denied — capability token not held (`EACCES = 13`).
    PermissionDenied,
    /// Broken pipe — remote end has closed its write side (`EPIPE = 32`).
    BrokenPipe,
    /// Unknown or unmapped errno code. The raw value is preserved so callers
    /// can log it without losing information.
    Unknown(u64),
}

impl core::fmt::Display for NetErrno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AddrInUse => f.write_str("address already in use"),
            Self::ConnectionRefused => f.write_str("connection refused"),
            Self::TimedOut => f.write_str("connection timed out"),
            Self::NetworkUnreachable => f.write_str("network unreachable"),
            Self::HostUnreachable => f.write_str("host unreachable"),
            Self::ConnectionReset => f.write_str("connection reset by peer"),
            Self::ConnectionAborted => f.write_str("connection aborted"),
            Self::NotConnected => f.write_str("socket is not connected"),
            Self::AlreadyConnected => f.write_str("socket is already connected"),
            Self::BadFd => f.write_str("bad file descriptor"),
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::PermissionDenied => f.write_str("permission denied"),
            Self::BrokenPipe => f.write_str("broken pipe"),
            Self::Unknown(code) => write!(f, "unknown network error (code {code})"),
        }
    }
}

// =============================================================================
// errno_from_raw
// =============================================================================

/// Map a raw `u64` errno code from the kernel two-register return path to
/// a typed [`NetErrno`] variant.
///
/// Unknown codes are preserved in [`NetErrno::Unknown`] so no information
/// is lost when an unexpected value arrives from a future kernel version.
///
/// Values are sourced from Linux `errno-base.h` and `errno.h` (the POSIX
/// alignment documented in `crates/nexacore-kernel/src/syscall.rs` §
/// `syscall_errno`).
///
/// # Example
///
/// ```rust
/// use nexacore_usys::net::{NetErrno, errno_from_raw};
///
/// assert_eq!(errno_from_raw(98), NetErrno::AddrInUse);
/// assert_eq!(errno_from_raw(111), NetErrno::ConnectionRefused);
/// assert_eq!(errno_from_raw(110), NetErrno::TimedOut);
/// assert_eq!(errno_from_raw(0), NetErrno::Unknown(0));
/// ```
#[must_use]
pub fn errno_from_raw(code: u64) -> NetErrno {
    match code {
        98 => NetErrno::AddrInUse,
        111 => NetErrno::ConnectionRefused,
        110 => NetErrno::TimedOut,
        101 => NetErrno::NetworkUnreachable,
        113 => NetErrno::HostUnreachable,
        104 => NetErrno::ConnectionReset,
        103 => NetErrno::ConnectionAborted,
        107 => NetErrno::NotConnected,
        106 => NetErrno::AlreadyConnected,
        9 => NetErrno::BadFd,
        22 => NetErrno::InvalidArgument,
        13 => NetErrno::PermissionDenied,
        32 => NetErrno::BrokenPipe,
        other => NetErrno::Unknown(other),
    }
}

// =============================================================================
// Wire encoding helpers
// =============================================================================

/// Encode a [`SocketRequest`] for transmission over the kernel IPC relay.
///
/// Uses [`nexacore_types::wire::encode_canonical`] — the single workspace-level
/// audit point for `postcard` serialisation.  The returned bytes are suitable
/// for placement in a kernel IPC message buffer.
///
/// # Errors
///
/// Returns an [`NexaCoreError::Wire`] if serialisation fails (this is
/// practically unreachable for well-formed in-memory values but the
/// `Result` is kept to be safe and consistent with the rest of the wire
/// API).
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketDomain, SocketType};
/// use nexacore_usys::net::{encode_socket_request, socket_request};
///
/// let req = socket_request(SocketDomain::Inet, SocketType::Stream);
/// # #[allow(clippy::expect_used)]
/// let bytes = encode_socket_request(&req).expect("encode must succeed");
/// assert!(!bytes.is_empty());
/// ```
pub fn encode_socket_request(req: &SocketRequest) -> Result<Vec<u8>, NexaCoreError> {
    wire::encode_canonical(req)
}

/// Decode a [`SocketResponse`] received from the kernel IPC relay.
///
/// Uses [`nexacore_types::wire::decode_canonical`] — the single workspace-level
/// audit point for `postcard` deserialisation.  Trailing bytes in `data`
/// cause a [`NexaCoreError::Wire`] error (consistent with the no-trailing-data
/// property documented in `nexacore-types/src/wire.rs`).
///
/// # Errors
///
/// Returns an [`NexaCoreError::Wire`] if the input is malformed, truncated, or
/// contains trailing bytes past the canonical encoding.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketResponse};
/// use nexacore_usys::net::decode_socket_response;
///
/// // Build a known response, encode it, then decode it back.
/// let resp = SocketResponse::Handle(SocketHandle(42));
/// # #[allow(clippy::expect_used)]
/// let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
/// # #[allow(clippy::expect_used)]
/// let decoded = decode_socket_response(&bytes).expect("decode");
/// assert_eq!(decoded, resp);
/// ```
pub fn decode_socket_response(data: &[u8]) -> Result<SocketResponse, NexaCoreError> {
    wire::decode_canonical(data)
}

// =============================================================================
// Request builder functions
// =============================================================================

/// Build a [`SocketRequest::Socket`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketDomain, SocketRequest, SocketType};
/// use nexacore_usys::net::socket_request;
///
/// let req = socket_request(SocketDomain::Inet, SocketType::Stream);
/// assert!(matches!(
///     req,
///     SocketRequest::Socket {
///         domain: SocketDomain::Inet,
///         sock_type: SocketType::Stream,
///     }
/// ));
/// ```
#[must_use]
pub fn socket_request(domain: SocketDomain, sock_type: SocketType) -> SocketRequest {
    SocketRequest::Socket { domain, sock_type }
}

/// Build a [`SocketRequest::Bind`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketApiAddr, SocketHandle, SocketRequest};
/// use nexacore_usys::net::bind_request;
///
/// let addr = SocketApiAddr {
///     ip: [127, 0, 0, 1],
///     port: 8080,
/// };
/// let req = bind_request(SocketHandle(1), addr);
/// assert!(matches!(
///     req,
///     SocketRequest::Bind {
///         handle: SocketHandle(1),
///         ..
///     }
/// ));
/// ```
#[must_use]
pub fn bind_request(handle: SocketHandle, addr: SocketApiAddr) -> SocketRequest {
    SocketRequest::Bind { handle, addr }
}

/// Build a [`SocketRequest::Listen`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketRequest};
/// use nexacore_usys::net::listen_request;
///
/// let req = listen_request(SocketHandle(2), 128);
/// assert!(matches!(
///     req,
///     SocketRequest::Listen {
///         handle: SocketHandle(2),
///         backlog: 128
///     }
/// ));
/// ```
#[must_use]
pub fn listen_request(handle: SocketHandle, backlog: u32) -> SocketRequest {
    SocketRequest::Listen { handle, backlog }
}

/// Build a [`SocketRequest::Accept`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketRequest};
/// use nexacore_usys::net::accept_request;
///
/// let req = accept_request(SocketHandle(3));
/// assert!(matches!(
///     req,
///     SocketRequest::Accept {
///         handle: SocketHandle(3)
///     }
/// ));
/// ```
#[must_use]
pub fn accept_request(handle: SocketHandle) -> SocketRequest {
    SocketRequest::Accept { handle }
}

/// Build a [`SocketRequest::Connect`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketApiAddr, SocketHandle, SocketRequest};
/// use nexacore_usys::net::connect_request;
///
/// let addr = SocketApiAddr {
///     ip: [93, 184, 216, 34],
///     port: 443,
/// };
/// let req = connect_request(SocketHandle(4), addr);
/// assert!(matches!(
///     req,
///     SocketRequest::Connect {
///         handle: SocketHandle(4),
///         ..
///     }
/// ));
/// ```
#[must_use]
pub fn connect_request(handle: SocketHandle, addr: SocketApiAddr) -> SocketRequest {
    SocketRequest::Connect { handle, addr }
}

/// Build a [`SocketRequest::Send`] request.
///
/// `flags` is reserved for future use; callers MUST pass `0`.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketRequest};
/// use nexacore_usys::net::send_request;
///
/// let req = send_request(SocketHandle(5), vec![0xDE, 0xAD], 0);
/// assert!(matches!(
///     req,
///     SocketRequest::Send {
///         handle: SocketHandle(5),
///         flags: 0,
///         ..
///     }
/// ));
/// ```
#[must_use]
pub fn send_request(handle: SocketHandle, data: Vec<u8>, flags: u32) -> SocketRequest {
    SocketRequest::Send {
        handle,
        data,
        flags,
    }
}

/// Build a [`SocketRequest::Recv`] request.
///
/// `flags` is reserved for future use; callers MUST pass `0`.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketRequest};
/// use nexacore_usys::net::recv_request;
///
/// let req = recv_request(SocketHandle(5), 4096, 0);
/// assert!(matches!(
///     req,
///     SocketRequest::Recv {
///         handle: SocketHandle(5),
///         max_len: 4096,
///         flags: 0
///     }
/// ));
/// ```
#[must_use]
pub fn recv_request(handle: SocketHandle, max_len: u32, flags: u32) -> SocketRequest {
    SocketRequest::Recv {
        handle,
        max_len,
        flags,
    }
}

/// Build a [`SocketRequest::SendTo`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketApiAddr, SocketHandle, SocketRequest};
/// use nexacore_usys::net::sendto_request;
///
/// let addr = SocketApiAddr {
///     ip: [127, 0, 0, 1],
///     port: 5353,
/// };
/// let req = sendto_request(SocketHandle(6), vec![1, 2, 3], addr);
/// assert!(matches!(
///     req,
///     SocketRequest::SendTo {
///         handle: SocketHandle(6),
///         ..
///     }
/// ));
/// ```
#[must_use]
pub fn sendto_request(handle: SocketHandle, data: Vec<u8>, addr: SocketApiAddr) -> SocketRequest {
    SocketRequest::SendTo { handle, data, addr }
}

/// Build a [`SocketRequest::RecvFrom`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketRequest};
/// use nexacore_usys::net::recvfrom_request;
///
/// let req = recvfrom_request(SocketHandle(7), 1500);
/// assert!(matches!(
///     req,
///     SocketRequest::RecvFrom {
///         handle: SocketHandle(7),
///         max_len: 1500
///     }
/// ));
/// ```
#[must_use]
pub fn recvfrom_request(handle: SocketHandle, max_len: u32) -> SocketRequest {
    SocketRequest::RecvFrom { handle, max_len }
}

/// Build a [`SocketRequest::Close`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketRequest};
/// use nexacore_usys::net::close_request;
///
/// let req = close_request(SocketHandle(8));
/// assert!(matches!(
///     req,
///     SocketRequest::Close {
///         handle: SocketHandle(8)
///     }
/// ));
/// ```
#[must_use]
pub fn close_request(handle: SocketHandle) -> SocketRequest {
    SocketRequest::Close { handle }
}

/// Build a [`SocketRequest::Shutdown`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{ShutdownHow, SocketHandle, SocketRequest};
/// use nexacore_usys::net::shutdown_request;
///
/// let req = shutdown_request(SocketHandle(9), ShutdownHow::Both);
/// assert!(matches!(
///     req,
///     SocketRequest::Shutdown {
///         handle: SocketHandle(9),
///         how: ShutdownHow::Both,
///     }
/// ));
/// ```
#[must_use]
pub fn shutdown_request(handle: SocketHandle, how: ShutdownHow) -> SocketRequest {
    SocketRequest::Shutdown { handle, how }
}

/// Build a [`SocketRequest::SetSockOpt`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::{SocketHandle, SocketOption, SocketRequest};
/// use nexacore_usys::net::setsockopt_request;
///
/// let req = setsockopt_request(SocketHandle(10), SocketOption::NoDelay(true));
/// assert!(matches!(
///     req,
///     SocketRequest::SetSockOpt {
///         handle: SocketHandle(10),
///         option: SocketOption::NoDelay(true),
///     }
/// ));
/// ```
#[must_use]
pub fn setsockopt_request(handle: SocketHandle, opt: SocketOption) -> SocketRequest {
    SocketRequest::SetSockOpt {
        handle,
        option: opt,
    }
}

/// Build a [`SocketRequest::Resolve`] request.
///
/// # Example
///
/// ```rust
/// use nexacore_types::socket::SocketRequest;
/// use nexacore_usys::net::resolve_request;
///
/// let req = resolve_request("example.com".to_string());
/// assert!(matches!(req, SocketRequest::Resolve { .. }));
/// ```
#[must_use]
pub fn resolve_request(hostname: String) -> SocketRequest {
    SocketRequest::Resolve { hostname }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // In bare-metal mode the std prelude is absent; `.to_string()` requires
    // `ToString` to be explicitly in scope.
    #[cfg(feature = "bare-metal")]
    use alloc::string::ToString;
    #[cfg(feature = "bare-metal")]
    use alloc::vec;

    use nexacore_types::socket::{NetError, SocketInfo};

    use super::*;

    // Convenience helper: loopback address.
    fn loopback(port: u16) -> SocketApiAddr {
        SocketApiAddr {
            ip: [127, 0, 0, 1],
            port,
        }
    }

    // -------------------------------------------------------------------------
    // syscall_nr constants match kernel values
    // -------------------------------------------------------------------------

    #[test]
    fn syscall_nr_constants_match_kernel() {
        // These assertions are the canonical cross-check against
        // crates/nexacore-kernel/src/syscall.rs. If the kernel renumbers any
        // NET syscall, this test will fail deterministically.
        assert_eq!(syscall_nr::NET_REGISTER, 100);
        assert_eq!(syscall_nr::NET_UNREGISTER, 101);
        assert_eq!(syscall_nr::NET_LOOKUP, 102);
        assert_eq!(syscall_nr::NET_SOCKET, 103);
        assert_eq!(syscall_nr::NET_BIND, 104);
        assert_eq!(syscall_nr::NET_LISTEN, 105);
        assert_eq!(syscall_nr::NET_ACCEPT, 106);
        assert_eq!(syscall_nr::NET_CONNECT, 107);
        assert_eq!(syscall_nr::NET_SEND, 108);
        assert_eq!(syscall_nr::NET_RECV, 109);
        assert_eq!(syscall_nr::NET_SENDTO, 110);
        assert_eq!(syscall_nr::NET_RECVFROM, 111);
        assert_eq!(syscall_nr::NET_CLOSE, 112);
        assert_eq!(syscall_nr::NET_SHUTDOWN, 113);
    }

    // -------------------------------------------------------------------------
    // errno_from_raw — known codes
    // -------------------------------------------------------------------------

    #[test]
    fn errno_from_raw_addr_in_use() {
        assert_eq!(errno_from_raw(98), NetErrno::AddrInUse);
    }

    #[test]
    fn errno_from_raw_connection_refused() {
        assert_eq!(errno_from_raw(111), NetErrno::ConnectionRefused);
    }

    #[test]
    fn errno_from_raw_timed_out() {
        assert_eq!(errno_from_raw(110), NetErrno::TimedOut);
    }

    #[test]
    fn errno_from_raw_network_unreachable() {
        assert_eq!(errno_from_raw(101), NetErrno::NetworkUnreachable);
    }

    #[test]
    fn errno_from_raw_host_unreachable() {
        assert_eq!(errno_from_raw(113), NetErrno::HostUnreachable);
    }

    #[test]
    fn errno_from_raw_connection_reset() {
        assert_eq!(errno_from_raw(104), NetErrno::ConnectionReset);
    }

    #[test]
    fn errno_from_raw_connection_aborted() {
        assert_eq!(errno_from_raw(103), NetErrno::ConnectionAborted);
    }

    #[test]
    fn errno_from_raw_not_connected() {
        assert_eq!(errno_from_raw(107), NetErrno::NotConnected);
    }

    #[test]
    fn errno_from_raw_already_connected() {
        assert_eq!(errno_from_raw(106), NetErrno::AlreadyConnected);
    }

    #[test]
    fn errno_from_raw_bad_fd() {
        assert_eq!(errno_from_raw(9), NetErrno::BadFd);
    }

    #[test]
    fn errno_from_raw_invalid_argument() {
        assert_eq!(errno_from_raw(22), NetErrno::InvalidArgument);
    }

    #[test]
    fn errno_from_raw_permission_denied() {
        assert_eq!(errno_from_raw(13), NetErrno::PermissionDenied);
    }

    #[test]
    fn errno_from_raw_broken_pipe() {
        assert_eq!(errno_from_raw(32), NetErrno::BrokenPipe);
    }

    // -------------------------------------------------------------------------
    // errno_from_raw — unknown code
    // -------------------------------------------------------------------------

    #[test]
    fn errno_from_raw_unknown_preserves_code() {
        assert_eq!(errno_from_raw(0), NetErrno::Unknown(0));
        assert_eq!(errno_from_raw(200), NetErrno::Unknown(200));
        assert_eq!(errno_from_raw(u64::MAX), NetErrno::Unknown(u64::MAX));
    }

    // -------------------------------------------------------------------------
    // NetErrno Display
    // -------------------------------------------------------------------------

    #[test]
    fn net_errno_display_non_empty() {
        // Every known variant must produce a non-empty message.
        let known = [
            NetErrno::AddrInUse,
            NetErrno::ConnectionRefused,
            NetErrno::TimedOut,
            NetErrno::NetworkUnreachable,
            NetErrno::HostUnreachable,
            NetErrno::ConnectionReset,
            NetErrno::ConnectionAborted,
            NetErrno::NotConnected,
            NetErrno::AlreadyConnected,
            NetErrno::BadFd,
            NetErrno::InvalidArgument,
            NetErrno::PermissionDenied,
            NetErrno::BrokenPipe,
        ];
        for v in known {
            let msg = v.to_string();
            assert!(!msg.is_empty(), "Display empty for {v:?}");
        }
    }

    #[test]
    fn net_errno_display_unknown_includes_code() {
        let msg = NetErrno::Unknown(42).to_string();
        assert!(msg.contains("42"), "expected code 42 in: {msg}");
    }

    // -------------------------------------------------------------------------
    // encode_socket_request / decode_socket_response round-trips
    // -------------------------------------------------------------------------

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_socket() {
        let req = socket_request(SocketDomain::Inet, SocketType::Stream);
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_bind() {
        let req = bind_request(SocketHandle(1), loopback(8080));
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_listen() {
        let req = listen_request(SocketHandle(2), 128);
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_accept() {
        let req = accept_request(SocketHandle(3));
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_connect() {
        let addr = SocketApiAddr {
            ip: [93, 184, 216, 34],
            port: 443,
        };
        let req = connect_request(SocketHandle(4), addr);
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_send() {
        let req = send_request(SocketHandle(5), vec![0xDE, 0xAD, 0xBE, 0xEF], 0);
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_recv() {
        let req = recv_request(SocketHandle(5), 4096, 0);
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_sendto() {
        let req = sendto_request(SocketHandle(6), vec![1, 2, 3], loopback(5353));
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_recvfrom() {
        let req = recvfrom_request(SocketHandle(7), 1500);
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_close() {
        let req = close_request(SocketHandle(8));
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_shutdown() {
        let req = shutdown_request(SocketHandle(9), ShutdownHow::Both);
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_setsockopt() {
        let req = setsockopt_request(SocketHandle(10), SocketOption::NoDelay(true));
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_request_roundtrip_resolve() {
        let req = resolve_request("example.com".to_string());
        let bytes = encode_socket_request(&req).expect("encode");
        let decoded: SocketRequest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    // -------------------------------------------------------------------------
    // decode_socket_response round-trips
    // -------------------------------------------------------------------------

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_ok() {
        let resp = SocketResponse::Ok(0);
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_handle() {
        let resp = SocketResponse::Handle(SocketHandle(0xDEAD_BEEF));
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_data() {
        let resp = SocketResponse::Data(vec![0xCA, 0xFE, 0xBA, 0xBE]);
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_addr() {
        let resp = SocketResponse::Addr(loopback(80));
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_data_from() {
        let resp = SocketResponse::DataFrom(vec![1, 2, 3], loopback(12345));
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_addresses() {
        let resp = SocketResponse::Addresses(vec![
            SocketApiAddr {
                ip: [1, 1, 1, 1],
                port: 0,
            },
            SocketApiAddr {
                ip: [8, 8, 8, 8],
                port: 0,
            },
        ]);
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_error() {
        let resp = SocketResponse::Error(NetError::ConnectionRefused);
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_decode_socket_response_roundtrip_socket_list() {
        let resp = SocketResponse::SocketList(vec![SocketInfo {
            protocol: SocketType::Stream,
            local_addr: loopback(8080),
            remote_addr: SocketApiAddr {
                ip: [10, 0, 0, 1],
                port: 50234,
            },
            state: "ESTABLISHED".to_string(),
        }]);
        let bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        let decoded = decode_socket_response(&bytes).expect("decode");
        assert_eq!(decoded, resp);
    }

    // -------------------------------------------------------------------------
    // decode_socket_response error cases
    // -------------------------------------------------------------------------

    #[test]
    #[allow(clippy::expect_used)]
    fn decode_socket_response_rejects_empty_input() {
        let err = decode_socket_response(&[]).expect_err("must fail on empty input");
        assert!(matches!(err, NexaCoreError::Wire { .. }));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn decode_socket_response_rejects_trailing_bytes() {
        let resp = SocketResponse::Ok(0);
        let mut bytes = nexacore_types::wire::encode_canonical(&resp).expect("encode");
        bytes.push(0xFF);
        let err = decode_socket_response(&bytes).expect_err("must fail on trailing bytes");
        assert!(matches!(err, NexaCoreError::Wire { .. }));
    }

    // -------------------------------------------------------------------------
    // Builder functions return the correct variant
    // -------------------------------------------------------------------------

    #[test]
    fn builder_socket_correct_variant() {
        let req = socket_request(SocketDomain::Inet, SocketType::Dgram);
        assert!(
            matches!(
                req,
                SocketRequest::Socket {
                    domain: SocketDomain::Inet,
                    sock_type: SocketType::Dgram
                }
            ),
            "unexpected variant: {req:?}"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn builder_bind_stores_handle_and_addr() {
        let addr = loopback(9090);
        let req = bind_request(SocketHandle(77), addr);
        if let SocketRequest::Bind {
            handle,
            addr: stored,
        } = req
        {
            assert_eq!(handle, SocketHandle(77));
            assert_eq!(stored, addr);
        } else {
            panic!("expected Bind variant, got {req:?}");
        }
    }

    #[test]
    #[allow(clippy::panic)]
    fn builder_listen_stores_backlog() {
        let req = listen_request(SocketHandle(1), 256);
        if let SocketRequest::Listen { backlog, .. } = req {
            assert_eq!(backlog, 256);
        } else {
            panic!("expected Listen variant, got {req:?}");
        }
    }

    #[test]
    #[allow(clippy::panic)]
    fn builder_send_stores_data_and_flags() {
        let data = vec![1u8, 2, 3, 4];
        let req = send_request(SocketHandle(5), data.clone(), 0);
        if let SocketRequest::Send {
            data: stored,
            flags,
            ..
        } = req
        {
            assert_eq!(stored, data);
            assert_eq!(flags, 0);
        } else {
            panic!("expected Send variant, got {req:?}");
        }
    }

    #[test]
    #[allow(clippy::panic)]
    fn builder_recv_stores_max_len() {
        let req = recv_request(SocketHandle(6), 2048, 0);
        if let SocketRequest::Recv { max_len, .. } = req {
            assert_eq!(max_len, 2048);
        } else {
            panic!("expected Recv variant, got {req:?}");
        }
    }

    #[test]
    #[allow(clippy::panic)]
    fn builder_setsockopt_stores_option() {
        let req = setsockopt_request(SocketHandle(10), SocketOption::ReuseAddr(true));
        if let SocketRequest::SetSockOpt { option, .. } = req {
            assert_eq!(option, SocketOption::ReuseAddr(true));
        } else {
            panic!("expected SetSockOpt variant, got {req:?}");
        }
    }

    #[test]
    #[allow(clippy::panic)]
    fn builder_resolve_stores_hostname() {
        let req = resolve_request("nexacore-os.org".to_string());
        if let SocketRequest::Resolve { hostname } = req {
            assert_eq!(hostname, "nexacore-os.org");
        } else {
            panic!("expected Resolve variant, got {req:?}");
        }
    }

    // -------------------------------------------------------------------------
    // Encoding is deterministic (same input → same bytes)
    // -------------------------------------------------------------------------

    #[test]
    #[allow(clippy::expect_used)]
    fn encode_socket_request_is_deterministic() {
        let req = connect_request(
            SocketHandle(1),
            SocketApiAddr {
                ip: [10, 0, 0, 1],
                port: 80,
            },
        );
        let a = encode_socket_request(&req).expect("encode-a");
        let b = encode_socket_request(&req).expect("encode-b");
        assert_eq!(a, b);
    }
}

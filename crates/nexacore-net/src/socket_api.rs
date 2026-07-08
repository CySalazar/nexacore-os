//! Socket API dispatcher (N3.2).
//!
//! This module is the canonical entry point that maps a [`SocketRequest`]
//! received on the `nexacore.svc.net.stack` IPC channel to the appropriate
//! sub-system in the network stack.
//!
//! The actual dispatch logic lives in [`crate::service::NetworkService`].
//! This module re-exports the constants, wraps them in convenience helpers,
//! and documents the mapping from request variant to sub-system.
//!
//! ## Request → sub-system mapping
//!
//! | Request variant            | Sub-system            |
//! |----------------------------|-----------------------|
//! | `Socket`                   | handle allocator      |
//! | `Bind`                     | [`crate::udp`]        |
//! | `Listen`, `Accept`         | [`crate::tcp`]        |
//! | `Connect`                  | [`crate::tcp`]        |
//! | `Send`, `Recv`             | [`crate::tcp`]        |
//! | `SendTo`, `RecvFrom`       | [`crate::udp`]        |
//! | `Close`                    | [`crate::udp`]        |
//! | `Resolve`                  | [`crate::dns`]        |
//! | `ListSockets`              | table scan            |
//!
//! ## IPC channel constants
//!
//! - [`SOCKET_API_CHANNEL`] — `"nexacore.svc.net.stack"` (re-exported from
//!   `nexacore-types`)
//! - [`NET_CONFIG_CHANNEL`] — `"nexacore.svc.net.config"` (re-exported from
//!   `nexacore-types`)

pub use nexacore_types::socket::{
    NET_CONFIG_CHANNEL, NetError, SOCKET_API_CHANNEL, SocketApiAddr, SocketDomain, SocketHandle,
    SocketInfo, SocketOption, SocketRequest, SocketResponse, SocketType,
};

use crate::service::NetworkService;

// =============================================================================
// Dispatch
// =============================================================================

/// Dispatch a [`SocketRequest`] to the network service and return the response.
///
/// This is the single entry point for all userspace socket operations.  The
/// caller is responsible for deserialising the request from the IPC channel
/// (using [`nexacore_types::wire::decode_canonical`]) before calling this function,
/// and for serialising the response before writing it back.
///
/// # Examples
///
/// ```
/// use nexacore_net::{
///     service::NetworkService,
///     socket_api::{SocketDomain, SocketRequest, SocketResponse, SocketType, dispatch},
/// };
///
/// let mut svc = NetworkService::new();
/// let req = SocketRequest::Socket {
///     domain: SocketDomain::Inet,
///     sock_type: SocketType::Dgram,
/// };
/// let resp = dispatch(&mut svc, req);
/// assert!(matches!(resp, SocketResponse::Handle(_)));
/// ```
pub fn dispatch(service: &mut NetworkService, request: SocketRequest) -> SocketResponse {
    service.handle_socket_request(request)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    use crate::service::NetworkService;

    fn make_svc() -> NetworkService {
        NetworkService::new()
    }

    #[test]
    fn dispatch_socket_returns_handle() {
        let mut svc = make_svc();
        let req = SocketRequest::Socket {
            domain: SocketDomain::Inet,
            sock_type: SocketType::Stream,
        };
        let resp = dispatch(&mut svc, req);
        assert!(matches!(resp, SocketResponse::Handle(_)));
    }

    #[test]
    fn dispatch_bind_success() {
        let mut svc = make_svc();
        let req = SocketRequest::Bind {
            handle: SocketHandle(0),
            addr: SocketApiAddr {
                ip: [0, 0, 0, 0],
                port: 1234,
            },
        };
        let resp = dispatch(&mut svc, req);
        assert!(matches!(resp, SocketResponse::Ok(_)));
    }

    #[test]
    fn dispatch_bind_duplicate_returns_error() {
        let mut svc = make_svc();
        let req = || SocketRequest::Bind {
            handle: SocketHandle(0),
            addr: SocketApiAddr {
                ip: [0, 0, 0, 0],
                port: 4321,
            },
        };
        assert!(matches!(dispatch(&mut svc, req()), SocketResponse::Ok(_)));
        assert!(matches!(
            dispatch(&mut svc, req()),
            SocketResponse::Error(NetError::AddrInUse)
        ));
    }

    #[test]
    fn dispatch_close_succeeds() {
        let mut svc = make_svc();
        // Bind first.
        let _ = dispatch(
            &mut svc,
            SocketRequest::Bind {
                handle: SocketHandle(0),
                addr: SocketApiAddr {
                    ip: [0, 0, 0, 0],
                    port: 5555,
                },
            },
        );
        let resp = dispatch(
            &mut svc,
            SocketRequest::Close {
                handle: SocketHandle(5555),
            },
        );
        assert!(matches!(resp, SocketResponse::Ok(0)));
    }

    #[test]
    fn dispatch_recv_from_empty_returns_wouldblock() {
        let mut svc = make_svc();
        let _ = dispatch(
            &mut svc,
            SocketRequest::Bind {
                handle: SocketHandle(0),
                addr: SocketApiAddr {
                    ip: [0, 0, 0, 0],
                    port: 6666,
                },
            },
        );
        let resp = dispatch(
            &mut svc,
            SocketRequest::RecvFrom {
                handle: SocketHandle(6666),
                max_len: 512,
            },
        );
        assert!(matches!(resp, SocketResponse::Error(NetError::WouldBlock)));
    }

    #[test]
    fn dispatch_list_sockets_returns_socket_list() {
        let mut svc = make_svc();
        let resp = dispatch(&mut svc, SocketRequest::ListSockets);
        assert!(matches!(resp, SocketResponse::SocketList(_)));
    }

    #[test]
    fn dispatch_resolve_returns_error_when_no_cache() {
        let mut svc = make_svc();
        let resp = dispatch(
            &mut svc,
            SocketRequest::Resolve {
                hostname: "example.com".into(),
            },
        );
        assert!(matches!(resp, SocketResponse::Error(_)));
    }

    #[test]
    fn channel_constant_correct() {
        assert_eq!(SOCKET_API_CHANNEL, "nexacore.svc.net.stack");
    }

    #[test]
    fn net_config_channel_constant_correct() {
        assert_eq!(NET_CONFIG_CHANNEL, "nexacore.svc.net.config");
    }
}

//! Dual-stack socket addressing: `IPv4`-mapped `IPv6` (WS4-04.5).
//!
//! A dual-stack `IPv6` socket accepts `IPv4` peers too, representing each as an
//! **`IPv4`-mapped `IPv6` address** `::ffff:a.b.c.d` (RFC 4291 §2.5.5.2). This module
//! provides the address conversions and the acceptance policy that decides,
//! for a listening `IPv6` socket, whether an incoming peer is admitted and which
//! `IPv6` address it is surfaced as.
//!
//! Pure addressing logic over `nexacore_types::net` — no I/O; the socket layer
//! (WS4-05.5) wires it into the accept path.

use nexacore_types::net::{Ipv4Addr, Ipv6Addr};

/// The 12-byte prefix of an `IPv4`-mapped `IPv6` address: ten zero bytes then
/// `0xFF 0xFF`.
const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF];

/// Whether `addr` is an `IPv4`-mapped `IPv6` address (`::ffff:0:0/96`).
#[must_use]
pub fn is_v4_mapped(addr: Ipv6Addr) -> bool {
    addr.0.get(..12) == Some(&V4_MAPPED_PREFIX)
}

/// The embedded `IPv4` address of a v4-mapped `IPv6` address, or `None` if `addr`
/// is not v4-mapped.
#[must_use]
pub fn mapped_to_v4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    if !is_v4_mapped(addr) {
        return None;
    }
    let octets: [u8; 4] = addr.0.get(12..16)?.try_into().ok()?;
    Some(Ipv4Addr(octets))
}

/// The `IPv4`-mapped `IPv6` form of an `IPv4` address (`::ffff:a.b.c.d`).
#[must_use]
pub fn v4_to_mapped(addr: Ipv4Addr) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[..12].copy_from_slice(&V4_MAPPED_PREFIX);
    bytes[12..16].copy_from_slice(&addr.0);
    Ipv6Addr(bytes)
}

/// A socket-layer peer address in a dual-stack world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualStackAddr {
    /// A native `IPv4` address.
    V4(Ipv4Addr),
    /// An `IPv6` address (possibly `IPv4`-mapped).
    V6(Ipv6Addr),
}

impl DualStackAddr {
    /// The canonical form: a v4-mapped [`Self::V6`] collapses to its [`Self::V4`]
    /// form; every other address is unchanged. Used so an application sees a
    /// stable representation regardless of which family the packet arrived on.
    #[must_use]
    pub fn canonical(self) -> Self {
        match self {
            Self::V6(addr) => mapped_to_v4(addr).map_or(Self::V6(addr), Self::V4),
            Self::V4(_) => self,
        }
    }

    /// The `IPv6` representation used on a dual-stack socket: a [`Self::V4`] is
    /// mapped to `::ffff:a.b.c.d`; a [`Self::V6`] is returned as-is.
    #[must_use]
    pub fn as_v6(self) -> Ipv6Addr {
        match self {
            Self::V4(addr) => v4_to_mapped(addr),
            Self::V6(addr) => addr,
        }
    }

    /// Whether this address is `IPv4` (native or v4-mapped `IPv6`).
    #[must_use]
    pub fn is_ipv4(self) -> bool {
        match self {
            Self::V4(_) => true,
            Self::V6(addr) => is_v4_mapped(addr),
        }
    }
}

/// The acceptance policy of a listening `IPv6` socket (RFC 3493 `IPV6_V6ONLY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DualStackPolicy {
    /// When `true`, the socket is `IPv6`-only and rejects `IPv4` (and v4-mapped)
    /// peers; when `false` it is dual-stack and admits them as v4-mapped.
    pub v6_only: bool,
}

impl DualStackPolicy {
    /// An `IPv6`-only policy.
    #[must_use]
    pub fn v6_only() -> Self {
        Self { v6_only: true }
    }

    /// A dual-stack policy (accepts `IPv4` as v4-mapped).
    #[must_use]
    pub fn dual_stack() -> Self {
        Self { v6_only: false }
    }

    /// Whether an incoming `peer` is accepted by an `IPv6` socket under this
    /// policy, and the `IPv6` address it is surfaced as.
    ///
    /// - `IPv6`-only: only a **native** `IPv6` peer is accepted; an `IPv4` or
    ///   v4-mapped peer is rejected (`None`).
    /// - Dual-stack: every peer is accepted, `IPv4` as its v4-mapped form.
    #[must_use]
    pub fn accept(self, peer: DualStackAddr) -> Option<Ipv6Addr> {
        if self.v6_only {
            if peer.is_ipv4() {
                None
            } else {
                Some(peer.as_v6())
            }
        } else {
            Some(peer.as_v6())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: Ipv4Addr = Ipv4Addr([192, 0, 2, 50]);

    #[test]
    fn v4_maps_to_and_from_v6() {
        let mapped = v4_to_mapped(V4);
        assert_eq!(
            mapped.0,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 50]
        );
        assert!(is_v4_mapped(mapped));
        assert_eq!(mapped_to_v4(mapped), Some(V4));
    }

    #[test]
    fn native_v6_is_not_v4_mapped() {
        let native = Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!is_v4_mapped(native));
        assert_eq!(mapped_to_v4(native), None);
    }

    #[test]
    fn canonical_collapses_mapped_but_not_native() {
        // A v4-mapped V6 collapses to V4.
        let mapped = DualStackAddr::V6(v4_to_mapped(V4));
        assert_eq!(mapped.canonical(), DualStackAddr::V4(V4));
        // A native V6 stays V6.
        let native = Ipv6Addr::LOOPBACK;
        assert_eq!(
            DualStackAddr::V6(native).canonical(),
            DualStackAddr::V6(native)
        );
        // A V4 stays V4.
        assert_eq!(DualStackAddr::V4(V4).canonical(), DualStackAddr::V4(V4));
    }

    #[test]
    fn is_ipv4_covers_native_and_mapped() {
        assert!(DualStackAddr::V4(V4).is_ipv4());
        assert!(DualStackAddr::V6(v4_to_mapped(V4)).is_ipv4());
        assert!(!DualStackAddr::V6(Ipv6Addr::LOOPBACK).is_ipv4());
    }

    #[test]
    fn v6only_rejects_ipv4_peers() {
        let policy = DualStackPolicy::v6_only();
        assert_eq!(policy.accept(DualStackAddr::V4(V4)), None);
        assert_eq!(policy.accept(DualStackAddr::V6(v4_to_mapped(V4))), None);
        // A native `IPv6` peer is accepted as-is.
        assert_eq!(
            policy.accept(DualStackAddr::V6(Ipv6Addr::LOOPBACK)),
            Some(Ipv6Addr::LOOPBACK)
        );
    }

    #[test]
    fn dual_stack_admits_ipv4_as_v4_mapped() {
        let policy = DualStackPolicy::dual_stack();
        assert_eq!(policy.accept(DualStackAddr::V4(V4)), Some(v4_to_mapped(V4)));
        assert_eq!(
            policy.accept(DualStackAddr::V6(Ipv6Addr::LOOPBACK)),
            Some(Ipv6Addr::LOOPBACK)
        );
        // Default policy is dual-stack (v6_only = false).
        assert_eq!(
            DualStackPolicy::default().accept(DualStackAddr::V4(V4)),
            Some(v4_to_mapped(V4))
        );
    }
}

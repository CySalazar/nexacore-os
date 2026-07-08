//! Stateless Address Autoconfiguration (WS4-04.4, RFC 4862 / RFC 4291).
//!
//! `SLAAC` lets a host derive a global `IPv6` address with no server: it takes
//! an on-link prefix advertised in a Router Advertisement's Prefix Information
//! option (see [`crate::ndp`]) and appends a per-interface identifier built
//! from the link-layer (`MAC`) address via Modified `EUI-64`.
//!
//! This module is the pure derivation + lifetime bookkeeping. It needs no
//! clock: advertised lifetimes are stored as-is, and ageing is driven by the
//! caller (the address is *preferred* while its preferred lifetime is non-zero,
//! then *deprecated*).

use alloc::vec::Vec;

use nexacore_types::net::{Ipv6Addr, MacAddress};

use crate::ndp::{NdpOption, PrefixInfo};

/// The standard `SLAAC` prefix length: a `/64` leaves 64 bits for the
/// Modified `EUI-64` interface identifier.
pub const SLAAC_PREFIX_LEN: u8 = 64;

/// Derive the 64-bit Modified `EUI-64` interface identifier from a 48-bit
/// `MAC` address (RFC 4291 appendix A).
///
/// The `MAC`'s OUI and NIC halves are split around the inserted `FF:FE`, and
/// the Universal/Local bit (bit 1 of the first octet) is inverted.
#[must_use]
pub fn eui64_interface_id(mac: MacAddress) -> [u8; 8] {
    let m = mac.0;
    [
        m[0] ^ 0x02, // flip the Universal/Local bit
        m[1],
        m[2],
        0xFF,
        0xFE,
        m[3],
        m[4],
        m[5],
    ]
}

/// Combine a `/64` `prefix` with the Modified `EUI-64` identifier of `mac` to
/// form a full `SLAAC` address.
///
/// Only the top 64 bits of `prefix` are used; the low 64 bits are replaced by
/// the interface identifier.
#[must_use]
pub fn slaac_address(prefix: Ipv6Addr, mac: MacAddress) -> Ipv6Addr {
    let iid = eui64_interface_id(mac);
    let mut addr = [0u8; 16];
    // High 64 bits: the prefix. Low 64 bits: the interface identifier.
    let (high, low) = addr.split_at_mut(8);
    high.copy_from_slice(&prefix.0[..8]);
    low.copy_from_slice(&iid);
    Ipv6Addr(addr)
}

/// Whether `prefix` is the link-local prefix (`fe80::/10`), which `SLAAC` must
/// not autoconfigure a *global* address from (RFC 4862 § 5.5.3).
#[must_use]
fn is_link_local(prefix: Ipv6Addr) -> bool {
    prefix.0[0] == 0xfe && (prefix.0[1] & 0xc0) == 0x80
}

/// The preference state of a configured address (RFC 4862 § 5.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressState {
    /// Usable for new and existing communications.
    Preferred,
    /// Still valid, but should not start new communications.
    Deprecated,
}

/// An address configured by `SLAAC`, with its advertised lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfiguredAddress {
    /// The derived `IPv6` address.
    pub addr: Ipv6Addr,
    /// Seconds the address remains valid.
    pub valid_lifetime: u32,
    /// Seconds the address remains preferred.
    pub preferred_lifetime: u32,
}

impl ConfiguredAddress {
    /// The current preference state, derived from the preferred lifetime.
    #[must_use]
    pub fn state(self) -> AddressState {
        if self.preferred_lifetime > 0 {
            AddressState::Preferred
        } else {
            AddressState::Deprecated
        }
    }
}

/// Derive a `SLAAC` address from one Prefix Information option.
///
/// Returns `None` if the prefix is not eligible (RFC 4862 § 5.5.3): the
/// Autonomous flag must be set, the prefix must be a non-link-local `/64`, the
/// valid lifetime must be non-zero, and the preferred lifetime must not exceed
/// the valid lifetime.
#[must_use]
pub fn address_from_prefix(mac: MacAddress, info: &PrefixInfo) -> Option<ConfiguredAddress> {
    if !info.autonomous
        || info.prefix_len != SLAAC_PREFIX_LEN
        || info.valid_lifetime == 0
        || info.preferred_lifetime > info.valid_lifetime
        || is_link_local(info.prefix)
    {
        return None;
    }
    Some(ConfiguredAddress {
        addr: slaac_address(info.prefix, mac),
        valid_lifetime: info.valid_lifetime,
        preferred_lifetime: info.preferred_lifetime,
    })
}

/// Per-interface `SLAAC` state: the link-layer address plus the set of
/// autoconfigured addresses.
#[derive(Debug, Clone)]
pub struct SlaacState {
    mac: MacAddress,
    addresses: Vec<ConfiguredAddress>,
}

impl SlaacState {
    /// Create `SLAAC` state for an interface with link-layer address `mac`.
    #[must_use]
    pub fn new(mac: MacAddress) -> Self {
        Self {
            mac,
            addresses: Vec::new(),
        }
    }

    /// Process the options of a received Router Advertisement, configuring (or
    /// refreshing the lifetimes of) an address for each eligible autonomous
    /// prefix. Returns the addresses newly added by this call.
    pub fn process_ra_options(&mut self, options: &[NdpOption]) -> Vec<ConfiguredAddress> {
        let mut added = Vec::new();
        for opt in options {
            let NdpOption::PrefixInfo(info) = opt else {
                continue;
            };
            let Some(configured) = address_from_prefix(self.mac, info) else {
                continue;
            };
            if let Some(existing) = self
                .addresses
                .iter_mut()
                .find(|a| a.addr == configured.addr)
            {
                // Refresh the lifetimes on an already-configured address.
                existing.valid_lifetime = configured.valid_lifetime;
                existing.preferred_lifetime = configured.preferred_lifetime;
            } else {
                self.addresses.push(configured);
                added.push(configured);
            }
        }
        added
    }

    /// The currently configured addresses.
    #[must_use]
    pub fn addresses(&self) -> &[ConfiguredAddress] {
        &self.addresses
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;

    fn mac() -> MacAddress {
        MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    }

    fn prefix() -> Ipv6Addr {
        // 2001:db8:: /64
        Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    fn autonomous_prefix(valid: u32, preferred: u32) -> PrefixInfo {
        PrefixInfo {
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: valid,
            preferred_lifetime: preferred,
            prefix: prefix(),
        }
    }

    #[test]
    fn eui64_flips_ul_bit_and_inserts_fffe() {
        // 00:11:22:33:44:55 -> 02:11:22:FF:FE:33:44:55 (RFC 4291 example).
        assert_eq!(
            eui64_interface_id(mac()),
            [0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55]
        );
    }

    #[test]
    fn slaac_address_combines_prefix_and_eui64() {
        // 2001:db8::/64 + EUI-64 -> 2001:db8::211:22ff:fe33:4455.
        let addr = slaac_address(prefix(), mac());
        assert_eq!(
            addr,
            Ipv6Addr([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55
            ])
        );
    }

    #[test]
    fn address_from_autonomous_prefix_is_configured() {
        let info = autonomous_prefix(86_400, 14_400);
        let configured = address_from_prefix(mac(), &info).unwrap();
        assert_eq!(configured.addr, slaac_address(prefix(), mac()));
        assert_eq!(configured.valid_lifetime, 86_400);
        assert_eq!(configured.state(), AddressState::Preferred);
    }

    #[test]
    fn non_eligible_prefixes_are_rejected() {
        // Autonomous flag clear.
        let mut info = autonomous_prefix(100, 50);
        info.autonomous = false;
        assert!(address_from_prefix(mac(), &info).is_none());
        // Non-/64 prefix.
        let mut info = autonomous_prefix(100, 50);
        info.prefix_len = 48;
        assert!(address_from_prefix(mac(), &info).is_none());
        // Zero valid lifetime.
        assert!(address_from_prefix(mac(), &autonomous_prefix(0, 0)).is_none());
        // Preferred exceeds valid.
        assert!(address_from_prefix(mac(), &autonomous_prefix(50, 100)).is_none());
        // Link-local prefix is not autoconfigured as a global address.
        let mut info = autonomous_prefix(100, 50);
        info.prefix = Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(address_from_prefix(mac(), &info).is_none());
    }

    #[test]
    fn zero_preferred_lifetime_is_deprecated() {
        let configured = address_from_prefix(mac(), &autonomous_prefix(100, 0)).unwrap();
        assert_eq!(configured.state(), AddressState::Deprecated);
    }

    #[test]
    fn state_configures_then_refreshes_without_duplicating() {
        let mut state = SlaacState::new(mac());
        let opts = alloc::vec![NdpOption::PrefixInfo(autonomous_prefix(100, 50))];
        // First RA configures one address.
        let added = state.process_ra_options(&opts);
        assert_eq!(added.len(), 1);
        assert_eq!(state.addresses().len(), 1);
        // A second RA for the same prefix refreshes, does not duplicate.
        let opts2 = alloc::vec![NdpOption::PrefixInfo(autonomous_prefix(200, 120))];
        let added2 = state.process_ra_options(&opts2);
        assert!(added2.is_empty());
        assert_eq!(state.addresses().len(), 1);
        assert_eq!(state.addresses()[0].valid_lifetime, 200);
        assert_eq!(state.addresses()[0].preferred_lifetime, 120);
    }

    #[test]
    fn state_ignores_non_prefix_and_ineligible_options() {
        let mut state = SlaacState::new(mac());
        let opts = alloc::vec![
            NdpOption::Mtu(1500),
            NdpOption::SourceLinkAddr(mac()),
            NdpOption::PrefixInfo(PrefixInfo {
                autonomous: false,
                ..autonomous_prefix(100, 50)
            }),
        ];
        assert!(state.process_ra_options(&opts).is_empty());
        assert!(state.addresses().is_empty());
    }
}

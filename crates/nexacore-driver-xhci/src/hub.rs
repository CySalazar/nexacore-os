//! USB hub enumeration and downstream port routing (WS2-04.13).
//!
//! When a USB hub is attached to an xHCI root port, the devices below it are
//! addressed by a **route string** — a 20-bit field (five 4-bit tiers) in the
//! Slot Context that names the downstream port at each external-hub tier on the
//! path from the root port to the device (xHCI 1.2 § 8.9 / 6.2.2). A device
//! directly on a root port has route string 0; a device behind a first-tier
//! hub's port 3 has route string `0x3`; behind that hub's port 3 then a
//! second-tier hub's port 5, `0x53`.
//!
//! This module parses the USB hub class descriptor (USB 2.0 § 11.23.2.1 /
//! USB 3.x § 10.15.2.1) and the per-port status word (USB 2.0 § 11.24.2.7),
//! and computes route strings for downstream ports. It is pure byte logic and
//! host-tested; wiring it into the live enumeration walk on the rig is the rest
//! of WS2-04.

/// Errors from hub descriptor parsing or route computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubError {
    /// The descriptor slice is shorter than the hub descriptor minimum.
    TooShort,
    /// `bDescriptorType` is not a hub descriptor type (`0x29`/`0x2A`).
    WrongType,
    /// A route path is deeper than the five tiers a route string can encode.
    TooManyTiers,
    /// A downstream port number is 0 or greater than 15 (out of nibble range).
    InvalidPort,
}

/// USB 2.0 hub class descriptor type (`bDescriptorType`).
pub const HUB_DESC_TYPE_USB2: u8 = 0x29;
/// USB 3.x (`SuperSpeed`) hub class descriptor type.
pub const HUB_DESC_TYPE_USB3: u8 = 0x2A;

/// Minimum length of the fixed portion of a hub class descriptor (through
/// `bHubContrCurrent`); the variable `DeviceRemovable` bitmap follows.
pub const HUB_DESCRIPTOR_MIN_LEN: usize = 7;

/// Maximum number of external-hub tiers an xHCI route string encodes (5 nibbles
/// = 20 bits).
pub const MAX_HUB_TIERS: usize = 5;

/// Parsed fixed fields of a USB hub class descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubDescriptor {
    /// `bNbrPorts` — number of downstream ports.
    pub num_ports: u8,
    /// `wHubCharacteristics` (little-endian).
    pub characteristics: u16,
    /// `bPwrOn2PwrGood` — power-on to power-good time, in 2 ms units.
    pub power_on_to_good_2ms: u8,
    /// `bHubContrCurrent` — hub controller current draw, in mA.
    pub hub_control_current_ma: u8,
    /// Whether this is a `SuperSpeed` (USB 3.x) hub descriptor.
    pub is_superspeed: bool,
}

impl HubDescriptor {
    /// Whether the hub is part of a compound device (`wHubCharacteristics`
    /// bit 2).
    #[must_use]
    pub const fn is_compound_device(self) -> bool {
        self.characteristics & (1 << 2) != 0
    }

    /// Logical power-switching mode (`wHubCharacteristics` bits 1:0):
    /// `0` = ganged, `1` = per-port, `2`/`3` = no switching.
    #[must_use]
    pub const fn power_switching_mode(self) -> u8 {
        (self.characteristics & 0b11) as u8
    }
}

/// Parse the fixed portion of a USB hub class descriptor.
///
/// # Errors
///
/// [`HubError::TooShort`] if `data` is shorter than [`HUB_DESCRIPTOR_MIN_LEN`];
/// [`HubError::WrongType`] if `bDescriptorType` is neither the USB 2.0 nor the
/// USB 3.x hub type.
pub fn parse_hub_descriptor(data: &[u8]) -> Result<HubDescriptor, HubError> {
    // Read the fixed portion into an array so the field accesses are provably
    // in-bounds (no slice indexing).
    // Offsets: [0]=bLength, [1]=bDescriptorType, [2]=bNbrPorts,
    // [3..5]=wHubCharacteristics, [5]=bPwrOn2PwrGood, [6]=bHubContrCurrent.
    let fixed: [u8; HUB_DESCRIPTOR_MIN_LEN] = data
        .get(..HUB_DESCRIPTOR_MIN_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(HubError::TooShort)?;
    let is_superspeed = match fixed[1] {
        HUB_DESC_TYPE_USB2 => false,
        HUB_DESC_TYPE_USB3 => true,
        _ => return Err(HubError::WrongType),
    };
    Ok(HubDescriptor {
        num_ports: fixed[2],
        characteristics: u16::from_le_bytes([fixed[3], fixed[4]]),
        power_on_to_good_2ms: fixed[5],
        hub_control_current_ma: fixed[6],
        is_superspeed,
    })
}

/// Compute the xHCI route string for a device reached through `path`.
///
/// `path` is the list of downstream-port numbers at each successive
/// external-hub tier (root→device order). An empty path (a device on a root
/// port) yields `0`.
///
/// # Errors
///
/// [`HubError::TooManyTiers`] if `path` is longer than [`MAX_HUB_TIERS`];
/// [`HubError::InvalidPort`] if any port is `0` or `> 15`.
pub fn route_string(path: &[u8]) -> Result<u32, HubError> {
    if path.len() > MAX_HUB_TIERS {
        return Err(HubError::TooManyTiers);
    }
    let mut route = 0u32;
    for (tier, &port) in path.iter().enumerate() {
        if port == 0 || port > 15 {
            return Err(HubError::InvalidPort);
        }
        route |= u32::from(port) << (4 * tier);
    }
    Ok(route)
}

/// Extend a parent hub's route string with the `downstream_port` of a child hub
/// (or device) attached at tier `tier` (0-based tier index of the new hop).
///
/// # Errors
///
/// [`HubError::TooManyTiers`] if `tier >= MAX_HUB_TIERS`;
/// [`HubError::InvalidPort`] if `downstream_port` is `0` or `> 15`.
pub fn child_route(parent_route: u32, tier: usize, downstream_port: u8) -> Result<u32, HubError> {
    if tier >= MAX_HUB_TIERS {
        return Err(HubError::TooManyTiers);
    }
    if downstream_port == 0 || downstream_port > 15 {
        return Err(HubError::InvalidPort);
    }
    Ok(parent_route | (u32::from(downstream_port) << (4 * tier)))
}

/// The number of external-hub tiers a route string encodes (0 for a root-port
/// device).
#[must_use]
pub fn route_tier_count(route: u32) -> usize {
    let mut count = 0;
    for tier in 0..MAX_HUB_TIERS {
        if (route >> (4 * tier)) & 0xF != 0 {
            count = tier + 1;
        }
    }
    count
}

/// Decoded USB hub port status (`wPortStatus`, USB 2.0 § 11.24.2.7).
///
/// Each field mirrors one named status bit of the hardware word; the many
/// booleans are the spec's own layout, not a modelling choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct HubPortStatus {
    /// A device is attached (`PORT_CONNECTION`, bit 0).
    pub connected: bool,
    /// The port is enabled (`PORT_ENABLE`, bit 1).
    pub enabled: bool,
    /// The port is suspended (`PORT_SUSPEND`, bit 2).
    pub suspended: bool,
    /// Over-current condition (`PORT_OVER_CURRENT`, bit 3).
    pub over_current: bool,
    /// The port is in reset (`PORT_RESET`, bit 4).
    pub reset: bool,
    /// Port power is on (`PORT_POWER`, bit 8).
    pub powered: bool,
    /// A low-speed device is attached (`PORT_LOW_SPEED`, bit 9).
    pub low_speed: bool,
    /// A high-speed device is attached (`PORT_HIGH_SPEED`, bit 10).
    pub high_speed: bool,
}

/// Decode a hub port status word (`wPortStatus`).
#[must_use]
pub fn parse_hub_port_status(w_port_status: u16) -> HubPortStatus {
    let bit = |n: u16| w_port_status & (1 << n) != 0;
    HubPortStatus {
        connected: bit(0),
        enabled: bit(1),
        suspended: bit(2),
        over_current: bit(3),
        reset: bit(4),
        powered: bit(8),
        low_speed: bit(9),
        high_speed: bit(10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usb2_hub(num_ports: u8, characteristics: u16) -> [u8; 9] {
        let c = characteristics.to_le_bytes();
        [
            9,                  // bLength
            HUB_DESC_TYPE_USB2, // bDescriptorType
            num_ports,          // bNbrPorts
            c[0],
            c[1], // wHubCharacteristics
            10,   // bPwrOn2PwrGood (20 ms)
            100,  // bHubContrCurrent (mA)
            0x00, // DeviceRemovable
            0xFF, // PortPwrCtrlMask
        ]
    }

    #[test]
    fn parses_usb2_hub_descriptor() {
        let d = parse_hub_descriptor(&usb2_hub(4, 0b0000_0100)).unwrap();
        assert_eq!(d.num_ports, 4);
        assert!(!d.is_superspeed);
        assert_eq!(d.power_on_to_good_2ms, 10);
        assert_eq!(d.hub_control_current_ma, 100);
        assert!(d.is_compound_device());
        assert_eq!(d.power_switching_mode(), 0);
    }

    #[test]
    fn detects_superspeed_hub() {
        let mut raw = usb2_hub(2, 0);
        raw[1] = HUB_DESC_TYPE_USB3;
        assert!(parse_hub_descriptor(&raw).unwrap().is_superspeed);
    }

    #[test]
    fn rejects_short_and_wrong_type() {
        assert_eq!(parse_hub_descriptor(&[0u8; 4]), Err(HubError::TooShort));
        let mut raw = usb2_hub(2, 0);
        raw[1] = 0x01; // device descriptor type
        assert_eq!(parse_hub_descriptor(&raw), Err(HubError::WrongType));
    }

    #[test]
    fn route_string_encodes_tiers() {
        assert_eq!(route_string(&[]).unwrap(), 0);
        assert_eq!(route_string(&[3]).unwrap(), 0x3);
        // Tier1 port 3, tier2 port 5 → 0x53.
        assert_eq!(route_string(&[3, 5]).unwrap(), 0x53);
        assert_eq!(route_string(&[1, 2, 3, 4, 5]).unwrap(), 0x54321);
    }

    #[test]
    fn route_string_rejects_bad_input() {
        assert_eq!(route_string(&[0]), Err(HubError::InvalidPort));
        assert_eq!(route_string(&[16]), Err(HubError::InvalidPort));
        assert_eq!(
            route_string(&[1, 2, 3, 4, 5, 6]),
            Err(HubError::TooManyTiers)
        );
    }

    #[test]
    fn child_route_extends_parent() {
        let parent = route_string(&[3]).unwrap(); // 0x3
        let child = child_route(parent, 1, 5).unwrap(); // add tier2 port 5
        assert_eq!(child, 0x53);
        assert_eq!(route_tier_count(child), 2);
        assert_eq!(child_route(parent, 5, 1), Err(HubError::TooManyTiers));
        assert_eq!(child_route(parent, 1, 0), Err(HubError::InvalidPort));
    }

    #[test]
    fn tier_count_counts_nonzero_nibbles() {
        assert_eq!(route_tier_count(0), 0);
        assert_eq!(route_tier_count(0x3), 1);
        assert_eq!(route_tier_count(0x503), 3); // tier3 present even with a zero tier2
    }

    #[test]
    fn parses_port_status_bits() {
        // connected + enabled + power + high-speed.
        let s = parse_hub_port_status(0b0000_0101_0000_0011);
        assert!(s.connected);
        assert!(s.enabled);
        assert!(s.powered);
        assert!(s.high_speed);
        assert!(!s.reset);
        assert!(!s.low_speed);
    }
}

//! USB control-transfer SETUP packet builders.
//!
//! Each function returns the 8-byte setup packet `[u8; 8]` for a standard
//! or class control request.  These packets are the `setup_data` argument to
//! [`crate::trb::setup_stage_trb`] — the caller passes the returned array
//! directly to the TRB constructor.
//!
//! ## Wire layout (USB § 9.3 Table 9-2)
//!
//! ```text
//! Byte 0: bmRequestType
//! Byte 1: bRequest
//! Bytes 2-3: wValue  (LE)
//! Bytes 4-5: wIndex  (LE)
//! Bytes 6-7: wLength (LE)
//! ```
//!
//! ## References
//!
//! - USB 2.0 specification § 9.3 — USB Device Requests.
//! - USB HID Specification 1.11 § 7.2 — Class-Specific Requests.

// =============================================================================
// Standard descriptor-fetch requests (bmRequestType = 0x80)
// =============================================================================

/// Build a `GET_DESCRIPTOR` setup packet.
///
/// Issues a standard IN request to retrieve a USB descriptor.
///
/// `desc_type` is the descriptor type code (e.g. `1` for Device, `2` for
/// Configuration).  `desc_index` selects the instance for types that support
/// multiple instances (e.g. string descriptors).  `length` is the number of
/// bytes to transfer (placed in `wLength`).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::control::get_descriptor_setup;
///
/// // GET_DESCRIPTOR(Device): type=1, index=0, length=18.
/// let pkt = get_descriptor_setup(1, 0, 18);
/// assert_eq!(pkt[0], 0x80); // bmRequestType: IN, Standard, Device
/// assert_eq!(pkt[1], 0x06); // bRequest: GET_DESCRIPTOR
/// assert_eq!(pkt[2], 0); // wValue low = desc_index
/// assert_eq!(pkt[3], 1); // wValue high = desc_type
/// assert_eq!(pkt[6], 18); // wLength low
/// assert_eq!(pkt[7], 0); // wLength high
/// ```
#[must_use]
pub fn get_descriptor_setup(desc_type: u8, desc_index: u8, length: u16) -> [u8; 8] {
    // bmRequestType = 0x80: Direction IN (bit 7), Standard (bits 6:5 = 00),
    //                        Device recipient (bits 4:0 = 00000).
    // bRequest = 0x06: GET_DESCRIPTOR.
    // wValue = (desc_type << 8) | desc_index.
    // wIndex = 0 (language ID for string descriptors; 0 for others).
    let length_bytes = length.to_le_bytes();
    [
        0x80,
        0x06,
        desc_index,      // wValue low
        desc_type,       // wValue high
        0x00,            // wIndex low
        0x00,            // wIndex high
        length_bytes[0], // wLength low
        length_bytes[1], // wLength high
    ]
}

/// Build a `GET_DESCRIPTOR(Report)` setup packet for a HID interface
/// (WS7-06).
///
/// Unlike [`get_descriptor_setup`] (device recipient), the HID *Report*
/// descriptor is fetched with an **interface-recipient** standard IN request
/// (`bmRequestType = 0x81`): `wValue` high byte `0x22` (Report), `wIndex` =
/// the HID interface number (HID 1.11 § 7.1.1).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::control::get_report_descriptor_setup;
///
/// let pkt = get_report_descriptor_setup(0, 128);
/// assert_eq!(pkt[0], 0x81); // bmRequestType: IN, Standard, Interface
/// assert_eq!(pkt[1], 0x06); // bRequest: GET_DESCRIPTOR
/// assert_eq!(pkt[3], 0x22); // wValue high = Report descriptor type
/// assert_eq!(pkt[4], 0); // wIndex low = interface number
/// assert_eq!(pkt[6], 128); // wLength low
/// ```
#[must_use]
pub fn get_report_descriptor_setup(interface: u8, length: u16) -> [u8; 8] {
    // bmRequestType = 0x81: Direction IN, Standard, Interface recipient.
    // bRequest = 0x06: GET_DESCRIPTOR; wValue = 0x2200 (Report, index 0).
    let length_bytes = length.to_le_bytes();
    [
        0x81,
        0x06,
        0x00, // wValue low = descriptor index 0
        0x22, // wValue high = Report descriptor type
        interface,
        0x00,
        length_bytes[0],
        length_bytes[1],
    ]
}

// =============================================================================
// Standard configuration request (bmRequestType = 0x00)
// =============================================================================

/// Build a `SET_CONFIGURATION` setup packet.
///
/// Issues a standard OUT request to select the active USB configuration.
/// `config_value` is the `bConfigurationValue` from the target configuration
/// descriptor.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::control::set_configuration_setup;
///
/// let pkt = set_configuration_setup(1);
/// assert_eq!(pkt[0], 0x00); // bmRequestType: OUT, Standard, Device
/// assert_eq!(pkt[1], 0x09); // bRequest: SET_CONFIGURATION
/// assert_eq!(pkt[2], 1); // wValue = bConfigurationValue
/// ```
#[must_use]
pub fn set_configuration_setup(config_value: u8) -> [u8; 8] {
    // bmRequestType = 0x00: Direction OUT (bit 7 = 0), Standard (bits 6:5 = 00),
    //                        Device recipient (bits 4:0 = 00000).
    // bRequest = 0x09: SET_CONFIGURATION.
    // wValue = bConfigurationValue (low byte only; high byte = 0).
    // wIndex = 0; wLength = 0.
    [0x00, 0x09, config_value, 0x00, 0x00, 0x00, 0x00, 0x00]
}

// =============================================================================
// HID class-specific requests (bmRequestType = 0x21)
// =============================================================================

/// Build a `SET_PROTOCOL` setup packet to select HID boot protocol.
///
/// Issues a HID class OUT request to switch the specified interface to Boot
/// Protocol (wValue = 0).  Only valid for HID devices with subclass 1
/// (Boot Interface).
///
/// `interface` is the `bInterfaceNumber` of the HID interface.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::control::set_protocol_boot_setup;
///
/// let pkt = set_protocol_boot_setup(0);
/// assert_eq!(pkt[0], 0x21); // bmRequestType: OUT, Class, Interface
/// assert_eq!(pkt[1], 0x0B); // bRequest: SET_PROTOCOL
/// assert_eq!(pkt[2], 0x00); // wValue = 0 (Boot Protocol)
/// assert_eq!(pkt[3], 0x00);
/// assert_eq!(pkt[4], 0); // wIndex = interface number
/// ```
#[must_use]
pub fn set_protocol_boot_setup(interface: u8) -> [u8; 8] {
    set_protocol_setup(interface, HidProtocol::Boot)
}

/// The HID protocol a `SET_PROTOCOL` request selects (WS2-05.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidProtocol {
    /// Boot Protocol — the fixed 8-byte keyboard / 3-byte mouse layout
    /// (`wValue = 0`); usable without parsing the report descriptor.
    Boot,
    /// Report Protocol — the layout defined by the report descriptor
    /// (`wValue = 1`).
    Report,
}

impl HidProtocol {
    /// The `wValue` low byte encoding this protocol.
    #[must_use]
    pub fn wvalue(self) -> u8 {
        match self {
            Self::Boot => 0,
            Self::Report => 1,
        }
    }
}

/// Build a `SET_PROTOCOL` setup packet selecting `protocol` on `interface`
/// (WS2-05.2).
///
/// `bmRequestType` `0x21` (OUT, Class, Interface), `bRequest` `0x0B`
/// (`SET_PROTOCOL`), `wValue` = the protocol, `wIndex` = interface,
/// `wLength` = 0.
#[must_use]
pub fn set_protocol_setup(interface: u8, protocol: HidProtocol) -> [u8; 8] {
    [
        0x21,
        0x0B,
        protocol.wvalue(),
        0x00,
        interface,
        0x00,
        0x00,
        0x00,
    ]
}

/// The ordered control transfers a driver issues to activate HID Boot Protocol
/// on `interface`: `SET_PROTOCOL(Boot)` then `SET_IDLE(0)` (WS2-05.2).
///
/// After this sequence the device reports the fixed boot layout only on state
/// change, which is what the interrupt-IN report handler (WS2-05.8) expects.
#[must_use]
pub fn hid_boot_init_sequence(interface: u8) -> [[u8; 8]; 2] {
    [
        set_protocol_setup(interface, HidProtocol::Boot),
        set_idle_setup(interface),
    ]
}

/// Build a `SET_IDLE` setup packet to suppress redundant HID reports.
///
/// Issues a HID class OUT request to set the idle rate to 0 for the specified
/// interface.  With idle rate 0 the device only sends a report when the state
/// changes (no repeated identical reports), which is the correct setting for
/// interrupt-IN polling.
///
/// `interface` is the `bInterfaceNumber` of the HID interface.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::control::set_idle_setup;
///
/// let pkt = set_idle_setup(0);
/// assert_eq!(pkt[0], 0x21); // bmRequestType: OUT, Class, Interface
/// assert_eq!(pkt[1], 0x0A); // bRequest: SET_IDLE
/// assert_eq!(pkt[2], 0x00); // wValue low = idle rate 0
/// assert_eq!(pkt[3], 0x00); // wValue high = report ID 0 (all reports)
/// ```
#[must_use]
pub fn set_idle_setup(interface: u8) -> [u8; 8] {
    // bmRequestType = 0x21: Direction OUT, Class, Interface.
    // bRequest = 0x0A: SET_IDLE.
    // wValue = 0x0000: idle rate = 0, report ID = 0 (applies to all reports).
    // wIndex = interface number; wLength = 0.
    [0x21, 0x0A, 0x00, 0x00, interface, 0x00, 0x00, 0x00]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_protocol_selects_boot_or_report() {
        assert_eq!(HidProtocol::Boot.wvalue(), 0);
        assert_eq!(HidProtocol::Report.wvalue(), 1);
        let boot = set_protocol_setup(2, HidProtocol::Boot);
        assert_eq!(boot, [0x21, 0x0B, 0x00, 0x00, 2, 0x00, 0x00, 0x00]);
        let report = set_protocol_setup(2, HidProtocol::Report);
        assert_eq!(report[2], 0x01); // wValue = 1 (Report Protocol)
        // The existing boot helper agrees with the generalised builder.
        assert_eq!(set_protocol_boot_setup(2), boot);
    }

    #[test]
    fn boot_init_sequence_is_set_protocol_then_set_idle() {
        let seq = hid_boot_init_sequence(1);
        assert_eq!(seq[0], set_protocol_setup(1, HidProtocol::Boot));
        assert_eq!(seq[0][1], 0x0B); // SET_PROTOCOL
        assert_eq!(seq[1], set_idle_setup(1));
        assert_eq!(seq[1][1], 0x0A); // SET_IDLE
    }

    // -- get_descriptor_setup -----------------------------------------------

    #[test]
    fn get_descriptor_setup_device_descriptor() {
        let pkt = get_descriptor_setup(1, 0, 18);
        assert_eq!(pkt[0], 0x80, "bmRequestType IN/Standard/Device");
        assert_eq!(pkt[1], 0x06, "bRequest GET_DESCRIPTOR");
        assert_eq!(pkt[2], 0, "wValue low = index 0");
        assert_eq!(pkt[3], 1, "wValue high = type 1");
        assert_eq!(pkt[4], 0, "wIndex low");
        assert_eq!(pkt[5], 0, "wIndex high");
        assert_eq!(pkt[6], 18, "wLength low");
        assert_eq!(pkt[7], 0, "wLength high");
    }

    #[test]
    fn get_descriptor_setup_configuration_descriptor() {
        // GET_DESCRIPTOR(Configuration, index=0, length=255)
        let pkt = get_descriptor_setup(2, 0, 255);
        assert_eq!(pkt[3], 2, "desc_type = 2");
        assert_eq!(pkt[6], 255, "wLength = 255");
    }

    #[test]
    fn get_descriptor_setup_wlength_16bit() {
        // Large wLength that needs both bytes (e.g. 300 = 0x012C).
        let pkt = get_descriptor_setup(2, 0, 300);
        assert_eq!(pkt[6], 0x2C, "wLength low byte");
        assert_eq!(pkt[7], 0x01, "wLength high byte");
    }

    // -- get_report_descriptor_setup (WS7-06) --------------------------------

    #[test]
    fn get_report_descriptor_setup_targets_the_interface() {
        let pkt = get_report_descriptor_setup(2, 300);
        assert_eq!(pkt[0], 0x81, "bmRequestType IN/Standard/Interface");
        assert_eq!(pkt[1], 0x06, "bRequest GET_DESCRIPTOR");
        assert_eq!(pkt[2], 0x00, "wValue low = descriptor index 0");
        assert_eq!(pkt[3], 0x22, "wValue high = Report type");
        assert_eq!(pkt[4], 2, "wIndex low = interface number");
        assert_eq!(pkt[5], 0, "wIndex high");
        assert_eq!(pkt[6], 0x2C, "wLength low byte");
        assert_eq!(pkt[7], 0x01, "wLength high byte");
    }

    // -- set_configuration_setup -------------------------------------------

    #[test]
    fn set_configuration_setup_fields() {
        let pkt = set_configuration_setup(1);
        assert_eq!(pkt[0], 0x00, "bmRequestType OUT/Standard/Device");
        assert_eq!(pkt[1], 0x09, "bRequest SET_CONFIGURATION");
        assert_eq!(pkt[2], 1, "bConfigurationValue");
        // wIndex and wLength must be zero.
        assert_eq!(pkt[4], 0);
        assert_eq!(pkt[5], 0);
        assert_eq!(pkt[6], 0);
        assert_eq!(pkt[7], 0);
    }

    // -- set_protocol_boot_setup -------------------------------------------

    #[test]
    fn set_protocol_boot_setup_fields() {
        let pkt = set_protocol_boot_setup(0);
        assert_eq!(pkt[0], 0x21, "bmRequestType Class/Interface");
        assert_eq!(pkt[1], 0x0B, "bRequest SET_PROTOCOL");
        assert_eq!(pkt[2], 0x00, "wValue = Boot Protocol");
        assert_eq!(pkt[3], 0x00);
        assert_eq!(pkt[4], 0, "wIndex = interface 0");
        assert_eq!(pkt[6], 0, "wLength = 0");
    }

    #[test]
    fn set_protocol_boot_setup_interface_1() {
        let pkt = set_protocol_boot_setup(1);
        assert_eq!(pkt[4], 1, "wIndex = interface 1");
    }

    // -- set_idle_setup -----------------------------------------------------

    #[test]
    fn set_idle_setup_fields() {
        let pkt = set_idle_setup(0);
        assert_eq!(pkt[0], 0x21, "bmRequestType Class/Interface");
        assert_eq!(pkt[1], 0x0A, "bRequest SET_IDLE");
        assert_eq!(pkt[2], 0x00, "idle rate = 0");
        assert_eq!(pkt[3], 0x00, "report ID = 0");
        assert_eq!(pkt[4], 0, "wIndex = interface 0");
        assert_eq!(pkt[6], 0, "wLength = 0");
    }

    #[test]
    fn set_idle_setup_interface_number_in_windex() {
        let pkt = set_idle_setup(3);
        assert_eq!(pkt[4], 3, "wIndex = interface 3");
    }
}

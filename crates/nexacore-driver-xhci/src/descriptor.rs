//! USB descriptor parsing — untrusted-input hardened.
//!
//! All data parsed in this module is received over the USB bus (via control
//! transfers from the device) and is therefore **untrusted**. Every parse
//! function:
//!
//! 1. Checks that the input slice is at least as long as the minimum fixed-size
//!    header before accessing any field.
//! 2. Validates `bLength` against the total slice length before advancing the
//!    cursor into the slice.
//! 3. Validates `bDescriptorType` to distinguish known descriptor types.
//! 4. Returns a typed `Err` on any malformed, truncated, or out-of-range input.
//!    **Never panics. Never over-reads.**
//! 5. Skips unknown descriptor types by `bLength` (forward-compatibility).
//!
//! ## References
//!
//! - USB 2.0 specification § 9.4–9.6 (descriptor layout).
//! - USB 3.x specification § 9.4–9.6 (compatible superset).

// =============================================================================
// Descriptor type constants (USB § 9.4 Table 9-5)
// =============================================================================

/// `bDescriptorType` = 1: Device Descriptor.
pub const DESC_TYPE_DEVICE: u8 = 1;

/// `bDescriptorType` = 2: Configuration Descriptor.
pub const DESC_TYPE_CONFIGURATION: u8 = 2;

/// `bDescriptorType` = 4: Interface Descriptor.
pub const DESC_TYPE_INTERFACE: u8 = 4;

/// `bDescriptorType` = 5: Endpoint Descriptor.
pub const DESC_TYPE_ENDPOINT: u8 = 5;

// =============================================================================
// Error type
// =============================================================================

/// Errors returned by USB descriptor parsing functions.
///
/// Every variant carries enough context for the caller to diagnose the
/// problem without further state; no heap allocation is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DescriptorError {
    /// The input slice is shorter than the minimum required for this
    /// descriptor type.
    ///
    /// For a Device Descriptor the minimum is 18 bytes (USB § 9.6.1);
    /// for a Configuration Descriptor the minimum is 9 bytes.
    TooShort,
    /// `bLength` in the descriptor header claims fewer bytes than the
    /// fixed-size minimum for this descriptor type.
    ///
    /// For a Device Descriptor `bLength` must be `>= 18`; for Configuration
    /// `>= 9`; for Interface `>= 9`; for Endpoint `>= 7`.
    BLengthTooSmall,
    /// `bLength` in the descriptor header claims more bytes than are
    /// available in the input slice (would require an over-read).
    BLengthExceedsData,
    /// `bDescriptorType` does not match the expected type for this parse call.
    WrongType,
    /// `wTotalLength` in a Configuration Descriptor is less than the
    /// descriptor's own `bLength`, or exceeds the input slice length.
    ///
    /// This is a special case of `BLengthExceedsData` for the
    /// `wTotalLength` field.
    InvalidTotalLength,
    /// A nested descriptor's `bLength` is zero (would cause an infinite
    /// advance loop) or advances past the total length boundary.
    MalformedNestedDescriptor,
}

// =============================================================================
// Device Descriptor (USB § 9.6.1)
// =============================================================================

/// Parsed USB Device Descriptor.
///
/// Contains only the fields relevant to TASK-26 (device class, max packet
/// size, VID/PID, and configuration count). Full descriptor fields are
/// available through the raw byte slice in more advanced scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDescriptor {
    /// `bcdUSB` — USB specification release number in BCD.
    pub bcd_usb: u16,
    /// `bDeviceClass` — device class code. `0` = class determined per interface.
    pub device_class: u8,
    /// `bDeviceSubClass` — device sub-class code.
    pub device_sub_class: u8,
    /// `bDeviceProtocol` — device protocol code.
    pub device_protocol: u8,
    /// `bMaxPacketSize0` — maximum packet size for endpoint 0.
    ///
    /// Valid values: 8, 16, 32, 64 (USB 2); 9 (SS, meaning `2^9 = 512`).
    pub max_packet_size0: u8,
    /// `idVendor` — vendor ID assigned by USB-IF.
    pub id_vendor: u16,
    /// `idProduct` — product ID assigned by the manufacturer.
    pub id_product: u16,
    /// `bcdDevice` — device release number in BCD.
    pub bcd_device: u16,
    /// `bNumConfigurations` — number of configurations.
    pub num_configurations: u8,
}

/// Minimum byte length of a USB Device Descriptor (USB § 9.6.1 Table 9-8).
pub const DEVICE_DESCRIPTOR_MIN_LEN: usize = 18;

/// Parse a USB Device Descriptor from `data`.
///
/// `data` must be at least 18 bytes and must begin with a valid Device
/// Descriptor header (`bLength >= 18`, `bDescriptorType = 1`).
///
/// # Errors
///
/// - [`DescriptorError::TooShort`] when `data.len() < 18`.
/// - [`DescriptorError::BLengthTooSmall`] when `bLength < 18`.
/// - [`DescriptorError::BLengthExceedsData`] when `bLength > data.len()`.
/// - [`DescriptorError::WrongType`] when `bDescriptorType != 1`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::descriptor::{DEVICE_DESCRIPTOR_MIN_LEN, parse_device_descriptor};
///
/// // A minimal Device Descriptor for a USB HID keyboard (VID=0x045E, PID=0x00DD).
/// let raw: [u8; 18] = [
///     0x12, 0x01, // bLength=18, bDescriptorType=1
///     0x00, 0x02, // bcdUSB = 2.00
///     0x00, 0x00, 0x00, // bDeviceClass, SubClass, Protocol
///     0x08, // bMaxPacketSize0 = 8
///     0x5E, 0x04, // idVendor = 0x045E (Microsoft)
///     0xDD, 0x00, // idProduct = 0x00DD
///     0x12, 0x03, // bcdDevice
///     0x01, 0x02, 0x03, // iManufacturer, iProduct, iSerialNumber
///     0x01, // bNumConfigurations
/// ];
/// let desc = parse_device_descriptor(&raw).unwrap();
/// assert_eq!(desc.id_vendor, 0x045E);
/// assert_eq!(desc.id_product, 0x00DD);
/// ```
pub fn parse_device_descriptor(data: &[u8]) -> Result<DeviceDescriptor, DescriptorError> {
    if data.len() < DEVICE_DESCRIPTOR_MIN_LEN {
        return Err(DescriptorError::TooShort);
    }
    let b_length = *data.first().ok_or(DescriptorError::TooShort)? as usize;
    let b_type = *data.get(1).ok_or(DescriptorError::TooShort)?;

    if b_length < DEVICE_DESCRIPTOR_MIN_LEN {
        return Err(DescriptorError::BLengthTooSmall);
    }
    if b_length > data.len() {
        return Err(DescriptorError::BLengthExceedsData);
    }
    if b_type != DESC_TYPE_DEVICE {
        return Err(DescriptorError::WrongType);
    }

    // All field accesses below are bounded by `b_length >= 18` and
    // `data.len() >= b_length` — both checked above.
    let bcd_usb = read_le_u16(data, 2).ok_or(DescriptorError::TooShort)?;
    let device_class = *data.get(4).ok_or(DescriptorError::TooShort)?;
    let device_sub_class = *data.get(5).ok_or(DescriptorError::TooShort)?;
    let device_protocol = *data.get(6).ok_or(DescriptorError::TooShort)?;
    let max_packet_size0 = *data.get(7).ok_or(DescriptorError::TooShort)?;
    let id_vendor = read_le_u16(data, 8).ok_or(DescriptorError::TooShort)?;
    let id_product = read_le_u16(data, 10).ok_or(DescriptorError::TooShort)?;
    let bcd_device = read_le_u16(data, 12).ok_or(DescriptorError::TooShort)?;
    // Bytes 14, 15, 16 are string index fields (iManufacturer, iProduct,
    // iSerialNumber) — not stored in DeviceDescriptor for TASK-26.
    let num_configurations = *data.get(17).ok_or(DescriptorError::TooShort)?;

    Ok(DeviceDescriptor {
        bcd_usb,
        device_class,
        device_sub_class,
        device_protocol,
        max_packet_size0,
        id_vendor,
        id_product,
        bcd_device,
        num_configurations,
    })
}

// =============================================================================
// Configuration Descriptor and nested descriptor iteration (USB § 9.6.3)
// =============================================================================

/// Parsed Interface Descriptor (USB § 9.6.5 Table 9-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    /// `bInterfaceNumber` — interface index within the configuration.
    pub interface_number: u8,
    /// `bAlternateSetting`.
    pub alternate_setting: u8,
    /// `bNumEndpoints` — number of endpoints (excluding EP0) used.
    pub num_endpoints: u8,
    /// `bInterfaceClass` — class code.
    pub interface_class: u8,
    /// `bInterfaceSubClass`.
    pub interface_sub_class: u8,
    /// `bInterfaceProtocol`.
    pub interface_protocol: u8,
}

/// Parsed Endpoint Descriptor (USB § 9.6.6 Table 9-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointDescriptor {
    /// `bEndpointAddress` — endpoint number + direction.
    pub address: u8,
    /// `bmAttributes` — transfer type + usage type bits.
    pub attributes: u8,
    /// `wMaxPacketSize`.
    pub max_packet_size: u16,
    /// `bInterval` — polling interval (for interrupt and isoch endpoints).
    pub interval: u8,
}

/// A parsed descriptor encountered while walking a Configuration Descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDescItem {
    /// An Interface Descriptor.
    Interface(InterfaceDescriptor),
    /// An Endpoint Descriptor.
    Endpoint(EndpointDescriptor),
    /// An unknown or vendor-specific descriptor: `(bDescriptorType, bLength)`.
    ///
    /// The cursor was advanced past this descriptor by `bLength` bytes; no
    /// data is returned.
    Unknown(u8, u8),
}

/// Parsed Configuration Descriptor header (USB § 9.6.3 Table 9-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationHeader {
    /// `wTotalLength` — total length of the configuration descriptor data
    /// (header + all nested descriptors).
    pub total_length: u16,
    /// `bNumInterfaces`.
    pub num_interfaces: u8,
    /// `bConfigurationValue`.
    pub configuration_value: u8,
    /// `bmAttributes`.
    pub attributes: u8,
    /// `bMaxPower` — maximum current in 2 mA units.
    pub max_power: u8,
}

/// Minimum byte length of a USB Configuration Descriptor header.
pub const CONFIG_DESCRIPTOR_MIN_LEN: usize = 9;

/// Parse the Configuration Descriptor header from `data` and return the
/// header fields along with a slice covering the nested descriptors.
///
/// The returned nested slice covers `data[9..total_length]` (where
/// `total_length` is the `wTotalLength` field). Walking that slice with
/// [`walk_config_descriptors`] yields the interface and endpoint descriptors.
///
/// # Errors
///
/// - [`DescriptorError::TooShort`] when `data.len() < 9`.
/// - [`DescriptorError::BLengthTooSmall`] when `bLength < 9`.
/// - [`DescriptorError::BLengthExceedsData`] when `bLength > data.len()`.
/// - [`DescriptorError::WrongType`] when `bDescriptorType != 2`.
/// - [`DescriptorError::InvalidTotalLength`] when `wTotalLength < bLength` or
///   `wTotalLength > data.len()`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::descriptor::parse_configuration_header;
///
/// // Minimal config descriptor: 9-byte header, bLength=9, type=2,
/// // wTotalLength=9 (header only, no endpoints).
/// let raw = [0x09u8, 0x02, 0x09, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32];
/// let (hdr, nested) = parse_configuration_header(&raw).unwrap();
/// assert_eq!(hdr.num_interfaces, 1);
/// assert!(nested.is_empty());
/// ```
pub fn parse_configuration_header(
    data: &[u8],
) -> Result<(ConfigurationHeader, &[u8]), DescriptorError> {
    if data.len() < CONFIG_DESCRIPTOR_MIN_LEN {
        return Err(DescriptorError::TooShort);
    }
    let b_length = *data.first().ok_or(DescriptorError::TooShort)? as usize;
    let b_type = *data.get(1).ok_or(DescriptorError::TooShort)?;

    if b_length < CONFIG_DESCRIPTOR_MIN_LEN {
        return Err(DescriptorError::BLengthTooSmall);
    }
    if b_length > data.len() {
        return Err(DescriptorError::BLengthExceedsData);
    }
    if b_type != DESC_TYPE_CONFIGURATION {
        return Err(DescriptorError::WrongType);
    }

    let total_length = read_le_u16(data, 2).ok_or(DescriptorError::TooShort)?;
    let total_len_usize = total_length as usize;
    if total_len_usize < b_length {
        return Err(DescriptorError::InvalidTotalLength);
    }
    if total_len_usize > data.len() {
        return Err(DescriptorError::InvalidTotalLength);
    }

    let num_interfaces = *data.get(4).ok_or(DescriptorError::TooShort)?;
    let configuration_value = *data.get(5).ok_or(DescriptorError::TooShort)?;
    let attributes = *data.get(7).ok_or(DescriptorError::TooShort)?;
    let max_power = *data.get(8).ok_or(DescriptorError::TooShort)?;

    let header = ConfigurationHeader {
        total_length,
        num_interfaces,
        configuration_value,
        attributes,
        max_power,
    };

    // Nested descriptors start after the config header, within total_length.
    let nested = data
        .get(b_length..total_len_usize)
        .ok_or(DescriptorError::InvalidTotalLength)?;
    Ok((header, nested))
}

/// Walk the nested descriptor bytes from a Configuration Descriptor and call
/// `visitor` for each recognised descriptor.
///
/// `nested` is the slice returned by [`parse_configuration_header`]. This
/// function iterates by `bLength` steps; unknown descriptor types are yielded
/// as [`ConfigDescItem::Unknown`] (the caller may inspect the type and skip
/// or record them).
///
/// Returns the number of descriptors visited on success.
///
/// # Errors
///
/// - [`DescriptorError::MalformedNestedDescriptor`] when any nested
///   descriptor's `bLength` is zero or would advance past the slice end.
///   The walk is aborted immediately; already-visited descriptors have been
///   delivered to `visitor`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::descriptor::{
///     ConfigDescItem, DESC_TYPE_INTERFACE, walk_config_descriptors,
/// };
///
/// // Minimal interface descriptor (9 bytes, type=4).
/// let nested = [0x09u8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// let mut count = 0usize;
/// walk_config_descriptors(&nested, |item| {
///     if matches!(item, ConfigDescItem::Interface(_)) {
///         count += 1;
///     }
/// })
/// .unwrap();
/// assert_eq!(count, 1);
/// ```
pub fn walk_config_descriptors<F>(nested: &[u8], mut visitor: F) -> Result<usize, DescriptorError>
where
    F: FnMut(ConfigDescItem),
{
    let mut cursor = 0usize;
    let mut count = 0usize;
    while cursor < nested.len() {
        // Need at least 2 bytes (bLength + bDescriptorType).
        let remaining = nested
            .get(cursor..)
            .ok_or(DescriptorError::MalformedNestedDescriptor)?;
        if remaining.len() < 2 {
            break; // trailing padding — tolerate
        }

        let b_length = *remaining
            .first()
            .ok_or(DescriptorError::MalformedNestedDescriptor)? as usize;
        let b_type = *remaining
            .get(1)
            .ok_or(DescriptorError::MalformedNestedDescriptor)?;

        if b_length == 0 {
            return Err(DescriptorError::MalformedNestedDescriptor);
        }
        if b_length > remaining.len() {
            return Err(DescriptorError::MalformedNestedDescriptor);
        }

        let desc_bytes = remaining
            .get(0..b_length)
            .ok_or(DescriptorError::MalformedNestedDescriptor)?;

        match b_type {
            DESC_TYPE_INTERFACE => {
                if b_length >= 9 {
                    let iface = parse_interface_from_bytes(desc_bytes);
                    visitor(ConfigDescItem::Interface(iface));
                    count += 1;
                } else {
                    return Err(DescriptorError::BLengthTooSmall);
                }
            }
            DESC_TYPE_ENDPOINT => {
                if b_length >= 7 {
                    let ep = parse_endpoint_from_bytes(desc_bytes);
                    visitor(ConfigDescItem::Endpoint(ep));
                    count += 1;
                } else {
                    return Err(DescriptorError::BLengthTooSmall);
                }
            }
            _ => {
                // Unknown descriptor type: skip by bLength (forward compat).
                // b_length was validated above as <= remaining.len() <= slice len <= usize::MAX;
                // in practice bLength is a u8 read from a u8 field so it fits in u8.
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "b_length came from a u8 bLength field; fits in u8 by construction"
                )]
                visitor(ConfigDescItem::Unknown(b_type, b_length as u8));
                count += 1;
            }
        }

        cursor = cursor
            .checked_add(b_length)
            .ok_or(DescriptorError::MalformedNestedDescriptor)?;
    }
    Ok(count)
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Read a little-endian u16 from `data` starting at `offset`.
///
/// Returns `None` if `data.len() < offset + 2`.
fn read_le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let lo = *data.get(offset)?;
    let hi = *data.get(offset + 1)?;
    Some(u16::from(lo) | (u16::from(hi) << 8))
}

/// Parse an Interface Descriptor from a validated byte slice (`b_length >= 9`).
fn parse_interface_from_bytes(data: &[u8]) -> InterfaceDescriptor {
    // Accesses are safe: caller guarantees data.len() >= 9.
    InterfaceDescriptor {
        interface_number: data.get(2).copied().unwrap_or(0),
        alternate_setting: data.get(3).copied().unwrap_or(0),
        num_endpoints: data.get(4).copied().unwrap_or(0),
        interface_class: data.get(5).copied().unwrap_or(0),
        interface_sub_class: data.get(6).copied().unwrap_or(0),
        interface_protocol: data.get(7).copied().unwrap_or(0),
    }
}

/// Parse an Endpoint Descriptor from a validated byte slice (`b_length >= 7`).
fn parse_endpoint_from_bytes(data: &[u8]) -> EndpointDescriptor {
    let max_packet_size = read_le_u16(data, 4).unwrap_or(0);
    EndpointDescriptor {
        address: data.get(2).copied().unwrap_or(0),
        attributes: data.get(3).copied().unwrap_or(0),
        max_packet_size,
        interval: data.get(6).copied().unwrap_or(0),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_device_descriptor ---------------------------------------------

    /// A real 18-byte USB Device Descriptor for a USB keyboard (VID=0x045E PID=0x00DD).
    const KEYBOARD_DEVICE_DESC: [u8; 18] = [
        0x12, 0x01, // bLength=18, bDescriptorType=1
        0x00, 0x02, // bcdUSB = 2.00
        0x00, 0x00, 0x00, // bDeviceClass=0, bDeviceSubClass=0, bDeviceProtocol=0
        0x08, // bMaxPacketSize0 = 8
        0x5E, 0x04, // idVendor = 0x045E
        0xDD, 0x00, // idProduct = 0x00DD
        0x12, 0x03, // bcdDevice = 0x0312
        0x01, 0x02, 0x03, // iManufacturer=1, iProduct=2, iSerial=3
        0x01, // bNumConfigurations = 1
    ];

    #[test]
    fn parse_device_descriptor_happy_path() {
        let desc = parse_device_descriptor(&KEYBOARD_DEVICE_DESC).unwrap();
        assert_eq!(desc.id_vendor, 0x045E);
        assert_eq!(desc.id_product, 0x00DD);
        assert_eq!(desc.bcd_usb, 0x0200);
        assert_eq!(desc.max_packet_size0, 8);
        assert_eq!(desc.num_configurations, 1);
        assert_eq!(desc.device_class, 0);
    }

    #[test]
    fn parse_device_descriptor_too_short_rejects() {
        let short = &KEYBOARD_DEVICE_DESC[..17];
        assert_eq!(
            parse_device_descriptor(short),
            Err(DescriptorError::TooShort)
        );
    }

    #[test]
    fn parse_device_descriptor_empty_rejects() {
        assert_eq!(parse_device_descriptor(&[]), Err(DescriptorError::TooShort));
    }

    #[test]
    fn parse_device_descriptor_blength_too_small_rejects() {
        let mut bad = KEYBOARD_DEVICE_DESC;
        bad[0] = 0x11; // bLength = 17 < 18
        assert_eq!(
            parse_device_descriptor(&bad),
            Err(DescriptorError::BLengthTooSmall)
        );
    }

    #[test]
    fn parse_device_descriptor_blength_zero_rejects() {
        let mut bad = KEYBOARD_DEVICE_DESC;
        bad[0] = 0; // bLength = 0
        assert_eq!(
            parse_device_descriptor(&bad),
            Err(DescriptorError::BLengthTooSmall)
        );
    }

    #[test]
    fn parse_device_descriptor_blength_exceeds_data_rejects() {
        let mut bad = KEYBOARD_DEVICE_DESC;
        bad[0] = 0x13; // bLength = 19 > 18 (the actual data length)
        assert_eq!(
            parse_device_descriptor(&bad),
            Err(DescriptorError::BLengthExceedsData)
        );
    }

    #[test]
    fn parse_device_descriptor_wrong_type_rejects() {
        let mut bad = KEYBOARD_DEVICE_DESC;
        bad[1] = 0x02; // bDescriptorType = 2 (Configuration, not Device)
        assert_eq!(
            parse_device_descriptor(&bad),
            Err(DescriptorError::WrongType)
        );
    }

    #[test]
    fn parse_device_descriptor_type_zero_rejects() {
        let mut bad = KEYBOARD_DEVICE_DESC;
        bad[1] = 0x00;
        assert_eq!(
            parse_device_descriptor(&bad),
            Err(DescriptorError::WrongType)
        );
    }

    // -- parse_configuration_header ------------------------------------------

    /// A minimal Configuration Descriptor (9 bytes, no nested descriptors).
    const CONFIG_HEADER_ONLY: [u8; 9] = [
        0x09, 0x02, // bLength=9, bDescriptorType=2
        0x09, 0x00, // wTotalLength = 9
        0x01, // bNumInterfaces = 1
        0x01, // bConfigurationValue = 1
        0x00, // iConfiguration
        0x80, // bmAttributes
        0x32, // bMaxPower = 50 (100 mA)
    ];

    #[test]
    fn parse_configuration_header_happy_path() {
        let (hdr, nested) = parse_configuration_header(&CONFIG_HEADER_ONLY).unwrap();
        assert_eq!(hdr.num_interfaces, 1);
        assert_eq!(hdr.configuration_value, 1);
        assert_eq!(hdr.total_length, 9);
        assert!(nested.is_empty());
    }

    #[test]
    fn parse_configuration_header_too_short_rejects() {
        assert_eq!(
            parse_configuration_header(&[0x09u8, 0x02][..]),
            Err(DescriptorError::TooShort)
        );
    }

    #[test]
    fn parse_configuration_header_wrong_type_rejects() {
        let mut bad = CONFIG_HEADER_ONLY;
        bad[1] = 0x01; // Device type
        assert_eq!(
            parse_configuration_header(&bad),
            Err(DescriptorError::WrongType)
        );
    }

    #[test]
    fn parse_configuration_header_invalid_total_length_too_small_rejects() {
        let mut bad = CONFIG_HEADER_ONLY;
        bad[2] = 0x08; // wTotalLength = 8 < bLength = 9
        bad[3] = 0x00;
        assert_eq!(
            parse_configuration_header(&bad),
            Err(DescriptorError::InvalidTotalLength)
        );
    }

    #[test]
    fn parse_configuration_header_invalid_total_length_exceeds_data_rejects() {
        let mut bad = CONFIG_HEADER_ONLY;
        bad[2] = 0x64; // wTotalLength = 100 > 9 (actual data)
        bad[3] = 0x00;
        assert_eq!(
            parse_configuration_header(&bad),
            Err(DescriptorError::InvalidTotalLength)
        );
    }

    // -- walk_config_descriptors ---------------------------------------------

    /// Minimal Interface Descriptor (9 bytes).
    const IFACE_DESC: [u8; 9] = [
        0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01,
        0x00,
        //bLen bType bNum  bAlt  nEP  bClass bSub bProto iIface
    ];

    /// Minimal Endpoint Descriptor (7 bytes).
    const EP_DESC: [u8; 7] = [
        0x07, 0x05, 0x81, 0x03, 0x08, 0x00,
        0x0A,
        //bLen bType bAddr bAttr wMPS        bInterval
    ];

    #[test]
    fn walk_config_descriptors_parses_interface() {
        let mut interfaces = 0usize;
        walk_config_descriptors(&IFACE_DESC, |item| {
            if matches!(item, ConfigDescItem::Interface(_)) {
                interfaces += 1;
            }
        })
        .unwrap();
        assert_eq!(interfaces, 1);
    }

    #[test]
    fn walk_config_descriptors_parses_endpoint() {
        let mut endpoints = 0usize;
        walk_config_descriptors(&EP_DESC, |item| {
            if matches!(item, ConfigDescItem::Endpoint(_)) {
                endpoints += 1;
            }
        })
        .unwrap();
        assert_eq!(endpoints, 1);
    }

    #[test]
    fn walk_config_descriptors_parses_iface_then_endpoint() {
        let mut nested = [0u8; 16];
        nested.get_mut(0..9).unwrap().copy_from_slice(&IFACE_DESC);
        nested.get_mut(9..16).unwrap().copy_from_slice(&EP_DESC);
        let mut items = 0usize;
        walk_config_descriptors(&nested, |_| items += 1).unwrap();
        assert_eq!(items, 2);
    }

    #[test]
    fn walk_config_descriptors_skips_unknown_by_blength() {
        // A vendor-specific descriptor: bLength=4, type=0xFF, 2 bytes padding.
        let unknown: [u8; 4] = [0x04, 0xFF, 0xAA, 0xBB];
        let mut unknowns = 0usize;
        walk_config_descriptors(&unknown, |item| {
            if let ConfigDescItem::Unknown(t, _) = item {
                assert_eq!(t, 0xFF);
                unknowns += 1;
            }
        })
        .unwrap();
        assert_eq!(unknowns, 1);
    }

    #[test]
    fn walk_config_descriptors_blength_zero_returns_err() {
        let bad: [u8; 4] = [0x00, 0x04, 0x00, 0x00]; // bLength = 0
        assert_eq!(
            walk_config_descriptors(&bad, |_| {}),
            Err(DescriptorError::MalformedNestedDescriptor)
        );
    }

    #[test]
    fn walk_config_descriptors_blength_exceeds_remaining_returns_err() {
        // bLength = 10 but only 7 bytes available.
        let bad: [u8; 7] = [0x0A, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            walk_config_descriptors(&bad, |_| {}),
            Err(DescriptorError::MalformedNestedDescriptor)
        );
    }

    #[test]
    fn walk_config_descriptors_empty_nested_returns_ok() {
        let count = walk_config_descriptors(&[], |_| {}).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn descriptor_error_variants_distinguishable() {
        let variants = [
            DescriptorError::TooShort,
            DescriptorError::BLengthTooSmall,
            DescriptorError::BLengthExceedsData,
            DescriptorError::WrongType,
            DescriptorError::InvalidTotalLength,
            DescriptorError::MalformedNestedDescriptor,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "variant {i} must equal itself");
                } else {
                    assert_ne!(a, b, "variants {i} and {j} must differ");
                }
            }
        }
    }

    #[test]
    fn endpoint_descriptor_fields_parsed_correctly() {
        let mut ep_items: Vec<EndpointDescriptor> = Vec::new();
        walk_config_descriptors(&EP_DESC, |item| {
            if let ConfigDescItem::Endpoint(ep) = item {
                ep_items.push(ep);
            }
        })
        .unwrap();
        let ep = ep_items.first().unwrap();
        assert_eq!(ep.address, 0x81); // IN endpoint 1
        assert_eq!(ep.attributes, 0x03); // Interrupt
        assert_eq!(ep.max_packet_size, 8);
        assert_eq!(ep.interval, 0x0A);
    }

    #[test]
    fn interface_descriptor_fields_parsed_correctly() {
        let mut iface_items: Vec<InterfaceDescriptor> = Vec::new();
        walk_config_descriptors(&IFACE_DESC, |item| {
            if let ConfigDescItem::Interface(i) = item {
                iface_items.push(i);
            }
        })
        .unwrap();
        let iface = iface_items.first().unwrap();
        assert_eq!(iface.interface_class, 0x03); // HID
        assert_eq!(iface.num_endpoints, 1);
    }
}

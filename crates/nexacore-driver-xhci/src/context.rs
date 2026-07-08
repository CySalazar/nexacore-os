//! xHCI device context data structures: DCBAA, Slot Context, Endpoint Context,
//! and Input Context.
//!
//! ## Layout
//!
//! Per xHCI § 6.2, all context structures come in two sizes:
//! - **32-byte contexts** when `HCCPARAMS1.CSZ = 0`.
//! - **64-byte contexts** when `HCCPARAMS1.CSZ = 1`.
//!
//! This module exposes the context size as a `const` generic parameter `CSZ`
//! (in bytes: 32 or 64) so the compiler selects the correct layout at
//! instantiation time. The image crate reads `HCCPARAMS1.CSZ` at bring-up
//! and chooses the appropriate type.
//!
//! ## DCBAA
//!
//! The Device Context Base Address Array (DCBAA) is an array of `MaxSlots + 1`
//! 64-bit pointers. Slot 0 is reserved for a Scratchpad Buffer Array pointer
//! (or zero if the controller reports `HCSPARAMS2.Max Scratchpad Bufs = 0`).
//! Slots 1..=`MaxSlots` point to the device context for each assigned slot.
//!
//! ## Input Context
//!
//! The Input Context consists of:
//! - Input Control Context (32 or 64 bytes): Add/Drop bitmask.
//! - Slot Context (32 or 64 bytes): device-level state.
//! - Endpoint Context array: EP0 (and additional EPs for Configure Endpoint).
//!
//! All builder functions write into caller-supplied byte slices; no allocation
//! is performed here.

// =============================================================================
// Context size type alias
// =============================================================================

/// 32-byte context size discriminant (CSZ = 0).
pub const CTX_SIZE_32: usize = 32;

/// 64-byte context size discriminant (CSZ = 1).
pub const CTX_SIZE_64: usize = 64;

// =============================================================================
// USB speed constants (used in Slot Context Route String + speed fields)
// =============================================================================

/// USB device speed: Full Speed (12 Mb/s), USB 1.1.
pub const USB_SPEED_FULL: u8 = 1;

/// USB device speed: Low Speed (1.5 Mb/s), USB 1.0.
pub const USB_SPEED_LOW: u8 = 2;

/// USB device speed: High Speed (480 Mb/s), USB 2.0.
pub const USB_SPEED_HIGH: u8 = 3;

/// USB device speed: `SuperSpeed` (5 Gb/s), USB 3.0.
pub const USB_SPEED_SUPER: u8 = 4;

/// USB device speed: `SuperSpeed`+ (10 Gb/s), USB 3.1.
pub const USB_SPEED_SUPER_PLUS: u8 = 5;

// =============================================================================
// Input Control Context
// =============================================================================

/// Write an Input Control Context into `buf[0..ctx_size]`.
///
/// The Input Control Context specifies which contexts the Enable Slot /
/// Address Device / Configure Endpoint command should add or drop:
/// - `add_flags`: bitmask of context indices to add (bit 0 = Slot Context,
///   bit 1 = EP0, bits 2..=31 = EP1..=EP30).
/// - `drop_flags`: bitmask of contexts to drop (same bit numbering).
///
/// For Address Device the `add_flags` MUST include bit 0 (Slot) and bit 1
/// (EP0); `drop_flags` MUST be 0.
///
/// # Errors
///
/// Returns `false` if `buf.len() < ctx_size`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::context::{CTX_SIZE_32, write_input_control_context};
///
/// let mut buf = [0u8; CTX_SIZE_32];
/// // Add slot + EP0; drop nothing.
/// assert!(write_input_control_context(&mut buf, CTX_SIZE_32, 0b11, 0));
/// let add = u32::from_le_bytes(buf[4..8].try_into().unwrap());
/// assert_eq!(add, 0b11);
/// ```
pub fn write_input_control_context(
    buf: &mut [u8],
    ctx_size: usize,
    add_flags: u32,
    drop_flags: u32,
) -> bool {
    if buf.len() < ctx_size {
        return false;
    }
    // Bytes 0..3: Drop Context Flags (D31..D2; bits 1:0 reserved).
    // Drop flags only apply to bits 31:2; bits 1:0 (Slot and reserved) stay 0.
    let drop_masked = drop_flags & 0xFFFF_FFFC;
    let drop_bytes = drop_masked.to_le_bytes();
    if let Some(dest) = buf.get_mut(0..4) {
        dest.copy_from_slice(&drop_bytes);
    }
    // Bytes 4..7: Add Context Flags (A31..A0).
    let add_bytes = add_flags.to_le_bytes();
    if let Some(dest) = buf.get_mut(4..8) {
        dest.copy_from_slice(&add_bytes);
    }
    // Bytes 8..ctx_size: zeroed (Configuration Value, Interface Number, etc.).
    if let Some(rest) = buf.get_mut(8..ctx_size) {
        rest.fill(0);
    }
    true
}

// =============================================================================
// Slot Context builder
// =============================================================================

/// Write a Slot Context into `buf[0..ctx_size]`.
///
/// Per xHCI § 6.2.2:
/// - `route_string`: 20-bit USB route string (0 for root-hub ports).
/// - `speed`: USB device speed (one of the `USB_SPEED_*` constants).
/// - `root_hub_port`: 1-based root hub port number.
/// - `context_entries`: number of endpoint contexts following the Slot Context
///   (1 = EP0 only; must be `1..=31`).
///
/// # Errors
///
/// Returns `false` if `buf.len() < ctx_size`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::context::{CTX_SIZE_32, USB_SPEED_HIGH, write_slot_context};
///
/// let mut buf = [0u8; CTX_SIZE_32];
/// assert!(write_slot_context(
///     &mut buf,
///     CTX_SIZE_32,
///     0,
///     USB_SPEED_HIGH,
///     1,
///     1
/// ));
/// // DWord 0: Route String=0, Speed=3 (bits 23:20), Context Entries=1 (bits 31:27).
/// let dw0 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
/// assert_eq!((dw0 >> 20) & 0xF, u32::from(USB_SPEED_HIGH), "speed field");
/// assert_eq!((dw0 >> 27) & 0x1F, 1, "context entries");
/// ```
pub fn write_slot_context(
    buf: &mut [u8],
    ctx_size: usize,
    route_string: u32,
    speed: u8,
    root_hub_port: u8,
    context_entries: u8,
) -> bool {
    if buf.len() < ctx_size {
        return false;
    }
    // DWord 0 (xHCI § 6.2.2 Table 57):
    //   Bits 19:0  — Route String
    //   Bits 23:20 — Speed
    //   Bit 25     — MTT (Multi-TT hub, 0 for direct connection)
    //   Bit 26     — Hub (0 for non-hub)
    //   Bits 31:27 — Context Entries
    let dw0: u32 = (route_string & 0x000F_FFFF)
        | (u32::from(speed & 0xF) << 20)
        | (u32::from(context_entries & 0x1F) << 27);
    // DWord 1: Max Exit Latency (bits 15:0) — 0 for FS/LS/HS; RH port (bits 23:16);
    //          bits 31:24 reserved.
    let dw1: u32 = u32::from(root_hub_port) << 16;
    // DWord 2..7: zeroed for Address Device (fields like USB Device Address are
    // filled by the xHC after SET_ADDRESS).
    if let Some(dest) = buf.get_mut(0..4) {
        dest.copy_from_slice(&dw0.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(4..8) {
        dest.copy_from_slice(&dw1.to_le_bytes());
    }
    if let Some(rest) = buf.get_mut(8..ctx_size) {
        rest.fill(0);
    }
    true
}

// =============================================================================
// Endpoint Context builder
// =============================================================================

/// Endpoint type codes used in the Endpoint Context `EP Type` field
/// (xHCI § 6.2.3 Table 58).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointType {
    /// Not valid (EP Type = 0).
    NotValid = 0,
    /// Isoch OUT (EP Type = 1).
    IsochOut = 1,
    /// Bulk OUT (EP Type = 2).
    BulkOut = 2,
    /// Interrupt OUT (EP Type = 3).
    InterruptOut = 3,
    /// Control Bidirectional (EP Type = 4) — EP0.
    Control = 4,
    /// Isoch IN (EP Type = 5).
    IsochIn = 5,
    /// Bulk IN (EP Type = 6).
    BulkIn = 6,
    /// Interrupt IN (EP Type = 7).
    InterruptIn = 7,
}

/// Write an Endpoint 0 (Control) Context into `buf[0..ctx_size]`.
///
/// Per xHCI § 6.2.3, the EP0 context is always type `Control` (4). The
/// `transfer_ring_dequeue_ptr` must be the IOVA of the EP0 transfer ring's
/// first TRB, with bit 0 set to the Dequeue Cycle State (DCS).
///
/// `max_packet_size` is read from the Device Descriptor `bMaxPacketSize0`
/// field (8, 16, 32, or 64 bytes for FS/HS; 512 for SS).
///
/// `cycle_state` is the initial producer cycle state (same as the DCS bit
/// embedded in `transfer_ring_dequeue_ptr`).
///
/// # Errors
///
/// Returns `false` if `buf.len() < ctx_size`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::context::{CTX_SIZE_32, EndpointType, write_ep0_context};
///
/// let mut buf = [0u8; CTX_SIZE_32];
/// // EP0 transfer ring at IOVA 0x0040_0001 (DCS=1).
/// assert!(write_ep0_context(
///     &mut buf,
///     CTX_SIZE_32,
///     0x0040_0001,
///     64,
///     true
/// ));
/// // DWord 1: EP State = 0 (initial), EP Type = 4 (Control) in bits 5:3.
/// let dw1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
/// assert_eq!((dw1 >> 3) & 0x7, EndpointType::Control as u32, "EP type");
/// ```
pub fn write_ep0_context(
    buf: &mut [u8],
    ctx_size: usize,
    transfer_ring_dequeue_ptr: u64,
    max_packet_size: u16,
    _cycle_state: bool,
) -> bool {
    if buf.len() < ctx_size {
        return false;
    }
    // DWord 0: EP State (bits 2:0) = 0 (Disabled, xHC transitions to Running);
    //          Mult (bits 9:8) = 0; Max P Streams (bits 14:10) = 0;
    //          LSA (bit 15) = 0; Interval (bits 23:16) = 0; Max ESIT Hi (bits 31:24) = 0.
    let dw0: u32 = 0;
    // DWord 1: Cerr (bits 3:1) = 3 (max retries); EP Type (bits 5:3) = 4 (Control);
    //          bits 7:6 = 0; Max Burst Size (bits 15:8) = 0;
    //          Max Packet Size (bits 31:16).
    let dw1: u32 = (3u32 << 1)              // CErr = 3
        | (u32::from(EndpointType::Control as u8) << 3) // EP Type = 4 (Control)
        | (u32::from(max_packet_size) << 16); // Max Packet Size
    // DWord 2: TR Dequeue Pointer Lo (bits 63:4 are the pointer; bit 0 = DCS).
    #[allow(clippy::cast_possible_truncation)]
    let dw2: u32 = transfer_ring_dequeue_ptr as u32;
    // DWord 3: TR Dequeue Pointer Hi.
    #[allow(clippy::cast_possible_truncation)]
    let dw3: u32 = (transfer_ring_dequeue_ptr >> 32) as u32;
    // DWord 4: Average TRB Length (bits 15:0) = 8 (typical for EP0 control);
    //          Max ESIT Payload Lo (bits 31:16) = 0.
    let dw4: u32 = 8;
    if let Some(dest) = buf.get_mut(0..4) {
        dest.copy_from_slice(&dw0.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(4..8) {
        dest.copy_from_slice(&dw1.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(8..12) {
        dest.copy_from_slice(&dw2.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(12..16) {
        dest.copy_from_slice(&dw3.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(16..20) {
        dest.copy_from_slice(&dw4.to_le_bytes());
    }
    if let Some(rest) = buf.get_mut(20..ctx_size) {
        rest.fill(0);
    }
    true
}

// =============================================================================
// Generic endpoint context builder
// =============================================================================

/// Map a High-Speed interrupt endpoint's `bInterval` to the xHCI Endpoint
/// Context `Interval` field (WS7-06).
///
/// For HS/SS interrupt endpoints the USB descriptor encodes the period as
/// `2^(bInterval-1)` microframes, while the Endpoint Context wants the
/// exponent itself: `Interval = bInterval - 1`, clamped to the valid `0..=15`
/// range (xHCI § 6.2.3.6 Table 65). A `bInterval` of 0 (invalid per USB spec)
/// maps to 0 (125 µs) rather than underflowing.
#[must_use]
pub fn hs_interrupt_context_interval(binterval: u8) -> u8 {
    binterval.saturating_sub(1).min(15)
}

/// Write a generic (non-EP0) Endpoint Context into `buf[0..ctx_size]`.
///
/// Parameterised over endpoint type, max-packet-size, and interval so that
/// the caller can build an endpoint context for any Bulk IN/OUT or Interrupt
/// IN/OUT endpoint discovered during configuration-descriptor walking.
///
/// Per xHCI § 6.2.3:
/// - `ep_type`: one of the [`EndpointType`] variants (Bulk IN/OUT,
///   Interrupt IN/OUT, etc.).
/// - `max_packet_size`: the `wMaxPacketSize` from the Endpoint Descriptor.
/// - `interval`: the `bInterval` from the Endpoint Descriptor.
///   Significant only for Interrupt and Isoch endpoints (xHCI encodes it as
///   `Interval` in `DWord` 0, bits 23:16).
/// - `tr_dequeue_ptr_with_dcs`: the IOVA of the Transfer Ring's first TRB
///   with bit 0 set to the Dequeue Cycle State (DCS).
///
/// The function sets:
/// - `CErr = 3` (maximum error count, per xHCI § 6.2.3) for all non-isoch
///   endpoint types.
/// - `Average TRB Length` = 512 for Bulk endpoints; 8 for Interrupt/Control.
///
/// Returns `false` if `buf.len() < ctx_size`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::context::{CTX_SIZE_32, EndpointType, write_endpoint_context};
///
/// let mut buf = [0u8; CTX_SIZE_32];
/// // Bulk IN endpoint, 512-byte packets, TR at IOVA 0x0050_0001 (DCS=1).
/// assert!(write_endpoint_context(
///     &mut buf,
///     CTX_SIZE_32,
///     EndpointType::BulkIn,
///     512,
///     0,
///     0x0050_0001
/// ));
/// let dw1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
/// // EP Type in bits 5:3 = 6 (BulkIn).
/// assert_eq!((dw1 >> 3) & 0x7, EndpointType::BulkIn as u32);
/// ```
pub fn write_endpoint_context(
    buf: &mut [u8],
    ctx_size: usize,
    ep_type: EndpointType,
    max_packet_size: u16,
    interval: u8,
    tr_dequeue_ptr_with_dcs: u64,
) -> bool {
    if buf.len() < ctx_size {
        return false;
    }
    // DWord 0: Interval (bits 23:16); all other fields 0 for default config.
    let dw0: u32 = u32::from(interval) << 16;
    // DWord 1: CErr (bits 2:1) = 3; EP Type (bits 5:3); Max Packet Size (bits 31:16).
    // CErr = 3 provides maximum retry count for non-isoch endpoints; per xHCI
    // § 6.2.3 Table 60 the field is "Error Count" for non-isoch endpoints.
    let cerr: u32 = 3;
    let dw1: u32 =
        (cerr << 1) | (u32::from(ep_type as u8) << 3) | (u32::from(max_packet_size) << 16);
    // DWord 2: TR Dequeue Pointer low (with DCS in bit 0).
    #[allow(clippy::cast_possible_truncation)]
    let dw2: u32 = tr_dequeue_ptr_with_dcs as u32;
    // DWord 3: TR Dequeue Pointer high.
    #[allow(clippy::cast_possible_truncation)]
    let dw3: u32 = (tr_dequeue_ptr_with_dcs >> 32) as u32;
    // DWord 4: Average TRB Length (bits 15:0).
    // Bulk: 512 bytes is typical for full USB 3 packets.
    // Interrupt/Control: 8 bytes is the boot-protocol report size.
    let avg_trb_len: u16 = match ep_type {
        EndpointType::BulkIn | EndpointType::BulkOut => 512,
        _ => 8,
    };
    let dw4: u32 = u32::from(avg_trb_len);
    if let Some(dest) = buf.get_mut(0..4) {
        dest.copy_from_slice(&dw0.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(4..8) {
        dest.copy_from_slice(&dw1.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(8..12) {
        dest.copy_from_slice(&dw2.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(12..16) {
        dest.copy_from_slice(&dw3.to_le_bytes());
    }
    if let Some(dest) = buf.get_mut(16..20) {
        dest.copy_from_slice(&dw4.to_le_bytes());
    }
    if let Some(rest) = buf.get_mut(20..ctx_size) {
        rest.fill(0);
    }
    true
}

// =============================================================================
// DCBAA pointer write helper
// =============================================================================

/// Write a 64-bit slot-to-device-context pointer into the DCBAA.
///
/// `dcbaa` is a mutable slice of the DMA page that holds the Device Context
/// Base Address Array. `slot_id` is the 1-based slot (0 = scratchpad buffer
/// array pointer, reserved). `device_context_ptr` is the IOVA of the output
/// device context for this slot.
///
/// Returns `false` if the DCBAA slice is too small to hold the entry for
/// `slot_id` (each entry is 8 bytes; the DCBAA must be at least
/// `(slot_id + 1) * 8` bytes).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::context::write_dcbaa_entry;
///
/// let mut dcbaa = [0u8; 256]; // 32 slots × 8 bytes
/// assert!(write_dcbaa_entry(&mut dcbaa, 1, 0x0060_0000));
/// let ptr = u64::from_le_bytes(dcbaa[8..16].try_into().unwrap());
/// assert_eq!(ptr, 0x0060_0000);
/// ```
pub fn write_dcbaa_entry(dcbaa: &mut [u8], slot_id: u8, device_context_ptr: u64) -> bool {
    let offset = (slot_id as usize) * 8;
    let Some(end) = offset.checked_add(8) else {
        return false;
    };
    let Some(dest) = dcbaa.get_mut(offset..end) else {
        return false;
    };
    let bytes = device_context_ptr.to_le_bytes();
    dest.copy_from_slice(&bytes);
    true
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- hs_interrupt_context_interval (WS7-06) -------------------------------

    #[test]
    fn hs_interrupt_interval_is_binterval_minus_one_clamped() {
        assert_eq!(hs_interrupt_context_interval(0), 0); // invalid → floor
        assert_eq!(hs_interrupt_context_interval(1), 0); // 125 µs
        assert_eq!(hs_interrupt_context_interval(7), 6); // 8 ms (QEMU HID)
        assert_eq!(hs_interrupt_context_interval(16), 15); // clamp top
        assert_eq!(hs_interrupt_context_interval(255), 15);
    }

    // -- write_input_control_context -----------------------------------------

    #[test]
    fn input_control_context_add_and_drop_flags() {
        let mut buf = [0u8; CTX_SIZE_32];
        let ok = write_input_control_context(&mut buf, CTX_SIZE_32, 0b11, 0);
        assert!(ok);
        let drop = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let add = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(drop, 0);
        assert_eq!(add, 0b11);
    }

    #[test]
    fn input_control_context_rejects_short_buf() {
        let mut buf = [0u8; 7];
        assert!(!write_input_control_context(&mut buf, CTX_SIZE_32, 0b11, 0));
    }

    #[test]
    fn input_control_context_drop_masks_reserved_bits() {
        let mut buf = [0u8; CTX_SIZE_32];
        // Bits 1:0 of drop_flags are reserved; they must be cleared.
        write_input_control_context(&mut buf, CTX_SIZE_32, 0, 0b111);
        let drop = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(drop & 0x3, 0, "bits 1:0 of drop must be 0");
        assert_eq!(drop & !0x3, 0b100, "bit 2 passes through");
    }

    #[test]
    fn input_control_context_64byte_variant() {
        let mut buf = [0u8; CTX_SIZE_64];
        let ok = write_input_control_context(&mut buf, CTX_SIZE_64, 0b11, 0);
        assert!(ok);
    }

    // -- write_slot_context --------------------------------------------------

    #[test]
    fn slot_context_fields_encoded_correctly() {
        let mut buf = [0u8; CTX_SIZE_32];
        let ok = write_slot_context(&mut buf, CTX_SIZE_32, 0, USB_SPEED_HIGH, 1, 1);
        assert!(ok);
        let dw0 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // Route String = 0.
        assert_eq!(dw0 & 0x000F_FFFF, 0);
        // Speed = 3 (High Speed), bits 23:20.
        assert_eq!((dw0 >> 20) & 0xF, u32::from(USB_SPEED_HIGH));
        // Context Entries = 1, bits 31:27.
        assert_eq!((dw0 >> 27) & 0x1F, 1);
        // Root hub port = 1, DWord 1 bits 23:16.
        let dw1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!((dw1 >> 16) & 0xFF, 1);
    }

    #[test]
    fn slot_context_rejects_short_buf() {
        let mut buf = [0u8; 4];
        assert!(!write_slot_context(
            &mut buf,
            CTX_SIZE_32,
            0,
            USB_SPEED_HIGH,
            1,
            1
        ));
    }

    #[test]
    fn slot_context_super_speed() {
        let mut buf = [0u8; CTX_SIZE_32];
        write_slot_context(&mut buf, CTX_SIZE_32, 0, USB_SPEED_SUPER, 2, 1);
        let dw0 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!((dw0 >> 20) & 0xF, u32::from(USB_SPEED_SUPER));
        let dw1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!((dw1 >> 16) & 0xFF, 2, "root hub port = 2");
    }

    // -- write_ep0_context ---------------------------------------------------

    #[test]
    fn ep0_context_type_and_max_packet() {
        let mut buf = [0u8; CTX_SIZE_32];
        // EP0 ring at IOVA 0x0040_0001 (DCS=1).
        let ok = write_ep0_context(&mut buf, CTX_SIZE_32, 0x0040_0001, 64, true);
        assert!(ok);
        let dw1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // EP Type (bits 5:3) = 4 (Control).
        assert_eq!((dw1 >> 3) & 0x7, EndpointType::Control as u32);
        // Max Packet Size (bits 31:16) = 64.
        assert_eq!((dw1 >> 16) & 0xFFFF, 64);
        // CErr (bits 2:1) = 3.
        assert_eq!((dw1 >> 1) & 0x3, 3);
    }

    #[test]
    fn ep0_context_dequeue_ptr_encoded() {
        let mut buf = [0u8; CTX_SIZE_32];
        let ptr: u64 = 0x0000_0001_0040_0001; // high and low both non-zero
        write_ep0_context(&mut buf, CTX_SIZE_32, ptr, 8, true);
        let dw2 = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let dw3 = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        #[allow(clippy::cast_possible_truncation)]
        let decoded = u64::from(dw2) | (u64::from(dw3) << 32);
        assert_eq!(decoded, ptr);
    }

    #[test]
    fn ep0_context_rejects_short_buf() {
        let mut buf = [0u8; 10];
        assert!(!write_ep0_context(&mut buf, CTX_SIZE_32, 0, 64, true));
    }

    // -- write_dcbaa_entry ---------------------------------------------------

    #[test]
    fn dcbaa_entry_written_at_correct_offset() {
        let mut dcbaa = [0u8; 256];
        assert!(write_dcbaa_entry(&mut dcbaa, 1, 0x0060_0000));
        let ptr = u64::from_le_bytes(dcbaa[8..16].try_into().unwrap());
        assert_eq!(ptr, 0x0060_0000);
    }

    #[test]
    fn dcbaa_entry_slot_0_scratchpad() {
        let mut dcbaa = [0u8; 64];
        assert!(write_dcbaa_entry(&mut dcbaa, 0, 0x0070_0000));
        let ptr = u64::from_le_bytes(dcbaa[0..8].try_into().unwrap());
        assert_eq!(ptr, 0x0070_0000);
    }

    #[test]
    fn dcbaa_entry_rejects_short_slice() {
        let mut dcbaa = [0u8; 8]; // only slot 0 fits
        assert!(!write_dcbaa_entry(&mut dcbaa, 1, 0x1000)); // slot 1 needs bytes 8..16
    }

    // -- write_endpoint_context ------------------------------------------------

    #[test]
    fn endpoint_context_bulk_in_fields() {
        let mut buf = [0u8; CTX_SIZE_32];
        let ptr: u64 = 0x0050_0001; // DCS = 1
        let ok = write_endpoint_context(&mut buf, CTX_SIZE_32, EndpointType::BulkIn, 512, 0, ptr);
        assert!(ok);
        let dw1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // EP Type (bits 5:3) = 6 (BulkIn).
        assert_eq!((dw1 >> 3) & 0x7, EndpointType::BulkIn as u32, "EP type");
        // Max Packet Size (bits 31:16) = 512.
        assert_eq!((dw1 >> 16) & 0xFFFF, 512, "MPS");
        // CErr (bits 2:1) = 3.
        assert_eq!((dw1 >> 1) & 0x3, 3, "CErr");
        // TR dequeue pointer low.
        let dw2 = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        #[allow(clippy::cast_possible_truncation)]
        let expected_dw2 = ptr as u32;
        assert_eq!(dw2, expected_dw2, "TR dequeue low");
    }

    #[test]
    fn endpoint_context_interrupt_in_interval() {
        let mut buf = [0u8; CTX_SIZE_32];
        let ok = write_endpoint_context(&mut buf, CTX_SIZE_32, EndpointType::InterruptIn, 8, 10, 1);
        assert!(ok);
        let dw0 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // Interval (bits 23:16) = 10.
        assert_eq!((dw0 >> 16) & 0xFF, 10, "interval");
        let dw1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        // EP Type (bits 5:3) = 7 (InterruptIn).
        assert_eq!(
            (dw1 >> 3) & 0x7,
            EndpointType::InterruptIn as u32,
            "EP type"
        );
        // Average TRB length for interrupt = 8.
        let dw4 = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        assert_eq!(dw4 & 0xFFFF, 8, "avg TRB len");
    }

    #[test]
    fn endpoint_context_bulk_out_average_trb_length() {
        let mut buf = [0u8; CTX_SIZE_32];
        write_endpoint_context(&mut buf, CTX_SIZE_32, EndpointType::BulkOut, 512, 0, 1);
        let dw4 = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        // Average TRB length for bulk = 512.
        assert_eq!(dw4 & 0xFFFF, 512, "avg TRB len bulk");
    }

    #[test]
    fn endpoint_context_rejects_short_buf() {
        let mut buf = [0u8; 10];
        assert!(!write_endpoint_context(
            &mut buf,
            CTX_SIZE_32,
            EndpointType::BulkIn,
            512,
            0,
            1
        ));
    }

    #[test]
    fn endpoint_context_64byte_variant() {
        let mut buf = [0u8; CTX_SIZE_64];
        assert!(write_endpoint_context(
            &mut buf,
            CTX_SIZE_64,
            EndpointType::InterruptIn,
            8,
            4,
            0x0055_0001
        ));
    }

    #[test]
    fn endpoint_context_dequeue_ptr_64bit() {
        let mut buf = [0u8; CTX_SIZE_32];
        let ptr: u64 = 0x0000_0001_0050_0001;
        write_endpoint_context(&mut buf, CTX_SIZE_32, EndpointType::BulkIn, 512, 0, ptr);
        let dw2 = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let dw3 = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let decoded = u64::from(dw2) | (u64::from(dw3) << 32);
        assert_eq!(decoded, ptr, "64-bit dequeue pointer");
    }

    #[test]
    fn endpoint_type_control_value_is_4() {
        assert_eq!(EndpointType::Control as u8, 4);
    }

    #[test]
    fn endpoint_type_variants_distinct() {
        let types = [
            EndpointType::NotValid,
            EndpointType::IsochOut,
            EndpointType::BulkOut,
            EndpointType::InterruptOut,
            EndpointType::Control,
            EndpointType::IsochIn,
            EndpointType::BulkIn,
            EndpointType::InterruptIn,
        ];
        for (i, a) in types.iter().enumerate() {
            for (j, b) in types.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }
}

//! Transfer Request Block (TRB) types, encodings, and constructors.
//!
//! Every TRB is exactly 16 bytes (4 × u32, little-endian). The `TRB_TYPE`
//! field occupies bits 15:10 of `DWord` 3 (the fourth u32). The cycle bit
//! occupies bit 0 of `DWord` 3.
//!
//! ## Untrusted-input discipline
//!
//! TRBs written by the controller into the Event Ring are **untrusted input**.
//! Every event-TRB parser in this module:
//! 1. Validates the `TRB_TYPE` field before interpreting any other field.
//! 2. Validates the `cycle bit` against the locally-expected cycle state.
//! 3. Returns `None` or a typed `Err` on any mismatch — never panics.
//!
//! The driver-produced TRBs (command ring, transfer ring) are fully
//! under driver control; their constructors enforce all invariants at
//! build time.
//!
//! ## References
//!
//! - xHCI § 6.4: Transfer Request Blocks.
//! - USB § 9.3-9.5: USB device framework (control transfer layout).

// =============================================================================
// TRB type constants (xHCI § 6.4.6 Table 131)
// =============================================================================

/// TRB type 1: Normal — data transfer on a bulk, interrupt, or isoch endpoint.
pub const TRB_TYPE_NORMAL: u8 = 1;

/// TRB type 2: Setup Stage — first TRB in a USB control transfer.
pub const TRB_TYPE_SETUP_STAGE: u8 = 2;

/// TRB type 3: Data Stage — optional data phase of a USB control transfer.
pub const TRB_TYPE_DATA_STAGE: u8 = 3;

/// TRB type 4: Status Stage — handshake phase of a USB control transfer.
pub const TRB_TYPE_STATUS_STAGE: u8 = 4;

/// TRB type 6: Link — wraps the command or transfer ring back to the start
/// and optionally toggles the cycle bit (per xHCI § 4.9.2).
pub const TRB_TYPE_LINK: u8 = 6;

/// TRB type 9: Enable Slot Command — requests the xHC to assign a new device
/// slot. The Slot Type field (bits 4:0 of `DWord` 3) selects USB 2 vs USB 3.
pub const TRB_TYPE_ENABLE_SLOT: u8 = 9;

/// TRB type 11: Address Device Command — issues a USB `SET_ADDRESS` request
/// and initialises the device's input context on the controller.
pub const TRB_TYPE_ADDRESS_DEVICE: u8 = 11;

/// TRB type 12: Configure Endpoint Command — configures endpoints beyond EP0.
pub const TRB_TYPE_CONFIGURE_ENDPOINT: u8 = 12;

/// TRB type 34: Port Status Change Event — the controller reports that a port
/// status change has occurred. The driver reads `PORTSC` to determine what
/// changed. (xHCI 1.2 Table 6-91.)
pub const TRB_TYPE_PORT_STATUS_CHANGE_EVENT: u8 = 34;

/// TRB type 33: Command Completion Event — the controller reports completion
/// of a command ring TRB. (xHCI 1.2 Table 6-91.)
pub const TRB_TYPE_COMMAND_COMPLETION_EVENT: u8 = 33;

/// TRB type 32: Transfer Event — the controller reports completion of a
/// transfer ring TRB. (xHCI 1.2 Table 6-91.)
pub const TRB_TYPE_TRANSFER_EVENT: u8 = 32;

// =============================================================================
// Command completion codes (xHCI § 6.4.5 Table 130)
// =============================================================================

/// Completion code 1: Success — the command or transfer completed without error.
pub const COMPLETION_CODE_SUCCESS: u8 = 1;

/// Completion code 4: Transaction Error — a USB transaction error occurred.
pub const COMPLETION_CODE_TRANSACTION_ERROR: u8 = 4;

/// Completion code: Short Packet (xHCI § 6.4.5).
///
/// The transfer completed with fewer bytes than the TRB requested — normal
/// for interrupt-IN HID endpoints whose report is smaller than
/// `wMaxPacketSize` (WS7-06).
pub const COMPLETION_CODE_SHORT_PACKET: u8 = 13;

/// Completion code 5: TRB Error — the xHC detected a malformed TRB.
pub const COMPLETION_CODE_TRB_ERROR: u8 = 5;

/// Completion code 11: Context State Error — the operation is illegal in the
/// endpoint's current context state.
pub const COMPLETION_CODE_CONTEXT_STATE_ERROR: u8 = 11;

/// Completion code 19: No Slots Available — no free device slots remain.
pub const COMPLETION_CODE_NO_SLOTS_AVAILABLE: u8 = 19;

// =============================================================================
// Trb — the 16-byte wire structure
// =============================================================================

/// A single Transfer Request Block: exactly 16 bytes, 4 × u32 little-endian.
///
/// The struct is a thin wrapper over `[u32; 4]` so the compiler enforces
/// the size and alignment without `unsafe`. All field access is done through
/// typed helpers rather than raw pointer casts.
///
/// `Trb` is `Copy` for ergonomic use in ring-buffer slot writes.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::Trb;
///
/// let t = Trb::from_dwords([0u32; 4]);
/// assert_eq!(t.trb_type(), 0);
/// assert!(!t.cycle_bit());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trb {
    dwords: [u32; 4],
}

impl Trb {
    /// Construct a `Trb` from four little-endian `DWord`s.
    #[must_use]
    pub const fn from_dwords(dwords: [u32; 4]) -> Self {
        Self { dwords }
    }

    /// Construct a `Trb` from a 16-byte byte slice.
    ///
    /// Returns `None` if `bytes.len() != 16`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::trb::Trb;
    ///
    /// let raw = [0u8; 16];
    /// let trb = Trb::from_bytes(&raw).unwrap();
    /// assert_eq!(trb.trb_type(), 0);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 16 {
            return None;
        }
        let mut dwords = [0u32; 4];
        for (i, dw) in dwords.iter_mut().enumerate() {
            // Checked indexing: each chunk of 4 bytes is within the 16-byte slice.
            let start = i * 4;
            let end = start + 4;
            let chunk = bytes.get(start..end)?;
            let mut arr = [0u8; 4];
            arr.copy_from_slice(chunk);
            *dw = u32::from_le_bytes(arr);
        }
        Some(Self { dwords })
    }

    /// Encode this TRB as a 16-byte array (little-endian).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::trb::Trb;
    ///
    /// let t = Trb::from_dwords([1, 2, 3, 4]);
    /// let bytes = t.to_bytes();
    /// assert_eq!(bytes[0], 1); // low byte of DWord 0
    /// ```
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, &dw) in self.dwords.iter().enumerate() {
            let start = i * 4;
            let end = start + 4;
            // Safety of indexing: `i < 4`, `start = i*4 < 16`, `end <= 16`.
            if let Some(dest) = out.get_mut(start..end) {
                dest.copy_from_slice(&dw.to_le_bytes());
            }
        }
        out
    }

    /// Return the raw `DWord` array.
    #[must_use]
    pub const fn dwords(self) -> [u32; 4] {
        self.dwords
    }

    // -------------------------------------------------------------------------
    // DWord 3 field accessors (shared across all TRB types)
    // -------------------------------------------------------------------------

    /// Extract the Cycle Bit (bit 0 of `DWord` 3).
    ///
    /// The cycle bit identifies which "lap" of the ring this TRB belongs to.
    /// The producer toggles this bit on every ring wrap; the consumer (for
    /// event rings, the xHC; for command/transfer rings, the driver) ignores
    /// TRBs whose cycle bit does not match the current expected cycle state.
    #[must_use]
    pub const fn cycle_bit(self) -> bool {
        (self.dwords[3] & 0x1) != 0
    }

    /// Extract the TRB Type field (bits 15:10 of `DWord` 3).
    ///
    /// Values correspond to the `TRB_TYPE_*` constants. Any value not
    /// recognised by the event parsers causes the parser to return `None`
    /// (never panic, never interpret the remaining fields as a known type).
    #[must_use]
    pub const fn trb_type(self) -> u8 {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "masked to 6 bits (0x3F); fits in u8"
        )]
        let v = ((self.dwords[3] >> 10) & 0x3F) as u8;
        v
    }

    // -------------------------------------------------------------------------
    // Setters for building TRBs
    // -------------------------------------------------------------------------

    /// Set the Cycle Bit (bit 0 of `DWord` 3) to `cycle`.
    #[must_use]
    pub const fn with_cycle_bit(mut self, cycle: bool) -> Self {
        if cycle {
            self.dwords[3] |= 0x1;
        } else {
            self.dwords[3] &= !0x1;
        }
        self
    }

    /// Set the TRB Type field (bits 15:10 of `DWord` 3).
    ///
    /// `trb_type` must fit in 6 bits (0..=63). Values outside this range are
    /// silently truncated to 6 bits.
    #[must_use]
    pub const fn with_trb_type(mut self, trb_type: u8) -> Self {
        // Clear bits 15:10, then set.
        // u32::from(u8) is not usable in const context; the cast is lossless
        // because u8 always fits in u32.
        #[allow(
            clippy::cast_lossless,
            reason = "u8→u32 widen is lossless; u32::from() is not const"
        )]
        let ty32 = trb_type as u32;
        self.dwords[3] &= !(0x3F << 10);
        self.dwords[3] |= (ty32 & 0x3F) << 10;
        self
    }
}

// =============================================================================
// Driver-produced TRB constructors
// =============================================================================

/// Construct a Link TRB that wraps the ring back to `ring_segment_ptr`.
///
/// A Link TRB occupies the last slot of a command or transfer ring. When the
/// producer pointer reaches this slot it follows the `ring_segment_ptr` back
/// to the beginning of the ring. If `toggle_cycle` is `true` the controller
/// will toggle the producer cycle bit on the wrap (xHCI § 4.9.2 — the Link
/// TRB's `TC` bit, `DWord` 3 bit 1).
///
/// The Link TRB itself carries the **producer's current cycle bit** — NOT the
/// toggled value — so the controller recognises it as valid before following
/// the wrap pointer.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_LINK, link_trb};
///
/// let t = link_trb(0x0010_0000, true, true);
/// assert_eq!(t.trb_type(), TRB_TYPE_LINK);
/// assert!(t.cycle_bit());
/// ```
#[must_use]
pub fn link_trb(ring_segment_ptr: u64, toggle_cycle: bool, cycle: bool) -> Trb {
    // DWord 0: low 32 bits of ring_segment_ptr (must be 16-byte aligned;
    // bits 3:0 are RsvdZ in a Link TRB, so we clear them as a courtesy).
    #[allow(clippy::cast_possible_truncation)]
    let dw0 = (ring_segment_ptr as u32) & !0xF;
    // DWord 1: high 32 bits of ring_segment_ptr.
    #[allow(clippy::cast_possible_truncation)]
    let dw1 = (ring_segment_ptr >> 32) as u32;
    // DWord 2: Interrupter Target (bits 31:22) — 0 for TASK-26.
    let dw2: u32 = 0;
    // DWord 3: Cycle (bit 0), TC (bit 1), TRB Type (bits 15:10).
    let mut dw3: u32 = (u32::from(TRB_TYPE_LINK) & 0x3F) << 10;
    if cycle {
        dw3 |= 0x1;
    }
    if toggle_cycle {
        dw3 |= 0x2;
    }
    Trb::from_dwords([dw0, dw1, dw2, dw3])
}

/// Construct an Enable Slot Command TRB.
///
/// Slot Type `0` requests a USB 2 or USB 3 slot (the controller selects
/// based on port speed). The `cycle` argument is the current producer cycle
/// bit.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_ENABLE_SLOT, enable_slot_trb};
///
/// let t = enable_slot_trb(true);
/// assert_eq!(t.trb_type(), TRB_TYPE_ENABLE_SLOT);
/// assert!(t.cycle_bit());
/// ```
#[must_use]
pub fn enable_slot_trb(cycle: bool) -> Trb {
    let mut dw3: u32 = (u32::from(TRB_TYPE_ENABLE_SLOT) & 0x3F) << 10;
    if cycle {
        dw3 |= 0x1;
    }
    Trb::from_dwords([0, 0, 0, dw3])
}

/// Construct an Address Device Command TRB.
///
/// `input_context_ptr` is the 64-bit IOVA of the Input Context data structure
/// (64-byte aligned). `slot_id` is the device slot assigned by the preceding
/// Enable Slot Command. `bsr` controls whether to block Set Address (BSR=1)
/// or perform the full `SET_ADDRESS` (BSR=0; normal path per xHCI § 4.3.4).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_ADDRESS_DEVICE, address_device_trb};
///
/// let t = address_device_trb(0x0020_0000, 1, false, true);
/// assert_eq!(t.trb_type(), TRB_TYPE_ADDRESS_DEVICE);
/// assert!(t.cycle_bit());
/// ```
#[must_use]
pub fn address_device_trb(input_context_ptr: u64, slot_id: u8, bsr: bool, cycle: bool) -> Trb {
    #[allow(clippy::cast_possible_truncation)]
    let dw0 = (input_context_ptr as u32) & !0x3F; // 64-byte aligned
    #[allow(clippy::cast_possible_truncation)]
    let dw1 = (input_context_ptr >> 32) as u32;
    let dw2: u32 = 0;
    // DWord 3: BSR (bit 9), TRB Type (bits 15:10), Slot ID (bits 31:24).
    let mut dw3: u32 = (u32::from(TRB_TYPE_ADDRESS_DEVICE) & 0x3F) << 10;
    dw3 |= (u32::from(slot_id)) << 24;
    if bsr {
        dw3 |= 1 << 9;
    }
    if cycle {
        dw3 |= 0x1;
    }
    Trb::from_dwords([dw0, dw1, dw2, dw3])
}

/// Construct a Setup Stage TRB for a USB control transfer.
///
/// The 8-byte `setup_data` bytes correspond to the USB `bmRequestType`,
/// `bRequest`, `wValue`, `wIndex`, `wLength` fields (USB § 9.3). `idt` must
/// be `1` when the setup data is included inline (always the case for control
/// transfers via the xHC, per xHCI § 6.4.1.2.1). `trt` is the Transfer Type:
/// `0`=No Data, `2`=OUT Data, `3`=IN Data.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_SETUP_STAGE, setup_stage_trb};
///
/// // GET_DESCRIPTOR(Device): bmRequestType=0x80, bRequest=6, wValue=0x0100,
/// //                          wIndex=0, wLength=18.
/// let setup = [0x80u8, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
/// let t = setup_stage_trb(setup, 3, true);
/// assert_eq!(t.trb_type(), TRB_TYPE_SETUP_STAGE);
/// ```
#[must_use]
pub fn setup_stage_trb(setup_data: [u8; 8], trt: u8, cycle: bool) -> Trb {
    let dw0 = u32::from_le_bytes([setup_data[0], setup_data[1], setup_data[2], setup_data[3]]);
    let dw1 = u32::from_le_bytes([setup_data[4], setup_data[5], setup_data[6], setup_data[7]]);
    // DWord 2: TRB Transfer Length (bits 16:0) = 8 — the Setup Stage TRB ALWAYS
    // carries the 8-byte USB setup packet as immediate data (IDT=1), so the
    // length field is the fixed value 8, NOT wLength (xHCI 1.2 §6.4.1.2.1,
    // Table 6-26). wLength lives in the setup packet bytes (dw1) and governs the
    // separate Data Stage TRB's length. (TASK-26: a length of wLength here made
    // qemu-xhci silently reject the whole control TD — no Transfer Event.)
    // Bits 31:22 = Interrupter Target = 0.
    let dw2: u32 = 8;
    // DWord 3: Cycle (bit 0), IDT=1 (bit 6), TRB Type (bits 15:10), TRT (bits 17:16).
    let mut dw3: u32 = (u32::from(TRB_TYPE_SETUP_STAGE) & 0x3F) << 10;
    dw3 |= 1 << 6; // IDT = 1 (Immediate Data, always set for Setup Stage)
    dw3 |= (u32::from(trt) & 0x3) << 16;
    if cycle {
        dw3 |= 0x1;
    }
    Trb::from_dwords([dw0, dw1, dw2, dw3])
}

/// Construct a Data Stage TRB for a USB control transfer.
///
/// `data_buffer_ptr` is the 64-bit IOVA of the data buffer. `transfer_length`
/// is the byte count. `dir_in` is `true` for IN transfers (device → host).
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_DATA_STAGE, data_stage_trb};
///
/// let t = data_stage_trb(0x0030_0000, 18, true, true);
/// assert_eq!(t.trb_type(), TRB_TYPE_DATA_STAGE);
/// ```
#[must_use]
pub fn data_stage_trb(
    data_buffer_ptr: u64,
    transfer_length: u32,
    dir_in: bool,
    cycle: bool,
) -> Trb {
    #[allow(clippy::cast_possible_truncation)]
    let dw0 = data_buffer_ptr as u32;
    #[allow(clippy::cast_possible_truncation)]
    let dw1 = (data_buffer_ptr >> 32) as u32;
    // DWord 2: Transfer Length (bits 16:0), TD Size (bits 21:17), Interrupter Target (bits 31:22).
    let dw2: u32 = transfer_length & 0x1_FFFF;
    // DWord 3: Cycle (bit 0), ENT (bit 1, 0), ISP (bit 2, 0), NS (bit 3, 0),
    //          CH (bit 4, 0), IOC (bit 5, 1 to get completion event),
    //          IDT (bit 6, 0), TRB Type (bits 15:10), DIR (bit 16).
    let mut dw3: u32 = (u32::from(TRB_TYPE_DATA_STAGE) & 0x3F) << 10;
    dw3 |= 1 << 5; // IOC = 1 — generate Transfer Event on completion
    if dir_in {
        dw3 |= 1 << 16; // DIR = 1 (IN)
    }
    if cycle {
        dw3 |= 0x1;
    }
    Trb::from_dwords([dw0, dw1, dw2, dw3])
}

/// Construct a Status Stage TRB for a USB control transfer.
///
/// `dir_in` is the direction of the status phase: for IN data transfers
/// (`GET_DESCRIPTOR`), the status phase is OUT (`dir_in=false`); for OUT data
/// transfers, the status phase is IN (`dir_in=true`). For no-data control
/// transfers, the status phase is always IN.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_STATUS_STAGE, status_stage_trb};
///
/// let t = status_stage_trb(false, true); // status OUT for GET_DESCRIPTOR
/// assert_eq!(t.trb_type(), TRB_TYPE_STATUS_STAGE);
/// ```
#[must_use]
pub fn status_stage_trb(dir_in: bool, cycle: bool) -> Trb {
    // DWord 3: Cycle (bit 0), IOC (bit 5), TRB Type (bits 15:10), DIR (bit 16).
    let mut dw3: u32 = (u32::from(TRB_TYPE_STATUS_STAGE) & 0x3F) << 10;
    dw3 |= 1 << 5; // IOC = 1
    if dir_in {
        dw3 |= 1 << 16;
    }
    if cycle {
        dw3 |= 0x1;
    }
    Trb::from_dwords([0, 0, 0, dw3])
}

/// Construct a Configure Endpoint Command TRB.
///
/// The Configure Endpoint command (type 12) instructs the xHC to configure
/// the endpoints described in the Input Context beyond EP0.  Unlike Address
/// Device there is no Block Set Address (BSR) bit — the command is issued
/// after `SET_ADDRESS` has already been completed.
///
/// `input_context_ptr` is the 64-bit IOVA of the Input Context (64-byte
/// aligned). `slot_id` is the already-addressed device slot. `cycle` is the
/// current producer cycle bit.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_CONFIGURE_ENDPOINT, configure_endpoint_trb};
///
/// let t = configure_endpoint_trb(0x0060_0000, 1, true);
/// assert_eq!(t.trb_type(), TRB_TYPE_CONFIGURE_ENDPOINT);
/// assert!(t.cycle_bit());
/// // Slot ID in DWord 3 bits 31:24.
/// assert_eq!((t.dwords()[3] >> 24) as u8, 1);
/// ```
#[must_use]
pub fn configure_endpoint_trb(input_context_ptr: u64, slot_id: u8, cycle: bool) -> Trb {
    // DWord 0: Input Context pointer low (64-byte aligned; bits 5:0 RsvdZ).
    #[allow(clippy::cast_possible_truncation)]
    let dw0 = (input_context_ptr as u32) & !0x3F;
    // DWord 1: Input Context pointer high.
    #[allow(clippy::cast_possible_truncation)]
    let dw1 = (input_context_ptr >> 32) as u32;
    let dw2: u32 = 0;
    // DWord 3: Cycle (bit 0), TRB Type (bits 15:10), Slot ID (bits 31:24).
    // No BSR bit (bit 9) — distinguishes Configure Endpoint from Address Device.
    let mut dw3: u32 = (u32::from(TRB_TYPE_CONFIGURE_ENDPOINT) & 0x3F) << 10;
    dw3 |= u32::from(slot_id) << 24;
    if cycle {
        dw3 |= 0x1;
    }
    Trb::from_dwords([dw0, dw1, dw2, dw3])
}

/// Construct a Normal TRB for a bulk or interrupt transfer.
///
/// Normal TRBs (type 1) carry the data buffer pointer and length for a
/// single bulk or interrupt transfer.  The direction is implicit in the
/// endpoint the TRB is enqueued onto — Normal TRBs do not carry a DIR bit
/// (unlike Data Stage TRBs for control transfers).
///
/// `data_buffer_ptr` is the 64-bit IOVA of the data buffer.
/// `transfer_length` is the byte count (must fit in 17 bits; values ≥ 128 KiB
/// are truncated to 17 bits at the TRB layer, not here — caller must split).
/// `ioc` requests a Transfer Event on completion (set for polling/blocking).
/// `cycle` is the current producer cycle bit.
///
/// The `dir_in` parameter is accepted for API consistency but is not encoded
/// into the TRB — the direction is the endpoint's, not the TRB's.  This
/// argument is kept so callers can document intent; it has no effect on the
/// encoded bits.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{TRB_TYPE_NORMAL, normal_trb};
///
/// let t = normal_trb(0x0070_0000, 8, true, true, true);
/// assert_eq!(t.trb_type(), TRB_TYPE_NORMAL);
/// assert!(t.cycle_bit());
/// // IOC bit (bit 5 of DWord 3) must be set.
/// assert!((t.dwords()[3] >> 5) & 1 != 0, "IOC");
/// ```
#[must_use]
pub fn normal_trb(
    data_buffer_ptr: u64,
    transfer_length: u32,
    _dir_in: bool,
    ioc: bool,
    cycle: bool,
) -> Trb {
    // DWord 0: Data buffer pointer low.
    #[allow(clippy::cast_possible_truncation)]
    let dw0 = data_buffer_ptr as u32;
    // DWord 1: Data buffer pointer high.
    #[allow(clippy::cast_possible_truncation)]
    let dw1 = (data_buffer_ptr >> 32) as u32;
    // DWord 2: Transfer Length (bits 16:0); Interrupter Target (bits 31:22) = 0.
    let dw2: u32 = transfer_length & 0x1_FFFF;
    // DWord 3: Cycle (bit 0), ISP (bit 2, Interrupt on Short Packet),
    //          IOC (bit 5), TRB Type (bits 15:10).
    // Normal TRBs have NO DIR bit — direction comes from the endpoint ring.
    let mut dw3: u32 = (u32::from(TRB_TYPE_NORMAL) & 0x3F) << 10;
    // ISP = 1: generate a Transfer Event on a short packet (device sends
    // fewer bytes than requested — common for interrupt-IN HID reports).
    dw3 |= 1 << 2;
    if ioc {
        dw3 |= 1 << 5;
    }
    if cycle {
        dw3 |= 0x1;
    }
    Trb::from_dwords([dw0, dw1, dw2, dw3])
}

// =============================================================================
// Event TRB parsers (untrusted — device-written data)
// =============================================================================

/// Parsed fields of a Command Completion Event TRB (type 34).
///
/// All fields are extracted after type validation; any malformed value
/// results in `None` from [`parse_command_completion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandCompletionEvent {
    /// Physical address of the command TRB that generated this completion.
    pub trb_ptr: u64,
    /// Completion code (see `COMPLETION_CODE_*` constants).
    pub completion_code: u8,
    /// The device slot ID assigned by the Enable Slot Command, or 0 for
    /// commands that do not assign a slot.
    pub slot_id: u8,
    /// The cycle bit as written by the controller.
    pub cycle: bool,
}

/// Parse a Command Completion Event TRB.
///
/// Returns `None` if the TRB type is not [`TRB_TYPE_COMMAND_COMPLETION_EVENT`]
/// or the cycle bit does not match `expected_cycle`. The `expected_cycle`
/// check is the primary dequeue guard: a TRB whose cycle bit does not match
/// belongs to a previous lap of the event ring and must not be consumed.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{
///     COMPLETION_CODE_SUCCESS, TRB_TYPE_COMMAND_COMPLETION_EVENT, Trb, parse_command_completion,
/// };
///
/// // Build a synthetic Command Completion: type=34, cycle=1, code=1, slot=2.
/// let dw0 = 0x0010_0000u32; // TRB pointer low
/// let dw1 = 0u32; // TRB pointer high
/// let dw2: u32 = (COMPLETION_CODE_SUCCESS as u32) << 24;
/// let mut dw3: u32 = (TRB_TYPE_COMMAND_COMPLETION_EVENT as u32) << 10;
/// dw3 |= 0x1; // cycle = 1
/// dw3 |= 2u32 << 24; // slot_id = 2
/// let trb = Trb::from_dwords([dw0, dw1, dw2, dw3]);
/// let ev = parse_command_completion(&trb, true).unwrap();
/// assert_eq!(ev.completion_code, COMPLETION_CODE_SUCCESS);
/// assert_eq!(ev.slot_id, 2);
/// ```
#[must_use]
pub fn parse_command_completion(trb: &Trb, expected_cycle: bool) -> Option<CommandCompletionEvent> {
    if trb.trb_type() != TRB_TYPE_COMMAND_COMPLETION_EVENT {
        return None;
    }
    if trb.cycle_bit() != expected_cycle {
        return None;
    }
    // TRB pointer: DWord 0 (low) + DWord 1 (high); bits 3:0 of DWord 0 are RsvdZ.
    let trb_ptr_lo = u64::from(trb.dwords()[0] & !0xF);
    let trb_ptr_hi = u64::from(trb.dwords()[1]);
    let trb_ptr = trb_ptr_lo | (trb_ptr_hi << 32);
    // DWord 2: Completion Code (bits 31:24). Shifted right 24 bits; fits in u8.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits 31:24 of u32 shifted right 24 → 8-bit value"
    )]
    let completion_code = (trb.dwords()[2] >> 24) as u8;
    // DWord 3: Slot ID (bits 31:24). Same shift argument.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits 31:24 shifted right 24 → 8-bit value"
    )]
    let slot_id = (trb.dwords()[3] >> 24) as u8;
    Some(CommandCompletionEvent {
        trb_ptr,
        completion_code,
        slot_id,
        cycle: trb.cycle_bit(),
    })
}

/// Parsed fields of a Transfer Event TRB (type 35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferEvent {
    /// IOVA of the TRB that generated this event.
    pub trb_ptr: u64,
    /// Number of bytes NOT transferred (residual).
    pub transfer_length: u32,
    /// Completion code.
    pub completion_code: u8,
    /// Device slot ID.
    pub slot_id: u8,
    /// Endpoint ID (EP number × 2 + direction, per xHCI § 4.8.1).
    pub endpoint_id: u8,
    /// Cycle bit as written by the controller.
    pub cycle: bool,
}

/// Parse a Transfer Event TRB.
///
/// Returns `None` if the TRB type is not [`TRB_TYPE_TRANSFER_EVENT`] or the
/// cycle bit does not match `expected_cycle`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{
///     COMPLETION_CODE_SUCCESS, TRB_TYPE_TRANSFER_EVENT, Trb, parse_transfer_event,
/// };
///
/// let dw2: u32 = (COMPLETION_CODE_SUCCESS as u32) << 24;
/// let mut dw3: u32 = (TRB_TYPE_TRANSFER_EVENT as u32) << 10;
/// dw3 |= 0x1; // cycle
/// dw3 |= (1u32 << 24); // slot_id = 1
/// dw3 |= (1u32 << 16); // endpoint_id = 1
/// let trb = Trb::from_dwords([0, 0, dw2, dw3]);
/// let ev = parse_transfer_event(&trb, true).unwrap();
/// assert_eq!(ev.completion_code, COMPLETION_CODE_SUCCESS);
/// ```
#[must_use]
pub fn parse_transfer_event(trb: &Trb, expected_cycle: bool) -> Option<TransferEvent> {
    if trb.trb_type() != TRB_TYPE_TRANSFER_EVENT {
        return None;
    }
    if trb.cycle_bit() != expected_cycle {
        return None;
    }
    let trb_ptr_lo = u64::from(trb.dwords()[0] & !0xF);
    let trb_ptr_hi = u64::from(trb.dwords()[1]);
    let trb_ptr = trb_ptr_lo | (trb_ptr_hi << 32);
    // DWord 2: Transfer Length (bits 23:0), Completion Code (bits 31:24).
    let transfer_length = trb.dwords()[2] & 0x00FF_FFFF;
    // Shifted right 24 bits; fits in u8.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits 31:24 shifted right 24 → 8-bit value"
    )]
    let completion_code = (trb.dwords()[2] >> 24) as u8;
    // DWord 3: Endpoint ID (bits 20:16), Slot ID (bits 31:24).
    // Masked to 5 bits then truncated; fits in u8.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "masked to 0x1F (5 bits); fits in u8"
    )]
    let endpoint_id = ((trb.dwords()[3] >> 16) & 0x1F) as u8;
    // Shifted right 24 bits; fits in u8.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits 31:24 shifted right 24 → 8-bit value"
    )]
    let slot_id = (trb.dwords()[3] >> 24) as u8;
    Some(TransferEvent {
        trb_ptr,
        transfer_length,
        completion_code,
        slot_id,
        endpoint_id,
        cycle: trb.cycle_bit(),
    })
}

/// Parsed fields of a Port Status Change Event TRB (type 33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortStatusChangeEvent {
    /// Root-hub port number (1-based) that changed.
    pub port_id: u8,
    /// Cycle bit as written by the controller.
    pub cycle: bool,
}

/// Parse a Port Status Change Event TRB.
///
/// Returns `None` if the TRB type is not [`TRB_TYPE_PORT_STATUS_CHANGE_EVENT`]
/// or the cycle bit does not match `expected_cycle`.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::trb::{
///     TRB_TYPE_PORT_STATUS_CHANGE_EVENT, Trb, parse_port_status_change,
/// };
///
/// let dw0: u32 = 3u32 << 24; // port_id = 3
/// let mut dw3: u32 = (TRB_TYPE_PORT_STATUS_CHANGE_EVENT as u32) << 10;
/// dw3 |= 0x1; // cycle
/// let trb = Trb::from_dwords([dw0, 0, 0, dw3]);
/// let ev = parse_port_status_change(&trb, true).unwrap();
/// assert_eq!(ev.port_id, 3);
/// ```
#[must_use]
pub fn parse_port_status_change(trb: &Trb, expected_cycle: bool) -> Option<PortStatusChangeEvent> {
    if trb.trb_type() != TRB_TYPE_PORT_STATUS_CHANGE_EVENT {
        return None;
    }
    if trb.cycle_bit() != expected_cycle {
        return None;
    }
    // DWord 0: Port ID (bits 31:24). Shifted right 24 bits; fits in u8.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits 31:24 shifted right 24 → 8-bit value"
    )]
    let port_id = (trb.dwords()[0] >> 24) as u8;
    Some(PortStatusChangeEvent {
        port_id,
        cycle: trb.cycle_bit(),
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Trb::from_bytes / to_bytes roundtrip --------------------------------

    #[test]
    fn trb_from_bytes_roundtrip() {
        let raw: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, // DWord 0
            0x05, 0x06, 0x07, 0x08, // DWord 1
            0x09, 0x0A, 0x0B, 0x0C, // DWord 2
            0x0D, 0x0E, 0x0F, 0x10, // DWord 3
        ];
        let trb = Trb::from_bytes(&raw).unwrap();
        assert_eq!(trb.to_bytes(), raw);
    }

    #[test]
    fn trb_from_bytes_rejects_wrong_size() {
        assert!(Trb::from_bytes(&[0u8; 15]).is_none());
        assert!(Trb::from_bytes(&[0u8; 17]).is_none());
        assert!(Trb::from_bytes(&[]).is_none());
    }

    #[test]
    fn trb_from_dwords_to_bytes_little_endian() {
        let trb = Trb::from_dwords([0x0403_0201, 0, 0, 0]);
        let bytes = trb.to_bytes();
        assert_eq!(bytes[0], 0x01); // little-endian: low byte first
        assert_eq!(bytes[1], 0x02);
        assert_eq!(bytes[2], 0x03);
        assert_eq!(bytes[3], 0x04);
    }

    // -- Cycle bit -----------------------------------------------------------

    #[test]
    fn cycle_bit_set() {
        let trb = Trb::from_dwords([0, 0, 0, 0x1]);
        assert!(trb.cycle_bit());
    }

    #[test]
    fn cycle_bit_clear() {
        let trb = Trb::from_dwords([0, 0, 0, 0x0]);
        assert!(!trb.cycle_bit());
    }

    #[test]
    fn with_cycle_bit_toggles_correctly() {
        let trb = Trb::from_dwords([0, 0, 0, 0]);
        let trb_on = trb.with_cycle_bit(true);
        let trb_off = trb_on.with_cycle_bit(false);
        assert!(trb_on.cycle_bit());
        assert!(!trb_off.cycle_bit());
    }

    // -- TRB type field ------------------------------------------------------

    #[test]
    fn trb_type_extracts_bits_15_10() {
        // Type = 34 = 0b10_0010 → bits 15:10 = 0b10_0010 << 10 = 0x0000_8800.
        let trb = Trb::from_dwords([0, 0, 0, (34u32 << 10)]);
        assert_eq!(trb.trb_type(), 34);
    }

    #[test]
    fn with_trb_type_roundtrip() {
        for ty in [1u8, 2, 6, 9, 11, 33, 34, 35] {
            let trb = Trb::from_dwords([0, 0, 0, 0]).with_trb_type(ty);
            assert_eq!(trb.trb_type(), ty, "type {ty}");
        }
    }

    #[test]
    fn with_trb_type_does_not_disturb_cycle_bit() {
        let trb = Trb::from_dwords([0, 0, 0, 0x1]) // cycle = 1
            .with_trb_type(TRB_TYPE_ENABLE_SLOT);
        assert!(trb.cycle_bit(), "cycle bit must survive type change");
        assert_eq!(trb.trb_type(), TRB_TYPE_ENABLE_SLOT);
    }

    // -- Link TRB ------------------------------------------------------------

    #[test]
    fn link_trb_type_and_cycle() {
        let t = link_trb(0x0010_0000, true, true);
        assert_eq!(t.trb_type(), TRB_TYPE_LINK);
        assert!(t.cycle_bit());
    }

    #[test]
    fn link_trb_toggle_cycle_bit_1_in_dw3() {
        let t_toggle = link_trb(0x0010_0000, true, false);
        // TC bit = bit 1 of DWord 3.
        assert!((t_toggle.dwords()[3] & 0x2) != 0, "TC bit set");
        let t_no_toggle = link_trb(0x0010_0000, false, false);
        assert!((t_no_toggle.dwords()[3] & 0x2) == 0, "TC bit clear");
    }

    #[test]
    fn link_trb_encodes_pointer() {
        let ptr: u64 = 0x0000_0001_0010_0000;
        let t = link_trb(ptr, false, false);
        let lo = u64::from(t.dwords()[0]);
        let hi = u64::from(t.dwords()[1]);
        let decoded = lo | (hi << 32);
        assert_eq!(decoded, ptr & !0xF, "pointer low aligned");
    }

    // -- Enable Slot TRB -----------------------------------------------------

    #[test]
    fn enable_slot_trb_type_and_cycle() {
        let t = enable_slot_trb(true);
        assert_eq!(t.trb_type(), TRB_TYPE_ENABLE_SLOT);
        assert!(t.cycle_bit());
        let t2 = enable_slot_trb(false);
        assert!(!t2.cycle_bit());
    }

    // -- Address Device TRB --------------------------------------------------

    #[test]
    fn address_device_trb_fields() {
        let ptr: u64 = 0x0020_0000;
        let t = address_device_trb(ptr, 1, false, true);
        assert_eq!(t.trb_type(), TRB_TYPE_ADDRESS_DEVICE);
        assert!(t.cycle_bit());
        // Slot ID in bits 31:24 of DWord 3.
        assert_eq!((t.dwords()[3] >> 24) as u8, 1);
        // BSR bit (bit 9 of DWord 3) should be clear.
        assert_eq!((t.dwords()[3] >> 9) & 1, 0);
    }

    #[test]
    fn address_device_trb_bsr_flag() {
        let t = address_device_trb(0x0020_0000, 1, true, false);
        // BSR = bit 9 of DWord 3.
        assert!((t.dwords()[3] >> 9) & 1 != 0, "BSR must be set");
    }

    // -- Setup Stage TRB -----------------------------------------------------

    #[test]
    fn setup_stage_trb_encodes_request_bytes() {
        // GET_DESCRIPTOR(Device): bmRequestType=0x80, bRequest=6,
        // wValue=0x0100, wIndex=0, wLength=18.
        let setup = [0x80u8, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let t = setup_stage_trb(setup, 3, true);
        assert_eq!(t.trb_type(), TRB_TYPE_SETUP_STAGE);
        assert!(t.cycle_bit());
        // IDT bit (bit 6 of DWord 3) must be 1.
        assert!((t.dwords()[3] >> 6) & 1 != 0, "IDT must be 1");
        // TRT field (bits 17:16 of DWord 3) = 3 (IN data).
        assert_eq!((t.dwords()[3] >> 16) & 0x3, 3);
        // TRB Transfer Length (DWord 2 bits 16:0) = 8: the Setup Stage TRB
        // always carries the fixed 8-byte setup packet as immediate data
        // (IDT=1), independent of wLength (xHCI §6.4.1.2.1).
        assert_eq!(t.dwords()[2] & 0x1_FFFF, 8);
    }

    // -- Data Stage TRB ------------------------------------------------------

    #[test]
    fn data_stage_trb_fields() {
        let t = data_stage_trb(0x0030_0000, 18, true, true);
        assert_eq!(t.trb_type(), TRB_TYPE_DATA_STAGE);
        assert!(t.cycle_bit());
        // DIR bit (bit 16 of DWord 3) = 1 for IN.
        assert!((t.dwords()[3] >> 16) & 1 != 0, "DIR must be IN");
        // Transfer length in DWord 2 bits 16:0.
        assert_eq!(t.dwords()[2] & 0x1_FFFF, 18);
    }

    // -- Status Stage TRB ----------------------------------------------------

    #[test]
    fn status_stage_trb_out_direction() {
        let t = status_stage_trb(false, true);
        assert_eq!(t.trb_type(), TRB_TYPE_STATUS_STAGE);
        assert!(t.cycle_bit());
        // DIR bit (bit 16 of DWord 3) = 0 for OUT.
        assert_eq!((t.dwords()[3] >> 16) & 1, 0, "DIR must be OUT");
    }

    #[test]
    fn status_stage_trb_in_direction() {
        let t = status_stage_trb(true, false);
        assert!((t.dwords()[3] >> 16) & 1 != 0, "DIR must be IN");
    }

    // -- Command Completion Event parser ------------------------------------

    #[test]
    fn parse_command_completion_happy_path() {
        let trb_ptr: u64 = 0x0010_0020;
        #[allow(clippy::cast_possible_truncation)]
        let dw0 = trb_ptr as u32;
        #[allow(clippy::cast_possible_truncation)]
        let dw1 = (trb_ptr >> 32) as u32;
        let dw2: u32 = u32::from(COMPLETION_CODE_SUCCESS) << 24;
        let mut dw3: u32 = (u32::from(TRB_TYPE_COMMAND_COMPLETION_EVENT)) << 10;
        dw3 |= 0x1; // cycle = true
        dw3 |= 2u32 << 24; // slot_id = 2
        let trb = Trb::from_dwords([dw0, dw1, dw2, dw3]);
        let ev = parse_command_completion(&trb, true).unwrap();
        assert_eq!(ev.completion_code, COMPLETION_CODE_SUCCESS);
        assert_eq!(ev.slot_id, 2);
        assert!(ev.cycle);
    }

    #[test]
    fn parse_command_completion_wrong_type_returns_none() {
        let mut dw3: u32 = (u32::from(TRB_TYPE_TRANSFER_EVENT)) << 10;
        dw3 |= 0x1;
        let trb = Trb::from_dwords([0, 0, 0, dw3]);
        assert!(parse_command_completion(&trb, true).is_none());
    }

    #[test]
    fn parse_command_completion_cycle_mismatch_returns_none() {
        let mut dw3: u32 = (u32::from(TRB_TYPE_COMMAND_COMPLETION_EVENT)) << 10;
        dw3 |= 0x0; // cycle = false
        let trb = Trb::from_dwords([0, 0, 0, dw3]);
        // expected_cycle = true, trb cycle = false → mismatch.
        assert!(parse_command_completion(&trb, true).is_none());
    }

    // -- Transfer Event parser -----------------------------------------------

    #[test]
    fn parse_transfer_event_happy_path() {
        let dw2: u32 = u32::from(COMPLETION_CODE_SUCCESS) << 24; // 0 residual bytes
        let mut dw3: u32 = (u32::from(TRB_TYPE_TRANSFER_EVENT)) << 10;
        dw3 |= 0x1; // cycle
        dw3 |= 1u32 << 24; // slot_id = 1
        dw3 |= 1u32 << 16; // endpoint_id = 1
        let trb = Trb::from_dwords([0, 0, dw2, dw3]);
        let ev = parse_transfer_event(&trb, true).unwrap();
        assert_eq!(ev.slot_id, 1);
        assert_eq!(ev.endpoint_id, 1);
        assert_eq!(ev.completion_code, COMPLETION_CODE_SUCCESS);
    }

    #[test]
    fn parse_transfer_event_cycle_mismatch_returns_none() {
        let mut dw3: u32 = (u32::from(TRB_TYPE_TRANSFER_EVENT)) << 10;
        dw3 |= 0x0; // cycle = false
        let trb = Trb::from_dwords([0, 0, 0, dw3]);
        assert!(parse_transfer_event(&trb, true).is_none());
    }

    // -- Port Status Change Event parser ------------------------------------

    #[test]
    fn parse_port_status_change_happy_path() {
        let dw0: u32 = 3u32 << 24; // port_id = 3
        let mut dw3: u32 = (u32::from(TRB_TYPE_PORT_STATUS_CHANGE_EVENT)) << 10;
        dw3 |= 0x1; // cycle
        let trb = Trb::from_dwords([dw0, 0, 0, dw3]);
        let ev = parse_port_status_change(&trb, true).unwrap();
        assert_eq!(ev.port_id, 3);
        assert!(ev.cycle);
    }

    #[test]
    fn parse_port_status_change_wrong_type_returns_none() {
        let mut dw3: u32 = (u32::from(TRB_TYPE_ENABLE_SLOT)) << 10;
        dw3 |= 0x1;
        let trb = Trb::from_dwords([0, 0, 0, dw3]);
        assert!(parse_port_status_change(&trb, true).is_none());
    }

    // -- Configure Endpoint TRB ---------------------------------------------

    #[test]
    fn configure_endpoint_trb_type_and_cycle() {
        let t = configure_endpoint_trb(0x0060_0000, 1, true);
        assert_eq!(t.trb_type(), TRB_TYPE_CONFIGURE_ENDPOINT);
        assert!(t.cycle_bit());
    }

    #[test]
    fn configure_endpoint_trb_slot_id_in_dw3() {
        let t = configure_endpoint_trb(0x0060_0000, 5, false);
        assert_eq!((t.dwords()[3] >> 24) as u8, 5, "slot_id = 5");
        assert!(!t.cycle_bit());
    }

    #[test]
    fn configure_endpoint_trb_encodes_input_context_ptr() {
        let ptr: u64 = 0x0000_0002_0060_0000;
        let t = configure_endpoint_trb(ptr, 1, false);
        let lo = u64::from(t.dwords()[0]);
        let hi = u64::from(t.dwords()[1]);
        let decoded = lo | (hi << 32);
        // Bits 5:0 of the low word are RsvdZ (64-byte aligned).
        assert_eq!(decoded, ptr & !0x3F, "input context ptr");
    }

    #[test]
    fn configure_endpoint_trb_no_bsr_bit() {
        // BSR is bit 9 of DWord 3; Configure Endpoint must NOT set it.
        let t = configure_endpoint_trb(0x0060_0000, 1, true);
        assert_eq!((t.dwords()[3] >> 9) & 1, 0, "BSR must be clear");
    }

    // -- Normal TRB ---------------------------------------------------------

    #[test]
    fn normal_trb_type_and_cycle() {
        let t = normal_trb(0x0070_0000, 8, true, true, true);
        assert_eq!(t.trb_type(), TRB_TYPE_NORMAL);
        assert!(t.cycle_bit());
    }

    #[test]
    fn normal_trb_ioc_bit_set() {
        let t = normal_trb(0x0070_0000, 64, false, true, false);
        // IOC is bit 5 of DWord 3.
        assert!((t.dwords()[3] >> 5) & 1 != 0, "IOC must be 1");
    }

    #[test]
    fn normal_trb_ioc_bit_clear_when_false() {
        let t = normal_trb(0x0070_0000, 64, false, false, false);
        assert_eq!((t.dwords()[3] >> 5) & 1, 0, "IOC must be 0");
    }

    #[test]
    fn normal_trb_transfer_length_in_dw2() {
        let t = normal_trb(0x0070_0000, 512, true, true, true);
        assert_eq!(t.dwords()[2] & 0x1_FFFF, 512, "transfer length");
    }

    #[test]
    fn normal_trb_encodes_buffer_ptr() {
        let ptr: u64 = 0x0000_0003_0070_0000;
        let t = normal_trb(ptr, 8, false, false, false);
        let lo = u64::from(t.dwords()[0]);
        let hi = u64::from(t.dwords()[1]);
        assert_eq!(lo | (hi << 32), ptr, "buffer pointer");
    }

    #[test]
    fn normal_trb_no_dir_bit() {
        // Normal TRBs do NOT encode a DIR bit (bit 16 of DWord 3).
        // Direction is inferred from the endpoint ring.
        let t_in = normal_trb(0, 8, true, false, false);
        let t_out = normal_trb(0, 8, false, false, false);
        // Both should have the same DWord 3 (except the cycle bit, which is
        // always false here, so they must be bit-identical for DWord 3).
        assert_eq!(
            t_in.dwords()[3],
            t_out.dwords()[3],
            "dir_in arg must not affect any TRB bit"
        );
    }

    // -- Type constant pinning -----------------------------------------------

    #[test]
    fn trb_type_constants_match_xhci_spec() {
        assert_eq!(TRB_TYPE_NORMAL, 1);
        assert_eq!(TRB_TYPE_SETUP_STAGE, 2);
        assert_eq!(TRB_TYPE_DATA_STAGE, 3);
        assert_eq!(TRB_TYPE_STATUS_STAGE, 4);
        assert_eq!(TRB_TYPE_LINK, 6);
        assert_eq!(TRB_TYPE_ENABLE_SLOT, 9);
        assert_eq!(TRB_TYPE_ADDRESS_DEVICE, 11);
        assert_eq!(TRB_TYPE_CONFIGURE_ENDPOINT, 12);
        assert_eq!(TRB_TYPE_PORT_STATUS_CHANGE_EVENT, 34);
        assert_eq!(TRB_TYPE_COMMAND_COMPLETION_EVENT, 33);
        assert_eq!(TRB_TYPE_TRANSFER_EVENT, 32);
    }
}

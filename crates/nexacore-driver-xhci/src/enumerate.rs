//! Device enumeration state machine (xHCI § 4.3, USB § 9).
//!
//! This module implements the pure state-machine portion of DE-E2: given a
//! root-hub port number and a stream of events (fed by the image crate), it
//! drives the xHCI enumeration sequence from port reset through to the device
//! descriptor read, producing the final `idVendor`/`idProduct` pair.
//!
//! ## State transitions
//!
//! ```text
//! PortReset
//!   │  (on_port_reset_complete)
//!   ▼
//! EnableSlot { port }
//!   │  submit Enable Slot command
//!   │  (on_command_completion → slot_id)
//!   ▼
//! AddressDevice { port, slot_id }
//!   │  build input context, submit Address Device command
//!   │  (on_command_completion → ok)
//!   ▼
//! GetDeviceDescriptor { port, slot_id }
//!   │  submit SETUP/DATA/STATUS transfer TRBs on EP0
//!   │  (on_transfer_event → descriptor bytes)
//!   ▼
//! Enumerated { vid, pid, slot_id }
//! ```
//!
//! Each `Failed` arm is reachable from any state and carries a typed reason.
//!
//! ## Design principle
//!
//! The state machine is entirely pure: it receives events, updates internal
//! state, and returns the **next TRBs to submit** (as fixed-size arrays, no
//! heap). The image crate is responsible for:
//! - Submitting the returned TRBs to the command / transfer ring.
//! - Ringing the appropriate doorbell.
//! - Forwarding the resulting event TRBs into [`Enumerator::on_event`].
//! - Checking per-step deadlines via [`Enumerator::is_timed_out`].

use crate::{
    context::{USB_SPEED_HIGH, USB_SPEED_SUPER},
    descriptor::parse_device_descriptor,
    trb::{
        TRB_TYPE_COMMAND_COMPLETION_EVENT, TRB_TYPE_TRANSFER_EVENT, Trb, address_device_trb,
        data_stage_trb, enable_slot_trb, setup_stage_trb, status_stage_trb,
    },
};

// =============================================================================
// Speed-aware EP0 max-packet-size helper
// =============================================================================

/// Return the correct EP0 max-packet-size for the given xHCI port speed code.
///
/// The PORTSC `Port Speed` field (bits 13:10, see xHCI § 5.4.8 Table 83)
/// encodes the negotiated bus speed.  The EP0 max-packet-size is fixed by the
/// USB specification for each speed:
///
/// | Speed code | USB speed     | EP0 MPS |
/// |------------|---------------|---------|
/// | 1          | Full Speed    | 64      |
/// | 2          | Low Speed     | 8       |
/// | 3          | High Speed    | 64      |
/// | 4          | `SuperSpeed`    | 512     |
/// | 5          | `SuperSpeed`+   | 512     |
/// | other      | Unknown       | 8       |
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::enumerate::ep0_max_packet_for_speed;
///
/// assert_eq!(ep0_max_packet_for_speed(3), 64); // High Speed
/// assert_eq!(ep0_max_packet_for_speed(4), 512); // SuperSpeed
/// assert_eq!(ep0_max_packet_for_speed(2), 8); // Low Speed
/// assert_eq!(ep0_max_packet_for_speed(1), 64); // Full Speed
/// assert_eq!(ep0_max_packet_for_speed(0), 8); // Unknown → conservative 8
/// ```
#[must_use]
pub fn ep0_max_packet_for_speed(port_speed: u8) -> u16 {
    match port_speed {
        USB_SPEED_HIGH => 64,       // High Speed: 480 Mb/s
        USB_SPEED_SUPER | 5 => 512, // SuperSpeed 5 Gb/s or SuperSpeed+ 10 Gb/s
        1 => 64,                    // Full Speed: 12 Mb/s
        _ => 8,                     // Low Speed (2) or unknown: conservative 8
    }
}

// =============================================================================
// Failure reasons
// =============================================================================

/// Reason the enumeration state machine reached the `Failed` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EnumFailReason {
    /// The step exceeded its deadline (the image crate's tick counter surpassed
    /// the deadline returned by the state).
    Timeout,
    /// The controller returned a non-success completion code for an Enable Slot
    /// or Address Device command.
    CommandError {
        /// The xHCI completion code (see `COMPLETION_CODE_*` in [`crate::trb`]).
        code: u8,
    },
    /// No free device slots were available (`COMPLETION_CODE_NO_SLOTS_AVAILABLE`).
    NoSlotsAvailable,
    /// An Address Device command failed.
    AddressDeviceError {
        /// The xHCI completion code.
        code: u8,
    },
    /// The `GET_DESCRIPTOR`(Device) transfer returned a transfer error.
    TransferError {
        /// The xHCI completion code.
        code: u8,
    },
    /// The 18-byte device descriptor returned by the device is malformed.
    MalformedDescriptor,
    /// An event TRB with an unexpected type was received in the current state.
    UnexpectedEvent {
        /// The TRB type value as reported by the device.
        trb_type: u8,
    },
}

// =============================================================================
// Commands produced by the state machine
// =============================================================================

/// Commands returned by the state machine for the image crate to execute.
///
/// Each variant contains the TRBs to submit and the ring to submit them on.
#[derive(Debug, Clone)]
pub enum EnumCommand {
    /// Submit one TRB to the **Command Ring** and ring doorbell 0.
    CommandRingTrb(Trb),
    /// Submit three TRBs (SETUP + DATA + STATUS) to the **EP0 Transfer Ring**
    /// and ring the EP0 doorbell for `slot_id`.
    Ep0Transfer {
        /// Device slot ID for the doorbell.
        slot_id: u8,
        /// SETUP Stage TRB.
        setup: Trb,
        /// DATA Stage TRB.
        data: Trb,
        /// STATUS Stage TRB.
        status: Trb,
    },
}

// =============================================================================
// Enumeration state
// =============================================================================

/// State of the enumeration state machine for a single root-hub port.
#[derive(Debug, Clone)]
enum EnumState {
    /// Waiting for the port reset to complete (caller invokes
    /// [`Enumerator::on_port_reset_complete`] when `PORTSC.PRC` is observed).
    PortReset,
    /// An Enable Slot command has been submitted to the command ring; waiting
    /// for the completion event to deliver the `slot_id`.
    EnableSlot,
    /// An Address Device command has been submitted; waiting for completion.
    AddressDevice {
        /// The slot ID assigned by the Enable Slot command.
        slot_id: u8,
    },
    /// The `GET_DESCRIPTOR`(Device) `SETUP`/`DATA`/`STATUS` sequence has been submitted;
    /// waiting for the DATA transfer event that carries the descriptor bytes.
    GetDeviceDescriptor {
        /// Device slot ID.
        slot_id: u8,
    },
    /// Enumeration completed successfully.
    Enumerated {
        /// Assigned device slot ID.
        slot_id: u8,
        /// `idVendor` from the Device Descriptor.
        vid: u16,
        /// `idProduct` from the Device Descriptor.
        pid: u16,
        /// The port speed code (xHCI PORTSC bits 13:10) used during bring-up.
        speed: u8,
        /// Negotiated EP0 max-packet-size (derived from the port speed).
        ep0_mps: u16,
    },
    /// Enumeration failed.
    Failed(EnumFailReason),
}

// =============================================================================
// Enumerator — the public state machine handle
// =============================================================================

/// Enumeration state machine for a single root-hub port.
///
/// Create one `Enumerator` per root-hub port that reported a device connect
/// event (`PORTSC.CCS = 1`). Drive it by:
///
/// 1. Asserting the port reset (`PORTSC.PR = 1`), waiting for `PORTSC.PRC`.
/// 2. Calling [`Self::on_port_reset_complete`] — this transitions from
///    `PortReset` to `EnableSlot` and returns the TRBs to submit.
/// 3. After each submitted TRB generates an event, calling [`Self::on_event`]
///    with the event TRB.
/// 4. After each step, checking [`Self::is_finished`] to detect
///    `Enumerated` or `Failed`.
/// 5. Optionally calling [`Self::is_timed_out`] with a monotonic tick to
///    detect per-step stalls.
///
/// # Example
///
/// ```rust
/// use nexacore_driver_xhci::enumerate::{EnumCommand, Enumerator};
///
/// let mut e = Enumerator::new(1, 0x1000_u64, 64);
/// let cmd = e.on_port_reset_complete_simple(true).unwrap();
/// assert!(matches!(cmd, EnumCommand::CommandRingTrb(_)));
/// ```
#[derive(Debug)]
pub struct Enumerator {
    /// Root-hub port number (1-based).
    port: u8,
    /// Port speed code read from PORTSC (xHCI bits 13:10).
    port_speed: u8,
    /// IOVA of the EP0 Transfer Ring base (used to build the Address Device
    /// input context pointer — the image crate writes the context at a
    /// fixed DMA address; the enumerator uses it to build the TRB).
    ep0_ring_base: u64,
    /// Maximum packet size for EP0 (derived from port speed; updated from the
    /// Device Descriptor `bMaxPacketSize0` field for a more accurate Address
    /// Device command on subsequent resets).
    ep0_max_packet_size: u16,
    /// Current state.
    state: EnumState,
    /// Step deadline (tick units). The image crate sets this via
    /// [`Self::deadline`] and checks it via [`Self::is_timed_out`].
    deadline: u64,
}

impl Enumerator {
    /// Construct a new `Enumerator` for `port` (1-based root-hub port number).
    ///
    /// `ep0_ring_base` is the IOVA of the EP0 Transfer Ring's first TRB
    /// (provided by the image crate from the DMA arena).
    ///
    /// `ep0_max_packet_size` is the initial max-packet-size assumption for EP0
    /// (typically 64 for HS; the descriptor read corrects it if necessary).
    ///
    /// The enumerator starts in `PortReset` state; the caller must assert the
    /// port reset and call [`Self::on_port_reset_complete`] when done.
    ///
    /// For speed-aware enumeration prefer [`Self::new_with_speed`], which
    /// derives the correct EP0 MPS from the PORTSC speed automatically.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::enumerate::Enumerator;
    ///
    /// let e = Enumerator::new(1, 0x0040_0000, 64);
    /// assert_eq!(e.port(), 1);
    /// assert!(!e.is_finished());
    /// ```
    #[must_use]
    pub fn new(port: u8, ep0_ring_base: u64, ep0_max_packet_size: u16) -> Self {
        Self {
            port,
            port_speed: 0,
            ep0_ring_base,
            ep0_max_packet_size,
            state: EnumState::PortReset,
            deadline: u64::MAX,
        }
    }

    /// Construct a speed-aware `Enumerator` for `port`.
    ///
    /// `port_speed` is the xHCI PORTSC `Port Speed` field (bits 13:10), read
    /// immediately after the port reset completes.  The EP0 max-packet-size is
    /// derived automatically from the speed code via
    /// [`ep0_max_packet_for_speed`].
    ///
    /// This is the preferred constructor for production use; [`Self::new`] is
    /// kept for compatibility with existing TASK-26 tests that pass the MPS
    /// explicitly.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::{context::USB_SPEED_HIGH, enumerate::Enumerator};
    ///
    /// let e = Enumerator::new_with_speed(1, 0x0040_0000, USB_SPEED_HIGH);
    /// assert_eq!(e.port(), 1);
    /// assert_eq!(e.ep0_max_packet_size(), 64); // HS MPS = 64
    /// ```
    #[must_use]
    pub fn new_with_speed(port: u8, ep0_ring_base: u64, port_speed: u8) -> Self {
        let ep0_max_packet_size = ep0_max_packet_for_speed(port_speed);
        Self {
            port,
            port_speed,
            ep0_ring_base,
            ep0_max_packet_size,
            state: EnumState::PortReset,
            deadline: u64::MAX,
        }
    }

    /// The root-hub port number this enumerator is driving (1-based).
    #[must_use]
    pub const fn port(&self) -> u8 {
        self.port
    }

    /// The port speed code as provided at construction.
    ///
    /// This is the xHCI PORTSC `Port Speed` field (bits 13:10).  Returns `0`
    /// when the enumerator was constructed via [`Self::new`] (no speed given).
    #[must_use]
    pub const fn port_speed(&self) -> u8 {
        self.port_speed
    }

    /// The IOVA of the EP0 Transfer Ring base as provided at construction.
    ///
    /// Exposed so the image crate can retrieve the value it passed in when
    /// building the Input Context for the Address Device command.
    #[must_use]
    pub const fn ep0_ring_base(&self) -> u64 {
        self.ep0_ring_base
    }

    /// The EP0 maximum packet size as provided at construction.
    ///
    /// Exposed for the image crate when building the Input Context.
    #[must_use]
    pub const fn ep0_max_packet_size(&self) -> u16 {
        self.ep0_max_packet_size
    }

    /// Returns `true` if the enumerator has reached a terminal state
    /// (`Enumerated` or `Failed`).
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(
            self.state,
            EnumState::Enumerated { .. } | EnumState::Failed(_)
        )
    }

    /// Returns the current step deadline (a monotonic tick value).
    ///
    /// The image crate checks `current_tick > deadline` to detect timeouts
    /// and calls [`Self::force_timeout`] if the deadline is exceeded.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Check whether the current tick has exceeded the step deadline.
    ///
    /// Does not mutate state — the caller must call [`Self::force_timeout`]
    /// to transition to `Failed(Timeout)` if desired.
    #[must_use]
    pub const fn is_timed_out(&self, current_tick: u64) -> bool {
        current_tick > self.deadline
    }

    /// Force a transition to `Failed(Timeout)`.
    ///
    /// The image crate calls this when [`Self::is_timed_out`] returns `true`.
    pub fn force_timeout(&mut self) {
        self.state = EnumState::Failed(EnumFailReason::Timeout);
    }

    /// Retrieve the enumerated VID/PID on success.
    ///
    /// Returns `Some((vid, pid, slot_id))` when in the `Enumerated` state,
    /// `None` otherwise.
    ///
    /// For the full enumeration record including speed and EP0 MPS, use
    /// [`Self::enumerated_device_full`].
    #[must_use]
    pub fn enumerated_device(&self) -> Option<(u16, u16, u8)> {
        if let EnumState::Enumerated {
            vid, pid, slot_id, ..
        } = self.state
        {
            Some((vid, pid, slot_id))
        } else {
            None
        }
    }

    /// Retrieve the full enumeration record on success.
    ///
    /// Returns `Some((vid, pid, slot_id, speed, ep0_mps))` when in the
    /// `Enumerated` state, `None` otherwise.  The `speed` field is the xHCI
    /// PORTSC port-speed code; `ep0_mps` is the EP0 max-packet-size derived
    /// from that speed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::{context::USB_SPEED_SUPER, enumerate::Enumerator};
    ///
    /// let e = Enumerator::new_with_speed(1, 0x0040_0000, USB_SPEED_SUPER);
    /// assert_eq!(e.ep0_max_packet_size(), 512); // SuperSpeed EP0 MPS
    /// ```
    #[must_use]
    pub fn enumerated_device_full(&self) -> Option<(u16, u16, u8, u8, u16)> {
        if let EnumState::Enumerated {
            vid,
            pid,
            slot_id,
            speed,
            ep0_mps,
        } = self.state
        {
            Some((vid, pid, slot_id, speed, ep0_mps))
        } else {
            None
        }
    }

    /// Retrieve the failure reason if enumeration failed.
    #[must_use]
    pub fn failure_reason(&self) -> Option<EnumFailReason> {
        if let EnumState::Failed(reason) = self.state {
            Some(reason)
        } else {
            None
        }
    }

    // =========================================================================
    // State transition methods
    // =========================================================================

    /// Transition from `PortReset` to `EnableSlot`.
    ///
    /// Called by the image crate when `PORTSC.PRC` is observed (the port
    /// reset has completed). Returns the Enable Slot command TRB to submit
    /// to the Command Ring.
    ///
    /// Returns `None` if the enumerator is not in `PortReset` state.
    ///
    /// The deadline is set to `current_tick + timeout_ticks`.
    pub fn on_port_reset_complete(
        &mut self,
        current_tick: u64,
        timeout_ticks: u64,
        producer_cycle: bool,
    ) -> Option<EnumCommand> {
        if !matches!(self.state, EnumState::PortReset) {
            return None;
        }
        self.deadline = current_tick.saturating_add(timeout_ticks);
        self.state = EnumState::EnableSlot;
        let trb = enable_slot_trb(producer_cycle);
        Some(EnumCommand::CommandRingTrb(trb))
    }

    /// Process an event TRB and drive the state machine forward.
    ///
    /// The caller provides:
    /// - `event_trb`: the TRB read from the event ring (validated cycle bit).
    /// - `input_context_ptr`: the IOVA of the Input Context buffer (needed for
    ///   the Address Device command); valid only when in `EnableSlot` state.
    /// - `data_buffer_ptr`: the IOVA of the 18-byte data buffer for
    ///   `GET_DESCRIPTOR` (needed when transitioning to `GetDeviceDescriptor`).
    /// - `descriptor_buf`: a reference to the 18-byte buffer into which the
    ///   controller has written the Device Descriptor (valid only when in
    ///   `GetDeviceDescriptor` state and a `TransferEvent` arrives).
    /// - `current_tick` and `timeout_ticks`: for the next step's deadline.
    /// - `producer_cycle`: current producer cycle bit for TRB construction.
    ///
    /// Returns the next [`EnumCommand`] to execute, or `None` if no command
    /// is needed (e.g. the state reached a terminal or the event was unexpected
    /// but the error has been recorded).
    ///
    /// # Panics
    ///
    /// This function never panics. Unexpected / malformed events transition
    /// to `Failed` with a typed reason.
    #[allow(clippy::too_many_arguments)]
    pub fn on_event(
        &mut self,
        event_trb: &Trb,
        input_context_ptr: u64,
        data_buffer_ptr: u64,
        descriptor_buf: &[u8],
        current_tick: u64,
        timeout_ticks: u64,
        producer_cycle: bool,
    ) -> Option<EnumCommand> {
        let trb_type = event_trb.trb_type();
        match &self.state {
            EnumState::EnableSlot => {
                if trb_type != TRB_TYPE_COMMAND_COMPLETION_EVENT {
                    self.state = EnumState::Failed(EnumFailReason::UnexpectedEvent { trb_type });
                    return None;
                }
                // Parse the completion: extract completion code and slot_id.
                // We parse manually to avoid cycle-bit dependency at this layer
                // (the cycle bit is checked by the event ring consumer before
                // calling on_event, per the module contract).
                let completion_code = (event_trb.dwords()[2] >> 24) as u8;
                let slot_id = (event_trb.dwords()[3] >> 24) as u8;

                if completion_code == crate::trb::COMPLETION_CODE_NO_SLOTS_AVAILABLE {
                    self.state = EnumState::Failed(EnumFailReason::NoSlotsAvailable);
                    return None;
                }
                if completion_code != crate::trb::COMPLETION_CODE_SUCCESS {
                    self.state = EnumState::Failed(EnumFailReason::CommandError {
                        code: completion_code,
                    });
                    return None;
                }
                if slot_id == 0 {
                    self.state = EnumState::Failed(EnumFailReason::CommandError { code: 0 });
                    return None;
                }

                // Transition to AddressDevice.
                self.deadline = current_tick.saturating_add(timeout_ticks);
                self.state = EnumState::AddressDevice { slot_id };
                let trb = address_device_trb(input_context_ptr, slot_id, false, producer_cycle);
                Some(EnumCommand::CommandRingTrb(trb))
            }

            EnumState::AddressDevice { slot_id } => {
                let slot_id = *slot_id;
                if trb_type != TRB_TYPE_COMMAND_COMPLETION_EVENT {
                    self.state = EnumState::Failed(EnumFailReason::UnexpectedEvent { trb_type });
                    return None;
                }
                let completion_code = (event_trb.dwords()[2] >> 24) as u8;
                if completion_code != crate::trb::COMPLETION_CODE_SUCCESS {
                    self.state = EnumState::Failed(EnumFailReason::AddressDeviceError {
                        code: completion_code,
                    });
                    return None;
                }

                // Transition to GetDeviceDescriptor.
                self.deadline = current_tick.saturating_add(timeout_ticks);
                self.state = EnumState::GetDeviceDescriptor { slot_id };

                // Build GET_DESCRIPTOR(Device) control transfer:
                // bmRequestType=0x80 (IN, Standard, Device)
                // bRequest=0x06 (GET_DESCRIPTOR)
                // wValue=0x0100 (Device Descriptor type=1, index=0)
                // wIndex=0x0000
                // wLength=18 (full Device Descriptor)
                let setup_data: [u8; 8] = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
                let setup = setup_stage_trb(setup_data, 3, producer_cycle); // TRT=3 (IN data)
                let data = data_stage_trb(data_buffer_ptr, 18, true, producer_cycle);
                let status = status_stage_trb(false, producer_cycle); // status OUT

                Some(EnumCommand::Ep0Transfer {
                    slot_id,
                    setup,
                    data,
                    status,
                })
            }

            EnumState::GetDeviceDescriptor { slot_id } => {
                let slot_id = *slot_id;
                if trb_type != TRB_TYPE_TRANSFER_EVENT {
                    self.state = EnumState::Failed(EnumFailReason::UnexpectedEvent { trb_type });
                    return None;
                }
                let completion_code = (event_trb.dwords()[2] >> 24) as u8;
                if completion_code != crate::trb::COMPLETION_CODE_SUCCESS {
                    self.state = EnumState::Failed(EnumFailReason::TransferError {
                        code: completion_code,
                    });
                    return None;
                }

                // Parse the 18-byte device descriptor from the data buffer.
                if let Ok(desc) = parse_device_descriptor(descriptor_buf) {
                    self.state = EnumState::Enumerated {
                        slot_id,
                        vid: desc.id_vendor,
                        pid: desc.id_product,
                        speed: self.port_speed,
                        ep0_mps: self.ep0_max_packet_size,
                    };
                } else {
                    self.state = EnumState::Failed(EnumFailReason::MalformedDescriptor);
                }
                None
            }

            // Terminal states — ignore further events.
            EnumState::Enumerated { .. } | EnumState::Failed(_) | EnumState::PortReset => None,
        }
    }
}

// Convenience wrapper for simple host-test use (no tick/timeout arguments needed).
impl Enumerator {
    /// Simplified entry point for host tests: transition `PortReset → EnableSlot`
    /// with `current_tick = 0` and `timeout_ticks = u64::MAX`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_driver_xhci::enumerate::{EnumCommand, Enumerator};
    ///
    /// let mut e = Enumerator::new(1, 0x0040_0000, 64);
    /// let cmd = e.on_port_reset_complete_simple(true).unwrap();
    /// assert!(matches!(cmd, EnumCommand::CommandRingTrb(_)));
    /// ```
    pub fn on_port_reset_complete_simple(&mut self, producer_cycle: bool) -> Option<EnumCommand> {
        self.on_port_reset_complete(0, u64::MAX, producer_cycle)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trb::{
        COMPLETION_CODE_NO_SLOTS_AVAILABLE, COMPLETION_CODE_SUCCESS, TRB_TYPE_ENABLE_SLOT,
    };

    /// Build a synthetic Command Completion Event TRB with the given
    /// completion code, slot_id, and cycle bit.
    fn make_cmd_completion(completion_code: u8, slot_id: u8, cycle: bool) -> Trb {
        let dw2: u32 = u32::from(completion_code) << 24;
        let mut dw3: u32 = (u32::from(TRB_TYPE_COMMAND_COMPLETION_EVENT)) << 10;
        if cycle {
            dw3 |= 0x1;
        }
        dw3 |= u32::from(slot_id) << 24;
        Trb::from_dwords([0, 0, dw2, dw3])
    }

    /// Build a synthetic Transfer Event TRB.
    fn make_transfer_event(completion_code: u8, slot_id: u8, cycle: bool) -> Trb {
        let dw2: u32 = u32::from(completion_code) << 24;
        let mut dw3: u32 = (u32::from(TRB_TYPE_TRANSFER_EVENT)) << 10;
        if cycle {
            dw3 |= 0x1;
        }
        dw3 |= u32::from(slot_id) << 24;
        dw3 |= 1u32 << 16; // endpoint_id = 1 (EP0 IN)
        Trb::from_dwords([0, 0, dw2, dw3])
    }

    /// A valid 18-byte USB Device Descriptor (HID keyboard VID=0x045E PID=0x00DD).
    fn keyboard_descriptor() -> [u8; 18] {
        [
            0x12, 0x01, // bLength=18, bDescriptorType=1
            0x00, 0x02, // bcdUSB = 2.00
            0x00, 0x00, 0x00, // class/sub/proto
            0x08, // bMaxPacketSize0
            0x5E, 0x04, // idVendor = 0x045E
            0xDD, 0x00, // idProduct = 0x00DD
            0x12, 0x03, // bcdDevice
            0x01, 0x02, 0x03, // string indices
            0x01, // bNumConfigurations
        ]
    }

    // -- Full happy-path: PortReset → EnableSlot → AddressDevice → GetDescriptor → Enumerated

    #[test]
    fn full_enumeration_happy_path() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        assert!(!e.is_finished());

        // Step 1: Port reset complete → EnableSlot command TRB.
        let cmd = e.on_port_reset_complete_simple(true).unwrap();
        let EnumCommand::CommandRingTrb(enable_slot_trb) = cmd else {
            panic!("expected CommandRingTrb")
        };
        assert_eq!(enable_slot_trb.trb_type(), TRB_TYPE_ENABLE_SLOT);
        assert!(!e.is_finished());

        // Step 2: Command completion for Enable Slot → slot_id = 3.
        let ev1 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 3, true);
        let cmd2 = e
            .on_event(
                &ev1,
                0x0060_0000,
                0x0080_0000,
                &keyboard_descriptor(),
                0,
                u64::MAX,
                true,
            )
            .unwrap();
        let EnumCommand::CommandRingTrb(addr_trb) = cmd2 else {
            panic!("expected AddressDevice CommandRingTrb")
        };
        assert_eq!(addr_trb.trb_type(), crate::trb::TRB_TYPE_ADDRESS_DEVICE);
        assert!(!e.is_finished());

        // Step 3: Command completion for Address Device.
        let ev2 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 3, true);
        let cmd3 = e.on_event(
            &ev2,
            0x0060_0000,
            0x0080_0000,
            &keyboard_descriptor(),
            0,
            u64::MAX,
            true,
        );
        // Returns an Ep0Transfer command.
        let ep0_cmd = cmd3.unwrap();
        assert!(matches!(
            ep0_cmd,
            EnumCommand::Ep0Transfer { slot_id: 3, .. }
        ));
        assert!(!e.is_finished());

        // Step 4: Transfer event with the device descriptor.
        let ev3 = make_transfer_event(COMPLETION_CODE_SUCCESS, 3, true);
        let cmd4 = e.on_event(
            &ev3,
            0x0060_0000,
            0x0080_0000,
            &keyboard_descriptor(),
            0,
            u64::MAX,
            true,
        );
        assert!(cmd4.is_none(), "terminal state returns None");
        assert!(e.is_finished());

        // Verify the enumerated device VID/PID.
        let (vid, pid, slot) = e.enumerated_device().unwrap();
        assert_eq!(vid, 0x045E);
        assert_eq!(pid, 0x00DD);
        assert_eq!(slot, 3);
    }

    // -- Timeout path -------------------------------------------------------

    #[test]
    fn timeout_transitions_to_failed() {
        let mut e = Enumerator::new(2, 0x0040_0000, 64);
        e.on_port_reset_complete_simple(true);
        // Simulate timeout.
        e.force_timeout();
        assert!(e.is_finished());
        assert_eq!(e.failure_reason(), Some(EnumFailReason::Timeout));
        assert!(e.enumerated_device().is_none());
    }

    #[test]
    fn is_timed_out_checks_deadline() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        e.on_port_reset_complete(0, 100, true);
        assert!(!e.is_timed_out(50));
        assert!(!e.is_timed_out(100));
        assert!(e.is_timed_out(101));
    }

    // -- No slots available -------------------------------------------------

    #[test]
    fn no_slots_available_transitions_to_failed() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        e.on_port_reset_complete_simple(true);
        let ev = make_cmd_completion(COMPLETION_CODE_NO_SLOTS_AVAILABLE, 0, true);
        e.on_event(&ev, 0, 0, &[], 0, u64::MAX, true);
        assert!(e.is_finished());
        assert_eq!(e.failure_reason(), Some(EnumFailReason::NoSlotsAvailable));
    }

    // -- Command error ------------------------------------------------------

    #[test]
    fn command_error_transitions_to_failed() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        e.on_port_reset_complete_simple(true);
        // Non-success, non-no-slots code.
        let ev = make_cmd_completion(5, 0, true); // TRB Error
        e.on_event(&ev, 0, 0, &[], 0, u64::MAX, true);
        assert!(e.is_finished());
        assert!(matches!(
            e.failure_reason(),
            Some(EnumFailReason::CommandError { code: 5 })
        ));
    }

    // -- Unexpected event ---------------------------------------------------

    #[test]
    fn unexpected_event_type_transitions_to_failed() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        e.on_port_reset_complete_simple(true);
        // Send a Transfer Event instead of Command Completion in EnableSlot state.
        let ev = make_transfer_event(COMPLETION_CODE_SUCCESS, 0, true);
        e.on_event(&ev, 0, 0, &[], 0, u64::MAX, true);
        assert!(e.is_finished());
        assert!(matches!(
            e.failure_reason(),
            Some(EnumFailReason::UnexpectedEvent {
                trb_type: TRB_TYPE_TRANSFER_EVENT
            })
        ));
    }

    // -- Malformed descriptor -----------------------------------------------

    #[test]
    fn malformed_descriptor_transitions_to_failed() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        e.on_port_reset_complete_simple(true);
        // Enable Slot completion.
        let ev1 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev1, 0, 0, &[], 0, u64::MAX, true);
        // Address Device completion.
        let ev2 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev2, 0, 0, &[], 0, u64::MAX, true);
        // Transfer event with a truncated / malformed descriptor.
        let ev3 = make_transfer_event(COMPLETION_CODE_SUCCESS, 1, true);
        let bad_desc = [0x12u8, 0x01]; // only 2 bytes (TooShort)
        e.on_event(&ev3, 0, 0, &bad_desc, 0, u64::MAX, true);
        assert!(e.is_finished());
        assert_eq!(
            e.failure_reason(),
            Some(EnumFailReason::MalformedDescriptor)
        );
    }

    // -- Transfer error -----------------------------------------------------

    #[test]
    fn transfer_error_in_get_descriptor_transitions_to_failed() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        e.on_port_reset_complete_simple(true);
        let ev1 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev1, 0, 0, &[], 0, u64::MAX, true);
        let ev2 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev2, 0, 0, &[], 0, u64::MAX, true);
        // Transfer Error during GET_DESCRIPTOR.
        let ev3 = make_transfer_event(crate::trb::COMPLETION_CODE_TRANSACTION_ERROR, 1, true);
        e.on_event(&ev3, 0, 0, &keyboard_descriptor(), 0, u64::MAX, true);
        assert!(e.is_finished());
        assert!(matches!(
            e.failure_reason(),
            Some(EnumFailReason::TransferError { .. })
        ));
    }

    // -- Terminal state ignores further events ------------------------------

    #[test]
    fn enumerated_state_ignores_further_events() {
        let mut e = Enumerator::new(1, 0x0040_0000, 64);
        e.on_port_reset_complete_simple(true);
        let ev1 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev1, 0, 0, &[], 0, u64::MAX, true);
        let ev2 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev2, 0, 0, &[], 0, u64::MAX, true);
        let ev3 = make_transfer_event(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev3, 0, 0, &keyboard_descriptor(), 0, u64::MAX, true);
        assert!(e.is_finished());

        // Send another event to a finished enumerator — must not panic or change state.
        let still_vid = e.enumerated_device().map(|(v, _, _)| v);
        e.on_event(&ev3, 0, 0, &keyboard_descriptor(), 0, u64::MAX, true);
        assert_eq!(e.enumerated_device().map(|(v, _, _)| v), still_vid);
    }

    // -- port() accessor ---------------------------------------------------

    #[test]
    fn enumerator_port_accessor() {
        let e = Enumerator::new(5, 0, 64);
        assert_eq!(e.port(), 5);
    }

    // -- ep0_max_packet_for_speed ------------------------------------------

    #[test]
    fn ep0_mps_high_speed() {
        assert_eq!(
            super::ep0_max_packet_for_speed(crate::context::USB_SPEED_HIGH),
            64
        );
    }

    #[test]
    fn ep0_mps_super_speed() {
        assert_eq!(
            super::ep0_max_packet_for_speed(crate::context::USB_SPEED_SUPER),
            512
        );
    }

    #[test]
    fn ep0_mps_low_speed() {
        assert_eq!(
            super::ep0_max_packet_for_speed(crate::context::USB_SPEED_LOW),
            8
        );
    }

    #[test]
    fn ep0_mps_full_speed() {
        assert_eq!(
            super::ep0_max_packet_for_speed(crate::context::USB_SPEED_FULL),
            64
        );
    }

    #[test]
    fn ep0_mps_unknown_speed_conservative() {
        assert_eq!(super::ep0_max_packet_for_speed(0), 8);
        assert_eq!(super::ep0_max_packet_for_speed(9), 8);
    }

    // -- new_with_speed ----------------------------------------------------

    #[test]
    fn new_with_speed_high_speed_mps_64() {
        let e = Enumerator::new_with_speed(1, 0x0040_0000, crate::context::USB_SPEED_HIGH);
        assert_eq!(e.ep0_max_packet_size(), 64);
        assert_eq!(e.port_speed(), crate::context::USB_SPEED_HIGH);
    }

    #[test]
    fn new_with_speed_super_speed_mps_512() {
        let e = Enumerator::new_with_speed(2, 0x0040_0000, crate::context::USB_SPEED_SUPER);
        assert_eq!(e.ep0_max_packet_size(), 512);
        assert_eq!(e.port_speed(), crate::context::USB_SPEED_SUPER);
    }

    // -- enumerated_device_full includes speed + ep0_mps ------------------

    #[test]
    fn enumerated_device_full_carries_speed_and_mps() {
        let mut e = Enumerator::new_with_speed(1, 0x0040_0000, crate::context::USB_SPEED_HIGH);
        e.on_port_reset_complete_simple(true);
        let ev1 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev1, 0, 0, &[], 0, u64::MAX, true);
        let ev2 = make_cmd_completion(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev2, 0, 0, &[], 0, u64::MAX, true);
        let ev3 = make_transfer_event(COMPLETION_CODE_SUCCESS, 1, true);
        e.on_event(&ev3, 0, 0, &keyboard_descriptor(), 0, u64::MAX, true);
        assert!(e.is_finished());
        let full = e.enumerated_device_full().unwrap();
        // full = (vid, pid, slot_id, speed, ep0_mps)
        assert_eq!(full.3, crate::context::USB_SPEED_HIGH, "speed");
        assert_eq!(full.4, 64, "ep0_mps");
    }
}

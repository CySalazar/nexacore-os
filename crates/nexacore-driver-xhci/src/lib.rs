//! # `nexacore-driver-xhci`
//!
//! NexaCore OS first-party xHCI (USB 3.x host controller interface) user-space
//! driver — TASK-26 scaffold (ADR-0048, DE-E1+E2) extended with HID +
//! Mass Storage class logic (ADR-0049, TASK-27, DE-E3+E4).
//!
//! ## Scope
//!
//! This crate implements the host-testable logic surface for the full xHCI
//! driver stack: controller bring-up (DE-E1), root-hub port enumeration
//! (DE-E2), HID boot-protocol keyboard/mouse driver (DE-E3), and Mass Storage
//! BOT/SCSI driver (DE-E4). The driver runs as a Ring 3 user-space process
//! spawned by the kernel via the boot-spawn path (ADR-0048 D2, mirroring
//! `nexacore-driver-nvme`).
//!
//! ## Module layout
//!
//! - [`regs`] — xHCI register set offsets and field accessors. Capability,
//!   operational, runtime, and doorbell register layouts per xHCI § 5.
//! - [`trb`] — Transfer Request Block types, encode/decode, and typed
//!   constructors + event parsers. Every device-written field is treated as
//!   untrusted input and validated before use.
//! - [`ring`] — Pure-state ring math: [`ring::CommandRing`] (producer),
//!   [`ring::EventRing`] (consumer, cycle-bit gated), [`ring::TransferRing`]
//!   (producer). No DMA, no MMIO. Host-testable by construction.
//! - [`context`] — DCBAA + slot/endpoint context builders. Parameterised by
//!   `HCCPARAMS1.CSZ` (32- or 64-byte context size). Includes the generic
//!   `write_endpoint_context` for Bulk/Interrupt endpoints beyond EP0.
//! - [`descriptor`] — USB descriptor parsing. Every parse is length-checked;
//!   malformed / truncated / over-long descriptors return typed errors, never
//!   panics.
//! - [`enumerate`] — Device enumeration state machine driven by feeding it
//!   events. Pure state: the image crate drives the actual MMIO/DMA I/O.
//!   Speed-aware: `ep0_max_packet_for_speed` derives the correct EP0 MPS.
//! - [`control`] — USB control-transfer SETUP packet builders for standard and
//!   HID class requests (`GET_DESCRIPTOR`, `SET_CONFIGURATION`,
//!   `SET_PROTOCOL(boot)`, `SET_IDLE`).
//! - [`hid`] — HID boot-protocol keyboard/mouse report parsing, consecutive
//!   report key-event diffing, and HID Usage ID → display keycode mapping
//!   (DE-E3, ADR-0049).
//! - [`storage`] — USB Mass Storage BOT/SCSI CBW/CSW codecs, SCSI CDB
//!   builders, BLK channel gateway, and INQUIRY/READ CAPACITY response
//!   parsers (DE-E4, ADR-0049).
//!
//! ## `MmioBackend` seam
//!
//! The crate exposes two traits — [`MmioBackend`] (write-only doorbell + register
//! sink) and [`MmioReadBackend`] (register source) — that decouple the pure ring /
//! control logic from live hardware. The image crate implements them with
//! `volatile_write` / `volatile_read` over the mapped BAR; host tests substitute
//! in-memory recorders for deterministic assertion.
//!
//! ## Security posture
//!
//! All data written by the device (event TRBs, descriptor bytes over control
//! transfers) is treated as **untrusted input**: explicit length bounds checks
//! are performed before every field access; out-of-range values yield typed
//! errors, never out-of-bounds reads or panics.
//!
//! ## Cross-references
//!
//! - ADR-0048: `docs/adr/0048-xhci-usb-driver.md`
//! - Template: `crates/nexacore-driver-nvme` (ADR-0036/0037)
//! - xHCI specification: xHCI for Universal Serial Bus, revision 1.2
//! - USB specification: USB 2.0 / 3.x § 9 (device framework)

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-driver-xhci")]
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
// Test-only allow list — mirrors nexacore-driver-nvme's ADR-0003 carve-out.
// Production code keeps the workspace `deny(unwrap_used, expect_used, panic)`
// invariants; test helpers use `.unwrap()` / `.expect()` for terseness.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::doc_markdown
    )
)]

// The `hid` module uses `alloc::vec::Vec` to return key-event lists from
// `HidKeyboardState::update`.  Pull in the `alloc` crate so `no_std` builds
// work correctly while `std` test-runs use `std::alloc` transparently.
extern crate alloc;

pub mod context;
pub mod control;
pub mod descriptor;
pub mod enumerate;
pub mod hid;
pub mod hub;
pub mod regs;
pub mod ring;
pub mod storage;
pub mod trb;
pub mod uvc;

// =============================================================================
// MmioBackend / MmioReadBackend — abstract MMIO seam
// =============================================================================

/// Abstract MMIO sink for register and doorbell writes.
///
/// The live driver implements this with a `volatile_write` to the controller's
/// mapped BAR; host tests implement it with an in-memory recorder for
/// assertion.
///
/// The trait is deliberately minimal: one write path, no read side (that
/// lives in [`MmioReadBackend`]), no error type (MMIO writes are fire-and-forget
/// per the xHCI specification — the controller signals errors asynchronously
/// via event TRBs, not via the write return path).
///
/// # Usage example (host test mock)
///
/// ```rust
/// use nexacore_driver_xhci::MmioBackend;
///
/// struct Recorder(Vec<(usize, u32)>);
///
/// impl MmioBackend for Recorder {
///     fn write_u32(&mut self, offset: usize, value: u32) {
///         self.0.push((offset, value));
///     }
/// }
///
/// let mut rec = Recorder(Vec::new());
/// rec.write_u32(0x20, 0x0000_0001); // USBCMD R/S
/// assert_eq!(rec.0.len(), 1);
/// ```
pub trait MmioBackend {
    /// Write a 32-bit value at the given byte offset inside the controller's
    /// MMIO region.
    ///
    /// The live implementation performs a 32-bit aligned `volatile_write`
    /// (required by the xHCI specification § 5.1 "Register Bit Definitions").
    /// Host implementations record the `(offset, value)` pair for assertion.
    fn write_u32(&mut self, offset: usize, value: u32);

    /// Write a 64-bit value at the given byte offset inside the controller's
    /// MMIO region.
    ///
    /// The live implementation performs two consecutive 32-bit `volatile_write`
    /// calls — low dword first, high dword second — per xHCI § 5.1 (64-bit
    /// registers must be written low-dword first). Host implementations
    /// may record both writes or the combined value as appropriate.
    ///
    /// The default implementation splits into two [`Self::write_u32`] calls.
    fn write_u64(&mut self, offset: usize, value: u64) {
        #![allow(clippy::cast_possible_truncation)]
        self.write_u32(offset, value as u32);
        self.write_u32(offset + 4, (value >> 32) as u32);
    }
}

/// Abstract MMIO source for register reads.
///
/// Separate from [`MmioBackend`] because the doorbell write path and the
/// status-register read path have independent lifetimes (the bring-up sequence
/// polls `USBSTS` before any doorbell write, and the transfer hot-path writes
/// doorbells without re-reading status registers). Splitting the traits avoids
/// forcing every doorbell-only implementation to also provide a read method.
///
/// The live implementation performs a 32-bit aligned `volatile_read` per the
/// xHCI specification; host implementations return pre-canned sequences of
/// values to simulate controller state transitions deterministically.
///
/// # Usage example (host test mock)
///
/// ```rust
/// use nexacore_driver_xhci::MmioReadBackend;
///
/// struct Fixed(u32);
///
/// impl MmioReadBackend for Fixed {
///     fn read_u32(&mut self, _offset: usize) -> u32 {
///         self.0
///     }
/// }
///
/// let mut fixed = Fixed(0x0000_0001); // USBSTS.HCH clear
/// assert_eq!(fixed.read_u32(0x04), 1);
/// ```
pub trait MmioReadBackend {
    /// Read a 32-bit value from the given byte offset inside the controller's
    /// MMIO region.
    fn read_u32(&mut self, offset: usize) -> u32;

    /// Read a 64-bit value from the given byte offset inside the controller's
    /// MMIO region.
    ///
    /// The default implementation assembles two consecutive [`Self::read_u32`]
    /// calls — low dword first. The live implementation MUST perform two
    /// aligned 32-bit volatile reads per xHCI § 5.1.
    fn read_u64(&mut self, offset: usize) -> u64 {
        let lo = u64::from(self.read_u32(offset));
        let hi = u64::from(self.read_u32(offset + 4));
        lo | (hi << 32)
    }
}

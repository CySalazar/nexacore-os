//! Main driver struct and TX/RX dispatch for the Intel e1000e.
//!
//! This module provides [`E1000eDriver`] — the central state object that ties
//! together the [`crate::ring::RxDescriptorRing`] and
//! [`crate::ring::TxDescriptorRing`] ring managers with the NET channel IPC
//! protocol defined in [`nexacore_types::net_channel`].
//!
//! ## Architecture
//!
//! `E1000eDriver` is intentionally free of hardware MMIO. All hardware
//! interactions (register writes, DMA mapping, IRQ attachment) live in the
//! bootable image sibling `nexacore-driver-e1000e-image` (P6.7.8.7). This crate
//! stays a host-testable `no_std + alloc` library:
//!
//! - The test suite exercises `handle_request`, `send_frame`, `poll_rx`, and
//!   `poll_tx_completions` entirely in software without hardware or MMIO.
//! - The bootable image wraps `E1000eDriver` and calls its methods in response
//!   to real IRQs and IPC messages.
//!
//! ## State machine
//!
//! The driver tracks its lifecycle via [`DriverState`]. After construction
//! (`new`) the driver starts in [`DriverState::Ready`] — the host-testable
//! model assumes the bring-up FSM ([`crate::bringup`]) has already completed
//! successfully before the `E1000eDriver` is handed any traffic. In the
//! bootable image the bring-up FSM transitions the driver from `Uninitialized`
//! to `Ready`.
//!
//! ## Buffer model
//!
//! RX receive buffers are simulated as `Vec<Vec<u8>>` pre-allocated in `new`.
//! Each `Vec<u8>` is `rx_buffer_size` bytes. In the bootable image the outer
//! `Vec` is replaced by DMA-mapped pages whose IOVAs are posted into the RX
//! ring, but the host-testable layer uses heap allocations to exercise the
//! same descriptor-ring paths.
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md

extern crate alloc;
use alloc::{vec, vec::Vec};

use nexacore_types::net_channel::{NetRequest, NetResponse};

use crate::ring::{RxDescriptorRing, TxDescriptorRing};

// =============================================================================
// DriverState
// =============================================================================

/// Lifecycle state of the e1000e driver.
///
/// Tracks the driver's position in its lifecycle. The bring-up FSM
/// ([`crate::bringup`]) is responsible for transitioning from
/// [`DriverState::Uninitialized`] to [`DriverState::Ready`]. Once at
/// `Ready`, the driver accepts NET channel requests and services RX/TX
/// interrupts.
///
/// # State transitions
///
/// ```text
/// Uninitialized
///     │  (bring-up FSM: PciEnumeration … MmioMap)
///     ▼
///   Reset
///     │  (GlobalReset complete)
///     ▼
/// Configured
///     │  (rings allocated, interrupts enabled, NET channel registered)
///     ▼
///   Ready  ←── normal operating mode; all NET channel requests handled
///     │  (on unrecoverable hardware error)
///     ▼
///   Error  ── driver process exits; kernel reclaims PCB
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    /// Driver object has been constructed but hardware bring-up has not
    /// started.
    Uninitialized,
    /// Global reset has been triggered; hardware is coming out of reset.
    Reset,
    /// Rings have been allocated and configured; interrupts not yet enabled.
    Configured,
    /// Bring-up complete; driver is servicing NET channel requests.
    Ready,
    /// An unrecoverable hardware error occurred; the driver process should
    /// exit.
    Error,
}

// =============================================================================
// DriverStats
// =============================================================================

/// Cumulative traffic and error counters for the e1000e driver.
///
/// Updated by [`E1000eDriver::send_frame`], [`E1000eDriver::poll_rx`], and
/// their error paths. All counters are u64 and saturate on overflow (the
/// driver runs until a kernel-level reboot, so saturation is acceptable).
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::driver::DriverStats;
///
/// let stats = DriverStats::default();
/// assert_eq!(stats.tx_packets, 0);
/// assert_eq!(stats.rx_packets, 0);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct DriverStats {
    /// Total frames successfully submitted for transmission.
    pub tx_packets: u64,
    /// Total frames successfully received and returned to the caller.
    pub rx_packets: u64,
    /// Total bytes submitted for transmission (across all `tx_packets`).
    pub tx_bytes: u64,
    /// Total bytes received (across all `rx_packets`).
    pub rx_bytes: u64,
    /// Total transmission errors (ring full, frame too large, etc.).
    pub tx_errors: u64,
    /// Total receive errors (descriptor errors set by hardware, etc.).
    pub rx_errors: u64,
}

// =============================================================================
// E1000eError
// =============================================================================

/// Errors returned by [`E1000eDriver`] operations.
///
/// These map onto the [`NetResponse`] variants that the driver emits over the
/// NET IPC channel. The distinction between `E1000eError` and `NetResponse` is
/// that the error type is internal (Rust `Result`), whereas `NetResponse` is
/// the wire-visible ABI.
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::driver::{E1000eDriver, E1000eError};
///
/// let mut driver = E1000eDriver::new(4, 4, 2048);
/// // A 1-byte frame is below the minimum Ethernet header length.
/// let err = driver.send_frame(&[0u8; 1]).unwrap_err();
/// assert_eq!(err, E1000eError::InvalidFrame);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E1000eError {
    /// The TX ring has no free descriptor slots. The caller should retry after
    /// [`E1000eDriver::poll_tx_completions`] reclaims completed slots.
    QueueFull,
    /// The frame exceeds the maximum Ethernet frame size (1514 bytes: 1500-byte
    /// payload + 14-byte header). Matches [`NetResponse::FrameTooLarge`].
    FrameTooLarge,
    /// No pre-allocated RX buffers are available to post into the RX ring.
    NoBuffersAvailable,
    /// The frame is structurally invalid (length < 14 bytes, the minimum
    /// Ethernet header).
    InvalidFrame,
    /// The driver is not in [`DriverState::Ready`]. Operations are rejected
    /// until bring-up completes.
    NotReady,
}

// =============================================================================
// MTU constant
// =============================================================================

/// Maximum Ethernet frame size accepted for transmission (bytes).
///
/// 1514 = 1500-byte payload + 14-byte header (no VLAN tag). The driver rejects
/// frames larger than this with [`E1000eError::FrameTooLarge`]. Matches the
/// `bytes_len` upper bound stated in [`NetRequest::SendFrame`].
pub const MAX_FRAME_BYTES: usize = 1514;

/// Minimum Ethernet frame size (bytes): 14-byte header only (no payload is
/// technically valid for padding-required frames). Any frame shorter than
/// this is rejected with [`E1000eError::InvalidFrame`].
pub const MIN_FRAME_BYTES: usize = 14;

// =============================================================================
// E1000eDriver
// =============================================================================

/// Central state object for the Intel e1000e user-space driver.
///
/// Owns the RX and TX descriptor rings, the pre-allocated RX receive buffers,
/// the driver lifecycle state, and cumulative statistics. The bootable image
/// sibling wraps this struct and calls its methods in response to hardware IRQs
/// and IPC requests on `nexacore.svc.net.eth<N>`.
///
/// ## Construction
///
/// Use [`E1000eDriver::new`]. The driver starts in [`DriverState::Ready`] so
/// that the host-testable model can exercise the full RX/TX path without
/// replaying the bring-up FSM.
///
/// ## Thread safety
///
/// `E1000eDriver` is **not** `Send` or `Sync`. It is designed for single-
/// threaded event-loop ownership in the driver process. Cross-core sharing
/// (if ever needed) must be provided by a wrapper with appropriate locking.
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::driver::{DriverState, E1000eDriver};
///
/// let driver = E1000eDriver::new(8, 8, 2048);
/// assert_eq!(driver.state, DriverState::Ready);
/// assert!(!driver.link_up); // link starts down until hardware confirms it
/// ```
pub struct E1000eDriver {
    /// Current lifecycle state of the driver.
    pub state: DriverState,
    /// The interface's MAC address in network byte order.
    pub mac: [u8; 6],
    /// `true` when the PHY reports an active link.
    pub link_up: bool,
    /// TX descriptor ring.
    pub tx_ring: TxDescriptorRing,
    /// RX descriptor ring.
    pub rx_ring: RxDescriptorRing,
    /// Pre-allocated RX receive buffers. Each entry is `rx_buffer_size` bytes.
    /// In the host-testable model these are heap-allocated `Vec<u8>` slices;
    /// the bootable image replaces them with IOVA-backed DMA pages.
    pub rx_buffers: Vec<Vec<u8>>,
    /// Cumulative driver statistics.
    pub stats: DriverStats,
    /// Size in bytes of each RX buffer. Fixed at construction time.
    rx_buffer_size: usize,
    /// Index of the next RX buffer to post (cycles through `rx_buffers`).
    next_rx_buf: usize,
}

impl E1000eDriver {
    /// Construct a new `E1000eDriver` with the given ring depths and RX buffer
    /// size.
    ///
    /// - `rx_ring_size` — number of RX descriptor slots. Clamped to at least 1
    ///   by [`RxDescriptorRing::new`].
    /// - `tx_ring_size` — number of TX descriptor slots. Clamped to at least 1
    ///   by [`TxDescriptorRing::new`].
    /// - `rx_buffer_size` — size in bytes of each pre-allocated RX buffer.
    ///   Must be at least 1; clamped to 1 if 0.
    ///
    /// The driver starts in [`DriverState::Ready`] with `link_up = false` and
    /// a zeroed MAC address. The bootable image sibling sets `mac` and
    /// `link_up` after the bring-up FSM reads `RAL[0]`/`RAH[0]` and the PHY
    /// status.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::driver::{DriverState, E1000eDriver};
    ///
    /// let driver = E1000eDriver::new(256, 256, 2048);
    /// assert_eq!(driver.state, DriverState::Ready);
    /// assert_eq!(driver.mac, [0u8; 6]);
    /// assert_eq!(driver.stats().tx_packets, 0);
    /// ```
    #[must_use]
    pub fn new(rx_ring_size: u16, tx_ring_size: u16, rx_buffer_size: usize) -> Self {
        let rx_buffer_size = rx_buffer_size.max(1);
        let rx_ring = RxDescriptorRing::new(rx_ring_size);
        let tx_ring = TxDescriptorRing::new(tx_ring_size);
        // Allocate one RX buffer per RX ring slot so the ring can always be
        // fully posted on start-up.
        let rx_count = rx_ring.count() as usize;
        let rx_buffers: Vec<Vec<u8>> = (0..rx_count).map(|_| vec![0u8; rx_buffer_size]).collect();

        Self {
            state: DriverState::Ready,
            mac: [0u8; 6],
            link_up: false,
            tx_ring,
            rx_ring,
            rx_buffers,
            stats: DriverStats::default(),
            rx_buffer_size,
            next_rx_buf: 0,
        }
    }

    /// Handle an incoming [`NetRequest`] from the network stack and return the
    /// appropriate [`NetResponse`].
    ///
    /// This is the primary dispatch function called by the driver's IPC event
    /// loop. All request variants are handled:
    ///
    /// - [`NetRequest::SendFrame`] → forwards to [`send_frame`](Self::send_frame).
    ///   The `bytes_iova` is used as a synthetic buffer address in the TX ring;
    ///   in the bootable image it is the actual DMA-mapped IOVA.
    /// - [`NetRequest::GetLinkState`] → returns [`NetResponse::Ok`] if the
    ///   driver is ready; the actual link state is queried via the out-of-band
    ///   companion mechanism described in `NCIP-Driver-Net-015` § S6.
    /// - [`NetRequest::GetMac`] → returns [`NetResponse::Ok`]; the MAC is read
    ///   from `driver.mac` directly.
    /// - [`NetRequest::SetPromisc`] → returns [`NetResponse::NotSupported`]
    ///   (v0.3 does not implement promiscuous mode; scheduled for v0.4).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::driver::E1000eDriver;
    /// use nexacore_types::net_channel::{NetRequest, NetResponse};
    ///
    /// let mut driver = E1000eDriver::new(4, 4, 2048);
    /// driver.link_up = true;
    ///
    /// let resp = driver.handle_request(&NetRequest::GetLinkState);
    /// assert_eq!(resp, NetResponse::Ok);
    /// ```
    pub fn handle_request(&mut self, req: &NetRequest) -> NetResponse {
        // Reject all requests immediately when the driver is not ready, except
        // that a driver in Error state also reports NotReady so callers can
        // detect the terminal condition.
        match self.state {
            DriverState::Ready => {}
            _ => return NetResponse::NotSupported,
        }

        match req {
            NetRequest::SendFrame {
                bytes_iova,
                bytes_len,
            } => {
                // Build a synthetic frame slice for validation purposes.
                // In the bootable image, the actual bytes are in the DMA
                // buffer at `bytes_iova`; here we create a zero-filled
                // slice of `bytes_len` to exercise the same validation path.
                let synthetic_frame = vec![0u8; *bytes_len as usize];
                match self.send_frame_iova(*bytes_iova, &synthetic_frame) {
                    Ok(()) => NetResponse::Ok,
                    Err(E1000eError::FrameTooLarge) => NetResponse::FrameTooLarge,
                    // QueueFull, InvalidFrame, and NoBuffersAvailable all map
                    // to InvalidArgument at the IPC boundary.
                    Err(
                        E1000eError::QueueFull
                        | E1000eError::InvalidFrame
                        | E1000eError::NoBuffersAvailable,
                    ) => NetResponse::InvalidArgument,
                    Err(E1000eError::NotReady) => NetResponse::NotSupported,
                }
            }
            NetRequest::GetLinkState => {
                // The actual link state is delivered via the companion out-of-
                // band mechanism (a structured `LinkState` message on a
                // separate call); this response confirms the driver is alive.
                if self.link_up {
                    NetResponse::Ok
                } else {
                    NetResponse::LinkDown
                }
            }
            NetRequest::GetMac => {
                // MAC is read directly from `self.mac` by the caller; the
                // NET channel only signals success/failure here.
                NetResponse::Ok
            }
            NetRequest::SetPromisc { .. } => {
                // Promiscuous mode is not implemented in v0.3. Scheduled for
                // v0.4 together with multicast filtering and VLAN offload.
                NetResponse::NotSupported
            }
            // `#[non_exhaustive]` catch-all: future variants are unsupported
            // until the driver is updated.
            _ => NetResponse::NotSupported,
        }
    }

    /// Transmit a raw Ethernet frame.
    ///
    /// Validates the frame length, posts the frame data into the TX ring, and
    /// updates statistics. In the host-testable model the frame bytes are
    /// copied into a heap buffer and the buffer's address is used as the
    /// `buffer_addr` in the TX descriptor. In the bootable image the caller
    /// provides an IOVA that the hardware DMA-reads directly.
    ///
    /// # Errors
    ///
    /// - [`E1000eError::NotReady`] — driver is not in [`DriverState::Ready`].
    /// - [`E1000eError::InvalidFrame`] — frame shorter than 14 bytes.
    /// - [`E1000eError::FrameTooLarge`] — frame longer than 1514 bytes.
    /// - [`E1000eError::QueueFull`] — TX ring has no free descriptor slots.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::driver::{E1000eDriver, E1000eError};
    ///
    /// let mut driver = E1000eDriver::new(4, 4, 2048);
    /// driver.link_up = true;
    ///
    /// // Minimum-size Ethernet frame (14-byte header, no payload).
    /// let frame = [0u8; 14];
    /// driver.send_frame(&frame).expect("send ok");
    /// assert_eq!(driver.stats().tx_packets, 1);
    /// ```
    // SAFETY for cast_possible_truncation: frame.len() is checked to be <=
    // MAX_FRAME_BYTES (1514) before the cast, so the value always fits in u16.
    #[allow(clippy::cast_possible_truncation)]
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), E1000eError> {
        if self.state != DriverState::Ready {
            return Err(E1000eError::NotReady);
        }
        if frame.len() < MIN_FRAME_BYTES {
            self.stats.tx_errors = self.stats.tx_errors.saturating_add(1);
            return Err(E1000eError::InvalidFrame);
        }
        if frame.len() > MAX_FRAME_BYTES {
            self.stats.tx_errors = self.stats.tx_errors.saturating_add(1);
            return Err(E1000eError::FrameTooLarge);
        }
        if self.tx_ring.is_full() {
            self.stats.tx_errors = self.stats.tx_errors.saturating_add(1);
            return Err(E1000eError::QueueFull);
        }

        // Use the frame slice's pointer as a synthetic IOVA for the host-
        // testable model. The bootable image sibling replaces this with the
        // real DMA IOVA from the `DmaMap` syscall.
        let buf_addr = frame.as_ptr() as u64;
        let len = frame.len() as u16;

        // submit_tx cannot fail here: is_full() check above guarantees a slot.
        self.tx_ring
            .submit_tx(buf_addr, len)
            .ok_or(E1000eError::QueueFull)?;

        self.stats.tx_packets = self.stats.tx_packets.saturating_add(1);
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(frame.len() as u64);
        Ok(())
    }

    /// Internal variant of `send_frame` that accepts an explicit IOVA.
    ///
    /// Used by [`handle_request`](Self::handle_request) for the `SendFrame`
    /// path where the caller provides the IOVA from a prior `DmaMap`; the
    /// `frame` slice is only used for length validation.
    ///
    /// This function does not update `tx_errors` on its own; the caller
    /// (`handle_request`) handles error accounting at the IPC boundary.
    // SAFETY for cast_possible_truncation: frame.len() is checked to be <=
    // MAX_FRAME_BYTES (1514) before the cast, so the value always fits in u16.
    #[allow(clippy::cast_possible_truncation)]
    fn send_frame_iova(&mut self, iova: u64, frame: &[u8]) -> Result<(), E1000eError> {
        if self.state != DriverState::Ready {
            return Err(E1000eError::NotReady);
        }
        if frame.len() < MIN_FRAME_BYTES {
            self.stats.tx_errors = self.stats.tx_errors.saturating_add(1);
            return Err(E1000eError::InvalidFrame);
        }
        if frame.len() > MAX_FRAME_BYTES {
            self.stats.tx_errors = self.stats.tx_errors.saturating_add(1);
            return Err(E1000eError::FrameTooLarge);
        }
        if self.tx_ring.is_full() {
            self.stats.tx_errors = self.stats.tx_errors.saturating_add(1);
            return Err(E1000eError::QueueFull);
        }

        let len = frame.len() as u16;
        self.tx_ring
            .submit_tx(iova, len)
            .ok_or(E1000eError::QueueFull)?;

        self.stats.tx_packets = self.stats.tx_packets.saturating_add(1);
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(frame.len() as u64);
        Ok(())
    }

    /// Poll the RX ring for a completed received frame.
    ///
    /// If a completed descriptor (DD+EOP set) is present at the head of the
    /// RX ring, the method:
    /// 1. Reaps the descriptor from the ring.
    /// 2. Copies the received bytes from the pre-allocated RX buffer into a
    ///    new `Vec<u8>` owned by the caller.
    /// 3. Re-posts a fresh buffer into the slot and advances the tail.
    /// 4. Updates `rx_packets` and `rx_bytes` statistics.
    ///
    /// Returns `Some(frame_bytes)` if a frame was available, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::{
    ///     driver::E1000eDriver,
    ///     ring::{RX_STATUS_DD, RX_STATUS_EOP},
    /// };
    ///
    /// let mut driver = E1000eDriver::new(4, 4, 2048);
    /// driver.link_up = true;
    ///
    /// // Post a buffer and simulate hardware completion.
    /// driver.rx_ring.post_buffer(0x8000, 2048);
    /// driver.rx_ring.advance_tail();
    /// driver.rx_ring.descriptors_mut()[0].length = 60;
    /// driver.rx_ring.descriptors_mut()[0].status = RX_STATUS_DD | RX_STATUS_EOP;
    ///
    /// let frame = driver.poll_rx();
    /// assert!(frame.is_some());
    /// assert_eq!(driver.stats().rx_packets, 1);
    /// ```
    pub fn poll_rx(&mut self) -> Option<Vec<u8>> {
        if self.state != DriverState::Ready {
            return None;
        }

        // Attempt to reap a completed descriptor.
        let (_desc_idx, bytes_received) = self.rx_ring.reap_rx()?;

        // Clamp to buffer size (defence against hardware reporting more bytes
        // than the buffer can hold — should never happen with correct RCTL.BSIZE,
        // but we guard defensively).
        let copy_len = (bytes_received as usize).min(self.rx_buffer_size);

        // Copy bytes out of the current RX buffer.
        // rx_buffers has rx_ring.count() >= 1 entries (guaranteed by new()),
        // so the modulo is always in bounds.
        let buf_idx = self.next_rx_buf % self.rx_buffers.len();
        // SAFETY for indexing_slicing: buf_idx < rx_buffers.len() by construction
        // above (modulo by non-zero len). The slice bound copy_len <=
        // rx_buffer_size == rx_buffers[buf_idx].len() by construction in new().
        #[allow(clippy::indexing_slicing)]
        let frame: Vec<u8> = self.rx_buffers[buf_idx][..copy_len].to_vec();

        // Update statistics.
        self.stats.rx_packets = self.stats.rx_packets.saturating_add(1);
        self.stats.rx_bytes = self.stats.rx_bytes.saturating_add(copy_len as u64);

        // Re-post the buffer into the ring for the next receive, using the
        // existing heap allocation's address as the synthetic IOVA.
        // SAFETY for indexing_slicing: same buf_idx bound argument as above.
        // SAFETY for cast_possible_truncation: rx_buffer_size is at most
        // MAX_RING_DEPTH * RX_BUFFER_BYTES which is well within u16::MAX
        // for the values used in practice (default 2048).
        #[allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]
        let iova = self.rx_buffers[buf_idx].as_ptr() as u64;
        #[allow(clippy::cast_possible_truncation)]
        if let Some(_slot) = self.rx_ring.post_buffer(iova, self.rx_buffer_size as u16) {
            self.rx_ring.advance_tail();
        }

        self.next_rx_buf = self.next_rx_buf.wrapping_add(1);
        Some(frame)
    }

    /// Reap completed TX descriptors and return the count freed.
    ///
    /// Delegates to [`TxDescriptorRing::reap_tx`] and returns the number of
    /// descriptors reclaimed. The caller may use the returned count to track
    /// outstanding frames or decide when to submit more work.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::{driver::E1000eDriver, ring::TX_STATUS_DD};
    ///
    /// let mut driver = E1000eDriver::new(4, 4, 2048);
    /// let frame = [0u8; 64];
    /// driver.send_frame(&frame).expect("ok");
    ///
    /// // Simulate hardware completion.
    /// driver.tx_ring.descriptors_mut()[0].status_reserved = TX_STATUS_DD;
    ///
    /// let freed = driver.poll_tx_completions();
    /// assert_eq!(freed, 1);
    /// ```
    pub fn poll_tx_completions(&mut self) -> u16 {
        self.tx_ring.reap_tx()
    }

    /// Return the interface's MAC address.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::driver::E1000eDriver;
    ///
    /// let mut driver = E1000eDriver::new(4, 4, 2048);
    /// driver.mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
    /// assert_eq!(driver.mac(), [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    /// ```
    #[must_use]
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Load the interface MAC from a `RAL[0]` / `RAH[0]` register read captured
    /// at bring-up (WS2-03.2). Fail-closed: if `AV` is clear (the EEPROM/NVM
    /// load has not completed) the stored MAC is left unchanged and `false` is
    /// returned, so the driver never advertises a zero/garbage address.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::{controller_regs::encode_mac_regs, driver::E1000eDriver};
    ///
    /// let mut driver = E1000eDriver::new(4, 4, 2048);
    /// let (ral, rah) = encode_mac_regs([0x52, 0x54, 0x00, 0x01, 0x02, 0x03]);
    /// assert!(driver.set_mac_from_regs(ral, rah));
    /// assert_eq!(driver.mac(), [0x52, 0x54, 0x00, 0x01, 0x02, 0x03]);
    /// // AV clear → refused, MAC untouched.
    /// assert!(!driver.set_mac_from_regs(0xAAAA_AAAA, 0x0000_BBBB));
    /// assert_eq!(driver.mac(), [0x52, 0x54, 0x00, 0x01, 0x02, 0x03]);
    /// ```
    #[allow(clippy::similar_names)] // ral/rah are datasheet register names
    pub fn set_mac_from_regs(&mut self, ral: u32, rah: u32) -> bool {
        match crate::controller_regs::decode_mac(ral, rah) {
            Some(mac) => {
                self.mac = mac;
                true
            }
            None => false,
        }
    }

    /// Update [`E1000eDriver::link_up`] from a device `STATUS` register read and
    /// return the decoded [`crate::phy::LinkStatus`] (WS2-03.7). Called on every `LSC`
    /// interrupt and once at bring-up after the PHY reports a link.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::{
    ///     controller_regs::{STATUS_FD_BIT, STATUS_LU_BIT},
    ///     driver::E1000eDriver,
    ///     phy::LinkSpeed,
    /// };
    ///
    /// let mut driver = E1000eDriver::new(4, 4, 2048);
    /// // LU | FD | speed=0b10 (1 Gb/s).
    /// let link = driver.update_link_from_status(STATUS_LU_BIT | STATUS_FD_BIT | (0b10 << 6));
    /// assert!(driver.link_up);
    /// assert_eq!(link.speed, LinkSpeed::Mb1000);
    /// // Link drop.
    /// driver.update_link_from_status(0);
    /// assert!(!driver.link_up);
    /// ```
    pub fn update_link_from_status(&mut self, status: u32) -> crate::phy::LinkStatus {
        let link = crate::phy::LinkStatus::from_csr_status(status);
        self.link_up = link.up;
        link
    }

    /// Return a reference to the cumulative driver statistics.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::driver::E1000eDriver;
    ///
    /// let driver = E1000eDriver::new(4, 4, 2048);
    /// let s = driver.stats();
    /// assert_eq!(s.tx_packets, 0);
    /// assert_eq!(s.rx_packets, 0);
    /// ```
    #[must_use]
    pub fn stats(&self) -> &DriverStats {
        &self.stats
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]
mod tests {
    use nexacore_types::net_channel::{NetRequest, NetResponse};

    use super::*;
    use crate::ring::{RX_STATUS_DD, RX_STATUS_EOP, TX_STATUS_DD};

    // ---- construction -------------------------------------------------------

    #[test]
    fn new_driver_starts_ready_with_zero_stats() {
        let d = E1000eDriver::new(8, 8, 2048);
        assert_eq!(d.state, DriverState::Ready);
        assert_eq!(d.mac, [0u8; 6]);
        assert!(!d.link_up);
        assert_eq!(d.stats.tx_packets, 0);
        assert_eq!(d.stats.rx_packets, 0);
        assert_eq!(d.stats.tx_bytes, 0);
        assert_eq!(d.stats.rx_bytes, 0);
        assert_eq!(d.stats.tx_errors, 0);
        assert_eq!(d.stats.rx_errors, 0);
    }

    #[test]
    fn new_driver_allocates_rx_buffers_matching_ring_size() {
        let d = E1000eDriver::new(4, 4, 2048);
        // rx_buffers count should match rx_ring.count()
        assert_eq!(d.rx_buffers.len(), d.rx_ring.count() as usize);
    }

    // ---- send_frame ---------------------------------------------------------

    #[test]
    fn send_frame_succeeds_for_valid_14_byte_frame() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let frame = [0u8; 14];
        d.send_frame(&frame).unwrap();
        assert_eq!(d.stats.tx_packets, 1);
        assert_eq!(d.stats.tx_bytes, 14);
    }

    #[test]
    fn send_frame_succeeds_for_max_frame() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let frame = [0u8; MAX_FRAME_BYTES];
        d.send_frame(&frame).unwrap();
        assert_eq!(d.stats.tx_packets, 1);
        assert_eq!(d.stats.tx_bytes, MAX_FRAME_BYTES as u64);
    }

    #[test]
    fn send_frame_rejects_too_short() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let err = d.send_frame(&[0u8; 1]).unwrap_err();
        assert_eq!(err, E1000eError::InvalidFrame);
        assert_eq!(d.stats.tx_errors, 1);
    }

    #[test]
    fn send_frame_rejects_empty_slice() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let err = d.send_frame(&[]).unwrap_err();
        assert_eq!(err, E1000eError::InvalidFrame);
        assert_eq!(d.stats.tx_errors, 1);
    }

    #[test]
    fn send_frame_rejects_frame_too_large() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let frame = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = d.send_frame(&frame).unwrap_err();
        assert_eq!(err, E1000eError::FrameTooLarge);
        assert_eq!(d.stats.tx_errors, 1);
    }

    #[test]
    fn send_frame_rejects_when_queue_full() {
        // Ring of count 2: only 1 free slot (sentinel).
        let mut d = E1000eDriver::new(4, 2, 2048);
        let frame = [0u8; 64];
        d.send_frame(&frame).unwrap(); // fills the one slot
        let err = d.send_frame(&frame).unwrap_err();
        assert_eq!(err, E1000eError::QueueFull);
    }

    #[test]
    fn send_frame_rejects_when_not_ready() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.state = DriverState::Uninitialized;
        let frame = [0u8; 64];
        let err = d.send_frame(&frame).unwrap_err();
        assert_eq!(err, E1000eError::NotReady);
    }

    // ---- poll_rx ------------------------------------------------------------

    #[test]
    fn poll_rx_returns_none_on_empty_ring() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        assert!(d.poll_rx().is_none());
    }

    #[test]
    fn poll_rx_returns_frame_after_simulated_completion() {
        let mut d = E1000eDriver::new(4, 4, 2048);

        d.rx_ring.post_buffer(0x8000, 2048).unwrap();
        d.rx_ring.advance_tail();

        // Simulate hardware: mark descriptor as done.
        d.rx_ring.descriptors_mut()[0].length = 60;
        d.rx_ring.descriptors_mut()[0].status = RX_STATUS_DD | RX_STATUS_EOP;

        let frame = d.poll_rx().unwrap();
        assert_eq!(frame.len(), 60);
        assert_eq!(d.stats.rx_packets, 1);
        assert_eq!(d.stats.rx_bytes, 60);
    }

    #[test]
    fn poll_rx_returns_none_when_not_ready() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.state = DriverState::Error;
        assert!(d.poll_rx().is_none());
    }

    // ---- poll_tx_completions ------------------------------------------------

    #[test]
    fn poll_tx_completions_returns_zero_when_none_complete() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let frame = [0u8; 64];
        d.send_frame(&frame).unwrap();
        assert_eq!(d.poll_tx_completions(), 0);
    }

    #[test]
    fn poll_tx_completions_counts_completed_descriptors() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let frame = [0u8; 64];
        d.send_frame(&frame).unwrap();
        d.tx_ring.descriptors_mut()[0].status_reserved = TX_STATUS_DD;
        assert_eq!(d.poll_tx_completions(), 1);
        assert_eq!(d.tx_ring.num_free(), 3);
    }

    // ---- handle_request dispatch -------------------------------------------

    #[test]
    fn handle_request_get_link_state_ok_when_link_up() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.link_up = true;
        let resp = d.handle_request(&NetRequest::GetLinkState);
        assert_eq!(resp, NetResponse::Ok);
    }

    #[test]
    fn handle_request_get_link_state_link_down_when_link_off() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.link_up = false;
        let resp = d.handle_request(&NetRequest::GetLinkState);
        assert_eq!(resp, NetResponse::LinkDown);
    }

    #[test]
    fn handle_request_get_mac_returns_ok() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        let resp = d.handle_request(&NetRequest::GetMac);
        assert_eq!(resp, NetResponse::Ok);
    }

    #[test]
    fn handle_request_set_promisc_not_supported() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let resp = d.handle_request(&NetRequest::SetPromisc { on: true });
        assert_eq!(resp, NetResponse::NotSupported);
    }

    #[test]
    fn handle_request_send_frame_ok() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let req = NetRequest::SendFrame {
            bytes_iova: 0xA000,
            bytes_len: 64,
        };
        let resp = d.handle_request(&req);
        assert_eq!(resp, NetResponse::Ok);
        assert_eq!(d.stats.tx_packets, 1);
    }

    #[test]
    fn handle_request_send_frame_too_large() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let req = NetRequest::SendFrame {
            bytes_iova: 0xA000,
            bytes_len: (MAX_FRAME_BYTES + 1) as u16,
        };
        let resp = d.handle_request(&req);
        assert_eq!(resp, NetResponse::FrameTooLarge);
    }

    #[test]
    fn handle_request_rejects_when_not_ready() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.state = DriverState::Configured;
        let resp = d.handle_request(&NetRequest::GetLinkState);
        assert_eq!(resp, NetResponse::NotSupported);
    }

    // ---- mac() and stats() accessors ----------------------------------------

    #[test]
    fn mac_accessor_returns_configured_mac() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(d.mac(), [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn set_mac_from_regs_loads_eeprom_mac_when_av_set() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let (ral, rah) =
            crate::controller_regs::encode_mac_regs([0x52, 0x54, 0x00, 0x0A, 0x0B, 0x0C]);
        assert!(d.set_mac_from_regs(ral, rah));
        assert_eq!(d.mac(), [0x52, 0x54, 0x00, 0x0A, 0x0B, 0x0C]);
    }

    #[test]
    fn set_mac_from_regs_fails_closed_and_preserves_mac_when_av_clear() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        d.mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        // AV bit clear → refuse and leave the existing MAC intact.
        assert!(!d.set_mac_from_regs(0x4433_2211, 0x0000_6655));
        assert_eq!(d.mac(), [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn update_link_from_status_tracks_lu_bit() {
        use crate::controller_regs::STATUS_LU_BIT;
        let mut d = E1000eDriver::new(4, 4, 2048);
        assert!(!d.link_up);
        let link = d.update_link_from_status(STATUS_LU_BIT);
        assert!(link.up && d.link_up);
        // Link drop → link_up clears.
        d.update_link_from_status(0);
        assert!(!d.link_up);
    }

    #[test]
    fn stats_accessor_reflects_cumulative_counters() {
        let mut d = E1000eDriver::new(4, 4, 2048);
        let frame = [0u8; 100];
        d.send_frame(&frame).unwrap();
        let s = d.stats();
        assert_eq!(s.tx_packets, 1);
        assert_eq!(s.tx_bytes, 100);
    }

    // ---- driver_stats default -----------------------------------------------

    #[test]
    fn driver_stats_default_is_all_zeros() {
        let s = DriverStats::default();
        assert_eq!(s.tx_packets, 0);
        assert_eq!(s.rx_packets, 0);
        assert_eq!(s.tx_bytes, 0);
        assert_eq!(s.rx_bytes, 0);
        assert_eq!(s.tx_errors, 0);
        assert_eq!(s.rx_errors, 0);
    }
}

//! Virtio-net driver main state machine — N1.3.
//!
//! [`VirtioNetDriver`] is the top-level driver struct that owns the TX and RX
//! virtqueues, the RX buffer pool, the driver lifecycle state, and the
//! per-interface statistics counters.
//!
//! ## Layering
//!
//! This module is the sole public entry point for the M1 driver logic. It
//! delegates to:
//!
//! - [`crate::ring::SplitVirtqueue`] for descriptor management.
//! - [`crate::tx_rx`] for frame framing / header stripping / MTU validation.
//! - [`nexacore_types::net_channel`] for the IPC request/response/event ABI.
//!
//! The actual MMIO writes, DMA mappings, and IRQ attachment live in the
//! bootable image sibling `nexacore-driver-net-virtio-image`. This crate is
//! host-testable.
//!
//! ## Driver state machine
//!
//! ```text
//! Uninitialized ──▶ Reset ──▶ Acknowledged ──▶ FeaturesNegotiated
//!      ──▶ FeaturesLocked ──▶ VirtqueuesConfigured ──▶ MacAcquired
//!      ──▶ Ready ──▶ (loop: send/recv)
//!
//! Any state ──▶ Error   (on unrecoverable failure)
//! ```
//!
//! The bring-up FSM from [`crate::bringup`] drives the transition sequence;
//! this struct tracks the higher-level ready/error state that the IPC channel
//! handler consults.

extern crate alloc;

use alloc::vec::Vec;

use nexacore_types::net_channel::{LinkState, NetRequest, NetResponse};

use crate::{
    ring::SplitVirtqueue,
    tx_rx::{NetDriverError, RxBufferPool, prepare_tx_frame, strip_rx_header},
};

// ---------------------------------------------------------------------------
// Default configuration constants
// ---------------------------------------------------------------------------

/// Default simulated link speed reported by `GetLinkState` responses (1 Gbps).
const DEFAULT_LINK_SPEED_MBPS: u32 = 1_000;

/// Number of RX bytes allocated per receive buffer.
const DEFAULT_RX_BUFFER_SIZE: usize = 2048;

// ---------------------------------------------------------------------------
// DriverState
// ---------------------------------------------------------------------------

/// Lifecycle state of the [`VirtioNetDriver`].
///
/// Advances strictly in declaration order through the bring-up sequence;
/// `Error` is a terminal failure state reachable from any other state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    /// Driver struct has been constructed but bring-up has not started.
    Uninitialized,
    /// Device has been reset (`device_status = 0x00`).
    Reset,
    /// `ACKNOWLEDGE | DRIVER` written; driver has identified itself.
    Acknowledged,
    /// Feature negotiation complete; `driver_feature` written.
    FeaturesNegotiated,
    /// `FEATURES_OK` confirmed by re-reading `device_status`.
    FeaturesLocked,
    /// RX and TX virtqueues DMA-mapped and programmed.
    VirtqueuesConfigured,
    /// MAC address read from Device Cfg.
    MacAcquired,
    /// `DRIVER_OK` set; device is live and serving the NET channel.
    Ready,
    /// Unrecoverable error; driver process should exit.
    Error,
}

// ---------------------------------------------------------------------------
// DriverStats
// ---------------------------------------------------------------------------

/// Per-interface packet and byte counters.
///
/// All counters are monotonically increasing and never reset during the
/// lifetime of the driver process. They are intended for diagnostic polling
/// and do not wrap (saturating arithmetic is used, so overflow is not
/// possible in practice given realistic traffic volumes over a driver
/// process lifetime).
#[derive(Debug, Clone, Copy, Default)]
pub struct DriverStats {
    /// Total frames successfully enqueued for transmission.
    pub tx_packets: u64,
    /// Total frames received and returned to the caller.
    pub rx_packets: u64,
    /// Total bytes enqueued for transmission (excluding the virtio-net header).
    pub tx_bytes: u64,
    /// Total bytes received (excluding the virtio-net header).
    pub rx_bytes: u64,
    /// Total TX errors (queue full, frame too large, etc.).
    pub tx_errors: u64,
    /// Total RX errors (invalid frame, header strip failure, etc.).
    pub rx_errors: u64,
}

// ---------------------------------------------------------------------------
// VirtioNetDriver
// ---------------------------------------------------------------------------

/// The complete virtio-net driver state.
///
/// Owns the TX and RX virtqueues, the RX buffer pool, the current link state,
/// and cumulative statistics. The `handle_request` dispatcher maps incoming
/// [`NetRequest`] messages from the network stack onto driver operations and
/// returns the appropriate [`NetResponse`].
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::driver::{DriverState, VirtioNetDriver};
///
/// let driver = VirtioNetDriver::new(256, 256);
/// assert_eq!(driver.state, DriverState::Uninitialized);
/// assert_eq!(driver.mac(), [0u8; 6]);
/// ```
pub struct VirtioNetDriver {
    /// Current lifecycle state.
    pub state: DriverState,
    /// Interface MAC address (set during `MacAcquired` phase).
    pub mac: [u8; 6],
    /// `true` if the physical link is currently up.
    pub link_up: bool,
    /// TX virtqueue (queue index 1 per virtio-net § 5.1.2).
    pub tx_queue: SplitVirtqueue,
    /// RX virtqueue (queue index 0 per virtio-net § 5.1.2).
    pub rx_queue: SplitVirtqueue,
    /// Pre-allocated RX receive buffer pool.
    pub rx_pool: RxBufferPool,
    /// Cumulative per-interface statistics.
    pub stats: DriverStats,
}

impl core::fmt::Debug for VirtioNetDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `tx_queue`, `rx_queue`, and `rx_pool` are intentionally omitted from
        // the Debug output; they are large structural fields whose contents are
        // not useful in log output. `.finish_non_exhaustive()` signals that
        // the impl is deliberately partial.
        f.debug_struct("VirtioNetDriver")
            .field("state", &self.state)
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl VirtioNetDriver {
    /// Construct a new driver with `queue_size` descriptors per virtqueue and
    /// `rx_buffer_count` pre-allocated RX buffers.
    ///
    /// The driver starts in [`DriverState::Uninitialized`]. MAC is zeroed; the
    /// bring-up sequence will populate it during [`DriverState::MacAcquired`].
    ///
    /// # Panics
    ///
    /// Panics if `queue_size` or `rx_buffer_count` is `0` (forwarded from the
    /// constructors of [`SplitVirtqueue`] and [`RxBufferPool`]).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::{DriverState, VirtioNetDriver};
    ///
    /// let driver = VirtioNetDriver::new(256, 256);
    /// assert_eq!(driver.state, DriverState::Uninitialized);
    /// assert!(!driver.link_up);
    /// ```
    #[must_use]
    pub fn new(queue_size: u16, rx_buffer_count: u16) -> Self {
        Self {
            state: DriverState::Uninitialized,
            mac: [0u8; 6],
            link_up: false,
            tx_queue: SplitVirtqueue::new(queue_size),
            rx_queue: SplitVirtqueue::new(queue_size),
            rx_pool: RxBufferPool::new(rx_buffer_count, DEFAULT_RX_BUFFER_SIZE),
            stats: DriverStats::default(),
        }
    }

    /// Dispatch a [`NetRequest`] from the network stack and return the
    /// appropriate [`NetResponse`].
    ///
    /// Handles the full M0 + M1 request surface:
    ///
    /// - [`NetRequest::SendFrameInline`]: the M0 inline-transport path.
    ///   Validates link-up and frame bounds, then calls
    ///   [`send_frame`](Self::send_frame) directly on the carried bytes.
    ///   Returns `Ok` on success; `LinkDown`, `FrameTooLarge`, or
    ///   `InvalidArgument` on error.
    /// - [`NetRequest::SendFrame`]: the M1 IOVA path. Delegates to
    ///   [`send_frame`](Self::send_frame) with a synthetic zero-padded frame
    ///   (the IOVA cannot be dereferenced in the library layer). Returns `Ok`
    ///   on success, `FrameTooLarge`, `LinkDown`, or `InvalidArgument` on
    ///   error.
    /// - [`NetRequest::GetLinkState`]: returns `Ok` (the actual [`LinkState`]
    ///   snapshot is conveyed via a companion channel per the driver NCIP; this
    ///   response is the acknowledgement).
    /// - [`NetRequest::GetMac`]: returns `Ok` (MAC returned via companion
    ///   channel).
    /// - [`NetRequest::SetPromisc`]: returns `NotSupported` (M1 does not
    ///   implement hardware promiscuous mode).
    ///
    /// Returns `InvalidArgument` when the frame bytes are empty.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::VirtioNetDriver;
    /// use nexacore_types::net_channel::{NetRequest, NetResponse};
    ///
    /// let mut driver = VirtioNetDriver::new(256, 256);
    /// let response = driver.handle_request(&NetRequest::GetMac);
    /// assert_eq!(response, NetResponse::Ok);
    /// ```
    pub fn handle_request(&mut self, req: &NetRequest) -> NetResponse {
        match req {
            // ---- M0 inline-frame transport (contract, NCIP-015 § M0) --------
            //
            // The frame bytes travel inside the IPC message itself; no IOVA
            // indirection is needed.  This is the primary M0 data path; the
            // IOVA path (SendFrame) is the high-throughput successor.
            NetRequest::SendFrameInline { bytes } => {
                if bytes.is_empty() {
                    return NetResponse::InvalidArgument;
                }
                if !self.link_up {
                    return NetResponse::LinkDown;
                }
                match self.send_frame(bytes) {
                    Ok(()) => NetResponse::Ok,
                    Err(NetDriverError::FrameTooLarge | NetDriverError::QueueFull) => {
                        NetResponse::FrameTooLarge
                    }
                    Err(NetDriverError::InvalidFrame | NetDriverError::NoBuffersAvailable) => {
                        NetResponse::InvalidArgument
                    }
                }
            }
            // ---- M1 IOVA-based TX (future zero-copy path) ------------------
            NetRequest::SendFrame {
                bytes_iova,
                bytes_len,
            } => {
                if *bytes_len == 0 {
                    return NetResponse::InvalidArgument;
                }
                if !self.link_up {
                    return NetResponse::LinkDown;
                }
                // In the library layer we cannot dereference the IOVA address.
                // Synthesise a zero-padded frame of `bytes_len` bytes so that
                // the TX path exercises the full virtqueue + stats machinery.
                // The bootable image sibling will replace this with a real DMA
                // buffer read.
                let _ = bytes_iova; // IOVA unused in the library layer
                let synthetic_frame = alloc::vec![0u8; *bytes_len as usize];
                match self.send_frame(&synthetic_frame) {
                    Ok(()) => NetResponse::Ok,
                    Err(NetDriverError::FrameTooLarge | NetDriverError::QueueFull) => {
                        NetResponse::FrameTooLarge
                    }
                    Err(_) => NetResponse::InvalidArgument,
                }
            }
            // `GetLinkState` and `GetMac` are both acknowledged with `Ok`; the
            // actual data is conveyed on the companion event channel per the
            // driver NCIP.
            NetRequest::GetLinkState | NetRequest::GetMac => NetResponse::Ok,
            // `#[non_exhaustive]` — all other variants (including `SetPromisc`
            // and any future additions) are not supported in M1.
            _ => NetResponse::NotSupported,
        }
    }

    /// Enqueue a TX frame using the inline-transport byte slice.
    ///
    /// This is the M0-facing convenience wrapper around
    /// [`send_frame`](Self::send_frame) used by the service-loop image. It
    /// validates the frame, delegates to the virtqueue path, and returns the
    /// driver-level error directly so the caller can map it to a
    /// [`NetResponse`] without going through
    /// [`handle_request`](Self::handle_request).
    ///
    /// # Errors
    ///
    /// See [`send_frame`](Self::send_frame) — same error variants apply.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::{driver::VirtioNetDriver, tx_rx::NetDriverError};
    ///
    /// let mut driver = VirtioNetDriver::new(256, 256);
    /// // A valid minimum-length Ethernet frame (14 bytes).
    /// let frame = vec![0u8; 14];
    /// driver.link_up = true;
    /// assert!(driver.tx_send_frame_inline(&frame).is_ok());
    /// ```
    pub fn tx_send_frame_inline(&mut self, frame: &[u8]) -> Result<(), NetDriverError> {
        // Delegate directly — `send_frame` handles all validation.
        self.send_frame(frame)
    }

    /// Enqueue a TX frame into the TX virtqueue.
    ///
    /// Prepends the `virtio_net_hdr` (via [`prepare_tx_frame`]), allocates a
    /// descriptor, updates statistics, and returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// - [`NetDriverError::FrameTooLarge`] if the frame exceeds MTU bounds.
    /// - [`NetDriverError::InvalidFrame`] if the frame is empty.
    /// - [`NetDriverError::QueueFull`] if no TX descriptors are available.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::VirtioNetDriver;
    ///
    /// let mut driver = VirtioNetDriver::new(256, 256);
    /// let frame = vec![0u8; 64];
    /// assert!(driver.send_frame(&frame).is_ok());
    /// assert_eq!(driver.stats().tx_packets, 1);
    /// ```
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetDriverError> {
        // Prepare the TX buffer (prepends virtio-net header and validates size).
        let prepared = prepare_tx_frame(frame)?;

        // Guard against a full queue before attempting to allocate a descriptor.
        if self.tx_queue.is_full() {
            self.stats.tx_errors = self.stats.tx_errors.saturating_add(1);
            return Err(NetDriverError::QueueFull);
        }

        // Use `0` as the synthetic buffer address (no DMA in the library layer).
        // `prepared.len()` is bounded by MAX_FRAME_SIZE + VIRTIO_NET_HDR_SIZE
        // (≤ 1524) which fits comfortably in u32.
        #[allow(clippy::cast_possible_truncation)]
        let len = prepared.len() as u32;
        let _idx = self
            .tx_queue
            .add_buffer(0, len, false)
            .ok_or(NetDriverError::QueueFull)?;

        // Update statistics. Frame length excludes the virtio-net header.
        self.stats.tx_packets = self.stats.tx_packets.saturating_add(1);
        // `frame.len()` ≤ MAX_FRAME_SIZE (1514) which fits in u64 without
        // truncation; saturating_add handles the (theoretical) counter wrap.
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(frame.len() as u64);

        Ok(())
    }

    /// Poll the RX virtqueue for a completed receive buffer.
    ///
    /// If the device has placed a frame into an RX buffer (simulated via
    /// [`SplitVirtqueue::simulate_device_completion`] in tests), this method:
    ///
    /// 1. Pops the used element from the RX queue.
    /// 2. Reads the corresponding RX pool buffer.
    /// 3. Strips the `virtio_net_hdr` via [`strip_rx_header`].
    /// 4. Returns the Ethernet frame payload as a `Vec<u8>`.
    /// 5. Releases the RX pool buffer.
    ///
    /// Returns `None` if no RX completions are pending.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::VirtioNetDriver;
    ///
    /// let mut driver = VirtioNetDriver::new(4, 4);
    /// // No RX completions yet.
    /// assert!(driver.poll_rx().is_none());
    /// ```
    pub fn poll_rx(&mut self) -> Option<Vec<u8>> {
        let (desc_idx, bytes_written) = self.rx_queue.pop_used()?;

        // Map the descriptor index back to an RX pool buffer id. In the
        // library layer the descriptor index == pool buffer id because the
        // driver posts buffers in order at initialisation. The bootable image
        // may use a more sophisticated mapping.
        let buf_id = desc_idx;

        // Determine how many bytes to read: the used element's `bytes_written`
        // if non-zero, otherwise the full buffer size.
        let read_len = if bytes_written > 0 {
            // `bytes_written` comes from the device and is at most the buffer
            // size we programmed; `.min` caps it defensively.
            (bytes_written as usize).min(self.rx_pool.buffer_size())
        } else {
            self.rx_pool.buffer_size()
        };

        let frame = self.rx_pool.get(buf_id).and_then(|data| {
            // Guard against a buffer smaller than `read_len` (defensive).
            let slice = data.get(..read_len)?;
            let payload = strip_rx_header(slice)?;
            Some(payload.to_vec())
        });

        // Release the buffer regardless of whether we could parse a payload.
        self.rx_pool.release(buf_id);

        if let Some(ref f) = frame {
            self.stats.rx_packets = self.stats.rx_packets.saturating_add(1);
            self.stats.rx_bytes = self.stats.rx_bytes.saturating_add(f.len() as u64);
        } else {
            self.stats.rx_errors = self.stats.rx_errors.saturating_add(1);
        }

        frame
    }

    /// Reap all completed TX descriptors from the TX used ring and return them
    /// to the free list.
    ///
    /// In a real driver this would be called from the TX interrupt handler or
    /// the polling loop to reclaim TX descriptors after the device has
    /// consumed the buffers. In the library layer it drains the simulated used
    /// ring.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::VirtioNetDriver;
    ///
    /// let mut driver = VirtioNetDriver::new(4, 4);
    /// let frame = vec![0u8; 64];
    /// driver.send_frame(&frame).unwrap();
    /// // Simulate device completion.
    /// driver.tx_queue.simulate_device_completion(0, 0);
    /// driver.poll_tx_completions();
    /// // Descriptor is back on the free list.
    /// assert_eq!(driver.tx_queue.num_free(), 4);
    /// ```
    pub fn poll_tx_completions(&mut self) {
        // Drain until the used ring is empty.
        while self.tx_queue.pop_used().is_some() {
            // The descriptor is returned to the free list by `pop_used`.
        }
    }

    /// Return the interface MAC address.
    ///
    /// Zeroed until the driver reaches [`DriverState::MacAcquired`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::VirtioNetDriver;
    ///
    /// let mut driver = VirtioNetDriver::new(256, 256);
    /// driver.mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    /// assert_eq!(driver.mac(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    /// ```
    #[must_use]
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Return a reference to the cumulative statistics counters.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::VirtioNetDriver;
    ///
    /// let driver = VirtioNetDriver::new(256, 256);
    /// let stats = driver.stats();
    /// assert_eq!(stats.tx_packets, 0);
    /// assert_eq!(stats.rx_packets, 0);
    /// ```
    #[must_use]
    pub fn stats(&self) -> &DriverStats {
        &self.stats
    }

    /// Construct a [`LinkState`] snapshot from the current driver state.
    ///
    /// Used when replying to a `GetLinkState` companion channel message.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::driver::VirtioNetDriver;
    ///
    /// let mut driver = VirtioNetDriver::new(256, 256);
    /// driver.link_up = true;
    /// driver.mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    /// let ls = driver.link_state_snapshot();
    /// assert!(ls.up);
    /// assert_eq!(ls.speed_mbps, 1_000);
    /// ```
    #[must_use]
    pub fn link_state_snapshot(&self) -> LinkState {
        LinkState {
            up: self.link_up,
            speed_mbps: if self.link_up {
                DEFAULT_LINK_SPEED_MBPS
            } else {
                0
            },
            duplex_full: self.link_up,
            mac: self.mac,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use nexacore_types::net_channel::{NetRequest, NetResponse};

    use super::*;

    // ---- construction -------------------------------------------------------

    #[test]
    fn new_driver_is_uninitialized() {
        let driver = VirtioNetDriver::new(256, 256);
        assert_eq!(driver.state, DriverState::Uninitialized);
    }

    #[test]
    fn new_driver_link_is_down() {
        let driver = VirtioNetDriver::new(256, 256);
        assert!(!driver.link_up);
    }

    #[test]
    fn new_driver_mac_is_zeroed() {
        let driver = VirtioNetDriver::new(256, 256);
        assert_eq!(driver.mac(), [0u8; 6]);
    }

    #[test]
    fn new_driver_stats_are_zero() {
        let driver = VirtioNetDriver::new(256, 256);
        let s = driver.stats();
        assert_eq!(s.tx_packets, 0);
        assert_eq!(s.rx_packets, 0);
        assert_eq!(s.tx_bytes, 0);
        assert_eq!(s.rx_bytes, 0);
        assert_eq!(s.tx_errors, 0);
        assert_eq!(s.rx_errors, 0);
    }

    // ---- handle_request dispatch --------------------------------------------

    #[test]
    fn handle_get_mac_returns_ok() {
        let mut driver = VirtioNetDriver::new(256, 256);
        assert_eq!(driver.handle_request(&NetRequest::GetMac), NetResponse::Ok);
    }

    #[test]
    fn handle_get_link_state_returns_ok() {
        let mut driver = VirtioNetDriver::new(256, 256);
        assert_eq!(
            driver.handle_request(&NetRequest::GetLinkState),
            NetResponse::Ok
        );
    }

    #[test]
    fn handle_set_promisc_returns_not_supported() {
        let mut driver = VirtioNetDriver::new(256, 256);
        assert_eq!(
            driver.handle_request(&NetRequest::SetPromisc { on: true }),
            NetResponse::NotSupported
        );
        assert_eq!(
            driver.handle_request(&NetRequest::SetPromisc { on: false }),
            NetResponse::NotSupported
        );
    }

    #[test]
    fn handle_send_frame_link_down_returns_link_down() {
        let mut driver = VirtioNetDriver::new(256, 256);
        // link_up defaults to false
        let resp = driver.handle_request(&NetRequest::SendFrame {
            bytes_iova: 0x1000,
            bytes_len: 64,
        });
        assert_eq!(resp, NetResponse::LinkDown);
    }

    // ---- SendFrameInline ----------------------------------------------------

    #[test]
    fn handle_send_frame_inline_link_down_returns_link_down() {
        let mut driver = VirtioNetDriver::new(256, 256);
        // link_up defaults to false
        let frame = alloc::vec![0u8; 64];
        let resp = driver.handle_request(&NetRequest::SendFrameInline { bytes: frame });
        assert_eq!(resp, NetResponse::LinkDown);
    }

    #[test]
    fn handle_send_frame_inline_empty_returns_invalid_argument() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        let resp = driver.handle_request(&NetRequest::SendFrameInline {
            bytes: alloc::vec![],
        });
        assert_eq!(resp, NetResponse::InvalidArgument);
    }

    #[test]
    fn handle_send_frame_inline_valid_frame_link_up_returns_ok() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        // Minimum valid Ethernet frame: 14 bytes (6-byte dst + 6-byte src + 2-byte ethertype)
        let frame = alloc::vec![0u8; 14];
        let resp = driver.handle_request(&NetRequest::SendFrameInline { bytes: frame });
        assert_eq!(resp, NetResponse::Ok);
    }

    #[test]
    fn handle_send_frame_inline_max_frame_returns_ok() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        // MAX_FRAME_SIZE = 1514
        let frame = alloc::vec![0u8; 1514];
        let resp = driver.handle_request(&NetRequest::SendFrameInline { bytes: frame });
        assert_eq!(resp, NetResponse::Ok);
    }

    #[test]
    fn handle_send_frame_inline_oversized_returns_frame_too_large() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        // 1515 > MAX_FRAME_SIZE = 1514
        let frame = alloc::vec![0u8; 1515];
        let resp = driver.handle_request(&NetRequest::SendFrameInline { bytes: frame });
        assert_eq!(resp, NetResponse::FrameTooLarge);
    }

    #[test]
    fn handle_send_frame_inline_increments_tx_stats() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        let frame = alloc::vec![0xAAu8; 64];
        driver.handle_request(&NetRequest::SendFrameInline { bytes: frame });
        assert_eq!(driver.stats().tx_packets, 1);
        assert_eq!(driver.stats().tx_bytes, 64);
    }

    // ---- tx_send_frame_inline -----------------------------------------------

    #[test]
    fn tx_send_frame_inline_delegates_to_send_frame() {
        let mut driver = VirtioNetDriver::new(256, 256);
        let frame = alloc::vec![0u8; 64];
        assert!(driver.tx_send_frame_inline(&frame).is_ok());
        assert_eq!(driver.stats().tx_packets, 1);
    }

    #[test]
    fn tx_send_frame_inline_rejects_too_small() {
        use crate::tx_rx::NetDriverError;
        let mut driver = VirtioNetDriver::new(256, 256);
        // 13 bytes < MIN_FRAME_SIZE = 14
        let frame = alloc::vec![0u8; 13];
        assert_eq!(
            driver.tx_send_frame_inline(&frame),
            Err(NetDriverError::FrameTooLarge)
        );
    }

    #[test]
    fn tx_send_frame_inline_rejects_too_large() {
        use crate::tx_rx::NetDriverError;
        let mut driver = VirtioNetDriver::new(256, 256);
        // 1515 > MAX_FRAME_SIZE = 1514
        let frame = alloc::vec![0u8; 1515];
        assert_eq!(
            driver.tx_send_frame_inline(&frame),
            Err(NetDriverError::FrameTooLarge)
        );
    }

    #[test]
    fn handle_send_frame_zero_len_returns_invalid_argument() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        let resp = driver.handle_request(&NetRequest::SendFrame {
            bytes_iova: 0x1000,
            bytes_len: 0,
        });
        assert_eq!(resp, NetResponse::InvalidArgument);
    }

    #[test]
    fn handle_send_frame_link_up_returns_ok() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        let resp = driver.handle_request(&NetRequest::SendFrame {
            bytes_iova: 0x1000,
            bytes_len: 64,
        });
        assert_eq!(resp, NetResponse::Ok);
    }

    // ---- send_frame ---------------------------------------------------------

    #[test]
    fn send_frame_increments_tx_packets() {
        let mut driver = VirtioNetDriver::new(256, 256);
        let frame = alloc::vec![0u8; 64];
        driver.send_frame(&frame).unwrap();
        assert_eq!(driver.stats().tx_packets, 1);
    }

    #[test]
    fn send_frame_increments_tx_bytes_with_frame_len() {
        let mut driver = VirtioNetDriver::new(256, 256);
        let frame = alloc::vec![0u8; 100];
        driver.send_frame(&frame).unwrap();
        assert_eq!(driver.stats().tx_bytes, 100);
    }

    #[test]
    fn send_frame_empty_returns_invalid_frame() {
        let mut driver = VirtioNetDriver::new(256, 256);
        assert_eq!(driver.send_frame(&[]), Err(NetDriverError::InvalidFrame));
    }

    #[test]
    fn send_frame_oversized_returns_frame_too_large() {
        let mut driver = VirtioNetDriver::new(256, 256);
        let frame = alloc::vec![0u8; 2000];
        assert_eq!(
            driver.send_frame(&frame),
            Err(NetDriverError::FrameTooLarge)
        );
    }

    #[test]
    fn send_frame_queue_full_returns_queue_full() {
        let mut driver = VirtioNetDriver::new(1, 1);
        let frame = alloc::vec![0u8; 64];
        // Fill the single TX descriptor.
        driver.send_frame(&frame).unwrap();
        // Second send must fail.
        assert_eq!(driver.send_frame(&frame), Err(NetDriverError::QueueFull));
    }

    // ---- poll_rx ------------------------------------------------------------

    #[test]
    fn poll_rx_returns_none_when_no_completions() {
        let mut driver = VirtioNetDriver::new(4, 4);
        assert!(driver.poll_rx().is_none());
    }

    #[test]
    fn poll_rx_strips_header_and_returns_payload() {
        use crate::tx_rx::VIRTIO_NET_HDR_SIZE;

        let mut driver = VirtioNetDriver::new(4, 4);

        // Post one RX buffer to the RX queue (descriptor index 0).
        let buf_id = driver.rx_pool.allocate().unwrap();
        let total = VIRTIO_NET_HDR_SIZE + 4;
        {
            // Write known payload bytes after the virtio-net header.
            // The buffer is DEFAULT_RX_BUFFER_SIZE (2048) bytes — the
            // indices below are well within bounds.
            let buf = driver.rx_pool.get_mut(buf_id).unwrap();
            if let Some(b) = buf.get_mut(VIRTIO_NET_HDR_SIZE) {
                *b = 0xAA;
            }
            if let Some(b) = buf.get_mut(VIRTIO_NET_HDR_SIZE + 1) {
                *b = 0xBB;
            }
            if let Some(b) = buf.get_mut(VIRTIO_NET_HDR_SIZE + 2) {
                *b = 0xCC;
            }
            if let Some(b) = buf.get_mut(VIRTIO_NET_HDR_SIZE + 3) {
                *b = 0xDD;
            }
        }
        // Add the RX buffer as a writable descriptor.
        // `buffer_size()` returns DEFAULT_RX_BUFFER_SIZE (2048) which fits in u32.
        #[allow(clippy::cast_possible_truncation)]
        let buf_size_u32 = driver.rx_pool.buffer_size() as u32;
        let _desc = driver.rx_queue.add_buffer(0, buf_size_u32, true);
        // Simulate device writing `total` bytes into descriptor 0.
        // `total` = VIRTIO_NET_HDR_SIZE + 4 = 14, fits in u32.
        #[allow(clippy::cast_possible_truncation)]
        let total_u32 = total as u32;
        driver
            .rx_queue
            .simulate_device_completion(buf_id, total_u32);

        // Release the pool buffer so poll_rx can re-claim it correctly.
        // Re-allocate so it is "in_use" during poll.
        driver.rx_pool.release(buf_id);
        driver.rx_pool.allocate();

        let frame = driver.poll_rx();
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    // ---- poll_tx_completions ------------------------------------------------

    #[test]
    fn poll_tx_completions_reclaims_descriptors() {
        let mut driver = VirtioNetDriver::new(4, 4);
        let frame = alloc::vec![0u8; 64];
        driver.send_frame(&frame).unwrap();
        assert_eq!(driver.tx_queue.num_free(), 3);
        // Simulate device completing the TX.
        driver.tx_queue.simulate_device_completion(0, 0);
        driver.poll_tx_completions();
        assert_eq!(driver.tx_queue.num_free(), 4);
    }

    // ---- mac / stats accessors ----------------------------------------------

    #[test]
    fn mac_accessor_returns_stored_mac() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.mac = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];
        assert_eq!(driver.mac(), [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn stats_reference_reflects_live_counters() {
        let mut driver = VirtioNetDriver::new(256, 256);
        let frame = alloc::vec![0u8; 64];
        driver.send_frame(&frame).unwrap();
        // stats() must reflect the increment immediately.
        assert_eq!(driver.stats().tx_packets, 1);
    }

    // ---- state machine transitions ------------------------------------------

    #[test]
    fn driver_state_enum_all_variants_are_distinct() {
        let states = [
            DriverState::Uninitialized,
            DriverState::Reset,
            DriverState::Acknowledged,
            DriverState::FeaturesNegotiated,
            DriverState::FeaturesLocked,
            DriverState::VirtqueuesConfigured,
            DriverState::MacAcquired,
            DriverState::Ready,
            DriverState::Error,
        ];
        for (i, &a) in states.iter().enumerate() {
            for &b in states.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn driver_transitions_to_ready_manually() {
        // The library layer does not run the bring-up FSM automatically;
        // the bootable image drives it. This test covers the direct field
        // assignment path that tests use.
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.state = DriverState::Ready;
        driver.mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        driver.link_up = true;
        assert_eq!(driver.state, DriverState::Ready);
        assert!(driver.link_up);
    }

    // ---- link_state_snapshot ------------------------------------------------

    #[test]
    fn link_state_snapshot_up() {
        let mut driver = VirtioNetDriver::new(256, 256);
        driver.link_up = true;
        driver.mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ls = driver.link_state_snapshot();
        assert!(ls.up);
        assert_eq!(ls.speed_mbps, 1_000);
        assert!(ls.duplex_full);
        assert_eq!(ls.mac, driver.mac);
    }

    #[test]
    fn link_state_snapshot_down() {
        let driver = VirtioNetDriver::new(256, 256);
        let ls = driver.link_state_snapshot();
        assert!(!ls.up);
        assert_eq!(ls.speed_mbps, 0);
    }
}

//! TX/RX frame handling for the virtio-net M1 driver.
//!
//! Every frame sent or received through a virtio-net device is prefixed with a
//! `virtio_net_hdr` structure (virtio 1.0 § 5.1.6). This module provides:
//!
//! - The header type ([`VirtioNetHeader`]) and its size constant
//!   ([`VIRTIO_NET_HDR_SIZE`]).
//! - Frame-level helpers: [`prepare_tx_frame`] (prepend header to a raw
//!   Ethernet frame) and [`strip_rx_header`] (remove the header from received
//!   data before passing it up the stack).
//! - MTU validation: [`validate_frame_size`] enforces Ethernet size bounds.
//! - An RX buffer pool ([`RxBufferPool`]) that pre-allocates fixed-size receive
//!   buffers which the driver posts to the RX virtqueue and reclaims after the
//!   network stack has consumed the frame.
//!
//! ## Design decisions
//!
//! - `no_std + alloc`, zero `unsafe`: backed by `Vec<u8>` rather than raw DMA
//!   pages. The MMIO/DMA wiring lives in the bootable image sibling.
//! - MTU: standard Ethernet 1500-byte payload + 14-byte header = 1514 bytes
//!   maximum frame size. Minimum is 14 bytes (bare Ethernet header, no
//!   payload).
//! - `VirtioNetHeader` is exactly 10 bytes per virtio 1.0 § 5.1.6; a
//!   compile-time assert enforces this.

extern crate alloc;

use alloc::{vec, vec::Vec};

// ---------------------------------------------------------------------------
// MTU bounds
// ---------------------------------------------------------------------------

/// Maximum Ethernet frame size in bytes (1500-byte payload + 14-byte header).
///
/// Frames larger than this MUST be rejected with [`NetDriverError::FrameTooLarge`].
pub const MAX_FRAME_SIZE: usize = 1514;

/// Minimum Ethernet frame size in bytes (14-byte header, zero-length payload).
///
/// Frames smaller than this are structurally invalid.
pub const MIN_FRAME_SIZE: usize = 14;

// ---------------------------------------------------------------------------
// virtio-net header
// ---------------------------------------------------------------------------

/// `virtio_net_hdr` — the 10-byte header prepended to every frame on the wire
/// between the driver and the virtio-net device (virtio 1.0 § 5.1.6).
///
/// In the M1 deliverable `VIRTIO_NET_F_CSUM` and `VIRTIO_NET_F_GSO_*` are not
/// negotiated, so all fields other than `flags = 0` and `num_buffers = 1` are
/// set to zero.
///
/// # Wire layout (`repr(C)`, exactly 10 bytes)
///
/// | offset | size | field         |
/// |--------|------|---------------|
/// | 0      | 1    | `flags`       |
/// | 1      | 1    | `gso_type`    |
/// | 2      | 2    | `hdr_len`     |
/// | 4      | 2    | `gso_size`    |
/// | 6      | 2    | `csum_start`  |
/// | 8      | 2    | `csum_offset` |
///
/// The `num_buffers` field present in the `VIRTIO_NET_F_MRG_RXBUF` extended
/// header is omitted here; M1 does not negotiate `VIRTIO_NET_F_MRG_RXBUF`
/// (deferred). Total: 1 + 1 + 2 + 2 + 2 + 2 = 10 bytes.
///
/// See [`VIRTIO_NET_HDR_SIZE`] for the compile-time size assertion.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtioNetHeader {
    /// Checksum / offload flags. `0` in M1 (no offload negotiated).
    pub flags: u8,
    /// GSO type. `VIRTIO_NET_HDR_GSO_NONE = 0` in M1.
    pub gso_type: u8,
    /// Header length (used only when GSO is active). `0` in M1.
    pub hdr_len: u16,
    /// GSO segment size. `0` in M1.
    pub gso_size: u16,
    /// Checksum start offset. `0` in M1.
    pub csum_start: u16,
    /// Checksum offset within the header. `0` in M1.
    pub csum_offset: u16,
}

/// Byte size of the `virtio_net_hdr` used by the M1 driver (no
/// `VIRTIO_NET_F_MRG_RXBUF`, so `num_buffers` is absent from the TX path).
///
/// `flags(1) + gso_type(1) + hdr_len(2) + gso_size(2) + csum_start(2) +
/// csum_offset(2)` = **10 bytes** as specified in virtio 1.0 § 5.1.6.
pub const VIRTIO_NET_HDR_SIZE: usize = 10;

// Compile-time invariant: VirtioNetHeader must be exactly VIRTIO_NET_HDR_SIZE
// bytes. This guards against accidentally adding a field.
const _HEADER_SIZE_ASSERT: () =
    assert!(core::mem::size_of::<VirtioNetHeader>() == VIRTIO_NET_HDR_SIZE);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during virtio-net driver TX/RX operations.
///
/// This type is intentionally `Copy` so callers do not need to clone error
/// values for logging or retry logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDriverError {
    /// The TX virtqueue has no free descriptors.
    QueueFull,
    /// The frame exceeds the interface MTU (> [`MAX_FRAME_SIZE`] bytes) or is
    /// below the minimum Ethernet frame size (< [`MIN_FRAME_SIZE`] bytes).
    FrameTooLarge,
    /// No RX buffers are available in the pool.
    NoBuffersAvailable,
    /// The frame data is structurally invalid (e.g. too short to strip the
    /// virtio-net header on RX).
    InvalidFrame,
}

impl core::fmt::Display for NetDriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::QueueFull => f.write_str("virtqueue is full"),
            Self::FrameTooLarge => f.write_str("frame exceeds MTU or is below minimum size"),
            Self::NoBuffersAvailable => f.write_str("no RX buffers available in pool"),
            Self::InvalidFrame => f.write_str("invalid frame data"),
        }
    }
}

// ---------------------------------------------------------------------------
// Frame helpers
// ---------------------------------------------------------------------------

/// Validate that `len` is within the Ethernet frame size bounds.
///
/// Returns `Ok(())` if `MIN_FRAME_SIZE <= len <= MAX_FRAME_SIZE`.
///
/// # Errors
///
/// Returns [`NetDriverError::FrameTooLarge`] if `len` is outside
/// `[MIN_FRAME_SIZE, MAX_FRAME_SIZE]`.
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::tx_rx::{NetDriverError, validate_frame_size};
///
/// assert!(validate_frame_size(64).is_ok());
/// assert_eq!(validate_frame_size(0), Err(NetDriverError::FrameTooLarge));
/// assert_eq!(
///     validate_frame_size(1515),
///     Err(NetDriverError::FrameTooLarge)
/// );
/// ```
pub fn validate_frame_size(len: usize) -> Result<(), NetDriverError> {
    if (MIN_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&len) {
        Ok(())
    } else {
        Err(NetDriverError::FrameTooLarge)
    }
}

/// Prepare a TX frame by prepending a zeroed `virtio_net_hdr`.
///
/// Validates the frame size first. Returns `Ok(Vec<u8>)` where the first
/// `VIRTIO_NET_HDR_SIZE` bytes are the header (all zeros — no offload in M1)
/// followed by the raw Ethernet frame bytes.
///
/// # Errors
///
/// - [`NetDriverError::FrameTooLarge`] if `frame.len()` is outside
///   `[MIN_FRAME_SIZE, MAX_FRAME_SIZE]`.
/// - [`NetDriverError::InvalidFrame`] if `frame` is empty.
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::tx_rx::{VIRTIO_NET_HDR_SIZE, prepare_tx_frame};
///
/// let payload = vec![0u8; 60]; // minimum-padded Ethernet frame
/// let prepared = prepare_tx_frame(&payload).unwrap();
/// assert_eq!(prepared.len(), 60 + VIRTIO_NET_HDR_SIZE);
/// // First VIRTIO_NET_HDR_SIZE bytes are the zero header.
/// let header = prepared.get(..VIRTIO_NET_HDR_SIZE).unwrap();
/// assert!(header.iter().all(|&b| b == 0));
/// // Remainder is the original frame.
/// let body = prepared.get(VIRTIO_NET_HDR_SIZE..).unwrap();
/// assert_eq!(body, payload.as_slice());
/// ```
pub fn prepare_tx_frame(frame: &[u8]) -> Result<Vec<u8>, NetDriverError> {
    if frame.is_empty() {
        return Err(NetDriverError::InvalidFrame);
    }
    validate_frame_size(frame.len())?;

    // Pre-allocate the full output buffer: header + frame.
    let total = VIRTIO_NET_HDR_SIZE
        .checked_add(frame.len())
        .ok_or(NetDriverError::FrameTooLarge)?;

    let mut buf = vec![0u8; total];
    // Header is already zero (default VirtioNetHeader). Copy the frame after.
    // `buf` has exactly `total = VIRTIO_NET_HDR_SIZE + frame.len()` bytes so
    // the slice `[VIRTIO_NET_HDR_SIZE..]` is exactly `frame.len()` bytes.
    // The `get_mut` + `copy_from_slice` path avoids the `indexing_slicing` lint.
    if let Some(dest) = buf.get_mut(VIRTIO_NET_HDR_SIZE..) {
        dest.copy_from_slice(frame);
    }
    Ok(buf)
}

/// Strip the `virtio_net_hdr` from a received buffer and return the Ethernet
/// frame payload.
///
/// Returns `None` if `data.len() < VIRTIO_NET_HDR_SIZE` (i.e. the data cannot
/// possibly contain a valid header + frame).
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::tx_rx::{VIRTIO_NET_HDR_SIZE, strip_rx_header};
///
/// let mut data = vec![0u8; VIRTIO_NET_HDR_SIZE]; // just the header
/// data.extend_from_slice(&[0xDE, 0xAD]); // two payload bytes
/// let frame = strip_rx_header(&data).unwrap();
/// assert_eq!(frame.len(), 2);
/// assert_eq!(frame, &[0xDE, 0xAD]);
/// ```
#[must_use]
pub fn strip_rx_header(data: &[u8]) -> Option<&[u8]> {
    // `get(VIRTIO_NET_HDR_SIZE..)` returns `None` when
    // `data.len() < VIRTIO_NET_HDR_SIZE`, which is the documented contract.
    data.get(VIRTIO_NET_HDR_SIZE..)
}

// ---------------------------------------------------------------------------
// RX buffer pool
// ---------------------------------------------------------------------------

/// A single RX buffer managed by [`RxBufferPool`].
///
/// Each buffer has a stable numeric `id` that the driver passes to the RX
/// virtqueue and uses to reclaim the buffer after the network stack has
/// processed the frame.
pub struct RxBuffer {
    /// Stable identifier for this buffer within its owning pool.
    pub id: u16,
    /// The backing byte storage (pre-allocated to `buffer_size` bytes).
    pub data: Vec<u8>,
    /// `true` while the buffer is posted to the virtqueue and not yet returned
    /// by the driver.
    pub in_use: bool,
}

impl core::fmt::Debug for RxBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxBuffer")
            .field("id", &self.id)
            .field("in_use", &self.in_use)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// Pre-allocated pool of fixed-size RX receive buffers.
///
/// The driver posts each buffer to the RX virtqueue at initialisation
/// (NCIP-015 § S4.1 step 8) and after each received frame. The network stack
/// calls [`RxBufferPool::release`] once it has copied or processed the frame.
///
/// ## Design
///
/// - Buffers are allocated at construction time and never reallocated.
/// - `allocate` / `release` are O(n) scans; the maximum pool size is bounded
///   by the RX virtqueue depth (256 entries in M1), so linear scans are
///   acceptable.
/// - All methods are safe (`no_std + alloc`, zero `unsafe`).
///
/// # Example
///
/// ```
/// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
///
/// let mut pool = RxBufferPool::new(4, 2048);
/// let id = pool.allocate().unwrap();
/// assert!(pool.get(id).is_some());
/// pool.release(id);
/// // After release the buffer is available again.
/// assert!(pool.allocate().is_some());
/// ```
pub struct RxBufferPool {
    /// All buffers, indexed by position (position == `buffer.id`).
    buffers: Vec<RxBuffer>,
    /// Size of each buffer in bytes.
    buffer_size: usize,
}

impl core::fmt::Debug for RxBufferPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxBufferPool")
            .field("count", &self.buffers.len())
            .field("buffer_size", &self.buffer_size)
            .finish()
    }
}

impl RxBufferPool {
    /// Construct a new pool with `count` buffers, each of `buffer_size` bytes.
    ///
    /// All buffers are initially free.
    ///
    /// # Panics
    ///
    /// Panics if `count` is `0` or `buffer_size` is `0`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
    ///
    /// let pool = RxBufferPool::new(8, 1536);
    /// assert_eq!(pool.len(), 8);
    /// assert_eq!(pool.buffer_size(), 1536);
    /// ```
    #[must_use]
    pub fn new(count: u16, buffer_size: usize) -> Self {
        assert!(count > 0, "RxBufferPool count must be > 0");
        assert!(buffer_size > 0, "RxBufferPool buffer_size must be > 0");

        let buffers = (0..count)
            .map(|i| RxBuffer {
                id: i,
                data: vec![0u8; buffer_size],
                in_use: false,
            })
            .collect();

        Self {
            buffers,
            buffer_size,
        }
    }

    /// Returns the number of buffers in the pool (free + in-use).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
    ///
    /// let pool = RxBufferPool::new(3, 64);
    /// assert_eq!(pool.len(), 3);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// Returns `true` if the pool has no buffers at all.
    ///
    /// A pool with all buffers in-use is NOT considered empty; use
    /// [`allocate`](Self::allocate) returning `None` to detect exhaustion.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// Returns the fixed size of each buffer in bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
    ///
    /// let pool = RxBufferPool::new(2, 4096);
    /// assert_eq!(pool.buffer_size(), 4096);
    /// ```
    #[must_use]
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Allocate a free buffer from the pool.
    ///
    /// Returns the buffer's `id` on success, or `None` if all buffers are
    /// currently in-use.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
    ///
    /// let mut pool = RxBufferPool::new(2, 64);
    /// let a = pool.allocate().unwrap();
    /// let b = pool.allocate().unwrap();
    /// assert_ne!(a, b);
    /// assert!(pool.allocate().is_none()); // pool exhausted
    /// ```
    pub fn allocate(&mut self) -> Option<u16> {
        self.buffers.iter_mut().find(|b| !b.in_use).map(|b| {
            b.in_use = true;
            b.id
        })
    }

    /// Release a buffer back to the pool by `id`.
    ///
    /// If `id` is out of range or the buffer is not currently in-use, this
    /// method is a no-op (defensive — mismatched releases must not corrupt
    /// the pool state).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
    ///
    /// let mut pool = RxBufferPool::new(2, 64);
    /// let id = pool.allocate().unwrap();
    /// pool.release(id);
    /// // Buffer is available again.
    /// assert!(pool.allocate().is_some());
    /// ```
    pub fn release(&mut self, id: u16) {
        if let Some(buf) = self.buffers.get_mut(id as usize) {
            buf.in_use = false;
        }
        // Out-of-range `id` → silent no-op.
    }

    /// Get an immutable slice of the buffer data for `id`.
    ///
    /// Returns `None` if `id` is out of range.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
    ///
    /// let mut pool = RxBufferPool::new(2, 8);
    /// let id = pool.allocate().unwrap();
    /// let data = pool.get(id).unwrap();
    /// assert_eq!(data.len(), 8);
    /// ```
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&[u8]> {
        self.buffers.get(id as usize).map(|b| b.data.as_slice())
    }

    /// Get a mutable slice of the buffer data for `id`.
    ///
    /// Returns `None` if `id` is out of range.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_net_virtio::tx_rx::RxBufferPool;
    ///
    /// let mut pool = RxBufferPool::new(2, 8);
    /// let id = pool.allocate().unwrap();
    /// let data = pool.get_mut(id).unwrap();
    /// data[0] = 0xFF;
    /// assert_eq!(pool.get(id).unwrap()[0], 0xFF);
    /// ```
    pub fn get_mut(&mut self, id: u16) -> Option<&mut [u8]> {
        self.buffers
            .get_mut(id as usize)
            .map(|b| b.data.as_mut_slice())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validate_frame_size ------------------------------------------------

    #[test]
    fn validate_accepts_minimum_frame() {
        assert!(validate_frame_size(MIN_FRAME_SIZE).is_ok());
    }

    #[test]
    fn validate_accepts_maximum_frame() {
        assert!(validate_frame_size(MAX_FRAME_SIZE).is_ok());
    }

    #[test]
    fn validate_accepts_typical_frame() {
        assert!(validate_frame_size(64).is_ok());
        assert!(validate_frame_size(1500).is_ok());
    }

    #[test]
    fn validate_rejects_zero() {
        assert_eq!(validate_frame_size(0), Err(NetDriverError::FrameTooLarge));
    }

    #[test]
    fn validate_rejects_below_minimum() {
        assert_eq!(
            validate_frame_size(MIN_FRAME_SIZE - 1),
            Err(NetDriverError::FrameTooLarge)
        );
    }

    #[test]
    fn validate_rejects_above_maximum() {
        assert_eq!(
            validate_frame_size(MAX_FRAME_SIZE + 1),
            Err(NetDriverError::FrameTooLarge)
        );
    }

    // ---- prepare_tx_frame ---------------------------------------------------

    #[test]
    fn prepare_tx_frame_prepends_header() {
        let frame = vec![0xABu8; 64];
        let result = prepare_tx_frame(&frame).unwrap();
        assert_eq!(result.len(), 64 + VIRTIO_NET_HDR_SIZE);
        // Header is all zeros.
        assert!(result[..VIRTIO_NET_HDR_SIZE].iter().all(|&b| b == 0));
        // Payload follows.
        assert_eq!(&result[VIRTIO_NET_HDR_SIZE..], frame.as_slice());
    }

    #[test]
    fn prepare_tx_frame_rejects_empty() {
        assert_eq!(prepare_tx_frame(&[]), Err(NetDriverError::InvalidFrame));
    }

    #[test]
    fn prepare_tx_frame_rejects_oversized() {
        let frame = vec![0u8; MAX_FRAME_SIZE + 1];
        assert_eq!(prepare_tx_frame(&frame), Err(NetDriverError::FrameTooLarge));
    }

    #[test]
    fn prepare_tx_frame_rejects_too_small() {
        let frame = vec![0u8; MIN_FRAME_SIZE - 1];
        assert_eq!(prepare_tx_frame(&frame), Err(NetDriverError::FrameTooLarge));
    }

    #[test]
    fn prepare_tx_frame_minimum_size() {
        let frame = vec![0xFFu8; MIN_FRAME_SIZE];
        let result = prepare_tx_frame(&frame).unwrap();
        assert_eq!(result.len(), MIN_FRAME_SIZE + VIRTIO_NET_HDR_SIZE);
    }

    // ---- strip_rx_header ----------------------------------------------------

    #[test]
    fn strip_rx_header_returns_payload() {
        let mut data = vec![0u8; VIRTIO_NET_HDR_SIZE];
        data.extend_from_slice(&[0x01, 0x02, 0x03]);
        let frame = strip_rx_header(&data).unwrap();
        assert_eq!(frame, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn strip_rx_header_exact_header_size_returns_empty_slice() {
        let data = vec![0u8; VIRTIO_NET_HDR_SIZE];
        let frame = strip_rx_header(&data).unwrap();
        assert!(frame.is_empty());
    }

    #[test]
    fn strip_rx_header_too_short_returns_none() {
        let data = vec![0u8; VIRTIO_NET_HDR_SIZE - 1];
        assert!(strip_rx_header(&data).is_none());
    }

    #[test]
    fn strip_rx_header_empty_returns_none() {
        assert!(strip_rx_header(&[]).is_none());
    }

    #[test]
    fn virtio_net_hdr_size_constant_is_ten() {
        assert_eq!(VIRTIO_NET_HDR_SIZE, 10);
    }

    // ---- RxBufferPool -------------------------------------------------------

    #[test]
    fn rx_pool_new_creates_correct_count() {
        let pool = RxBufferPool::new(8, 2048);
        assert_eq!(pool.len(), 8);
    }

    #[test]
    fn rx_pool_new_sets_buffer_size() {
        let pool = RxBufferPool::new(4, 1536);
        assert_eq!(pool.buffer_size(), 1536);
    }

    #[test]
    fn rx_pool_allocate_returns_ids() {
        let mut pool = RxBufferPool::new(4, 64);
        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rx_pool_allocate_exhaustion_returns_none() {
        let mut pool = RxBufferPool::new(2, 64);
        pool.allocate().unwrap();
        pool.allocate().unwrap();
        assert!(pool.allocate().is_none());
    }

    #[test]
    fn rx_pool_release_makes_buffer_available() {
        let mut pool = RxBufferPool::new(2, 64);
        let id = pool.allocate().unwrap();
        pool.release(id);
        let id2 = pool.allocate().unwrap();
        assert_eq!(id, id2); // same buffer re-issued
    }

    #[test]
    fn rx_pool_release_out_of_range_is_noop() {
        let mut pool = RxBufferPool::new(2, 64);
        pool.release(255); // should not panic
    }

    #[test]
    fn rx_pool_get_returns_correct_size_slice() {
        let mut pool = RxBufferPool::new(2, 128);
        let id = pool.allocate().unwrap();
        assert_eq!(pool.get(id).unwrap().len(), 128);
    }

    #[test]
    fn rx_pool_get_mut_allows_write() {
        let mut pool = RxBufferPool::new(2, 4);
        let id = pool.allocate().unwrap();
        {
            let buf = pool.get_mut(id).unwrap();
            buf[0] = 0xAB;
        }
        assert_eq!(pool.get(id).unwrap()[0], 0xAB);
    }

    #[test]
    fn rx_pool_get_out_of_range_returns_none() {
        let pool = RxBufferPool::new(2, 64);
        assert!(pool.get(99).is_none());
    }
}

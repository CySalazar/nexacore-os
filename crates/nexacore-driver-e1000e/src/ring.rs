//! RX / TX descriptor ring managers for the Intel e1000e driver.
//!
//! This module provides host-testable, `no_std + alloc` implementations of
//! the RX and TX descriptor rings as specified in the Intel 82574L Gigabit
//! Ethernet Controller datasheet:
//!
//! - **RX legacy descriptor** (§ 3.2.3 / § 10.7.1) — 16-byte format with a
//!   buffer address, received length, checksum, status flags, error flags, and
//!   a special field.
//! - **TX legacy descriptor** (§ 3.3.3 / § 10.8.1) — 16-byte format with a
//!   buffer address, length, checksum-offset, command bits, status/reserved,
//!   checksum-start, and a special field.
//!
//! ## Ring semantics
//!
//! Both rings operate on the standard head/tail convention used by the e1000e
//! hardware:
//!
//! - **Head** (`RDH` / `TDH`): advanced by hardware as it consumes descriptors.
//! - **Tail** (`RDT` / `TDT`): advanced by software after posting buffers (RX)
//!   or submitting frames (TX).
//!
//! Because this crate runs as a host-testable library without live hardware,
//! the rings use `Vec<{Rx,Tx}Descriptor>` and software-managed head/tail
//! pointers. The bootable image sibling (`nexacore-driver-e1000e-image`, P6.7.8.7)
//! hands the ring base address to the controller via `RDBAL`/`RDBAH`/`RDLEN`
//! and `TDBAL`/`TDBAH`/`TDLEN` MMIO writes.
//!
//! ## No `unsafe`
//!
//! All index arithmetic is performed with explicit modulo wrapping. No
//! pointer arithmetic or `unsafe` blocks are present; the `Vec` allocation
//! ensures bounds are maintained by the Rust runtime.
//!
//! [`NCIP-Driver-Net-015`]: ../../../ncips/ncip-driver-net-015.md

extern crate alloc;
use alloc::{vec, vec::Vec};

// =============================================================================
// RX descriptor — Intel 82574L datasheet § 3.2.3 / § 10.7.1
// =============================================================================

/// A single legacy RX descriptor (Intel 82574L datasheet § 3.2.3 / § 10.7.1).
///
/// The hardware writes `length`, `checksum`, `status`, and `errors` into this
/// struct after DMA-completing a received frame into `buffer_addr`. Software
/// detects completion by polling the [`RX_STATUS_DD`] bit in `status`.
///
/// In the host-testable simulation the driver layer sets these fields directly
/// to simulate hardware write-back.
///
/// # Wire layout
///
/// ```text
/// Offset  Size  Field
///  0      8     buffer_addr  (physical / IOVA address)
///  8      2     length       (bytes written by hardware)
/// 10      2     checksum     (IP / TCP checksum of received frame)
/// 12      1     status       (DD | EOP | … bits)
/// 13      1     errors       (RXE | IPE | TCPE | … bits)
/// 14      2     special      (VLAN tag / priority)
/// ```
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::ring::{RX_STATUS_DD, RX_STATUS_EOP, RxDescriptor};
///
/// let mut d = RxDescriptor::default();
/// d.buffer_addr = 0x8000;
/// d.length = 60;
/// d.status = RX_STATUS_DD | RX_STATUS_EOP;
/// assert_ne!(d.status & RX_STATUS_DD, 0);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RxDescriptor {
    /// Physical / IOVA address of the receive buffer.
    pub buffer_addr: u64,
    /// Number of bytes written by hardware into the buffer.
    pub length: u16,
    /// Hardware-computed IP / TCP checksum of the received frame.
    pub checksum: u16,
    /// Status bits (see [`RX_STATUS_DD`], [`RX_STATUS_EOP`]).
    pub status: u8,
    /// Error bits set by hardware on reception failure.
    pub errors: u8,
    /// VLAN tag or priority information written by hardware.
    pub special: u16,
}

// =============================================================================
// TX descriptor — Intel 82574L datasheet § 3.3.3 / § 10.8.1
// =============================================================================

/// A single legacy TX descriptor (Intel 82574L datasheet § 3.3.3 / § 10.8.1).
///
/// Software fills `buffer_addr`, `length`, `cso`, `cmd`, `css`, and `special`
/// before advancing the tail pointer. Hardware sets the [`TX_STATUS_DD`] bit
/// in `status_reserved` once the descriptor has been consumed and the frame
/// transmitted.
///
/// # Wire layout
///
/// ```text
/// Offset  Size  Field
///  0      8     buffer_addr    (physical / IOVA address)
///  8      2     length         (bytes to transmit)
/// 10      1     cso            (checksum offset)
/// 11      1     cmd            (EOP | IFCS | RS | … bits)
/// 12      1     status_reserved (DD in low nibble; reserved high nibble)
/// 13      1     css            (checksum start)
/// 14      2     special        (VLAN tag / priority)
/// ```
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::ring::{TX_CMD_EOP, TX_CMD_IFCS, TX_CMD_RS, TxDescriptor};
///
/// let mut d = TxDescriptor::default();
/// d.buffer_addr = 0x9000;
/// d.length = 64;
/// d.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
/// assert_ne!(d.cmd & TX_CMD_EOP, 0);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct TxDescriptor {
    /// Physical / IOVA address of the transmit buffer.
    pub buffer_addr: u64,
    /// Number of bytes to transmit from the buffer.
    pub length: u16,
    /// Byte offset from the start of the frame to insert the checksum.
    pub cso: u8,
    /// Command bits (see [`TX_CMD_EOP`], [`TX_CMD_IFCS`], [`TX_CMD_RS`]).
    pub cmd: u8,
    /// Status bits written back by hardware; low nibble contains DD.
    pub status_reserved: u8,
    /// Byte offset from the start of the frame where checksum computation
    /// begins.
    pub css: u8,
    /// VLAN tag or priority information.
    pub special: u16,
}

// =============================================================================
// RX status bit constants
// =============================================================================

/// `RX_STATUS_DD` — Descriptor Done (bit 0 of the status byte).
///
/// Set by hardware when a received frame has been written into the descriptor's
/// buffer and the descriptor is ready to be consumed by software.
/// Software MUST clear this bit (by zeroing the descriptor) before recycling
/// the descriptor back into the ring.
pub const RX_STATUS_DD: u8 = 0x01;

/// `RX_STATUS_EOP` — End of Packet (bit 1 of the status byte).
///
/// Set by hardware when this descriptor holds the last fragment of a received
/// Ethernet frame. For frames that fit in a single buffer (the common case
/// with 2 KiB buffers and ≤ 1514-byte frames) both DD and EOP are set
/// simultaneously.
pub const RX_STATUS_EOP: u8 = 0x02;

// =============================================================================
// TX command bit constants
// =============================================================================

/// `TX_CMD_EOP` — End of Packet (bit 0 of the cmd byte).
///
/// Marks this descriptor as the last fragment of a frame. The hardware does
/// not begin frame transmission until it encounters a descriptor with EOP set.
pub const TX_CMD_EOP: u8 = 0x01;

/// `TX_CMD_IFCS` — Insert FCS (bit 1 of the cmd byte).
///
/// Instructs the hardware to append the Ethernet FCS (CRC-32) to the frame
/// automatically. Software MUST set this for all normal unicast / multicast /
/// broadcast frames; only raw-socket applications that pre-compute the FCS
/// should clear it.
pub const TX_CMD_IFCS: u8 = 0x02;

/// `TX_CMD_RS` — Report Status (bit 3 of the cmd byte).
///
/// Instructs the hardware to write back the descriptor status (setting
/// [`TX_STATUS_DD`]) after the frame is transmitted. Software relies on this
/// write-back to detect TX completion and reclaim the descriptor slot.
pub const TX_CMD_RS: u8 = 0x08;

/// `TX_STATUS_DD` — Descriptor Done (bit 0 of the `status_reserved` byte).
///
/// Set by hardware in the descriptor's `status_reserved` field after the
/// frame has been transmitted and the descriptor slot is safe to reclaim.
/// Only meaningful when [`TX_CMD_RS`] was set in the command bits of the
/// same descriptor.
pub const TX_STATUS_DD: u8 = 0x01;

// =============================================================================
// RxDescriptorRing
// =============================================================================

/// Manager for the RX descriptor ring.
///
/// Maintains a `Vec` of [`RxDescriptor`] entries and software head/tail
/// pointers that mirror the `RDH` / `RDT` hardware registers. The ring is
/// not circular by raw index; indices wrap modulo `count` so the ring depth
/// must be nonzero (enforced by [`RxDescriptorRing::new`]).
///
/// ## Usage pattern
///
/// 1. Call [`post_buffer`](Self::post_buffer) to hand a DMA-mapped buffer to
///    (simulated) hardware for an upcoming receive.
/// 2. When hardware signals `RXT0` (or the test runner sets DD+EOP), call
///    [`reap_rx`](Self::reap_rx) to consume the completed descriptor.
/// 3. Call [`advance_tail`](Self::advance_tail) to tell (simulated) hardware
///    that the tail pointer has moved.
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::ring::{RX_STATUS_DD, RX_STATUS_EOP, RxDescriptorRing};
///
/// let mut ring = RxDescriptorRing::new(4);
/// // Post a buffer at a fictional DMA address.
/// let idx = ring.post_buffer(0x1000, 2048).expect("ring has room");
/// assert_eq!(idx, 0);
/// // Advance the tail to commit the buffer to (simulated) hardware.
/// ring.advance_tail();
///
/// // Simulate hardware completion of the descriptor.
/// ring.descriptors_mut()[0].length = 60;
/// ring.descriptors_mut()[0].status = RX_STATUS_DD | RX_STATUS_EOP;
///
/// // Reap the completed descriptor.
/// let (desc_idx, len) = ring.reap_rx().expect("descriptor ready");
/// assert_eq!(desc_idx, 0);
/// assert_eq!(len, 60);
/// ```
pub struct RxDescriptorRing {
    /// The descriptor table. Length equals `count`.
    descriptors: Vec<RxDescriptor>,
    /// Number of entries in the ring. Always > 0 after construction.
    count: u16,
    /// Software-maintained head (mirrors `RDH`).
    head: u16,
    /// Software-maintained tail (mirrors `RDT`).
    tail: u16,
}

impl RxDescriptorRing {
    /// Construct a new RX descriptor ring with `count` entries.
    ///
    /// All descriptors are zero-initialised. `count` must be at least 1;
    /// a count of 0 is clamped to 1 (defence-in-depth; callers should
    /// use a validated depth from [`crate::ring_config::is_valid_ring_depth`]).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::RxDescriptorRing;
    ///
    /// let ring = RxDescriptorRing::new(8);
    /// assert_eq!(ring.head(), 0);
    /// assert_eq!(ring.tail(), 0);
    /// ```
    #[must_use]
    pub fn new(count: u16) -> Self {
        // Clamp to at least 1 to avoid a zero-count ring (division/modulo
        // by zero in index arithmetic).
        let count = count.max(1);
        Self {
            descriptors: vec![RxDescriptor::default(); count as usize],
            count,
            head: 0,
            tail: 0,
        }
    }

    /// Return an immutable slice of all descriptors in the ring.
    ///
    /// Primarily used by tests and the bootable image sibling to obtain the
    /// ring's base address for DMA mapping.
    #[must_use]
    pub fn descriptors(&self) -> &[RxDescriptor] {
        &self.descriptors
    }

    /// Return a mutable slice of all descriptors in the ring.
    ///
    /// The bootable image sibling and the test harness use this to simulate
    /// hardware write-back (setting `status`, `length`, etc.). Production code
    /// that runs without live hardware also calls this via the test shim.
    pub fn descriptors_mut(&mut self) -> &mut [RxDescriptor] {
        &mut self.descriptors
    }

    /// Current value of the software-maintained head pointer (mirrors `RDH`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::RxDescriptorRing;
    ///
    /// let ring = RxDescriptorRing::new(4);
    /// assert_eq!(ring.head(), 0);
    /// ```
    #[must_use]
    pub fn head(&self) -> u16 {
        self.head
    }

    /// Current value of the software-maintained tail pointer (mirrors `RDT`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::RxDescriptorRing;
    ///
    /// let ring = RxDescriptorRing::new(4);
    /// assert_eq!(ring.tail(), 0);
    /// ```
    #[must_use]
    pub fn tail(&self) -> u16 {
        self.tail
    }

    /// Number of descriptors in the ring.
    #[must_use]
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Post a DMA buffer at `buf_addr` with capacity `len` into the tail slot
    /// of the RX ring.
    ///
    /// Returns `Some(tail_index)` on success, or `None` if the ring is full
    /// (all slots are occupied by unreaped descriptors). On success the tail
    /// pointer is **not** advanced — the caller must call
    /// [`advance_tail`](Self::advance_tail) after posting one or more buffers
    /// to commit them to hardware.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::RxDescriptorRing;
    ///
    /// let mut ring = RxDescriptorRing::new(4);
    /// let idx = ring.post_buffer(0x4000, 2048);
    /// assert_eq!(idx, Some(0));
    /// ```
    // SAFETY for indexing_slicing: `slot = self.tail as usize`. `self.tail`
    // is always in `0..self.count` by the modulo arithmetic in `advance_tail`
    // and `reap_rx`. `self.descriptors.len() == self.count as usize`, so
    // `slot < self.descriptors.len()` is always true.
    #[allow(clippy::indexing_slicing)]
    pub fn post_buffer(&mut self, buf_addr: u64, len: u16) -> Option<u16> {
        // The ring is full when advancing tail would make it equal to head
        // (standard circular-buffer invariant: one slot is kept empty to
        // distinguish full from empty).
        let next_tail = (self.tail + 1) % self.count;
        if next_tail == self.head && self.is_full_sentinel() {
            return None;
        }

        let slot = self.tail as usize;
        self.descriptors[slot].buffer_addr = buf_addr;
        self.descriptors[slot].length = len;
        self.descriptors[slot].status = 0;
        self.descriptors[slot].errors = 0;
        Some(self.tail)
    }

    /// Advance the software tail pointer by one slot (wraps modulo `count`).
    ///
    /// Call this after [`post_buffer`](Self::post_buffer) to commit the newly
    /// posted buffer to (simulated) hardware. In the bootable image sibling
    /// this corresponds to writing the new tail value to the `RDT` MMIO
    /// register.
    pub fn advance_tail(&mut self) {
        self.tail = (self.tail + 1) % self.count;
    }

    /// Advance the head pointer by one slot (wraps modulo `count`).
    ///
    /// Called internally after reaping a completed descriptor to return the
    /// slot to the pool for future [`post_buffer`](Self::post_buffer) calls.
    fn advance_head(&mut self) {
        self.head = (self.head + 1) % self.count;
    }

    /// Returns `true` when the ring cannot accept a new buffer post.
    ///
    /// The ring is full when advancing `tail` by one would make it coincide
    /// with `head`, meaning all descriptor slots are in-flight.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.is_full_sentinel()
    }

    /// Internal check: tail+1 mod count == head AND tail != head.
    ///
    /// This distinguishes the full condition (tail wrapped around to one
    /// behind head) from the empty condition (tail == head, no buffers
    /// posted yet or all reaped). We track fullness via the one-slot
    /// reserved sentinel: the ring of capacity `count` holds at most
    /// `count - 1` live descriptors.
    fn is_full_sentinel(&self) -> bool {
        (self.tail + 1) % self.count == self.head
    }

    /// Attempt to reap the oldest completed RX descriptor.
    ///
    /// Checks the head descriptor for the `DD` (Descriptor Done) bit. If
    /// both `DD` and `EOP` are set, the descriptor is consumed: the head
    /// pointer advances, the descriptor is zeroed for reuse, and
    /// `Some((head_index, bytes_received))` is returned.
    ///
    /// Returns `None` if the head descriptor is not yet done (hardware has
    /// not written back yet) or if no buffers have been posted.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::{RX_STATUS_DD, RX_STATUS_EOP, RxDescriptorRing};
    ///
    /// let mut ring = RxDescriptorRing::new(4);
    /// ring.post_buffer(0x8000, 2048);
    /// ring.advance_tail();
    ///
    /// // Simulate hardware writing back the descriptor.
    /// ring.descriptors_mut()[0].length = 74;
    /// ring.descriptors_mut()[0].status = RX_STATUS_DD | RX_STATUS_EOP;
    ///
    /// let result = ring.reap_rx();
    /// assert_eq!(result, Some((0, 74)));
    /// assert_eq!(ring.head(), 1);
    /// ```
    // SAFETY for indexing_slicing: `head_idx = self.head as usize`. `self.head`
    // is always in `0..self.count` by the modulo arithmetic in `advance_head`.
    // `self.descriptors.len() == self.count as usize`, so the index is in bounds.
    #[allow(clippy::indexing_slicing)]
    pub fn reap_rx(&mut self) -> Option<(u16, u16)> {
        // If tail == head the ring is empty (no buffers posted, or all
        // buffers have already been reaped).
        if self.tail == self.head {
            return None;
        }

        let head_idx = self.head as usize;
        let status = self.descriptors[head_idx].status;

        // Only reap when both DD and EOP are set: the descriptor is done
        // and this is the last (or only) fragment of the frame.
        if (status & RX_STATUS_DD) == 0 || (status & RX_STATUS_EOP) == 0 {
            return None;
        }

        let length = self.descriptors[head_idx].length;
        let returned_idx = self.head;

        // Zero the descriptor so it can be safely reused.
        self.descriptors[head_idx] = RxDescriptor::default();
        self.advance_head();

        Some((returned_idx, length))
    }
}

// =============================================================================
// TxDescriptorRing
// =============================================================================

/// Manager for the TX descriptor ring.
///
/// Maintains a `Vec` of [`TxDescriptor`] entries and software head/tail
/// pointers that mirror the `TDH` / `TDT` hardware registers. The ring tracks
/// a `tx_free` counter of slots available for new transmissions.
///
/// ## Usage pattern
///
/// 1. Call [`submit_tx`](Self::submit_tx) to fill the next available slot and
///    get the slot index to hand to hardware.
/// 2. After advancing the tail (MMIO write to `TDT` in the bootable image),
///    hardware transmits the frame and sets [`TX_STATUS_DD`] in `status_reserved`.
/// 3. Periodically call [`reap_tx`](Self::reap_tx) to reclaim completed slots
///    and replenish `tx_free`.
///
/// # Example
///
/// ```
/// use nexacore_driver_e1000e::ring::{TX_STATUS_DD, TxDescriptorRing};
///
/// let mut ring = TxDescriptorRing::new(4);
/// assert!(!ring.is_full());
/// assert_eq!(ring.num_free(), 3); // one slot reserved as sentinel
///
/// let idx = ring.submit_tx(0xA000, 128).expect("ring has room");
/// // Simulate hardware TX completion write-back.
/// ring.descriptors_mut()[idx as usize].status_reserved = TX_STATUS_DD;
/// let reaped = ring.reap_tx();
/// assert_eq!(reaped, 1);
/// ```
pub struct TxDescriptorRing {
    /// The descriptor table. Length equals `count`.
    descriptors: Vec<TxDescriptor>,
    /// Number of entries in the ring. Always > 0 after construction.
    count: u16,
    /// Software-maintained head (mirrors `TDH`).
    head: u16,
    /// Software-maintained tail (mirrors `TDT`).
    tail: u16,
    /// Count of free (not yet submitted) descriptor slots.
    tx_free: u16,
}

impl TxDescriptorRing {
    /// Construct a new TX descriptor ring with `count` entries.
    ///
    /// All descriptors are zero-initialised. `count` is clamped to at least 1.
    /// `tx_free` is initialised to `count - 1` because one slot is kept as a
    /// sentinel to distinguish full from empty.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::TxDescriptorRing;
    ///
    /// let ring = TxDescriptorRing::new(8);
    /// assert_eq!(ring.num_free(), 7);
    /// assert!(!ring.is_full());
    /// ```
    #[must_use]
    pub fn new(count: u16) -> Self {
        let count = count.max(1);
        // Free slots = count - 1 (one slot is the empty/full sentinel).
        let tx_free = count.saturating_sub(1);
        Self {
            descriptors: vec![TxDescriptor::default(); count as usize],
            count,
            head: 0,
            tail: 0,
            tx_free,
        }
    }

    /// Return an immutable slice of all descriptors in the ring.
    #[must_use]
    pub fn descriptors(&self) -> &[TxDescriptor] {
        &self.descriptors
    }

    /// Return a mutable slice of all descriptors in the ring.
    ///
    /// Used by tests to simulate hardware TX completion write-back.
    pub fn descriptors_mut(&mut self) -> &mut [TxDescriptor] {
        &mut self.descriptors
    }

    /// Current value of the software-maintained head pointer (mirrors `TDH`).
    #[must_use]
    pub fn head(&self) -> u16 {
        self.head
    }

    /// Current value of the software-maintained tail pointer (mirrors `TDT`).
    #[must_use]
    pub fn tail(&self) -> u16 {
        self.tail
    }

    /// Number of entries in the ring.
    #[must_use]
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Returns `true` when no free descriptor slots remain.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::TxDescriptorRing;
    ///
    /// let mut ring = TxDescriptorRing::new(2);
    /// assert!(!ring.is_full()); // 1 free slot
    /// ring.submit_tx(0x1000, 64).expect("ok");
    /// assert!(ring.is_full());
    /// ```
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.tx_free == 0
    }

    /// Returns the number of descriptor slots available for new TX submissions.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::TxDescriptorRing;
    ///
    /// let ring = TxDescriptorRing::new(4);
    /// assert_eq!(ring.num_free(), 3);
    /// ```
    #[must_use]
    pub fn num_free(&self) -> u16 {
        self.tx_free
    }

    /// Submit a frame buffer for transmission.
    ///
    /// Fills the next available tail descriptor with `buf_addr`, `len`, and
    /// the standard command flags `EOP | IFCS | RS`. Advances the tail pointer
    /// and decrements `tx_free`. Returns `Some(descriptor_index)` on success,
    /// or `None` if the ring is full.
    ///
    /// The caller is responsible for writing the new tail value to the `TDT`
    /// MMIO register in the bootable image sibling to trigger hardware
    /// transmission.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::{TX_CMD_EOP, TX_CMD_IFCS, TX_CMD_RS, TxDescriptorRing};
    ///
    /// let mut ring = TxDescriptorRing::new(4);
    /// let idx = ring.submit_tx(0xB000, 1514).expect("ring has room");
    /// let desc = &ring.descriptors()[idx as usize];
    /// assert_eq!(desc.buffer_addr, 0xB000);
    /// assert_eq!(desc.length, 1514);
    /// assert_ne!(desc.cmd & TX_CMD_EOP, 0);
    /// assert_ne!(desc.cmd & TX_CMD_IFCS, 0);
    /// assert_ne!(desc.cmd & TX_CMD_RS, 0);
    /// ```
    // SAFETY for indexing_slicing: `slot = self.tail as usize`. `self.tail`
    // is always in `0..self.count` by the modulo arithmetic applied after
    // each submit. `self.descriptors.len() == self.count as usize`.
    #[allow(clippy::indexing_slicing)]
    pub fn submit_tx(&mut self, buf_addr: u64, len: u16) -> Option<u16> {
        if self.is_full() {
            return None;
        }

        let slot = self.tail as usize;
        self.descriptors[slot].buffer_addr = buf_addr;
        self.descriptors[slot].length = len;
        self.descriptors[slot].cso = 0;
        self.descriptors[slot].cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        self.descriptors[slot].status_reserved = 0;
        self.descriptors[slot].css = 0;
        self.descriptors[slot].special = 0;

        let submitted_idx = self.tail;
        self.tail = (self.tail + 1) % self.count;
        // tx_free is always >= 1 here (is_full check above), so subtract is safe.
        self.tx_free -= 1;

        Some(submitted_idx)
    }

    /// Reap all completed TX descriptors from the head of the ring.
    ///
    /// Scans from `head` towards `tail`, consuming every descriptor that has
    /// [`TX_STATUS_DD`] set in `status_reserved`. Each reaped descriptor is
    /// zeroed and `tx_free` is incremented. Returns the count of descriptors
    /// reaped during this call.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_driver_e1000e::ring::{TX_STATUS_DD, TxDescriptorRing};
    ///
    /// let mut ring = TxDescriptorRing::new(4);
    /// ring.submit_tx(0xC000, 64).expect("ok");
    /// ring.submit_tx(0xD000, 128).expect("ok");
    ///
    /// // Simulate hardware completing both descriptors.
    /// ring.descriptors_mut()[0].status_reserved = TX_STATUS_DD;
    /// ring.descriptors_mut()[1].status_reserved = TX_STATUS_DD;
    ///
    /// let reaped = ring.reap_tx();
    /// assert_eq!(reaped, 2);
    /// assert_eq!(ring.num_free(), 3); // back to count-1
    /// ```
    // SAFETY for indexing_slicing: `head_idx = self.head as usize`. The loop
    // condition `self.head != self.tail` ensures we only access slots that were
    // submitted (i.e. within the live window). `self.head` is always in
    // `0..self.count` by the modulo arithmetic after each advance. Thus
    // `head_idx < self.descriptors.len()`.
    #[allow(clippy::indexing_slicing)]
    pub fn reap_tx(&mut self) -> u16 {
        let mut reaped: u16 = 0;

        // Walk from head towards tail, stopping when we hit a descriptor
        // without DD set (hardware processes in-order, so the first non-DD
        // descriptor marks the boundary of completed work).
        while self.head != self.tail {
            let head_idx = self.head as usize;
            if self.descriptors[head_idx].status_reserved & TX_STATUS_DD == 0 {
                // Hardware has not yet finished this descriptor.
                break;
            }

            // Zero the descriptor so stale status bits cannot confuse a
            // future reap after the slot is reused.
            self.descriptors[head_idx] = TxDescriptor::default();
            self.head = (self.head + 1) % self.count;

            // Saturating add guards against the theoretical overflow if count
            // is very small and a logic error double-counts; in practice
            // tx_free never exceeds count - 1.
            self.tx_free = self.tx_free.saturating_add(1).min(self.count - 1);
            reaped += 1;
        }

        reaped
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // ---- RX descriptor constant sanity -------------------------------------

    #[test]
    fn rx_status_dd_is_bit_0() {
        assert_eq!(RX_STATUS_DD, 0x01);
    }

    #[test]
    fn rx_status_eop_is_bit_1() {
        assert_eq!(RX_STATUS_EOP, 0x02);
    }

    // ---- TX command constant sanity ----------------------------------------

    #[test]
    fn tx_cmd_eop_is_bit_0() {
        assert_eq!(TX_CMD_EOP, 0x01);
    }

    #[test]
    fn tx_cmd_ifcs_is_bit_1() {
        assert_eq!(TX_CMD_IFCS, 0x02);
    }

    #[test]
    fn tx_cmd_rs_is_bit_3() {
        assert_eq!(TX_CMD_RS, 0x08);
    }

    #[test]
    fn tx_status_dd_is_bit_0() {
        assert_eq!(TX_STATUS_DD, 0x01);
    }

    // ---- RxDescriptorRing construction -------------------------------------

    #[test]
    fn rx_ring_new_initialises_head_and_tail_to_zero() {
        let ring = RxDescriptorRing::new(8);
        assert_eq!(ring.head(), 0);
        assert_eq!(ring.tail(), 0);
        assert_eq!(ring.count(), 8);
    }

    #[test]
    fn rx_ring_new_clamps_zero_count_to_one() {
        let ring = RxDescriptorRing::new(0);
        assert_eq!(ring.count(), 1);
    }

    #[test]
    fn rx_ring_post_buffer_returns_tail_index() {
        let mut ring = RxDescriptorRing::new(4);
        let idx = ring.post_buffer(0x1000, 2048).unwrap();
        assert_eq!(idx, 0);
    }

    // ---- RxDescriptorRing: post + reap -------------------------------------

    #[test]
    fn rx_ring_reap_returns_none_when_dd_not_set() {
        let mut ring = RxDescriptorRing::new(4);
        ring.post_buffer(0x1000, 2048).unwrap();
        ring.advance_tail();
        // No hardware write-back → DD not set.
        assert_eq!(ring.reap_rx(), None);
    }

    #[test]
    fn rx_ring_reap_returns_none_on_empty_ring() {
        let mut ring = RxDescriptorRing::new(4);
        // No buffers posted.
        assert_eq!(ring.reap_rx(), None);
    }

    #[test]
    fn rx_ring_reap_succeeds_on_dd_and_eop_set() {
        let mut ring = RxDescriptorRing::new(4);
        ring.post_buffer(0x2000, 2048).unwrap();
        ring.advance_tail();

        // Simulate hardware write-back.
        ring.descriptors_mut()[0].length = 74;
        ring.descriptors_mut()[0].status = RX_STATUS_DD | RX_STATUS_EOP;

        let result = ring.reap_rx().unwrap();
        assert_eq!(result, (0, 74));
        assert_eq!(ring.head(), 1);
    }

    #[test]
    fn rx_ring_reap_requires_eop_in_addition_to_dd() {
        let mut ring = RxDescriptorRing::new(4);
        ring.post_buffer(0x3000, 2048).unwrap();
        ring.advance_tail();

        // DD set but not EOP (multi-fragment frame scenario not yet fully
        // received).
        ring.descriptors_mut()[0].status = RX_STATUS_DD;
        assert_eq!(ring.reap_rx(), None);
    }

    #[test]
    fn rx_ring_reap_zeroes_descriptor_after_consumption() {
        let mut ring = RxDescriptorRing::new(4);
        ring.post_buffer(0x5000, 2048).unwrap();
        ring.advance_tail();
        ring.descriptors_mut()[0].length = 60;
        ring.descriptors_mut()[0].status = RX_STATUS_DD | RX_STATUS_EOP;

        ring.reap_rx().unwrap();

        // The descriptor at index 0 should now be zeroed.
        assert_eq!(ring.descriptors()[0].status, 0);
        assert_eq!(ring.descriptors()[0].length, 0);
        assert_eq!(ring.descriptors()[0].buffer_addr, 0);
    }

    // ---- RxDescriptorRing: wrap-around ------------------------------------

    #[test]
    fn rx_ring_wrap_around_uses_modulo() {
        let mut ring = RxDescriptorRing::new(4);

        // Fill and drain the ring twice to exercise wrap-around.
        for cycle in 0u64..2 {
            for i in 0u64..3 {
                let addr = 0x1000 * (cycle * 3 + i + 1);
                ring.post_buffer(addr, 2048).unwrap();
                ring.advance_tail();
            }
            for expected_idx in 0..3u16 {
                let slot_idx = ((cycle as u16) * 3 + expected_idx) % 4;
                ring.descriptors_mut()[slot_idx as usize].length = 64;
                ring.descriptors_mut()[slot_idx as usize].status = RX_STATUS_DD | RX_STATUS_EOP;
                let (idx, len) = ring.reap_rx().unwrap();
                assert_eq!(idx, slot_idx);
                assert_eq!(len, 64);
            }
        }
    }

    // ---- RxDescriptorRing: full detection ----------------------------------

    #[test]
    fn rx_ring_is_not_full_when_empty() {
        let ring = RxDescriptorRing::new(4);
        assert!(!ring.is_full());
    }

    #[test]
    fn rx_ring_is_full_after_count_minus_one_posts() {
        let mut ring = RxDescriptorRing::new(4);
        // A ring of capacity 4 can hold 3 live buffers (one sentinel slot).
        for addr in [0x1000u64, 0x2000, 0x3000] {
            ring.post_buffer(addr, 2048).unwrap();
            ring.advance_tail();
        }
        assert!(ring.is_full());
    }

    #[test]
    fn rx_ring_post_returns_none_when_full() {
        let mut ring = RxDescriptorRing::new(4);
        for addr in [0x1000u64, 0x2000, 0x3000] {
            ring.post_buffer(addr, 2048).unwrap();
            ring.advance_tail();
        }
        assert_eq!(ring.post_buffer(0x4000, 2048), None);
    }

    // ---- TxDescriptorRing construction -------------------------------------

    #[test]
    fn tx_ring_new_initialises_correctly() {
        let ring = TxDescriptorRing::new(8);
        assert_eq!(ring.head(), 0);
        assert_eq!(ring.tail(), 0);
        assert_eq!(ring.count(), 8);
        assert_eq!(ring.num_free(), 7);
        assert!(!ring.is_full());
    }

    #[test]
    fn tx_ring_new_clamps_zero_count_to_one() {
        let ring = TxDescriptorRing::new(0);
        assert_eq!(ring.count(), 1);
        // A ring of count 1 has 0 free slots (count - 1 = 0, immediately full).
        assert_eq!(ring.num_free(), 0);
        assert!(ring.is_full());
    }

    // ---- TxDescriptorRing: submit ------------------------------------------

    #[test]
    fn tx_ring_submit_fills_descriptor_and_advances_tail() {
        let mut ring = TxDescriptorRing::new(4);
        let idx = ring.submit_tx(0xA000, 1514).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(ring.tail(), 1);
        assert_eq!(ring.num_free(), 2);

        let desc = &ring.descriptors()[0];
        assert_eq!(desc.buffer_addr, 0xA000);
        assert_eq!(desc.length, 1514);
        assert_ne!(desc.cmd & TX_CMD_EOP, 0);
        assert_ne!(desc.cmd & TX_CMD_IFCS, 0);
        assert_ne!(desc.cmd & TX_CMD_RS, 0);
    }

    #[test]
    fn tx_ring_submit_returns_none_when_full() {
        let mut ring = TxDescriptorRing::new(2);
        ring.submit_tx(0x1000, 64).unwrap(); // fills the one available slot
        assert!(ring.is_full());
        assert_eq!(ring.submit_tx(0x2000, 64), None);
    }

    // ---- TxDescriptorRing: reap --------------------------------------------

    #[test]
    fn tx_ring_reap_returns_zero_when_no_dd_set() {
        let mut ring = TxDescriptorRing::new(4);
        ring.submit_tx(0xB000, 128).unwrap();
        // Hardware has not yet completed the descriptor.
        assert_eq!(ring.reap_tx(), 0);
    }

    #[test]
    fn tx_ring_reap_counts_completed_descriptors() {
        let mut ring = TxDescriptorRing::new(4);
        ring.submit_tx(0xC000, 64).unwrap();
        ring.submit_tx(0xD000, 128).unwrap();

        ring.descriptors_mut()[0].status_reserved = TX_STATUS_DD;
        ring.descriptors_mut()[1].status_reserved = TX_STATUS_DD;

        assert_eq!(ring.reap_tx(), 2);
        assert_eq!(ring.num_free(), 3);
    }

    #[test]
    fn tx_ring_reap_stops_at_first_non_dd_descriptor() {
        let mut ring = TxDescriptorRing::new(4);
        ring.submit_tx(0x1000, 64).unwrap();
        ring.submit_tx(0x2000, 64).unwrap();
        ring.submit_tx(0x3000, 64).unwrap();

        // Only the first two are done.
        ring.descriptors_mut()[0].status_reserved = TX_STATUS_DD;
        ring.descriptors_mut()[1].status_reserved = TX_STATUS_DD;
        // Index 2 has no DD set.

        assert_eq!(ring.reap_tx(), 2);
        assert_eq!(ring.head(), 2);
    }

    // ---- TxDescriptorRing: wrap-around -------------------------------------

    #[test]
    fn tx_ring_wrap_around_works_correctly() {
        let mut ring = TxDescriptorRing::new(4);

        // Submit and reap three batches to force the head/tail to wrap.
        for cycle in 0..3u16 {
            let addr = 0x1000u64 * (u64::from(cycle) + 1);
            let idx = ring.submit_tx(addr, 64).unwrap();
            ring.descriptors_mut()[idx as usize].status_reserved = TX_STATUS_DD;
            let reaped = ring.reap_tx();
            assert_eq!(reaped, 1, "cycle {cycle}: expected 1 reaped");
        }
        // After 3 single-submit-single-reap cycles on a ring of 4, head and
        // tail should both be at index 3 (3 % 4 == 3).
        assert_eq!(ring.head(), 3);
        assert_eq!(ring.tail(), 3);
        assert_eq!(ring.num_free(), 3);
    }

    // ---- Descriptor size contract (compile-time sanity) --------------------

    #[test]
    fn rx_descriptor_default_is_all_zeros() {
        let d = RxDescriptor::default();
        assert_eq!(d.buffer_addr, 0);
        assert_eq!(d.length, 0);
        assert_eq!(d.status, 0);
        assert_eq!(d.errors, 0);
    }

    #[test]
    fn tx_descriptor_default_is_all_zeros() {
        let d = TxDescriptor::default();
        assert_eq!(d.buffer_addr, 0);
        assert_eq!(d.length, 0);
        assert_eq!(d.cmd, 0);
        assert_eq!(d.status_reserved, 0);
    }
}

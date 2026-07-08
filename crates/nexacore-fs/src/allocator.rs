//! # Bitmap-based Copy-on-Write block allocator
//!
//! Implements the free-space bitmap described in NCIP-FS-Wire-023 §S3.
//! Each bit in the bitmap represents one 4 KiB block on the volume.
//! A bit value of `0` means the block is free; `1` means allocated.
//!
//! Block numbers are **1-based physical addresses** (0 is the
//! `NULL_BLOCK` sentinel — never allocated).  The bitmap itself uses
//! 0-based indices internally and converts at the boundary.
//!
//! ## `CoW` semantics
//!
//! The allocator does not implement `CoW` directly — it provides the
//! primitive operations (`allocate` / `free`) that the `CoW` write path
//! in [`ondisk::OnDiskVolume`] composes to achieve crash safety:
//!
//! 1. `allocate()` → write new data to the fresh block.
//! 2. Update inode pointer (single 8-byte atomic write).
//! 3. `free(old_block)` → release the previous block.
//!
//! [`ondisk::OnDiskVolume`]: crate::ondisk::OnDiskVolume

extern crate alloc;
use alloc::{vec, vec::Vec};

// =============================================================================
// Constants
// =============================================================================

/// Sentinel value meaning "no block" (NULL pointer in the block graph).
///
/// The allocator guarantees that `allocate()` never returns this value;
/// it always returns a positive (≥ 1) block number.
pub const NULL_BLOCK: u64 = 0;

// =============================================================================
// BlockBitmap
// =============================================================================

/// Bitmap tracking which blocks are allocated on an `NCFS` volume.
///
/// Internally stored as a `Vec<u8>` where bit `i` of byte `i / 8`
/// corresponds to block number `i + 1` (since block 0 is the NULL
/// sentinel). A `0` bit means **free**; a `1` bit means **allocated**.
///
/// Blocks beyond `total_blocks` — padding bits in the final byte — are
/// permanently set to `1` (allocated-sentinel) so they are never
/// returned by `allocate()`.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::allocator::BlockBitmap;
///
/// let mut bm = BlockBitmap::new(16);
/// assert_eq!(bm.free_count(), 16);
///
/// let b = bm.allocate().expect("allocate succeeds on a fresh bitmap");
/// assert!(b >= 1, "block numbers are 1-based");
/// assert_eq!(bm.free_count(), 15);
///
/// bm.free(b);
/// assert_eq!(bm.free_count(), 16);
/// ```
#[derive(Debug, Clone)]
pub struct BlockBitmap {
    /// Raw bitmap bytes.  Bit `i % 8` of byte `i / 8` represents block `i + 1`.
    bits: Vec<u8>,
    /// Total number of data blocks the bitmap tracks.
    total_blocks: u64,
    /// Running count of unallocated blocks (avoids O(n) scan on every check).
    free_count: u64,
}

impl BlockBitmap {
    /// Create a fresh bitmap for `total_blocks` blocks, all free.
    ///
    /// The bitmap is zero-initialised.  Excess bits in the last byte
    /// (when `total_blocks` is not a multiple of 8) are set to `1`
    /// (allocated-sentinel) so they are never returned by `allocate()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let bm = BlockBitmap::new(8);
    /// assert_eq!(bm.free_count(), 8);
    /// assert_eq!(bm.total_blocks(), 8);
    /// ```
    #[must_use]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "ceil division is exact (integer arithmetic); last-byte index is provably in-bounds (byte_count - 1 is the last valid index)"
    )]
    pub fn new(total_blocks: u64) -> Self {
        // Number of bytes needed: ceil(total_blocks / 8).
        let byte_count = ((total_blocks + 7) / 8) as usize;
        let mut bits = vec![0u8; byte_count];

        // Seal excess bits in the last byte as allocated so they are
        // invisible to allocate().
        if total_blocks % 8 != 0 {
            let used_bits = (total_blocks % 8) as u8;
            let last = byte_count - 1;
            // Set the high (8 - used_bits) bits to 1.
            bits[last] = !((1u8 << used_bits) - 1);
        }

        Self {
            bits,
            total_blocks,
            free_count: total_blocks,
        }
    }

    /// Restore a bitmap from its serialised byte representation.
    ///
    /// `bytes` must be at least `ceil(total_blocks / 8)` bytes long.
    /// Returns `None` if the slice is shorter than required.
    ///
    /// The `free_count` is recomputed by scanning the bitmap so the
    /// in-memory counter is always consistent with the on-disk bits.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let mut bm = BlockBitmap::new(8);
    /// bm.allocate();
    /// let raw = bm.as_bytes().to_vec();
    /// let restored = BlockBitmap::from_bytes(&raw, 8).expect("from_bytes");
    /// assert_eq!(restored.free_count(), 7);
    /// ```
    #[must_use]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "required is provably <= bytes.len() after the length check; slicing is safe"
    )]
    pub fn from_bytes(bytes: &[u8], total_blocks: u64) -> Option<Self> {
        let required = ((total_blocks + 7) / 8) as usize;
        if bytes.len() < required {
            return None;
        }
        let bits = bytes[..required].to_vec();

        // Recompute free_count by counting zero bits within the valid range.
        let free_count = Self::count_free_bits(&bits, total_blocks);

        Some(Self {
            bits,
            total_blocks,
            free_count,
        })
    }

    /// Allocate the lowest-numbered free block and return its 1-based number.
    ///
    /// Returns `None` when the volume is full (no free blocks remain).
    ///
    /// The allocation strategy is first-fit (lowest numbered free block)
    /// which keeps the bitmap scan O(n) in the worst case but O(1) in the
    /// common case of a mostly-empty volume.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let mut bm = BlockBitmap::new(4);
    /// let b1 = bm.allocate().unwrap();
    /// let b2 = bm.allocate().unwrap();
    /// assert_ne!(b1, b2);
    /// assert_eq!(bm.free_count(), 2);
    /// ```
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "byte_idx is from 0..bits.len() so bits[byte_idx] is in-bounds; NexaCore OS targets 64-bit so usize cast is safe"
    )]
    pub fn allocate(&mut self) -> Option<u64> {
        if self.free_count == 0 {
            return None;
        }
        // First-fit scan: find the first zero bit within valid blocks.
        for byte_idx in 0..self.bits.len() {
            let byte = self.bits[byte_idx];
            if byte == 0xFF {
                // All 8 bits allocated in this byte; skip.
                continue;
            }
            // Find the lowest zero bit in this byte.
            for bit_idx in 0u8..8 {
                if byte & (1 << bit_idx) == 0 {
                    // Compute the 0-based block index.
                    let block_idx = byte_idx as u64 * 8 + u64::from(bit_idx);
                    if block_idx >= self.total_blocks {
                        // Past the end of valid blocks; bitmap exhausted.
                        return None;
                    }
                    // Mark as allocated.
                    self.bits[byte_idx] |= 1 << bit_idx;
                    self.free_count -= 1;
                    // Return 1-based block number.
                    return Some(block_idx + 1);
                }
            }
        }
        None
    }

    /// Free a previously allocated block, making it available for reuse.
    ///
    /// `block_number` is the 1-based physical block address returned by
    /// [`BlockBitmap::allocate`].  Freeing an already-free block is
    /// idempotent (a second free is a no-op, not a double-free panic).
    /// Freeing block 0 or a number beyond `total_blocks` is ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let mut bm = BlockBitmap::new(4);
    /// let b = bm.allocate().unwrap();
    /// bm.free(b);
    /// assert_eq!(bm.free_count(), 4);
    /// // Double-free is safe (idempotent).
    /// bm.free(b);
    /// assert_eq!(bm.free_count(), 4);
    /// ```
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "byte_idx is block_number/8 which is within 0..bits.len() after the range check; NexaCore OS is 64-bit"
    )]
    pub fn free(&mut self, block_number: u64) {
        // Block 0 is the NULL sentinel; never allocatable or freeable.
        if block_number == 0 || block_number > self.total_blocks {
            return;
        }
        // Convert to 0-based index.
        let idx = block_number - 1;
        let byte_idx = (idx / 8) as usize;
        let bit_idx = (idx % 8) as u8;

        // Check whether the block is actually allocated before decrementing
        // the free counter — idempotent double-free.
        if self.bits[byte_idx] & (1 << bit_idx) != 0 {
            self.bits[byte_idx] &= !(1 << bit_idx);
            self.free_count += 1;
        }
    }

    /// Mark a specific block as allocated without using first-fit allocation.
    ///
    /// This is used during filesystem formatting to reserve structural blocks
    /// (e.g., the integrity region at block `total_blocks`). If the block is
    /// already allocated this is a no-op (idempotent). Block 0 and out-of-range
    /// numbers are ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let mut bm = BlockBitmap::new(8);
    /// bm.mark_allocated(5);
    /// assert!(bm.is_allocated(5));
    /// assert_eq!(bm.free_count(), 7);
    /// // Idempotent.
    /// bm.mark_allocated(5);
    /// assert_eq!(bm.free_count(), 7);
    /// ```
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "byte_idx is within bits.len() after the range check; NexaCore OS is 64-bit"
    )]
    pub fn mark_allocated(&mut self, block_number: u64) {
        if block_number == 0 || block_number > self.total_blocks {
            return;
        }
        let idx = block_number - 1;
        let byte_idx = (idx / 8) as usize;
        let bit_idx = (idx % 8) as u8;
        if self.bits[byte_idx] & (1 << bit_idx) == 0 {
            self.bits[byte_idx] |= 1 << bit_idx;
            self.free_count -= 1;
        }
    }

    /// Return the number of free (unallocated) blocks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let bm = BlockBitmap::new(10);
    /// assert_eq!(bm.free_count(), 10);
    /// ```
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.free_count
    }

    /// Return the total number of blocks tracked by this bitmap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let bm = BlockBitmap::new(100);
    /// assert_eq!(bm.total_blocks(), 100);
    /// ```
    #[must_use]
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Return `true` if `block_number` is currently allocated.
    ///
    /// Block 0 and out-of-range numbers always return `false`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let mut bm = BlockBitmap::new(8);
    /// let b = bm.allocate().unwrap();
    /// assert!(bm.is_allocated(b));
    /// bm.free(b);
    /// assert!(!bm.is_allocated(b));
    /// ```
    #[must_use]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "byte_idx is within bits.len() after the range check; NexaCore OS is 64-bit"
    )]
    pub fn is_allocated(&self, block_number: u64) -> bool {
        if block_number == 0 || block_number > self.total_blocks {
            return false;
        }
        let idx = block_number - 1;
        let byte_idx = (idx / 8) as usize;
        let bit_idx = (idx % 8) as u8;
        self.bits[byte_idx] & (1 << bit_idx) != 0
    }

    /// Return a byte slice over the raw bitmap data.
    ///
    /// The returned slice is suitable for serialising to the bitmap region
    /// on disk (blocks 1 through N per NCIP-FS-Wire-023 §S3).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_fs::allocator::BlockBitmap;
    ///
    /// let bm = BlockBitmap::new(8);
    /// assert_eq!(bm.as_bytes().len(), 1);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Count the number of zero bits (free blocks) in the given bitmap bytes,
    /// considering only the first `total_blocks` bit positions.
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "byte_idx < bits.len() is checked before indexing; NexaCore OS is 64-bit"
    )]
    fn count_free_bits(bits: &[u8], total_blocks: u64) -> u64 {
        let mut free = 0u64;
        for idx in 0..total_blocks {
            let byte_idx = (idx / 8) as usize;
            let bit_idx = (idx % 8) as u8;
            if byte_idx < bits.len() && bits[byte_idx] & (1 << bit_idx) == 0 {
                free += 1;
            }
        }
        free
    }
}

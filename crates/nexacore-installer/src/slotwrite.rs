//! Atomic system-image write to the inactive A/B slot (WS11-05.5).
//!
//! Flashing an update means streaming a system image onto the **inactive** root
//! slot while the active slot keeps running, so a crash at any point can never
//! leave a half-written slot that the bootloader would try to boot. This module
//! is the I/O half that [`crate::ab`] (pure state) deliberately omits: it drives
//! the v3 [`BlockDevice`] seam and the [`AbState`] boot-control block together to
//! give that guarantee.
//!
//! The [`BlockDevice`] passed to [`write_image_to_slot`] represents the target
//! slot's *partition* (its [`BlockDevice::block_count`] is the slot capacity in
//! 4 KiB blocks). The write is atomic w.r.t. boot:
//!
//! 1. the target slot is marked **un-bootable** ([`AbState::begin_update`])
//!    *before* the first byte is written — a crash mid-flash boots the old slot;
//! 2. the image is streamed block-by-block over the seam and flushed;
//! 3. the written blocks are read back and compared against the image;
//! 4. the slot is left un-bootable, ready for a separate `finish_update` to make
//!    it the boot target (the boot-slot switch is WS11-05.7, out of scope here).
//!
//! Every failure path is fail-closed: an oversized image, a device error, or a
//! read-back mismatch all leave the slot un-bootable, never partially bootable.

use nexacore_fs::v3::{BLOCK_SIZE, Block, V3Error, blockdev::BlockDevice, zero_block};

use crate::ab::{AbState, Slot};

/// Pad a (≤ [`BLOCK_SIZE`]) image chunk into a full zeroed [`Block`].
fn block_from_chunk(chunk: &[u8]) -> Block {
    let mut block = zero_block();
    // `chunk` comes from `slice::chunks(BLOCK_SIZE)`, so `chunk.len() <=
    // BLOCK_SIZE` and the destination range always exists.
    if let Some(dst) = block.get_mut(..chunk.len()) {
        dst.copy_from_slice(chunk);
    }
    block
}

/// Why an image write to an A/B slot could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotWriteError {
    /// The image is larger than the destination slot partition.
    ImageTooLarge {
        /// Image length in bytes.
        image_len: u64,
        /// Slot capacity in bytes.
        slot_capacity: u64,
    },
    /// Refused to flash the slot the system is currently booting from: doing so
    /// would mark the running slot un-bootable and defeat the A/B guarantee.
    SlotInUse,
    /// The block-device seam failed while writing, flushing, or reading back.
    Device(V3Error),
    /// The blocks read back from the device did not match the image.
    VerifyMismatch,
}

impl core::fmt::Display for SlotWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ImageTooLarge {
                image_len,
                slot_capacity,
            } => write!(
                f,
                "image of {image_len} bytes exceeds slot capacity of {slot_capacity} bytes"
            ),
            Self::SlotInUse => f.write_str("refused to flash the currently-booting slot"),
            Self::Device(e) => write!(f, "block device error during slot write: {e}"),
            Self::VerifyMismatch => f.write_str("read-back verification did not match the image"),
        }
    }
}

impl core::error::Error for SlotWriteError {}

impl From<V3Error> for SlotWriteError {
    fn from(e: V3Error) -> Self {
        Self::Device(e)
    }
}

/// Atomically write `image` to `slot`'s partition on `dev`, updating `state`.
///
/// `dev` is the block device backing `slot`'s root partition; its
/// [`BlockDevice::block_count`] bounds the slot capacity. On success the slot is
/// left **un-bootable** with its blocks written and verified, ready for a
/// separate `finish_update` (WS11-05.7) to make it the boot target.
///
/// The target slot is marked un-bootable ([`AbState::begin_update`]) before any
/// write, so every early return below leaves it un-bootable — a crash or error
/// mid-flash can never boot a partial slot.
///
/// # Errors
/// - [`SlotWriteError::SlotInUse`] if `slot` is the slot currently being booted
///   (checked before any state change, so `state` is left untouched);
/// - [`SlotWriteError::ImageTooLarge`] if `image` does not fit the slot;
/// - [`SlotWriteError::Device`] if the seam fails while writing/flushing/reading;
/// - [`SlotWriteError::VerifyMismatch`] if the read-back does not match `image`.
pub fn write_image_to_slot<D: BlockDevice>(
    dev: &mut D,
    slot: Slot,
    image: &[u8],
    state: &mut AbState,
) -> Result<(), SlotWriteError> {
    // Never flash the slot we are booting from: that slot must stay bootable.
    if state.boot_slot() == Some(slot) {
        return Err(SlotWriteError::SlotInUse);
    }

    // Mark the target un-bootable BEFORE the first write. From here on every
    // return path leaves the slot un-bootable (fail-closed).
    state.begin_update(slot);

    let capacity = dev.block_count().saturating_mul(BLOCK_SIZE as u64);
    let image_len = image.len() as u64;
    if image_len > capacity {
        return Err(SlotWriteError::ImageTooLarge {
            image_len,
            slot_capacity: capacity,
        });
    }

    // Stream the image block-by-block; the final short block is zero-padded.
    for (index, chunk) in image.chunks(BLOCK_SIZE).enumerate() {
        dev.write_block(index as u64, &block_from_chunk(chunk))?;
    }
    dev.flush()?;

    // Verify: read every written block back and compare against the image.
    for (index, chunk) in image.chunks(BLOCK_SIZE).enumerate() {
        let mut read = zero_block();
        dev.read_block(index as u64, &mut read)?;
        if read != block_from_chunk(chunk) {
            return Err(SlotWriteError::VerifyMismatch);
        }
    }

    // Slot is written and verified but intentionally left un-bootable: the
    // boot-slot switch (finish_update) is a separate, later step (WS11-05.7).
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use nexacore_fs::v3::blockdev::MemBlockDevice;

    use super::*;

    /// A block device that fails `write_block` once it reaches `fail_at`,
    /// wrapping a [`MemBlockDevice`] for every other operation.
    struct FailAtWrite {
        inner: MemBlockDevice,
        fail_at: u64,
    }

    impl BlockDevice for FailAtWrite {
        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }
        fn read_block(&self, index: u64, out: &mut [u8; BLOCK_SIZE]) -> Result<(), V3Error> {
            self.inner.read_block(index, out)
        }
        fn write_block(&mut self, index: u64, data: &[u8; BLOCK_SIZE]) -> Result<(), V3Error> {
            if index >= self.fail_at {
                return Err(V3Error::Io);
            }
            self.inner.write_block(index, data)
        }
        fn flush(&mut self) -> Result<(), V3Error> {
            self.inner.flush()
        }
        fn commit_root(&mut self, generation: u64) -> Result<(), V3Error> {
            self.inner.commit_root(generation)
        }
        fn committed_generation(&self) -> u64 {
            self.inner.committed_generation()
        }
    }

    /// Read the first `len` bytes back off a device, block by block.
    fn read_back(dev: &MemBlockDevice, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut index = 0u64;
        while out.len() < len {
            let mut block = zero_block();
            dev.read_block(index, &mut block).unwrap();
            out.extend_from_slice(&block);
            index += 1;
        }
        out.truncate(len);
        out
    }

    #[test]
    fn successful_write_marks_unbootable_first_then_writes_all_blocks() {
        let mut dev = MemBlockDevice::new(8);
        let mut state = AbState::new();
        let target = state.target_slot(); // B on a fresh install
        assert_eq!(target, Slot::B);

        // An image spanning 2.5 blocks so the tail block is zero-padded.
        let image: Vec<u8> = (0..(BLOCK_SIZE * 2 + 100))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();

        write_image_to_slot(&mut dev, target, &image, &mut state).unwrap();

        // The target was left un-bootable — a separate finish must flip it.
        assert!(!state.slot(target).is_bootable());
        // All bytes are on the device and read back identically.
        assert_eq!(read_back(&dev, image.len()), image);
    }

    #[test]
    fn slot_is_unbootable_until_a_separate_finish() {
        let mut dev = MemBlockDevice::new(4);
        let mut state = AbState::new();
        let target = state.target_slot();
        let image = vec![0x5Au8; BLOCK_SIZE];

        write_image_to_slot(&mut dev, target, &image, &mut state).unwrap();
        assert!(!state.slot(target).is_bootable());

        // Only an explicit finish makes it the boot slot (WS11-05.7 territory).
        state.finish_update(target);
        assert!(state.slot(target).is_bootable());
        assert_eq!(state.boot_slot(), Some(target));
    }

    #[test]
    fn oversized_image_fails_closed() {
        // Two-block slot, three-block image.
        let mut dev = MemBlockDevice::new(2);
        let mut state = AbState::new();
        let target = state.target_slot();
        let image = vec![0xFFu8; BLOCK_SIZE * 3];

        let err = write_image_to_slot(&mut dev, target, &image, &mut state).unwrap_err();
        assert_eq!(
            err,
            SlotWriteError::ImageTooLarge {
                image_len: (BLOCK_SIZE * 3) as u64,
                slot_capacity: (BLOCK_SIZE * 2) as u64,
            }
        );
        // Fail-closed: the slot stays un-bootable.
        assert!(!state.slot(target).is_bootable());
    }

    #[test]
    fn mid_write_failure_leaves_slot_unbootable() {
        // The seam fails at block 2; the first two blocks write, then error.
        let mut dev = FailAtWrite {
            inner: MemBlockDevice::new(8),
            fail_at: 2,
        };
        let mut state = AbState::new();
        let target = state.target_slot();
        let image = vec![0x11u8; BLOCK_SIZE * 4];

        let err = write_image_to_slot(&mut dev, target, &image, &mut state).unwrap_err();
        assert_eq!(err, SlotWriteError::Device(V3Error::Io));
        // A partial write must never leave a bootable slot.
        assert!(!state.slot(target).is_bootable());
    }

    #[test]
    fn refuses_to_flash_the_active_slot() {
        let mut dev = MemBlockDevice::new(4);
        let mut state = AbState::new();
        let active = state.boot_slot().unwrap(); // A on a fresh install
        let before = state.slot(active);
        let image = vec![0u8; BLOCK_SIZE];

        let err = write_image_to_slot(&mut dev, active, &image, &mut state).unwrap_err();
        assert_eq!(err, SlotWriteError::SlotInUse);
        // The refusal happens before any state change: the active slot is intact.
        assert_eq!(state.slot(active), before);
        assert!(state.slot(active).is_bootable());
    }
}

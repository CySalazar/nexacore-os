//! Lazy block-device trait and an in-memory implementation (WS3-01.1).
//!
//! v0–v2 mounted a whole volume as one `&[u8]`, capping the volume at 128
//! blocks (ADR-0037). v3 instead talks to a [`BlockDevice`]: blocks are read
//! and written on demand, [`BlockDevice::flush`] orders writes to the backing
//! store, and [`BlockDevice::commit_root`] records the durable commit point of
//! a superblock generation (the atomic-commit barrier the dual-superblock layer
//! relies on, WS3-01.2). This removes the volume-size cap and is the
//! prerequisite for every other v3 feature (ADR-0051 D6).

// Block indices fit usize on the 64-bit targets NexaCore supports; the
// `u64 as usize` conversions are checked against `block_count`.
#![allow(clippy::cast_possible_truncation)]

use alloc::{vec, vec::Vec};

use super::{BLOCK_SIZE, Block, V3Error};

/// A lazily-accessed block device: the substrate every v3 object lives on.
pub trait BlockDevice {
    /// Number of addressable blocks.
    fn block_count(&self) -> u64;

    /// Read block `index` into `out`.
    ///
    /// # Errors
    /// [`V3Error::BlockOutOfRange`] if `index >= block_count`, or
    /// [`V3Error::Io`] on a backing-store failure.
    fn read_block(&self, index: u64, out: &mut Block) -> Result<(), V3Error>;

    /// Write `data` to block `index`. The write need not be durable until
    /// [`BlockDevice::flush`].
    ///
    /// # Errors
    /// [`V3Error::BlockOutOfRange`] if `index >= block_count`, or
    /// [`V3Error::Io`] on a backing-store failure.
    fn write_block(&mut self, index: u64, data: &Block) -> Result<(), V3Error>;

    /// Order all prior writes to the backing store.
    ///
    /// # Errors
    /// [`V3Error::Io`] on a backing-store failure.
    fn flush(&mut self) -> Result<(), V3Error>;

    /// Record `generation` as the durably-committed superblock generation,
    /// after the slot carrying it has been flushed. A crash before this call
    /// leaves the previous generation as the mount point.
    ///
    /// # Errors
    /// [`V3Error::Io`] on a backing-store failure.
    fn commit_root(&mut self, generation: u64) -> Result<(), V3Error>;

    /// The last generation passed to [`BlockDevice::commit_root`] (`0` if none).
    fn committed_generation(&self) -> u64;
}

/// In-memory [`BlockDevice`] for host tests and `mkfs` staging.
#[derive(Debug, Clone)]
pub struct MemBlockDevice {
    blocks: Vec<u8>,
    count: u64,
    committed_generation: u64,
    flushes: u64,
}

impl MemBlockDevice {
    /// Allocate a zeroed device of `block_count` blocks.
    #[must_use]
    pub fn new(block_count: u64) -> Self {
        let len = (block_count as usize).saturating_mul(BLOCK_SIZE);
        Self {
            blocks: vec![0u8; len],
            count: block_count,
            committed_generation: 0,
            flushes: 0,
        }
    }

    /// How many times [`BlockDevice::flush`] has been called (test
    /// observability for the commit ordering).
    #[must_use]
    pub const fn flush_count(&self) -> u64 {
        self.flushes
    }

    fn span(&self, index: u64) -> Option<core::ops::Range<usize>> {
        if index >= self.count {
            return None;
        }
        let start = (index as usize).checked_mul(BLOCK_SIZE)?;
        let end = start.checked_add(BLOCK_SIZE)?;
        if end <= self.blocks.len() {
            Some(start..end)
        } else {
            None
        }
    }
}

impl BlockDevice for MemBlockDevice {
    fn block_count(&self) -> u64 {
        self.count
    }

    fn read_block(&self, index: u64, out: &mut Block) -> Result<(), V3Error> {
        let span = self.span(index).ok_or(V3Error::BlockOutOfRange)?;
        let src = self.blocks.get(span).ok_or(V3Error::Io)?;
        out.copy_from_slice(src);
        Ok(())
    }

    fn write_block(&mut self, index: u64, data: &Block) -> Result<(), V3Error> {
        let span = self.span(index).ok_or(V3Error::BlockOutOfRange)?;
        let dst = self.blocks.get_mut(span).ok_or(V3Error::Io)?;
        dst.copy_from_slice(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), V3Error> {
        self.flushes = self.flushes.saturating_add(1);
        Ok(())
    }

    fn commit_root(&mut self, generation: u64) -> Result<(), V3Error> {
        // A real device would persist the pointer in a dedicated commit region;
        // in memory we just record it after the caller has flushed.
        self.committed_generation = generation;
        Ok(())
    }

    fn committed_generation(&self) -> u64 {
        self.committed_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_round_trips() {
        let mut dev = MemBlockDevice::new(8);
        assert_eq!(dev.block_count(), 8);
        let mut block = super::super::zero_block();
        block[0] = 0xAB;
        block[BLOCK_SIZE - 1] = 0xCD;
        dev.write_block(3, &block).unwrap();
        let mut read = super::super::zero_block();
        dev.read_block(3, &mut read).unwrap();
        assert_eq!(read[0], 0xAB);
        assert_eq!(read[BLOCK_SIZE - 1], 0xCD);
        // An untouched block stays zero.
        dev.read_block(0, &mut read).unwrap();
        assert!(read.iter().all(|&b| b == 0));
    }

    #[test]
    fn out_of_range_is_rejected() {
        let mut dev = MemBlockDevice::new(2);
        let block = super::super::zero_block();
        assert_eq!(dev.write_block(2, &block), Err(V3Error::BlockOutOfRange));
        let mut out = super::super::zero_block();
        assert_eq!(dev.read_block(99, &mut out), Err(V3Error::BlockOutOfRange));
    }

    #[test]
    fn commit_root_records_generation_after_flush() {
        let mut dev = MemBlockDevice::new(4);
        assert_eq!(dev.committed_generation(), 0);
        dev.flush().unwrap();
        dev.commit_root(7).unwrap();
        assert_eq!(dev.committed_generation(), 7);
        assert_eq!(dev.flush_count(), 1);
    }
}

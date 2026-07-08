//! LRU block cache, write-back queue, commit write-barrier, and freed-block
//! retention over a [`BlockDevice`] (WS3-03).
//!
//! v3 talks to the disk one 4 KiB [`Block`] at a time ([`super::blockdev`]).
//! Without a cache every read hits the backing store and every write is
//! synchronous. This module adds the durability/performance layer mandated by
//! WS3-03 and NCIP-FS-Wire-027 §S1, *above* the atomic-commit model — recovery
//! stays structural (the mount picks the highest valid dual-superblock
//! generation, WS3-01.2); nothing here persists a transaction log.
//!
//! - [`BlockCache`] — an LRU cache indexed by block number, with dirty tracking
//!   and a write-back queue. Reads are served from the cache on a hit; writes
//!   are buffered and marked dirty. Eviction of a dirty victim writes it back
//!   first, so no buffered write is ever lost.
//! - The **commit write-barrier** ([`BlockCache::commit_superblock`]) enforces
//!   §S1: every dirty object of the new generation is written and *flushed to
//!   durability* before the alternate superblock slot that references them is
//!   committed. A crash between the two leaves the previous generation intact.
//! - [`RetentionTracker`] — freed-block retention bound to the commit
//!   generation: a block freed at generation *N* may not be re-allocated before
//!   *N+1* has committed, nor TRIM-ed before a retention window of generations.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use super::{
    Block, V3Error,
    blockdev::BlockDevice,
    superblock::{self, MacKey, SuperblockV3},
    zero_block,
};

/// One cached block: its contents, whether it holds unwritten changes, and a
/// recency stamp for LRU eviction.
#[derive(Clone)]
struct CacheEntry {
    data: Block,
    dirty: bool,
    last_used: u64,
}

/// An LRU write-back block cache layered over a [`BlockDevice`].
///
/// The cache holds at most `capacity` blocks. A read is served from the cache
/// on a hit and populates it on a miss; a write updates the cached block and
/// marks it dirty, deferring the backing-store write to [`BlockCache::writeback`]
/// (or to eviction, whichever comes first). The superblock slots (blocks
/// [`superblock::SLOT_A`]/[`superblock::SLOT_B`]) are **not** routed through the
/// cache — they are committed directly by [`BlockCache::commit_superblock`],
/// which also enforces the §S1 write-barrier.
pub struct BlockCache<D: BlockDevice> {
    dev: D,
    entries: BTreeMap<u64, CacheEntry>,
    dirty: BTreeSet<u64>,
    capacity: usize,
    clock: u64,
}

impl<D: BlockDevice> BlockCache<D> {
    /// Wrap `dev` in a cache holding at most `capacity` blocks (clamped to at
    /// least one).
    #[must_use]
    pub fn new(dev: D, capacity: usize) -> Self {
        Self {
            dev,
            entries: BTreeMap::new(),
            dirty: BTreeSet::new(),
            capacity: capacity.max(1),
            clock: 0,
        }
    }

    /// The cache capacity in blocks.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of blocks currently resident in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no blocks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether block `index` is currently resident in the cache.
    #[must_use]
    pub fn is_cached(&self, index: u64) -> bool {
        self.entries.contains_key(&index)
    }

    /// Whether block `index` is resident and holds unwritten changes.
    #[must_use]
    pub fn is_dirty(&self, index: u64) -> bool {
        self.dirty.contains(&index)
    }

    /// The number of dirty blocks queued for write-back.
    #[must_use]
    pub fn dirty_len(&self) -> usize {
        self.dirty.len()
    }

    /// The dirty blocks queued for write-back, in ascending block order.
    #[must_use]
    pub fn dirty_blocks(&self) -> Vec<u64> {
        self.dirty.iter().copied().collect()
    }

    /// Borrow the underlying device (e.g. to read committed state).
    #[must_use]
    pub fn device(&self) -> &D {
        &self.dev
    }

    /// The device's durably-committed superblock generation.
    #[must_use]
    pub fn committed_generation(&self) -> u64 {
        self.dev.committed_generation()
    }

    /// Consume the cache and return the underlying device. Any dirty blocks not
    /// yet written back are dropped, so callers should [`BlockCache::sync`]
    /// first if durability is required.
    #[must_use]
    pub fn into_device(self) -> D {
        self.dev
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    /// Evict least-recently-used entries until the cache is within capacity,
    /// never evicting `protect` (the entry just touched). A dirty victim is
    /// written back before being dropped.
    fn evict_to_capacity(&mut self, protect: u64) -> Result<(), V3Error> {
        while self.entries.len() > self.capacity {
            let victim = self
                .entries
                .iter()
                .filter(|&(&idx, _)| idx != protect)
                .min_by_key(|&(_, entry)| entry.last_used)
                .map(|(&idx, _)| idx);
            let Some(victim) = victim else { break };
            if let Some(entry) = self.entries.remove(&victim) {
                if entry.dirty {
                    self.dev.write_block(victim, &entry.data)?;
                    self.dirty.remove(&victim);
                }
            }
        }
        Ok(())
    }

    /// Read block `index` into `out`, from the cache on a hit or the backing
    /// store on a miss (populating the cache).
    ///
    /// # Errors
    /// [`V3Error::BlockOutOfRange`] if `index` is outside the device, or
    /// [`V3Error::Io`] on a backing-store failure.
    pub fn read(&mut self, index: u64, out: &mut Block) -> Result<(), V3Error> {
        let now = self.tick();
        if let Some(entry) = self.entries.get_mut(&index) {
            entry.last_used = now;
            out.copy_from_slice(&entry.data);
            return Ok(());
        }
        let mut data = zero_block();
        self.dev.read_block(index, &mut data)?;
        out.copy_from_slice(&data);
        self.entries.insert(
            index,
            CacheEntry {
                data,
                dirty: false,
                last_used: now,
            },
        );
        self.evict_to_capacity(index)?;
        Ok(())
    }

    /// Buffer a write of `data` to block `index`, marking it dirty for later
    /// write-back. The block is validated against the device bounds so an
    /// out-of-range write fails fast rather than surfacing at write-back.
    ///
    /// # Errors
    /// [`V3Error::BlockOutOfRange`] if `index` is outside the device.
    pub fn write(&mut self, index: u64, data: &Block) -> Result<(), V3Error> {
        if index >= self.dev.block_count() {
            return Err(V3Error::BlockOutOfRange);
        }
        let now = self.tick();
        match self.entries.get_mut(&index) {
            Some(entry) => {
                entry.data.copy_from_slice(data);
                entry.dirty = true;
                entry.last_used = now;
            }
            None => {
                self.entries.insert(
                    index,
                    CacheEntry {
                        data: *data,
                        dirty: true,
                        last_used: now,
                    },
                );
            }
        }
        self.dirty.insert(index);
        self.evict_to_capacity(index)?;
        Ok(())
    }

    /// Write every dirty block to the backing store (in ascending block order)
    /// and clear the write-back queue, returning the number of blocks written.
    /// The writes are issued but not necessarily durable — use [`BlockCache::sync`]
    /// or [`BlockCache::commit_superblock`] to order them to durability.
    ///
    /// # Errors
    /// [`V3Error::Io`] on a backing-store failure.
    pub fn writeback(&mut self) -> Result<usize, V3Error> {
        let pending: Vec<u64> = self.dirty.iter().copied().collect();
        let mut written = 0usize;
        for index in pending {
            if let Some(entry) = self.entries.get_mut(&index) {
                if entry.dirty {
                    self.dev.write_block(index, &entry.data)?;
                    entry.dirty = false;
                    written = written.saturating_add(1);
                }
            }
            self.dirty.remove(&index);
        }
        Ok(written)
    }

    /// Write back all dirty blocks and order them to durability
    /// ([`BlockDevice::flush`]) — the periodic write-back path. Returns the
    /// number of blocks written.
    ///
    /// # Errors
    /// [`V3Error::Io`] on a backing-store failure.
    pub fn sync(&mut self) -> Result<usize, V3Error> {
        let written = self.writeback()?;
        self.dev.flush()?;
        Ok(written)
    }

    /// Commit `sb` (its `generation` already incremented) with the §S1 write
    /// barrier: every dirty object of the new generation is written back and
    /// **flushed to durability** *before* the alternate superblock slot that
    /// references them is written and committed. A crash between the barrier
    /// flush and the superblock commit leaves the previous generation as the
    /// mount point.
    ///
    /// # Errors
    /// [`V3Error::Io`] on a backing-store failure.
    pub fn commit_superblock(&mut self, sb: &SuperblockV3, key: &MacKey) -> Result<(), V3Error> {
        // Barrier: new-generation objects durable first …
        self.writeback()?;
        self.dev.flush()?;
        // … then the atomic root commit (write slot → flush → record).
        superblock::commit(&mut self.dev, sb, key)
    }
}

/// Freed-block retention bound to the CoW commit generation (WS3-03.5).
///
/// A block freed while generation *N* is live must not be handed back to the
/// allocator until *N+1* has committed (otherwise a crash could expose it under
/// the still-mountable generation *N*), and must not be TRIM-ed until it has
/// aged past a retention window of generations. This tracker records the
/// generation each freed block was released at and answers both questions
/// against the current committed generation.
#[derive(Debug, Clone)]
pub struct RetentionTracker {
    freed: BTreeMap<u64, u64>,
    window: u64,
}

impl RetentionTracker {
    /// Create a tracker retaining freed blocks for `window` generations before
    /// they become TRIM-able (clamped to at least one).
    #[must_use]
    pub fn new(window: u64) -> Self {
        Self {
            freed: BTreeMap::new(),
            window: window.max(1),
        }
    }

    /// The retention window, in generations.
    #[must_use]
    pub fn window(&self) -> u64 {
        self.window
    }

    /// Record that `block` was freed while `generation` was live.
    pub fn free_at(&mut self, block: u64, generation: u64) {
        self.freed.insert(block, generation);
    }

    /// The number of freed blocks still being retained.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.freed.len()
    }

    /// Whether nothing is being retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.freed.is_empty()
    }

    /// Whether `block` (freed at generation *N*) may be re-allocated now, i.e.
    /// the current `committed` generation is at least *N+1*.
    #[must_use]
    pub fn is_reusable(&self, block: u64, committed: u64) -> bool {
        self.freed
            .get(&block)
            .is_some_and(|&freed| committed > freed)
    }

    /// All retained blocks that may be re-allocated at `committed`, ascending.
    #[must_use]
    pub fn reusable(&self, committed: u64) -> Vec<u64> {
        self.freed
            .iter()
            .filter(|&(_, &freed)| committed > freed)
            .map(|(&block, _)| block)
            .collect()
    }

    /// Whether `block` (freed at generation *N*) may be TRIM-ed now, i.e. the
    /// current `committed` generation is at least *N + window*.
    #[must_use]
    pub fn is_trimmable(&self, block: u64, committed: u64) -> bool {
        self.freed
            .get(&block)
            .is_some_and(|&freed| committed >= freed.saturating_add(self.window))
    }

    /// All retained blocks that may be TRIM-ed at `committed`, ascending.
    #[must_use]
    pub fn trimmable(&self, committed: u64) -> Vec<u64> {
        self.freed
            .iter()
            .filter(|&(_, &freed)| committed >= freed.saturating_add(self.window))
            .map(|(&block, _)| block)
            .collect()
    }

    /// Stop retaining `block` (after it has been re-allocated or TRIM-ed),
    /// returning whether it was being tracked.
    pub fn release(&mut self, block: u64) -> bool {
        self.freed.remove(&block).is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{super::blockdev::MemBlockDevice, *};

    fn block_of(byte: u8) -> Block {
        let mut b = zero_block();
        b[0] = byte;
        b[super::super::BLOCK_SIZE - 1] = byte;
        b
    }

    #[test]
    fn read_miss_populates_then_hit_serves_from_cache() {
        let mut dev = MemBlockDevice::new(8);
        dev.write_block(3, &block_of(0x11)).unwrap();
        let mut cache = BlockCache::new(dev, 4);

        assert!(cache.is_empty());
        let mut out = zero_block();
        cache.read(3, &mut out).unwrap();
        assert_eq!(out[0], 0x11);
        assert!(cache.is_cached(3));
        assert_eq!(cache.len(), 1);
        // A second read is a hit (still correct), not dirtied.
        cache.read(3, &mut out).unwrap();
        assert_eq!(out[0], 0x11);
        assert!(!cache.is_dirty(3));
    }

    #[test]
    fn write_is_buffered_then_written_back() {
        let dev = MemBlockDevice::new(8);
        let mut cache = BlockCache::new(dev, 4);

        cache.write(2, &block_of(0xAA)).unwrap();
        cache.write(5, &block_of(0xBB)).unwrap();
        assert_eq!(cache.dirty_len(), 2);
        assert_eq!(cache.dirty_blocks(), alloc::vec![2, 5]);
        // The device has not seen the writes yet.
        let mut probe = zero_block();
        cache.device().read_block(2, &mut probe).unwrap();
        assert_eq!(probe[0], 0x00);

        let n = cache.writeback().unwrap();
        assert_eq!(n, 2);
        assert_eq!(cache.dirty_len(), 0);
        cache.device().read_block(2, &mut probe).unwrap();
        assert_eq!(probe[0], 0xAA);
        cache.device().read_block(5, &mut probe).unwrap();
        assert_eq!(probe[0], 0xBB);
    }

    #[test]
    fn out_of_range_write_fails_fast() {
        let dev = MemBlockDevice::new(4);
        let mut cache = BlockCache::new(dev, 4);
        assert_eq!(cache.write(4, &block_of(1)), Err(V3Error::BlockOutOfRange));
        assert!(cache.is_empty());
        assert_eq!(cache.dirty_len(), 0);
    }

    #[test]
    fn eviction_writes_back_dirty_victim() {
        let dev = MemBlockDevice::new(16);
        // Capacity 2 forces eviction on the third distinct block.
        let mut cache = BlockCache::new(dev, 2);
        cache.write(2, &block_of(0x22)).unwrap();
        cache.write(3, &block_of(0x33)).unwrap();
        // Touch 2 so 3 becomes the LRU victim.
        let mut out = zero_block();
        cache.read(2, &mut out).unwrap();
        cache.write(4, &block_of(0x44)).unwrap();

        assert!(cache.len() <= 2);
        assert!(!cache.is_cached(3));
        // The evicted dirty block was written back, not lost.
        let mut probe = zero_block();
        cache.device().read_block(3, &mut probe).unwrap();
        assert_eq!(probe[0], 0x33);
    }

    fn key() -> MacKey {
        [7u8; 32]
    }

    fn sb(generation: u64) -> SuperblockV3 {
        SuperblockV3 {
            generation,
            total_blocks: 16,
            root_dir_inode: 2,
            merkle_root: [0u8; 32],
            key_epoch: 0,
            free_blocks: 10,
            inode_count: 1,
            alloc_map_block: 4,
            snapshot_table_block: 0,
        }
    }

    #[test]
    fn commit_barrier_flushes_objects_before_superblock() {
        let dev = MemBlockDevice::new(16);
        let mut cache = BlockCache::new(dev, 8);

        // New-generation objects (blocks 2..6), still only in the cache.
        for idx in 2u64..6 {
            let byte = u8::try_from(idx).unwrap();
            cache.write(idx, &block_of(byte)).unwrap();
        }
        assert_eq!(cache.dirty_len(), 4);
        assert_eq!(cache.committed_generation(), 0);

        cache.commit_superblock(&sb(1), &key()).unwrap();

        // After commit: objects are durable on the device …
        assert_eq!(cache.dirty_len(), 0);
        let mut probe = zero_block();
        for idx in 2u64..6 {
            let byte = u8::try_from(idx).unwrap();
            cache.device().read_block(idx, &mut probe).unwrap();
            assert_eq!(probe[0], byte, "object {idx} not durable");
        }
        // … and the superblock generation is committed. flush ran twice:
        // once for the object barrier, once inside superblock::commit.
        assert_eq!(cache.committed_generation(), 1);
        assert!(cache.device().flush_count() >= 2);
    }

    #[test]
    fn crash_before_commit_keeps_old_generation() {
        let dev = MemBlockDevice::new(16);
        let mut cache = BlockCache::new(dev, 8);
        cache.write(2, &block_of(0x99)).unwrap();
        // Periodic write-back can run without advancing the commit point.
        cache.sync().unwrap();
        assert_eq!(cache.committed_generation(), 0);
    }

    #[test]
    fn retention_gates_reuse_and_trim_by_generation() {
        let mut ret = RetentionTracker::new(3);
        assert_eq!(ret.window(), 3);
        assert!(ret.is_empty());

        // Block 40 freed while generation 5 was live.
        ret.free_at(40, 5);
        assert_eq!(ret.pending_len(), 1);

        // Not reusable until generation 6 commits …
        assert!(!ret.is_reusable(40, 5));
        assert!(ret.is_reusable(40, 6));
        assert_eq!(ret.reusable(5), Vec::<u64>::new());
        assert_eq!(ret.reusable(6), alloc::vec![40]);

        // … and not TRIM-able until generation 5 + window(3) = 8.
        assert!(!ret.is_trimmable(40, 7));
        assert!(ret.is_trimmable(40, 8));
        assert_eq!(ret.trimmable(7), Vec::<u64>::new());
        assert_eq!(ret.trimmable(8), alloc::vec![40]);

        // Releasing stops tracking.
        assert!(ret.release(40));
        assert!(!ret.release(40));
        assert!(ret.is_empty());
        // An untracked block is never reusable/trimmable.
        assert!(!ret.is_reusable(40, 100));
        assert!(!ret.is_trimmable(40, 100));
    }

    #[test]
    fn retention_window_is_clamped_to_one() {
        let ret = RetentionTracker::new(0);
        assert_eq!(ret.window(), 1);
    }
}

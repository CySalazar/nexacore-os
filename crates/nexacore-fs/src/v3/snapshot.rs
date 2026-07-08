//! O(1) snapshots: retained roots + writable clones (WS3-01.10).
//!
//! A snapshot is just the set of committed roots at one generation — the root
//! directory, the Merkle root and the key epoch (a [`SnapshotEntry`]). Taking
//! one is O(1): it records those scalars from the live superblock, copying no
//! data ([`SnapshotTable::take`]). Because the v3 format is copy-on-write, the
//! snapshot's blocks stay valid as long as they are *retained* — their
//! [`super::extent::AllocMap`] refcounts are held above zero ([`retain`]), so a
//! later write to a shared block copies instead of overwriting.
//!
//! A **writable clone** ([`clone_from`]) starts a new generation seeded from a
//! snapshot's roots; it then diverges from the snapshot through ordinary CoW.

// `buf.len() / ENTRY_LEN` is an exact entry count.
#![allow(clippy::integer_division)]

use alloc::vec::Vec;

use super::{V3Error, extent::AllocMap, merkle, superblock::SuperblockV3};

/// Encoded size of a [`SnapshotEntry`].
pub const ENTRY_LEN: usize = 64;

/// A retained set of roots identifying a point-in-time snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Caller-assigned snapshot id.
    pub id: u64,
    /// Generation the snapshot was taken at.
    pub generation: u64,
    /// Root directory inode retained by the snapshot.
    pub root_dir_inode: u64,
    /// Merkle integrity root at the snapshot generation.
    pub merkle_root: merkle::Hash,
    /// Key epoch in effect at the snapshot generation.
    pub key_epoch: u64,
}

impl SnapshotEntry {
    /// Encode to [`ENTRY_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut b = [0u8; ENTRY_LEN];
        b[0..8].copy_from_slice(&self.id.to_le_bytes());
        b[8..16].copy_from_slice(&self.generation.to_le_bytes());
        b[16..24].copy_from_slice(&self.root_dir_inode.to_le_bytes());
        b[24..56].copy_from_slice(&self.merkle_root);
        b[56..64].copy_from_slice(&self.key_epoch.to_le_bytes());
        b
    }

    /// Decode from a byte slice (`None` if shorter than [`ENTRY_LEN`]).
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        let id = u64::from_le_bytes(buf.get(0..8)?.try_into().ok()?);
        let generation = u64::from_le_bytes(buf.get(8..16)?.try_into().ok()?);
        let root_dir_inode = u64::from_le_bytes(buf.get(16..24)?.try_into().ok()?);
        let merkle_root: merkle::Hash = buf.get(24..56)?.try_into().ok()?;
        let key_epoch = u64::from_le_bytes(buf.get(56..64)?.try_into().ok()?);
        Some(Self {
            id,
            generation,
            root_dir_inode,
            merkle_root,
            key_epoch,
        })
    }
}

/// The volume's table of live snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotTable {
    entries: Vec<SnapshotEntry>,
}

impl SnapshotTable {
    /// New empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// All snapshots.
    #[must_use]
    pub fn entries(&self) -> &[SnapshotEntry] {
        &self.entries
    }

    /// Number of snapshots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if there are no snapshots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Take a snapshot of `sb`'s current roots under `id` — O(1), copies no data.
    /// Returns the new entry, or [`V3Error::InvalidName`] if `id` already exists.
    ///
    /// # Errors
    /// [`V3Error::InvalidName`] if `id` is already in the table.
    pub fn take(&mut self, id: u64, sb: &SuperblockV3) -> Result<SnapshotEntry, V3Error> {
        if self.get(id).is_some() {
            return Err(V3Error::InvalidName);
        }
        let entry = SnapshotEntry {
            id,
            generation: sb.generation,
            root_dir_inode: sb.root_dir_inode,
            merkle_root: sb.merkle_root,
            key_epoch: sb.key_epoch,
        };
        self.entries.push(entry);
        Ok(entry)
    }

    /// Look up a snapshot by id.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<SnapshotEntry> {
        self.entries.iter().copied().find(|e| e.id == id)
    }

    /// Delete a snapshot by id; returns it if present. (Reclaiming its
    /// now-unreferenced blocks is the allocator's job via `AllocMap::decref`.)
    pub fn delete(&mut self, id: u64) -> Option<SnapshotEntry> {
        let pos = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.remove(pos))
    }

    /// Encode the table to its on-disk byte sequence.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.entries.len() * ENTRY_LEN);
        for e in &self.entries {
            v.extend_from_slice(&e.encode());
        }
        v
    }

    /// Decode a table from its on-disk bytes.
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] if the buffer length is not a multiple of
    /// [`ENTRY_LEN`] or an entry fails to decode.
    pub fn decode(buf: &[u8]) -> Result<Self, V3Error> {
        if buf.len() % ENTRY_LEN != 0 {
            return Err(V3Error::Corrupt);
        }
        let mut entries = Vec::with_capacity(buf.len() / ENTRY_LEN);
        for chunk in buf.chunks(ENTRY_LEN) {
            entries.push(SnapshotEntry::decode(chunk).ok_or(V3Error::Corrupt)?);
        }
        Ok(Self { entries })
    }
}

/// Start a writable clone seeded from a snapshot.
///
/// Returns a new superblock at `current.generation + 1` carrying `snapshot`'s
/// roots; the clone then diverges from the snapshot through ordinary CoW.
#[must_use]
pub fn clone_from(snapshot: &SnapshotEntry, current: &SuperblockV3) -> SuperblockV3 {
    SuperblockV3 {
        generation: current.generation + 1,
        root_dir_inode: snapshot.root_dir_inode,
        merkle_root: snapshot.merkle_root,
        key_epoch: snapshot.key_epoch,
        ..*current
    }
}

/// Retain a snapshot's live `blocks` by bumping their allocation refcounts.
///
/// A later write to a now-shared block copies-on-write instead of overwriting
/// it. The block list comes from walking the snapshot's object tree (WS3-01.3).
///
/// # Errors
/// [`V3Error::BlockOutOfRange`] if a block index is not tracked.
pub fn retain(alloc: &mut AllocMap, blocks: &[u64]) -> Result<(), V3Error> {
    for &b in blocks {
        alloc.incref(b)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // The fixture casts a generation counter into a marker byte.
    #![allow(clippy::cast_possible_truncation)]
    use super::*;

    fn sb(g: u64) -> SuperblockV3 {
        SuperblockV3 {
            generation: g,
            total_blocks: 256,
            root_dir_inode: 1,
            merkle_root: [g as u8; 32],
            key_epoch: 4,
            free_blocks: 200,
            inode_count: 3,
            alloc_map_block: 2,
            snapshot_table_block: 5,
        }
    }

    #[test]
    fn take_records_roots_in_o1() {
        let mut t = SnapshotTable::new();
        let snap = t.take(1, &sb(7)).unwrap();
        assert_eq!(snap.generation, 7);
        assert_eq!(snap.root_dir_inode, 1);
        assert_eq!(snap.key_epoch, 4);
        assert_eq!(t.len(), 1);
        // take() only read the superblock struct — no block device was touched.
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut t = SnapshotTable::new();
        t.take(1, &sb(1)).unwrap();
        assert_eq!(t.take(1, &sb(2)), Err(V3Error::InvalidName));
    }

    #[test]
    fn get_and_delete() {
        let mut t = SnapshotTable::new();
        t.take(10, &sb(3)).unwrap();
        t.take(20, &sb(4)).unwrap();
        assert!(t.get(10).is_some());
        let removed = t.delete(10).unwrap();
        assert_eq!(removed.id, 10);
        assert!(t.get(10).is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn entry_round_trips() {
        let e = SnapshotEntry {
            id: 5,
            generation: 9,
            root_dir_inode: 1,
            merkle_root: [0xAB; 32],
            key_epoch: 2,
        };
        assert_eq!(SnapshotEntry::decode(&e.encode()), Some(e));
    }

    #[test]
    fn table_round_trips_and_rejects_ragged() {
        let mut t = SnapshotTable::new();
        t.take(1, &sb(1)).unwrap();
        t.take(2, &sb(2)).unwrap();
        let bytes = t.encode();
        assert_eq!(bytes.len(), 2 * ENTRY_LEN);
        assert_eq!(SnapshotTable::decode(&bytes).unwrap(), t);
        assert_eq!(
            SnapshotTable::decode(&bytes[..bytes.len() - 1]),
            Err(V3Error::Corrupt)
        );
    }

    #[test]
    fn clone_seeds_from_snapshot_at_new_generation() {
        let base = sb(10);
        let mut t = SnapshotTable::new();
        let snap = t.take(1, &sb(7)).unwrap();
        let clone = clone_from(&snap, &base);
        assert_eq!(clone.generation, 11, "new writable generation");
        assert_eq!(clone.merkle_root, snap.merkle_root, "seeded from snapshot");
        assert_eq!(clone.key_epoch, snap.key_epoch);
        assert_eq!(
            clone.total_blocks, base.total_blocks,
            "volume geometry kept"
        );
    }

    #[test]
    fn retain_makes_blocks_shared_for_cow() {
        let mut alloc = AllocMap::new(16, 4);
        let b = alloc.alloc().unwrap();
        assert!(!alloc.is_shared(b));
        // Snapshot retains the block → now shared → next write must CoW.
        retain(&mut alloc, &[b]).unwrap();
        assert!(alloc.is_shared(b));
    }

    #[test]
    fn retain_out_of_range_errors() {
        let mut alloc = AllocMap::new(4, 0);
        assert_eq!(retain(&mut alloc, &[99]), Err(V3Error::BlockOutOfRange));
    }
}

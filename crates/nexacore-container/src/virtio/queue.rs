//! Split-virtqueue processing over a host-side guest-memory buffer.
//!
//! See `NCIP-Container-006` § 3 and the VIRTIO 1.x specification § 2.7
//! ("Split Virtqueues"). Every virtio device backend consumes guest requests
//! through a *virtqueue*: a triple of guest-memory rings — the **descriptor
//! table**, the driver-owned **available ring**, and the device-owned **used
//! ring**. The guest publishes a descriptor chain and advances the available
//! ring; the host walks the chain, performs the device operation, and signals
//! completion through the used ring.
//!
//! This module implements that mechanism against a [`crate::memory::GuestRam`]
//! backing buffer, so the virtio backends can be driven end-to-end **without a
//! real hypervisor**. All ring access is bounds-checked through `GuestRam`'s
//! accessors; a malformed chain (out-of-range descriptor, `next` cycle longer
//! than the queue) is rejected rather than trusted, which is the security-
//! relevant property for a host that must not trust guest-controlled rings.

// Ring indices are `u16` per the spec; computing byte offsets multiplies them
// up to `u64`. The casts widen and are bounds-checked at the `GuestRam` layer.
#![allow(clippy::cast_lossless, clippy::cast_possible_truncation)]

use crate::memory::GuestRam;

/// Descriptor flag: the descriptor chains to another via its `next` field.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
/// Descriptor flag: the buffer is **write-only** for the device (guest-readable
/// output region).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
/// Descriptor flag: the buffer contains a list of indirect descriptors.
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

/// Size in bytes of one `virtq_desc` descriptor table entry.
pub const DESC_SIZE: u64 = 16;

/// A guest-memory segment referenced by one descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length in bytes.
    pub len: u32,
}

/// A walked descriptor chain, split into device-readable (driver→device) and
/// device-writable (device→driver) segments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DescriptorChain {
    /// Index of the head descriptor (used to signal completion).
    pub head: u16,
    /// Buffers the device reads from (input to the operation).
    pub readable: Vec<Segment>,
    /// Buffers the device writes into (output of the operation).
    pub writable: Vec<Segment>,
}

/// A split virtqueue addressed in guest memory.
///
/// Construct with the guest physical addresses the driver programmed into the
/// device's virtio config space. The host owns the *position* counters
/// (`next_avail` / `next_used`); the rings themselves live in guest RAM.
#[derive(Debug, Clone)]
pub struct SplitQueue {
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    next_avail: u16,
    next_used: u16,
}

impl SplitQueue {
    /// Create a queue of `size` descriptors (MUST be a power of two ≤ 32768) at
    /// the given guest physical ring addresses.
    #[must_use]
    pub fn new(size: u16, desc: u64, avail: u64, used: u64) -> Self {
        Self {
            size,
            desc,
            avail,
            used,
            next_avail: 0,
            next_used: 0,
        }
    }

    /// Queue size (number of descriptors).
    #[must_use]
    pub fn size(&self) -> u16 {
        self.size
    }

    /// The available ring's `idx` field (total descriptors ever published by
    /// the driver, mod 2¹⁶). Returns `None` if the ring is out of bounds.
    #[must_use]
    pub fn avail_idx(&self, ram: &GuestRam) -> Option<u16> {
        // avail ring layout: flags(u16), idx(u16), ring[size](u16)...
        ram.read_u16(self.avail + 2)
    }

    /// Pop the next available descriptor chain, walking its `next` links.
    ///
    /// Returns `None` when no new chain is available, or when the chain is
    /// malformed (descriptor out of range, or a `next` cycle longer than the
    /// queue — which a hostile guest could craft to hang the device).
    #[must_use]
    pub fn pop(&mut self, ram: &GuestRam) -> Option<DescriptorChain> {
        let avail_idx = self.avail_idx(ram)?;
        if self.next_avail == avail_idx {
            return None; // Nothing new published.
        }
        // ring[] starts 4 bytes into the avail structure (after flags+idx).
        let ring_slot = self.next_avail % self.size;
        let head = ram.read_u16(self.avail + 4 + (ring_slot as u64) * 2)?;

        let chain = self.walk(ram, head)?;
        self.next_avail = self.next_avail.wrapping_add(1);
        Some(chain)
    }

    /// Walk the descriptor chain starting at `head`.
    fn walk(&self, ram: &GuestRam, head: u16) -> Option<DescriptorChain> {
        let mut chain = DescriptorChain {
            head,
            ..DescriptorChain::default()
        };
        let mut idx = head;
        // A valid chain visits each descriptor at most once; cap the walk at
        // `size` steps to defeat guest-crafted `next` cycles.
        for _ in 0..self.size {
            if idx >= self.size {
                return None; // Descriptor index out of range.
            }
            let base = self.desc + (idx as u64) * DESC_SIZE;
            let addr = ram.read_u64(base)?;
            let len = ram.read_u32(base + 8)?;
            let flags = ram.read_u16(base + 12)?;
            let next = ram.read_u16(base + 14)?;

            // Indirect descriptors are not supported by these backends.
            if flags & VIRTQ_DESC_F_INDIRECT != 0 {
                return None;
            }
            let seg = Segment { addr, len };
            if flags & VIRTQ_DESC_F_WRITE != 0 {
                chain.writable.push(seg);
            } else {
                chain.readable.push(seg);
            }

            if flags & VIRTQ_DESC_F_NEXT == 0 {
                return Some(chain);
            }
            idx = next;
        }
        None // Chain longer than the queue → malformed.
    }

    /// Signal completion of a chain by writing a used-ring element and bumping
    /// the used `idx`. `len` is the number of bytes the device wrote into the
    /// chain's writable buffers.
    ///
    /// Returns `None` if the used ring is out of bounds.
    #[must_use]
    pub fn add_used(&mut self, ram: &mut GuestRam, head: u16, len: u32) -> Option<()> {
        // used ring layout: flags(u16), idx(u16), ring[size]{id:u32, len:u32}...
        let slot = self.next_used % self.size;
        let elem = self.used + 4 + (slot as u64) * 8;
        ram.write_u32(elem, head as u32)?;
        ram.write_u32(elem + 4, len)?;
        self.next_used = self.next_used.wrapping_add(1);
        ram.write_u16(self.used + 2, self.next_used)?;
        Some(())
    }

    /// The device-owned used `idx` (number of chains completed).
    #[must_use]
    pub fn used_idx(&self, ram: &GuestRam) -> Option<u16> {
        ram.read_u16(self.used + 2)
    }
}

/// Test helper: lay out a power-of-two split virtqueue in guest RAM and return
/// the ring addresses. Public within the crate so backend tests can reuse it.
#[cfg(test)]
pub(crate) fn place_queue(_size: u16) -> (GuestRam, u64, u64, u64) {
    // desc table at 0x1000, avail at 0x2000, used at 0x3000 — generously spaced.
    let ram = GuestRam::new(0x8000);
    (ram, 0x1000, 0x2000, 0x3000)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// Write a descriptor into the table.
    fn write_desc(ram: &mut GuestRam, desc: u64, idx: u16, seg: Segment, flags: u16, next: u16) {
        let base = desc + (idx as u64) * DESC_SIZE;
        ram.write_slice(base, &seg.addr.to_le_bytes()).unwrap();
        ram.write_u32(base + 8, seg.len).unwrap();
        ram.write_u16(base + 12, flags).unwrap();
        ram.write_u16(base + 14, next).unwrap();
    }

    /// Publish `head` into the avail ring and bump its idx.
    fn publish(ram: &mut GuestRam, avail: u64, slot: u16, head: u16, new_idx: u16) {
        ram.write_u16(avail + 4 + (slot as u64) * 2, head).unwrap();
        ram.write_u16(avail + 2, new_idx).unwrap();
    }

    #[test]
    fn pop_returns_none_when_empty() {
        let (ram, desc, avail, used) = place_queue(8);
        let mut q = SplitQueue::new(8, desc, avail, used);
        assert!(q.pop(&ram).is_none());
    }

    #[test]
    fn pop_walks_single_writable_descriptor() {
        let (mut ram, desc, avail, used) = place_queue(8);
        write_desc(
            &mut ram,
            desc,
            0,
            Segment {
                addr: 0x4000,
                len: 16,
            },
            VIRTQ_DESC_F_WRITE,
            0,
        );
        publish(&mut ram, avail, 0, 0, 1);

        let mut q = SplitQueue::new(8, desc, avail, used);
        let chain = q.pop(&ram).expect("chain");
        assert_eq!(chain.head, 0);
        assert!(chain.readable.is_empty());
        assert_eq!(
            chain.writable,
            vec![Segment {
                addr: 0x4000,
                len: 16
            }]
        );
        // Second pop sees nothing new.
        assert!(q.pop(&ram).is_none());
    }

    #[test]
    fn pop_walks_chained_readable_then_writable() {
        let (mut ram, desc, avail, used) = place_queue(8);
        write_desc(
            &mut ram,
            desc,
            0,
            Segment {
                addr: 0x4000,
                len: 8,
            },
            VIRTQ_DESC_F_NEXT,
            1,
        );
        write_desc(
            &mut ram,
            desc,
            1,
            Segment {
                addr: 0x5000,
                len: 32,
            },
            VIRTQ_DESC_F_WRITE,
            0,
        );
        publish(&mut ram, avail, 0, 0, 1);

        let mut q = SplitQueue::new(8, desc, avail, used);
        let chain = q.pop(&ram).expect("chain");
        assert_eq!(
            chain.readable,
            vec![Segment {
                addr: 0x4000,
                len: 8
            }]
        );
        assert_eq!(
            chain.writable,
            vec![Segment {
                addr: 0x5000,
                len: 32
            }]
        );
    }

    #[test]
    fn malformed_out_of_range_descriptor_rejected() {
        let (mut ram, desc, avail, used) = place_queue(4);
        // head index 9 ≥ size 4.
        publish(&mut ram, avail, 0, 9, 1);
        let mut q = SplitQueue::new(4, desc, avail, used);
        assert!(q.pop(&ram).is_none());
    }

    #[test]
    fn malformed_next_cycle_rejected() {
        let (mut ram, desc, avail, used) = place_queue(4);
        // Descriptor 0 -> 1 -> 0 -> ... cycle.
        write_desc(
            &mut ram,
            desc,
            0,
            Segment {
                addr: 0x4000,
                len: 8,
            },
            VIRTQ_DESC_F_NEXT,
            1,
        );
        write_desc(
            &mut ram,
            desc,
            1,
            Segment {
                addr: 0x5000,
                len: 8,
            },
            VIRTQ_DESC_F_NEXT,
            0,
        );
        publish(&mut ram, avail, 0, 0, 1);
        let mut q = SplitQueue::new(4, desc, avail, used);
        assert!(q.pop(&ram).is_none());
    }

    #[test]
    fn add_used_writes_element_and_bumps_idx() {
        let (mut ram, desc, avail, used) = place_queue(8);
        let mut q = SplitQueue::new(8, desc, avail, used);
        assert_eq!(q.used_idx(&ram), Some(0));
        q.add_used(&mut ram, 3, 16).expect("add_used");
        assert_eq!(q.used_idx(&ram), Some(1));
        // The used element records id=3, len=16.
        assert_eq!(ram.read_u32(used + 4), Some(3));
        assert_eq!(ram.read_u32(used + 8), Some(16));
    }
}

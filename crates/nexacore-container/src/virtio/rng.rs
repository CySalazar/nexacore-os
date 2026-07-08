//! `virtio-rng` host-side backend — bridges guest entropy requests to
//! the kernel CSPRNG.
//!
//! See `NCIP-Container-006` § 3. The `virtio-rng` capability is
//! **always granted** to every container; entropy is a non-rivalrous
//! resource and starving a container of randomness is an
//! availability hazard with no defensive value.

use crate::{ContainerError, ContainerResult, memory::GuestRam, virtio::queue::SplitQueue};

/// virtio-rng backend trait.
pub trait VirtioRngBackend: Send + Sync {
    /// Fill the caller's buffer with cryptographically-strong random
    /// bytes from the host CSPRNG (`getrandom`).
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Virtio`] for host-side errors or
    /// [`ContainerError::NotYetImplemented`] in the v0.1 scaffold.
    fn fill(&self, buf: &mut [u8]) -> ContainerResult<()>;
}

/// A host entropy source injected into a [`HostEntropyRng`].
///
/// In production this wraps the kernel CSPRNG (`getrandom`); tests inject a
/// deterministic source so the virtqueue path is reproducible.
pub trait EntropySource: Send + Sync {
    /// Fill `buf` with entropy bytes.
    fn fill(&self, buf: &mut [u8]);
}

/// Functional `virtio-rng` backend that fills guest buffers from an injected
/// [`EntropySource`] and can drain the device request virtqueue end-to-end.
///
/// Entropy is non-rivalrous, so — per `NCIP-Container-006` § 3 — no capability
/// check gates rng; the backend always serves entropy.
#[derive(Debug, Default)]
pub struct HostEntropyRng<S: EntropySource> {
    source: S,
}

impl<S: EntropySource> HostEntropyRng<S> {
    /// Construct from an entropy source.
    pub fn new(source: S) -> Self {
        Self { source }
    }

    /// Service the device request virtqueue: for every available descriptor
    /// chain, fill its writable segments with entropy and signal completion via
    /// the used ring. Returns the number of chains serviced.
    pub fn process_queue(&self, ram: &mut GuestRam, queue: &mut SplitQueue) -> usize {
        let mut serviced = 0;
        while let Some(chain) = queue.pop(ram) {
            let mut written = 0u32;
            for seg in &chain.writable {
                let len = usize::try_from(seg.len).unwrap_or(0);
                let mut buf = vec![0u8; len];
                self.source.fill(&mut buf);
                if ram.write_slice(seg.addr, &buf).is_some() {
                    written = written.saturating_add(seg.len);
                }
            }
            if queue.add_used(ram, chain.head, written).is_some() {
                serviced += 1;
            }
        }
        serviced
    }
}

impl<S: EntropySource> VirtioRngBackend for HostEntropyRng<S> {
    fn fill(&self, buf: &mut [u8]) -> ContainerResult<()> {
        self.source.fill(buf);
        Ok(())
    }
}

/// v0.1 stub.
#[derive(Debug, Default)]
pub struct StubVirtioRng;

impl VirtioRngBackend for StubVirtioRng {
    fn fill(&self, _buf: &mut [u8]) -> ContainerResult<()> {
        Err(ContainerError::NotYetImplemented("virtio::rng::fill"))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    /// Deterministic entropy source: byte `i` = `(seed + i) as u8`.
    #[derive(Debug, Default)]
    struct CountingEntropy {
        seed: u8,
    }
    impl EntropySource for CountingEntropy {
        fn fill(&self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.seed.wrapping_add(i as u8);
            }
        }
    }

    #[test]
    fn stub_fill_returns_not_yet_implemented() {
        let b = StubVirtioRng;
        let mut buf = [0u8; 16];
        let err = b.fill(&mut buf).expect_err("stub");
        assert!(matches!(
            err,
            ContainerError::NotYetImplemented("virtio::rng::fill")
        ));
    }

    #[test]
    fn host_entropy_fills_buffer() {
        let rng = HostEntropyRng::new(CountingEntropy { seed: 10 });
        let mut buf = [0u8; 4];
        rng.fill(&mut buf).expect("fill");
        assert_eq!(buf, [10, 11, 12, 13]);
    }

    #[test]
    fn host_entropy_drains_virtqueue() {
        use crate::virtio::queue::{DESC_SIZE, SplitQueue, VIRTQ_DESC_F_WRITE, place_queue};

        let (mut ram, desc, avail, used) = place_queue(8);
        // One writable descriptor of 8 bytes at guest address 0x4000.
        ram.write_slice(desc, &0x4000u64.to_le_bytes()).unwrap();
        ram.write_u32(desc + 8, 8).unwrap();
        ram.write_u16(desc + 12, VIRTQ_DESC_F_WRITE).unwrap();
        ram.write_u16(desc + 14, 0).unwrap();
        let _ = DESC_SIZE; // documents the descriptor stride used above.
        // Publish head 0.
        ram.write_u16(avail + 4, 0).unwrap();
        ram.write_u16(avail + 2, 1).unwrap();

        let mut q = SplitQueue::new(8, desc, avail, used);
        let rng = HostEntropyRng::new(CountingEntropy { seed: 0 });
        let serviced = rng.process_queue(&mut ram, &mut q);
        assert_eq!(serviced, 1);
        // The writable buffer was filled with the counting pattern.
        assert_eq!(
            ram.read_slice(0x4000, 8),
            Some(&[0, 1, 2, 3, 4, 5, 6, 7][..])
        );
        // The used ring records the completion (id=0, len=8).
        assert_eq!(q.used_idx(&ram), Some(1));
        assert_eq!(ram.read_u32(used + 4), Some(0));
        assert_eq!(ram.read_u32(used + 8), Some(8));
    }
}

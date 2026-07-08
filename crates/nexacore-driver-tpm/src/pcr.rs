//! Measured-boot PCR bank, extend chain, and event log (WS10-05.5/.6/.11).
//!
//! A TPM Platform Configuration Register (PCR) is never written directly; it is
//! *extended*: `PCR_new = H(PCR_old || measurement)`. Because each extend folds
//! the previous value in, a PCR's final value is a tamper-evident summary of the
//! exact sequence of measurements — reorder or alter any one and the value
//! diverges. This module models a bank of PCRs plus the measured-boot event log
//! that records what was measured into each, so the boot chain
//! (bootloader → kernel → initramfs, WS10-05.5) and the started-services
//! manifest (WS10-05.6) can be measured and later replayed/verified (WS10-05.11).
//!
//! The extend hash is injected through [`ExtendHash`] so this crate stays
//! dependency-free and `no_std`; a real TPM SHA-256 bank supplies a SHA-256
//! implementation, while tests use a deterministic stand-in to exercise the
//! chain semantics.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Number of PCRs in a bank (TPM 2.0 defines 24).
pub const PCR_COUNT: usize = 24;
/// PCR digest size in bytes (SHA-256).
pub const PCR_SIZE: usize = 32;

/// A PCR value / measurement digest.
pub type PcrValue = [u8; PCR_SIZE];

/// The hash used to extend PCRs (`H(data) -> digest`). Real TPMs use SHA-256.
pub trait ExtendHash {
    /// Hash `data` into a [`PcrValue`].
    fn hash(&self, data: &[u8]) -> PcrValue;
}

/// An error extending a PCR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrError {
    /// The PCR index is `>= PCR_COUNT`.
    InvalidIndex,
}

/// One measured-boot event: the PCR extended, the measurement folded in, and a
/// human-readable description of what was measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementEvent {
    /// The PCR index extended.
    pub pcr: u8,
    /// The measurement digest folded into the PCR.
    pub digest: PcrValue,
    /// What was measured (e.g. `"kernel"`).
    pub description: String,
}

/// A bank of PCRs with a measured-boot event log.
#[derive(Debug, Clone)]
pub struct PcrBank<H> {
    pcrs: [PcrValue; PCR_COUNT],
    log: Vec<MeasurementEvent>,
    hash: H,
}

impl<H: ExtendHash> PcrBank<H> {
    /// A fresh bank: every PCR is zero (the reset state) and the log is empty.
    #[must_use]
    pub fn new(hash: H) -> Self {
        Self {
            pcrs: [[0u8; PCR_SIZE]; PCR_COUNT],
            log: Vec::new(),
            hash,
        }
    }

    /// The current value of PCR `index`, or `None` if out of range.
    #[must_use]
    pub fn pcr(&self, index: u8) -> Option<PcrValue> {
        self.pcrs.get(usize::from(index)).copied()
    }

    /// Extend PCR `index` with a pre-computed measurement `digest`
    /// (`PCR = H(PCR || digest)`), recording the event. Returns the new value.
    ///
    /// # Errors
    ///
    /// [`PcrError::InvalidIndex`] if `index >= PCR_COUNT`.
    pub fn extend(
        &mut self,
        index: u8,
        digest: &PcrValue,
        description: &str,
    ) -> Result<PcrValue, PcrError> {
        let idx = usize::from(index);
        let current = *self.pcrs.get(idx).ok_or(PcrError::InvalidIndex)?;
        let mut buf = Vec::with_capacity(PCR_SIZE * 2);
        buf.extend_from_slice(&current);
        buf.extend_from_slice(digest);
        let new = self.hash.hash(&buf);
        if let Some(slot) = self.pcrs.get_mut(idx) {
            *slot = new;
        }
        self.log.push(MeasurementEvent {
            pcr: index,
            digest: *digest,
            description: description.to_string(),
        });
        Ok(new)
    }

    /// Measure a component: hash its `bytes` into a digest, then extend PCR
    /// `index` with it. This is the boot-chain measurement step (WS10-05.5) —
    /// each stage measures the next before handing off.
    ///
    /// # Errors
    ///
    /// [`PcrError::InvalidIndex`] if `index >= PCR_COUNT`.
    pub fn measure(
        &mut self,
        index: u8,
        bytes: &[u8],
        description: &str,
    ) -> Result<PcrValue, PcrError> {
        let digest = self.hash.hash(bytes);
        self.extend(index, &digest, description)
    }

    /// The measured-boot event log, in order.
    #[must_use]
    pub fn log(&self) -> &[MeasurementEvent] {
        &self.log
    }

    /// The digests measured into PCR `index`, in order.
    #[must_use]
    pub fn digests_for(&self, index: u8) -> Vec<PcrValue> {
        self.log
            .iter()
            .filter(|e| e.pcr == index)
            .map(|e| e.digest)
            .collect()
    }

    /// Whether PCR `index` equals the replay of `expected_digests` from the
    /// reset state — the attestation check that the chain is exactly as
    /// expected (WS10-05.11).
    #[must_use]
    pub fn matches_expected(&self, index: u8, expected_digests: &[PcrValue]) -> bool {
        self.pcr(index) == Some(replay(&self.hash, expected_digests))
    }
}

/// Replay an extend chain from the reset (all-zero) state: fold each digest in
/// with `PCR = H(PCR || digest)` and return the final value.
#[must_use]
pub fn replay<H: ExtendHash>(hash: &H, digests: &[PcrValue]) -> PcrValue {
    let mut pcr = [0u8; PCR_SIZE];
    for digest in digests {
        let mut buf = Vec::with_capacity(PCR_SIZE * 2);
        buf.extend_from_slice(&pcr);
        buf.extend_from_slice(digest);
        pcr = hash.hash(&buf);
    }
    pcr
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic, order-sensitive stand-in for SHA-256 (FNV-1a spread over
    /// 32 bytes). It is NOT cryptographic — it only exercises the chain logic.
    struct TestHash;

    impl ExtendHash for TestHash {
        fn hash(&self, data: &[u8]) -> PcrValue {
            let mut acc = 0xcbf2_9ce4_8422_2325u64;
            for &b in data {
                acc = (acc ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            let mut out = [0u8; PCR_SIZE];
            for (i, slot) in out.iter_mut().enumerate() {
                let mixed = acc
                    .wrapping_add(i as u64)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15);
                *slot = (mixed >> ((i % 8) * 8)) as u8;
            }
            out
        }
    }

    fn bank() -> PcrBank<TestHash> {
        PcrBank::new(TestHash)
    }

    #[test]
    fn fresh_bank_is_all_zero() {
        let b = bank();
        assert_eq!(b.pcr(0), Some([0u8; PCR_SIZE]));
        assert_eq!(b.pcr(23), Some([0u8; PCR_SIZE]));
        assert_eq!(b.pcr(24), None); // out of range
        assert!(b.log().is_empty());
    }

    #[test]
    fn extend_is_order_sensitive_and_logged() {
        let mut b = bank();
        let a = TestHash.hash(b"component-a");
        let c = TestHash.hash(b"component-c");
        b.extend(4, &a, "a").unwrap();
        let after_ac = b.extend(4, &c, "c").unwrap();

        // A different order yields a different PCR value.
        let mut b2 = bank();
        b2.extend(4, &c, "c").unwrap();
        let after_ca = b2.extend(4, &a, "a").unwrap();
        assert_ne!(after_ac, after_ca);

        // The event log records both measurements in order.
        assert_eq!(b.log().len(), 2);
        assert_eq!(b.log()[0].description, "a");
        assert_eq!(b.log()[1].pcr, 4);
    }

    #[test]
    fn boot_chain_measurement_matches_the_expected_replay() {
        let mut b = bank();
        // Measure the boot chain into PCR 0, the services manifest into PCR 8.
        b.measure(0, b"bootloader-image", "bootloader").unwrap();
        b.measure(0, b"kernel-image", "kernel").unwrap();
        b.measure(0, b"initramfs-image", "initramfs").unwrap();
        b.measure(8, b"services-manifest", "services").unwrap();

        // An independent verifier replays the expected digests.
        let expected_boot = [
            TestHash.hash(b"bootloader-image"),
            TestHash.hash(b"kernel-image"),
            TestHash.hash(b"initramfs-image"),
        ];
        assert!(b.matches_expected(0, &expected_boot));
        assert_eq!(b.digests_for(0), expected_boot.to_vec());

        let expected_services = [TestHash.hash(b"services-manifest")];
        assert!(b.matches_expected(8, &expected_services));

        // A tampered kernel breaks the match.
        let tampered = [
            TestHash.hash(b"bootloader-image"),
            TestHash.hash(b"EVIL-kernel-image"),
            TestHash.hash(b"initramfs-image"),
        ];
        assert!(!b.matches_expected(0, &tampered));
    }

    #[test]
    fn extend_rejects_out_of_range_index() {
        let mut b = bank();
        assert_eq!(
            b.extend(24, &[1u8; PCR_SIZE], "x"),
            Err(PcrError::InvalidIndex)
        );
    }
}

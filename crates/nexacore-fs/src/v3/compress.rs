//! Opt-in per-extent compression, ordered compress → encrypt → tag
//! (WS3-01.11, NCIP-018 §S1.1).
//!
//! An extent may be stored compressed. The security-critical rule is the
//! **order of operations**: the plaintext is compressed *first*, then the
//! compressed bytes are sealed by the AEAD ([`super::block_crypto::seal_block`],
//! which encrypts and authenticates in one step). On read the inverse order is
//! mandatory: the AEAD tag is verified **before** anything is decompressed, so a
//! tampered or truncated extent is rejected and its bytes never reach the
//! decompressor (defeating decompression-bomb and malleability attacks against
//! unauthenticated input).
//!
//! Compression is **opt-in per extent**: it is applied only when it actually
//! shrinks the data; otherwise the extent is stored uncompressed. The choice is
//! recorded in a one-byte flag *inside* the sealed frame — the AEAD therefore
//! authenticates the flag too, so it cannot be flipped to force (or suppress)
//! decompression.
//!
//! The concrete compressor is a seam: the default [`NoCompression`] is the
//! identity, and a real ZSTD backend plugs in behind the [`Compressor`] trait
//! (no vetted `no_std` ZSTD crate is vendored in the workspace yet, mirroring
//! the crypto seams in [`super::block_crypto`]).

use alloc::vec::Vec;

use super::{
    V3Error,
    block_crypto::{Key32, open_block, seal_block},
};

/// The compressed-frame header: a `flag` byte followed by the little-endian
/// `u32` uncompressed length.
const FRAME_HEADER: usize = 5;

/// A pluggable compression backend. The default is identity ([`NoCompression`]);
/// a real ZSTD implementation is library-gated behind this trait.
pub trait Compressor {
    /// Compress `input`. A backend that cannot shrink the input may return it
    /// unchanged — the extent pipeline then stores it uncompressed.
    fn compress(&self, input: &[u8]) -> Vec<u8>;

    /// Decompress `input`, which must expand to exactly `expected_len` bytes.
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] if the input is malformed or does not expand to
    /// `expected_len` (a bound that caps decompression-bomb expansion).
    fn decompress(&self, input: &[u8], expected_len: usize) -> Result<Vec<u8>, V3Error>;
}

/// The identity compressor: never shrinks input, so the extent pipeline always
/// stores uncompressed. The placeholder until a ZSTD backend is vendored.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCompression;

impl Compressor for NoCompression {
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        input.to_vec()
    }

    fn decompress(&self, input: &[u8], expected_len: usize) -> Result<Vec<u8>, V3Error> {
        if input.len() == expected_len {
            Ok(input.to_vec())
        } else {
            Err(V3Error::Corrupt)
        }
    }
}

/// Seal an extent's `plaintext`: compress (if it shrinks), then AEAD-encrypt and
/// tag the framed result, returning `ciphertext ‖ tag`.
///
/// The order is compress → encrypt → tag; the compressed flag and original
/// length are framed inside the sealed payload, so the AEAD authenticates them.
///
/// # Errors
/// [`V3Error::Overflow`] if `plaintext` is longer than `u32::MAX`;
/// [`V3Error::Crypto`] if the AEAD fails.
pub fn seal_extent<C: Compressor>(
    compressor: &C,
    epoch_key: &Key32,
    generation: u64,
    block: u64,
    key_epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, V3Error> {
    let orig_len = u32::try_from(plaintext.len()).map_err(|_| V3Error::Overflow)?;
    let compressed = compressor.compress(plaintext);
    // Opt-in: keep compression only when it actually shrank the extent.
    let (flag, body): (u8, &[u8]) = if compressed.len() < plaintext.len() {
        (1, compressed.as_slice())
    } else {
        (0, plaintext)
    };
    let mut framed = Vec::with_capacity(FRAME_HEADER + body.len());
    framed.push(flag);
    framed.extend_from_slice(&orig_len.to_le_bytes());
    framed.extend_from_slice(body);
    seal_block(epoch_key, generation, block, key_epoch, &framed)
}

/// Open an extent sealed by [`seal_extent`]: verify the AEAD tag, then (only if
/// it verifies) decompress if the framed flag says so, returning the original
/// plaintext.
///
/// # Errors
/// [`V3Error::Crypto`] if the tag does not verify (wrong key/position/epoch,
/// tampering, truncation) — in which case nothing is decompressed;
/// [`V3Error::Corrupt`] if the verified frame is malformed or does not expand to
/// the framed length.
pub fn open_extent<C: Compressor>(
    compressor: &C,
    epoch_key: &Key32,
    generation: u64,
    block: u64,
    key_epoch: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, V3Error> {
    // Tag verification happens here, before any decompression is attempted.
    let framed = open_block(epoch_key, generation, block, key_epoch, ciphertext)?;
    let flag = *framed.first().ok_or(V3Error::Corrupt)?;
    let len_bytes = framed.get(1..FRAME_HEADER).ok_or(V3Error::Corrupt)?;
    let len_array: [u8; 4] = len_bytes.try_into().map_err(|_| V3Error::Corrupt)?;
    let expected_len =
        usize::try_from(u32::from_le_bytes(len_array)).map_err(|_| V3Error::Corrupt)?;
    let body = framed.get(FRAME_HEADER..).ok_or(V3Error::Corrupt)?;
    match flag {
        0 => {
            if body.len() == expected_len {
                Ok(body.to_vec())
            } else {
                Err(V3Error::Corrupt)
            }
        }
        1 => compressor.decompress(body, expected_len),
        _ => Err(V3Error::Corrupt),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use core::cell::Cell;

    use super::*;

    const KEY: Key32 = [0x24; 32];

    /// A trivial run-length compressor that actually shrinks repetitive input,
    /// used to exercise the `compressed == true` path.
    struct Rle;

    impl Compressor for Rle {
        fn compress(&self, input: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            let mut i = 0;
            while let Some(&b) = input.get(i) {
                let mut run = 1usize;
                while run < 255 && input.get(i + run) == Some(&b) {
                    run += 1;
                }
                out.push(u8::try_from(run).unwrap_or(255));
                out.push(b);
                i += run;
            }
            out
        }

        fn decompress(&self, input: &[u8], expected_len: usize) -> Result<Vec<u8>, V3Error> {
            let mut out = Vec::new();
            let mut pairs = input.chunks_exact(2);
            for pair in &mut pairs {
                let (count, byte) = (pair[0], pair[1]);
                for _ in 0..count {
                    out.push(byte);
                }
            }
            if !pairs.remainder().is_empty() || out.len() != expected_len {
                return Err(V3Error::Corrupt);
            }
            Ok(out)
        }
    }

    /// A compressor that records whether `decompress` was ever called, to prove
    /// the read path never decompresses unauthenticated data.
    struct Spy<'a> {
        inner: Rle,
        decompressed: &'a Cell<bool>,
    }

    impl Compressor for Spy<'_> {
        fn compress(&self, input: &[u8]) -> Vec<u8> {
            self.inner.compress(input)
        }
        fn decompress(&self, input: &[u8], expected_len: usize) -> Result<Vec<u8>, V3Error> {
            self.decompressed.set(true);
            self.inner.decompress(input, expected_len)
        }
    }

    #[test]
    fn compressible_data_round_trips_compressed() {
        let plain = [0x7Au8; 400]; // highly compressible
        let sealed = seal_extent(&Rle, &KEY, 3, 9, 0, &plain).unwrap();
        // Compression shrank it: the sealed frame is far smaller than the input.
        assert!(sealed.len() < plain.len());
        let opened = open_extent(&Rle, &KEY, 3, 9, 0, &sealed).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn incompressible_data_is_stored_uncompressed() {
        // A run-length coder expands non-repetitive data, so the pipeline opts
        // out and stores it verbatim (compressed flag 0).
        let plain: Vec<u8> = (0..200u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let sealed = seal_extent(&Rle, &KEY, 1, 2, 0, &plain).unwrap();
        let opened = open_extent(&Rle, &KEY, 1, 2, 0, &sealed).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn no_compression_backend_round_trips() {
        let plain = b"identity backend".to_vec();
        let sealed = seal_extent(&NoCompression, &KEY, 5, 5, 0, &plain).unwrap();
        assert_eq!(
            open_extent(&NoCompression, &KEY, 5, 5, 0, &sealed).unwrap(),
            plain
        );
    }

    #[test]
    fn tampered_extent_is_rejected_before_decompression() {
        let called = Cell::new(false);
        let spy = Spy {
            inner: Rle,
            decompressed: &called,
        };
        let plain = [0x11u8; 300];
        let mut sealed = seal_extent(&spy, &KEY, 7, 1, 0, &plain).unwrap();
        // Flip a ciphertext byte.
        if let Some(byte) = sealed.get_mut(FRAME_HEADER + 2) {
            *byte ^= 0xFF;
        }
        let result = open_extent(&spy, &KEY, 7, 1, 0, &sealed);
        assert_eq!(result.err(), Some(V3Error::Crypto));
        assert!(
            !called.get(),
            "decompressor must not run on unauthenticated data"
        );
    }

    #[test]
    fn wrong_position_fails_to_open() {
        let plain = [0x22u8; 128];
        let sealed = seal_extent(&Rle, &KEY, 4, 8, 0, &plain).unwrap();
        // Opening at a different block number fails the AEAD position binding.
        assert_eq!(
            open_extent(&Rle, &KEY, 4, 9, 0, &sealed).err(),
            Some(V3Error::Crypto)
        );
    }
}

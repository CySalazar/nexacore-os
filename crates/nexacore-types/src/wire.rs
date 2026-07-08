//! Canonical wire encoding (`postcard` 1.x) for the NexaCore OS workspace.
//!
//! This module is the **single audit point** for serialization. Every
//! `Serialize` / `Deserialize` flow that crosses a trust boundary
//! (signing pre-image, mesh wire format, sealed-on-disk envelopes)
//! MUST go through [`encode_canonical`] / [`decode_canonical`] —
//! never call `postcard::*` directly outside this module.
//!
//! The workspace-level `clippy::disallowed_methods` lint (configured in
//! `clippy.toml`) enforces this rule mechanically: a direct call to
//! `postcard::to_allocvec`, `postcard::to_vec`, `postcard::from_bytes`,
//! or `postcard::take_from_bytes` outside this file produces a clippy
//! error.
//!
//! # Why a single audit point
//!
//! 1. The canonical-encoding contract (encoding options, framing, byte
//!    order) is documented here once instead of being re-derived per
//!    call site.
//! 2. A future encoder swap (under a follow-up Standards-Track NCIP) only
//!    needs to change this file plus the workspace dependency entry;
//!    every consumer keeps the same Rust API.
//! 3. Errors from the encoder are mapped to a single
//!    [`NexaCoreError::Wire`] family so downstream code does not need to
//!    pattern-match `postcard::Error` variants.
//!
//! # Canonical-encoding properties
//!
//! `postcard` 1.x with default options produces:
//!
//! - **Self-delimiting** length prefixes (LEB128 varints) on every
//!   `Vec`, `String`, and `Map`.
//! - **One byte sequence per value**: a `Serialize` impl that returns
//!   a value with stable field order produces stable bytes. The
//!   `Serialize` impls in this workspace order fields by textual
//!   declaration; reordering is a wire-format major bump.
//! - **No trailing data**: [`decode_canonical`] rejects inputs with
//!   bytes past the canonical encoding by checking that
//!   `postcard::take_from_bytes` consumes the entire slice. This is the
//!   property that prevents an attacker from smuggling extra data past
//!   a signature pre-image.
//!
//! # Authoritative reference
//!
//! See [`NCIP-Serde-004`](https://github.com/CySalazar/nexacore-os/blob/main/ncips/ncip-serde-004.md)
//! for the migration rationale and the choice of `postcard` over
//! alternatives (bitcode, rkyv, wincode, bincode 1.3.3).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::{NexaCoreError, Result, WireErrorKind};

/// Encode `value` into the canonical wire byte representation.
///
/// The encoding is deterministic and self-delimiting; the same input
/// value always produces the same output bytes, which is the
/// security-critical invariant for signature pre-images.
///
/// # Errors
///
/// Returns [`NexaCoreError::Wire`] with [`WireErrorKind::EncodeFailed`] if
/// the encoder fails. In practice, every `Serialize` impl in NexaCore OS
/// is total over its domain, so reaching this error indicates a bug or
/// an out-of-memory condition.
///
/// # Lint suppression rationale
///
/// `clippy::disallowed_methods` is configured workspace-wide to flag
/// direct calls to `postcard::to_allocvec` outside this module. The
/// `#[allow(clippy::disallowed_methods)]` here is the audit anchor: the
/// only call to the raw encoder lives on this single line, and the
/// surrounding function provides the canonical-error mapping.
#[allow(clippy::disallowed_methods)]
pub fn encode_canonical<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(value)
        .map_err(|_| NexaCoreError::wire(WireErrorKind::EncodeFailed, "wire::encode_canonical"))
}

/// Encode `value` into a caller-provided byte buffer under the canonical
/// wire encoding, returning the number of bytes written.
///
/// This is the **non-allocating** companion to [`encode_canonical`].
/// It is the encoder used on code paths that cannot tolerate a heap
/// allocation — most prominently the kernel panic handler
/// (`NCIP-Kernel-012` §S1) which encodes a structured `PanicRecord` into
/// a `static`-sized buffer while interrupts are already disabled and the
/// allocator may be in an inconsistent state.
///
/// On overflow (the encoded value would not fit in `buf`) the function
/// returns [`NexaCoreError::Wire`] with [`WireErrorKind::EncodeFailed`].
/// The caller MUST handle that case: in the panic-path use case it falls
/// back to a fixed-string overflow marker emitted to the early console.
///
/// # Errors
///
/// - [`NexaCoreError::Wire`] with [`WireErrorKind::EncodeFailed`] if the
///   encoder fails — either because the value cannot be serialized or
///   because `buf` is too small.
///
/// # Lint suppression rationale
///
/// `clippy::disallowed_methods` is configured workspace-wide to flag
/// direct calls to `postcard::to_slice` outside this module. As with
/// [`encode_canonical`], the `#[allow]` here is the audit anchor: the
/// only call to the raw slice encoder lives on this single line, with
/// canonical-error mapping applied around it.
#[allow(clippy::disallowed_methods)]
pub fn encode_into_slice<T: Serialize + ?Sized>(value: &T, buf: &mut [u8]) -> Result<usize> {
    let encoded = postcard::to_slice(value, buf)
        .map_err(|_| NexaCoreError::wire(WireErrorKind::EncodeFailed, "wire::encode_into_slice"))?;
    Ok(encoded.len())
}

/// Decode `bytes` into a value of type `T` under the canonical wire
/// encoding.
///
/// The decoder enforces the **no-trailing-bytes** invariant: if `bytes`
/// contains any data past the canonical encoding of a `T`, the call
/// returns [`NexaCoreError::Wire`] with [`WireErrorKind::TrailingBytes`].
/// This is what prevents an attacker from smuggling extra data past a
/// signature pre-image.
///
/// # Errors
///
/// - [`NexaCoreError::Wire`] with [`WireErrorKind::DecodeFailed`] if the
///   bytes do not parse as a `T` at all (truncated input, wrong type
///   tag, invalid varint, etc.).
/// - [`NexaCoreError::Wire`] with [`WireErrorKind::TrailingBytes`] if the
///   input parsed successfully but bytes remain past the encoding.
///
/// # Lint suppression rationale
///
/// As with [`encode_canonical`], the direct call to
/// `postcard::take_from_bytes` is the only raw decoder invocation in
/// the workspace and is locally allowed via
/// `#[allow(clippy::disallowed_methods)]`.
#[allow(clippy::disallowed_methods)]
pub fn decode_canonical<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    let (value, tail) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| NexaCoreError::wire(WireErrorKind::DecodeFailed, "wire::decode_canonical"))?;
    if !tail.is_empty() {
        return Err(NexaCoreError::wire(
            WireErrorKind::TrailingBytes,
            "wire::decode_canonical",
        ));
    }
    Ok(value)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec, vec::Vec};

    use super::*;
    use crate::error::WireErrorKind;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct SampleStruct {
        a: u32,
        b: String,
        c: Vec<u8>,
    }

    #[test]
    fn encode_decode_round_trip_struct() {
        let value = SampleStruct {
            a: 0xDEAD_BEEF,
            b: String::from("nexacore-os"),
            c: vec![1, 2, 3, 4, 5],
        };
        let bytes = encode_canonical(&value).expect("encode succeeds");
        let decoded: SampleStruct = decode_canonical(&bytes).expect("decode succeeds");
        assert_eq!(decoded, value);
    }

    #[test]
    fn encoding_is_deterministic() {
        // Same value → same bytes. This is the signature-pre-image
        // invariant; if it ever breaks, signatures across nodes diverge.
        let value = SampleStruct {
            a: 42,
            b: String::from("determinism"),
            c: vec![0xAA, 0xBB],
        };
        let a = encode_canonical(&value).expect("encode-a");
        let b = encode_canonical(&value).expect("encode-b");
        assert_eq!(a, b);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let value = 0xCAFE_u32;
        let mut bytes = encode_canonical(&value).expect("encode");
        bytes.push(0x00); // trailing byte
        let err = decode_canonical::<u32>(&bytes).expect_err("must reject trailing");
        match err {
            NexaCoreError::Wire { kind, context } => {
                assert_eq!(kind, WireErrorKind::TrailingBytes);
                assert_eq!(context, "wire::decode_canonical");
            }
            other => panic!("expected Wire::TrailingBytes, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let value = SampleStruct {
            a: 1,
            b: String::from("truncate-me"),
            c: vec![9, 9, 9],
        };
        let bytes = encode_canonical(&value).expect("encode");
        let truncated = &bytes[..bytes.len() - 2];
        let err = decode_canonical::<SampleStruct>(truncated).expect_err("must reject truncated");
        match err {
            NexaCoreError::Wire { kind, context } => {
                assert_eq!(kind, WireErrorKind::DecodeFailed);
                assert_eq!(context, "wire::decode_canonical");
            }
            other => panic!("expected Wire::DecodeFailed, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_empty_input_for_non_unit_type() {
        let err = decode_canonical::<u64>(&[]).expect_err("must reject empty");
        assert!(matches!(
            err,
            NexaCoreError::Wire {
                kind: WireErrorKind::DecodeFailed,
                ..
            }
        ));
    }

    #[test]
    fn vec_u8_round_trip_preserves_length_prefix() {
        // Encoding `Vec<u8>` carries a varint length prefix that the
        // decoder consumes. A 4-byte payload becomes 5 bytes on the
        // wire (1-byte varint for length 4 + 4 raw bytes).
        let payload: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let bytes = encode_canonical(&payload).expect("encode");
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 4); // varint(4) fits in 1 byte
        let decoded: Vec<u8> = decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn unit_type_round_trip_is_zero_bytes() {
        // `()` encodes to zero bytes under postcard. The encode helper
        // must not error on it, and the decode helper must accept an
        // empty slice as the canonical encoding.
        let bytes = encode_canonical(&()).expect("encode unit");
        assert!(bytes.is_empty());
        let _decoded: () = decode_canonical(&bytes).expect("decode unit");
    }

    // -------------------------------------------------------------------------
    // encode_into_slice — non-allocating encoder (NCIP-Kernel-012 K3.b)
    // -------------------------------------------------------------------------

    #[test]
    fn encode_into_slice_matches_encode_canonical_bytes() {
        // The non-allocating slice encoder must produce byte-for-byte
        // identical output to the allocating encoder for any value that
        // fits in the destination buffer. This is the determinism
        // invariant inherited from postcard: same value → same bytes,
        // regardless of which encoder produced them.
        let value = SampleStruct {
            a: 0xCAFE_BABE,
            b: String::from("slice-encoder"),
            c: vec![0x11, 0x22, 0x33, 0x44],
        };
        let allocated = encode_canonical(&value).expect("encode_canonical");
        let mut buf = [0u8; 256];
        let written = encode_into_slice(&value, &mut buf).expect("encode_into_slice");
        assert_eq!(written, allocated.len());
        assert_eq!(&buf[..written], allocated.as_slice());
    }

    #[test]
    fn encode_into_slice_returns_overflow_error_when_buf_too_small() {
        let value = SampleStruct {
            a: 1,
            b: String::from("this-is-too-long-for-an-8-byte-buffer"),
            c: vec![0; 32],
        };
        let mut tiny = [0u8; 8];
        let err = encode_into_slice(&value, &mut tiny).expect_err("must overflow");
        match err {
            NexaCoreError::Wire { kind, context } => {
                assert_eq!(kind, WireErrorKind::EncodeFailed);
                assert_eq!(context, "wire::encode_into_slice");
            }
            other => panic!("expected Wire::EncodeFailed, got {other:?}"),
        }
    }

    #[test]
    fn encode_into_slice_round_trip_via_decode_canonical() {
        // The bytes produced by encode_into_slice must decode back via
        // the canonical decoder — i.e., the encoder is not a separate
        // wire format, just a non-allocating path to the same bytes.
        let value = SampleStruct {
            a: 0x1234_5678,
            b: String::from("round-trip"),
            c: vec![9, 8, 7, 6, 5],
        };
        let mut buf = [0u8; 128];
        let written = encode_into_slice(&value, &mut buf).expect("encode");
        let decoded: SampleStruct = decode_canonical(&buf[..written]).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn encode_into_slice_writes_zero_bytes_for_unit() {
        // Symmetric with `unit_type_round_trip_is_zero_bytes` above:
        // the non-allocating encoder also produces an empty encoding
        // for `()`. The returned byte count is 0; the buffer is
        // untouched (well, may have stale data — the contract is only
        // that the *first* `written` bytes are the encoding).
        let mut buf = [0u8; 4];
        let written = encode_into_slice(&(), &mut buf).expect("encode unit");
        assert_eq!(written, 0);
    }
}

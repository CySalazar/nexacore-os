//! Fused dequantize + GEMV kernel for quantized weights (WS5-01.6 / .7).
//!
//! Transformer inference is dominated by matrix-vector products of a large
//! **quantized** weight matrix `W` against an `f32` activation vector `x`. The
//! naive path dequantizes all of `W` into `f32` (8× the memory of a `Q4_K`
//! weight) and then runs a dense matmul. `fused_dequant_gemv` instead
//! dequantizes `W` **one row at a time** and immediately reduces that row
//! against `x`, so the full `f32` weight matrix is never materialized — only a
//! single row's worth of `f32` exists at any moment. This is the point of a
//! fused quantized GEMV: the same arithmetic, a fraction of the memory traffic.
//!
//! The kernel is **dtype-generic**: it reuses the exact per-block dequant of
//! [`crate::tensor_loader::dequantize_to_f32`], so it covers `Q4_K` (WS5-01.6)
//! and — sharing one common kernel — `Q5_K` and `Q8_0` (WS5-01.7), and its
//! result is **bit-identical** to the dequantize-in-full-then-matmul reference
//! path. A later iteration plugs SIMD (`AVX2`/`AVX-512`) behind this same entry point
//! (WS5-01.8 / .9).
//!
//! `no_std + alloc`: part of the bare-metal inference-engine subset.

// Numeric compute kernel: explicit floating-point arithmetic is intentional and
// matches the other compute modules (`tensor_hal`, `tensor_loader`).
#![allow(clippy::float_arithmetic)]

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use nexacore_types::error::{NexaCoreError, Result};

use crate::{
    gguf::{GgufDtype, GgufTensorInfo},
    tensor_loader::{dequantize_to_f32, gguf_tensor_byte_size},
};

/// Builds the 1-D tensor descriptor for a single quantized row of `k` elements.
fn row_info(dtype: GgufDtype, k: usize) -> GgufTensorInfo {
    GgufTensorInfo {
        name: String::new(),
        n_dimensions: 1,
        dimensions: vec![u64::try_from(k).unwrap_or(u64::MAX)],
        dtype,
        offset: 0,
    }
}

/// Fused dequantize + GEMV: computes `y = W · x`.
///
/// `weight_raw` holds an `n_rows × k` weight matrix stored row-major in the
/// quantized `dtype`; `x` is the length-`k` activation vector. Each row is
/// dequantized on the fly and reduced against `x`, yielding `y` of length
/// `n_rows`. The full `f32` weight matrix is never materialized.
///
/// `k` must be block-aligned for `dtype` (a multiple of 32 for `Q8_0`, 256 for
/// `Q4_K`/`Q5_K`); otherwise the per-row dequant rejects the byte count.
///
/// # Errors
///
/// - Returns an error if `x.len() != k`.
/// - Returns an error if `weight_raw.len()` is not exactly `n_rows` quantized
///   rows (a block-aligned byte-count mismatch), never panicking.
/// - Propagates any [`dequantize_to_f32`] error.
#[allow(
    clippy::indexing_slicing,
    reason = "chunks_exact(4) guarantees each chunk has exactly 4 bytes"
)]
pub fn fused_dequant_gemv(
    dtype: GgufDtype,
    weight_raw: &[u8],
    x: &[f32],
    n_rows: usize,
    k: usize,
) -> Result<Vec<f32>> {
    if x.len() != k {
        return Err(NexaCoreError::internal(
            "fused_dequant_gemv: activation length does not match k",
        ));
    }

    let info = row_info(dtype, k);
    let row_bytes = gguf_tensor_byte_size(&info)?;
    let expected = row_bytes
        .checked_mul(n_rows)
        .ok_or_else(|| NexaCoreError::internal("fused_dequant_gemv: weight size overflow"))?;
    if weight_raw.len() != expected {
        return Err(NexaCoreError::internal(
            "fused_dequant_gemv: weight byte count does not match n_rows × k",
        ));
    }

    let mut y = Vec::with_capacity(n_rows);
    for r in 0..n_rows {
        let start = r * row_bytes; // < expected ≤ usize::MAX, checked above
        let end = start + row_bytes;
        let row = weight_raw
            .get(start..end)
            .ok_or_else(|| NexaCoreError::internal("fused_dequant_gemv: row slice out of range"))?;
        let row_f32 = dequantize_to_f32(&info, row)?;
        // Dot the just-dequantized row against x. The dequant produces exactly
        // k f32 values, so zipping with x pairs every element (no indexing).
        let acc = row_f32
            .as_bytes()
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .zip(x.iter().copied())
            .map(|(w, xi)| w * xi)
            .sum::<f32>();
        y.push(acc);
    }
    Ok(y)
}

#[cfg(test)]
mod tests {
    // Test fixtures construct raw quantized byte patterns, which is inherently
    // cast-heavy (usize indices and signed quants packed into bytes).
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    use super::*;

    /// 1.0 in `IEEE-754` binary16, little-endian.
    const F16_ONE: [u8; 2] = [0x00, 0x3C];

    /// Builds `n_rows` quantized rows (one super-block / block per row) with
    /// finite f16 scales (1.0) and a deterministic payload, so dequant is
    /// finite and the fused vs reference comparison is exact (no NaN/Inf).
    /// Returns `(bytes, k)`.
    fn build_rows(dtype: GgufDtype, n_rows: usize) -> (Vec<u8>, usize) {
        let (block_bytes, k) = match dtype {
            GgufDtype::Q8_0 => (34, 32),
            GgufDtype::Q4_K => (144, 256),
            GgufDtype::Q5_K => (176, 256),
            _ => unreachable!("test only builds Q8_0/Q4_K/Q5_K"),
        };
        let mut bytes = Vec::with_capacity(block_bytes * n_rows);
        for r in 0..n_rows {
            let row_start = bytes.len();
            match dtype {
                GgufDtype::Q8_0 => {
                    bytes.extend_from_slice(&F16_ONE); // d
                    for i in 0..32 {
                        // small signed quants in [-8, 7]
                        bytes.push((((i + r) % 16) as i8 - 8) as u8);
                    }
                }
                GgufDtype::Q4_K => {
                    bytes.extend_from_slice(&F16_ONE); // d
                    bytes.extend_from_slice(&F16_ONE); // dmin
                    for i in 0..12 {
                        bytes.push(((i * 7 + r) % 64) as u8); // 6-bit scales
                    }
                    for i in 0..128 {
                        bytes.push(((i + r * 3) % 256) as u8); // 4-bit quant pairs
                    }
                }
                GgufDtype::Q5_K => {
                    bytes.extend_from_slice(&F16_ONE); // d
                    bytes.extend_from_slice(&F16_ONE); // dmin
                    for i in 0..12 {
                        bytes.push(((i * 5 + r) % 64) as u8); // 6-bit scales
                    }
                    for i in 0..32 {
                        bytes.push(((i * 13 + r) % 256) as u8); // qh high-bit plane
                    }
                    for i in 0..128 {
                        bytes.push(((i + r * 5) % 256) as u8); // 4-bit quant pairs
                    }
                }
                _ => unreachable!(),
            }
            assert_eq!(bytes.len() - row_start, block_bytes);
        }
        (bytes, k)
    }

    /// Reference: dequantize the whole matrix, then a plain scalar GEMV.
    fn reference_gemv(
        dtype: GgufDtype,
        raw: &[u8],
        x: &[f32],
        n_rows: usize,
        k: usize,
    ) -> Vec<f32> {
        let info = GgufTensorInfo {
            name: String::new(),
            n_dimensions: 1,
            dimensions: vec![(n_rows * k) as u64],
            dtype,
            offset: 0,
        };
        let buf = dequantize_to_f32(&info, raw).expect("reference dequant");
        let w: Vec<f32> = buf
            .as_bytes()
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert_eq!(w.len(), n_rows * k);
        let mut y = Vec::with_capacity(n_rows);
        for r in 0..n_rows {
            let mut acc = 0.0f32;
            for p in 0..k {
                acc += w[r * k + p] * x[p];
            }
            y.push(acc);
        }
        y
    }

    fn assert_matches_reference(dtype: GgufDtype, n_rows: usize) {
        let (raw, k) = build_rows(dtype, n_rows);
        // A non-trivial activation: alternating small values.
        let x: Vec<f32> = (0..k)
            .map(|i| if i % 2 == 0 { 0.5 } else { -0.25 })
            .collect();
        let got = fused_dequant_gemv(dtype, &raw, &x, n_rows, k).expect("fused gemv");
        let want = reference_gemv(dtype, &raw, &x, n_rows, k);
        assert_eq!(got.len(), n_rows);
        for (g, w) in got.iter().zip(want.iter()) {
            // Identical arithmetic in identical order ⇒ bit-exact.
            assert_eq!(g.to_bits(), w.to_bits(), "fused != reference");
        }
    }

    #[test]
    fn fused_matches_reference_q8_0() {
        assert_matches_reference(GgufDtype::Q8_0, 4);
    }

    #[test]
    fn fused_matches_reference_q4_k() {
        assert_matches_reference(GgufDtype::Q4_K, 3);
    }

    #[test]
    fn fused_matches_reference_q5_k() {
        assert_matches_reference(GgufDtype::Q5_K, 3);
    }

    #[test]
    fn q8_0_golden_gemv() {
        // One row, k=32, d=1.0, qs[i] = i-8 (so dequant = i-8), x = all ones.
        // y[0] = sum_{i=0..31}(i-8) = sum(0..31) - 32*8 = 496 - 256 = 240.
        let mut raw = Vec::new();
        raw.extend_from_slice(&F16_ONE);
        for i in 0..32i32 {
            raw.push((i - 8) as i8 as u8);
        }
        let x = vec![1.0f32; 32];
        let y = fused_dequant_gemv(GgufDtype::Q8_0, &raw, &x, 1, 32).unwrap();
        assert_eq!(y, vec![240.0f32]);
    }

    #[test]
    fn rejects_activation_length_mismatch() {
        let (raw, k) = build_rows(GgufDtype::Q8_0, 2);
        let x = vec![1.0f32; k + 1];
        assert!(fused_dequant_gemv(GgufDtype::Q8_0, &raw, &x, 2, k).is_err());
    }

    #[test]
    fn rejects_weight_byte_count_mismatch() {
        let (mut raw, k) = build_rows(GgufDtype::Q8_0, 2);
        raw.push(0); // one byte too many — not a whole number of rows
        let x = vec![1.0f32; k];
        assert!(fused_dequant_gemv(GgufDtype::Q8_0, &raw, &x, 2, k).is_err());
    }
}

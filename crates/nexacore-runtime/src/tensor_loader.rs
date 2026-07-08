//! GGUF tensor weight extraction into HAL [`nexacore_hal::tensor::TensorBuffer`]s.
//!
//! This module bridges the GGUF parser ([`crate::gguf`]) and the HAL tensor
//! abstraction ([`nexacore_hal::tensor`]). It extracts raw bytes for each tensor
//! from the GGUF data blob and, where possible, converts them to a canonical
//! `F32` representation suitable for inference.
//!
//! ## Phase 2 / Sprint 8–12 scope
//!
//! - **F32**: passed through as-is (zero-copy byte slice → owned `Vec`).
//! - **F16**: each 16-bit half-precision value is expanded to `f32`.
//! - **BF16**: each 16-bit bfloat16 value is expanded to `f32`.
//! - **I8**: stored as [`nexacore_hal::tensor::TensorDtype::I8`] without conversion.
//! - **Q8_0**: real dequantization (Sprint 8). Block layout: 2-byte f16 scale
//!   + 32 × i8 quantized values = 34 bytes/block.
//!   Output formula: `x[i] = q[i] * scale`.
//! - **Q4_0**: real dequantization (Sprint 8). Block layout: 2-byte f16 scale
//!   + 16 packed bytes (32 × 4-bit nibbles) = 18 bytes/block.
//!   Each nibble is sign-extended by subtracting 8, giving range [-8, 7],
//!   then multiplied by the scale.
//! - **Q4_K**: real dequantization (Sprint 12 / TASK-16, ADR-0038). Super-block
//!   layout: 144 bytes/256 elements — byte-exact to llama.cpp `block_q4_K`.
//!   Uses `get_scale_min_k4` to unpack 6-bit sub-scales and sub-mins.
//! - **Q5_K**: real dequantization (WS5-01.5). Super-block layout: 176
//!   bytes/256 elements — byte-exact to llama.cpp `block_q5_K`. Like Q4_K plus
//!   a 32-byte high-bit plane (`qh`) supplying each quant's 5th bit.
//! - **All other quantized types** (Q4_1, Q5_0, Q5_1, Q8_1, Q2_K, Q3_K,
//!   Q6_K, I16, I32, I64, F64): a zero-filled `F32` buffer of the
//!   correct shape is returned. Full dequantization is deferred to a later
//!   phase.

// Float arithmetic is fundamental to tensor dequantization; the lint is
// suppressed file-wide because every arithmetic operation here is intentional.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::float_arithmetic
)]

// Alloc types: re-exported by std's prelude on host builds, pulled from
// `alloc` when building without std (TASK-13-pre / ADR-0034).
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use nexacore_hal::tensor::{TensorBuffer, TensorDescriptor, TensorDtype};
use nexacore_types::{NexaCoreError, Result};

use crate::gguf::{GgufDtype, GgufHeader, GgufTensorInfo};

// =============================================================================
// LoadedTensor
// =============================================================================

/// A tensor extracted from a GGUF file, paired with its name and data buffer.
///
/// # Example
///
/// ```rust
/// use nexacore_hal::tensor::{TensorBuffer, TensorDescriptor, TensorDtype};
/// use nexacore_runtime::tensor_loader::LoadedTensor;
///
/// let desc = TensorDescriptor::named(vec![2, 2], TensorDtype::F32, "weights");
/// let buf = TensorBuffer::new(desc, vec![0u8; 16]);
/// let lt = LoadedTensor {
///     name: "weights".into(),
///     buffer: buf,
/// };
/// assert_eq!(lt.name, "weights");
/// assert_eq!(lt.buffer.len(), 16);
/// ```
#[derive(Debug)]
pub struct LoadedTensor {
    /// GGUF tensor name (e.g. `"token_embd.weight"`).
    pub name: String,
    /// Tensor data in HAL format (always F32 after dequantization, except I8).
    pub buffer: TensorBuffer,
}

// =============================================================================
// dtype helpers
// =============================================================================

/// Map a [`GgufDtype`] to the closest [`TensorDtype`] supported by the HAL.
///
/// Quantized types (`Q4_0` … `Q8_1`, k-quants, integer widths other than I8,
/// F64) map to [`TensorDtype::F32`] because the dequantization step produces
/// `f32` output.
///
/// # Example
///
/// ```rust
/// use nexacore_hal::tensor::TensorDtype;
/// use nexacore_runtime::{gguf::GgufDtype, tensor_loader::gguf_dtype_to_hal};
///
/// assert_eq!(gguf_dtype_to_hal(GgufDtype::F32), TensorDtype::F32);
/// assert_eq!(gguf_dtype_to_hal(GgufDtype::F16), TensorDtype::F16);
/// assert_eq!(gguf_dtype_to_hal(GgufDtype::Bf16), TensorDtype::Bf16);
/// assert_eq!(gguf_dtype_to_hal(GgufDtype::I8), TensorDtype::I8);
/// // Quantized types become F32 after dequantization.
/// assert_eq!(gguf_dtype_to_hal(GgufDtype::Q4_0), TensorDtype::F32);
/// ```
#[must_use]
pub fn gguf_dtype_to_hal(dtype: GgufDtype) -> TensorDtype {
    match dtype {
        GgufDtype::F16 => TensorDtype::F16,
        GgufDtype::Bf16 => TensorDtype::Bf16,
        GgufDtype::I8 => TensorDtype::I8,
        // F32 and all quantized/wide-int/f64 types produce F32 after
        // dequantization (quantized types are zero-filled stubs in Phase 2).
        _ => TensorDtype::F32,
    }
}

/// Compute the total byte size of a tensor on disk given its shape and dtype.
///
/// For quantized types the computation accounts for sub-byte packing and
/// block-level overhead. Returns an error if any dimension overflows `usize`.
// `match_same_arms` is suppressed because semantically identical arms
// (e.g. I8 vs k-quant 1-byte upper bound, F16 vs Q3_K 2-byte upper bound)
// belong to distinct logical categories. Merging them would obscure the
// intent and make the Phase-4 expansion to exact sizes harder to follow.
#[allow(clippy::match_same_arms)]
pub(crate) fn gguf_tensor_byte_size(tensor_info: &GgufTensorInfo) -> Result<usize> {
    let n_elements: usize = tensor_info.dimensions.iter().try_fold(1usize, |acc, &d| {
        let d_usize = usize::try_from(d).map_err(|_| {
            NexaCoreError::internal("tensor_loader::byte_size — dimension overflows usize")
        })?;
        acc.checked_mul(d_usize).ok_or_else(|| {
            NexaCoreError::internal("tensor_loader::byte_size — element count overflow")
        })
    })?;

    // Bit-width per element depends on the dtype. For quantized formats that
    // use fractional bits-per-element, we compute bytes as ceiling division.
    // All values are taken from the GGUF spec and llama.cpp constants:
    // https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
    let byte_size = match tensor_info.dtype {
        // Floating-point and integer scalar types.
        GgufDtype::F32 | GgufDtype::I32 => n_elements.checked_mul(4),
        // 2-byte element types: F16, BF16, I16.
        GgufDtype::F16 | GgufDtype::Bf16 | GgufDtype::I16 => n_elements.checked_mul(2),
        GgufDtype::I8 => Some(n_elements),
        // 8-byte element types: I64, F64.
        GgufDtype::I64 | GgufDtype::F64 => n_elements.checked_mul(8),
        // Q4_0: 4 bits/element + 2-byte scale per 32-element block = 18 bytes/block.
        GgufDtype::Q4_0 => n_elements.div_ceil(32).checked_mul(18),
        // Q4_1: 4 bits/element + 4 bytes (scale+min) per 32-element block = 20 bytes/block.
        GgufDtype::Q4_1 => n_elements.div_ceil(32).checked_mul(20),
        // Q5_0: 5 bits/element + 2-byte scale per 32-element block = 22 bytes/block.
        GgufDtype::Q5_0 => n_elements.div_ceil(32).checked_mul(22),
        // Q5_1: 5 bits/element + 4 bytes per 32-element block = 24 bytes/block.
        GgufDtype::Q5_1 => n_elements.div_ceil(32).checked_mul(24),
        // Q8_0: 8 bits/element + 2-byte scale per 32-element block = 34 bytes/block.
        GgufDtype::Q8_0 => n_elements.div_ceil(32).checked_mul(34),
        // Q8_1: 8 bits/element + 4 bytes per 32-element block = 36 bytes/block.
        GgufDtype::Q8_1 => n_elements.div_ceil(32).checked_mul(36),
        // Q4_K (TASK-16, ADR-0038): super-block is 256 elements / 144 bytes.
        // n_blocks = ceil(n_elements / 256); each block is exactly 144 bytes.
        GgufDtype::Q4_K => n_elements.div_ceil(256).checked_mul(144),
        // k-quant stubs: conservative upper-bound approximation.
        // For Phase 2 stub the byte size governs only how many bytes are sliced
        // from the data region before being discarded (zeros are returned).
        // 1-byte-per-element upper bound: Q2_K (~2.625 bpe), Q6_K (~6.56 bpe).
        GgufDtype::Q2_K | GgufDtype::Q6_K => Some(n_elements),
        // 2-byte-per-element upper bound: Q3_K (~3.44 bpe).
        GgufDtype::Q3_K => n_elements.checked_mul(2),
        // Q5_K (WS5-01.5): super-block is 256 elements / 176 bytes.
        // n_blocks = ceil(n_elements / 256); each block is exactly 176 bytes.
        GgufDtype::Q5_K => n_elements.div_ceil(256).checked_mul(176),
    }
    .ok_or_else(|| NexaCoreError::internal("tensor_loader::byte_size — byte size overflow"))?;

    Ok(byte_size)
}

// =============================================================================
// extract_tensor_bytes
// =============================================================================

/// Extract the raw on-disk bytes for a single tensor from the GGUF data blob.
///
/// `data` is the full GGUF file byte slice. Tensor data begins at
/// `header.data_offset`; each tensor's bytes start at
/// `header.data_offset + tensor_info.offset` and span `byte_size` bytes
/// (computed from shape × dtype).
///
/// The returned slice is a zero-copy view into `data`; no allocation is
/// performed.
///
/// # Errors
///
/// - [`NexaCoreError::Internal`] if the computed byte range lies outside `data`.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::{
///     gguf::{GGUF_MAGIC, GGUF_VERSION_3, GgufDtype, GgufHeader, GgufTensorInfo},
///     tensor_loader::extract_tensor_bytes,
/// };
///
/// // Build a minimal GGUF with one 2-element F32 tensor.
/// let mut buf = Vec::<u8>::new();
/// buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
/// buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
/// buf.extend_from_slice(&1u64.to_le_bytes()); // tensor_count
/// buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count
/// // tensor name "w" (u64 len + bytes)
/// buf.extend_from_slice(&1u64.to_le_bytes());
/// buf.push(b'w');
/// buf.extend_from_slice(&1u32.to_le_bytes()); // n_dimensions
/// buf.extend_from_slice(&2u64.to_le_bytes()); // dim[0] = 2
/// buf.extend_from_slice(&0u32.to_le_bytes()); // dtype F32
/// buf.extend_from_slice(&0u64.to_le_bytes()); // offset 0
/// // Pad to 32-byte alignment, then append 8 bytes of tensor data.
/// while buf.len() % 32 != 0 {
///     buf.push(0);
/// }
/// buf.extend_from_slice(&1.0f32.to_le_bytes());
/// buf.extend_from_slice(&2.0f32.to_le_bytes());
///
/// let header = nexacore_runtime::gguf::parse_gguf(&buf).unwrap();
/// let t_info = &header.tensors[0];
/// let raw = extract_tensor_bytes(&buf, &header, t_info).unwrap();
/// assert_eq!(raw.len(), 8); // 2 × 4 bytes
/// ```
pub fn extract_tensor_bytes<'a>(
    data: &'a [u8],
    header: &GgufHeader,
    tensor_info: &GgufTensorInfo,
) -> Result<&'a [u8]> {
    let byte_size = gguf_tensor_byte_size(tensor_info)?;

    // offset of this tensor's data within the data region (relative to
    // header.data_offset).
    let tensor_offset_in_region = usize::try_from(tensor_info.offset).map_err(|_| {
        NexaCoreError::internal("tensor_loader::extract — tensor offset overflows usize")
    })?;

    let start = header
        .data_offset
        .checked_add(tensor_offset_in_region)
        .ok_or_else(|| {
            NexaCoreError::internal("tensor_loader::extract — tensor start overflows usize")
        })?;

    let end = start.checked_add(byte_size).ok_or_else(|| {
        NexaCoreError::internal("tensor_loader::extract — tensor end overflows usize")
    })?;

    data.get(start..end).ok_or_else(|| {
        NexaCoreError::internal("tensor_loader::extract — tensor bytes out of bounds in GGUF data")
    })
}

// =============================================================================
// F16 → F32 conversion
// =============================================================================

/// Convert a single IEEE 754 half-precision (F16) bit pattern to `f32`.
///
/// Layout: 1 sign bit, 5 exponent bits (bias 15), 10 mantissa bits.
/// Special values (Inf, `NaN`, subnormals) are handled correctly.
fn f16_bits_to_f32(bits: u16) -> f32 {
    let sign: u32 = u32::from(bits >> 15) << 31;
    let exp_f16: u32 = u32::from((bits >> 10) & 0x1F);
    let mantissa: u32 = u32::from(bits & 0x03FF);

    let f32_bits: u32 = if exp_f16 == 0 {
        // Subnormal F16: convert to F32 subnormal or zero.
        if mantissa == 0 {
            // Positive or negative zero.
            sign
        } else {
            // Normalise the subnormal: find leading 1 bit of mantissa.
            let mut m = mantissa;
            let mut e = 127 - 14; // F32 bias - F16 bias + 1
            while m & 0x0400 == 0 {
                m <<= 1;
                e -= 1;
            }
            m &= 0x03FF;
            sign | (e << 23) | (m << 13)
        }
    } else if exp_f16 == 31 {
        // F16 Inf or NaN → F32 Inf or NaN (preserve mantissa).
        sign | 0x7F80_0000 | (mantissa << 13)
    } else {
        // Normal F16: re-bias exponent from 15 to 127.
        sign | ((exp_f16 + 127 - 15) << 23) | (mantissa << 13)
    };

    f32::from_bits(f32_bits)
}

/// Convert a single bfloat16 bit pattern to `f32`.
///
/// BF16 shares the same sign and exponent layout as F32 but has only
/// 7 mantissa bits. Conversion is zero-extending the bit pattern to 32 bits
/// (the lower 16 bits of the F32 mantissa become zero).
fn bf16_bits_to_f32(bits: u16) -> f32 {
    f32::from_bits(u32::from(bits) << 16)
}

// =============================================================================
// Q4_K helpers (TASK-16 / ADR-0038)
// =============================================================================

/// Unpack the 6-bit sub-scale and 6-bit sub-min for sub-block index `j`
/// from the 12-byte `scales` field of a `block_q4_K` super-block.
///
/// This is a byte-exact port of `get_scale_min_k4` from llama.cpp
/// `ggml-quants.c`. The 12 bytes hold 8 pairs of (6-bit scale, 6-bit min),
/// packed as follows:
///
/// - For `j < 4`: scale is the low 6 bits of `scales[j]`; min is the low 6
///   bits of `scales[j + 4]`.
/// - For `j >= 4` (i.e., `j` in 4..8): bits of the scale and min are split
///   across `scales[j + 4]` (4-bit half) and `scales[j - 4]` (upper 2 bits).
///
/// All arithmetic is on `u8` values; no overflow is possible.
///
/// # Panics
///
/// Never panics: `j` is always in `0..8` and `scales` always has 12 bytes
/// at the call sites in `dequantize_to_f32`.
#[inline]
fn get_scale_min_k4(j: usize, scales: &[u8]) -> (u8, u8) {
    // j < 4: straightforward 6-bit extraction from bytes j and j+4.
    // j >= 4: the 6 bits are split: low 4 from scales[j+4], high 2 from
    //         the upper 2 bits of scales[j-4] (for scale) or scales[j] (for min).
    if j < 4 {
        // SAFETY: j ∈ [0,3], so j ≤ 3 and j+4 ≤ 7; scales has ≥ 12 bytes.
        #[allow(clippy::indexing_slicing)]
        let sc = scales[j] & 63;
        #[allow(clippy::indexing_slicing)]
        let m = scales[j + 4] & 63;
        (sc, m)
    } else {
        // j ∈ [4,7]: j+4 ∈ [8,11] ≤ 11; j-4 ∈ [0,3] ≥ 0; j ∈ [4,7].
        // All accesses are in [0,11] — within the 12-byte array.
        #[allow(clippy::indexing_slicing)]
        let sc = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
        #[allow(clippy::indexing_slicing)]
        let m = (scales[j + 4] >> 4) | ((scales[j] >> 6) << 4);
        (sc, m)
    }
}

// =============================================================================
// dequantize_to_f32
// =============================================================================

/// Convert raw GGUF tensor bytes into a [`TensorBuffer`].
///
/// The output dtype depends on the source dtype:
///
/// | Source dtype | Output dtype | Operation |
/// |---|---|---|
/// | F32 | F32 | byte copy |
/// | F16 | F32 | each 16-bit value expanded to f32 |
/// | BF16 | F32 | each 16-bit value expanded to f32 |
/// | I8 | I8 | byte copy |
/// | `Q8_0` | F32 | block dequantization: `q[i] * scale` (f16 scale, 34 bytes/block) |
/// | `Q4_0` | F32 | block dequantization: `(nibble - 8) * scale` (f16 scale, 18 bytes/block) |
/// | `Q4_K` | F32 | k-quant super-block dequant (f16 d/dmin, 6-bit sub-scales, 144 bytes/256 elems) |
/// | `Q5_K` | F32 | k-quant super-block dequant with high-bit plane (f16 d/dmin, 6-bit sub-scales, `qh`, 176 bytes/256 elems) |
/// | All others | F32 | zeroed buffer (stub; full dequantization deferred) |
///
/// # Errors
///
/// - [`NexaCoreError::Internal`] if `raw_bytes.len()` is not a multiple of the
///   element byte width for F32, F16, BF16, or I8.
/// - [`NexaCoreError::Internal`] if `raw_bytes.len()` does not equal the expected
///   block-aligned byte count for `Q8_0`, `Q4_0`, or `Q4_K`.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::{
///     gguf::{GgufDtype, GgufTensorInfo},
///     tensor_loader::dequantize_to_f32,
/// };
///
/// let info = GgufTensorInfo {
///     name: "w".into(),
///     n_dimensions: 1,
///     dimensions: vec![2],
///     dtype: GgufDtype::F32,
///     offset: 0,
/// };
/// let raw = [0u8, 0, 128, 63, 0, 0, 0, 64]; // 1.0f32, 2.0f32 LE
/// let buf = dequantize_to_f32(&info, &raw).unwrap();
/// assert_eq!(buf.len(), 8);
/// ```
// This function is necessarily long: each branch handles a distinct GGUF dtype
// with its own block layout and conversion arithmetic. Splitting it would
// scatter related constants and error messages across multiple private helpers
// without improving comprehension. The line count is justified.
#[allow(clippy::too_many_lines)]
pub fn dequantize_to_f32(tensor_info: &GgufTensorInfo, raw_bytes: &[u8]) -> Result<TensorBuffer> {
    let shape: Vec<usize> = tensor_info.dimensions.iter().map(|&d| d as usize).collect();

    let n_elements: usize = shape.iter().product::<usize>().max(1);

    let (dtype, bytes) = match tensor_info.dtype {
        GgufDtype::F32 => {
            if raw_bytes.len() != n_elements * 4 {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — F32 byte count mismatch",
                ));
            }
            (TensorDtype::F32, raw_bytes.to_vec())
        }

        GgufDtype::F16 => {
            if raw_bytes.len() != n_elements * 2 {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — F16 byte count mismatch",
                ));
            }
            let mut out = vec![0u8; n_elements * 4];
            for i in 0..n_elements {
                let lo = raw_bytes.get(i * 2).copied().ok_or_else(|| {
                    NexaCoreError::internal("tensor_loader::dequantize — F16 read OOB")
                })?;
                let hi = raw_bytes.get(i * 2 + 1).copied().ok_or_else(|| {
                    NexaCoreError::internal("tensor_loader::dequantize — F16 read OOB")
                })?;
                let bits = u16::from_le_bytes([lo, hi]);
                let f = f16_bits_to_f32(bits);
                let f_bytes = f.to_le_bytes();
                let dst = out.get_mut(i * 4..i * 4 + 4).ok_or_else(|| {
                    NexaCoreError::internal("tensor_loader::dequantize — F16 write OOB")
                })?;
                dst.copy_from_slice(&f_bytes);
            }
            (TensorDtype::F32, out)
        }

        GgufDtype::Bf16 => {
            if raw_bytes.len() != n_elements * 2 {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — BF16 byte count mismatch",
                ));
            }
            let mut out = vec![0u8; n_elements * 4];
            for i in 0..n_elements {
                let lo = raw_bytes.get(i * 2).copied().ok_or_else(|| {
                    NexaCoreError::internal("tensor_loader::dequantize — BF16 read OOB")
                })?;
                let hi = raw_bytes.get(i * 2 + 1).copied().ok_or_else(|| {
                    NexaCoreError::internal("tensor_loader::dequantize — BF16 read OOB")
                })?;
                let bits = u16::from_le_bytes([lo, hi]);
                let f = bf16_bits_to_f32(bits);
                let f_bytes = f.to_le_bytes();
                let dst = out.get_mut(i * 4..i * 4 + 4).ok_or_else(|| {
                    NexaCoreError::internal("tensor_loader::dequantize — BF16 write OOB")
                })?;
                dst.copy_from_slice(&f_bytes);
            }
            (TensorDtype::F32, out)
        }

        GgufDtype::I8 => {
            if raw_bytes.len() != n_elements {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — I8 byte count mismatch",
                ));
            }
            (TensorDtype::I8, raw_bytes.to_vec())
        }

        // Q8_0 dequantization (Sprint 8).
        //
        // Block layout (34 bytes per block):
        //   bytes [0..2]  — f16 LE scale `d`
        //   bytes [2..34] — 32 × i8 quantized values
        //
        // Dequantize: x[i] = q[i] * d
        //
        // The GGUF spec requires tensor data to be written in complete blocks;
        // when n_elements is not a multiple of 32 the last block is zero-padded
        // on disk. We allocate n_blocks * 32 output elements but only the first
        // n_elements are semantically meaningful.
        GgufDtype::Q8_0 => {
            let n_blocks = n_elements.div_ceil(32);
            let expected_bytes = n_blocks.checked_mul(34).ok_or_else(|| {
                NexaCoreError::internal("tensor_loader::dequantize — Q8_0 byte count overflow")
            })?;
            if raw_bytes.len() != expected_bytes {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — Q8_0 byte count mismatch",
                ));
            }
            // Each output element is 4 bytes (f32 LE).
            let mut out = vec![0u8; n_blocks * 32 * 4];
            // SAFETY: All index arithmetic below is in-bounds because:
            //   raw_bytes.len() == n_blocks * 34 (verified above), so for
            //   block ∈ [0, n_blocks), base = block*34:
            //     base+1 < n_blocks*34  ✓
            //     base+2+j < n_blocks*34 for j < 32  ✓
            //   out.len() == n_blocks*32*4, so out_offset+4 <= n_blocks*32*4  ✓
            #[allow(clippy::indexing_slicing)]
            for block in 0..n_blocks {
                let base = block * 34;
                // Read the f16 scale from the first two bytes of the block.
                let scale_bits = u16::from_le_bytes([raw_bytes[base], raw_bytes[base + 1]]);
                let scale = f16_bits_to_f32(scale_bits);
                // Dequantize each of the 32 i8 quantized values in this block.
                for j in 0..32usize {
                    // Reinterpret the u8 byte as a signed i8; this is a
                    // value-preserving bit cast with no undefined behaviour.
                    let q = raw_bytes[base + 2 + j] as i8;
                    let x = f32::from(q) * scale;
                    let out_offset = (block * 32 + j) * 4;
                    out[out_offset..out_offset + 4].copy_from_slice(&x.to_le_bytes());
                }
            }
            (TensorDtype::F32, out)
        }

        // Q4_0 dequantization (Sprint 8).
        //
        // Block layout (18 bytes per block):
        //   bytes [0..2]  — f16 LE scale `d`
        //   bytes [2..18] — 16 packed bytes holding 32 × 4-bit nibbles
        //
        // Each packed byte `b` at nibble-pair index `k` encodes:
        //   element 2k+0 from the low  nibble: (b & 0x0F)
        //   element 2k+1 from the high nibble: (b >> 4)
        //
        // Nibbles are unsigned [0, 15]; subtract 8 to get signed range [-8, 7].
        // Dequantize: x[i] = (nibble_i - 8) * d
        GgufDtype::Q4_0 => {
            let n_blocks = n_elements.div_ceil(32);
            let expected_bytes = n_blocks.checked_mul(18).ok_or_else(|| {
                NexaCoreError::internal("tensor_loader::dequantize — Q4_0 byte count overflow")
            })?;
            if raw_bytes.len() != expected_bytes {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — Q4_0 byte count mismatch",
                ));
            }
            let mut out = vec![0u8; n_blocks * 32 * 4];
            // SAFETY: All index arithmetic below is in-bounds because:
            //   raw_bytes.len() == n_blocks * 18 (verified above), so for
            //   block ∈ [0, n_blocks), base = block*18:
            //     base+1 < n_blocks*18  ✓
            //     base+2+k < n_blocks*18 for k < 16  ✓
            //   out.len() == n_blocks*32*4; out_hi+4 = (block*32+k*2+1)*4+4
            //     ≤ (n_blocks*32)*4  ✓  (since block < n_blocks, k < 16)
            #[allow(clippy::indexing_slicing)]
            for block in 0..n_blocks {
                let base = block * 18;
                let scale_bits = u16::from_le_bytes([raw_bytes[base], raw_bytes[base + 1]]);
                let scale = f16_bits_to_f32(scale_bits);
                // 16 packed bytes → 32 nibbles.
                for k in 0..16usize {
                    let packed = raw_bytes[base + 2 + k];
                    // Low nibble → element 2k, high nibble → element 2k+1.
                    // Cast through i32 to perform the signed subtraction before
                    // narrowing to f32; avoids any intermediate unsigned wrap.
                    let lo = (i32::from(packed & 0x0F) - 8) as f32 * scale;
                    let hi = (i32::from(packed >> 4) - 8) as f32 * scale;
                    let out_lo = (block * 32 + k * 2) * 4;
                    let out_hi = out_lo + 4;
                    out[out_lo..out_lo + 4].copy_from_slice(&lo.to_le_bytes());
                    out[out_hi..out_hi + 4].copy_from_slice(&hi.to_le_bytes());
                }
            }
            (TensorDtype::F32, out)
        }

        // Q4_K dequantization (TASK-16, ADR-0038, Sprint 12).
        //
        // Super-block layout (144 bytes, QK_K = 256 elements):
        //   bytes [0..2]   — f16 LE scale `d`     (super-block scale for 6-bit sub-scales)
        //   bytes [2..4]   — f16 LE dmin  `dmin`  (super-block scale for 6-bit sub-mins)
        //   bytes [4..16]  — `scales[12]`: 8 × (6-bit scale + 6-bit min), bit-packed
        //   bytes [16..144]— `qs[128]`: 256 × 4-bit quants (low nibble first)
        //
        // Dequantize formula (byte-exact to llama.cpp `dequantize_row_q4_K`):
        //   d    = f16→f32(d_bits);  min = f16→f32(dmin_bits)
        //   for is in [0, 2, 4, 6]  (4 outer steps, each over 64 elements):
        //     (sc1, m1) = get_scale_min_k4(is + 0, scales)
        //     (sc2, m2) = get_scale_min_k4(is + 1, scales)
        //     d1 = d * f32(sc1);  m1f = min * f32(m1)
        //     d2 = d * f32(sc2);  m2f = min * f32(m2)
        //     for l in 0..32: y[..] = d1 * f32(qs[l] & 0x0F) - m1f
        //     for l in 0..32: y[..] = d2 * f32(qs[l] >>  4 ) - m2f
        //     qs_ptr += 32
        GgufDtype::Q4_K => {
            let n_blocks = n_elements.div_ceil(256);
            let expected_bytes = n_blocks.checked_mul(144).ok_or_else(|| {
                NexaCoreError::internal("tensor_loader::dequantize — Q4_K byte count overflow")
            })?;
            if raw_bytes.len() != expected_bytes {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — Q4_K byte count mismatch",
                ));
            }
            // Each output element is 4 bytes (f32 LE).
            let mut out = vec![0u8; n_blocks * 256 * 4];
            // SAFETY: All index arithmetic below is in-bounds because:
            //   raw_bytes.len() == n_blocks * 144 (verified above), so for
            //   block ∈ [0, n_blocks), base = block * 144:
            //     base + 1  < n_blocks*144  ✓  (f16 d)
            //     base + 3  < n_blocks*144  ✓  (f16 dmin)
            //     base + 4 + s < n_blocks*144 for s < 12  ✓  (scales)
            //     base + 16 + q < n_blocks*144 for q < 128 ✓  (qs)
            //   get_scale_min_k4 accesses scales[j] and scales[j+4] for j < 8,
            //     all within [0..12].
            //   out.len() == n_blocks*256*4; out_off + 4 ≤ n_blocks*256*4
            //     for elem < n_blocks*256.
            #[allow(clippy::indexing_slicing)]
            for block in 0..n_blocks {
                let base = block * 144;

                // Read f16 super-block scale `d` (bytes [0..2]).
                let d_bits = u16::from_le_bytes([raw_bytes[base], raw_bytes[base + 1]]);
                let d_f32 = f16_bits_to_f32(d_bits);

                // Read f16 super-block min `dmin` (bytes [2..4]).
                let dmin_bits = u16::from_le_bytes([raw_bytes[base + 2], raw_bytes[base + 3]]);
                let min_f32 = f16_bits_to_f32(dmin_bits);

                // The 12 scales bytes occupy positions [4..16] in the block.
                // We pass a slice reference to get_scale_min_k4.
                let scales_start = base + 4;
                // scales_slice is [base+4 .. base+16], exactly 12 bytes.
                let scales_slice = &raw_bytes[scales_start..scales_start + 12];

                // qs occupies positions [16..144] in the block: 128 bytes for
                // 256 × 4-bit quantized values.
                let qs_base = base + 16;

                // Output element counter for this super-block.
                let out_base = block * 256;

                // 4 outer steps, each covering 64 output elements using 32 qs bytes.
                // is iterates as 0, 2, 4, 6 (two sub-block indices per outer step).
                let mut is: usize = 0;
                for step in 0..4usize {
                    // 32 qs bytes for this outer step (positions 0, 32, 64, 96 within qs).
                    let qs_off = qs_base + step * 32;

                    // Sub-block 0 of this step: indices (is, is+0) → scale/min pair 1.
                    let (sc1, m1) = get_scale_min_k4(is, scales_slice);
                    let d1 = d_f32 * f32::from(sc1);
                    let m1f = min_f32 * f32::from(m1);

                    // Sub-block 1 of this step: indices (is+1) → scale/min pair 2.
                    let (sc2, m2) = get_scale_min_k4(is + 1, scales_slice);
                    let d2 = d_f32 * f32::from(sc2);
                    let m2f = min_f32 * f32::from(m2);

                    // First 32 elements of this 64-element step: low nibbles.
                    // Output elements: out_base + step*64 + [0..32].
                    // NOTE: `f32::mul_add` is unavailable in `no_std` on stable.
                    // We use explicit arithmetic; `suboptimal_flops` is suppressed.
                    #[allow(clippy::suboptimal_flops)]
                    for l in 0..32usize {
                        let nibble_lo = f32::from(raw_bytes[qs_off + l] & 0x0F);
                        let val = d1 * nibble_lo - m1f;
                        let elem = out_base + step * 64 + l;
                        let off = elem * 4;
                        out[off..off + 4].copy_from_slice(&val.to_le_bytes());
                    }

                    // Second 32 elements of this 64-element step: high nibbles.
                    // Output elements: out_base + step*64 + 32 + [0..32].
                    #[allow(clippy::suboptimal_flops)]
                    for l in 0..32usize {
                        let nibble_hi = f32::from(raw_bytes[qs_off + l] >> 4);
                        let val = d2 * nibble_hi - m2f;
                        let elem = out_base + step * 64 + 32 + l;
                        let off = elem * 4;
                        out[off..off + 4].copy_from_slice(&val.to_le_bytes());
                    }

                    is += 2;
                }
            }
            (TensorDtype::F32, out)
        }

        // Q5_K dequantization (WS5-01.5).
        //
        // Super-block layout (176 bytes, QK_K = 256 elements):
        //   bytes [0..2]    — f16 LE scale `d`
        //   bytes [2..4]    — f16 LE min   `dmin`
        //   bytes [4..16]   — `scales[12]`: 8 × (6-bit scale + 6-bit min), as Q4_K
        //   bytes [16..48]  — `qh[32]`: the 5th (high) bit of each of the 256 quants
        //   bytes [48..176] — `qs[128]`: 256 × 4-bit low quants (low nibble first)
        //
        // Byte-exact to llama.cpp `dequantize_row_q5_K`: identical to Q4_K but
        // each quant gains a 5th bit pulled from `qh` via a per-step moving mask
        // (`u1 = 1<<2s`, `u2 = 2<<2s` for outer step `s`): a set bit adds 16.
        GgufDtype::Q5_K => {
            let n_blocks = n_elements.div_ceil(256);
            let expected_bytes = n_blocks.checked_mul(176).ok_or_else(|| {
                NexaCoreError::internal("tensor_loader::dequantize — Q5_K byte count overflow")
            })?;
            if raw_bytes.len() != expected_bytes {
                return Err(NexaCoreError::internal(
                    "tensor_loader::dequantize — Q5_K byte count mismatch",
                ));
            }
            let mut out = vec![0u8; n_blocks * 256 * 4];
            // SAFETY: raw_bytes.len() == n_blocks * 176 (verified above); for
            // block ∈ [0, n_blocks), base = block*176, all reads are in-bounds:
            //   d/dmin at base..base+4, scales at base+4..base+16,
            //   qh at base+16..base+48 (high_plane + l, l < 32),
            //   qs at base+48..base+176 (qs_off + l, qs_off = base+48+step*32,
            //   step < 4, l < 32 → max base+48+96+31 = base+175). `out` writes
            //   are at (block*256 + ..)*4 < n_blocks*256*4.
            #[allow(clippy::indexing_slicing)]
            for block in 0..n_blocks {
                let base = block * 176;
                let d_f32 =
                    f16_bits_to_f32(u16::from_le_bytes([raw_bytes[base], raw_bytes[base + 1]]));
                let min_f32 = f16_bits_to_f32(u16::from_le_bytes([
                    raw_bytes[base + 2],
                    raw_bytes[base + 3],
                ]));
                let scales_slice = &raw_bytes[base + 4..base + 16];
                let high_plane = base + 16; // qh: 32 bytes, one high bit per quant
                let low_quants = base + 48; // qs: 128 bytes of 4-bit low quants
                let out_base = block * 256;

                let mut is: usize = 0;
                for step in 0..4usize {
                    let qs_off = low_quants + step * 32;
                    let (sc1, m1) = get_scale_min_k4(is, scales_slice);
                    let d1 = d_f32 * f32::from(sc1);
                    let m1f = min_f32 * f32::from(m1);
                    let (sc2, m2) = get_scale_min_k4(is + 1, scales_slice);
                    let d2 = d_f32 * f32::from(sc2);
                    let m2f = min_f32 * f32::from(m2);
                    // Per-step high-bit masks (1<<2s for low nibbles, 2<<2s for high).
                    let lo_mask = 1u8 << (step * 2);
                    let hi_mask = 2u8 << (step * 2);

                    #[allow(clippy::suboptimal_flops)]
                    for l in 0..32usize {
                        let high = if raw_bytes[high_plane + l] & lo_mask != 0 {
                            16
                        } else {
                            0
                        };
                        let q = (raw_bytes[qs_off + l] & 0x0F) + high;
                        let val = d1 * f32::from(q) - m1f;
                        let off = (out_base + step * 64 + l) * 4;
                        out[off..off + 4].copy_from_slice(&val.to_le_bytes());
                    }
                    #[allow(clippy::suboptimal_flops)]
                    for l in 0..32usize {
                        let high = if raw_bytes[high_plane + l] & hi_mask != 0 {
                            16
                        } else {
                            0
                        };
                        let q = (raw_bytes[qs_off + l] >> 4) + high;
                        let val = d2 * f32::from(q) - m2f;
                        let off = (out_base + step * 64 + 32 + l) * 4;
                        out[off..off + 4].copy_from_slice(&val.to_le_bytes());
                    }
                    is += 2;
                }
            }
            (TensorDtype::F32, out)
        }

        // All remaining quantized types (Q4_1, Q5_0, Q5_1, Q8_1, Q2_K, Q3_K,
        // Q6_K, I16, I32, I64, F64): return a zeroed F32 buffer with
        // the correct shape. Full dequantization is deferred to a later phase.
        _ => {
            let zero_bytes = vec![0u8; n_elements * 4];
            (TensorDtype::F32, zero_bytes)
        }
    };

    let desc = TensorDescriptor::named(shape, dtype, tensor_info.name.clone());
    Ok(TensorBuffer::new(desc, bytes))
}

// =============================================================================
// load_all_tensors
// =============================================================================

/// Load all tensors from a GGUF file into [`TensorBuffer`]s.
///
/// Iterates [`GgufHeader::tensors`], extracts raw bytes for each via
/// [`extract_tensor_bytes`], and converts them via [`dequantize_to_f32`].
///
/// # Errors
///
/// - [`NexaCoreError::Internal`] if any tensor's bytes are out of bounds or the
///   conversion fails.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::{
///     gguf::{GGUF_MAGIC, GGUF_VERSION_3, GgufDtype, GgufHeader, parse_gguf},
///     tensor_loader::load_all_tensors,
/// };
///
/// let mut buf = Vec::<u8>::new();
/// buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
/// buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
/// buf.extend_from_slice(&0u64.to_le_bytes()); // tensor_count = 0
/// buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count = 0
///
/// let header = parse_gguf(&buf).unwrap();
/// let tensors = load_all_tensors(&buf, &header).unwrap();
/// assert!(tensors.is_empty());
/// ```
pub fn load_all_tensors(data: &[u8], header: &GgufHeader) -> Result<Vec<LoadedTensor>> {
    header
        .tensors
        .iter()
        .map(|info| {
            let raw = extract_tensor_bytes(data, header, info)?;
            let buffer = dequantize_to_f32(info, raw)?;
            Ok(LoadedTensor {
                name: info.name.clone(),
                buffer,
            })
        })
        .collect()
}

// =============================================================================
// load_tensor_by_name
// =============================================================================

/// Load a single tensor by name from a GGUF file.
///
/// Searches [`GgufHeader::tensors`] for an entry whose name equals `name`,
/// then extracts and dequantizes it.
///
/// # Errors
///
/// - [`NexaCoreError::Internal`] if no tensor with the given name exists.
/// - [`NexaCoreError::Internal`] if extraction or conversion fails.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::{
///     gguf::{GGUF_MAGIC, GGUF_VERSION_3, GgufDtype, parse_gguf},
///     tensor_loader::load_tensor_by_name,
/// };
///
/// // Minimal GGUF with no tensors — should return an error for any name.
/// let mut buf = Vec::<u8>::new();
/// buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
/// buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
/// buf.extend_from_slice(&0u64.to_le_bytes());
/// buf.extend_from_slice(&0u64.to_le_bytes());
///
/// let header = parse_gguf(&buf).unwrap();
/// assert!(load_tensor_by_name(&buf, &header, "missing").is_err());
/// ```
pub fn load_tensor_by_name(data: &[u8], header: &GgufHeader, name: &str) -> Result<LoadedTensor> {
    let info = header
        .tensors
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| {
            NexaCoreError::internal("tensor_loader::load_by_name — tensor name not found in header")
        })?;
    let raw = extract_tensor_bytes(data, header, info)?;
    let buffer = dequantize_to_f32(info, raw)?;
    Ok(LoadedTensor {
        name: info.name.clone(),
        buffer,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use nexacore_hal::tensor::TensorDtype;

    use super::*;
    use crate::gguf::{
        GGUF_DEFAULT_ALIGNMENT, GGUF_MAGIC, GGUF_VERSION_3, GgufDtype, GgufTensorInfo, parse_gguf,
    };

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /// Encode a GGUF-format string (u64 length prefix + UTF-8 bytes).
    fn gguf_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf
    }

    /// Build a minimal GGUF file with the given tensors.
    ///
    /// `tensors`: list of `(name, dims, dtype, data_bytes)`.
    ///
    /// Tensor offsets within the data region are packed sequentially with
    /// 32-byte alignment (matching GGUF spec defaults).
    fn make_test_gguf(tensors: &[(&str, &[u64], GgufDtype, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
        buf.extend_from_slice(&(tensors.len() as u64).to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count

        // Pre-compute offsets for tensor data region.
        // Each tensor's offset is aligned to GGUF_DEFAULT_ALIGNMENT within
        // the data region.
        let mut offsets: Vec<u64> = Vec::new();
        let mut running_offset: u64 = 0;
        for (_, _, _, data) in tensors {
            offsets.push(running_offset);
            let next = running_offset + data.len() as u64;
            // Align up to GGUF_DEFAULT_ALIGNMENT.
            running_offset =
                (next + GGUF_DEFAULT_ALIGNMENT as u64 - 1) & !(GGUF_DEFAULT_ALIGNMENT as u64 - 1);
        }

        // Write tensor info entries.
        for ((name, dims, dtype, _), &offset) in tensors.iter().zip(&offsets) {
            buf.extend_from_slice(&gguf_string(name));
            buf.extend_from_slice(&(dims.len() as u32).to_le_bytes());
            for &d in *dims {
                buf.extend_from_slice(&d.to_le_bytes());
            }
            buf.extend_from_slice(&(*dtype as u32).to_le_bytes());
            buf.extend_from_slice(&offset.to_le_bytes());
        }

        // Pad to 32-byte alignment to start the data region.
        while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
            buf.push(0);
        }

        // Write tensor data, inserting alignment padding between tensors.
        for (i, (_, _, _, data)) in tensors.iter().enumerate() {
            buf.extend_from_slice(data);
            if i + 1 < tensors.len() {
                while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
                    buf.push(0);
                }
            }
        }

        buf
    }

    // -------------------------------------------------------------------------
    // test_gguf_dtype_to_hal
    // -------------------------------------------------------------------------

    #[test]
    fn test_gguf_dtype_to_hal() {
        assert_eq!(gguf_dtype_to_hal(GgufDtype::F32), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::F16), TensorDtype::F16);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Bf16), TensorDtype::Bf16);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::I8), TensorDtype::I8);
        // All quantized types → F32
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q4_0), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q4_1), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q5_0), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q5_1), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q8_0), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q8_1), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q2_K), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q3_K), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q4_K), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q5_K), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::Q6_K), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::I16), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::I32), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::I64), TensorDtype::F32);
        assert_eq!(gguf_dtype_to_hal(GgufDtype::F64), TensorDtype::F32);
    }

    // -------------------------------------------------------------------------
    // test_extract_tensor_bytes_f32
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_tensor_bytes_f32() {
        let data_bytes: [u8; 8] = [
            0x00, 0x00, 0x80, 0x3F, // 1.0f32 LE
            0x00, 0x00, 0x00, 0x40, // 2.0f32 LE
        ];
        let gguf_data = make_test_gguf(&[("w", &[2], GgufDtype::F32, &data_bytes)]);
        let header = parse_gguf(&gguf_data).unwrap();
        let info = &header.tensors[0];

        let raw = extract_tensor_bytes(&gguf_data, &header, info).unwrap();
        assert_eq!(raw.len(), 8);
        assert_eq!(&raw[0..4], &1.0f32.to_le_bytes());
        assert_eq!(&raw[4..8], &2.0f32.to_le_bytes());
    }

    // -------------------------------------------------------------------------
    // test_dequantize_f32_passthrough
    // -------------------------------------------------------------------------

    #[test]
    fn test_dequantize_f32_passthrough() {
        let info = GgufTensorInfo {
            name: "test".into(),
            n_dimensions: 1,
            dimensions: vec![3],
            dtype: GgufDtype::F32,
            offset: 0,
        };
        let raw: Vec<u8> = [1.0f32, 2.0f32, 3.0f32]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        let buf = dequantize_to_f32(&info, &raw).unwrap();
        assert_eq!(buf.descriptor.shape, vec![3]);
        assert_eq!(buf.descriptor.dtype, TensorDtype::F32);
        assert_eq!(buf.len(), 12);
        // Values should pass through unchanged.
        let got: Vec<f32> = buf
            .as_bytes()
            .chunks(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        assert_eq!(got, vec![1.0f32, 2.0f32, 3.0f32]);
    }

    // -------------------------------------------------------------------------
    // test_dequantize_f16_to_f32
    // -------------------------------------------------------------------------

    #[test]
    fn test_dequantize_f16_to_f32() {
        let info = GgufTensorInfo {
            name: "h".into(),
            n_dimensions: 1,
            dimensions: vec![2],
            dtype: GgufDtype::F16,
            offset: 0,
        };
        // F16 bit patterns for 1.0 and -2.0:
        // 1.0 → sign=0 exp=0b01111 (15) mantissa=0 → 0x3C00
        // -2.0 → sign=1 exp=0b10000 (16) mantissa=0 → 0xC000
        let raw: Vec<u8> = vec![0x00, 0x3C, 0x00, 0xC0];

        let buf = dequantize_to_f32(&info, &raw).unwrap();
        assert_eq!(buf.descriptor.dtype, TensorDtype::F32);
        assert_eq!(buf.len(), 8);

        let v0 = f32::from_le_bytes(buf.as_bytes()[0..4].try_into().unwrap());
        let v1 = f32::from_le_bytes(buf.as_bytes()[4..8].try_into().unwrap());
        assert!((v0 - 1.0f32).abs() < 1e-6, "expected 1.0, got {v0}");
        assert!((v1 - (-2.0f32)).abs() < 1e-6, "expected -2.0, got {v1}");
    }

    // -------------------------------------------------------------------------
    // test_dequantize_bf16_to_f32
    // -------------------------------------------------------------------------

    #[test]
    fn test_dequantize_bf16_to_f32() {
        let info = GgufTensorInfo {
            name: "b".into(),
            n_dimensions: 1,
            dimensions: vec![1],
            dtype: GgufDtype::Bf16,
            offset: 0,
        };
        // BF16 bit pattern for 1.0:
        // F32 1.0 = 0x3F800000; upper 16 bits = 0x3F80
        // Stored in LE: [0x80, 0x3F]
        let raw: Vec<u8> = vec![0x80, 0x3F];

        let buf = dequantize_to_f32(&info, &raw).unwrap();
        assert_eq!(buf.descriptor.dtype, TensorDtype::F32);
        let v = f32::from_le_bytes(buf.as_bytes()[0..4].try_into().unwrap());
        assert!((v - 1.0f32).abs() < 1e-6, "expected 1.0, got {v}");
    }

    // -------------------------------------------------------------------------
    // test_dequantize_i8_passthrough
    // -------------------------------------------------------------------------

    #[test]
    fn test_dequantize_i8_passthrough() {
        let info = GgufTensorInfo {
            name: "qi".into(),
            n_dimensions: 1,
            dimensions: vec![4],
            dtype: GgufDtype::I8,
            offset: 0,
        };
        let raw: Vec<u8> = vec![1, 2, 3, 4];
        let buf = dequantize_to_f32(&info, &raw).unwrap();
        assert_eq!(buf.descriptor.dtype, TensorDtype::I8);
        assert_eq!(buf.as_bytes(), &[1u8, 2, 3, 4]);
    }

    // -------------------------------------------------------------------------
    // test_dequantize_quantized_returns_zeros
    // -------------------------------------------------------------------------

    #[test]
    fn test_dequantize_quantized_returns_zeros() {
        // Q4_1 with 4 elements: Sprint 8 has not yet implemented Q4_1 dequantization,
        // so it falls through to the zero-fill stub.
        // Byte size for Q4_1: ceil(4/32) * 20 = 20 bytes on disk.
        // The stub ignores raw_bytes and returns a zeroed F32 buffer.
        let info = GgufTensorInfo {
            name: "q".into(),
            n_dimensions: 1,
            dimensions: vec![4],
            dtype: GgufDtype::Q4_1,
            offset: 0,
        };
        let raw: Vec<u8> = vec![0xAB; 20];
        let buf = dequantize_to_f32(&info, &raw).unwrap();
        assert_eq!(buf.descriptor.dtype, TensorDtype::F32);
        assert_eq!(buf.descriptor.shape, vec![4]);
        // All bytes must be zero (deferred dequantization returns zeroed stub).
        assert!(buf.as_bytes().iter().all(|&b| b == 0));
    }

    // -------------------------------------------------------------------------
    // test_load_all_tensors_minimal
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_all_tensors_minimal() {
        let t1_data: Vec<u8> = [1.0f32, 2.0f32]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let t2_data: Vec<u8> = [3.0f32, 4.0f32, 5.0f32]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        let gguf_data = make_test_gguf(&[
            ("layer0.weight", &[2], GgufDtype::F32, &t1_data),
            ("layer0.bias", &[3], GgufDtype::F32, &t2_data),
        ]);

        let header = parse_gguf(&gguf_data).unwrap();
        let loaded = load_all_tensors(&gguf_data, &header).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "layer0.weight");
        assert_eq!(loaded[0].buffer.descriptor.shape, vec![2]);
        assert_eq!(loaded[1].name, "layer0.bias");
        assert_eq!(loaded[1].buffer.descriptor.shape, vec![3]);
    }

    // -------------------------------------------------------------------------
    // test_load_tensor_by_name_found
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_tensor_by_name_found() {
        let data: Vec<u8> = [7.0f32].iter().flat_map(|f| f.to_le_bytes()).collect();
        let gguf_data = make_test_gguf(&[("target", &[1], GgufDtype::F32, &data)]);
        let header = parse_gguf(&gguf_data).unwrap();

        let lt = load_tensor_by_name(&gguf_data, &header, "target").unwrap();
        assert_eq!(lt.name, "target");
        let v = f32::from_le_bytes(lt.buffer.as_bytes()[0..4].try_into().unwrap());
        assert!((v - 7.0f32).abs() < 1e-6, "expected 7.0, got {v}");
    }

    // -------------------------------------------------------------------------
    // test_load_tensor_by_name_not_found
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_tensor_by_name_not_found() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());

        let header = parse_gguf(&buf).unwrap();
        assert!(load_tensor_by_name(&buf, &header, "nope").is_err());
    }

    // -------------------------------------------------------------------------
    // test_f16_zero
    // -------------------------------------------------------------------------

    #[test]
    fn test_f16_zero() {
        // F16 bit pattern 0x0000 → 0.0f32
        assert_eq!(f16_bits_to_f32(0x0000), 0.0f32);
    }

    // -------------------------------------------------------------------------
    // test_f16_negative_zero
    // -------------------------------------------------------------------------

    #[test]
    fn test_f16_negative_zero() {
        // F16 0x8000 → -0.0f32
        let v = f16_bits_to_f32(0x8000);
        assert_eq!(v.to_bits(), (-0.0f32).to_bits());
    }

    // -------------------------------------------------------------------------
    // test_f16_infinity
    // -------------------------------------------------------------------------

    #[test]
    fn test_f16_infinity() {
        // F16 0x7C00 → +Inf
        assert!(f16_bits_to_f32(0x7C00).is_infinite());
        assert!(f16_bits_to_f32(0x7C00).is_sign_positive());
        // F16 0xFC00 → -Inf
        assert!(f16_bits_to_f32(0xFC00).is_infinite());
        assert!(f16_bits_to_f32(0xFC00).is_sign_negative());
    }

    // =========================================================================
    // Golden Q8_0 unit test (TASK-16)
    // =========================================================================

    /// Direct unit test for Q8_0 dequantization of one known block.
    ///
    /// Chosen parameters:
    ///   scale = 0.5f32 (f16 bit pattern 0x3800 = LE [0x00, 0x38])
    ///   quantized values: i8 sequence 1, -1, 2, -2, 3, -3, 4, -4, 5, … (first 16)
    ///                     then 0-padded for remainder of block
    ///
    /// Expected: x[i] = q[i] * 0.5
    #[test]
    fn test_q8_0_golden_one_block() {
        // f16 bit pattern for 0.5: sign=0, exp=14 (biased), mantissa=0 → 0x3800
        // LE encoding: [0x00, 0x38]
        let scale_bits: u16 = 0x3800;
        let scale_f32 = f16_bits_to_f32(scale_bits);
        assert!(
            (scale_f32 - 0.5).abs() < 1e-6,
            "scale should be 0.5, got {scale_f32}"
        );

        // 32 quantized i8 values: alternating positive/negative, cycling [1..-8].
        let q_vals: [i8; 32] = [
            1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6, 7, -7, 8, -8, 9, -9, 10, -10, 11, -11, 12,
            -12, 13, -13, 14, -14, 15, -15, 16, -16,
        ];

        // Build one Q8_0 block: 2-byte scale + 32 × i8
        let mut block = Vec::with_capacity(34);
        block.extend_from_slice(&scale_bits.to_le_bytes());
        for &q in &q_vals {
            block.push(q.to_le_bytes()[0]);
        }
        assert_eq!(block.len(), 34);

        let info = GgufTensorInfo {
            name: "q8_golden".into(),
            n_dimensions: 1,
            dimensions: vec![32],
            dtype: GgufDtype::Q8_0,
            offset: 0,
        };

        let buf = dequantize_to_f32(&info, &block).unwrap();
        assert_eq!(buf.descriptor.dtype, TensorDtype::F32);
        assert_eq!(buf.as_bytes().len(), 32 * 4);

        // Verify each element independently: x[i] = q_vals[i] * 0.5
        for i in 0..32usize {
            let expected = f32::from(q_vals[i]) * 0.5;
            let got = f32::from_le_bytes(buf.as_bytes()[i * 4..i * 4 + 4].try_into().unwrap());
            assert!(
                (got - expected).abs() < 1e-5,
                "Q8_0 element {i}: expected {expected}, got {got}"
            );
        }
    }

    // =========================================================================
    // get_scale_min_k4 unit tests (TASK-16)
    // =========================================================================

    /// Verify the j<4 branch of get_scale_min_k4 with known byte values.
    #[test]
    fn test_get_scale_min_k4_j_lt_4() {
        // scales[0..12] with distinct values so we can verify extraction.
        // j=0: sc = scales[0] & 63 = 0x41 & 63 = 1; m = scales[4] & 63 = 0x45 & 63 = 5
        // j=1: sc = scales[1] & 63 = 0x42 & 63 = 2; m = scales[5] & 63 = 0x46 & 63 = 6
        // j=2: sc = scales[2] & 63 = 0x43 & 63 = 3; m = scales[6] & 63 = 0x47 & 63 = 7
        // j=3: sc = scales[3] & 63 = 0x44 & 63 = 4; m = scales[7] & 63 = 0x48 & 63 = 8
        let scales = [
            0x41u8, 0x42, 0x43, 0x44, // scales[0..4]: sc values (low 6 bits)
            0x45, 0x46, 0x47, 0x48, // scales[4..8]: min values (low 6 bits)
            0x00, 0x00, 0x00, 0x00, // scales[8..12]: used by j>=4 only
        ];
        let (sc, m) = get_scale_min_k4(0, &scales);
        assert_eq!(sc, 1, "j=0 sc");
        assert_eq!(m, 5, "j=0 m");

        let (sc, m) = get_scale_min_k4(1, &scales);
        assert_eq!(sc, 2, "j=1 sc");
        assert_eq!(m, 6, "j=1 m");

        let (sc, m) = get_scale_min_k4(2, &scales);
        assert_eq!(sc, 3, "j=2 sc");
        assert_eq!(m, 7, "j=2 m");

        let (sc, m) = get_scale_min_k4(3, &scales);
        assert_eq!(sc, 4, "j=3 sc");
        assert_eq!(m, 8, "j=3 m");
    }

    /// Verify the j>=4 branch of get_scale_min_k4 with known byte values.
    ///
    /// For j>=4:
    ///   sc = (scales[j+4] & 0x0F) | ((scales[j-4] >> 6) << 4)
    ///   m  = (scales[j+4] >> 4)   | ((scales[j]   >> 6) << 4)
    ///
    /// We pick values where the upper 2 bits of scales[j-4] and scales[j]
    /// are non-zero to exercise both halves.
    #[test]
    fn test_get_scale_min_k4_j_ge_4() {
        // Construct scales such that for j=4:
        //   scales[8] (j+4=8): 0xAB → low nibble = 0xB = 11, high nibble = 0xA = 10
        //   scales[0] (j-4=0): 0xC5 → upper 2 bits = 0xC5 >> 6 = 3
        //   scales[4] (j=4):   0xD2 → upper 2 bits = 0xD2 >> 6 = 3
        //
        // Expected for j=4:
        //   sc = (0xAB & 0x0F) | ((0xC5 >> 6) << 4)
        //      = 11 | (3 << 4)
        //      = 11 | 48 = 59
        //   m  = (0xAB >> 4) | ((0xD2 >> 6) << 4)
        //      = 10 | (3 << 4)
        //      = 10 | 48 = 58
        let mut scales = [0u8; 12];
        scales[0] = 0xC5; // j-4 for j=4
        scales[4] = 0xD2; // j   for j=4
        scales[8] = 0xAB; // j+4 for j=4

        let (sc, m) = get_scale_min_k4(4, &scales);
        // sc = (0xAB & 0x0F) | ((0xC5 >> 6) << 4) = 11 | 48 = 59
        assert_eq!(sc, 59, "j=4 sc: expected 59, got {sc}");
        // m  = (0xAB >> 4) | ((0xD2 >> 6) << 4) = 10 | 48 = 58
        assert_eq!(m, 58, "j=4 m: expected 58, got {m}");
    }

    // =========================================================================
    // Golden Q4_K unit test (TASK-16)
    // =========================================================================

    /// Build one Q4_K block from explicit (d, dmin, scales[12], qs[128]) and
    /// return the 144-byte block.
    ///
    /// This is a test helper — it exposes the encoded block so callers can
    /// compute expected values independently and verify them against
    /// `dequantize_to_f32`.
    fn build_q4_k_block(d_bits: u16, dmin_bits: u16, scales: &[u8; 12], qs: &[u8; 128]) -> Vec<u8> {
        let mut block = Vec::with_capacity(144);
        block.extend_from_slice(&d_bits.to_le_bytes());
        block.extend_from_slice(&dmin_bits.to_le_bytes());
        block.extend_from_slice(scales);
        block.extend_from_slice(qs);
        assert_eq!(block.len(), 144);
        block
    }

    /// Golden test for Q4_K dequantization of one block with VARIED sub-scales
    /// and sub-mins, exercising both branches of `get_scale_min_k4`.
    ///
    /// Design:
    ///   d    = 1.0  (f16 0x3C00)
    ///   dmin = 0.5  (f16 0x3800)
    ///
    /// scales[12] chosen to produce distinct (sc, m) for each of the 8
    /// sub-blocks (j=0..7), exercising both j<4 and j>=4 branches:
    ///
    ///   j=0: sc=2, m=3   j=4: sc derived from scales[8] and scales[0]
    ///   j=1: sc=4, m=5   j=5: sc derived from scales[9] and scales[1]
    ///   j=2: sc=6, m=7   j=6: sc derived from scales[10] and scales[2]
    ///   j=3: sc=8, m=9   j=7: sc derived from scales[11] and scales[3]
    ///
    /// qs[128]: all bytes = 0x12 (low nibble=2, high nibble=1) for simplicity.
    ///
    /// Expected values are computed INDEPENDENTLY here (not by calling the
    /// function under test) using the dequant formula.
    // The golden test is necessarily long: it derives all 8 (sc, m) pairs,
    // verifies each branch of get_scale_min_k4, encodes a full 144-byte block,
    // runs dequantization, and independently checks all 256 outputs. Splitting
    // it would hide the end-to-end derivation chain.
    #[allow(clippy::cognitive_complexity)]
    #[test]
    fn test_q4_k_golden_one_block() {
        // d = 1.0, f16 bit pattern 0x3C00.
        let d_bits: u16 = 0x3C00;
        let d_f32 = f16_bits_to_f32(d_bits);
        assert!((d_f32 - 1.0).abs() < 1e-6, "d should be 1.0, got {d_f32}");

        // dmin = 0.5, f16 bit pattern 0x3800.
        let dmin_bits: u16 = 0x3800;
        let min_f32 = f16_bits_to_f32(dmin_bits);
        assert!(
            (min_f32 - 0.5).abs() < 1e-6,
            "dmin should be 0.5, got {min_f32}"
        );

        // Construct scales[12] so that:
        //   j=0: sc = scales[0] & 63 = 2, m = scales[4] & 63 = 3
        //   j=1: sc = scales[1] & 63 = 4, m = scales[5] & 63 = 5
        //   j=2: sc = scales[2] & 63 = 6, m = scales[6] & 63 = 7
        //   j=3: sc = scales[3] & 63 = 8, m = scales[7] & 63 = 9
        //   j=4: sc = (scales[8] & 0x0F) | ((scales[0] >> 6) << 4)
        //        m  = (scales[8] >> 4)   | ((scales[4] >> 6) << 4)
        //        We want: scales[8] = 0xAB (low=11, high=10); scales[0] & 0xC0=0 → sc=11
        //                 scales[4] & 0xC0=0 → m=10
        //   j=5: scales[9]=0xCD, scales[1]=2 (no upper bits), scales[5]=5 (no upper bits) → sc=13, m=12
        //   j=6: scales[10]=0xEF, scales[2]=6 (no upper bits), scales[6]=7 (no upper bits) → sc=15, m=14
        //   j=7: scales[11]=0x21, scales[3]=8 (no upper bits), scales[7]=9 (no upper bits) → sc=1, m=2
        //
        // We pick scales[0..4] with no upper bits set (< 64) and scales[4..8] with no upper bits set.
        let scales: [u8; 12] = [
            2, 4, 6, 8, // [0..4]: j<4 scale values (low 6 bits), no high bits
            3, 5, 7, 9, // [4..8]: j<4 min values (low 6 bits), no high bits
            0xAB, 0xCD, 0xEF, 0x21, // [8..12]: used by j>=4
        ];

        // Verify expected (sc, m) for each sub-block:
        // j=0..3 (j<4 branch):
        let expected_sc_m: [(u8, u8); 8] = {
            let mut arr = [(0u8, 0u8); 8];
            for j in 0..4 {
                arr[j] = get_scale_min_k4(j, &scales);
            }
            for j in 4..8 {
                arr[j] = get_scale_min_k4(j, &scales);
            }
            arr
        };
        // j=0: sc=2,m=3; j=1: sc=4,m=5; j=2: sc=6,m=7; j=3: sc=8,m=9
        assert_eq!(expected_sc_m[0], (2, 3), "j=0");
        assert_eq!(expected_sc_m[1], (4, 5), "j=1");
        assert_eq!(expected_sc_m[2], (6, 7), "j=2");
        assert_eq!(expected_sc_m[3], (8, 9), "j=3");
        // j=4: sc=(0xAB&0x0F)|((2>>6)<<4) = 11|(0<<4)=11; m=(0xAB>>4)|((3>>6)<<4)=10|(0<<4)=10
        assert_eq!(expected_sc_m[4], (11, 10), "j=4");
        // j=5: sc=(0xCD&0x0F)|((4>>6)<<4)=13|(0<<4)=13; m=(0xCD>>4)|((5>>6)<<4)=12|(0<<4)=12
        assert_eq!(expected_sc_m[5], (13, 12), "j=5");
        // j=6: sc=(0xEF&0x0F)|((6>>6)<<4)=15|(0<<4)=15; m=(0xEF>>4)|((7>>6)<<4)=14|(0<<4)=14
        assert_eq!(expected_sc_m[6], (15, 14), "j=6");
        // j=7: sc=(0x21&0x0F)|((8>>6)<<4)=1|(0<<4)=1; m=(0x21>>4)|((9>>6)<<4)=2|(0<<4)=2
        assert_eq!(expected_sc_m[7], (1, 2), "j=7");

        // qs[128]: all bytes = 0x12 → low nibble = 2, high nibble = 1.
        let qs = [0x12u8; 128];

        let block_bytes = build_q4_k_block(d_bits, dmin_bits, &scales, &qs);
        assert_eq!(block_bytes.len(), 144);

        let info = GgufTensorInfo {
            name: "q4k_golden".into(),
            n_dimensions: 1,
            dimensions: vec![256],
            dtype: GgufDtype::Q4_K,
            offset: 0,
        };

        let buf = dequantize_to_f32(&info, &block_bytes).unwrap();
        assert_eq!(buf.descriptor.dtype, TensorDtype::F32);
        assert_eq!(buf.as_bytes().len(), 256 * 4);

        // Compute expected values independently using the dequant formula.
        // The outer loop steps: is = 0, 2, 4, 6 → step = 0, 1, 2, 3.
        // For each step, sub-block 0 uses is+0 → expected_sc_m[is],
        //                sub-block 1 uses is+1 → expected_sc_m[is+1].
        // All qs bytes are 0x12 → lo_nibble=2, hi_nibble=1.
        let mut expected = vec![0.0f32; 256];
        let mut is: usize = 0;
        for step in 0..4usize {
            let (sc1, m1) = expected_sc_m[is];
            let d1 = d_f32 * f32::from(sc1);
            let m1f = min_f32 * f32::from(m1);

            let (sc2, m2) = expected_sc_m[is + 1];
            let d2 = d_f32 * f32::from(sc2);
            let m2f = min_f32 * f32::from(m2);

            // First 32 elements (low nibbles): y = d1 * 2 - m1f
            for l in 0..32usize {
                expected[step * 64 + l] = d1 * 2.0 - m1f;
            }
            // Next 32 elements (high nibbles): y = d2 * 1 - m2f
            for l in 0..32usize {
                expected[step * 64 + 32 + l] = d2 * 1.0 - m2f;
            }
            is += 2;
        }

        for i in 0..256usize {
            let got = f32::from_le_bytes(buf.as_bytes()[i * 4..i * 4 + 4].try_into().unwrap());
            assert!(
                (got - expected[i]).abs() < 1e-4,
                "Q4_K element {i}: expected {}, got {got}",
                expected[i]
            );
        }
    }

    // =========================================================================
    // Multi-block Q4_K test (TASK-16)
    // =========================================================================

    /// Q4_K dequantization over 2 blocks, verifying that the output is
    /// correctly laid out: first 256 elements from block 0, next 256 from
    /// block 1.
    #[test]
    fn test_q4_k_two_blocks() {
        // Block A: d=1.0 (0x3C00), dmin=0.0 (0x0000), all scales=1, qs all 0x01.
        // j<4 uses scales[j] for sc and scales[j+4] for m. With all 1s:
        //   j<4:  (sc,m) = (1,1)
        //   j>=4: sc=(1&0x0F)|((1>>6)<<4)=1|0=1; m=(1>>4)|((1>>6)<<4)=0|0=0
        let d_a = f16_bits_to_f32(0x3C00); // 1.0
        let min_a = f16_bits_to_f32(0x0000); // 0.0
        let qs_a = [0x01u8; 128]; // low nibble=1, high nibble=0

        // Block B: d=2.0 (0x4000), dmin=0.0, all scales=2, qs all 0x23.
        let scales_b = [2u8; 12];
        let d_b = f16_bits_to_f32(0x4000); // 2.0
        let min_b = f16_bits_to_f32(0x0000); // 0.0
        let qs_b = [0x23u8; 128]; // low nibble=3, high nibble=2

        let block_a = build_q4_k_block(0x3C00, 0x0000, &[1u8; 12], &qs_a);
        let block_b = build_q4_k_block(0x4000, 0x0000, &[2u8; 12], &qs_b);

        let mut data = Vec::new();
        data.extend_from_slice(&block_a);
        data.extend_from_slice(&block_b);
        assert_eq!(data.len(), 288);

        let info = GgufTensorInfo {
            name: "q4k_two".into(),
            n_dimensions: 1,
            dimensions: vec![512],
            dtype: GgufDtype::Q4_K,
            offset: 0,
        };

        let buf = dequantize_to_f32(&info, &data).unwrap();
        assert_eq!(buf.as_bytes().len(), 512 * 4);

        // Check a few representative values in each block.
        // Block A: for j<4, all (sc,m) = (1,1); for j>=4, (sc,m) = (1,0).
        // Step 0 (is=0): sub-block 0: (sc=1,m=1), d1=1.0*1=1.0, m1f=0.0*1=0.0
        //                             low-nibble qs=1 → y=1.0*1-0.0=1.0
        //                sub-block 1: (sc=1,m=1), d2=1.0, m2f=0.0
        //                             high-nibble qs=0 → y=1.0*0-0.0=0.0
        let elem0 = f32::from_le_bytes(buf.as_bytes()[0..4].try_into().unwrap());
        let elem32 = f32::from_le_bytes(buf.as_bytes()[32 * 4..32 * 4 + 4].try_into().unwrap());
        assert!(
            (elem0 - (d_a * 1.0 - min_a * 1.0)).abs() < 1e-4,
            "block A elem 0: got {elem0}"
        );
        assert!(
            (elem32 - (d_a * 0.0 - min_a * 1.0)).abs() < 1e-4,
            "block A elem 32: got {elem32}"
        );

        // Block B starts at element 256.
        // Step 0 (is=0): for j<4 with scales_b=2: (sc=2,m=2)
        // d1=2.0*2=4.0, m1f=0.0*2=0.0; low-nibble=3 → y=4.0*3-0.0=12.0
        let elem256 = f32::from_le_bytes(buf.as_bytes()[256 * 4..256 * 4 + 4].try_into().unwrap());
        let (sc_b0, m_b0) = get_scale_min_k4(0, &scales_b);
        let expected_b0 = d_b * f32::from(sc_b0) * 3.0 - min_b * f32::from(m_b0);
        assert!(
            (elem256 - expected_b0).abs() < 1e-4,
            "block B elem 0: expected {expected_b0}, got {elem256}"
        );
    }

    // =========================================================================
    // Q4_K byte-count mismatch → Err (TASK-16)
    // =========================================================================

    /// A byte buffer whose length is not a multiple of 144 must produce an error.
    #[test]
    fn test_q4_k_byte_count_mismatch_returns_err() {
        // 256 elements → n_blocks=1 → expected 144 bytes; supply 143.
        let info = GgufTensorInfo {
            name: "q4k_bad".into(),
            n_dimensions: 1,
            dimensions: vec![256],
            dtype: GgufDtype::Q4_K,
            offset: 0,
        };
        let short_data = vec![0u8; 143];
        let result = dequantize_to_f32(&info, &short_data);
        assert!(result.is_err(), "must return Err on byte-count mismatch");

        // Also test with 145 bytes (one too many).
        let long_data = vec![0u8; 145];
        let result = dequantize_to_f32(&info, &long_data);
        assert!(
            result.is_err(),
            "must return Err on byte-count mismatch (too long)"
        );

        // Correct size (144) must succeed.
        let correct_data = vec![0u8; 144];
        let result = dequantize_to_f32(&info, &correct_data);
        assert!(result.is_ok(), "must succeed with exactly 144 bytes");
    }

    // =========================================================================
    // Golden Q5_K unit test (WS5-01.5)
    // =========================================================================

    /// Build one Q5_K block from explicit fields, returning the 176-byte block.
    fn build_q5_k_block(
        d_bits: u16,
        dmin_bits: u16,
        scales: &[u8; 12],
        qh: &[u8; 32],
        qs: &[u8; 128],
    ) -> Vec<u8> {
        let mut block = Vec::with_capacity(176);
        block.extend_from_slice(&d_bits.to_le_bytes());
        block.extend_from_slice(&dmin_bits.to_le_bytes());
        block.extend_from_slice(scales);
        block.extend_from_slice(qh);
        block.extend_from_slice(qs);
        assert_eq!(block.len(), 176);
        block
    }

    /// Golden test for Q5_K dequantization, exercising the high-bit (`qh`)
    /// plane on both the low- and high-nibble paths of outer step 0.
    ///
    /// Setup: `d = 1.0`, `dmin = 0.0`, and `scales[0] = scales[1] = 1` with
    /// `scales[4] = scales[5] = 0`, so step-0 sub-blocks have `(sc, m) = (1, 0)`
    /// → `d1 = d2 = 1.0`, `m1 = m2 = 0.0`. Output then equals the 5-bit quant.
    ///
    ///   qs[0] = 0x25 → low nibble 5, high nibble 2
    ///   qh[0] = 0x02 → bit0 (u1=1) clear, bit1 (u2=2) set
    ///   qs[2] = 0x03 → low nibble 3 ; qh[2] = 0x01 → bit0 set
    ///
    /// Expected: out[0] = 5 (lo, no high bit); out[32] = 2 + 16 = 18 (hi, bit1
    /// set); out[2] = 3 + 16 = 19 (lo, bit0 set); everything else 0.
    #[test]
    fn test_q5_k_golden_one_block() {
        let d_bits: u16 = 0x3C00; // 1.0
        let dmin_bits: u16 = 0x0000; // 0.0

        let mut scales = [0u8; 12];
        scales[0] = 1; // step 0 sub-block 0 scale
        scales[1] = 1; // step 0 sub-block 1 scale
        // scales[4]/scales[5] (the mins for j=0/1) stay 0.

        let mut qs = [0u8; 128];
        qs[0] = 0x25; // lo=5, hi=2
        qs[2] = 0x03; // lo=3

        let mut qh = [0u8; 32];
        qh[0] = 0x02; // bit1 set → affects step-0 high nibble (u2=2)
        qh[2] = 0x01; // bit0 set → affects step-0 low nibble (u1=1)

        let block = build_q5_k_block(d_bits, dmin_bits, &scales, &qh, &qs);
        let info = GgufTensorInfo {
            name: "q5k_golden".into(),
            n_dimensions: 1,
            dimensions: vec![256],
            dtype: GgufDtype::Q5_K,
            offset: 0,
        };

        let buf = dequantize_to_f32(&info, &block).unwrap();
        assert_eq!(buf.descriptor.dtype, TensorDtype::F32);
        assert_eq!(buf.as_bytes().len(), 256 * 4);

        let elem = |i: usize| -> f32 {
            f32::from_le_bytes(buf.as_bytes()[i * 4..i * 4 + 4].try_into().unwrap())
        };

        assert!((elem(0) - 5.0).abs() < 1e-4, "out[0] = {}", elem(0));
        assert!((elem(1) - 0.0).abs() < 1e-4, "out[1] = {}", elem(1));
        assert!((elem(2) - 19.0).abs() < 1e-4, "out[2] = {}", elem(2));
        assert!((elem(32) - 18.0).abs() < 1e-4, "out[32] = {}", elem(32));
        // Outer steps 1..4 are untouched (all source bytes there are zero).
        assert!((elem(64) - 0.0).abs() < 1e-4, "out[64] = {}", elem(64));
        assert!((elem(255) - 0.0).abs() < 1e-4, "out[255] = {}", elem(255));
    }

    /// A Q5_K buffer whose length is not a multiple of 176 must produce an error.
    #[test]
    fn test_q5_k_byte_count_mismatch_returns_err() {
        let info = GgufTensorInfo {
            name: "q5k_bad".into(),
            n_dimensions: 1,
            dimensions: vec![256],
            dtype: GgufDtype::Q5_K,
            offset: 0,
        };
        assert!(dequantize_to_f32(&info, &[0u8; 175]).is_err());
        assert!(dequantize_to_f32(&info, &[0u8; 177]).is_err());
        assert!(dequantize_to_f32(&info, &[0u8; 176]).is_ok());
    }

    // =========================================================================
    // Q4_K proptest — no panic on arbitrary bytes (TASK-16)
    // =========================================================================

    /// Proptest: feeding arbitrary byte vectors of lengths that are exact
    /// multiples of 144 (matching n_elements/256 blocks) must never panic.
    /// Non-multiples must return Err. Neither path may panic.
    #[cfg(test)]
    mod proptest_q4k {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// Arbitrary Q4_K byte buffers with exactly 1 block (144 bytes)
            /// must always produce Ok — no panics.
            #[test]
            fn q4k_one_block_no_panic(data in prop::collection::vec(any::<u8>(), 144..=144)) {
                let info = GgufTensorInfo {
                    name: "fuzz".into(),
                    n_dimensions: 1,
                    dimensions: vec![256],
                    dtype: GgufDtype::Q4_K,
                    offset: 0,
                };
                // Must not panic, and must be Ok (exact 144 matches 1 block of 256 elems).
                let result = dequantize_to_f32(&info, &data);
                prop_assert!(result.is_ok(), "exact 144 bytes should succeed");
            }

            /// Arbitrary Q4_K byte buffers with 2 blocks (288 bytes) and
            /// 512 elements must always produce Ok — no panics.
            #[test]
            fn q4k_two_blocks_no_panic(data in prop::collection::vec(any::<u8>(), 288..=288)) {
                let info = GgufTensorInfo {
                    name: "fuzz2".into(),
                    n_dimensions: 1,
                    dimensions: vec![512],
                    dtype: GgufDtype::Q4_K,
                    offset: 0,
                };
                let result = dequantize_to_f32(&info, &data);
                prop_assert!(result.is_ok(), "exact 288 bytes (2 blocks) should succeed");
            }

            /// Arbitrary byte lengths (1..=300) fed to a 256-element Q4_K tensor
            /// (expecting exactly 144 bytes). Non-144 lengths must return Err,
            /// 144 must return Ok. Neither must panic.
            #[test]
            fn q4k_arbitrary_length_no_panic(len in 1usize..=300,
                                             seed in any::<u8>()) {
                let data: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
                let info = GgufTensorInfo {
                    name: "fuzz3".into(),
                    n_dimensions: 1,
                    dimensions: vec![256],
                    dtype: GgufDtype::Q4_K,
                    offset: 0,
                };
                let result = dequantize_to_f32(&info, &data);
                if len == 144 {
                    prop_assert!(result.is_ok(), "len=144 must succeed");
                } else {
                    prop_assert!(result.is_err(), "len={len} must fail (expected 144)");
                }
            }

            /// Arbitrary Q8_0 byte buffers — one block (34 bytes), must never panic.
            #[test]
            fn q8_0_one_block_no_panic(data in prop::collection::vec(any::<u8>(), 34..=34)) {
                let info = GgufTensorInfo {
                    name: "fuzz_q8".into(),
                    n_dimensions: 1,
                    dimensions: vec![32],
                    dtype: GgufDtype::Q8_0,
                    offset: 0,
                };
                let result = dequantize_to_f32(&info, &data);
                prop_assert!(result.is_ok(), "exact 34 bytes Q8_0 should succeed");
            }

            /// Arbitrary Q4_0 byte buffers — one block (18 bytes), must never panic.
            #[test]
            fn q4_0_one_block_no_panic(data in prop::collection::vec(any::<u8>(), 18..=18)) {
                let info = GgufTensorInfo {
                    name: "fuzz_q4".into(),
                    n_dimensions: 1,
                    dimensions: vec![32],
                    dtype: GgufDtype::Q4_0,
                    offset: 0,
                };
                let result = dequantize_to_f32(&info, &data);
                prop_assert!(result.is_ok(), "exact 18 bytes Q4_0 should succeed");
            }

            /// Arbitrary Q5_K byte buffers — one block (176 bytes), must never panic.
            #[test]
            fn q5k_one_block_no_panic(data in prop::collection::vec(any::<u8>(), 176..=176)) {
                let info = GgufTensorInfo {
                    name: "fuzz_q5k".into(),
                    n_dimensions: 1,
                    dimensions: vec![256],
                    dtype: GgufDtype::Q5_K,
                    offset: 0,
                };
                let result = dequantize_to_f32(&info, &data);
                prop_assert!(result.is_ok(), "exact 176 bytes Q5_K should succeed");
            }
        }
    }
}

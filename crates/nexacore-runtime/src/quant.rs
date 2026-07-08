//! GGUF quantized block layouts (WS5-01.1).
//!
//! Byte-exact `#[repr(C)]` mirrors of the ggml / llama.cpp block structs for
//! the quantization schemes the on-device inference engine targets:
//!
//! | Scheme | ggml struct   | elems/block | bytes/block |
//! |--------|---------------|-------------|-------------|
//! | Q8_0   | `block_q8_0`  | 32          | 34          |
//! | Q4_K   | `block_q4_K`  | 256         | 144         |
//! | Q5_K   | `block_q5_K`  | 256         | 176         |
//!
//! These structs define the canonical in-memory layout the `no_std` engine
//! reads tensor data through for fused dequant + matmul (WS5-01.3 onward),
//! without copying. They are layout-compatible with the byte-offset parsing the
//! load-time full-dequant path in [`crate::tensor_loader`] performs today
//! (TASK-16 / ADR-0038); this module formalizes those layouts as named types.
//!
//! Field semantics and the dequantization formulae match llama.cpp exactly
//! (see each struct). `f16` fields are stored as raw little-endian `u16` bit
//! patterns; conversion to `f32` happens in the dequant kernels (WS5-01.3+),
//! reusing the same half-precision decode as `tensor_loader`.

/// Elements per k-quant super-block (`QK_K` in ggml).
pub const QK_K: usize = 256;

/// Elements per legacy-quant block (`QK8_0` in ggml; also `QK4_0`, `QK5_0`).
pub const QK8_0: usize = 32;

/// Encoded size of a [`BlockQ8_0`] in bytes.
pub const BLOCK_Q8_0_BYTES: usize = 34;

/// Encoded size of a [`BlockQ4_K`] in bytes.
pub const BLOCK_Q4_K_BYTES: usize = 144;

/// Encoded size of a [`BlockQ5_K`] in bytes.
pub const BLOCK_Q5_K_BYTES: usize = 176;

/// Size in bytes of the bit-packed `(6-bit scale, 6-bit min)` array shared by
/// the K-quant super-blocks (`K_SCALE_SIZE` in ggml).
pub const K_SCALE_SIZE: usize = 12;

/// Bytes of packed 4-bit quants in a K-quant super-block (`QK_K / 2` = 128).
#[allow(
    clippy::integer_division,
    reason = "exact compile-time division: QK_K (256) is even"
)]
pub const K_QUANT_BYTES: usize = QK_K / 2;

/// Bytes of the `Q5_K` high-bit plane — one bit per element (`QK_K / 8` = 32).
#[allow(
    clippy::integer_division,
    reason = "exact compile-time division: QK_K (256) is a multiple of 8"
)]
pub const Q5K_HIGH_BITS_BYTES: usize = QK_K / 8;

/// `block_q8_0` — one legacy-quant block of [`QK8_0`] (32) elements.
///
/// Layout (34 bytes): an `f16` scale `d` followed by 32 signed 8-bit quants.
/// Dequantization: `y[i] = f16→f32(d) * (qs[i] as f32)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    non_camel_case_types,
    reason = "name mirrors the ggml `block_q8_0` struct for cross-referencing"
)]
pub struct BlockQ8_0 {
    /// `f16` block scale `d`, little-endian bit pattern.
    pub d: u16,
    /// 32 signed 8-bit quantized weights.
    pub qs: [i8; QK8_0],
}

/// `block_q4_K` — one K-quant super-block of [`QK_K`] (256) elements, viewed as
/// 8 sub-blocks of 32.
///
/// Layout (144 bytes):
/// - `d`: `f16` super-block scale applied to the 6-bit sub-scales;
/// - `dmin`: `f16` super-block scale applied to the 6-bit sub-mins;
/// - `scales[12]`: 8 × `(6-bit scale, 6-bit min)` pairs, bit-packed
///   (`get_scale_min_k4` unpacks them);
/// - `qs[128]`: 256 × 4-bit quants, low nibble of each byte first.
///
/// Dequantization (byte-exact to llama.cpp `dequantize_row_q4_K`):
/// `y = f16→f32(d) * sub_scale * q4 - f16→f32(dmin) * sub_min`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    non_camel_case_types,
    reason = "name mirrors the ggml `block_q4_K` struct for cross-referencing"
)]
pub struct BlockQ4_K {
    /// `f16` super-block scale `d` for the 6-bit sub-scales (LE bits).
    pub d: u16,
    /// `f16` super-block min `dmin` for the 6-bit sub-mins (LE bits).
    pub dmin: u16,
    /// 8 × `(6-bit scale, 6-bit min)`, bit-packed into 12 bytes.
    pub scales: [u8; K_SCALE_SIZE],
    /// 256 × 4-bit quants (low nibble first), packed into 128 bytes.
    pub qs: [u8; K_QUANT_BYTES],
}

/// `block_q5_K` — one K-quant super-block of [`QK_K`] (256) elements.
///
/// Identical to [`BlockQ4_K`] plus a 32-byte high-bit plane `qh` carrying the
/// 5th bit of each quant (so each weight is `(qh_bit << 4) | qs_nibble`).
///
/// Layout (176 bytes): `d` (f16) · `dmin` (f16) · `scales[12]` · `qh[32]` ·
/// `qs[128]`. Dequantization matches llama.cpp `dequantize_row_q5_K`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    non_camel_case_types,
    reason = "name mirrors the ggml `block_q5_K` struct for cross-referencing"
)]
pub struct BlockQ5_K {
    /// `f16` super-block scale `d` for the 6-bit sub-scales (LE bits).
    pub d: u16,
    /// `f16` super-block min `dmin` for the 6-bit sub-mins (LE bits).
    pub dmin: u16,
    /// 8 × `(6-bit scale, 6-bit min)`, bit-packed into 12 bytes.
    pub scales: [u8; K_SCALE_SIZE],
    /// 256 × high (5th) bit of each quant, packed into 32 bytes.
    pub qh: [u8; Q5K_HIGH_BITS_BYTES],
    /// 256 × low 4 bits of each quant, packed into 128 bytes.
    pub qs: [u8; K_QUANT_BYTES],
}

// Compile-time guarantees that each `#[repr(C)]` layout is padding-free and
// matches the on-disk GGUF block size. If a field is reordered or a type
// changes, the build breaks here rather than silently misreading tensor data.
const _: () = assert!(core::mem::size_of::<BlockQ8_0>() == BLOCK_Q8_0_BYTES);
const _: () = assert!(core::mem::size_of::<BlockQ4_K>() == BLOCK_Q4_K_BYTES);
const _: () = assert!(core::mem::size_of::<BlockQ5_K>() == BLOCK_Q5_K_BYTES);
// `f16` fields force 2-byte alignment; nothing needs more.
const _: () = assert!(core::mem::align_of::<BlockQ8_0>() == 2);
const _: () = assert!(core::mem::align_of::<BlockQ4_K>() == 2);
const _: () = assert!(core::mem::align_of::<BlockQ5_K>() == 2);

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use super::*;

    #[test]
    fn block_sizes_match_gguf_on_disk_layout() {
        assert_eq!(size_of::<BlockQ8_0>(), 34);
        assert_eq!(size_of::<BlockQ4_K>(), 144);
        assert_eq!(size_of::<BlockQ5_K>(), 176);
        // The exported byte-size constants agree with `size_of`.
        assert_eq!(size_of::<BlockQ8_0>(), BLOCK_Q8_0_BYTES);
        assert_eq!(size_of::<BlockQ4_K>(), BLOCK_Q4_K_BYTES);
        assert_eq!(size_of::<BlockQ5_K>(), BLOCK_Q5_K_BYTES);
    }

    #[test]
    fn blocks_are_two_byte_aligned() {
        assert_eq!(align_of::<BlockQ8_0>(), 2);
        assert_eq!(align_of::<BlockQ4_K>(), 2);
        assert_eq!(align_of::<BlockQ5_K>(), 2);
    }

    #[test]
    fn q8_0_field_offsets() {
        assert_eq!(offset_of!(BlockQ8_0, d), 0);
        assert_eq!(offset_of!(BlockQ8_0, qs), 2);
    }

    #[test]
    fn q4_k_field_offsets() {
        assert_eq!(offset_of!(BlockQ4_K, d), 0);
        assert_eq!(offset_of!(BlockQ4_K, dmin), 2);
        assert_eq!(offset_of!(BlockQ4_K, scales), 4);
        assert_eq!(offset_of!(BlockQ4_K, qs), 16);
    }

    #[test]
    fn q5_k_field_offsets() {
        assert_eq!(offset_of!(BlockQ5_K, d), 0);
        assert_eq!(offset_of!(BlockQ5_K, dmin), 2);
        assert_eq!(offset_of!(BlockQ5_K, scales), 4);
        assert_eq!(offset_of!(BlockQ5_K, qh), 16);
        assert_eq!(offset_of!(BlockQ5_K, qs), 48);
    }

    #[test]
    fn element_and_scale_constants() {
        assert_eq!(QK_K, 256);
        assert_eq!(QK8_0, 32);
        assert_eq!(K_SCALE_SIZE, 12);
        // Derived packed-array sizes used by the layouts.
        assert_eq!(K_QUANT_BYTES, 128); // 4-bit quants
        assert_eq!(Q5K_HIGH_BITS_BYTES, 32); // Q5_K high-bit plane
    }
}

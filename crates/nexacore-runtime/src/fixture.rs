//! `fixture` — the canonical tiny model fixture.
//!
//! One source of truth for the synthetic transformer used by:
//!
//! - the crate's e2e quantised-inference test and the TASK-12
//!   `LocalCpuProvider` golden test (host, `cfg(test)`),
//! - the [`crate::engine`] golden test on the ported sync path (host),
//! - the Ring 3 `nexacore-runtime-image`, which embeds this fixture as its
//!   on-device model for the M1 CPU-fallback smoke (TASK-13-pre /
//!   ADR-0034 — the REAL engine in Ring 3, not a mock).
//!
//! Compiled only under `cfg(test)` or the `fixture-model` feature so the
//! production std surface does not carry fixture code.
//!
//! # Determinism
//!
//! The weights make every greedy step argmax to token id 3 (`'d'`), so the
//! golden `"ab"` (ids `[0, 1]`) with a 4-token budget generates `"dddd"` —
//! pinned by the host golden tests and re-asserted from Ring 3 on the test VM.
//!
//! # TASK-16 additions
//!
//! - [`build_synthetic_q4_k_gguf`]: same logical weights as the Q8_0 fixture
//!   but encoded with `Q4_K` (dtype code 12, 144-byte super-blocks).
//! - [`build_synthetic_f32_gguf`]: the exact same integer-valued weights as
//!   the Q8_0 fixture (scale = 1.0, values 1..=7 cycling) but stored as raw
//!   F32, so Q8_0-vs-F32 cosine similarity ≈ 1.0 and Q4_K-vs-F32 ≥ 0.99.

// Alloc types: re-exported by std's prelude on host builds, pulled from
// `alloc` when building without std (TASK-13-pre / ADR-0034).
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use nexacore_hal::transformer::TransformerConfig;

use crate::bpe::{BpeTokenizer, BpeVocabulary, SpecialTokens};

/// The fixture architecture: `n_layers=1`, `n_heads=1`, `d_model=4`,
/// `d_ff=8`, `vocab_size=8`, `max_seq_len=16` — matching the tensor table
/// of [`build_synthetic_q8_0_gguf`].
#[must_use]
pub const fn config() -> TransformerConfig {
    TransformerConfig {
        n_layers: 1,
        n_heads: 1,
        d_model: 4,
        d_ff: 8,
        vocab_size: 8,
        max_seq_len: 16,
        rms_norm_eps: 1e-5,
    }
}

/// Tokenizer matching the fixture's `vocab_size = 8`.
///
/// Ids 0..=7 map to bytes `a`..=`h`, no merges.  Special ids sit OUTSIDE
/// the model vocabulary (the 8-logit head can never sample them), so
/// generation terminates on budget/context, never EOS — deterministic for
/// the golden.
#[must_use]
pub fn tokenizer() -> BpeTokenizer {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "i ∈ 0..8 always fits in u8"
    )]
    let tokens: Vec<(u32, Vec<u8>)> = (0u32..8).map(|i| (i, vec![b'a' + i as u8])).collect();
    let special = SpecialTokens {
        bos: 252,
        eos: 253,
        pad: 254,
        unk: 255,
    };
    BpeTokenizer::new(BpeVocabulary::new(tokens, Vec::new(), special))
}

/// Build a minimal synthetic GGUF v3 binary with `Q8_0`-encoded weight
/// tensors for a tiny transformer (`n_layers=1`, `n_heads=1`, `d_model=4`,
/// `d_ff=8`, `vocab_size=8`, `max_seq_len=16`).
///
/// All tensors use `Q8_0` encoding with scale = 1.0 (f16 `0x3C00`) and
/// non-zero quantized values so dequantization yields a non-zero F32 buffer.
///
/// # Tensor layout
///
/// | Name                       | Shape  | `n_elements` |
/// |----------------------------|--------|--------------|
/// | `token_embd.weight`        | [8, 4] | 32           |
/// | `blk.0.attn_q.weight`      | [4, 4] | 16           |
/// | `blk.0.attn_k.weight`      | [4, 4] | 16           |
/// | `blk.0.attn_v.weight`      | [4, 4] | 16           |
/// | `blk.0.attn_output.weight` | [4, 4] | 16           |
/// | `blk.0.ffn_gate.weight`    | [4, 8] | 32           |
/// | `blk.0.ffn_up.weight`      | [4, 8] | 32           |
/// | `blk.0.ffn_down.weight`    | [8, 4] | 32           |
/// | `blk.0.attn_norm.weight`   | [4]    | 4 (1 block)  |
/// | `blk.0.ffn_norm.weight`    | [4]    | 4 (1 block)  |
/// | `output.weight`            | [4, 8] | 32           |
/// | `output_norm.weight`       | [4]    | 4 (1 block)  |
///
/// Tensors with `n_elements` < 32 are encoded in a single `Q8_0` block of 34
/// bytes (scale + 32 i8 values); only the first `n_elements` values are
/// semantically meaningful, the rest are zero-padded. This matches the
/// GGUF spec requirement that quantized data is written in complete blocks.
#[must_use]
pub fn build_synthetic_q8_0_gguf() -> Vec<u8> {
    use crate::gguf::{GGUF_DEFAULT_ALIGNMENT, GGUF_MAGIC, GGUF_VERSION_3};

    // F16 bit pattern for 1.0:
    //   sign=0, exponent = 15 (biased) = 0b01111, mantissa = 0
    //   stored little-endian: [0x00, 0x3C]
    const F16_ONE_LE: [u8; 2] = [0x00, 0x3C];
    // Non-zero cycle values [1..=7]: all in i8 range, no truncation possible.
    // CYCLE[i % 7] ∈ [1, 7] ⊂ i8::MIN..=i8::MAX.
    const CYCLE: [i8; 7] = [1, 2, 3, 4, 5, 6, 7];
    // Q8_0 dtype discriminant in the GGUF enum: GgufDtype::Q8_0 = 8.
    const DTYPE_Q8_0: u32 = 8;

    // Encode n_elements into Q8_0 blocks (34 bytes each).
    // The first `n_elements` values cycle through 1..=7; the rest pad to 0.
    let encode_q8_0 = |n_elements: usize| -> Vec<u8> {
        let n_blocks = n_elements.div_ceil(32);
        let mut data = Vec::with_capacity(n_blocks * 34);
        for block in 0..n_blocks {
            data.extend_from_slice(&F16_ONE_LE);
            for j in 0..32usize {
                let elem_idx = block * 32 + j;
                let q: i8 = if elem_idx < n_elements {
                    // elem_idx % 7 ∈ [0, 6]; CYCLE has 7 elements → always
                    // in bounds, so the fallback value is unreachable.
                    CYCLE.get(elem_idx % 7).copied().unwrap_or(1)
                } else {
                    0
                };
                // Reinterpret the i8 bit pattern as u8 for byte-level storage.
                // Values [1,7] share the same bit pattern in i8 and u8.
                data.push(q.to_le_bytes()[0]);
            }
        }
        data
    };

    // Encode a GGUF length-prefixed string (u64 byte count + UTF-8 bytes).
    let gguf_str = |s: &str| -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = Vec::with_capacity(8 + b.len());
        v.extend_from_slice(&(b.len() as u64).to_le_bytes());
        v.extend_from_slice(b);
        v
    };

    // Tensor table: (name, dims, n_elements).
    // Shapes follow the conventions from transformer.rs:
    //   ffn_gate/ffn_up: [d_model, d_ff]
    //   output.weight:   [d_model, vocab_size] (maps to TransformerWeights::output_proj)
    let tensors: &[(&str, &[u64], usize)] = &[
        ("token_embd.weight", &[8, 4], 32),
        ("blk.0.attn_q.weight", &[4, 4], 16),
        ("blk.0.attn_k.weight", &[4, 4], 16),
        ("blk.0.attn_v.weight", &[4, 4], 16),
        ("blk.0.attn_output.weight", &[4, 4], 16),
        ("blk.0.ffn_gate.weight", &[4, 8], 32),
        ("blk.0.ffn_up.weight", &[4, 8], 32),
        ("blk.0.ffn_down.weight", &[8, 4], 32),
        ("blk.0.attn_norm.weight", &[4], 4),
        ("blk.0.ffn_norm.weight", &[4], 4),
        ("output.weight", &[4, 8], 32),
        ("output_norm.weight", &[4], 4),
    ];

    // Pre-encode all tensor data blobs.
    let data_blobs: Vec<Vec<u8>> = tensors.iter().map(|(_, _, n)| encode_q8_0(*n)).collect();

    // Pre-compute byte offsets within the data region (aligned to 32 bytes).
    let mut offsets: Vec<u64> = Vec::with_capacity(tensors.len());
    let mut running: u64 = 0;
    for blob in &data_blobs {
        offsets.push(running);
        let next = running + blob.len() as u64;
        running = (next + GGUF_DEFAULT_ALIGNMENT as u64 - 1) & !(GGUF_DEFAULT_ALIGNMENT as u64 - 1);
    }

    let mut buf = Vec::new();

    // GGUF header.
    buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
    buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
    buf.extend_from_slice(&(tensors.len() as u64).to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count = 0

    // Tensor info entries.
    for ((name, dims, _), &offset) in tensors.iter().zip(&offsets) {
        buf.extend_from_slice(&gguf_str(name));
        // Static fixture table: rank is 1 or 2, the fallback is unreachable.
        buf.extend_from_slice(&u32::try_from(dims.len()).unwrap_or(u32::MAX).to_le_bytes());
        for &d in *dims {
            buf.extend_from_slice(&d.to_le_bytes());
        }
        buf.extend_from_slice(&DTYPE_Q8_0.to_le_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
    }

    // Alignment padding before data region.
    while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
        buf.push(0);
    }

    // Tensor data with inter-tensor alignment padding.
    for (i, blob) in data_blobs.iter().enumerate() {
        buf.extend_from_slice(blob);
        if i + 1 < data_blobs.len() {
            while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
                buf.push(0);
            }
        }
    }

    buf
}

/// Build a minimal synthetic GGUF v3 binary with `Q4_K`-encoded weight tensors.
///
/// Same tiny transformer as [`build_synthetic_q8_0_gguf`]
/// (`n_layers=1`, `n_heads=1`, `d_model=4`, `d_ff=8`, `vocab_size=8`,
/// `max_seq_len=16`).
///
/// Each `Q4_K` super-block encodes 256 elements in 144 bytes:
///   - `d = 1.0` (f16 `0x3C00`): the super-block dequant scale
///   - `dmin = 0.0` (f16 `0x0000`): no offset subtracted
///   - `scales[12]`: all bytes = `0x01` → each sub-block `sc = 1, m = 0`
///     (for `j < 4`); for `j >= 4` the split bits give `sc = 1, m = 0`
///   - `qs[128]`: element values 1..=7 cycled, packed two-per-byte
///     (low nibble = element 2k, high nibble = element 2k+1)
///
/// The dequantized values are identical to the `Q8_0` fixture's values when
/// rounded to integers (both produce values from the set {1,2,3,4,5,6,7}),
/// making the Q4_K-vs-F32 cosine similarity test reliable.
///
/// # Tensor layout
///
/// Identical to [`build_synthetic_q8_0_gguf`] (same names, shapes, and
/// `n_elements`); only the dtype and encoding differ.
#[must_use]
pub fn build_synthetic_q4_k_gguf() -> Vec<u8> {
    use crate::gguf::{GGUF_DEFAULT_ALIGNMENT, GGUF_MAGIC, GGUF_VERSION_3};

    // Q4_K dtype discriminant: GgufDtype::Q4_K = 12.
    const DTYPE_Q4_K: u32 = 12;

    // F16 bit pattern for 1.0: 0x3C00 LE.
    const F16_ONE: [u8; 2] = [0x00, 0x3C];
    // F16 bit pattern for 0.0: 0x0000 LE.
    const F16_ZERO: [u8; 2] = [0x00, 0x00];
    // Cycle values 1..=7 (non-zero nibbles, same as Q8_0 fixture).
    const CYCLE: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];

    // Encode n_elements into Q4_K super-blocks (144 bytes each, 256 elems/block).
    //
    // Layout per block:
    //   [0..2]   f16 d = 1.0
    //   [2..4]   f16 dmin = 0.0
    //   [4..16]  scales[12]: all 0x01 → (sc=1,m=1) for j<4; (sc=1,m=0) for j>=4
    //   [16..144] qs[128]: pairs packed as (CYCLE[2k % 7], CYCLE[(2k+1) % 7])
    //
    // With d=1.0, dmin=0.0:
    //   For j<4: d1=1*1=1, m1f=0*1=0 → y=1*nibble - 0 = nibble value
    //   For j>=4: d1=1*1=1, m1f=0*0=0 → y=1*nibble - 0 = nibble value
    // So dequantized values = nibble values, matching the Q8_0 fixture.
    let encode_q4_k = |n_elements: usize| -> Vec<u8> {
        let n_blocks = n_elements.div_ceil(256);
        let mut data = Vec::with_capacity(n_blocks * 144);
        for block in 0..n_blocks {
            // f16 d = 1.0, dmin = 0.0
            data.extend_from_slice(&F16_ONE);
            data.extend_from_slice(&F16_ZERO);
            // scales[12]: all 0x01
            data.extend_from_slice(&[0x01u8; 12]);
            // qs[128]: 256 nibbles packed as per the Q4_K dequant layout.
            //
            // The dequant loop processes qs in 4 outer steps of 32 bytes each.
            // Within each step (step ∈ 0..4, qs offset = step*32):
            //   output element `step*64 + l`      (l < 32) ← low  nibble of qs[step*32 + l]
            //   output element `step*64 + 32 + l` (l < 32) ← high nibble of qs[step*32 + l]
            //
            // So qs[step*32 + l] must encode:
            //   lo = CYCLE[(step*64 + l) % 7]          (output elem step*64 + l)
            //   hi = CYCLE[(step*64 + 32 + l) % 7]     (output elem step*64 + 32 + l)
            for step in 0..4usize {
                for l in 0..32usize {
                    let out_lo = block * 256 + step * 64 + l;
                    let out_hi = block * 256 + step * 64 + 32 + l;
                    let lo = if out_lo < n_elements {
                        *CYCLE.get(out_lo % 7).unwrap_or(&1)
                    } else {
                        0
                    };
                    let hi = if out_hi < n_elements {
                        *CYCLE.get(out_hi % 7).unwrap_or(&1)
                    } else {
                        0
                    };
                    data.push((hi << 4) | (lo & 0x0F));
                }
            }
        }
        data
    };

    // Encode a GGUF length-prefixed string (u64 byte count + UTF-8 bytes).
    let gguf_str = |s: &str| -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = Vec::with_capacity(8 + b.len());
        v.extend_from_slice(&(b.len() as u64).to_le_bytes());
        v.extend_from_slice(b);
        v
    };

    // Same tensor table as the Q8_0 fixture.
    let tensors: &[(&str, &[u64], usize)] = &[
        ("token_embd.weight", &[8, 4], 32),
        ("blk.0.attn_q.weight", &[4, 4], 16),
        ("blk.0.attn_k.weight", &[4, 4], 16),
        ("blk.0.attn_v.weight", &[4, 4], 16),
        ("blk.0.attn_output.weight", &[4, 4], 16),
        ("blk.0.ffn_gate.weight", &[4, 8], 32),
        ("blk.0.ffn_up.weight", &[4, 8], 32),
        ("blk.0.ffn_down.weight", &[8, 4], 32),
        ("blk.0.attn_norm.weight", &[4], 4),
        ("blk.0.ffn_norm.weight", &[4], 4),
        ("output.weight", &[4, 8], 32),
        ("output_norm.weight", &[4], 4),
    ];

    let data_blobs: Vec<Vec<u8>> = tensors.iter().map(|(_, _, n)| encode_q4_k(*n)).collect();

    let mut offsets: Vec<u64> = Vec::with_capacity(tensors.len());
    let mut running: u64 = 0;
    for blob in &data_blobs {
        offsets.push(running);
        let next = running + blob.len() as u64;
        running = (next + GGUF_DEFAULT_ALIGNMENT as u64 - 1) & !(GGUF_DEFAULT_ALIGNMENT as u64 - 1);
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
    buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
    buf.extend_from_slice(&(tensors.len() as u64).to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());

    for ((name, dims, _), &offset) in tensors.iter().zip(&offsets) {
        buf.extend_from_slice(&gguf_str(name));
        buf.extend_from_slice(&u32::try_from(dims.len()).unwrap_or(u32::MAX).to_le_bytes());
        for &d in *dims {
            buf.extend_from_slice(&d.to_le_bytes());
        }
        buf.extend_from_slice(&DTYPE_Q4_K.to_le_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
    }

    while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
        buf.push(0);
    }

    for (i, blob) in data_blobs.iter().enumerate() {
        buf.extend_from_slice(blob);
        if i + 1 < data_blobs.len() {
            while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
                buf.push(0);
            }
        }
    }

    buf
}

/// Build a minimal synthetic GGUF v3 binary with raw `F32`-encoded weight
/// tensors for the same tiny transformer as [`build_synthetic_q8_0_gguf`].
///
/// The weights are exactly the same logical values that the `Q8_0` fixture
/// produces after dequantization: values 1..=7 cycling, scale=1.0, so
/// dequantized `Q8_0` `weight[i]` = (i%7)+1 for all i in-bounds. Storing those
/// same f32 values directly in the F32 fixture means:
///
/// - `cosine(Q8_0_output, F32_output)` ≈ 1.0 (nearly identical inputs)
/// - `cosine(Q4_K_output, F32_output)` ≥ 0.99 (`Q4_K` encodes the same nibble
///   values with `d=1.0, dmin=0.0`, so the weights are identical to F32 up
///   to quantization error in the 4-bit nibble representation)
///
/// The F32 fixture is used by the E2E cosine-similarity tests (TASK-16).
///
/// # Tensor layout
///
/// Identical shapes to [`build_synthetic_q8_0_gguf`]; dtype F32 (code 0).
#[must_use]
pub fn build_synthetic_f32_gguf() -> Vec<u8> {
    use crate::gguf::{GGUF_DEFAULT_ALIGNMENT, GGUF_MAGIC, GGUF_VERSION_3};

    const DTYPE_F32: u32 = 0;
    const CYCLE: [f32; 7] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];

    // Encode n_elements as raw F32 values cycling through 1.0..=7.0.
    let encode_f32 = |n_elements: usize| -> Vec<u8> {
        let mut data = Vec::with_capacity(n_elements * 4);
        for i in 0..n_elements {
            // CYCLE has 7 elements; i % 7 ∈ [0,6] always in bounds.
            let v = *CYCLE.get(i % 7).unwrap_or(&1.0);
            data.extend_from_slice(&v.to_le_bytes());
        }
        data
    };

    let gguf_str = |s: &str| -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = Vec::with_capacity(8 + b.len());
        v.extend_from_slice(&(b.len() as u64).to_le_bytes());
        v.extend_from_slice(b);
        v
    };

    let tensors: &[(&str, &[u64], usize)] = &[
        ("token_embd.weight", &[8, 4], 32),
        ("blk.0.attn_q.weight", &[4, 4], 16),
        ("blk.0.attn_k.weight", &[4, 4], 16),
        ("blk.0.attn_v.weight", &[4, 4], 16),
        ("blk.0.attn_output.weight", &[4, 4], 16),
        ("blk.0.ffn_gate.weight", &[4, 8], 32),
        ("blk.0.ffn_up.weight", &[4, 8], 32),
        ("blk.0.ffn_down.weight", &[8, 4], 32),
        ("blk.0.attn_norm.weight", &[4], 4),
        ("blk.0.ffn_norm.weight", &[4], 4),
        ("output.weight", &[4, 8], 32),
        ("output_norm.weight", &[4], 4),
    ];

    let data_blobs: Vec<Vec<u8>> = tensors.iter().map(|(_, _, n)| encode_f32(*n)).collect();

    let mut offsets: Vec<u64> = Vec::with_capacity(tensors.len());
    let mut running: u64 = 0;
    for blob in &data_blobs {
        offsets.push(running);
        let next = running + blob.len() as u64;
        running = (next + GGUF_DEFAULT_ALIGNMENT as u64 - 1) & !(GGUF_DEFAULT_ALIGNMENT as u64 - 1);
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
    buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
    buf.extend_from_slice(&(tensors.len() as u64).to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());

    for ((name, dims, _), &offset) in tensors.iter().zip(&offsets) {
        buf.extend_from_slice(&gguf_str(name));
        buf.extend_from_slice(&u32::try_from(dims.len()).unwrap_or(u32::MAX).to_le_bytes());
        for &d in *dims {
            buf.extend_from_slice(&d.to_le_bytes());
        }
        buf.extend_from_slice(&DTYPE_F32.to_le_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
    }

    while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
        buf.push(0);
    }

    for (i, blob) in data_blobs.iter().enumerate() {
        buf.extend_from_slice(blob);
        if i + 1 < data_blobs.len() {
            while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
                buf.push(0);
            }
        }
    }

    buf
}

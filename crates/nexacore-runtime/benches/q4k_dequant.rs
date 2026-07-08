//! Benchmark for `Q4_K` dequantization throughput (TASK-16 / ADR-0038).
//!
//! Measures the time to dequantize a ~1 MiB `Q4_K` tensor — a realistic
//! chunk size for a single weight matrix in a small LLM. Provides a
//! throughput baseline (elements/second and bytes/second) for future
//! SIMD-accelerated implementations to compare against.
//!
//! Run with:
//! ```bash
//! cargo bench -p nexacore-runtime --bench q4k_dequant
//! ```
//!
//! This bench file is NOT compiled for `x86_64-unknown-none` (it uses
//! criterion, which requires std). It is gated by the `[[bench]]` table
//! in Cargo.toml, which is ignored when building with `--target
//! x86_64-unknown-none`.
// Bench files are separate compilation units not covered by the crate-root
// cfg_attr(test, allow(...)). The specific lints below are intentional:
//   - missing_docs: criterion macros generate undocumented functions by design.
//   - expect_used: bench setup panics on bad fixture data; that is acceptable.
//   - doc_markdown: type names like Q4_K, Q8_0 are clearer without backticks
//     in prose comments within bench code.
//   - indexing_slicing: bench helpers use index arithmetic with proven bounds.
//   - items_after_statements: CYCLE const is local to the function body.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::indexing_slicing,
    clippy::items_after_statements
)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nexacore_runtime::{
    gguf::{GgufDtype, GgufTensorInfo},
    tensor_loader::dequantize_to_f32,
};

// Nibble cycle values 1..=7 for synthetic block data.
const CYCLE: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];

// =============================================================================
// Bench helpers
// =============================================================================

/// Build a synthetic `Q4_K` block with known (non-trivial) values.
///
/// Layout: d=1.0 (0x3C00), dmin=0.0 (0x0000), scales all=1, qs cycling
/// through nibble values 1..=7 (same pattern as the fixture model).
fn make_q4k_block() -> [u8; 144] {
    let mut block = [0u8; 144];
    // d = 1.0 (f16 0x3C00 LE)
    block[0] = 0x00;
    block[1] = 0x3C;
    // dmin = 0.0 (f16 0x0000 LE)
    block[2] = 0x00;
    block[3] = 0x00;
    // scales[12]: all 1
    for b in &mut block[4..16] {
        *b = 1;
    }
    // qs[128]: nibble values cycling through CYCLE, packed two-per-byte.
    // (k*2) % 7 and (k*2+1) % 7 are always in [0,6] so indexing is safe.
    for k in 0..128usize {
        let lo = CYCLE[(k * 2) % 7];
        let hi = CYCLE[(k * 2 + 1) % 7];
        // k ∈ [0,127], so 16+k ∈ [16,143] — within the 144-byte array.
        block[16 + k] = (hi << 4) | (lo & 0x0F);
    }
    block
}

/// Build a `Q4_K` byte buffer for `n_blocks` super-blocks (~1 MiB total at
/// ~7300 blocks × 144 bytes = ~1 052 kB).
fn make_q4k_data(n_blocks: usize) -> Vec<u8> {
    let block = make_q4k_block();
    let mut data = Vec::with_capacity(n_blocks * 144);
    for _ in 0..n_blocks {
        data.extend_from_slice(&block);
    }
    data
}

// =============================================================================
// Q4_K dequant throughput
// =============================================================================

/// Measure `Q4_K` dequantization throughput for a ~1 MiB tensor.
///
/// Reports both elements/second (useful for comparing quantisation formats)
/// and bytes-in/second (useful for memory-bandwidth estimation).
fn bench_q4k_dequant(c: &mut Criterion) {
    // ~1 MiB input: 7296 blocks × 144 bytes = 1 050 624 bytes.
    // 7296 blocks × 256 elements = 1 867 776 elements.
    const N_BLOCKS: usize = 7296;
    const N_ELEMENTS: usize = N_BLOCKS * 256;

    let data = make_q4k_data(N_BLOCKS);
    let info = GgufTensorInfo {
        name: "bench_q4k".into(),
        n_dimensions: 1,
        dimensions: vec![N_ELEMENTS as u64],
        dtype: GgufDtype::Q4_K,
        offset: 0,
    };

    let mut group = c.benchmark_group("q4k_dequant_throughput");
    // Report throughput in elements (each element = one f32 output value).
    group.throughput(Throughput::Elements(N_ELEMENTS as u64));

    group.bench_with_input(
        BenchmarkId::new("q4k_dequant_1mib", N_ELEMENTS),
        &data,
        |b, raw| {
            b.iter(|| {
                dequantize_to_f32(&info, raw).expect("bench fixture must dequantize without error")
            });
        },
    );

    group.finish();
}

// =============================================================================
// Comparison: Q4_K vs Q8_0 dequant at equal element count
// =============================================================================

/// Compare `Q4_K` and `Q8_0` dequantization throughput at the same element count.
///
/// This surfaces the relative cost of the k-quant sub-scale unpacking
/// compared to the simpler `Q8_0` block structure.
fn bench_q4k_vs_q8_0(c: &mut Criterion) {
    // Use 256 elements (one Q4_K super-block = 144 bytes,
    //                   eight Q8_0 blocks of 32 = 272 bytes).
    const N_ELEMENTS: usize = 256;

    // Q4_K: 1 block × 144 bytes.
    let q4k_data = make_q4k_data(1);
    let q4k_info = GgufTensorInfo {
        name: "bench_q4k_cmp".into(),
        n_dimensions: 1,
        dimensions: vec![N_ELEMENTS as u64],
        dtype: GgufDtype::Q4_K,
        offset: 0,
    };

    // Q8_0: ceil(256/32) = 8 blocks × 34 bytes = 272 bytes.
    // Scale = 1.0 (f16 0x3C00 LE), quantized values cycling 1..=7.
    let mut q8_data = Vec::with_capacity(8 * 34);
    for block in 0..8usize {
        q8_data.extend_from_slice(&[0x00u8, 0x3C]); // scale = 1.0
        for j in 0..32usize {
            let elem = block * 32 + j;
            // (elem % 7) ∈ [0,6]; +1 ∈ [1,7] — always fits in u8.
            let v = u8::try_from((elem % 7) + 1).unwrap_or(1);
            q8_data.push(v);
        }
    }
    let q8_info = GgufTensorInfo {
        name: "bench_q8_cmp".into(),
        n_dimensions: 1,
        dimensions: vec![N_ELEMENTS as u64],
        dtype: GgufDtype::Q8_0,
        offset: 0,
    };

    let mut group = c.benchmark_group("q4k_vs_q8_0");
    group.throughput(Throughput::Elements(N_ELEMENTS as u64));

    group.bench_function("q4k_256_elems", |b| {
        b.iter(|| {
            dequantize_to_f32(&q4k_info, &q4k_data).expect("Q4_K bench dequant must succeed")
        });
    });

    group.bench_function("q8_0_256_elems", |b| {
        b.iter(|| dequantize_to_f32(&q8_info, &q8_data).expect("Q8_0 bench dequant must succeed"));
    });

    group.finish();
}

criterion_group!(benches, bench_q4k_dequant, bench_q4k_vs_q8_0);
criterion_main!(benches);

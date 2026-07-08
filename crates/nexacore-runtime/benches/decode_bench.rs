//! Benchmark suite for streaming decode throughput (Sprint 8).
// Bench files are separate compilation units not covered by the crate-root
// cfg_attr(test, allow(...)). The specific lints below are intentional here:
//   - missing_docs: criterion macros generate undocumented functions by design.
//   - expect_used: bench setup panics on bad fixture data; that is acceptable.
#![allow(missing_docs, clippy::expect_used)]
//!
//! Measures:
//! - Tokens per second for the streaming decode loop.
//! - Latency per token across prompt sizes (warm-up included in prompt).
//! - Throughput comparison: greedy (temperature=0) vs temperature sampling.
//!
//! Run with:
//! ```bash
//! cargo bench -p nexacore-runtime --bench decode_bench
//! ```

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nexacore_hal::{
    tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype},
    transformer::{TransformerConfig, TransformerLayerWeights, TransformerWeights},
};
use nexacore_runtime::decode::{StreamDecodeConfig, streaming_decode};

// =============================================================================
// Helpers
// =============================================================================

/// Build an F32 [`TensorBuffer`].
fn make_f32_buf(shape: Vec<usize>, values: &[f32]) -> TensorBuffer {
    let desc = TensorDescriptor::new(shape, TensorDtype::F32);
    let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
    TensorBuffer::new(desc, bytes)
}

/// Build a small but non-trivial transformer config for benchmarking.
///
/// Uses `d_model=16, d_ff=32, n_layers=1, vocab_size=32` to keep the
/// benchmark fast while exercising all code paths.
fn bench_config() -> TransformerConfig {
    TransformerConfig {
        n_layers: 1,
        n_heads: 2,
        d_model: 16,
        d_ff: 32,
        vocab_size: 32,
        max_seq_len: 64,
        rms_norm_eps: 1e-5,
    }
}

/// Build matching weights (identity-like matrices for determinism).
fn bench_weights(cfg: &TransformerConfig) -> TransformerWeights {
    let d = cfg.d_model;
    let f = cfg.d_ff;
    let v = cfg.vocab_size;

    let eye = |rows: usize, cols: usize| -> TensorBuffer {
        let n = rows * cols;
        let vals: Vec<f32> = (0..n)
            .map(|i| {
                if i % (cols + 1) == 0 {
                    1.0_f32
                } else {
                    0.01_f32
                }
            })
            .collect();
        make_f32_buf(vec![rows, cols], &vals)
    };
    let ones = |size: usize| -> TensorBuffer { make_f32_buf(vec![size], &vec![1.0_f32; size]) };

    let layer = TransformerLayerWeights {
        attn_q: eye(d, d),
        attn_k: eye(d, d),
        attn_v: eye(d, d),
        attn_o: eye(d, d),
        ffn_gate: eye(d, f),
        ffn_up: eye(d, f),
        ffn_down: eye(f, d),
        attn_norm: ones(d),
        ffn_norm: ones(d),
    };

    TransformerWeights {
        token_embedding: eye(v, d),
        layers: vec![layer],
        output_norm: ones(d),
        output_proj: eye(d, v),
        n_kv_heads: None,
    }
}

// =============================================================================
// Tokens-per-second benchmark
// =============================================================================

/// Measure decode throughput in tokens/second for different `max_new_tokens`.
fn bench_decode_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_tokens_per_second");
    let backend = CpuBackend::new();
    let cfg = bench_config();
    let weights = bench_weights(&cfg);
    let prompt = vec![1u32, 2, 3, 4];

    for &n_tokens in &[1usize, 2, 4] {
        group.throughput(Throughput::Elements(n_tokens as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_tokens), &n_tokens, |b, &n| {
            b.iter(|| {
                let decode_cfg = StreamDecodeConfig {
                    max_new_tokens: n,
                    temperature: 0.0,
                    top_k: 1,
                    eos_token_id: None,
                };
                streaming_decode(&backend, &cfg, &weights, &prompt, decode_cfg).count()
            });
        });
    }

    group.finish();
}

// =============================================================================
// Greedy vs sampled decoding latency
// =============================================================================

/// Compare greedy (temperature=0) vs sampled (temperature=1.0) decoding
/// for a fixed number of tokens.
fn bench_greedy_vs_sampled(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_greedy_vs_sampled");
    let backend = CpuBackend::new();
    let cfg = bench_config();
    let weights = bench_weights(&cfg);
    let prompt = vec![1u32, 2, 3];
    let n_tokens = 2usize;

    group.throughput(Throughput::Elements(n_tokens as u64));

    // Greedy decoding.
    group.bench_function("greedy", |b| {
        b.iter(|| {
            streaming_decode(
                &backend,
                &cfg,
                &weights,
                &prompt,
                StreamDecodeConfig {
                    max_new_tokens: n_tokens,
                    temperature: 0.0,
                    top_k: 1,
                    eos_token_id: None,
                },
            )
            .count();
        });
    });

    // Temperature sampling.
    group.bench_function("sampled_t1", |b| {
        b.iter(|| {
            streaming_decode(
                &backend,
                &cfg,
                &weights,
                &prompt,
                StreamDecodeConfig {
                    max_new_tokens: n_tokens,
                    temperature: 1.0,
                    top_k: 5,
                    eos_token_id: None,
                },
            )
            .count();
        });
    });

    group.finish();
}

// =============================================================================
// Prompt size effect on first-token latency
// =============================================================================

/// Measure time-to-first-token as the prompt grows.
///
/// Autoregressive decode is O(n²) in sequence length due to full-sequence
/// re-processing. This benchmark surfaces that growth rate.
fn bench_prompt_size_effect(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_first_token_latency");
    let backend = CpuBackend::new();
    let cfg = bench_config();
    let weights = bench_weights(&cfg);

    for &prompt_len in &[1usize, 2, 4] {
        // prompt_len is always ≤ 4 in this benchmark; try_from never fails here.
        let prompt_len_u32 = u32::try_from(prompt_len).expect("benchmark prompt_len fits in u32");
        let prompt: Vec<u32> = (0..prompt_len_u32).collect();
        group.bench_with_input(
            BenchmarkId::new("prompt_len", prompt_len),
            &prompt,
            |b, p| {
                b.iter(|| {
                    // Only generate 1 token to isolate first-token latency.
                    let decode_cfg = StreamDecodeConfig {
                        max_new_tokens: 1,
                        temperature: 0.0,
                        top_k: 1,
                        eos_token_id: None,
                    };
                    streaming_decode(&backend, &cfg, &weights, p, decode_cfg)
                        .next()
                        .and_then(std::result::Result::ok)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_decode_throughput,
    bench_greedy_vs_sampled,
    bench_prompt_size_effect,
);
criterion_main!(benches);

//! Benchmark suite for quantization operations (Sprint 8).
// Allow missing_docs in benchmark crates: criterion_group! / criterion_main!
// generate functions that the workspace lint flags. Bench files are not
// public library code and documentation is not required here.
#![allow(missing_docs)]
//!
//! Measures:
//! - Quantize throughput (FP32 → INT8) at various tensor sizes.
//! - Dequantize throughput (INT8 → FP32) at various tensor sizes.
//! - FP32 `MatMul` vs `QuantizedMatMul` latency for square matrices.
//! - Memory footprint: INT8 vs FP32 element counts per byte.
//!
//! Run with:
//! ```bash
//! cargo bench -p nexacore-hal --bench quant_bench
//! ```
//
// Benchmark helpers perform quantization math and synthetic data generation
// that intentionally use float arithmetic and casts — narrowly allowed here.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::tuple_array_conversions,
    clippy::semicolon_if_nothing_returned,
    clippy::suboptimal_flops
)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nexacore_hal::tensor::{
    CpuBackend, QuantizationScheme, TensorBackend, TensorBuffer, TensorDescriptor, TensorDtype,
    TensorOp, symmetric_quant_params,
};

// =============================================================================
// Helpers
// =============================================================================

/// Build an F32 [`TensorBuffer`] from a flat slice of values.
fn make_f32_buf(shape: Vec<usize>, values: &[f32]) -> TensorBuffer {
    let desc = TensorDescriptor::new(shape, TensorDtype::F32);
    let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
    TensorBuffer::new(desc, bytes)
}

/// Build an INT8 [`TensorBuffer`] by quantizing a slice of f32 values.
fn make_i8_buf_from_f32(shape: Vec<usize>, values: &[f32]) -> TensorBuffer {
    let params = symmetric_quant_params(values);
    let desc = TensorDescriptor::new(shape, TensorDtype::I8);
    let bytes: Vec<u8> = values
        .iter()
        .map(|&x| {
            let q_f32 = (x / params.scale).round() + f32::from(params.zero_point);
            let q = q_f32.clamp(-128.0, 127.0) as i8;
            q as u8
        })
        .collect();
    TensorBuffer::new(desc, bytes)
}

/// Generate a synthetic f32 data vector of `n` elements with values in [-1, 1].
fn synthetic_data(n: usize) -> Vec<f32> {
    (0..n)
        .map(|i| {
            // Deterministic values in [-1.0, 1.0] using a simple modular pattern.
            // i % 1000 always fits in u16; cast to u16 first to satisfy
            // cast_precision_loss (u16 <= 999 < 2^10, within f32 mantissa range).
            let v = (i % 1000) as u16;
            f32::from(v) / 500.0_f32 - 1.0_f32
        })
        .collect()
}

/// Tokio single-thread runtime for driving async ops inside benchmarks.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime build")
        .block_on(fut)
}

// =============================================================================
// Quantize throughput benchmark
// =============================================================================

/// Benchmark FP32 → INT8 quantization throughput across tensor sizes.
///
/// Sizes tested: 256, 1024, 4096, 16384 elements.
fn bench_quantize(c: &mut Criterion) {
    let mut group = c.benchmark_group("quantize_fp32_to_int8");
    let backend = CpuBackend::new();

    for &n_elems in &[256usize, 1024, 4096, 16384] {
        let data = synthetic_data(n_elems);
        let buf = make_f32_buf(vec![n_elems], &data);
        group.throughput(Throughput::Elements(n_elems as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_elems), &buf, |b, buf| {
            b.iter(|| {
                block_on(backend.execute(
                    TensorOp::Quantize {
                        scheme: QuantizationScheme::PerTensor,
                    },
                    &[buf],
                ))
                .expect("quantize bench error");
            });
        });
    }

    group.finish();
}

// =============================================================================
// Dequantize throughput benchmark
// =============================================================================

/// Benchmark INT8 → FP32 dequantization throughput across tensor sizes.
fn bench_dequantize(c: &mut Criterion) {
    let mut group = c.benchmark_group("dequantize_int8_to_fp32");
    let backend = CpuBackend::new();

    for &n_elems in &[256usize, 1024, 4096, 16384] {
        let data = synthetic_data(n_elems);
        let params = symmetric_quant_params(&data);
        let buf = make_i8_buf_from_f32(vec![n_elems], &data);
        group.throughput(Throughput::Elements(n_elems as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_elems), &buf, |b, buf| {
            b.iter(|| {
                block_on(backend.execute(TensorOp::Dequantize { params }, &[buf]))
                    .expect("dequantize bench error");
            });
        });
    }

    group.finish();
}

// =============================================================================
// FP32 MatMul vs QuantizedMatMul latency benchmark
// =============================================================================

/// Compare FP32 `MatMul` vs `QuantizedMatMul` for square matrices.
///
/// Sizes tested: 16×16, 32×32, 64×64.
fn bench_matmul_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("matmul_fp32_vs_quantized");
    let backend = CpuBackend::new();

    for &dim in &[16usize, 32, 64] {
        let n = dim * dim;
        let data_a = synthetic_data(n);
        let data_b = synthetic_data(n);

        // FP32 buffers.
        let a_fp32 = make_f32_buf(vec![dim, dim], &data_a);
        let b_fp32 = make_f32_buf(vec![dim, dim], &data_b);

        // INT8 buffers.
        let params_a = symmetric_quant_params(&data_a);
        let params_b = symmetric_quant_params(&data_b);
        let a_i8 = make_i8_buf_from_f32(vec![dim, dim], &data_a);
        let b_i8 = make_i8_buf_from_f32(vec![dim, dim], &data_b);

        group.throughput(Throughput::Elements((dim * dim * dim) as u64)); // FLOPs proxy: M*N*K

        // FP32 MatMul.
        group.bench_with_input(
            BenchmarkId::new("fp32", dim),
            &(&a_fp32, &b_fp32),
            |b, (a, bmat)| {
                b.iter(|| {
                    block_on(backend.execute(
                        TensorOp::MatMul {
                            transpose_a: false,
                            transpose_b: false,
                        },
                        &[a, bmat],
                    ))
                    .expect("fp32 matmul bench error");
                });
            },
        );

        // QuantizedMatMul.
        group.bench_with_input(
            BenchmarkId::new("quantized_i8", dim),
            &(&a_i8, &b_i8),
            |b, (a, bmat)| {
                b.iter(|| {
                    block_on(backend.execute(
                        TensorOp::QuantizedMatMul {
                            params_a,
                            params_b,
                            out_scale: 1.0,
                        },
                        &[a, bmat],
                    ))
                    .expect("quant matmul bench error");
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Memory savings benchmark (informational)
// =============================================================================

/// Measure effective memory savings from INT8 vs FP32.
///
/// This is a throughput benchmark in bytes: it shows the ratio of bytes
/// processed per second for INT8 vs FP32 quantize/dequantize operations,
/// which correlates directly with the 4× theoretical memory reduction.
fn bench_memory_savings(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_savings_int8_vs_fp32");
    let backend = CpuBackend::new();
    let n_elems = 65536usize; // 256 KiB as FP32, 64 KiB as INT8
    let data = synthetic_data(n_elems);

    // FP32 bytes: n_elems * 4.
    let fp32_bytes = n_elems * 4;
    group.throughput(Throughput::Bytes(fp32_bytes as u64));
    let fp32_buf = make_f32_buf(vec![n_elems], &data);

    // Benchmark: quantize the FP32 buffer (cost of reducing from FP32 to INT8).
    group.bench_function("quantize_65k", |b| {
        b.iter(|| {
            block_on(backend.execute(
                TensorOp::Quantize {
                    scheme: QuantizationScheme::PerTensor,
                },
                &[&fp32_buf],
            ))
            .expect("quantize bench error");
        });
    });

    // INT8 bytes: n_elems * 1 (4× smaller).
    let int8_bytes = n_elems;
    group.throughput(Throughput::Bytes(int8_bytes as u64));
    let i8_buf = make_i8_buf_from_f32(vec![n_elems], &data);
    let params = symmetric_quant_params(&data);

    // Benchmark: dequantize the INT8 buffer (cost of expanding back to FP32).
    group.bench_function("dequantize_65k", |b| {
        b.iter(|| {
            block_on(backend.execute(TensorOp::Dequantize { params }, &[&i8_buf]))
                .expect("dequantize bench error");
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_quantize,
    bench_dequantize,
    bench_matmul_comparison,
    bench_memory_savings,
);
criterion_main!(benches);

//! End-to-end integration tests for the transformer forward pass.
//!
//! These tests run against a tiny model to verify that the full pipeline
//! produces non-trivial (non-zero) output.

// Integration tests are not production library code; allow the same
// test-helper lint waivers that the crate's cfg_attr(test, …) block applies
// inside the crate.  These are narrowly-scoped to this integration-test file.
#![allow(
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops
)]

use nexacore_hal::{
    tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype},
    transformer::{
        TransformerConfig, TransformerLayerWeights, TransformerWeights, transformer_forward,
    },
};
use nexacore_types::error::Result;

// Helper: build an F32 TensorBuffer from a shape and a flat slice.
fn make_f32_buf(shape: Vec<usize>, values: &[f32]) -> TensorBuffer {
    let desc = TensorDescriptor::new(shape, TensorDtype::F32);
    let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
    TensorBuffer::new(desc, bytes)
}

// Helper: read all f32 values from a TensorBuffer.
fn read_f32_buf(buf: &TensorBuffer) -> Vec<f32> {
    let raw = buf.as_bytes();
    (0..buf.descriptor.num_elements())
        .map(|i| {
            let b = i * 4;
            f32::from_le_bytes([raw[b], raw[b + 1], raw[b + 2], raw[b + 3]])
        })
        .collect()
}

/// E2E tiny-model test: verify output shape is correct and not all zeros.
#[tokio::test]
async fn test_e2e_tiny_model() -> Result<()> {
    let backend = CpuBackend::new();
    let cfg = TransformerConfig {
        n_layers: 2,
        n_heads: 2,
        d_model: 8,
        d_ff: 16,
        vocab_size: 16,
        max_seq_len: 16,
        rms_norm_eps: 1e-5,
    };

    let make_weight = |rows: usize, cols: usize| -> TensorBuffer {
        let n = rows * cols;
        let vals: Vec<f32> = (0..n).map(|i| ((i % 7) as f32) * 0.1 + 0.01).collect();
        make_f32_buf(vec![rows, cols], &vals)
    };
    let make_vec = |size: usize| -> TensorBuffer {
        let vals: Vec<f32> = (0..size).map(|i| ((i % 5) as f32) * 0.1 + 0.01).collect();
        make_f32_buf(vec![size], &vals)
    };

    let layer = || -> TransformerLayerWeights {
        TransformerLayerWeights {
            attn_q: make_weight(cfg.d_model, cfg.d_model),
            attn_k: make_weight(cfg.d_model, cfg.d_model),
            attn_v: make_weight(cfg.d_model, cfg.d_model),
            attn_o: make_weight(cfg.d_model, cfg.d_model),
            ffn_gate: make_weight(cfg.d_model, cfg.d_ff),
            ffn_up: make_weight(cfg.d_model, cfg.d_ff),
            ffn_down: make_weight(cfg.d_ff, cfg.d_model),
            attn_norm: make_vec(cfg.d_model),
            ffn_norm: make_vec(cfg.d_model),
        }
    };

    let weights = TransformerWeights {
        token_embedding: make_weight(cfg.vocab_size, cfg.d_model),
        layers: vec![layer(), layer()],
        output_norm: make_vec(cfg.d_model),
        output_proj: make_weight(cfg.d_model, cfg.vocab_size),
        n_kv_heads: None,
    };

    let seq_len = 4usize;
    let idx_desc = TensorDescriptor::new(vec![seq_len], TensorDtype::U8);
    let input_ids = TensorBuffer::new(idx_desc, vec![0u8, 1, 2, 3]);

    let logits = transformer_forward(&backend, &cfg, &weights, &input_ids).await?;

    // Shape check.
    assert_eq!(
        logits.descriptor.shape,
        vec![seq_len, cfg.vocab_size],
        "logits shape mismatch"
    );

    // At least some values must be non-zero.
    let vals = read_f32_buf(&logits);
    let any_nonzero = vals.iter().any(|v| v.abs() > 1e-9_f32);
    assert!(
        any_nonzero,
        "all logits are zero — forward pass produced no output"
    );

    Ok(())
}

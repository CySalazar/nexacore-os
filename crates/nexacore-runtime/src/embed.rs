//! Embedding path: pool a transformer hidden state into a dense vector
//! (WS5-03.5).
//!
//! An embedding turns a piece of text into a single fixed-width vector. The
//! engine runs the transformer up to its final hidden state
//! ([`nexacore_hal::transformer::transformer_hidden_sync`], `[seq_len,
//! d_model]`) and then **pools** those per-token states into one `[d_model]`
//! vector. This module implements the pooling and optional L2-normalization —
//! the embedding-specific reduction — plus `embed_sync`, the end-to-end path.
//!
//! Pooling strategies (`Pooling`):
//! * `Pooling::LastToken` — the last token's hidden state. The natural choice
//!   for decoder-only / causal models (the last position has attended to the
//!   whole sequence). This is the "last hidden state" pooling WS5-03.5 names.
//! * `Pooling::Mean` — the mean over all positions (sentence-transformer
//!   style).
//! * `Pooling::Cls` — the first token (BERT `[CLS]` style).
//!
//! With `normalize`, the vector is L2-normalized so a dot product is the cosine
//! similarity — matching `AiEmbedRequest::normalize`. `no_std + alloc`.

// Float reduction over hidden states; the seq-length-to-f32 cast is bounded by
// the (small) sequence length; `len / 4` converts an F32 byte count to a float
// count.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::integer_division
)]

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use nexacore_hal::{
    math::sqrt,
    tensor::{CpuBackend, TensorBuffer},
    transformer::{TransformerConfig, TransformerWeights, transformer_hidden_sync},
};
use nexacore_types::error::{HalErrorKind, NexaCoreError, Result};

/// How to reduce the per-token hidden states `[seq_len, d_model]` to a single
/// `[d_model]` embedding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pooling {
    /// The last token's hidden state (decoder-only / causal convention).
    LastToken,
    /// The element-wise mean over all token positions (sentence-transformer
    /// convention).
    Mean,
    /// The first token's hidden state (BERT `[CLS]` convention).
    Cls,
}

/// Pools a row-major `[seq_len, d_model]` hidden-state slice into `[d_model]`.
///
/// # Errors
///
/// Fails if `seq_len`/`d_model` is zero or `hidden.len() != seq_len * d_model`.
pub fn pool(hidden: &[f32], seq_len: usize, d_model: usize, strategy: Pooling) -> Result<Vec<f32>> {
    if seq_len == 0 || d_model == 0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "embed::pool::empty",
        ));
    }
    let expected = seq_len
        .checked_mul(d_model)
        .ok_or_else(|| NexaCoreError::hal(HalErrorKind::DeviceFailure, "embed::pool::overflow"))?;
    if hidden.len() != expected {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "embed::pool::shape_mismatch",
        ));
    }

    match strategy {
        Pooling::Cls => Ok(row(hidden, 0, d_model)?.to_vec()),
        Pooling::LastToken => Ok(row(hidden, seq_len - 1, d_model)?.to_vec()),
        Pooling::Mean => {
            let mut acc = vec![0.0_f32; d_model];
            for i in 0..seq_len {
                let r = row(hidden, i, d_model)?;
                for (a, &x) in acc.iter_mut().zip(r.iter()) {
                    *a += x;
                }
            }
            let inv = 1.0_f32 / seq_len as f32;
            for a in &mut acc {
                *a *= inv;
            }
            Ok(acc)
        }
    }
}

/// L2-normalizes `v` in place. A zero vector is left unchanged.
pub fn l2_normalize(v: &mut [f32]) {
    let norm_sq: f32 = v.iter().map(|&x| x * x).sum();
    let norm = sqrt(norm_sq);
    if norm > 0.0 {
        let inv = 1.0_f32 / norm;
        for x in v.iter_mut() {
            *x *= inv;
        }
    }
}

/// Pools `hidden` and, when `normalize` is set, L2-normalizes the result.
///
/// # Errors
///
/// Propagates [`pool`] errors.
pub fn embed_from_hidden(
    hidden: &[f32],
    seq_len: usize,
    d_model: usize,
    strategy: Pooling,
    normalize: bool,
) -> Result<Vec<f32>> {
    let mut v = pool(hidden, seq_len, d_model, strategy)?;
    if normalize {
        l2_normalize(&mut v);
    }
    Ok(v)
}

/// End-to-end embedding path: run the transformer to its final hidden state,
/// then pool (and optionally normalize) into a `[d_model]` vector.
///
/// # Errors
///
/// Propagates transformer-forward and pooling errors.
pub fn embed_sync(
    backend: &CpuBackend,
    config: &TransformerConfig,
    weights: &TransformerWeights,
    input_ids: &TensorBuffer,
    strategy: Pooling,
    normalize: bool,
) -> Result<Vec<f32>> {
    let hidden = transformer_hidden_sync(backend, config, weights, input_ids)?;
    let shape = &hidden.descriptor.shape;
    let seq_len = shape
        .first()
        .copied()
        .ok_or_else(|| NexaCoreError::hal(HalErrorKind::DeviceFailure, "embed::hidden_shape"))?;
    let d_model = shape
        .get(1)
        .copied()
        .ok_or_else(|| NexaCoreError::hal(HalErrorKind::DeviceFailure, "embed::hidden_shape"))?;
    let flat = buffer_to_f32(&hidden)?;
    embed_from_hidden(&flat, seq_len, d_model, strategy, normalize)
}

/// Borrows row `i` (`d_model` floats) of a row-major `[_, d_model]` slice.
fn row(hidden: &[f32], i: usize, d_model: usize) -> Result<&[f32]> {
    let start = i
        .checked_mul(d_model)
        .ok_or_else(|| NexaCoreError::hal(HalErrorKind::DeviceFailure, "embed::row::overflow"))?;
    let end = start
        .checked_add(d_model)
        .ok_or_else(|| NexaCoreError::hal(HalErrorKind::DeviceFailure, "embed::row::overflow"))?;
    hidden
        .get(start..end)
        .ok_or_else(|| NexaCoreError::hal(HalErrorKind::DeviceFailure, "embed::row::oob"))
}

/// Decodes an F32 [`TensorBuffer`]'s little-endian bytes into a `Vec<f32>`.
///
/// Shared with the classifier path ([`crate::classify`]), which also needs the
/// transformer hidden state as floats.
pub(crate) fn buffer_to_f32(buf: &TensorBuffer) -> Result<Vec<f32>> {
    let bytes = buf.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "embed::buffer_to_f32::misaligned",
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        let arr: [u8; 4] = chunk.try_into().map_err(|_| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "embed::buffer_to_f32::chunk")
        })?;
        out.push(f32::from_le_bytes(arr));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    use nexacore_hal::{
        tensor::{TensorBuffer, TensorDescriptor, TensorDtype},
        transformer::{TransformerLayerWeights, TransformerWeights},
    };

    use super::*;

    // hidden = [[1,2],[3,4],[5,6]] (seq_len = 3, d_model = 2).
    fn hidden_3x2() -> Vec<f32> {
        vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
    }

    #[test]
    fn last_token_pooling_takes_the_final_row() {
        let v = pool(&hidden_3x2(), 3, 2, Pooling::LastToken).unwrap();
        assert_eq!(v, vec![5.0, 6.0]);
    }

    #[test]
    fn cls_pooling_takes_the_first_row() {
        let v = pool(&hidden_3x2(), 3, 2, Pooling::Cls).unwrap();
        assert_eq!(v, vec![1.0, 2.0]);
    }

    #[test]
    fn mean_pooling_averages_the_rows() {
        let v = pool(&hidden_3x2(), 3, 2, Pooling::Mean).unwrap();
        // column means: (1+3+5)/3 = 3, (2+4+6)/3 = 4.
        assert_eq!(v, vec![3.0, 4.0]);
    }

    #[test]
    fn pool_rejects_shape_mismatch_and_empty() {
        assert!(pool(&hidden_3x2(), 3, 3, Pooling::Mean).is_err()); // 9 != 6
        assert!(pool(&[], 0, 2, Pooling::Mean).is_err());
        assert!(pool(&hidden_3x2(), 3, 0, Pooling::Mean).is_err());
    }

    #[test]
    fn l2_normalize_yields_unit_norm() {
        let mut v = vec![3.0_f32, 4.0];
        l2_normalize(&mut v);
        assert!((v[0] - 0.6).abs() < 1e-6);
        assert!((v[1] - 0.8).abs() < 1e-6);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
        // A zero vector is left untouched.
        let mut z = vec![0.0_f32, 0.0];
        l2_normalize(&mut z);
        assert_eq!(z, vec![0.0, 0.0]);
    }

    #[test]
    fn embed_from_hidden_pools_then_normalizes() {
        let v = embed_from_hidden(&hidden_3x2(), 3, 2, Pooling::LastToken, true).unwrap();
        // Last row [5,6], normalized.
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
    }

    // --- end-to-end path against a tiny zero-weight model -------------------

    fn zeros(shape: Vec<usize>) -> TensorBuffer {
        let desc = TensorDescriptor::new(shape, TensorDtype::F32);
        let n = desc.byte_size();
        TensorBuffer::new(desc, vec![0u8; n])
    }

    fn tiny_config() -> TransformerConfig {
        TransformerConfig {
            n_layers: 1,
            n_heads: 2,
            d_model: 4,
            d_ff: 8,
            vocab_size: 8,
            max_seq_len: 16,
            rms_norm_eps: 1e-5,
        }
    }

    fn tiny_weights() -> TransformerWeights {
        let layer = TransformerLayerWeights {
            attn_q: zeros(vec![4, 4]),
            attn_k: zeros(vec![4, 4]),
            attn_v: zeros(vec![4, 4]),
            attn_o: zeros(vec![4, 4]),
            ffn_gate: zeros(vec![4, 8]),
            ffn_up: zeros(vec![4, 8]),
            ffn_down: zeros(vec![8, 4]),
            attn_norm: zeros(vec![4]),
            ffn_norm: zeros(vec![4]),
        };
        TransformerWeights {
            token_embedding: zeros(vec![8, 4]),
            layers: vec![layer],
            output_norm: zeros(vec![4]),
            output_proj: zeros(vec![4, 8]),
            n_kv_heads: None,
        }
    }

    #[test]
    fn embed_sync_produces_a_d_model_vector() {
        let backend = CpuBackend::new();
        let cfg = tiny_config();
        let weights = tiny_weights();
        let seq_len = 3;
        let ids = TensorBuffer::new(
            TensorDescriptor::new(vec![seq_len], TensorDtype::U8),
            vec![0u8; seq_len],
        );
        let v = embed_sync(&backend, &cfg, &weights, &ids, Pooling::LastToken, false).unwrap();
        assert_eq!(v.len(), cfg.d_model);
        assert!(v.iter().all(|x| x.is_finite()));
    }
}

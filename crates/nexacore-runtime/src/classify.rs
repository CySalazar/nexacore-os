//! Classifier path: run the transformer to its hidden state, project through a
//! linear classification head, and rank the resulting labels (WS5-03.7).
//!
//! A classifier turns a piece of text into a ranked set of `(label, score)`
//! pairs. The engine runs the transformer up to its final hidden state
//! ([`nexacore_hal::transformer::transformer_hidden_sync`], `[seq_len,
//! d_model]`), **pools** it into one `[d_model]` vector (reusing
//! [`crate::embed::pool`]), then applies a **classification head** — a linear
//! projection `[d_model, num_classes]` (+ optional bias) — to obtain
//! `[num_classes]` logits. A numerically stable `softmax` turns the logits
//! into probabilities, and `rank_labels` pairs them with the head's labels
//! and returns the top-scoring ones.
//!
//! The head is a small dense layer held as plain floats, so the whole path is
//! host-testable against a tiny model with no device backend. `no_std + alloc`.

// The path is float maths end to end (head GEMV, softmax); the model effect
// stays behind `CpuBackend`/`TransformerWeights`, so the reductions here are
// pure and host-testable.
#![allow(clippy::float_arithmetic)]

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString as _},
    vec,
    vec::Vec,
};

use nexacore_hal::{
    math::exp,
    tensor::{CpuBackend, TensorBuffer},
    transformer::{TransformerConfig, TransformerWeights, transformer_hidden_sync},
};
use nexacore_types::{
    ai::ScoredLabel,
    error::{HalErrorKind, NexaCoreError, Result},
};

use crate::embed::{Pooling, buffer_to_f32, pool};

/// Numerically stable softmax over `logits`.
///
/// Subtracts the maximum logit before exponentiating so large values cannot
/// overflow `exp`. Returns an empty vector for empty input; a degenerate
/// all-`-inf` input yields an all-zero vector (the sum guard avoids a divide by
/// zero).
#[must_use]
pub fn softmax(logits: &[f32]) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exps: Vec<f32> = logits.iter().map(|&z| exp(z - max)).collect();
    let sum: f32 = exps.iter().sum();
    if sum > 0.0 {
        let inv = 1.0_f32 / sum;
        for e in &mut exps {
            *e *= inv;
        }
    }
    exps
}

/// Applies a linear classification head to a pooled `[d_model]` vector.
///
/// `weight` is row-major `[d_model, num_classes]`, so the output logits are
/// `logits[j] = bias[j] + Σ_i pooled[i] · weight[i, j]`. `bias`, when present,
/// is `[num_classes]`.
///
/// # Errors
///
/// Fails if `num_classes` is zero, if `weight.len() != pooled.len() *
/// num_classes`, or if `bias` is present with the wrong length.
pub fn head_logits(
    pooled: &[f32],
    weight: &[f32],
    bias: Option<&[f32]>,
    num_classes: usize,
) -> Result<Vec<f32>> {
    if num_classes == 0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "classify::head::no_classes",
        ));
    }
    let expected = pooled.len().checked_mul(num_classes).ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "classify::head::overflow")
    })?;
    if weight.len() != expected {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "classify::head::weight_shape",
        ));
    }
    if let Some(b) = bias {
        if b.len() != num_classes {
            return Err(NexaCoreError::hal(
                HalErrorKind::DeviceFailure,
                "classify::head::bias_shape",
            ));
        }
    }

    let mut logits = bias.map_or_else(|| vec![0.0_f32; num_classes], <[f32]>::to_vec);
    // `weight` is exactly `pooled.len()` rows of `num_classes`, so the
    // `chunks_exact`/`zip` pairs every input dimension with its weight row.
    for (&x, row) in pooled.iter().zip(weight.chunks_exact(num_classes)) {
        for (acc, &w) in logits.iter_mut().zip(row.iter()) {
            *acc += x * w;
        }
    }
    Ok(logits)
}

/// Pairs each score with its label and returns the `top_k` highest-scoring
/// labels, ordered by descending score.
///
/// `top_k == 0` returns every label. Ties keep their input order (stable sort),
/// so the ranking is deterministic.
///
/// # Errors
///
/// Fails if `scores.len() != labels.len()`.
pub fn rank_labels<S: AsRef<str>>(
    scores: &[f32],
    labels: &[S],
    top_k: usize,
) -> Result<Vec<ScoredLabel>> {
    if scores.len() != labels.len() {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "classify::rank::label_count",
        ));
    }
    let mut pairs: Vec<ScoredLabel> = scores
        .iter()
        .zip(labels.iter())
        .map(|(&s, l)| ScoredLabel::new(l.as_ref().to_string(), s))
        .collect();
    // Descending by score; `total_cmp` gives a deterministic total order
    // (handles NaN) without a partial-ord unwrap.
    pairs.sort_by(|a, b| b.score.total_cmp(&a.score));
    if top_k != 0 && top_k < pairs.len() {
        pairs.truncate(top_k);
    }
    Ok(pairs)
}

/// A linear classification head over a pooled transformer hidden state.
///
/// Holds the projection as plain floats (the head is small relative to the
/// transformer), so the classifier path is host-testable without a device
/// backend.
pub struct ClassifierHead {
    /// Row-major `[d_model, num_classes]` projection weight.
    pub weight: Vec<f32>,
    /// Optional per-class bias `[num_classes]`.
    pub bias: Option<Vec<f32>>,
    /// One label per output class (length defines `num_classes`).
    pub labels: Vec<String>,
}

impl ClassifierHead {
    /// The number of output classes (the label count).
    #[must_use]
    pub fn num_classes(&self) -> usize {
        self.labels.len()
    }

    /// Runs the full classifier path: encode → pool → head → softmax → top-k
    /// labels.
    ///
    /// `pooling` selects how the per-token hidden states collapse to one vector
    /// (CLS is the usual choice for a classification head); `top_k` bounds the
    /// returned labels (`0` returns all).
    ///
    /// # Errors
    ///
    /// Propagates transformer-forward, pooling, and head/shape errors.
    pub fn classify_sync(
        &self,
        backend: &CpuBackend,
        config: &TransformerConfig,
        weights: &TransformerWeights,
        input_ids: &TensorBuffer,
        pooling: Pooling,
        top_k: usize,
    ) -> Result<Vec<ScoredLabel>> {
        let hidden = transformer_hidden_sync(backend, config, weights, input_ids)?;
        let shape = &hidden.descriptor.shape;
        let seq_len = shape.first().copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "classify::hidden_shape")
        })?;
        let d_model = shape.get(1).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "classify::hidden_shape")
        })?;
        let flat = buffer_to_f32(&hidden)?;
        let pooled = pool(&flat, seq_len, d_model, pooling)?;
        let logits = head_logits(
            &pooled,
            &self.weight,
            self.bias.as_deref(),
            self.num_classes(),
        )?;
        let probs = softmax(&logits);
        rank_labels(&probs, &self.labels, top_k)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString as _, vec, vec::Vec};

    use nexacore_hal::{
        tensor::{TensorBuffer, TensorDescriptor, TensorDtype},
        transformer::{TransformerLayerWeights, TransformerWeights},
    };

    use super::*;

    #[test]
    fn softmax_is_a_distribution_and_preserves_order() {
        let p = softmax(&[1.0, 2.0, 3.0]);
        let sum: f32 = p.iter().sum();
        assert!((sum - 1.0).abs() < 1e-6);
        // Monotonic in the logits: larger logit -> larger probability.
        assert!(p[0] < p[1] && p[1] < p[2]);
    }

    #[test]
    fn softmax_uniform_for_equal_logits() {
        let p = softmax(&[0.0, 0.0, 0.0]);
        for &x in &p {
            assert!((x - 1.0 / 3.0).abs() < 1e-6);
        }
    }

    #[test]
    fn softmax_is_numerically_stable_for_large_logits() {
        // Without max-subtraction these would overflow `exp` to inf/NaN.
        let p = softmax(&[1000.0, 1000.0]);
        assert!((p[0] - 0.5).abs() < 1e-6);
        assert!((p[1] - 0.5).abs() < 1e-6);
        assert!(p.iter().all(|x| x.is_finite()));
    }

    #[test]
    fn softmax_empty_is_empty() {
        assert!(softmax(&[]).is_empty());
    }

    #[test]
    fn head_logits_projects_with_bias() {
        // pooled = [1, 2], weight (d_model=2, num_classes=3) row-major:
        //   row0 = [1, 0, 2], row1 = [0, 1, 3]
        // logits[j] = bias[j] + pooled0*row0[j] + pooled1*row1[j]
        //   j0 = 0.5 + 1*1 + 2*0 = 1.5
        //   j1 = 0.5 + 1*0 + 2*1 = 2.5
        //   j2 = 0.5 + 1*2 + 2*3 = 8.5
        let pooled = [1.0_f32, 2.0];
        let weight = [1.0_f32, 0.0, 2.0, 0.0, 1.0, 3.0];
        let bias = [0.5_f32, 0.5, 0.5];
        let logits = head_logits(&pooled, &weight, Some(&bias), 3).unwrap();
        assert_eq!(logits, vec![1.5, 2.5, 8.5]);
    }

    #[test]
    fn head_logits_without_bias() {
        let pooled = [1.0_f32, 1.0];
        let weight = [1.0_f32, 2.0, 3.0, 4.0]; // d_model=2, num_classes=2
        let logits = head_logits(&pooled, &weight, None, 2).unwrap();
        // j0 = 1*1 + 1*3 = 4, j1 = 1*2 + 1*4 = 6
        assert_eq!(logits, vec![4.0, 6.0]);
    }

    #[test]
    fn head_logits_rejects_bad_shapes() {
        // weight shape mismatch: pooled(2) * num_classes(2) = 4 != weight len 3.
        assert!(head_logits(&[1.0, 2.0], &[1.0, 2.0, 3.0], None, 2).is_err());
        // zero classes.
        assert!(head_logits(&[1.0], &[1.0], None, 0).is_err());
        // bias length mismatch with an otherwise-correct weight shape:
        // pooled(1) * num_classes(2) = 2 == weight len 2, but bias len 1 != 2.
        assert!(head_logits(&[1.0], &[1.0, 2.0], Some(&[0.0]), 2).is_err());
        // a well-formed call with bias succeeds (guards against over-rejection).
        assert!(head_logits(&[1.0], &[1.0, 2.0], Some(&[0.0, 0.0]), 2).is_ok());
    }

    #[test]
    fn rank_labels_sorts_and_truncates() {
        let scores = [0.1_f32, 0.7, 0.2];
        let labels = ["a", "b", "c"];
        let top2 = rank_labels(&scores, &labels, 2).unwrap();
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].label, "b");
        assert_eq!(top2[1].label, "c");

        // top_k == 0 returns all, still sorted descending.
        let all = rank_labels(&scores, &labels, 0).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].label, "b");
        assert_eq!(all[2].label, "a");
    }

    #[test]
    fn rank_labels_rejects_length_mismatch() {
        assert!(rank_labels(&[0.5_f32], &["a", "b"], 0).is_err());
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

    fn tiny_head() -> ClassifierHead {
        ClassifierHead {
            // d_model = 4, num_classes = 3, all zeros -> uniform logits.
            weight: vec![0.0_f32; 4 * 3],
            bias: None,
            labels: vec!["x".to_string(), "y".to_string(), "z".to_string()],
        }
    }

    #[test]
    fn classify_sync_produces_ranked_labels() {
        let backend = CpuBackend::new();
        let cfg = tiny_config();
        let weights = tiny_weights();
        let head = tiny_head();
        let seq_len = 3;
        let ids = TensorBuffer::new(
            TensorDescriptor::new(vec![seq_len], TensorDtype::U8),
            vec![0u8; seq_len],
        );

        // top_k = 0 -> all classes; zero head -> uniform 1/3 probabilities.
        let all = head
            .classify_sync(&backend, &cfg, &weights, &ids, Pooling::Cls, 0)
            .unwrap();
        assert_eq!(all.len(), 3);
        let sum: f32 = all.iter().map(|l| l.score).sum();
        assert!((sum - 1.0).abs() < 1e-6);
        for l in &all {
            assert!((l.score - 1.0 / 3.0).abs() < 1e-6);
        }

        // top_k = 2 truncates to the two highest-scoring labels.
        let top2 = head
            .classify_sync(&backend, &cfg, &weights, &ids, Pooling::Cls, 2)
            .unwrap();
        assert_eq!(top2.len(), 2);
    }
}

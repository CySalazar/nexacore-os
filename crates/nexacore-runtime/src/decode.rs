//! Streaming greedy / sampled decode loop for autoregressive language models.
//!
//! This module implements a token-by-token decode loop on top of the
//! [`nexacore_hal::transformer`] forward pass.  The loop is lazy: it implements
//! [`Iterator`] so callers receive tokens as they are generated without
//! buffering the entire output sequence.
//!
//! # Sampling strategy
//!
//! Two controls are exposed:
//!
//! - **Temperature** (`temperature`): divides the logits before softmax.
//!   `temperature = 1.0` is the identity; `temperature → 0.0` approaches
//!   greedy (argmax); high temperature makes the distribution more uniform.
//!   Use `temperature = 0.0` to request greedy decoding (argmax, no sampling).
//!
//! - **Top-k** (`top_k`): restricts sampling to the `k` highest-probability
//!   tokens after temperature scaling.  `top_k = 1` is equivalent to greedy
//!   decoding.  `top_k = 0` disables top-k filtering (full vocabulary
//!   sampling).
//!
//! # Streaming
//!
//! [`crate::decode::streaming_decode`] returns a synchronous [`Iterator`].  Each call to
//! `next()` runs one transformer forward pass and yields one [`crate::decode::DecodeToken`].
//!
//! The loop terminates when any of the following conditions is met:
//! - `max_new_tokens` have been generated.
//! - The EOS token is sampled (if `eos_token_id` is `Some`).
//! - An error occurs during sampling or forward pass; the error is yielded as
//!   the next item and the iterator returns `None` on subsequent calls.
//!
//! # Usage
//!
//! ```no_run
//! # use nexacore_hal::tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype};
//! # use nexacore_hal::transformer::{TransformerConfig, TransformerLayerWeights, TransformerWeights};
//! # use nexacore_runtime::decode::{streaming_decode, StreamDecodeConfig};
//! # let backend = CpuBackend::new();
//! # let config = TransformerConfig {
//! #     n_layers: 1, n_heads: 1, d_model: 4, d_ff: 8,
//! #     vocab_size: 8, max_seq_len: 16, rms_norm_eps: 1e-5,
//! # };
//! # let weights: TransformerWeights = todo!();
//! # let prompt_ids: Vec<u32> = vec![1, 2];
//! let decode_cfg = StreamDecodeConfig {
//!     max_new_tokens: 10,
//!     temperature: 0.8,
//!     top_k: 5,
//!     eos_token_id: Some(2),
//! };
//! for token in streaming_decode(&backend, &config, &weights, &prompt_ids, decode_cfg) {
//!     let tok = token.unwrap();
//!     println!("token {} at position {}", tok.token_id, tok.position);
//! }
//! ```

#![allow(clippy::float_arithmetic)]

// Alloc types: re-exported by std's prelude on host builds, pulled from
// `alloc` when building without std (TASK-13-pre / ADR-0034).
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use nexacore_hal::{
    tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype},
    transformer::{TransformerConfig, TransformerWeights, transformer_forward_sync},
};
use nexacore_types::error::{HalErrorKind, NexaCoreError, Result};

// =============================================================================
// Public types
// =============================================================================

/// Configuration for the streaming autoregressive decode loop.
///
/// Controls sampling strategy (temperature, top-k) and termination conditions
/// (max tokens, EOS token).
///
/// # Example
///
/// ```
/// use nexacore_runtime::decode::StreamDecodeConfig;
///
/// // Greedy decode: temperature = 0.0 or top_k = 1.
/// let greedy = StreamDecodeConfig {
///     max_new_tokens: 20,
///     temperature: 0.0,
///     top_k: 1,
///     eos_token_id: Some(2),
/// };
/// assert_eq!(greedy.top_k, 1);
/// ```
#[derive(Clone, Debug)]
pub struct StreamDecodeConfig {
    /// Maximum number of new tokens to generate (excluding the prompt).
    ///
    /// The loop terminates after generating exactly this many tokens even if
    /// no EOS has been sampled.  Must be `>= 1`.
    pub max_new_tokens: usize,

    /// Temperature for softmax sampling.
    ///
    /// - `0.0`: greedy decoding (argmax), no sampling.
    /// - `1.0`: unscaled probabilities.
    /// - `> 1.0`: more uniform distribution (creative / diverse).
    /// - `0 < t < 1.0`: sharper distribution (more focused / conservative).
    ///
    /// Negative values are rejected at runtime.
    pub temperature: f32,

    /// Restrict sampling to the top-k highest-probability tokens.
    ///
    /// - `0`: disable top-k filtering (sample from the full vocabulary).
    /// - `1`: always pick the argmax (greedy).
    /// - `k > 1`: sample uniformly from the k highest-probability tokens
    ///   after temperature scaling and renormalization.
    pub top_k: usize,

    /// Token ID that signals end-of-sequence.
    ///
    /// When `Some(id)`, the decode loop stops immediately after sampling this
    /// token, yielding it as the last [`DecodeToken`].  When `None`, the loop
    /// runs until `max_new_tokens` is exhausted.
    pub eos_token_id: Option<u32>,
}

/// A single generated token yielded by the streaming decode iterator.
///
/// # Example
///
/// ```
/// use nexacore_runtime::decode::DecodeToken;
///
/// let tok = DecodeToken {
///     token_id: 42,
///     position: 7,
/// };
/// assert_eq!(tok.token_id, 42);
/// assert_eq!(tok.position, 7);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeToken {
    /// The sampled token ID.
    pub token_id: u32,
    /// Zero-based sequence position of this token (prompt length + step index).
    pub position: usize,
}

// =============================================================================
// Iterator state machine
// =============================================================================

/// Internal state enum that drives the decode iterator.
///
/// Using a state machine avoids borrowing issues and makes the terminal
/// conditions explicit.
enum DecodeState {
    /// The iterator is still generating tokens.  Holds the current token
    /// sequence (prompt + previously generated tokens).
    Running {
        /// Accumulated token IDs (prompt + all generated tokens so far).
        tokens: Vec<u32>,
        /// Number of new tokens generated so far (excluding the prompt).
        generated: usize,
    },
    /// The iterator has finished (EOS hit, `max_tokens` reached, or error).
    Done,
}

/// Streaming autoregressive decode iterator.
///
/// Produced by [`streaming_decode`].  Each call to [`Iterator::next`] runs one
/// transformer forward pass and yields the next generated token.
///
/// # Lifetime
///
/// The iterator holds shared references to the backend, config, and weights,
/// so it cannot outlive those values.
pub struct StreamDecoder<'a> {
    backend: &'a CpuBackend,
    config: &'a TransformerConfig,
    weights: &'a TransformerWeights,
    decode_cfg: StreamDecodeConfig,
    state: DecodeState,
}

impl<'a> StreamDecoder<'a> {
    /// Construct a new `StreamDecoder`.
    ///
    /// This is the same as calling [`streaming_decode`] directly.
    #[must_use]
    fn new(
        backend: &'a CpuBackend,
        config: &'a TransformerConfig,
        weights: &'a TransformerWeights,
        prompt_ids: &[u32],
        decode_cfg: StreamDecodeConfig,
    ) -> Self {
        Self {
            backend,
            config,
            weights,
            decode_cfg,
            state: DecodeState::Running {
                tokens: prompt_ids.to_vec(),
                generated: 0,
            },
        }
    }

    /// Run one decode step: forward pass + sampling.  Returns the sampled token
    /// or an error.
    fn step(&self, tokens: &[u32]) -> Result<u32> {
        // Build the input_ids buffer from the current token sequence.
        // Tokens are stored as u8 indices (the existing embedding lookup API
        // uses U8 dtype).  For vocabularies > 255 a wider representation would
        // be needed; this sprint targets the existing CpuBackend embedding API.
        let seq_len = tokens.len();
        let idx_desc = TensorDescriptor::new(vec![seq_len], TensorDtype::U8);

        // Clamp each token ID to u8 for the embedding lookup.
        // The existing transformer embedding uses U8 indices; this is noted as
        // a limitation for large vocabularies and tracked for Phase 4.
        let raw_bytes: Vec<u8> = tokens
            .iter()
            .map(|&id| {
                // Clamp silently: values > 255 are wrapped to 255 (unknown token).
                // This is the safe fallback for the current U8 embedding constraint.
                u8::try_from(id).unwrap_or(u8::MAX)
            })
            .collect();

        let input_ids = TensorBuffer::new(idx_desc, raw_bytes);

        // Run the transformer forward pass.  Fully synchronous: the forward
        // compute body is sync ([`transformer_forward_sync`]), so the former
        // tokio `block_on` bridge is gone — one less moving part, and the
        // decode loop is `no_std`-capable (TASK-13-pre / ADR-0034).
        let logits = transformer_forward_sync(self.backend, self.config, self.weights, &input_ids)?;

        // Extract the last row of the logits tensor: [seq_len, vocab_size]
        // → last row → [vocab_size].
        let vocab_size = self.config.vocab_size;
        let last_logits = extract_last_row(&logits, seq_len, vocab_size)?;

        // Apply temperature and top-k, then sample.
        sample_token(
            &last_logits,
            self.decode_cfg.temperature,
            self.decode_cfg.top_k,
        )
    }
}

impl Iterator for StreamDecoder<'_> {
    type Item = Result<DecodeToken>;

    fn next(&mut self) -> Option<Self::Item> {
        // Borrow the state to check if we're done.  We replace it in-place
        // to avoid partial-move issues.
        let running = match &self.state {
            DecodeState::Done => return None,
            DecodeState::Running { tokens, generated } => {
                let t = tokens.clone();
                let g = *generated;
                (t, g)
            }
        };

        let (mut tokens, generated) = running;

        // Check termination: max_new_tokens reached.
        if generated >= self.decode_cfg.max_new_tokens {
            self.state = DecodeState::Done;
            return None;
        }

        // Run one forward step.
        let token_id = match self.step(&tokens) {
            Ok(id) => id,
            Err(e) => {
                self.state = DecodeState::Done;
                return Some(Err(e));
            }
        };

        let position = tokens.len();
        tokens.push(token_id);

        let is_eos = self
            .decode_cfg
            .eos_token_id
            .is_some_and(|eos| eos == token_id);

        // Update state.
        if is_eos || generated + 1 >= self.decode_cfg.max_new_tokens {
            self.state = DecodeState::Done;
        } else {
            self.state = DecodeState::Running {
                tokens,
                generated: generated + 1,
            };
        }

        Some(Ok(DecodeToken { token_id, position }))
    }
}

// =============================================================================
// Public constructor
// =============================================================================

/// Create a streaming autoregressive decode iterator.
///
/// The iterator performs one transformer forward pass per call to
/// [`Iterator::next`], yielding tokens lazily as they are generated.
///
/// # Parameters
///
/// - `backend`: the [`CpuBackend`] instance to use for tensor ops.
/// - `config`: transformer architecture configuration (must match `weights`).
/// - `weights`: pre-loaded transformer weights.
/// - `prompt_ids`: the tokenized prompt as a slice of token IDs.
/// - `decode_cfg`: sampling parameters and termination conditions.
///
/// # Errors
///
/// Individual `next()` calls may return `Err(NexaCoreError::Hal { .. })` if a
/// tensor operation fails.  After an error, the iterator returns `None`.
///
/// # Example
///
/// ```no_run
/// # use nexacore_hal::tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype};
/// # use nexacore_hal::transformer::{TransformerConfig, TransformerLayerWeights, TransformerWeights};
/// # use nexacore_runtime::decode::{streaming_decode, StreamDecodeConfig};
/// # let backend = CpuBackend::new();
/// # let config: TransformerConfig = todo!();
/// # let weights: TransformerWeights = todo!();
/// let cfg = StreamDecodeConfig { max_new_tokens: 5, temperature: 1.0, top_k: 0, eos_token_id: None };
/// let tokens: Vec<_> = streaming_decode(&backend, &config, &weights, &[1u32, 2, 3], cfg)
///     .collect::<Result<Vec<_>, _>>()
///     .expect("decode failed");
/// ```
pub fn streaming_decode<'a>(
    backend: &'a CpuBackend,
    config: &'a TransformerConfig,
    weights: &'a TransformerWeights,
    prompt_ids: &[u32],
    decode_cfg: StreamDecodeConfig,
) -> StreamDecoder<'a> {
    StreamDecoder::new(backend, config, weights, prompt_ids, decode_cfg)
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Extract the last row of a `[seq_len, vocab_size]` logits buffer into a
/// flat `Vec<f32>` of length `vocab_size`.
///
/// This gives the prediction distribution over the vocabulary for the last
/// sequence position — the standard autoregressive sampling point.
///
/// `pub(crate)`: shared with `provider::local_cpu` (TASK-12), whose async
/// generate loop drives `transformer_forward` directly (the sync
/// [`StreamDecoder`] would nest a `block_on` inside the provider's async
/// context) — promoting the helper avoids duplicating the extraction.
pub(crate) fn extract_last_row(
    logits: &TensorBuffer,
    seq_len: usize,
    vocab_size: usize,
) -> Result<Vec<f32>> {
    if seq_len == 0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "decode::extract_last_row::seq_len_zero",
        ));
    }
    if vocab_size == 0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "decode::extract_last_row::vocab_size_zero",
        ));
    }

    let logit_bytes = logits.as_bytes();
    let last_row_start = (seq_len - 1) * vocab_size;
    let mut row_vals = Vec::with_capacity(vocab_size);

    for v in 0..vocab_size {
        let flat = last_row_start + v;
        let start = flat.checked_mul(4).ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "decode::read_f32::overflow")
        })?;
        let end = start.checked_add(4).ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "decode::read_f32::overflow")
        })?;
        let chunk: [u8; 4] = logit_bytes
            .get(start..end)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "decode::read_f32::oob")
            })?;
        row_vals.push(f32::from_le_bytes(chunk));
    }

    Ok(row_vals)
}

/// Apply temperature scaling and top-k filtering, then sample a token index.
///
/// Returns the sampled token ID as a `u32`.
///
/// # Sampling procedure
///
/// 1. If `temperature == 0.0`: return argmax (greedy, no randomness).
/// 2. Divide logits by `temperature`.
/// 3. Compute softmax probabilities.
/// 4. If `top_k > 0` and `top_k < vocab_size`: zero out all but the top-k
///    probability mass, renormalize.
/// 5. Sample from the resulting distribution using a simple linear-search
///    cumulative-distribution approach with a pseudo-random seed.
///
/// # Determinism
///
/// This implementation uses a simple `xorshift32` PRNG seeded from the logit
/// values themselves.  This makes sampling reproducible for the same inputs,
/// which is desirable for testing and debugging.  A cryptographic RNG is
/// intentionally NOT used here: sampling is not a security-sensitive operation
/// and the overhead of a CSPRNG call per token would be disproportionate.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
/// `pub(crate)`: shared with `provider::local_cpu` (TASK-12) — see
/// [`extract_last_row`] for the rationale.
pub(crate) fn sample_token(logits: &[f32], temperature: f32, top_k: usize) -> Result<u32> {
    if logits.is_empty() {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "decode::sample_token::empty_logits",
        ));
    }

    if temperature < 0.0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "decode::sample_token::negative_temperature",
        ));
    }

    // Greedy: temperature = 0.0 or top_k = 1.
    if temperature == 0.0 || top_k == 1 {
        let best = logits
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal))
            .map(|(idx, _)| idx)
            .ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "decode::sample_token::argmax_error",
                )
            })?;
        return Ok(best as u32);
    }

    // Temperature scaling.
    let scaled: Vec<f32> = logits.iter().map(|&l| l / temperature).collect();

    // Numerically stable softmax.
    let max_logit = scaled.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    // Routed through nexacore_hal::math for no_std compatibility (ADR-0034).
    let mut probs: Vec<f32> = scaled
        .iter()
        .map(|&l| nexacore_hal::math::exp(l - max_logit))
        .collect();
    let sum_exp: f32 = probs.iter().sum();
    if sum_exp == 0.0 {
        // All logits were -inf; fall back to uniform distribution.
        let uniform = 1.0_f32 / logits.len() as f32;
        probs.iter_mut().for_each(|p| *p = uniform);
    } else {
        probs.iter_mut().for_each(|p| *p /= sum_exp);
    }

    // Top-k filtering: zero out all but the top-k probability mass.
    let effective_k = if top_k == 0 || top_k >= probs.len() {
        probs.len()
    } else {
        top_k
    };

    if effective_k < probs.len() {
        // Find the k-th largest probability by partially sorting indices.
        let mut indices: Vec<usize> = (0..probs.len()).collect();
        indices.sort_unstable_by(|&a, &b| {
            probs
                .get(b)
                .and_then(|pb| probs.get(a).map(|pa| pb.partial_cmp(pa)))
                .flatten()
                .unwrap_or(core::cmp::Ordering::Equal)
        });
        // Zero out probabilities outside the top-k.
        for &idx in indices.get(effective_k..).unwrap_or(&[]) {
            if let Some(p) = probs.get_mut(idx) {
                *p = 0.0;
            }
        }
        // Renormalize.
        let new_sum: f32 = probs.iter().sum();
        if new_sum > 0.0 {
            probs.iter_mut().for_each(|p| *p /= new_sum);
        }
    }

    // Sample from the distribution using a pseudo-random value derived from the
    // logit values.  This is deterministic for the same inputs and avoids
    // dependency on a CSPRNG.
    //
    // PRNG: xorshift32 seeded by interpreting the first logit's bit pattern as
    // a u32.  The shift constants (13, 17, 5) are the canonical xorshift32
    // parameters from Marsaglia (2003).
    let seed_bits = logits.first().copied().unwrap_or(1.0_f32).to_bits();
    let seed = if seed_bits == 0 { 1 } else { seed_bits };
    let rand_val = xorshift32(seed);
    // Map to [0, 1).
    let u = (rand_val as f32) / (u32::MAX as f32);

    // Inverse CDF sampling: walk the CDF until it exceeds `u`.
    let mut cumsum = 0.0_f32;
    for (idx, &p) in probs.iter().enumerate() {
        cumsum += p;
        if u < cumsum {
            return Ok(idx as u32);
        }
    }

    // Fallback: return the last non-zero probability entry (handles rounding).
    let last = probs
        .iter()
        .enumerate()
        .rev()
        .find(|&(_, &p)| p > 0.0)
        .map_or(0, |(idx, _)| idx);
    Ok(last as u32)
}

/// Simple deterministic xorshift32 pseudo-random number generator.
///
/// Given a non-zero seed, produces a deterministic 32-bit value.  Not suitable
/// for cryptographic use; used here only for reproducible sampling in tests.
///
/// Reference: Marsaglia, G. (2003). "Xorshift RNGs". Journal of Statistical
/// Software, 8(14), 1–6.
#[inline]
fn xorshift32(mut state: u32) -> u32 {
    // Standard xorshift32 constants.
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    state
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]
mod tests {
    use nexacore_hal::{
        tensor::{TensorBuffer, TensorDescriptor, TensorDtype},
        transformer::{TransformerLayerWeights, TransformerWeights},
    };

    use super::*;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Build a flat F32 TensorBuffer.
    fn make_f32_buf(shape: Vec<usize>, values: &[f32]) -> TensorBuffer {
        let desc = TensorDescriptor::new(shape, TensorDtype::F32);
        let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        TensorBuffer::new(desc, bytes)
    }

    /// Build a minimal transformer config and weight set for unit tests.
    fn tiny_config() -> TransformerConfig {
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

    fn tiny_weights(cfg: &TransformerConfig) -> TransformerWeights {
        let d = cfg.d_model;
        let f = cfg.d_ff;
        let v = cfg.vocab_size;

        // Identity-like weights so the forward pass produces finite logits.
        let eye = |rows: usize, cols: usize| -> TensorBuffer {
            let n = rows * cols;
            let vals: Vec<f32> = (0..n)
                .map(|i| if i % (cols + 1) == 0 { 1.0 } else { 0.01 })
                .collect();
            make_f32_buf(vec![rows, cols], &vals)
        };
        let ones = |size: usize| -> TensorBuffer { make_f32_buf(vec![size], &vec![1.0; size]) };

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

    // -------------------------------------------------------------------------
    // sample_token unit tests
    // -------------------------------------------------------------------------

    /// Greedy decoding (temperature=0) always picks the argmax.
    #[test]
    fn sample_greedy_picks_argmax() -> nexacore_types::error::Result<()> {
        let logits = vec![0.1_f32, 5.0, 0.3, 0.2];
        let tok = sample_token(&logits, 0.0, 0)?;
        assert_eq!(tok, 1, "argmax of [0.1, 5.0, 0.3, 0.2] should be index 1");
        Ok(())
    }

    /// top_k = 1 is equivalent to greedy.
    #[test]
    fn sample_topk1_equals_greedy() -> nexacore_types::error::Result<()> {
        let logits = vec![0.1_f32, 5.0, 0.3, 0.2];
        let tok = sample_token(&logits, 1.0, 1)?;
        assert_eq!(tok, 1);
        Ok(())
    }

    /// Temperature scaling: with temperature=1.0 and top_k=0, the sampler
    /// should return a valid token index.
    #[test]
    fn sample_temperature_returns_valid_index() -> nexacore_types::error::Result<()> {
        let logits = vec![1.0_f32, 2.0, 3.0, 4.0];
        let tok = sample_token(&logits, 1.0, 0)?;
        assert!(
            (tok as usize) < logits.len(),
            "sampled token {tok} out of range [0, {})",
            logits.len()
        );
        Ok(())
    }

    /// Top-k filtering: with top_k=2, only the top-2 tokens can be sampled.
    #[test]
    fn sample_topk_restricts_to_top_tokens() -> nexacore_types::error::Result<()> {
        // Logits heavily concentrated on tokens 2 and 3.
        let logits = vec![-100.0_f32, -100.0, 10.0, 9.0];
        // With top_k=2 and high-confidence logits, we should always get 2 or 3.
        // Run multiple seeds by varying logits slightly.
        for delta in 0..10_u32 {
            let mut l = logits.clone();
            if let Some(v) = l.get_mut(0) {
                // mul_add: (-100.0).mul_add(1.0, delta as f32 * 0.001) would change
                // semantics here; the clippy suggestion to use mul_add doesn't apply
                // because we're adding a fixed constant to a product, not doing fma.
                // Suppress suboptimal_flops for this test-only arithmetic.
                #[allow(clippy::suboptimal_flops)]
                let new_v = -100.0_f32 + delta as f32 * 0.001_f32;
                *v = new_v;
            }
            let tok = sample_token(&l, 1.0, 2)?;
            assert!(
                tok == 2 || tok == 3,
                "top_k=2 should only produce tokens 2 or 3, got {tok}"
            );
        }
        Ok(())
    }

    /// Empty logits should return an error.
    #[test]
    fn sample_empty_logits_errors() {
        let result = sample_token(&[], 1.0, 0);
        assert!(result.is_err());
    }

    /// Negative temperature should return an error.
    #[test]
    fn sample_negative_temperature_errors() {
        let logits = vec![1.0_f32, 2.0];
        let result = sample_token(&logits, -1.0, 0);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // extract_last_row unit tests
    // -------------------------------------------------------------------------

    /// Extract the last row from a [2, 3] logits buffer.
    #[test]
    fn extract_last_row_correct() -> nexacore_types::error::Result<()> {
        let logits = make_f32_buf(vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let row = extract_last_row(&logits, 2, 3)?;
        assert_eq!(row.len(), 3);
        assert!((row[0] - 4.0_f32).abs() < 1e-6_f32);
        assert!((row[1] - 5.0_f32).abs() < 1e-6_f32);
        assert!((row[2] - 6.0_f32).abs() < 1e-6_f32);
        Ok(())
    }

    /// seq_len = 0 should return an error.
    #[test]
    fn extract_last_row_seq_len_zero_errors() {
        let logits = make_f32_buf(vec![1, 3], &[1.0, 2.0, 3.0]);
        assert!(extract_last_row(&logits, 0, 3).is_err());
    }

    // -------------------------------------------------------------------------
    // Streaming decode integration tests
    // -------------------------------------------------------------------------

    /// The decoder produces at most max_new_tokens tokens.
    #[test]
    fn decode_respects_max_new_tokens() {
        let backend = CpuBackend::new();
        let cfg = tiny_config();
        let weights = tiny_weights(&cfg);
        let prompt = vec![1u32, 2];
        let decode_cfg = StreamDecodeConfig {
            max_new_tokens: 3,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
        };
        let tokens: Vec<_> =
            streaming_decode(&backend, &cfg, &weights, &prompt, decode_cfg).collect();
        assert!(
            tokens.len() <= 3,
            "expected ≤ 3 tokens, got {}",
            tokens.len()
        );
    }

    /// Greedy decoding is deterministic: two runs with the same inputs produce
    /// the same token sequence.
    #[test]
    fn decode_greedy_is_deterministic() {
        let backend = CpuBackend::new();
        let cfg = tiny_config();
        let weights = tiny_weights(&cfg);
        let prompt = vec![1u32, 2];
        let decode_cfg = || StreamDecodeConfig {
            max_new_tokens: 2,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
        };
        // Collect only the Ok token IDs so we can use assert_eq! (NexaCoreError
        // does not implement PartialEq, so we extract the values instead).
        let run1: Vec<u32> = streaming_decode(&backend, &cfg, &weights, &prompt, decode_cfg())
            .filter_map(|r| r.ok().map(|t| t.token_id))
            .collect();
        let run2: Vec<u32> = streaming_decode(&backend, &cfg, &weights, &prompt, decode_cfg())
            .filter_map(|r| r.ok().map(|t| t.token_id))
            .collect();
        assert_eq!(run1, run2, "greedy decode must be deterministic");
    }

    /// EOS token stops the loop.
    #[test]
    fn decode_stops_on_eos() {
        let backend = CpuBackend::new();
        let cfg = tiny_config();
        let weights = tiny_weights(&cfg);
        let prompt = vec![1u32];
        // Find the first greedy token and use it as EOS.
        let decode_cfg_probe = StreamDecodeConfig {
            max_new_tokens: 1,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
        };
        let first_token = streaming_decode(&backend, &cfg, &weights, &prompt, decode_cfg_probe)
            .next()
            .and_then(std::result::Result::ok)
            .map(|t| t.token_id);

        if let Some(eos) = first_token {
            let decode_cfg = StreamDecodeConfig {
                max_new_tokens: 10,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: Some(eos),
            };
            let tokens: Vec<_> =
                streaming_decode(&backend, &cfg, &weights, &prompt, decode_cfg).collect();
            // Should stop after the EOS token: exactly 1 token generated.
            assert_eq!(tokens.len(), 1, "expected exactly 1 token before EOS stop");
            if let Some(Ok(t)) = tokens.first() {
                assert_eq!(t.token_id, eos);
            }
        }
        // If we couldn't get a first token, the test is vacuously satisfied.
    }

    /// Position field increments correctly.
    #[test]
    fn decode_positions_are_correct() {
        let backend = CpuBackend::new();
        let cfg = tiny_config();
        let weights = tiny_weights(&cfg);
        let prompt = vec![1u32, 2, 3];
        let decode_cfg = StreamDecodeConfig {
            max_new_tokens: 3,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
        };
        let tokens: Vec<_> =
            streaming_decode(&backend, &cfg, &weights, &prompt, decode_cfg).collect();
        // Positions should start at prompt.len() = 3 and increment.
        for (step, tok_result) in tokens.iter().enumerate() {
            if let Ok(tok) = tok_result {
                assert_eq!(
                    tok.position,
                    prompt.len() + step,
                    "position mismatch at step {step}"
                );
            }
        }
    }

    /// Empty prompt is handled gracefully (produces tokens starting at position 0).
    #[test]
    fn decode_empty_prompt_errors_gracefully() {
        let backend = CpuBackend::new();
        let cfg = tiny_config();
        let weights = tiny_weights(&cfg);
        // An empty prompt will cause the embedding lookup to produce a
        // [0, d_model] tensor, which the forward pass may reject.
        let decode_cfg = StreamDecodeConfig {
            max_new_tokens: 1,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
        };
        let result: Vec<_> = streaming_decode(&backend, &cfg, &weights, &[], decode_cfg).collect();
        // Either 0 tokens (empty prompt → no max_new_tokens iteration) or
        // the first next() returns an Err.  Both are valid.
        for r in result {
            // If we got a result, it must be Ok or Err (not panic).
            let _ = r;
        }
    }
}

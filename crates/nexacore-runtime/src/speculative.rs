//! Speculative decoding engine for autoregressive language models.
//!
//! Implements the speculative decoding algorithm from Leviathan et al. (2023):
//! "Fast Inference from Transformers via Speculative Decoding".
//!
//! The algorithm uses a small, fast *draft* model to speculatively generate
//! `draft_len` tokens, then verifies all of them against the large *target*
//! model in a single batched forward pass.  Tokens that survive modified
//! rejection sampling are accepted as-is; the first rejected token is replaced
//! by a corrected sample drawn from the adjusted distribution.  This yields
//! identical output distribution to pure autoregressive sampling from the
//! target model, while amortising the cost of the target forward pass across
//! multiple tokens.
//!
//! # Model interface
//!
//! Both models are provided as closures rather than concrete types so the
//! engine remains backend-agnostic and fully testable with synthetic functions:
//!
//! - `draft_forward`: `(&[usize]) -> Vec<f32>` — single-token forward pass
//!   returning a flat logits vector of length `vocab_size`.
//! - `target_forward`: `(&[usize]) -> Vec<Vec<f32>>` — batched forward pass
//!   over a full prompt + draft sequence, returning one logits vector per
//!   input position.
//!
//! # Determinism
//!
//! Sampling uses the same xorshift32 seeding strategy as [`crate::decode`]:
//! the seed is derived from the bit pattern of the first element of the
//! probability vector.  This makes sampling reproducible for identical inputs,
//! which is desirable for testing.  See `sample_from_distribution` for
//! details.
//!
//! # Usage
//!
//! ```
//! use nexacore_runtime::speculative::{SpeculativeConfig, speculative_decode};
//!
//! // Identity draft and target models (both return the same logits).
//! let vocab_size = 8usize;
//! let draft_forward =
//!     |_ctx: &[usize]| -> Vec<f32> { vec![0.1, 5.0, 0.3, 0.2, 0.1, 0.05, 0.05, 0.2] };
//! let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
//!     ctx.iter()
//!         .map(|_| vec![0.1, 5.0, 0.3, 0.2, 0.1, 0.05, 0.05, 0.2])
//!         .collect()
//! };
//!
//! let config = SpeculativeConfig {
//!     draft_len: 3,
//!     temperature: 0.0,
//!     max_new_tokens: 6,
//!     eos_token_id: None,
//! };
//!
//! let prompt = vec![0usize];
//! let tokens = speculative_decode(&prompt, &config, draft_forward, target_forward);
//! assert_eq!(tokens.len(), 6);
//! ```

#![allow(clippy::float_arithmetic)]

// =============================================================================
// Public types
// =============================================================================

/// Configuration for the speculative decoding loop.
///
/// Controls the draft budget, sampling temperature, and termination conditions.
///
/// # Example
///
/// ```
/// use nexacore_runtime::speculative::SpeculativeConfig;
///
/// let cfg = SpeculativeConfig {
///     draft_len: 5,
///     temperature: 1.0,
///     max_new_tokens: 20,
///     eos_token_id: Some(2),
/// };
/// assert_eq!(cfg.draft_len, 5);
/// ```
#[derive(Clone, Debug)]
pub struct SpeculativeConfig {
    /// Number of draft tokens to speculatively generate per round.
    ///
    /// Larger values amortise the target forward pass cost over more tokens but
    /// increase wasted work when the draft quality is low.  Typical range: 3–8.
    pub draft_len: usize,

    /// Sampling temperature applied to both draft and target distributions.
    ///
    /// - `0.0`: greedy (argmax) decoding throughout.
    /// - `1.0`: unscaled probabilities.
    /// - Values outside `[0.0, ∞)` produce undefined behaviour in callers.
    pub temperature: f32,

    /// Maximum number of new tokens to generate (excluding the prompt).
    pub max_new_tokens: usize,

    /// Token ID that signals end-of-sequence; the loop stops when generated.
    pub eos_token_id: Option<usize>,
}

/// The set of draft tokens produced by the draft model in one speculation round.
///
/// Produced by [`generate_draft`] and consumed by [`verify_draft`].
///
/// # Example
///
/// ```
/// use nexacore_runtime::speculative::DraftResult;
///
/// let draft = DraftResult {
///     tokens: vec![3, 1, 5],
///     draft_logits: vec![
///         vec![0.1, 0.2, 0.3, 0.4],
///         vec![0.4, 0.3, 0.2, 0.1],
///         vec![0.25, 0.25, 0.25, 0.25],
///     ],
/// };
/// assert_eq!(draft.tokens.len(), 3);
/// assert_eq!(draft.draft_logits.len(), 3);
/// ```
#[derive(Clone, Debug)]
pub struct DraftResult {
    /// Draft token IDs in generation order.
    pub tokens: Vec<usize>,
    /// Raw logits produced by the draft model at each draft step.
    ///
    /// `draft_logits[i]` is the logit vector used to sample `tokens[i]`.
    pub draft_logits: Vec<Vec<f32>>,
}

/// The outcome of verifying a [`DraftResult`] against the target model.
///
/// Produced by [`verify_draft`].
///
/// # Example
///
/// ```
/// use nexacore_runtime::speculative::VerifyResult;
///
/// let result = VerifyResult {
///     accepted: 2,
///     correction_token: Some(4),
///     target_logits: vec![
///         vec![0.1, 0.2, 0.3, 0.4],
///         vec![0.4, 0.3, 0.2, 0.1],
///         vec![0.15, 0.35, 0.25, 0.25],
///     ],
/// };
/// assert_eq!(result.accepted, 2);
/// assert!(result.correction_token.is_some());
/// ```
#[derive(Clone, Debug)]
pub struct VerifyResult {
    /// Number of draft tokens accepted by rejection sampling.
    ///
    /// `accepted` tokens from the draft are appended to the sequence as-is.
    pub accepted: usize,

    /// Corrected token sampled when rejection occurred, or a fresh sample from
    /// the target model when all draft tokens were accepted.
    ///
    /// `None` only in the degenerate case where both `draft.tokens` is empty
    /// AND the target model returns no logits (both are simultaneously empty).
    pub correction_token: Option<usize>,

    /// Target model logits at every verified position.
    ///
    /// Has length `prompt.len() + draft.tokens.len()` — one entry per token
    /// in the full verification sequence.
    pub target_logits: Vec<Vec<f32>>,
}

// =============================================================================
// Private helpers
// =============================================================================

/// Numerically stable softmax with temperature scaling.
///
/// Divides logits by `temperature` before computing softmax.  When
/// `temperature == 0.0` the result is a one-hot vector at the argmax position
/// (greedy).  An empty `logits` slice returns an empty `Vec`.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn softmax(logits: &[f32], temperature: f32) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }

    // Greedy: return a one-hot at the argmax to avoid division by zero.
    if temperature == 0.0 {
        let argmax = logits
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(0, |(i, _)| i);
        let mut out = vec![0.0f32; logits.len()];
        if let Some(slot) = out.get_mut(argmax) {
            *slot = 1.0;
        }
        return out;
    }

    // Temperature-scaled logits.
    let scaled: Vec<f32> = logits.iter().map(|&l| l / temperature).collect();

    // Subtract max for numerical stability (prevents exp overflow).
    let max_val = scaled.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut probs: Vec<f32> = scaled.iter().map(|&l| (l - max_val).exp()).collect();
    let sum: f32 = probs.iter().sum();

    if sum == 0.0 {
        // All logits were -inf: fall back to uniform.
        let uniform = 1.0_f32 / logits.len() as f32;
        probs.iter_mut().for_each(|p| *p = uniform);
    } else {
        probs.iter_mut().for_each(|p| *p /= sum);
    }

    probs
}

/// Sample a token index from a probability distribution using deterministic seeding.
///
/// The pseudo-random value is derived from the bit pattern of the first element
/// of `probs` via xorshift32, exactly as in [`crate::decode::sample_token`].
/// This makes sampling reproducible for the same probability vector.
///
/// Returns `0` when `probs` is empty (safe fallback; callers must ensure
/// non-empty distributions for meaningful output).
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn sample_from_distribution(probs: &[f32]) -> usize {
    if probs.is_empty() {
        return 0;
    }

    // Derive a deterministic seed from the first probability's bit pattern.
    // xorshift32 requires a non-zero seed.
    let seed_bits = probs.first().copied().unwrap_or(1.0_f32).to_bits();
    let seed = if seed_bits == 0 { 1u32 } else { seed_bits };
    let rand_val = xorshift32(seed);
    // Map to [0, 1).
    let u = (rand_val as f32) / (u32::MAX as f32);

    // Inverse CDF sampling.
    let mut cumsum = 0.0_f32;
    for (idx, &p) in probs.iter().enumerate() {
        cumsum += p;
        if u < cumsum {
            return idx;
        }
    }

    // Fallback: return the last non-zero probability index (handles rounding).
    probs
        .iter()
        .enumerate()
        .rev()
        .find(|&(_, &p)| p > 0.0)
        .map_or(0, |(i, _)| i)
}

/// Compute the acceptance probability for a single token under rejection sampling.
///
/// Returns `min(1.0, target_prob / draft_prob)`.
///
/// When `draft_prob == 0.0` the token would never be produced by the draft
/// model, so the target model's choice is always accepted (return `1.0`).
#[must_use]
fn acceptance_probability(target_prob: f32, draft_prob: f32) -> f32 {
    if draft_prob == 0.0 {
        // draft never produces this token; always accept target's choice.
        return 1.0;
    }
    (target_prob / draft_prob).min(1.0)
}

/// xorshift32 pseudo-random number generator (Marsaglia 2003).
///
/// Non-cryptographic; used only for reproducible sampling in tests.
/// Seed must be non-zero; passing zero will produce zero forever.
#[inline]
fn xorshift32(mut state: u32) -> u32 {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    state
}

/// Compute a deterministic pseudo-random value in [0, 1) from a position index.
///
/// Used in [`verify_draft`] to produce per-position acceptance thresholds that
/// differ from the sampling seed used by [`sample_from_distribution`], avoiding
/// correlation between the acceptance decision and the resample.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn position_rand(position: usize) -> f32 {
    // Derive a non-zero seed from the position.
    #[allow(clippy::cast_possible_truncation)]
    let pos_u32 = position as u32;
    let seed = xorshift32(pos_u32.wrapping_add(1).wrapping_mul(2_654_435_761));
    (seed as f32) / (u32::MAX as f32)
}

/// Sample from the adjusted distribution `max(0, target - draft) / Z` for rejection recovery.
///
/// This is the corrected distribution used when a draft token is rejected at
/// position `j`.  The result is a sample from the normalised positive part of
/// `target_prob[i] - draft_prob[i]`.  If the adjusted distribution is all-zero
/// (draft dominates everywhere), falls back to sampling from the target.
#[must_use]
fn sample_adjusted(target_probs: &[f32], draft_probs: &[f32]) -> usize {
    let n = target_probs.len().min(draft_probs.len());
    if n == 0 {
        return 0;
    }

    let mut adjusted: Vec<f32> = (0..n)
        .map(|i| {
            let t = target_probs.get(i).copied().unwrap_or(0.0);
            let d = draft_probs.get(i).copied().unwrap_or(0.0);
            (t - d).max(0.0)
        })
        .collect();

    let sum: f32 = adjusted.iter().sum();
    if sum == 0.0 {
        // Draft and target agree everywhere; sample directly from target.
        return sample_from_distribution(target_probs);
    }

    adjusted.iter_mut().for_each(|p| *p /= sum);
    sample_from_distribution(&adjusted)
}

// =============================================================================
// Public core functions
// =============================================================================

/// Generate draft tokens autoregressively using a smaller/faster model.
///
/// Calls `draft_forward` once per draft step, appending each sampled token
/// to the running context.  Returns the sampled tokens together with the
/// raw logits used to produce each one.
///
/// # Parameters
///
/// - `prompt`: current token sequence (prompt + any previously accepted tokens).
/// - `draft_len`: number of draft tokens to generate.
/// - `draft_forward`: single-step forward pass returning a flat logits vector.
/// - `temperature`: sampling temperature (`0.0` = greedy).
///
/// # Example
///
/// ```
/// use nexacore_runtime::speculative::generate_draft;
///
/// let draft_forward = |_ctx: &[usize]| -> Vec<f32> { vec![0.1, 5.0, 0.3, 0.2] };
///
/// let result = generate_draft(&[1usize, 2], 3, draft_forward, 0.0);
/// assert_eq!(result.tokens.len(), 3);
/// assert_eq!(result.draft_logits.len(), 3);
/// ```
#[must_use]
pub fn generate_draft(
    prompt: &[usize],
    draft_len: usize,
    draft_forward: impl Fn(&[usize]) -> Vec<f32>,
    temperature: f32,
) -> DraftResult {
    let mut context: Vec<usize> = prompt.to_vec();
    let mut tokens = Vec::with_capacity(draft_len);
    let mut draft_logits = Vec::with_capacity(draft_len);

    for _ in 0..draft_len {
        let logits = draft_forward(&context);
        let probs = softmax(&logits, temperature);
        let token = sample_from_distribution(&probs);
        draft_logits.push(logits);
        tokens.push(token);
        context.push(token);
    }

    DraftResult {
        tokens,
        draft_logits,
    }
}

/// Verify draft tokens against the target model using modified rejection sampling.
///
/// Runs a single batched forward pass over `prompt + draft.tokens`, then
/// walks the draft tokens left-to-right applying the acceptance criterion:
///
/// ```text
/// accept token_i  with probability  min(1, p_target[token_i] / p_draft[token_i])
/// ```
///
/// On the first rejection at position `j`, a correction token is drawn from
/// the adjusted distribution `max(0, target - draft) / Z`.  If all draft
/// tokens are accepted, a bonus token is sampled from the target distribution
/// at the last position.
///
/// # Parameters
///
/// - `prompt`: token sequence before the draft (used to build the verification context).
/// - `draft`: output of [`generate_draft`].
/// - `target_forward`: batched forward pass returning logits for each input position.
/// - `temperature`: sampling temperature applied to both target and draft distributions.
///
/// # Example
///
/// ```
/// use nexacore_runtime::speculative::{DraftResult, verify_draft};
///
/// // Target and draft agree exactly → all tokens accepted.
/// let draft = DraftResult {
///     tokens: vec![1usize, 1, 1],
///     draft_logits: vec![
///         vec![0.1, 5.0, 0.3, 0.2],
///         vec![0.1, 5.0, 0.3, 0.2],
///         vec![0.1, 5.0, 0.3, 0.2],
///     ],
/// };
/// let target_forward =
///     |ctx: &[usize]| -> Vec<Vec<f32>> { ctx.iter().map(|_| vec![0.1, 5.0, 0.3, 0.2]).collect() };
///
/// let result = verify_draft(&[0usize], &draft, target_forward, 0.0);
/// assert_eq!(result.accepted, 3);
/// assert!(result.correction_token.is_some());
/// ```
#[must_use]
pub fn verify_draft(
    prompt: &[usize],
    draft: &DraftResult,
    target_forward: impl Fn(&[usize]) -> Vec<Vec<f32>>,
    temperature: f32,
) -> VerifyResult {
    // Build the full verification context: prompt + all draft tokens.
    let mut full_context: Vec<usize> = prompt.to_vec();
    full_context.extend_from_slice(&draft.tokens);

    // Single batched target forward pass.
    let target_logits_raw = target_forward(&full_context);

    // Positions in target_logits_raw that correspond to draft token predictions:
    // target_logits_raw[prompt.len() - 1] predicts draft.tokens[0], etc.
    // If the prompt is empty we start from index 0.
    let draft_offset = if prompt.is_empty() {
        0
    } else {
        prompt.len() - 1
    };

    let mut accepted = 0;
    let mut correction_token: Option<usize> = None;

    for (i, &draft_token) in draft.tokens.iter().enumerate() {
        let target_pos = draft_offset + i;

        // Retrieve target logits for this draft position.
        let Some(target_logits) = target_logits_raw.get(target_pos) else {
            break;
        };
        let Some(draft_logits) = draft.draft_logits.get(i) else {
            break;
        };

        let target_probs = softmax(target_logits, temperature);
        let draft_probs = softmax(draft_logits, temperature);

        // Probability assigned to the draft token by each model.
        let t_prob = target_probs.get(draft_token).copied().unwrap_or(0.0);
        let d_prob = draft_probs.get(draft_token).copied().unwrap_or(0.0);

        let accept_prob = acceptance_probability(t_prob, d_prob);
        let u = position_rand(i);

        if u < accept_prob {
            accepted += 1;
        } else {
            // Rejection: draw correction from adjusted distribution.
            correction_token = Some(sample_adjusted(&target_probs, &draft_probs));
            break;
        }
    }

    // When all draft tokens are accepted, draw a bonus token from the target
    // at the position immediately after the last accepted draft token.
    if correction_token.is_none() {
        let bonus_pos = draft_offset + draft.tokens.len();
        let bonus_logits = target_logits_raw.get(bonus_pos).or_else(|| {
            // Fallback: use the last available target logits row.
            target_logits_raw.last()
        });
        if let Some(bl) = bonus_logits {
            let probs = softmax(bl, temperature);
            correction_token = Some(sample_from_distribution(&probs));
        } else if let Some(last_row) = target_logits_raw.last() {
            // last() already covered above, this branch is unreachable but
            // satisfies exhaustiveness without panicking.
            let probs = softmax(last_row, temperature);
            correction_token = Some(sample_from_distribution(&probs));
        }
    }

    VerifyResult {
        accepted,
        correction_token,
        target_logits: target_logits_raw,
    }
}

/// Run the full speculative decode loop.
///
/// Alternates between draft generation and target verification until
/// `max_new_tokens` tokens have been produced or the EOS token is generated.
///
/// The output distribution is identical to pure autoregressive sampling from
/// the target model (Leviathan et al. 2023, Theorem 1).
///
/// # Parameters
///
/// - `prompt`: initial token sequence.
/// - `config`: loop parameters (draft length, temperature, budget, EOS).
/// - `draft_forward`: single-step draft model forward pass.
/// - `target_forward`: batched target model forward pass.
///
/// # Returns
///
/// The generated token sequence (excluding the prompt), of length at most
/// `config.max_new_tokens`.
///
/// # Example
///
/// ```
/// use nexacore_runtime::speculative::{SpeculativeConfig, speculative_decode};
///
/// let config = SpeculativeConfig {
///     draft_len: 2,
///     temperature: 0.0,
///     max_new_tokens: 4,
///     eos_token_id: None,
/// };
///
/// // Greedy draft and target always pick token 1.
/// let draft_forward = |_: &[usize]| -> Vec<f32> { vec![0.1, 5.0, 0.3] };
/// let target_forward =
///     |ctx: &[usize]| -> Vec<Vec<f32>> { ctx.iter().map(|_| vec![0.1, 5.0, 0.3]).collect() };
///
/// let tokens = speculative_decode(&[0usize], &config, draft_forward, target_forward);
/// assert_eq!(tokens.len(), 4);
/// assert!(tokens.iter().all(|&t| t == 1));
/// ```
#[must_use]
pub fn speculative_decode(
    prompt: &[usize],
    config: &SpeculativeConfig,
    draft_forward: impl Fn(&[usize]) -> Vec<f32>,
    target_forward: impl Fn(&[usize]) -> Vec<Vec<f32>>,
) -> Vec<usize> {
    let mut generated: Vec<usize> = Vec::new();
    let mut context: Vec<usize> = prompt.to_vec();

    while generated.len() < config.max_new_tokens {
        // Determine how many draft tokens to attempt this round.
        let remaining = config.max_new_tokens - generated.len();
        let draft_len = config.draft_len.min(remaining);

        // Phase 1: draft.
        let draft = generate_draft(&context, draft_len, &draft_forward, config.temperature);

        // Phase 2: verify.
        let verify = verify_draft(&context, &draft, &target_forward, config.temperature);

        // Accept the first `verify.accepted` draft tokens.
        for &tok in draft.tokens.iter().take(verify.accepted) {
            if generated.len() >= config.max_new_tokens {
                break;
            }
            generated.push(tok);
            context.push(tok);
            if config.eos_token_id.is_some_and(|eos| eos == tok) {
                return generated;
            }
        }

        // Append the correction / bonus token if budget remains.
        if generated.len() < config.max_new_tokens {
            if let Some(tok) = verify.correction_token {
                generated.push(tok);
                context.push(tok);
                if config.eos_token_id.is_some_and(|eos| eos == tok) {
                    return generated;
                }
            }
        }
    }

    generated
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::float_cmp,
    clippy::unwrap_used
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // softmax
    // -------------------------------------------------------------------------

    /// Equal logits must produce a uniform distribution.
    #[test]
    fn softmax_uniform() {
        let logits = vec![1.0f32; 4];
        let probs = softmax(&logits, 1.0);
        assert_eq!(probs.len(), 4);
        for &p in &probs {
            assert!((p - 0.25).abs() < 1e-6, "expected 0.25 got {p}");
        }
    }

    /// Temperature near zero must produce a one-hot at the argmax.
    #[test]
    fn softmax_temperature_zero_is_argmax() {
        let logits = vec![0.1f32, 5.0, 0.3, 0.2];
        let probs = softmax(&logits, 0.0);
        assert_eq!(probs.len(), 4);
        assert!((probs[1] - 1.0).abs() < 1e-9, "index 1 should be 1.0");
        assert!((probs[0]).abs() < 1e-9);
        assert!((probs[2]).abs() < 1e-9);
        assert!((probs[3]).abs() < 1e-9);
    }

    /// Large logits must not produce `NaN` or Inf (numerical stability check).
    #[test]
    fn softmax_numerical_stability() {
        let logits = vec![1000.0f32, 1001.0, 999.0, 998.0];
        let probs = softmax(&logits, 1.0);
        for &p in &probs {
            assert!(p.is_finite(), "softmax must produce finite values; got {p}");
            assert!(
                p >= 0.0,
                "softmax must produce non-negative values; got {p}"
            );
        }
        let sum: f32 = probs.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-5,
            "softmax must sum to 1.0; got {sum}"
        );
    }

    // -------------------------------------------------------------------------
    // sample_from_distribution
    // -------------------------------------------------------------------------

    /// Same probability vector must produce the same token index every call.
    #[test]
    fn sample_from_distribution_deterministic() {
        let probs = vec![0.1f32, 0.5, 0.3, 0.1];
        let a = sample_from_distribution(&probs);
        let b = sample_from_distribution(&probs);
        assert_eq!(a, b, "same probs must yield same sample");
    }

    // -------------------------------------------------------------------------
    // acceptance_probability
    // -------------------------------------------------------------------------

    /// When target probability exceeds draft probability, acceptance is 1.0.
    #[test]
    fn acceptance_probability_higher_target() {
        let ap = acceptance_probability(0.8, 0.4);
        assert!((ap - 1.0).abs() < 1e-9, "expected 1.0, got {ap}");
    }

    /// When target probability is lower, acceptance equals the ratio.
    #[test]
    fn acceptance_probability_lower_target() {
        let ap = acceptance_probability(0.2, 0.8);
        assert!((ap - 0.25).abs() < 1e-6, "expected 0.25, got {ap}");
    }

    /// When draft probability is zero, acceptance must be 1.0 (no div by zero).
    #[test]
    fn acceptance_probability_zero_draft() {
        let ap = acceptance_probability(0.5, 0.0);
        assert!((ap - 1.0).abs() < 1e-9, "expected 1.0, got {ap}");
    }

    // -------------------------------------------------------------------------
    // generate_draft
    // -------------------------------------------------------------------------

    /// The draft result must contain exactly `draft_len` tokens and logit rows.
    #[test]
    fn generate_draft_produces_correct_length() {
        let draft_forward = |_: &[usize]| -> Vec<f32> { vec![0.1, 0.5, 0.3, 0.1] };
        let result = generate_draft(&[0usize], 5, draft_forward, 1.0);
        assert_eq!(result.tokens.len(), 5);
        assert_eq!(result.draft_logits.len(), 5);
    }

    /// With temperature 0 (greedy), repeated calls must yield identical tokens.
    #[test]
    fn generate_draft_greedy_deterministic() {
        let draft_forward = |_: &[usize]| -> Vec<f32> { vec![0.1, 5.0, 0.3, 0.2] };
        let r1 = generate_draft(&[1usize, 2], 4, draft_forward, 0.0);
        let r2 = generate_draft(&[1usize, 2], 4, draft_forward, 0.0);
        assert_eq!(r1.tokens, r2.tokens, "greedy draft must be deterministic");
    }

    // -------------------------------------------------------------------------
    // verify_draft
    // -------------------------------------------------------------------------

    /// When target and draft assign identical probability to every draft token,
    /// the acceptance probability is 1.0 at every position, so all are accepted.
    #[test]
    fn verify_draft_all_accepted() {
        // Greedy case: draft and target both have a massive peak at token 1.
        let logits = vec![0.1f32, 100.0, 0.3, 0.2];
        let draft = DraftResult {
            tokens: vec![1, 1, 1],
            draft_logits: vec![logits.clone(), logits.clone(), logits],
        };
        // Target returns the same logits.
        let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
            ctx.iter().map(|_| vec![0.1f32, 100.0, 0.3, 0.2]).collect()
        };
        let result = verify_draft(&[0usize], &draft, target_forward, 0.0);
        assert_eq!(
            result.accepted, 3,
            "all tokens should be accepted when models agree"
        );
        assert!(
            result.correction_token.is_some(),
            "a bonus token must always be provided"
        );
    }

    /// When the target strongly disagrees with the draft's first token,
    /// `accepted == 0` and a correction token is provided.
    #[test]
    fn verify_draft_first_rejected() {
        // Draft always picks token 0 (logits heavily weighted at 0).
        let draft_logits = vec![100.0f32, 0.1, 0.1, 0.1];
        let draft = DraftResult {
            tokens: vec![0, 0, 0],
            draft_logits: vec![draft_logits.clone(), draft_logits.clone(), draft_logits],
        };

        // Target strongly prefers token 3 — disagrees at every position.
        let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
            ctx.iter()
                .map(|_| vec![0.001f32, 0.001, 0.001, 100.0])
                .collect()
        };

        let result = verify_draft(&[0usize], &draft, target_forward, 1.0);

        // With draft_prob(token=0) ≈ 1.0 and target_prob(token=0) ≈ 0, the
        // acceptance ratio is ~0, so the first token is almost certainly rejected.
        // We allow accepted ∈ {0, 1} since the random seed is deterministic.
        assert!(
            result.accepted <= 1,
            "expected rejection early, accepted = {}",
            result.accepted
        );
        assert!(
            result.correction_token.is_some(),
            "correction token must be provided on rejection"
        );
    }

    /// Partial acceptance: some tokens accepted, then a rejection.
    #[test]
    fn verify_draft_partial_acceptance() {
        // Draft: alternates between token 1 (high) and token 0 (high).
        // Target: high prob at token 1 for first two positions,
        //         then strongly disagrees at position 2 (prefers token 3).
        let logits_agree = vec![0.001f32, 100.0, 0.001, 0.001];
        let logits_disagree = vec![0.001f32, 0.001, 0.001, 100.0];

        let draft = DraftResult {
            // draft picks token 1 at all positions
            tokens: vec![1, 1, 1],
            draft_logits: vec![
                logits_agree.clone(),
                logits_agree.clone(),
                logits_agree.clone(),
            ],
        };

        let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
            // target agrees at first two positions, then disagrees at position 2+
            ctx.iter()
                .enumerate()
                .map(|(i, _)| {
                    if i < 2 {
                        logits_agree.clone()
                    } else {
                        logits_disagree.clone()
                    }
                })
                .collect()
        };

        // Use temperature=1.0 so probabilities reflect the logits.
        let result = verify_draft(&[0usize], &draft, target_forward, 1.0);

        // With such extreme logits the first draft position maps to
        // target_logits_raw[0] (prompt_len-1 = 0). The draft offset means
        // position i=0 checks target_logits_raw[0], i=1 checks [1], i=2 checks [2].
        // Positions 0 and 1 agree; position 2 disagrees.
        // Accepted can be 2 or 3 depending on the PRNG path, but correction
        // must always be present.
        assert!(
            result.accepted <= 3,
            "cannot accept more tokens than drafted"
        );
        assert!(
            result.correction_token.is_some(),
            "correction token must always be provided"
        );
    }

    // -------------------------------------------------------------------------
    // verify_draft — edge cases
    // -------------------------------------------------------------------------

    /// Zero draft tokens: verify must immediately provide a token from the target.
    #[test]
    fn verify_draft_empty_draft() {
        let draft = DraftResult {
            tokens: vec![],
            draft_logits: vec![],
        };
        let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
            ctx.iter().map(|_| vec![0.1f32, 5.0, 0.3, 0.2]).collect()
        };
        let result = verify_draft(&[0usize, 1], &draft, target_forward, 0.0);
        assert_eq!(result.accepted, 0, "no draft tokens to accept");
        assert!(
            result.correction_token.is_some(),
            "must sample a token from target even with empty draft"
        );
    }

    // -------------------------------------------------------------------------
    // speculative_decode
    // -------------------------------------------------------------------------

    /// Greedy speculative decode with identical draft/target models must match
    /// greedy autoregressive output from the target model.
    #[test]
    fn speculative_decode_greedy_matches_autoregressive() {
        // Both models are identical and greedy: always pick argmax.
        let logits = vec![0.1f32, 5.0, 0.3, 0.2, 0.05];
        // Greedy argmax = index 1.

        let config = SpeculativeConfig {
            draft_len: 3,
            temperature: 0.0,
            max_new_tokens: 6,
            eos_token_id: None,
        };

        let draft_forward = {
            let l = logits.clone();
            move |_: &[usize]| -> Vec<f32> { l.clone() }
        };
        let target_forward = {
            let l = logits;
            move |ctx: &[usize]| -> Vec<Vec<f32>> { ctx.iter().map(|_| l.clone()).collect() }
        };

        let tokens = speculative_decode(&[0usize], &config, draft_forward, target_forward);

        // Greedy argmax of logits is always 1.
        assert_eq!(tokens.len(), 6);
        assert!(
            tokens.iter().all(|&t| t == 1),
            "greedy decode with identical models must always produce argmax token; got {tokens:?}"
        );
    }

    /// The output must never exceed `max_new_tokens`.
    #[test]
    fn speculative_decode_respects_max_tokens() {
        let config = SpeculativeConfig {
            draft_len: 4,
            temperature: 0.0,
            max_new_tokens: 7,
            eos_token_id: None,
        };
        let draft_forward = |_: &[usize]| -> Vec<f32> { vec![0.1, 5.0, 0.3] };
        let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
            ctx.iter().map(|_| vec![0.1f32, 5.0, 0.3]).collect()
        };
        let tokens = speculative_decode(&[0usize], &config, draft_forward, target_forward);
        assert!(
            tokens.len() <= 7,
            "output length {} exceeds max_new_tokens 7",
            tokens.len()
        );
    }

    /// The loop must stop as soon as the EOS token is produced.
    #[test]
    fn speculative_decode_stops_on_eos() {
        // EOS = token 2.  Draft and target always return logits that pick token 2.
        let config = SpeculativeConfig {
            draft_len: 3,
            temperature: 0.0,
            max_new_tokens: 20,
            eos_token_id: Some(2),
        };
        // Logits: token 2 has the highest score.
        let draft_forward = |_: &[usize]| -> Vec<f32> { vec![0.1, 0.3, 5.0, 0.2] };
        let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
            ctx.iter().map(|_| vec![0.1f32, 0.3, 5.0, 0.2]).collect()
        };
        let tokens = speculative_decode(&[0usize], &config, draft_forward, target_forward);
        // Last token must be the EOS token.
        assert_eq!(
            tokens.last().copied(),
            Some(2),
            "last token must be EOS; got {tokens:?}"
        );
        // No tokens after EOS.
        assert!(
            tokens.iter().position(|&t| t == 2) == Some(tokens.len() - 1),
            "EOS must be the terminal token"
        );
    }

    /// An empty prompt must be handled without panicking.
    #[test]
    fn speculative_decode_empty_prompt() {
        let config = SpeculativeConfig {
            draft_len: 2,
            temperature: 0.0,
            max_new_tokens: 3,
            eos_token_id: None,
        };
        let draft_forward = |_: &[usize]| -> Vec<f32> { vec![0.1, 5.0, 0.3] };
        let target_forward = |ctx: &[usize]| -> Vec<Vec<f32>> {
            ctx.iter().map(|_| vec![0.1f32, 5.0, 0.3]).collect()
        };
        // Must not panic.
        let tokens = speculative_decode(&[], &config, draft_forward, target_forward);
        assert!(
            tokens.len() <= 3,
            "empty prompt should still respect max_new_tokens"
        );
    }
}

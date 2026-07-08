//! `engine` — `no_std` facade over the REAL CPU inference chain.
//!
//! This module is the single place where the full Sprint 7/8 pipeline is
//! assembled end-to-end:
//!
//! ```text
//! GGUF bytes ─parse→ header ─load/dequant→ tensors ─map→ TransformerWeights
//! prompt ─BPE encode→ ids ─greedy loop (forward_sync + argmax)→ ids ─decode→ text
//! ```
//!
//! It exists so that BOTH consumers of the engine share one audited body
//! (TASK-13-pre / ADR-0034 — "reuse, not a second engine", ADR-0033):
//!
//! - **std**: [`LocalCpuProvider`](crate::provider::local_cpu::LocalCpuProvider) (TASK-12) delegates its
//!   GGUF→weights mapping and greedy loop here and only adds the
//!   [`InferenceProvider`](crate::provider::InferenceProvider) error/async
//!   surface on top.
//! - **`no_std`**: the Ring 3 `nexacore-runtime-image` builds a [`crate::engine::CpuEngine`]
//!   from an embedded fixture model and serves `AiInvoke` with it on
//!   `x86_64-unknown-none` — the real engine, not a mock (operator decision,
//!   ADR-0034).
//!
//! # Error style
//!
//! Following the `no_std` convention of [`crate::gguf`], errors are
//! [`NexaCoreError::internal`](nexacore_types::NexaCoreError::internal) with `&'static str` context paths
//! (`engine::<fn>::<cause>`).  The std provider wraps them into
//! `ProviderError` strings where richer formatting is available.
//!
//! # Determinism
//!
//! Generation is **greedy** (`temperature = 0`, `top_k = 1` → argmax), so
//! output is fully deterministic for fixed weights — the golden test pins
//! `"ab" → "dddd"` on the Q8_0 fixture through this exact surface.

// Float comparisons/arithmetic are inherent to inference math.
#![allow(clippy::float_arithmetic)]

// Alloc types: re-exported by std's prelude on host builds, pulled from
// `alloc` when building without std (TASK-13-pre / ADR-0034).
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use nexacore_hal::{
    tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype},
    transformer::{
        TransformerConfig, TransformerLayerWeights, TransformerWeights, transformer_forward_sync,
    },
};
use nexacore_types::{NexaCoreError, Result};

use crate::{
    bpe::BpeTokenizer,
    decode::{extract_last_row, sample_token},
    embed::{Pooling, embed_sync},
    tensor_loader::LoadedTensor,
};

/// Default generation budget when the caller passes `max_new_tokens == 0`.
///
/// Shared with [`LocalCpuProvider`](crate::provider::local_cpu::LocalCpuProvider) so the std provider and
/// the Ring 3 image resolve the same default.
pub const DEFAULT_MAX_NEW_TOKENS: u32 = 16;

// =============================================================================
// Weight mapping
// =============================================================================

/// Map dequantised tensors into [`TransformerWeights`] by canonical GGUF
/// names (`token_embd.weight`, `blk.{i}.attn_q.weight`, …), reframing each
/// to its logical shape.
///
/// Block-based quantisation pads buffers to whole blocks; the logical
/// element count derived from `config` is authoritative (same convention as
/// the crate's e2e test and `LocalCpuProvider`).
///
/// `config` is caller-supplied: deriving the architecture from GGUF metadata
/// keys is the TASK-16 (full quantised inference) scope; Phase 2 models are
/// fixtures with known shapes.
///
/// # Errors
///
/// [`NexaCoreError::Internal`] when a required tensor is missing
/// (`engine::build_weights::tensor_missing`) or smaller than the configured
/// shape requires (`engine::build_weights::tensor_too_small`).
pub fn build_weights(
    loaded: &[LoadedTensor],
    config: &TransformerConfig,
) -> Result<TransformerWeights> {
    let find = |name: &str, shape: Vec<usize>| -> Result<TensorBuffer> {
        let lt = loaded
            .iter()
            .find(|t| t.name == name)
            .ok_or_else(|| NexaCoreError::internal("engine::build_weights::tensor_missing"))?;
        let n_logical: usize = shape.iter().product();
        // Dequantised buffers are F32 (4 bytes/element).
        let byte_count = n_logical * 4;
        let src = lt.buffer.as_bytes();
        let truncated = src
            .get(..byte_count)
            .ok_or_else(|| NexaCoreError::internal("engine::build_weights::tensor_too_small"))?;
        Ok(TensorBuffer::new(
            TensorDescriptor::new(shape, TensorDtype::F32),
            truncated.to_vec(),
        ))
    };

    let d = config.d_model;
    let ff = config.d_ff;
    let v = config.vocab_size;

    let mut layers = Vec::with_capacity(config.n_layers);
    for i in 0..config.n_layers {
        layers.push(TransformerLayerWeights {
            attn_q: find(&format!("blk.{i}.attn_q.weight"), vec![d, d])?,
            attn_k: find(&format!("blk.{i}.attn_k.weight"), vec![d, d])?,
            attn_v: find(&format!("blk.{i}.attn_v.weight"), vec![d, d])?,
            attn_o: find(&format!("blk.{i}.attn_output.weight"), vec![d, d])?,
            ffn_gate: find(&format!("blk.{i}.ffn_gate.weight"), vec![d, ff])?,
            ffn_up: find(&format!("blk.{i}.ffn_up.weight"), vec![d, ff])?,
            ffn_down: find(&format!("blk.{i}.ffn_down.weight"), vec![ff, d])?,
            attn_norm: find(&format!("blk.{i}.attn_norm.weight"), vec![d])?,
            ffn_norm: find(&format!("blk.{i}.ffn_norm.weight"), vec![d])?,
        });
    }

    Ok(TransformerWeights {
        token_embedding: find("token_embd.weight", vec![v, d])?,
        layers,
        output_norm: find("output_norm.weight", vec![d])?,
        output_proj: find("output.weight", vec![d, v])?,
        n_kv_heads: None,
    })
}

// =============================================================================
// CpuEngine
// =============================================================================

/// The assembled CPU inference engine: backend + architecture + weights +
/// tokenizer.
///
/// Construct with [`CpuEngine::from_gguf`] (parse → dequantise → map) or
/// [`CpuEngine::new`] when the weights are already built.  Both paths are
/// `no_std`-capable.
///
/// # Example
///
/// ```no_run
/// # use nexacore_hal::transformer::TransformerConfig;
/// # use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
/// # use nexacore_runtime::engine::CpuEngine;
/// # let gguf_bytes: &[u8] = &[];
/// # let config = TransformerConfig {
/// #     n_layers: 1, n_heads: 1, d_model: 4, d_ff: 8,
/// #     vocab_size: 8, max_seq_len: 16, rms_norm_eps: 1e-5,
/// # };
/// let tokenizer = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
/// let engine = CpuEngine::from_gguf(gguf_bytes, config, tokenizer)?;
/// let (text, n_tokens) = engine.generate_text("ab", 4)?;
/// # Ok::<(), nexacore_types::NexaCoreError>(())
/// ```
pub struct CpuEngine {
    backend: CpuBackend,
    config: TransformerConfig,
    weights: TransformerWeights,
    tokenizer: BpeTokenizer,
}

impl CpuEngine {
    /// Assemble an engine from already-built weights.
    #[must_use]
    pub fn new(
        config: TransformerConfig,
        weights: TransformerWeights,
        tokenizer: BpeTokenizer,
    ) -> Self {
        Self {
            backend: CpuBackend::new(),
            config,
            weights,
            tokenizer,
        }
    }

    /// Build an engine directly from GGUF bytes: parse → load + dequantise →
    /// map tensors by canonical names into [`TransformerWeights`].
    ///
    /// # Errors
    ///
    /// Propagates [`crate::gguf::parse_gguf`],
    /// [`crate::tensor_loader::load_all_tensors`], and [`build_weights`]
    /// errors unchanged.
    pub fn from_gguf(
        gguf_bytes: &[u8],
        config: TransformerConfig,
        tokenizer: BpeTokenizer,
    ) -> Result<Self> {
        let header = crate::gguf::parse_gguf(gguf_bytes)?;
        let loaded = crate::tensor_loader::load_all_tensors(gguf_bytes, &header)?;
        let weights = build_weights(&loaded, &config)?;
        Ok(Self::new(config, weights, tokenizer))
    }

    /// The model architecture this engine was assembled with.
    #[must_use]
    pub const fn config(&self) -> &TransformerConfig {
        &self.config
    }

    /// The engine's weight tensors (e.g. for size heuristics).
    #[must_use]
    pub const fn weights(&self) -> &TransformerWeights {
        &self.weights
    }

    /// The engine's tokenizer.
    #[must_use]
    pub const fn tokenizer(&self) -> &BpeTokenizer {
        &self.tokenizer
    }

    /// Run the greedy autoregressive loop: one
    /// [`transformer_forward_sync`] per generated token, argmax sampling,
    /// EOS / context / budget termination.  Returns the generated token ids
    /// (prompt excluded).
    ///
    /// `max_new_tokens == 0` resolves to [`DEFAULT_MAX_NEW_TOKENS`].
    ///
    /// Token ids are passed to the embedding lookup as `U8` indices — the
    /// Sprint 7 contract (vocab ≤ 256; ids > 255 clamp to 255, same as the
    /// `StreamDecoder`).
    ///
    /// # Errors
    ///
    /// - `engine::greedy_generate::empty_prompt` — `prompt_ids` is empty.
    /// - `engine::greedy_generate::prompt_exceeds_context` — the prompt
    ///   alone fills (or overflows) `config.max_seq_len`.
    /// - Any forward-pass / sampling error, propagated unchanged.
    pub fn greedy_generate(&self, prompt_ids: &[u32], max_new_tokens: u32) -> Result<Vec<u32>> {
        if prompt_ids.is_empty() {
            return Err(NexaCoreError::internal(
                "engine::greedy_generate::empty_prompt",
            ));
        }
        if prompt_ids.len() >= self.config.max_seq_len {
            return Err(NexaCoreError::internal(
                "engine::greedy_generate::prompt_exceeds_context",
            ));
        }

        let budget = if max_new_tokens == 0 {
            DEFAULT_MAX_NEW_TOKENS
        } else {
            max_new_tokens
        };
        let eos = self.tokenizer.special_tokens().eos;

        let mut ids: Vec<u32> = prompt_ids.to_vec();
        let mut generated: Vec<u32> = Vec::new();

        for _ in 0..budget {
            if ids.len() >= self.config.max_seq_len {
                break; // context full — stop honestly rather than truncate.
            }

            let raw: Vec<u8> = ids
                .iter()
                .map(|&id| u8::try_from(id).unwrap_or(u8::MAX))
                .collect();
            let input =
                TensorBuffer::new(TensorDescriptor::new(vec![ids.len()], TensorDtype::U8), raw);

            let logits =
                transformer_forward_sync(&self.backend, &self.config, &self.weights, &input)?;
            let last = extract_last_row(&logits, ids.len(), self.config.vocab_size)?;

            // Greedy: temperature 0, top_k 1 — deterministic argmax.
            let token = sample_token(&last, 0.0, 1)?;

            if token == eos {
                break;
            }
            ids.push(token);
            generated.push(token);
        }

        Ok(generated)
    }

    /// Full text → text generation: BPE encode, [greedy
    /// loop](Self::greedy_generate), BPE decode.  Returns the generated text
    /// and the number of generated tokens.
    ///
    /// # Errors
    ///
    /// Propagates tokenizer encode/decode errors and every
    /// [`Self::greedy_generate`] error unchanged.
    pub fn generate_text(&self, prompt: &str, max_new_tokens: u32) -> Result<(String, u32)> {
        let prompt_ids = self.tokenizer.encode(prompt)?;
        let generated = self.greedy_generate(&prompt_ids, max_new_tokens)?;
        let text = self.tokenizer.decode(&generated)?;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "generated length is bounded by the u32 token budget"
        )]
        Ok((text, generated.len() as u32))
    }

    /// Embed `prompt_ids` into a dense vector by pooling the transformer's
    /// final hidden state ([`crate::embed`], WS5-03.5 path).
    ///
    /// Shares the same forward stack as [`Self::greedy_generate`]: it builds
    /// the `U8` `input_ids` tensor the embedding lookup expects, runs the
    /// transformer to its hidden state, and pools (with optional
    /// L2-normalization) into a `[d_model]` vector.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty prompt, a prompt that does not fit the
    /// context window, or any forward/pooling error.
    pub fn embed(&self, prompt_ids: &[u32], pooling: Pooling, normalize: bool) -> Result<Vec<f32>> {
        if prompt_ids.is_empty() {
            return Err(NexaCoreError::internal("engine::embed::empty_prompt"));
        }
        if prompt_ids.len() > self.config.max_seq_len {
            return Err(NexaCoreError::internal(
                "engine::embed::prompt_exceeds_context",
            ));
        }
        let raw: Vec<u8> = prompt_ids
            .iter()
            .map(|&id| u8::try_from(id).unwrap_or(u8::MAX))
            .collect();
        let input = TensorBuffer::new(
            TensorDescriptor::new(vec![prompt_ids.len()], TensorDtype::U8),
            raw,
        );
        embed_sync(
            &self.backend,
            &self.config,
            &self.weights,
            &input,
            pooling,
            normalize,
        )
    }

    /// Full text → embedding: BPE encode then [`Self::embed`].
    ///
    /// # Errors
    ///
    /// Propagates tokenizer encode errors and every [`Self::embed`] error.
    pub fn embed_text(&self, prompt: &str, pooling: Pooling, normalize: bool) -> Result<Vec<f32>> {
        let prompt_ids = self.tokenizer.encode(prompt)?;
        self.embed(&prompt_ids, pooling, normalize)
    }
}

impl core::fmt::Debug for CpuEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpuEngine")
            .field("n_layers", &self.config.n_layers)
            .field("vocab_size", &self.config.vocab_size)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpe::{BpeVocabulary, SpecialTokens};

    /// Tokenizer matching the synthetic fixture's `vocab_size = 8` —
    /// same construction as the `provider::local_cpu` fixture: ids 0..=7
    /// map to bytes `a`..=`h`, no merges, special ids outside the model
    /// vocabulary so generation terminates on budget, never EOS.
    fn fixture_tokenizer() -> BpeTokenizer {
        let tokens: Vec<(u32, Vec<u8>)> = (0u32..8).map(|i| (i, vec![b'a' + i as u8])).collect();
        let special = SpecialTokens {
            bos: 252,
            eos: 253,
            pad: 254,
            unk: 255,
        };
        BpeTokenizer::new(BpeVocabulary::new(tokens, Vec::new(), special))
    }

    /// The synthetic 1-layer Q8_0 fixture model (shared with the crate
    /// e2e test and the TASK-12 provider golden).
    fn fixture_config() -> TransformerConfig {
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

    fn fixture_engine() -> CpuEngine {
        let gguf = crate::tests::build_synthetic_q8_0_gguf();
        CpuEngine::from_gguf(&gguf, fixture_config(), fixture_tokenizer())
            .expect("fixture GGUF must load")
    }

    // ---- golden invariance on the ported sync path (ADR-0034 §5) ----------

    /// The TASK-12 golden (`"ab"` → `"dddd"` on the Q8_0 fixture) MUST hold
    /// through the exact `no_std` surface the Ring 3 image uses:
    /// `CpuEngine::from_gguf` → `generate_text` (sync forward, no tokio, no
    /// provider wrapper).  Same maths before/after the port — TASK-13-pre
    /// acceptance criterion 2.
    #[test]
    fn golden_ab_to_dddd_via_sync_engine_surface() {
        let engine = fixture_engine();
        let (text, tokens) = engine.generate_text("ab", 4).expect("generate");
        assert_eq!(tokens, 4, "budget fully used (EOS unreachable)");
        assert_eq!(text, "dddd", "ported sync path must match the std golden");

        // Greedy determinism: a second run is byte-identical.
        let (again, _) = engine.generate_text("ab", 4).expect("generate again");
        assert_eq!(text, again);
    }

    /// The embedding path (WS5-03.5) over the same fixture surface the Ring 3
    /// image uses: `embed_text` returns a `[d_model]` vector, deterministic and
    /// finite, and L2-normalization yields unit norm.
    #[test]
    fn embed_text_returns_stable_normalized_vector() {
        let engine = fixture_engine();
        let v = engine.embed_text("ab", Pooling::Mean, true).expect("embed");
        assert_eq!(v.len(), engine.config().d_model, "one float per d_model");
        assert!(v.iter().all(|x| x.is_finite()), "all components finite");

        // Determinism: a second run is identical (the stability the VM-103
        // smoke checks end-to-end).
        let again = engine
            .embed_text("ab", Pooling::Mean, true)
            .expect("embed again");
        assert_eq!(v, again);

        // L2-normalized -> unit norm.
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "normalized vector has unit norm");

        // ids-based entry point agrees with the text path.
        let ids = engine.tokenizer().encode("ab").expect("encode");
        let by_ids = engine.embed(&ids, Pooling::Mean, true).expect("embed ids");
        assert_eq!(v, by_ids);
    }

    /// Scenario-B hardware golden (TASK-13 / ADR-0035 D5): the Ring 3
    /// image filters `"what is 2+2?"` to its in-vocab bytes — `"ha"` —
    /// before the LocalCpu fallback serves it.  Pinning the output here
    /// makes the the test VM fallback capture predictable.
    #[test]
    fn golden_filtered_ha_prompt_is_deterministic() {
        let engine = fixture_engine();
        let (text, tokens) = engine.generate_text("ha", 4).expect("generate");
        let (again, _) = engine.generate_text("ha", 4).expect("generate again");
        assert_eq!(text, again, "greedy must be deterministic");
        assert_eq!(tokens, 4, "budget fully used (EOS unreachable)");
        // GOLDEN: pinned from the first run (same convention as the
        // "ab" -> "dddd" golden; the fixture weights drive every greedy
        // step to argmax id 3 regardless of these prompts).
        assert_eq!(text, "dddd");
    }

    // ---- construction errors ------------------------------------------------

    #[test]
    fn from_gguf_rejects_garbage_bytes() {
        let err = CpuEngine::from_gguf(b"not a gguf", fixture_config(), fixture_tokenizer())
            .expect_err("must fail");
        // GGUF parse error propagated unchanged (no panic, clean error).
        let _ = err;
    }

    #[test]
    fn from_gguf_rejects_missing_tensor() {
        let gguf = crate::tests::build_synthetic_q8_0_gguf();
        let mut config = fixture_config();
        config.n_layers = 2; // fixture has blk.0 only → blk.1 missing
        CpuEngine::from_gguf(&gguf, config, fixture_tokenizer()).expect_err("must fail");
    }

    // ---- greedy loop invariants ---------------------------------------------

    #[test]
    fn greedy_generate_rejects_empty_prompt() {
        let engine = fixture_engine();
        engine.greedy_generate(&[], 4).expect_err("empty prompt");
    }

    #[test]
    fn greedy_generate_rejects_prompt_at_context_limit() {
        let engine = fixture_engine();
        let prompt: Vec<u32> = (0..16).map(|i| i % 8).collect(); // == max_seq_len
        engine
            .greedy_generate(&prompt, 4)
            .expect_err("prompt fills the context");
    }

    #[test]
    fn zero_budget_resolves_to_default() {
        let engine = fixture_engine();
        let generated = engine
            .greedy_generate(&[0, 1], 0)
            .expect("default budget generate");
        // DEFAULT_MAX_NEW_TOKENS = 16 but the 16-token context caps
        // generation at 14 new tokens (2 prompt tokens already present).
        assert_eq!(generated.len(), 14, "context-capped default budget");
    }
}

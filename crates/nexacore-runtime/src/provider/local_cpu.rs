//! `LocalCpuProvider` — the `LocalCpu` fallback backend (TASK-12, DE-G4).
//!
//! Implements [`InferenceProvider`] over the inference engine that
//! already lives in this crate (Sprint 7/8): GGUF parsing
//! ([`crate::gguf`]), tensor loading + dequantisation
//! ([`crate::tensor_loader`]), the BPE tokenizer ([`crate::bpe`]), and
//! the transformer forward pass (`nexacore_hal::transformer`) — **reuse, not
//! a second engine** (ADR-0033).
//!
//! ## Async-native greedy loop
//!
//! [`crate::decode::streaming_decode`] is a synchronous iterator that
//! bridges the async forward pass with an internal `block_on`; calling
//! it from this provider's async methods would nest a runtime inside the
//! caller's runtime (tokio panics). The provider therefore drives
//! `transformer_forward` directly with `.await` and reuses the decode
//! module's `extract_last_row` / `sample_token` helpers (promoted
//! `pub(crate)` for exactly this — same maths, no duplication).
//! Generation is **greedy** (`temperature = 0`, `top_k = 1`), so output
//! is fully deterministic — the golden test pins it.
//!
//! ## The `degraded` honesty contract (plan §9)
//!
//! The Phase-2 CPU engine is correct but unoptimised; on real models it
//! is not interactive. The provider computes a `degraded` flag at
//! construction (total weight bytes > [`DEGRADED_WEIGHTS_BYTES`]) and
//! exposes it via [`LocalCpuProvider::degraded`]; the wiring propagates
//! it to the router ([`super::BackendRouter::with_backend_degraded`]),
//! which carries it on every [`nexacore_types::ai::BackendStatusEvent`] so
//! the UI (TASK-21) renders the state distinctly. The heuristic is
//! overridable ([`LocalCpuProvider::with_degraded`]) for callers with
//! better information.
//!
//! ## Scope (Phase 2)
//!
//! - `generate`/`chat`: served (chat uses a plain `role: content`
//!   transcript template — model-specific chat templates are a TASK-16+
//!   concern).
//! - `embeddings`: **not supported** — the engine has no pooling head;
//!   a terminal [`ProviderError::Backend`] keeps the failure honest
//!   (the `RemoteGpu` backend serves embeddings).
//! - Vocabulary ≤ 256: the CPU embedding lookup uses `U8` indices (the
//!   documented Sprint 7 limitation; wider indices land with TASK-16).

use async_trait::async_trait;
use nexacore_hal::transformer::{TransformerConfig, TransformerLayerWeights, TransformerWeights};

use super::{
    BackendKind, ChatMessage, ChatRequest, ChatResponse, EmbeddingsRequest, EmbeddingsResponse,
    GenerateRequest, GenerateResponse, HealthStatus, InferenceProvider, ProviderError,
};
use crate::{bpe::BpeTokenizer, engine::CpuEngine};

/// Weight-size threshold above which the provider flags itself
/// `degraded` (1 MiB).
///
/// Anything beyond a toy/fixture model is not interactive on the
/// Phase-2 unoptimised engine; the flag makes that explicit instead of
/// letting the UI imply GPU-class latency (plan §9). Overridable via
/// [`LocalCpuProvider::with_degraded`].
pub const DEGRADED_WEIGHTS_BYTES: usize = 1024 * 1024;

/// Default generation budget when the request carries `max_tokens = 0`
/// ("provider default"). Deliberately small: every token is a full
/// forward pass on the CPU.
pub const DEFAULT_MAX_NEW_TOKENS: u32 = 16;

/// The `LocalCpu` [`InferenceProvider`]: on-device greedy generation
/// over the Sprint 7/8 engine. Always available (no network), the
/// last-resort backend in [`super::BackendPolicy::PreferRemoteGpu`].
pub struct LocalCpuProvider {
    /// The assembled `no_std`-capable engine (TASK-13-pre / ADR-0034):
    /// weight mapping and the greedy loop live there so the Ring 3 image
    /// runs the SAME audited body.
    engine: CpuEngine,
    degraded: bool,
}

impl LocalCpuProvider {
    /// Build a provider from pre-loaded weights and a tokenizer.
    ///
    /// `degraded` is computed from the heuristic (see
    /// [`DEGRADED_WEIGHTS_BYTES`]); override with
    /// [`Self::with_degraded`].
    #[must_use]
    pub fn new(
        config: TransformerConfig,
        weights: TransformerWeights,
        tokenizer: BpeTokenizer,
    ) -> Self {
        let engine = CpuEngine::new(config, weights, tokenizer);
        let degraded = Self::weights_total_bytes(engine.weights()) > DEGRADED_WEIGHTS_BYTES;
        Self { engine, degraded }
    }

    /// Build a provider directly from GGUF bytes: parse → load +
    /// dequantise → map tensors by their canonical GGUF names
    /// (`token_embd.weight`, `blk.{i}.attn_q.weight`, …) into
    /// [`TransformerWeights`] — all delegated to
    /// [`CpuEngine::from_gguf`] (single audited engine body, ADR-0034).
    ///
    /// `config` is caller-supplied: deriving the architecture from GGUF
    /// metadata keys is the TASK-16 (full quantised inference) scope;
    /// Phase 2 models are fixtures with known shapes.
    ///
    /// # Errors
    ///
    /// [`ProviderError::InvalidRequest`] when the GGUF is malformed or a
    /// required tensor is missing/too small for the configured shape.
    pub fn from_gguf(
        gguf_bytes: &[u8],
        config: TransformerConfig,
        tokenizer: BpeTokenizer,
    ) -> Result<Self, ProviderError> {
        let engine = CpuEngine::from_gguf(gguf_bytes, config, tokenizer)
            .map_err(|e| ProviderError::InvalidRequest(format!("GGUF engine build failed: {e}")))?;
        let degraded = Self::weights_total_bytes(engine.weights()) > DEGRADED_WEIGHTS_BYTES;
        Ok(Self { engine, degraded })
    }

    /// Whether this provider serves with explicitly reduced performance
    /// (plan §9). Propagate to the router at wiring time via
    /// [`super::BackendRouter::with_backend_degraded`].
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.degraded
    }

    /// Override the degraded heuristic (builder style) — for callers
    /// with better information than the weight-size threshold (e.g. a
    /// measured tokens/s benchmark).
    #[must_use]
    pub fn with_degraded(mut self, degraded: bool) -> Self {
        self.degraded = degraded;
        self
    }

    /// Total bytes across all weight buffers (the degraded heuristic
    /// input).
    fn weights_total_bytes(w: &TransformerWeights) -> usize {
        let layer_bytes = |l: &TransformerLayerWeights| {
            l.attn_q.descriptor.byte_size()
                + l.attn_k.descriptor.byte_size()
                + l.attn_v.descriptor.byte_size()
                + l.attn_o.descriptor.byte_size()
                + l.ffn_gate.descriptor.byte_size()
                + l.ffn_up.descriptor.byte_size()
                + l.ffn_down.descriptor.byte_size()
                + l.attn_norm.descriptor.byte_size()
                + l.ffn_norm.descriptor.byte_size()
        };
        w.token_embedding.descriptor.byte_size()
            + w.output_norm.descriptor.byte_size()
            + w.output_proj.descriptor.byte_size()
            + w.layers.iter().map(layer_bytes).sum::<usize>()
    }

    /// Run the greedy autoregressive loop via [`CpuEngine::greedy_generate`]
    /// (one sync forward pass per generated token, argmax sampling, EOS /
    /// context / budget termination).  Returns the generated token ids
    /// (prompt excluded).
    ///
    /// Validation stays here so the error CLASS is preserved
    /// (`InvalidRequest` for caller mistakes vs `Backend` for engine
    /// faults); the engine re-checks the same invariants for its `no_std`
    /// consumers.
    fn greedy_generate(
        &self,
        prompt_ids: &[u32],
        max_new_tokens: u32,
    ) -> Result<Vec<u32>, ProviderError> {
        if prompt_ids.is_empty() {
            return Err(ProviderError::InvalidRequest("empty prompt".to_owned()));
        }
        if prompt_ids.len() >= self.engine.config().max_seq_len {
            return Err(ProviderError::InvalidRequest(format!(
                "prompt ({} tokens) exceeds the model context ({})",
                prompt_ids.len(),
                self.engine.config().max_seq_len
            )));
        }

        self.engine
            .greedy_generate(prompt_ids, max_new_tokens)
            .map_err(|e| ProviderError::Backend(format!("engine generation failed: {e}")))
    }
}

impl std::fmt::Debug for LocalCpuProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCpuProvider")
            .field("n_layers", &self.engine.config().n_layers)
            .field("vocab_size", &self.engine.config().vocab_size)
            .field("degraded", &self.degraded)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl InferenceProvider for LocalCpuProvider {
    fn kind(&self) -> BackendKind {
        BackendKind::LocalCpu
    }

    async fn generate(&self, req: &GenerateRequest) -> Result<GenerateResponse, ProviderError> {
        let prompt_ids = self
            .engine
            .tokenizer()
            .encode(&req.prompt)
            .map_err(|e| ProviderError::InvalidRequest(format!("tokenization failed: {e}")))?;

        let generated = self.greedy_generate(&prompt_ids, req.max_tokens)?;

        let text = self
            .engine
            .tokenizer()
            .decode(&generated)
            .map_err(|e| ProviderError::Backend(format!("detokenization failed: {e}")))?;

        #[allow(
            clippy::cast_possible_truncation,
            reason = "generated length is bounded by the u32 token budget"
        )]
        Ok(GenerateResponse {
            text,
            tokens: generated.len() as u32,
        })
    }

    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        // Plain transcript template (Phase 2): "role: content" per turn,
        // then the assistant cue. Model-specific chat templates are a
        // TASK-16+ concern.
        let mut prompt = String::new();
        for m in &req.messages {
            prompt.push_str(&m.role);
            prompt.push_str(": ");
            prompt.push_str(&m.content);
            prompt.push('\n');
        }
        prompt.push_str("assistant:");

        let generate_req = GenerateRequest {
            model: req.model.clone(),
            prompt,
            max_tokens: 0,
        };
        let resp = self.generate(&generate_req).await?;
        Ok(ChatResponse {
            message: ChatMessage {
                role: "assistant".to_owned(),
                content: resp.text,
            },
            tokens: resp.tokens,
        })
    }

    async fn embeddings(
        &self,
        _req: &EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, ProviderError> {
        // No pooling head in the Phase-2 engine — honest terminal error
        // (the RemoteGpu backend serves embeddings; see module docs).
        Err(ProviderError::Backend(
            "embeddings are not supported by the LocalCpu engine in Phase 2".to_owned(),
        ))
    }

    async fn health(&self) -> HealthStatus {
        // On-device, no connectivity to lose: always healthy. The
        // degraded flag is performance honesty, not ill health.
        HealthStatus {
            healthy: true,
            detail: if self.degraded {
                "ok (degraded: CPU engine, reduced performance)".to_owned()
            } else {
                "ok".to_owned()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        bpe::{BpeVocabulary, SpecialTokens},
        provider::{BackendPolicy, BackendRouter, MockInferenceProvider, RequestContext},
    };

    /// Tokenizer matching the synthetic fixture's `vocab_size = 8`:
    /// ids 0..=7 map to bytes `a`..=`h`, no merges. Special ids sit
    /// OUTSIDE the model vocabulary (the 8-logit head can never sample
    /// them), so generation terminates on budget/context, never EOS —
    /// deterministic for the golden test.
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
    /// e2e test): n_layers=1, n_heads=1, d_model=4, d_ff=8,
    /// vocab_size=8, max_seq_len=16.
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

    fn fixture_provider() -> LocalCpuProvider {
        let gguf = crate::tests::build_synthetic_q8_0_gguf();
        LocalCpuProvider::from_gguf(&gguf, fixture_config(), fixture_tokenizer())
            .expect("fixture GGUF must load")
    }

    // ---- construction + degraded heuristic --------------------------------

    #[test]
    fn from_gguf_builds_and_fixture_is_not_degraded() {
        let provider = fixture_provider();
        assert_eq!(provider.kind(), BackendKind::LocalCpu);
        assert!(
            !provider.degraded(),
            "tiny fixture is below the degraded threshold"
        );
    }

    #[test]
    fn degraded_override_is_respected() {
        let provider = fixture_provider().with_degraded(true);
        assert!(provider.degraded());
    }

    #[test]
    fn from_gguf_rejects_missing_tensor() {
        let gguf = crate::tests::build_synthetic_q8_0_gguf();
        let mut config = fixture_config();
        config.n_layers = 2; // fixture has blk.0 only → blk.1 missing
        let err =
            LocalCpuProvider::from_gguf(&gguf, config, fixture_tokenizer()).expect_err("must fail");
        assert!(matches!(err, ProviderError::InvalidRequest(_)), "{err:?}");
    }

    #[test]
    fn from_gguf_rejects_garbage_bytes() {
        let err = LocalCpuProvider::from_gguf(b"not a gguf", fixture_config(), fixture_tokenizer())
            .expect_err("must fail");
        assert!(matches!(err, ProviderError::InvalidRequest(_)), "{err:?}");
    }

    // ---- golden greedy generation (acceptance #1) --------------------------

    #[tokio::test]
    async fn golden_greedy_generate_is_deterministic_on_fixture() {
        let provider = fixture_provider();
        let req = GenerateRequest {
            model: "fixture".to_owned(),
            prompt: "ab".to_owned(), // ids [0, 1]
            max_tokens: 4,
        };

        let started = std::time::Instant::now();
        let first = provider.generate(&req).await.expect("generate");
        let elapsed = started.elapsed();
        // Acceptance #3: document the fixture latency (no numeric gate;
        // measured ~60-70µs for 4 tokens on the dev box — recorded in
        // the commit message). tracing avoids the disallowed eprintln.
        tracing::info!(
            ?elapsed,
            tokens = first.tokens,
            "task12 fixture generate latency"
        );

        // Greedy decoding on fixed weights is fully deterministic.
        let second = provider.generate(&req).await.expect("generate again");
        assert_eq!(first.text, second.text, "greedy must be deterministic");
        assert_eq!(first.tokens, second.tokens);

        // GOLDEN: the fixture weights drive every greedy step to argmax
        // id 3 ('d'). Pinned literally (captured from the first run) —
        // any engine change that shifts the forward maths must update
        // this consciously.
        assert_eq!(first.tokens, 4, "budget fully used (EOS unreachable)");
        assert_eq!(first.text, "dddd");
    }

    #[tokio::test]
    async fn generate_respects_context_bound() {
        let provider = fixture_provider();
        // 15-token prompt in a 16-token context → exactly 1 token fits.
        let req = GenerateRequest {
            model: "fixture".to_owned(),
            prompt: "a".repeat(15),
            max_tokens: 8,
        };
        let resp = provider.generate(&req).await.expect("generate");
        assert_eq!(resp.tokens, 1, "context-capped to max_seq_len");

        // A prompt that already fills the context is a clean error.
        let req = GenerateRequest {
            model: "fixture".to_owned(),
            prompt: "a".repeat(16),
            max_tokens: 1,
        };
        let err = provider.generate(&req).await.expect_err("over context");
        assert!(matches!(err, ProviderError::InvalidRequest(_)), "{err:?}");
    }

    #[tokio::test]
    async fn empty_prompt_is_invalid_request() {
        let provider = fixture_provider();
        let req = GenerateRequest {
            model: "fixture".to_owned(),
            prompt: String::new(),
            max_tokens: 4,
        };
        let err = provider.generate(&req).await.expect_err("empty");
        assert!(matches!(err, ProviderError::InvalidRequest(_)), "{err:?}");
    }

    #[tokio::test]
    async fn chat_out_of_vocab_template_is_clean_backend_error() {
        // The chat template (": ", "\n", "assistant:") is inherently
        // out-of-vocab for the 8-token fixture: those bytes encode to
        // UNK (id 255) which exceeds the model's embedding table. A real
        // tokenizer covers all 256 byte values, so this only bites
        // fixtures — what matters is that the engine surfaces a CLEAN
        // terminal error (no panic, no OOB read; the HAL bounds-checks
        // the lookup). The chat→generate delegation itself is covered by
        // the generate tests (chat is a thin transcript template).
        let provider = fixture_provider();
        let err = provider
            .chat(&ChatRequest {
                model: "fixture".to_owned(),
                messages: vec![ChatMessage {
                    role: "u".to_owned(),
                    content: "a".to_owned(),
                }],
            })
            .await
            .expect_err("out-of-vocab template on the tiny fixture");
        assert!(matches!(err, ProviderError::Backend(_)), "{err:?}");
    }

    #[tokio::test]
    async fn embeddings_are_honestly_unsupported() {
        let provider = fixture_provider();
        let err = provider
            .embeddings(&EmbeddingsRequest {
                model: "fixture".to_owned(),
                input: "abc".to_owned(),
            })
            .await
            .expect_err("unsupported");
        assert!(matches!(err, ProviderError::Backend(_)), "{err:?}");
        assert!(!err.is_retriable(), "terminal, no failover storm");
    }

    #[tokio::test]
    async fn health_reports_degraded_in_detail() {
        let provider = fixture_provider().with_degraded(true);
        let health = provider.health().await;
        assert!(health.healthy, "degraded is not unhealthy");
        assert!(health.detail.contains("degraded"), "{health:?}");
    }

    // ---- failover e2e (acceptance #2) --------------------------------------

    #[tokio::test]
    async fn failover_gpu_down_same_request_served_by_local_cpu_with_audit() {
        // GPU mock refuses; the SAME request must be served by the REAL
        // LocalCpuProvider, the audit must record backend_used=LocalCpu,
        // and the degraded flag must be visible on the router + events.
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Unavailable("gpu down".into())));

        let cpu = fixture_provider().with_degraded(true); // exercise propagation
        let cpu_degraded = cpu.degraded();

        let log = Arc::new(parking_lot::Mutex::new(
            crate::audit::InMemoryAuditLog::new(),
        ));
        let events = Arc::new(crate::provider::health::BufferStatusSink::new());
        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu))
            .with_backend_degraded(BackendKind::LocalCpu, cpu_degraded)
            .with_health(
                crate::provider::health::HealthPolicy::default(),
                Box::new(events.clone()),
            )
            .with_audit(log.clone());

        let ctx = RequestContext {
            session_id: nexacore_types::SessionId::from_bytes([0x12; 16]),
            capability_id: nexacore_types::CapabilityId::from_bytes([0x34; 16]),
            model_id: nexacore_types::ModelId::from_bytes([0x56; 32]),
            tier: 0,
            timestamp_ns: 7,
            input_token_count: 2,
        };
        let req = crate::provider::Tier0Request::new(GenerateRequest {
            model: "fixture".to_owned(),
            prompt: "ab".to_owned(),
            max_tokens: 4,
        });

        let routed = router
            .generate_with_ctx(&req, &ctx)
            .await
            .expect("LocalCpu serves the failover");
        assert_eq!(routed.backend_used, BackendKind::LocalCpu);
        assert_eq!(routed.value.text, "dddd", "same golden output");

        // Audit: exactly one record, attributed to LocalCpu.
        let rec = {
            use crate::audit::AuditLog;
            let guard = log.lock();
            assert_eq!(guard.count(), 1, "exactly one record per request");
            guard.iter().next().expect("one record").clone()
        };
        assert_eq!(rec.backend_used, Some(BackendKind::LocalCpu));

        // Degraded flag: readable on the router and carried on events.
        assert!(router.backend_degraded(BackendKind::LocalCpu));
        router.health().observe(BackendKind::LocalCpu, false); // force a transition
        let evs = events.events();
        assert_eq!(evs.len(), 2, "GPU demotion + forced LocalCpu demotion");
        assert!(
            evs.iter()
                .any(|e| e.backend == BackendKind::LocalCpu && e.degraded),
            "LocalCpu events carry degraded=true: {evs:?}"
        );
    }
}

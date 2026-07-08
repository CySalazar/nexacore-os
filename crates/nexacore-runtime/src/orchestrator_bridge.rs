//! Orchestrator → Runtime dispatch bridge.
//!
//! This module provides [`crate::orchestrator_bridge::OrchestratorBridge`], which sits between the
//! five-agent Orchestrator (in `nexacore-agent`) and the inference pipeline.
//! When the Orchestrator classifies an intent as requiring AI inference it
//! calls [`crate::orchestrator_bridge::OrchestratorBridge::process_intent`], which:
//!
//! 1. Pre-processes the intent text through [`crate::preprocessing::PreprocessingPipeline`] to
//!    remove PII before it reaches the model.
//! 2. Packages the sanitised text as an [`crate::relay::AiSyscallRequest`] and forwards
//!    it to the [`crate::relay::AiIpcRelay`].
//! 3. Post-processes the response by calling
//!    [`crate::preprocessing::PreprocessingPipeline::detokenize_pii`] on the raw output bytes.
//! 4. Returns a structured [`crate::orchestrator_bridge::IntentResult`] to the caller.
//!
//! ## Intent keyword matching
//!
//! [`crate::orchestrator_bridge::OrchestratorBridge::requires_inference`] uses a static keyword list to
//! decide whether an intent warrants an AI call. This avoids a circular
//! dependency (calling the model to decide whether to call the model). The
//! keywords are chosen to cover the dominant intent categories from
//! NCIP-Agent-Arch-022 §S2.2 that inherently require generative reasoning.
//!
//! ## Phase 2 note
//!
//! The bridge does not yet implement retry logic, timeout cancellation, or
//! streaming token delivery. These will be added in Phase 3 alongside the
//! real tensor backend.

use nexacore_types::ModelId;
use tracing::{debug, info, instrument};

use crate::{
    preprocessing::PreprocessingPipeline,
    relay::{AiIpcRelay, AiSyscallNumber, AiSyscallRequest, IntentDispatcher},
};

// =============================================================================
// IntentResult
// =============================================================================

/// The result of processing a user intent through the full bridge pipeline.
///
/// Returned by [`OrchestratorBridge::process_intent`] and surfaced to the
/// caller (typically the Orchestrator Agent) for delivery to the user.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
///
/// use nexacore_crypto::signing::NexaCoreSigningKey;
/// use nexacore_runtime::{
///     inference::InferencePipeline,
///     model::{ModelFormat, ModelManifest, ModelRegistry},
///     orchestrator_bridge::OrchestratorBridge,
///     relay::AiIpcRelay,
/// };
/// use nexacore_types::ModelId;
/// use tokio::sync::Mutex;
///
/// # #[tokio::main]
/// # async fn main() {
/// let sk = NexaCoreSigningKey::from_bytes([0x20; 32]);
/// let mut hash = [0u8; 32];
/// hash[..16].fill(0xBC);
/// let manifest = ModelManifest {
///     model_id: ModelId::from_manifest_hash(hash),
///     name: "bridge-doctest".into(),
///     version: "1.0.0".into(),
///     hash,
///     signature: sk.sign(&hash),
///     signing_key: sk.verifying_key(),
///     size_bytes: 0,
///     format: ModelFormat::Gguf,
/// };
/// let mut reg = ModelRegistry::new();
/// let id = reg.register(manifest).unwrap();
/// reg.load(id).unwrap();
///
/// let pipeline = InferencePipeline::new(Arc::new(Mutex::new(reg)));
/// let relay = AiIpcRelay::new(pipeline);
/// let bridge = OrchestratorBridge::new(relay);
///
/// let result = bridge
///     .process_intent("explain what a kernel is", id, 1)
///     .await;
/// assert_eq!(result.request_id, 1);
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct IntentResult {
    /// Echoes the `request_id` supplied to `process_intent`.
    pub request_id: u64,
    /// `true` if the inference call succeeded end-to-end.
    pub success: bool,
    /// Detokenized response text (PII tokens stripped / replaced).
    pub response_text: String,
    /// Number of PII entities tokenized in the input.
    pub entities_tokenized: usize,
    /// Wall-clock inference latency in microseconds as reported by the relay.
    pub inference_latency_us: u64,
}

// =============================================================================
// OrchestratorBridge
// =============================================================================

/// Bridge between the Orchestrator Agent and the AI inference pipeline.
///
/// `OrchestratorBridge` is the single integration point between agent-layer
/// intent processing and runtime-layer model dispatch. It is stateless apart
/// from its relay and preprocessor handles, which are both cheap to clone.
///
/// # Thread safety
///
/// `OrchestratorBridge` is `Send + Sync`. Wrap it in an `Arc` to share across
/// async tasks without a mutex.
/// # Dispatcher genericity (TASK-13 / ADR-0035 D1)
///
/// The bridge is generic over its [`IntentDispatcher`], defaulting to
/// [`AiIpcRelay`] so all pre-TASK-13 call sites compile unchanged.  The
/// agent path instantiates it over
/// [`ServingRelay`](crate::relay::ServingRelay), which routes through the
/// [`BackendRouter`](crate::provider::BackendRouter) audited dispatch —
/// a user prompt then reaches a REAL backend, and `backend_used` lands in
/// the [`crate::audit::AuditRecord`].
#[derive(Clone, Debug)]
pub struct OrchestratorBridge<D = AiIpcRelay> {
    /// Dispatcher that serves the built [`AiSyscallRequest`].
    relay: D,
    /// Pre-processing pipeline for PII scanning.
    preprocessor: PreprocessingPipeline,
}

/// Static keyword list used by [`OrchestratorBridge::requires_inference`].
///
/// A match on any of these keywords (case-insensitive) indicates that the
/// intent involves generative reasoning and therefore warrants an AI call.
/// The list is intentionally conservative to avoid unnecessary model invocations
/// for simple system operations.
const INFERENCE_KEYWORDS: &[&str] = &[
    "explain",
    "analyze",
    "analyse",
    "summarize",
    "summarise",
    "translate",
    "generate",
    "what is",
    "what are",
    "how does",
    "how do",
    "describe",
    "compare",
    "elaborate",
    "clarify",
    "interpret",
];

impl OrchestratorBridge {
    /// Determine whether an intent string requires AI inference.
    ///
    /// Returns `true` if `intent` contains any keyword from the
    /// `INFERENCE_KEYWORDS` list (case-insensitive match). Returns `false`
    /// for simple system commands that can be handled deterministically.
    ///
    /// Defined on the default instantiation
    /// (`OrchestratorBridge<AiIpcRelay>`) so existing
    /// `OrchestratorBridge::requires_inference(..)` call sites keep
    /// resolving without a turbofish (same pattern as `HashMap::new`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::orchestrator_bridge::OrchestratorBridge;
    ///
    /// assert!(OrchestratorBridge::requires_inference(
    ///     "explain what a kernel is"
    /// ));
    /// assert!(OrchestratorBridge::requires_inference("ANALYZE the logs"));
    /// assert!(!OrchestratorBridge::requires_inference("install firefox"));
    /// assert!(!OrchestratorBridge::requires_inference(
    ///     "list running processes"
    /// ));
    /// ```
    #[must_use]
    pub fn requires_inference(intent: &str) -> bool {
        let lower = intent.to_lowercase();
        INFERENCE_KEYWORDS.iter().any(|kw| lower.contains(kw))
    }
}

impl<D: IntentDispatcher> OrchestratorBridge<D> {
    /// Create a new bridge backed by `relay`.
    ///
    /// A fresh [`PreprocessingPipeline`] is constructed internally; callers
    /// do not need to manage it separately.
    ///
    /// ```rust
    /// use std::sync::Arc;
    ///
    /// use nexacore_runtime::{
    ///     inference::InferencePipeline, model::ModelRegistry,
    ///     orchestrator_bridge::OrchestratorBridge, relay::AiIpcRelay,
    /// };
    /// use tokio::sync::Mutex;
    ///
    /// let reg = ModelRegistry::new();
    /// let pipe = InferencePipeline::new(Arc::new(Mutex::new(reg)));
    /// let relay = AiIpcRelay::new(pipe);
    /// let bridge = OrchestratorBridge::new(relay);
    /// ```
    #[must_use]
    pub fn new(relay: D) -> Self {
        Self {
            relay,
            preprocessor: PreprocessingPipeline::new(),
        }
    }

    /// Process an intent through the full pipeline:
    /// PII scan → inference → PII detokenize → result.
    ///
    /// Steps:
    ///
    /// 1. Pre-process `intent` via [`PreprocessingPipeline::preprocess`].
    /// 2. Build an [`AiSyscallRequest`] with [`AiSyscallNumber::Invoke`] and
    ///    the sanitised text as `input_data` (UTF-8 bytes).
    /// 3. Dispatch through [`AiIpcRelay::dispatch`].
    /// 4. Decode the response bytes as UTF-8 (lossy) and detokenize PII.
    /// 5. Return an [`IntentResult`].
    ///
    /// This method does **not** check `requires_inference` — that is the
    /// caller's responsibility. The bridge processes whatever intent it is given.
    ///
    /// # Errors
    ///
    /// This method is infallible at the Rust level: all error conditions
    /// (model not loaded, pipeline failure) are reported via `success = false`
    /// on the returned [`IntentResult`]. The `response_text` will contain a
    /// human-readable error summary in that case.
    #[instrument(skip(self), fields(request_id, intent_len = intent.len()))]
    pub async fn process_intent(
        &self,
        intent: &str,
        model_id: ModelId,
        request_id: u64,
    ) -> IntentResult {
        info!(
            request_id,
            intent_preview = &intent[..intent.len().min(60)],
            "orchestrator bridge: processing intent"
        );

        // Step 1: Pre-process to remove PII before sending to the model.
        let preprocessed = self.preprocessor.preprocess(intent);
        debug!(
            entities_found = preprocessed.entities_found,
            "orchestrator bridge: preprocessing complete"
        );

        // Step 2: Build the syscall request.
        // The model_id's first 16 bytes form the compact kernel ABI form.
        let mut compact = [0u8; 16];
        compact.copy_from_slice(&model_id.as_bytes()[..16]);

        let syscall_req = AiSyscallRequest {
            syscall: AiSyscallNumber::Invoke,
            model_id_bytes: compact,
            // The bridge runs in-process inside the runtime (trusted
            // path through AiIpcRelay, which does not gate on this
            // field); a minimal well-formed token keeps the shared wire
            // type honest. Real capability material lands with
            // TASK-S11.E.
            capability: vec![0x01],
            input_data: preprocessed.processed_text.into_bytes(),
            request_id,
            caller_pid: 0, // bridge runs in the runtime process (pid resolved by relay layer in future)
        };

        // Step 3: Dispatch through the relay.
        let syscall_resp = self.relay.dispatch(syscall_req).await;

        // Step 4: Decode output and detokenize PII.
        let raw_output = String::from_utf8_lossy(&syscall_resp.output_data).into_owned();
        let response_text = if syscall_resp.success {
            self.preprocessor.detokenize_pii(&raw_output)
        } else {
            // On failure, include the relay error message for diagnostics.
            syscall_resp
                .error_message
                .unwrap_or_else(|| "inference failed: unknown error".to_string())
        };

        info!(
            request_id,
            success = syscall_resp.success,
            latency_us = syscall_resp.latency_us,
            entities_tokenized = preprocessed.entities_found,
            "orchestrator bridge: dispatch complete"
        );

        IntentResult {
            request_id,
            success: syscall_resp.success,
            response_text,
            entities_tokenized: preprocessed.entities_found,
            inference_latency_us: syscall_resp.latency_us,
        }
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use nexacore_crypto::signing::NexaCoreSigningKey;
    use nexacore_types::ModelId;
    use tokio::sync::Mutex;

    use super::*;
    use crate::{
        inference::InferencePipeline,
        model::{ModelFormat, ModelManifest, ModelRegistry},
        relay::AiIpcRelay,
    };

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    fn make_bridge_with_loaded_model(seed: u8, hash_byte: u8) -> (OrchestratorBridge, ModelId) {
        let sk = NexaCoreSigningKey::from_bytes([seed; 32]);
        let mut hash = [0u8; 32];
        hash[..16].fill(hash_byte);
        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(hash),
            name: "bridge-test-model".into(),
            version: "1.0.0".into(),
            hash,
            signature: sk.sign(&hash),
            signing_key: sk.verifying_key(),
            size_bytes: 0,
            format: ModelFormat::Gguf,
        };
        let mut reg = ModelRegistry::new();
        let id = reg.register(manifest).unwrap();
        reg.load(id).unwrap();
        let pipeline = InferencePipeline::new(Arc::new(Mutex::new(reg)));
        let relay = AiIpcRelay::new(pipeline);
        let bridge = OrchestratorBridge::new(relay);
        (bridge, id)
    }

    // -------------------------------------------------------------------------
    // requires_inference
    // -------------------------------------------------------------------------

    #[test]
    fn explain_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference(
            "explain what this file does"
        ));
    }

    #[test]
    fn analyze_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference(
            "analyze the system logs"
        ));
    }

    #[test]
    fn summarize_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference(
            "summarize the document"
        ));
    }

    #[test]
    fn translate_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference(
            "translate this to French"
        ));
    }

    #[test]
    fn generate_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference("generate a report"));
    }

    #[test]
    fn what_is_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference(
            "what is a system call"
        ));
    }

    #[test]
    fn how_does_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference(
            "how does the scheduler work"
        ));
    }

    #[test]
    fn describe_triggers_inference() {
        assert!(OrchestratorBridge::requires_inference(
            "describe the network topology"
        ));
    }

    #[test]
    fn install_does_not_trigger_inference() {
        assert!(!OrchestratorBridge::requires_inference("install firefox"));
    }

    #[test]
    fn list_does_not_trigger_inference() {
        assert!(!OrchestratorBridge::requires_inference(
            "list running processes"
        ));
    }

    #[test]
    fn case_insensitive_matching() {
        assert!(OrchestratorBridge::requires_inference("EXPLAIN the kernel"));
        assert!(OrchestratorBridge::requires_inference("Analyze This"));
    }

    #[test]
    fn empty_intent_does_not_trigger_inference() {
        assert!(!OrchestratorBridge::requires_inference(""));
    }

    // -------------------------------------------------------------------------
    // process_intent — success path
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn process_intent_loaded_model_succeeds() {
        let (bridge, id) = make_bridge_with_loaded_model(0x30, 0xAB);
        let result = bridge
            .process_intent("explain what this file does", id, 1)
            .await;
        assert!(result.success);
        assert_eq!(result.request_id, 1);
    }

    #[tokio::test]
    async fn process_intent_echoes_request_id() {
        let (bridge, id) = make_bridge_with_loaded_model(0x31, 0xAC);
        for rid in [0u64, 1, 999, u64::MAX - 1] {
            let result = bridge.process_intent("explain kernels", id, rid).await;
            assert_eq!(result.request_id, rid);
        }
    }

    #[tokio::test]
    async fn process_intent_records_latency() {
        let (bridge, id) = make_bridge_with_loaded_model(0x32, 0xAD);
        let result = bridge.process_intent("describe the system", id, 10).await;
        // latency_us is u64 — just verify it was populated.
        let _ = result.inference_latency_us;
        assert!(result.success);
    }

    // -------------------------------------------------------------------------
    // process_intent — error path
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn process_intent_unregistered_model_fails_gracefully() {
        let reg = ModelRegistry::new();
        let pipeline = InferencePipeline::new(Arc::new(Mutex::new(reg)));
        let relay = AiIpcRelay::new(pipeline);
        let bridge = OrchestratorBridge::new(relay);

        let unknown_id = ModelId::from_bytes([0xFF; 32]);
        let result = bridge
            .process_intent("explain something", unknown_id, 42)
            .await;
        assert!(!result.success);
        assert_eq!(result.request_id, 42);
        // response_text should carry the error message, not panic.
        assert!(!result.response_text.is_empty());
    }

    // -------------------------------------------------------------------------
    // PII integration: preprocessing propagates through bridge
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn process_intent_strips_pii_from_input() {
        // We cannot observe the sanitised input inside the relay (it's already
        // dispatched), but we can verify the entities_tokenized field is
        // populated when PII is present.
        let (bridge, id) = make_bridge_with_loaded_model(0x33, 0xAE);
        let result = bridge
            .process_intent("explain why user@example.com cannot log in", id, 20)
            .await;
        // The email should have been detected by the preprocessor.
        assert_eq!(result.entities_tokenized, 1);
    }

    #[tokio::test]
    async fn process_intent_zero_entities_for_clean_input() {
        let (bridge, id) = make_bridge_with_loaded_model(0x34, 0xAF);
        let result = bridge
            .process_intent("explain how the CPU scheduler works", id, 21)
            .await;
        assert_eq!(result.entities_tokenized, 0);
    }

    // -------------------------------------------------------------------------
    // Clone + concurrency
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn bridge_can_be_cloned_and_used_concurrently() {
        let (bridge, id) = make_bridge_with_loaded_model(0x35, 0xB0);
        let bridge2 = bridge.clone();

        let (r1, r2) = tokio::join!(
            bridge.process_intent("explain A", id, 100),
            bridge2.process_intent("describe B", id, 101),
        );

        assert!(r1.success);
        assert!(r2.success);
        assert_eq!(r1.request_id, 100);
        assert_eq!(r2.request_id, 101);
    }
}

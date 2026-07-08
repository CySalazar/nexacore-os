//! AI Syscall IPC Relay.
//!
//! This module bridges kernel AI syscalls (numbers 80–84) to the
//! runtime's serving engines. Two dispatchers live here:
//!
//! - `ServingRelay` — **the kernel IPC path (TASK-11, DE-G6).** The
//!   kernel relays each AI syscall over the 2-channel IPC rendezvous as
//!   an `AiSyscallRequest`; the runtime service loop decodes it and
//!   calls `ServingRelay::dispatch`, which validates the session
//!   capability, opens a session in the
//!   [`SessionManager`](crate::serving::SessionManager), serves the
//!   request through the [`BackendRouter`](crate::provider::BackendRouter)
//!   (audited `*_with_ctx` path, TASK-10), closes the session, and
//!   returns an `AiSyscallResponse`.
//! - `AiIpcRelay` — the Sprint 11.a in-process path used by
//!   [`crate::orchestrator_bridge::OrchestratorBridge`] (agent intents →
//!   [`crate::inference::InferencePipeline`]). It is **not** the kernel
//!   IPC dispatcher.
//!
//! The wire types (`AiSyscallNumber`, `AiSyscallRequest`,
//! `AiSyscallResponse`) originated here (Sprint 11.a) and moved to
//! [`nexacore_types::ai`] in TASK-11 (ADR-0032) so the kernel and the Ring 3
//! service image — both `no_std` — share them; they are re-exported
//! here so existing paths keep compiling.
//!
//! ## Design notes
//!
//! - Neither relay panics on malformed input: every error path returns a
//!   structured error response so the kernel can surface `EINVAL` or
//!   `EIO` instead of crashing.
//! - `model_id_bytes` carries only 16 bytes because the kernel ABI uses
//!   a compact form. The relays zero-extend them to the 32-byte
//!   [`ModelId`][nexacore_types::ModelId] by placing the 16 bytes in the
//!   high half and zeroing the low half (`NCIP-Agent-Arch-022 §S9`).
//! - All dispatch calls are recorded at `tracing::info` level; the
//!   `ServingRelay` additionally produces one
//!   [`crate::audit::AuditRecord`] per request through the router's
//!   audited path (`/docs/04-security-model.md §Audit log`).

use std::{sync::Arc, time::Instant};

// Wire types — defined in `nexacore-types::ai` (no_std, postcard) since
// TASK-11 so kernel + Ring 3 service share them; re-exported for API
// stability.
pub use nexacore_types::ai::{
    AI_MAX_PAYLOAD, AiSyscallNumber, AiSyscallRequest, AiSyscallResponse,
};
use nexacore_types::{CapabilityId, ModelId};
use tracing::{debug, info, instrument, warn};

use crate::{
    inference::{InferencePipeline, InferenceRequest},
    provider::{
        BackendRouter, EmbeddingsRequest, GenerateRequest, ProviderError, RequestContext,
        Tier0Request,
    },
    serving::{ServingError, SessionCapability, SessionManager},
};

// =============================================================================
// AiIpcRelay
// =============================================================================

/// The IPC relay that routes AI syscalls to the [`InferencePipeline`].
///
/// `AiIpcRelay` holds an `Arc`-wrapped pipeline so it can be cloned across
/// async tasks without copying the registry state. Construct one relay per
/// system boot; all concurrent AI syscall IPC endpoints share the same relay
/// instance.
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
///     relay::{AiIpcRelay, AiSyscallNumber, AiSyscallRequest},
/// };
/// use nexacore_types::ModelId;
/// use tokio::sync::Mutex;
///
/// # #[tokio::main]
/// # async fn main() {
/// let sk = NexaCoreSigningKey::from_bytes([0x10; 32]);
/// let hash = [0xABu8; 32];
/// let manifest = ModelManifest {
///     model_id: ModelId::from_manifest_hash(hash),
///     name: "relay-doctest".into(),
///     version: "1.0.0".into(),
///     hash,
///     signature: sk.sign(&hash),
///     signing_key: sk.verifying_key(),
///     size_bytes: 0,
///     format: ModelFormat::Gguf,
/// };
///
/// let mut reg = ModelRegistry::new();
/// let id = reg.register(manifest).unwrap();
/// reg.load(id).unwrap();
///
/// let pipeline = InferencePipeline::new(Arc::new(Mutex::new(reg)));
/// let relay = AiIpcRelay::new(pipeline);
///
/// // Build a 16-byte compact model id (high half of the 32-byte id).
/// let mut compact = [0u8; 16];
/// compact.copy_from_slice(&hash[..16]);
///
/// let req = AiSyscallRequest {
///     syscall: AiSyscallNumber::Invoke,
///     model_id_bytes: compact,
///     capability: vec![0x01],
///     input_data: b"hello".to_vec(),
///     request_id: 1,
///     caller_pid: 1000,
/// };
///
/// let resp = relay.dispatch(req).await;
/// assert_eq!(resp.request_id, 1);
/// # }
/// ```
pub struct AiIpcRelay {
    /// Shared inference pipeline. Wrapped in `Arc` so multiple relay clones
    /// (one per IPC endpoint) share the same registry without copying.
    ///
    /// `Arc<InferencePipeline>` does not derive `Debug` automatically because
    /// the inner `Mutex<ModelRegistry>` does not expose its contents through
    /// `Debug`. We implement `Debug` manually to show just the pointer address.
    pipeline: Arc<InferencePipeline>,
}

impl std::fmt::Debug for AiIpcRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiIpcRelay")
            .field("pipeline", &Arc::as_ptr(&self.pipeline))
            .finish()
    }
}

impl AiIpcRelay {
    /// Create a new relay backed by `pipeline`.
    ///
    /// The pipeline is placed inside an `Arc` so the relay can be cheaply
    /// cloned for concurrent IPC endpoint handlers.
    ///
    /// ```rust
    /// use std::sync::Arc;
    ///
    /// use nexacore_runtime::{inference::InferencePipeline, model::ModelRegistry, relay::AiIpcRelay};
    /// use tokio::sync::Mutex;
    ///
    /// let reg = ModelRegistry::new();
    /// let pipeline = InferencePipeline::new(Arc::new(Mutex::new(reg)));
    /// let _relay = AiIpcRelay::new(pipeline);
    /// ```
    #[must_use]
    pub fn new(pipeline: InferencePipeline) -> Self {
        Self {
            pipeline: Arc::new(pipeline),
        }
    }

    /// Dispatch an incoming AI syscall request to the inference pipeline.
    ///
    /// The method:
    ///
    /// 1. Logs the incoming request at `info` level (audit trail).
    /// 2. Zero-extends `model_id_bytes` (16 bytes) to a 32-byte
    ///    [`ModelId`] by copying the compact bytes into the high half.
    /// 3. Builds an [`InferenceRequest`] and calls `pipeline.infer`.
    /// 4. Converts the [`crate::inference::InferenceResponse`] into an [`AiSyscallResponse`].
    /// 5. On any error, returns a structured error response (never panics).
    ///
    /// # Syscall routing
    ///
    /// All five AI syscall numbers are accepted. In Phase 2 the pipeline
    /// stub returns an empty output for every variant; future streams will
    /// specialise routing by `syscall` (e.g., stream chunking for
    /// [`AiSyscallNumber::Stream`], embedding vector format for
    /// [`AiSyscallNumber::Embed`]).
    #[instrument(skip(self), fields(
        syscall   = ?request.syscall,
        request_id = request.request_id,
        caller_pid = request.caller_pid,
    ))]
    pub async fn dispatch(&self, request: AiSyscallRequest) -> AiSyscallResponse {
        let start = Instant::now();
        let request_id = request.request_id;

        info!(
            syscall    = ?request.syscall,
            request_id = request.request_id,
            caller_pid = request.caller_pid,
            "AI IPC relay: dispatching syscall"
        );

        // Zero-extend the compact 16-byte model id to 32 bytes.
        // The high 16 bytes carry the model identifier; the low 16 bytes
        // are zeroed. This matches the compact form stored in the kernel's
        // model table (NCIP-Agent-Arch-022 §S9).
        let model_id = {
            let mut full = [0u8; 32];
            full[..16].copy_from_slice(&request.model_id_bytes);
            ModelId::from_bytes(full)
        };

        debug!(model_id = ?model_id, "relay: resolved model id");

        let infer_req = InferenceRequest {
            model_id,
            input: request.input_data,
            request_id,
        };

        match self.pipeline.infer(infer_req).await {
            Ok(resp) => {
                let latency_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

                info!(
                    request_id = resp.request_id,
                    latency_us,
                    output_bytes = resp.output.len(),
                    "AI IPC relay: dispatch succeeded"
                );

                AiSyscallResponse {
                    request_id: resp.request_id,
                    success: true,
                    output_data: resp.output,
                    latency_us,
                    error_message: None,
                }
            }
            Err(err) => {
                let latency_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

                warn!(
                    request_id,
                    error = %err,
                    "AI IPC relay: dispatch failed"
                );

                AiSyscallResponse::error(request_id, latency_us, err.to_string())
            }
        }
    }
}

// Clone is required so that multiple IPC endpoint handlers can each hold a
// relay handle without lifetime entanglement. The `Arc<InferencePipeline>`
// inside is cheap to clone.
impl Clone for AiIpcRelay {
    fn clone(&self) -> Self {
        Self {
            pipeline: Arc::clone(&self.pipeline),
        }
    }
}

// =============================================================================
// ServingRelay — the kernel IPC dispatch path (TASK-11, DE-G6)
// =============================================================================

/// Dispatches kernel-relayed AI syscalls through the serving stack.
///
/// Session lifecycle + capability gating run through the
/// [`SessionManager`]; inference runs through the [`BackendRouter`]'s
/// audited `*_with_ctx` path (TASK-10) — one
/// [`crate::audit::AuditRecord`] per request when the router carries an
/// audit sink.
///
/// This is what the runtime service loop calls for every
/// [`AiSyscallRequest`] arriving over the kernel's 2-channel IPC
/// rendezvous. It replaces the Sprint 11.b "tensor stub" plan: the
/// request is served by a real backend (the Ollama `RemoteGpu` provider,
/// TASK-09, or — once TASK-12 lands — the on-device `LocalCpu` engine),
/// selected per [`crate::provider::BackendPolicy`] with the TASK-10
/// health/failover semantics.
///
/// ## Per-syscall semantics (ADR-0032)
///
/// | Syscall | Served as |
/// |---------|-----------|
/// | `Invoke` | `BackendRouter::generate_with_ctx` (UTF-8 prompt → text) |
/// | `Stream` | as `Invoke` — single-shot until the provider trait grows a streaming method (ADR-0030 note); the kernel ABI returns one response either way |
/// | `Embed` | `BackendRouter::embeddings_with_ctx` (UTF-8 text → postcard-encoded `Vec<f32>`) |
/// | `Classify` / `Transcribe` | structured "not yet supported" error (no backend implements them in Phase 2) |
///
/// ## Error posture
///
/// Never panics: malformed capability, oversize payload, non-UTF-8
/// input, session errors, and provider errors all map to a structured
/// [`AiSyscallResponse::error`] the kernel turns into an errno. Every
/// request — accepted or rejected — leaves the session table how it
/// found it (open → close on all paths).
pub struct ServingRelay {
    /// Session lifecycle + capability gating (Sprint 11.a engine).
    /// Async-mutexed: dispatch holds it only for open/close, never
    /// across the provider await.
    sessions: tokio::sync::Mutex<SessionManager>,
    /// The TASK-08/09/10 backend router (shared with the health prober).
    router: Arc<BackendRouter>,
    /// Audit-timestamp source (ns since the Unix epoch). Injected: NexaCore
    /// time must come from the attestable clock service (workspace
    /// `disallowed_methods` bans wall-clock `now`), which does not exist
    /// yet — the default reports `0` and the service binary wires the
    /// real source when it lands. Recorded metadata only; no routing
    /// decision reads it.
    clock_ns: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl ServingRelay {
    /// Build a relay over a session manager and a backend router.
    ///
    /// The router is shared (`Arc`) so the service binary can also hand
    /// it to [`crate::provider::spawn_periodic_health_probe`]. Audit
    /// timestamps default to `0` until a clock source is injected via
    /// [`Self::with_clock`] (see the `clock_ns` field docs).
    #[must_use]
    pub fn new(sessions: SessionManager, router: Arc<BackendRouter>) -> Self {
        Self {
            sessions: tokio::sync::Mutex::new(sessions),
            router,
            clock_ns: Box::new(|| 0),
        }
    }

    /// Inject the audit-timestamp source (builder style). The service
    /// binary supplies the attestable clock here once it exists; tests
    /// supply a constant.
    #[must_use]
    pub fn with_clock(mut self, clock_ns: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock_ns = Box::new(clock_ns);
        self
    }

    /// Number of live sessions (test/diagnostic hook).
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.session_count()
    }

    /// Derive the 16-byte audit [`CapabilityId`] from the opaque
    /// capability bytes: the first 16 bytes of `BLAKE3(bytes)`. The
    /// audit log must identify *which* capability was used without
    /// storing the token itself.
    fn capability_audit_id(capability: &[u8]) -> CapabilityId {
        let digest = blake3::hash(capability);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        CapabilityId::from_bytes(id)
    }

    /// Dispatch one kernel-relayed AI syscall request.
    ///
    /// See the type-level docs for routing and error semantics. Always
    /// returns a response (never panics); `request_id` is echoed on
    /// every path.
    #[instrument(skip(self, request), fields(
        syscall    = ?request.syscall,
        request_id = request.request_id,
        caller_pid = request.caller_pid,
    ))]
    pub async fn dispatch(&self, request: AiSyscallRequest) -> AiSyscallResponse {
        let start = Instant::now();
        let rid = request.request_id;
        let elapsed_us = |s: &Instant| u64::try_from(s.elapsed().as_micros()).unwrap_or(u64::MAX);

        // ── 1. Bounds (defence in depth — the kernel enforces the same
        //       caps on its copy path; the counterpart is untrusted). ──
        if request.input_data.len() > AI_MAX_PAYLOAD {
            return AiSyscallResponse::error(
                rid,
                elapsed_us(&start),
                format!(
                    "input exceeds AI_MAX_PAYLOAD ({} > {AI_MAX_PAYLOAD})",
                    request.input_data.len()
                ),
            );
        }
        if request.capability.len() > SessionCapability::MAX_LEN {
            return AiSyscallResponse::error(
                rid,
                elapsed_us(&start),
                "capability exceeds maximum length",
            );
        }

        // ── 2. Capability gating (service-side, Sprint 11.a contract). ──
        let Ok(capability) = SessionCapability::new(request.capability.clone()) else {
            warn!(request_id = rid, "serving relay: capability rejected");
            return AiSyscallResponse::error(rid, elapsed_us(&start), "capability rejected");
        };

        // ── 3. Model id (compact 16-byte → 32-byte, high half). ──
        let model_id = {
            let mut full = [0u8; 32];
            full[..16].copy_from_slice(&request.model_id_bytes);
            ModelId::from_bytes(full)
        };

        // ── 4. Open the session (capability re-checked inside).
        //       The lock guard is scoped to the block so it drops before
        //       the provider await (clippy::significant_drop_in_scrutinee).
        let open_result = {
            let mut sessions = self.sessions.lock().await;
            sessions.open_session(model_id, capability.clone())
        };
        let session_id = match open_result {
            Ok(sid) => sid,
            Err(e) => {
                return AiSyscallResponse::error(
                    rid,
                    elapsed_us(&start),
                    format!("session open failed: {e}"),
                );
            }
        };

        // ── 5. Serve through the audited router path. ──
        let ctx = RequestContext {
            session_id,
            capability_id: Self::capability_audit_id(&request.capability),
            model_id,
            tier: 0,
            timestamp_ns: (self.clock_ns)(),
            // The relay has no tokenizer; token accounting lands with the
            // LocalCpu serving integration (TASK-12).
            input_token_count: 0,
        };
        let served = self.serve(&request, &ctx).await;

        // ── 6. Close the session on every path (lifecycle invariant). ──
        let close_result = {
            let mut sessions = self.sessions.lock().await;
            sessions.close_session(session_id, &capability)
        };
        if let Err(e) = close_result {
            // Closing a just-opened idle session can only fail if the
            // session vanished — log it, do not mask the serve outcome.
            warn!(request_id = rid, error = %e, "serving relay: close_session failed");
        }

        // ── 7. Shape the response. ──
        match served {
            Ok(output_data) if output_data.len() > AI_MAX_PAYLOAD => AiSyscallResponse::error(
                rid,
                elapsed_us(&start),
                format!(
                    "output exceeds AI_MAX_PAYLOAD ({} > {AI_MAX_PAYLOAD}); \
                     response chunking is a planned follow-up (ADR-0032)",
                    output_data.len()
                ),
            ),
            Ok(output_data) => {
                let latency_us = elapsed_us(&start);
                info!(
                    request_id = rid,
                    latency_us,
                    output_bytes = output_data.len(),
                    "serving relay: dispatch succeeded"
                );
                AiSyscallResponse {
                    request_id: rid,
                    success: true,
                    output_data,
                    latency_us,
                    error_message: None,
                }
            }
            Err(msg) => {
                warn!(request_id = rid, error = %msg, "serving relay: dispatch failed");
                AiSyscallResponse::error(rid, elapsed_us(&start), msg)
            }
        }
    }

    /// Route the request to the backend router per syscall kind.
    /// Returns the raw output bytes or a human-readable error (no
    /// caller content in error strings).
    async fn serve(
        &self,
        request: &AiSyscallRequest,
        ctx: &RequestContext,
    ) -> Result<Vec<u8>, String> {
        use nexacore_types::identity::IdHex;

        let utf8_input = || {
            core::str::from_utf8(&request.input_data)
                .map_err(|_| "input is not valid UTF-8".to_owned())
        };

        match request.syscall {
            AiSyscallNumber::Invoke | AiSyscallNumber::Stream => {
                let prompt = utf8_input()?.to_owned();
                let req = Tier0Request::new(GenerateRequest {
                    model: ctx.model_id.to_hex(),
                    prompt,
                    max_tokens: 0,
                });
                let routed = self
                    .router
                    .generate_with_ctx(&req, ctx)
                    .await
                    .map_err(|e: ProviderError| e.to_string())?;
                debug!(
                    backend = routed.backend_used.label(),
                    "serving relay: generate served"
                );
                Ok(routed.value.text.into_bytes())
            }
            AiSyscallNumber::Embed => {
                let input = utf8_input()?.to_owned();
                let req = Tier0Request::new(EmbeddingsRequest {
                    model: ctx.model_id.to_hex(),
                    input,
                });
                let routed = self
                    .router
                    .embeddings_with_ctx(&req, ctx)
                    .await
                    .map_err(|e: ProviderError| e.to_string())?;
                nexacore_types::wire::encode_canonical(&routed.value.embedding)
                    .map_err(|e| format!("embedding encode failed: {e}"))
            }
            AiSyscallNumber::Classify | AiSyscallNumber::Transcribe => Err(format!(
                "{:?} is not yet supported (no Phase 2 backend implements it)",
                request.syscall
            )),
        }
    }
}

impl std::fmt::Debug for ServingRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServingRelay").finish_non_exhaustive()
    }
}

// `ServingError` is surfaced through `Display` in dispatch; this import
// keeps the error-mapping sites honest if the enum grows.
const _: fn(ServingError) -> String = |e| e.to_string();

// =============================================================================
// IntentDispatcher — the seam between the bridge and the dispatch path
// =============================================================================

/// Anything that can serve an [`AiSyscallRequest`] and produce an
/// [`AiSyscallResponse`] (TASK-13 / ADR-0035 D1).
///
/// Both dispatchers in this module implement it with identical
/// signatures, which lets
/// [`OrchestratorBridge`](crate::orchestrator_bridge::OrchestratorBridge)
/// be generic over the path:
///
/// - [`AiIpcRelay`] — the Sprint 11.a in-process pipeline (its `infer`
///   body is still the tensor stub; kept for back-compat and its tests);
/// - [`ServingRelay`] — the REAL path: session gating →
///   [`BackendRouter`] audited dispatch (`backend_used` lands in the
///   [`crate::audit::AuditRecord`]).
///
/// Agent-facing code (nexacore-sdk's `BridgeLink`) instantiates the bridge
/// over `ServingRelay`, so a user prompt traverses agent → bridge →
/// serving → provider for real.
#[async_trait::async_trait]
pub trait IntentDispatcher: Send + Sync {
    /// Serve one request, never panicking: every failure mode maps to a
    /// structured error response.
    async fn dispatch(&self, request: AiSyscallRequest) -> AiSyscallResponse;
}

#[async_trait::async_trait]
impl IntentDispatcher for AiIpcRelay {
    async fn dispatch(&self, request: AiSyscallRequest) -> AiSyscallResponse {
        // Delegate to the inherent method (kept callable directly).
        Self::dispatch(self, request).await
    }
}

#[async_trait::async_trait]
impl IntentDispatcher for ServingRelay {
    async fn dispatch(&self, request: AiSyscallRequest) -> AiSyscallResponse {
        // Delegate to the inherent method (kept callable directly).
        Self::dispatch(self, request).await
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
    };

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    fn make_relay_with_loaded_model(seed: u8, hash_byte: u8) -> (AiIpcRelay, [u8; 16]) {
        let sk = NexaCoreSigningKey::from_bytes([seed; 32]);
        // Use a hash whose bytes 16..32 are zero so the compact 16-byte
        // form round-trips through the relay's zero-extension correctly.
        let mut hash = [0u8; 32];
        hash[..16].fill(hash_byte);
        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(hash),
            name: "relay-test-model".into(),
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

        let mut compact = [0u8; 16];
        compact.fill(hash_byte);
        (relay, compact)
    }

    fn make_request(
        compact: [u8; 16],
        syscall: AiSyscallNumber,
        request_id: u64,
    ) -> AiSyscallRequest {
        AiSyscallRequest {
            syscall,
            model_id_bytes: compact,
            capability: vec![0x01],
            input_data: b"test input".to_vec(),
            request_id,
            caller_pid: 42,
        }
    }

    // -------------------------------------------------------------------------
    // AiSyscallNumber
    // -------------------------------------------------------------------------

    #[test]
    fn syscall_numbers_match_kernel_abi() {
        assert_eq!(AiSyscallNumber::Invoke.as_u32(), 80);
        assert_eq!(AiSyscallNumber::Stream.as_u32(), 81);
        assert_eq!(AiSyscallNumber::Embed.as_u32(), 82);
        assert_eq!(AiSyscallNumber::Classify.as_u32(), 83);
        assert_eq!(AiSyscallNumber::Transcribe.as_u32(), 84);
    }

    #[test]
    fn from_u32_round_trips_all_variants() {
        for n in 80u32..=84 {
            let variant = AiSyscallNumber::from_u32(n).unwrap();
            assert_eq!(variant.as_u32(), n);
        }
    }

    #[test]
    fn from_u32_rejects_out_of_range() {
        assert!(AiSyscallNumber::from_u32(0).is_none());
        assert!(AiSyscallNumber::from_u32(79).is_none());
        assert!(AiSyscallNumber::from_u32(85).is_none());
        assert!(AiSyscallNumber::from_u32(u32::MAX).is_none());
    }

    // -------------------------------------------------------------------------
    // AiSyscallResponse helpers
    // -------------------------------------------------------------------------

    #[test]
    fn error_response_has_correct_fields() {
        let resp = AiSyscallResponse::error(99, 500, "something went wrong");
        assert_eq!(resp.request_id, 99);
        assert!(!resp.success);
        assert!(resp.output_data.is_empty());
        assert_eq!(resp.latency_us, 500);
        assert_eq!(resp.error_message.as_deref(), Some("something went wrong"));
    }

    // -------------------------------------------------------------------------
    // AiIpcRelay — dispatch (loaded model)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn dispatch_loaded_model_succeeds() {
        let (relay, compact) = make_relay_with_loaded_model(0x10, 0xAA);
        let req = make_request(compact, AiSyscallNumber::Invoke, 1);
        let resp = relay.dispatch(req).await;
        assert!(resp.success);
        assert_eq!(resp.request_id, 1);
        assert!(resp.error_message.is_none());
    }

    #[tokio::test]
    async fn dispatch_echoes_request_id() {
        let (relay, compact) = make_relay_with_loaded_model(0x11, 0xBB);
        for rid in [0u64, 1, 42, u64::MAX - 1] {
            let req = make_request(compact, AiSyscallNumber::Embed, rid);
            let resp = relay.dispatch(req).await;
            assert_eq!(resp.request_id, rid);
        }
    }

    #[tokio::test]
    async fn dispatch_unregistered_model_returns_error_response() {
        // Build a relay with an empty registry — no model loaded.
        let empty_reg = ModelRegistry::new();
        let pipeline = InferencePipeline::new(Arc::new(Mutex::new(empty_reg)));
        let relay = AiIpcRelay::new(pipeline);

        let syscall_req = AiSyscallRequest {
            syscall: AiSyscallNumber::Invoke,
            model_id_bytes: [0xFF; 16],
            capability: vec![0x01],
            input_data: vec![],
            request_id: 7,
            caller_pid: 1,
        };
        let resp = relay.dispatch(syscall_req).await;
        assert!(!resp.success);
        assert_eq!(resp.request_id, 7);
        assert!(resp.error_message.is_some());
        assert!(resp.output_data.is_empty());
    }

    #[tokio::test]
    async fn dispatch_all_syscall_variants_accepted() {
        let (relay, compact) = make_relay_with_loaded_model(0x12, 0xCC);
        let variants = [
            AiSyscallNumber::Invoke,
            AiSyscallNumber::Stream,
            AiSyscallNumber::Embed,
            AiSyscallNumber::Classify,
            AiSyscallNumber::Transcribe,
        ];
        for (i, variant) in variants.iter().enumerate() {
            let req = make_request(compact, *variant, i as u64 + 100);
            let resp = relay.dispatch(req).await;
            // All variants route to the same stub pipeline — success for all.
            assert!(resp.success, "expected success for {variant:?}");
        }
    }

    #[tokio::test]
    async fn dispatch_records_latency() {
        let (relay, compact) = make_relay_with_loaded_model(0x13, 0xDD);
        let req = make_request(compact, AiSyscallNumber::Invoke, 200);
        let resp = relay.dispatch(req).await;
        // latency_us is a u64 and always >= 0; verify it was populated.
        let _ = resp.latency_us;
        assert!(resp.success);
    }

    #[tokio::test]
    async fn relay_can_be_cloned_and_used_concurrently() {
        let (relay, compact) = make_relay_with_loaded_model(0x14, 0xEE);
        let relay2 = relay.clone();

        let req1 = make_request(compact, AiSyscallNumber::Invoke, 300);
        let req2 = make_request(compact, AiSyscallNumber::Classify, 301);

        let (r1, r2) = tokio::join!(relay.dispatch(req1), relay2.dispatch(req2));
        assert!(r1.success);
        assert!(r2.success);
        assert_eq!(r1.request_id, 300);
        assert_eq!(r2.request_id, 301);
    }

    #[test]
    fn model_id_zero_extension_is_deterministic() {
        // Verify that the same compact bytes always produce the same ModelId.
        let compact: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let mut full1 = [0u8; 32];
        let mut full2 = [0u8; 32];
        full1[..16].copy_from_slice(&compact);
        full2[..16].copy_from_slice(&compact);
        assert_eq!(ModelId::from_bytes(full1), ModelId::from_bytes(full2));
        // Low half must be zero.
        assert_eq!(&full1[16..], &[0u8; 16]);
    }

    // =========================================================================
    // ServingRelay — the kernel IPC dispatch path (TASK-11)
    // =========================================================================

    use crate::{
        provider::{BackendKind, BackendPolicy, BackendRouter, MockInferenceProvider},
        serving::BatchConfig,
    };

    fn small_batch_config() -> BatchConfig {
        BatchConfig {
            max_batch_size: 4,
            max_queue_size: 16,
            preemption_enabled: false,
            max_total_tokens: 512,
        }
    }

    /// A ServingRelay whose RemoteGpu mock answers `generate` with `text`.
    fn serving_relay_with_gpu_text(text: &'static str) -> ServingRelay {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate().returning(move |_| {
            Ok(crate::provider::GenerateResponse {
                text: text.to_owned(),
                tokens: 2,
            })
        });
        let router = Arc::new(
            BackendRouter::new(BackendPolicy::PreferRemoteGpu).with_remote_gpu(Box::new(gpu)),
        );
        ServingRelay::new(SessionManager::new(small_batch_config()), router)
    }

    fn serving_request(syscall: AiSyscallNumber, capability: Vec<u8>) -> AiSyscallRequest {
        AiSyscallRequest {
            syscall,
            model_id_bytes: [0x42; 16],
            capability,
            input_data: b"what is 2+2?".to_vec(),
            request_id: 9,
            caller_pid: 1234,
        }
    }

    #[tokio::test]
    async fn serving_relay_invoke_serves_via_router_and_closes_session() {
        let relay = serving_relay_with_gpu_text("4");
        let resp = relay
            .dispatch(serving_request(AiSyscallNumber::Invoke, vec![0x01]))
            .await;
        assert!(resp.success, "{:?}", resp.error_message);
        assert_eq!(resp.request_id, 9);
        assert_eq!(resp.output_data, b"4");
        // Session lifecycle invariant: opened then closed inside dispatch.
        assert_eq!(relay.session_count().await, 0);
    }

    #[tokio::test]
    async fn serving_relay_stream_is_single_shot_like_invoke() {
        let relay = serving_relay_with_gpu_text("streamed");
        let resp = relay
            .dispatch(serving_request(AiSyscallNumber::Stream, vec![0x01]))
            .await;
        assert!(resp.success);
        assert_eq!(resp.output_data, b"streamed");
    }

    #[tokio::test]
    async fn serving_relay_embed_returns_postcard_vector() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_embeddings().returning(|_| {
            Ok(crate::provider::EmbeddingsResponse {
                embedding: vec![0.5, -1.0],
            })
        });
        let router = Arc::new(
            BackendRouter::new(BackendPolicy::PreferRemoteGpu).with_remote_gpu(Box::new(gpu)),
        );
        let relay = ServingRelay::new(SessionManager::new(small_batch_config()), router);

        let resp = relay
            .dispatch(serving_request(AiSyscallNumber::Embed, vec![0x01]))
            .await;
        assert!(resp.success, "{:?}", resp.error_message);
        let decoded: Vec<f32> =
            nexacore_types::wire::decode_canonical(&resp.output_data).expect("postcard vector");
        assert_eq!(decoded, vec![0.5, -1.0]);
    }

    #[tokio::test]
    async fn serving_relay_rejects_missing_capability() {
        // Empty capability bytes = "chiamante senza capability" → clean
        // structured error, no session leaked.
        let relay = serving_relay_with_gpu_text("never");
        let resp = relay
            .dispatch(serving_request(AiSyscallNumber::Invoke, vec![]))
            .await;
        assert!(!resp.success);
        assert!(
            resp.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("capability"),
            "{:?}",
            resp.error_message
        );
        assert_eq!(relay.session_count().await, 0);
    }

    #[tokio::test]
    async fn serving_relay_rejects_malformed_capability_zero_first_byte() {
        let relay = serving_relay_with_gpu_text("never");
        let resp = relay
            .dispatch(serving_request(AiSyscallNumber::Invoke, vec![0x00, 0x01]))
            .await;
        assert!(!resp.success);
    }

    #[tokio::test]
    async fn serving_relay_rejects_oversized_input_cleanly() {
        let relay = serving_relay_with_gpu_text("never");
        let mut req = serving_request(AiSyscallNumber::Invoke, vec![0x01]);
        req.input_data = vec![b'x'; AI_MAX_PAYLOAD + 1];
        let resp = relay.dispatch(req).await;
        assert!(!resp.success);
        assert!(
            resp.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("AI_MAX_PAYLOAD"),
            "{:?}",
            resp.error_message
        );
    }

    #[tokio::test]
    async fn serving_relay_rejects_invalid_utf8_input() {
        let relay = serving_relay_with_gpu_text("never");
        let mut req = serving_request(AiSyscallNumber::Invoke, vec![0x01]);
        req.input_data = vec![0xFF, 0xFE, 0xFD];
        let resp = relay.dispatch(req).await;
        assert!(!resp.success);
        assert!(
            resp.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("UTF-8")
        );
    }

    #[tokio::test]
    async fn serving_relay_classify_and_transcribe_are_structured_errors() {
        let relay = serving_relay_with_gpu_text("never");
        for syscall in [AiSyscallNumber::Classify, AiSyscallNumber::Transcribe] {
            let resp = relay.dispatch(serving_request(syscall, vec![0x01])).await;
            assert!(!resp.success, "{syscall:?} must be a structured error");
            assert!(resp.error_message.is_some());
            assert_eq!(relay.session_count().await, 0);
        }
    }

    #[tokio::test]
    async fn serving_relay_provider_failure_is_structured_error() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate()
            .returning(|_| Err(crate::provider::ProviderError::Unavailable("down".into())));
        let router = Arc::new(
            BackendRouter::new(BackendPolicy::RemoteGpuOnly).with_remote_gpu(Box::new(gpu)),
        );
        let relay = ServingRelay::new(SessionManager::new(small_batch_config()), router);
        let resp = relay
            .dispatch(serving_request(AiSyscallNumber::Invoke, vec![0x01]))
            .await;
        assert!(!resp.success);
        assert_eq!(relay.session_count().await, 0, "session closed on failure");
    }

    #[tokio::test]
    async fn serving_relay_writes_one_audit_record_with_backend_used() {
        // Wire an audit sink through the router: dispatch must produce
        // exactly ONE AuditRecord, attributed to the serving backend.
        let log = Arc::new(parking_lot::Mutex::new(
            crate::audit::InMemoryAuditLog::new(),
        ));
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate().returning(|_| {
            Ok(crate::provider::GenerateResponse {
                text: "ok".to_owned(),
                tokens: 1,
            })
        });
        let router = Arc::new(
            BackendRouter::new(BackendPolicy::PreferRemoteGpu)
                .with_remote_gpu(Box::new(gpu))
                .with_audit(log.clone()),
        );
        let relay = ServingRelay::new(SessionManager::new(small_batch_config()), router);

        let resp = relay
            .dispatch(serving_request(AiSyscallNumber::Invoke, vec![0x01]))
            .await;
        assert!(resp.success);

        let rec = {
            use crate::audit::AuditLog;
            let guard = log.lock();
            assert_eq!(guard.count(), 1, "exactly one audit record per request");
            guard.iter().next().expect("one record").clone()
        };
        assert_eq!(rec.backend_used, Some(BackendKind::RemoteGpu));
        assert_eq!(rec.tier, 0);
    }
}

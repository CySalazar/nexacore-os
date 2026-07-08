//! Provider-agnostic inference abstraction — TASK-08 (DE-G1).
//!
//! This module defines the seam between *what* the runtime wants
//! (generate / chat / embeddings) and *where* it runs (a remote GPU box
//! speaking some HTTP API, or the on-device CPU engine). Three pieces:
//!
//! 1. `InferenceProvider` — the async trait every backend implements.
//! 2. `BackendKind` — the closed set of backends (`BackendKind::RemoteGpu`,
//!    `BackendKind::LocalCpu`).
//! 3. `BackendRouter` — selects a backend per `BackendPolicy` and
//!    dispatches a request, falling back deterministically when a backend
//!    is unavailable.
//!
//! ## Scope
//!
//! TASK-08 delivered the abstraction + router; TASK-09 the `RemoteGpu`
//! Ollama client (`ollama`); TASK-10 made the router *resilient*
//! (ADR-0031): persistent per-backend health with anti-flap hysteresis
//! (`health`), health-aware dispatch ordering (unhealthy backends are
//! demoted to last resort), a periodic probe hook
//! (`BackendRouter::probe_health_once` /
//! `spawn_periodic_health_probe`), [`nexacore_types::ai::BackendStatusEvent`]
//! emission on every health transition (consumed by the TASK-21 status
//! bar), and per-request `backend_used` + latency auditing through
//! [`crate::audit::AuditSink`] (the `*_with_ctx` dispatch methods).
//!
//! ## Relationship to the [`crate::router`] tier router
//!
//! The [`crate::router::TierRouter`] decides the **execution tier**
//! (NCIP-021 §S2.1) — Phase 2 is Tier-0-only (local node). The
//! `BackendRouter` is *orthogonal* and operates **inside Tier 0**: once
//! the tier router has decided a request stays local, the backend router
//! picks *how* to serve it locally (the user-owned LAN GPU, or the CPU
//! fallback on the device itself — both under the user's control, both
//! Tier 0). To make that boundary a compiler-enforced invariant rather
//! than a convention, `BackendRouter` accepts only a `Tier0Request`;
//! a `Tier1Request` is a distinct type that cannot reach it (see the
//! `tests/compile_fail` trybuild fixture).
//!
//! ## Wire types
//!
//! The request/response types are `serde`-serializable and round-trip
//! under the canonical postcard encoding (`NCIP-Serde-004`,
//! [`nexacore_types::wire`]). They are the payloads the runtime/IPC layer
//! moves between the AI syscall path and the runtime service (TASK-11).
//!
//! ## Security posture
//!
//! - No `unsafe`.
//! - All errors are typed (`ProviderError`); no panics on the request
//!   path.
//! - The trait is `Send + Sync` so providers can be shared across the
//!   async runtime's worker threads.

// Audit anchor (test-only): `mockall::automock` on `InferenceProvider`
// below generates a `MockInferenceProvider` whose expectation store uses
// `std::sync::Mutex`, which the workspace `disallowed_methods` lint flags
// (it prefers `parking_lot`/`tokio` mutexes — see `clippy.toml`). That
// generated code is test-only and not under our control, so the allow is
// scoped to `cfg(test)` builds of THIS module only. Our own code in this
// module uses no disallowed method (audited); production builds compile
// without the mock and without this allow.
#![cfg_attr(test, allow(clippy::disallowed_methods))]

use std::sync::Arc;

use async_trait::async_trait;
use nexacore_types::{CapabilityId, ModelId, SessionId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::audit::{AuditRecord, AuditSink, AuditStatus};

pub mod health;
pub mod local_cpu;
pub mod ollama;

use health::{BackendStatusSink, HealthPolicy, HealthRegistry, TracingStatusSink};
// =============================================================================
// BackendKind
// =============================================================================

// `BackendKind` originated here (TASK-08) and moved to `nexacore-types::ai`
// in TASK-10 (ADR-0031) because the backend-status event that carries it
// crosses the IPC boundary to the UI. Re-exported so every existing
// `crate::provider::BackendKind` path keeps working; the variant order
// (and therefore the postcard encoding) is unchanged.
pub use nexacore_types::ai::BackendKind;

// =============================================================================
// Wire types — request/response payloads (postcard-canonical, NCIP-Serde-004)
// =============================================================================

/// One turn in a chat transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Role of the speaker (`"system"`, `"user"`, `"assistant"`). Kept a
    /// free-form `String` rather than an enum so a backend's roles that
    /// NexaCore does not model yet round-trip without loss.
    pub role: String,
    /// The message text.
    pub content: String,
}

/// A text-completion request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateRequest {
    /// Backend-specific model name (e.g. `"gemma4:latest"`). The router
    /// does not interpret it; it is forwarded to the chosen provider.
    pub model: String,
    /// The prompt to complete.
    pub prompt: String,
    /// Upper bound on generated tokens. `0` means "provider default".
    pub max_tokens: u32,
}

/// A text-completion response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateResponse {
    /// The generated completion text.
    pub text: String,
    /// Number of tokens the provider reports it generated (`0` if the
    /// provider does not report it).
    pub tokens: u32,
}

/// A multi-turn chat request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Backend-specific model name.
    pub model: String,
    /// Ordered transcript; the last entry is typically the new user turn.
    pub messages: Vec<ChatMessage>,
}

/// A chat response (a single assistant turn).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatResponse {
    /// The assistant's reply.
    pub message: ChatMessage,
    /// Tokens generated (`0` if unreported).
    pub tokens: u32,
}

/// An embeddings request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    /// Backend-specific embedding-model name.
    pub model: String,
    /// The text to embed.
    pub input: String,
}

/// An embeddings response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingsResponse {
    /// The embedding vector. `f32` matches the precision every embedding
    /// backend emits; the runtime does not re-quantise it.
    pub embedding: Vec<f32>,
}

/// A backend's self-reported health.
///
/// Returned by [`InferenceProvider::health`]. In TASK-08 the router does
/// not poll this on a timer (that is TASK-10); it is the typed hook those
/// later tasks consume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    /// `true` when the backend believes it can serve requests now.
    pub healthy: bool,
    /// Human-readable detail (e.g. `"ok"`, `"connection refused"`). Kept
    /// short; it is for logs, not control flow.
    pub detail: String,
}

impl HealthStatus {
    /// A healthy status with the canonical `"ok"` detail.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            healthy: true,
            detail: "ok".to_owned(),
        }
    }

    /// An unhealthy status carrying `detail`.
    #[must_use]
    pub fn unhealthy(detail: impl Into<String>) -> Self {
        Self {
            healthy: false,
            detail: detail.into(),
        }
    }
}

// =============================================================================
// ProviderError
// =============================================================================

/// Errors a provider (or the router) can return on the request path.
///
/// The distinction that drives router behaviour is
/// [`ProviderError::is_retriable`]: a *retriable* error (the backend is
/// down / unreachable) makes the router fall through to the next backend
/// in policy order, whereas a *terminal* error (the request itself is
/// bad, or the backend rejected it) stops the cascade and propagates —
/// retrying a malformed request on the CPU would just fail again.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ProviderError {
    /// The backend is unreachable / not running. **Retriable**: the
    /// router falls through to the next backend.
    #[error("backend unavailable: {0}")]
    Unavailable(String),

    /// A network/transport failure mid-request. **Retriable**.
    #[error("transport error: {0}")]
    Transport(String),

    /// The backend accepted the connection but returned an error for this
    /// request (bad model name, server-side failure, malformed response).
    /// **Terminal**: not retried on another backend.
    #[error("backend error: {0}")]
    Backend(String),

    /// The request was rejected before dispatch (e.g. empty model name).
    /// **Terminal**.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Every backend permitted by the policy was tried and each failed
    /// (or none were registered). Carries the count tried so the caller
    /// can distinguish "no backend configured" (`0`) from "all down".
    #[error("all {tried} permitted backend(s) failed; last error: {last}")]
    AllBackendsFailed {
        /// How many backends the router attempted.
        tried: usize,
        /// The last underlying error encountered (stringified).
        last: String,
    },
}

impl ProviderError {
    /// Whether the router should fall through to the next backend on this
    /// error. Only connectivity-class errors are retriable; a bad request
    /// or a backend-level rejection is terminal.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        matches!(self, Self::Unavailable(_) | Self::Transport(_))
    }
}

// =============================================================================
// InferenceProvider
// =============================================================================

/// A backend that can serve inference requests.
///
/// Implemented by the remote-GPU client (TASK-09) and the local-CPU
/// engine (TASK-12); mocked in tests via `mockall`. All methods are
/// `async` (the real backends do network / heavy-compute I/O) and take
/// the request by reference so the [`BackendRouter`] can hand the *same*
/// request to a fallback backend without cloning.
///
/// Implementors MUST be `Send + Sync` (the router shares them across the
/// async runtime).
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait InferenceProvider: Send + Sync {
    /// Which backend this provider is. Used by the router for ordering
    /// and by the audit log (`backend_used`, TASK-10).
    fn kind(&self) -> BackendKind;

    /// Run a text completion.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`]; connectivity-class variants are
    /// retriable (see [`ProviderError::is_retriable`]).
    async fn generate(&self, req: &GenerateRequest) -> Result<GenerateResponse, ProviderError>;

    /// Run a multi-turn chat completion.
    ///
    /// # Errors
    ///
    /// As [`InferenceProvider::generate`].
    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError>;

    /// Compute an embedding vector.
    ///
    /// # Errors
    ///
    /// As [`InferenceProvider::generate`].
    async fn embeddings(
        &self,
        req: &EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, ProviderError>;

    /// Report the backend's current health. Never fails — an unreachable
    /// backend returns `healthy: false`, not an error.
    async fn health(&self) -> HealthStatus;
}

// =============================================================================
// Tier-0 typestate — the compiler-enforced "router is Tier-0-only" boundary
// =============================================================================

/// A request that the tier router has already confined to Tier 0
/// (local-node execution). This is the **only** wrapper the
/// [`BackendRouter`] accepts.
///
/// Making the backend router generic over `Tier0Request<T>` (rather than
/// a bare `T`) turns "the backend router only handles Tier-0 traffic"
/// from a comment into a type error: a [`Tier1Request`] is a distinct
/// type with no conversion into `Tier0Request`, so it cannot be passed
/// to the router (the `tests/compile_fail` fixture pins this).
///
/// TASK-08 keeps the constructor public so the router can be unit-tested
/// in isolation; once the tier router is wired (TASK-11) the intent is
/// that `Tier0Request` is produced only from a
/// [`crate::router::TierDecision`] of [`crate::router::ExecutionTier::Local`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tier0Request<T> {
    inner: T,
}

impl<T> Tier0Request<T> {
    /// Wrap `inner` as a Tier-0-confined request.
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped request.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Unwrap to the inner request.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// A request bound for Tier 1+ (a personal cluster / mesh / cloud).
///
/// Off the local node, and deliberately a **distinct type** from
/// [`Tier0Request`] with no conversion between them, so it can never be
/// handed to the Tier-0-only [`BackendRouter`].
///
/// Phase 2 does not dispatch Tier 1+; this type exists so the boundary is
/// expressible and compiler-checked today (the trybuild compile-fail
/// fixture passes a `Tier1Request` to the router and asserts it does not
/// build).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tier1Request<T> {
    inner: T,
}

impl<T> Tier1Request<T> {
    /// Wrap `inner` as a Tier-1+ request.
    #[must_use]
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped request.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

// =============================================================================
// BackendPolicy
// =============================================================================

/// Which backends the [`BackendRouter`] may use, and in what order.
///
/// The order is **deterministic** (no clock, no randomness) so routing
/// decisions are reproducible and testable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BackendPolicy {
    /// Try [`BackendKind::RemoteGpu`] first, fall back to
    /// [`BackendKind::LocalCpu`]. The default: the GPU is faster when up,
    /// the CPU guarantees availability.
    #[default]
    PreferRemoteGpu,
    /// Use only [`BackendKind::RemoteGpu`]; never fall back to CPU. For
    /// callers that require GPU-class latency and would rather fail than
    /// run degraded on CPU.
    RemoteGpuOnly,
    /// Use only [`BackendKind::LocalCpu`]; never touch the network. The
    /// strictest-privacy / offline mode.
    LocalCpuOnly,
}

impl BackendPolicy {
    /// The deterministic backend order this policy implies, most
    /// preferred first.
    #[must_use]
    pub fn order(self) -> &'static [BackendKind] {
        match self {
            Self::PreferRemoteGpu => &[BackendKind::RemoteGpu, BackendKind::LocalCpu],
            Self::RemoteGpuOnly => &[BackendKind::RemoteGpu],
            Self::LocalCpuOnly => &[BackendKind::LocalCpu],
        }
    }
}

// =============================================================================
// RequestContext / Routed — audit plumbing (TASK-10, DE-G5)
// =============================================================================

/// Caller-supplied audit context for one inference request.
///
/// The serving layer (TASK-11) owns the session/capability/model
/// identities and the clock; the router owns the dispatch outcome
/// (`backend_used`, latency, status). The `*_with_ctx` methods join the
/// two into exactly one [`AuditRecord`] per request.
///
/// Carries **metadata only** — deliberately no prompt, no message
/// content, no PII (the audit schema's contract).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    /// Session this request belongs to.
    pub session_id: SessionId,
    /// Capability token that authorised the request.
    pub capability_id: CapabilityId,
    /// Content-addressed model identifier.
    pub model_id: ModelId,
    /// Execution tier (Phase 2: always 0 — the router is Tier-0-only).
    pub tier: u8,
    /// Wall-clock timestamp of the invocation (ns since Unix epoch),
    /// supplied by the caller so the router itself stays clock-free.
    pub timestamp_ns: u64,
    /// Token count of the (pre-processed, PII-stripped) input.
    pub input_token_count: u32,
}

/// A successful dispatch outcome plus its backend attribution.
///
/// Returned by the `*_with_ctx` methods so callers (and the UI) can see
/// *where* the response came from without re-deriving it from the audit
/// log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Routed<T> {
    /// The backend's response.
    pub value: T,
    /// Which backend served it.
    pub backend_used: BackendKind,
}

// =============================================================================
// BackendRouter
// =============================================================================

/// Selects a backend per [`BackendPolicy`] and dispatches a
/// [`Tier0Request`], falling back deterministically when a backend is
/// unavailable.
///
/// ## Failover (TASK-08 + TASK-10)
///
/// For each request the router computes [`Self::dispatch_order`]: the
/// policy-permitted, registered backends, **healthy first** (per the
/// [`health::HealthRegistry`]), unhealthy ones demoted to last resort —
/// never dropped, so a request still has a chance when *everything*
/// looks down (availability over freshness, ADR-0031). It then walks
/// that order: on a **retriable** error
/// ([`ProviderError::is_retriable`]) it falls through to the next
/// backend; on a **terminal** error it stops and propagates; on success
/// it returns immediately. If every backend fails retriably (or none
/// are registered), it returns [`ProviderError::AllBackendsFailed`].
///
/// ## Health evidence (TASK-10, ADR-0031)
///
/// Two sources feed the same hysteresis trackers:
///
/// - **per-request outcomes** — every attempt's success / retriable
///   failure is an observation (terminal errors are health-*neutral*:
///   the backend answered, so connectivity is proven, but the answer
///   was a rejection — neither up-evidence nor down-evidence);
/// - **periodic probes** — [`Self::probe_health_once`] runs each
///   registered backend's [`InferenceProvider::health`] (the Ollama
///   provider maps this to `GET /api/tags`). While a backend is demoted
///   it receives no requests, so the probe is the **only** recovery
///   path: drive it from a timer ([`spawn_periodic_health_probe`]).
///
/// Health transitions emit one [`nexacore_types::ai::BackendStatusEvent`]
/// each, through the sink configured via [`Self::with_health`].
///
/// ## Audit (TASK-10, DE-G5)
///
/// The `*_with_ctx` methods record exactly one [`AuditRecord`] per
/// request — `backend_used`, latency, status — through the
/// [`AuditSink`] configured via [`Self::with_audit`]. The context-free
/// methods ([`Self::generate`] etc.) still feed health but do not
/// audit: they exist for callers that have no session identity (tests,
/// probes); the serving path (TASK-11) goes through `*_with_ctx`.
pub struct BackendRouter {
    remote_gpu: Option<Box<dyn InferenceProvider>>,
    local_cpu: Option<Box<dyn InferenceProvider>>,
    policy: BackendPolicy,
    health: HealthRegistry,
    audit: Option<Arc<dyn AuditSink>>,
    /// Degraded flags `(RemoteGpu, LocalCpu)` — kept here so
    /// [`Self::with_health`] can re-apply them when it replaces the
    /// registry (they are provider properties, not health state).
    degraded_flags: (bool, bool),
}

impl BackendRouter {
    /// A router with no backends registered and the given `policy`.
    /// Register backends with [`Self::with_remote_gpu`] /
    /// [`Self::with_local_cpu`]; health starts with
    /// [`HealthPolicy::default`] thresholds and a [`TracingStatusSink`]
    /// (override with [`Self::with_health`]); auditing is off until
    /// [`Self::with_audit`].
    #[must_use]
    pub fn new(policy: BackendPolicy) -> Self {
        Self {
            remote_gpu: None,
            local_cpu: None,
            policy,
            health: HealthRegistry::new(HealthPolicy::default(), Box::new(TracingStatusSink)),
            audit: None,
            degraded_flags: (false, false),
        }
    }

    /// Register the [`BackendKind::RemoteGpu`] provider (builder style).
    #[must_use]
    pub fn with_remote_gpu(mut self, provider: Box<dyn InferenceProvider>) -> Self {
        self.remote_gpu = Some(provider);
        self
    }

    /// Register the [`BackendKind::LocalCpu`] provider (builder style).
    #[must_use]
    pub fn with_local_cpu(mut self, provider: Box<dyn InferenceProvider>) -> Self {
        self.local_cpu = Some(provider);
        self
    }

    /// Replace the health configuration: hysteresis thresholds + the
    /// sink that receives [`nexacore_types::ai::BackendStatusEvent`]s
    /// (builder style). One method for both so the policy and sink can
    /// never be set in a surprising order. Resets both backends to
    /// `Healthy` — call before dispatching traffic. Degraded flags set
    /// via [`Self::with_backend_degraded`] are re-applied (provider
    /// properties, not health state).
    #[must_use]
    pub fn with_health(mut self, policy: HealthPolicy, sink: Box<dyn BackendStatusSink>) -> Self {
        self.health = HealthRegistry::new(policy, sink);
        self.health
            .set_degraded(BackendKind::RemoteGpu, self.degraded_flags.0);
        self.health
            .set_degraded(BackendKind::LocalCpu, self.degraded_flags.1);
        self
    }

    /// Flag a backend as serving with explicitly reduced performance —
    /// the desktop plan's §9 honesty contract (TASK-12). Carried on
    /// every emitted [`nexacore_types::ai::BackendStatusEvent`] and readable
    /// via [`Self::backend_degraded`]. Set at wiring time from the
    /// provider's own assessment (e.g.
    /// [`local_cpu::LocalCpuProvider::degraded`]).
    #[must_use]
    pub fn with_backend_degraded(mut self, kind: BackendKind, degraded: bool) -> Self {
        match kind {
            BackendKind::RemoteGpu => self.degraded_flags.0 = degraded,
            BackendKind::LocalCpu => self.degraded_flags.1 = degraded,
        }
        self.health.set_degraded(kind, degraded);
        self
    }

    /// Whether `kind` is flagged degraded (TASK-12).
    #[must_use]
    pub fn backend_degraded(&self, kind: BackendKind) -> bool {
        self.health.is_degraded(kind)
    }

    /// Set the audit sink the `*_with_ctx` methods record into (builder
    /// style). Without it those methods still dispatch and return
    /// attribution, but write no [`AuditRecord`].
    #[must_use]
    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// The active policy.
    #[must_use]
    pub fn policy(&self) -> BackendPolicy {
        self.policy
    }

    /// The router's health view (lock-free reads; tests and the UI
    /// bridge use this to inspect current backend health).
    #[must_use]
    pub fn health(&self) -> &HealthRegistry {
        &self.health
    }

    /// The deterministic list of backends this router is *configured* to
    /// try: policy order intersected with registered backends. Ignores
    /// health — see [`Self::dispatch_order`] for the health-aware order
    /// actually used per request.
    ///
    /// Exposed so callers (and tests) can assert the selection without
    /// dispatching a request.
    #[must_use]
    pub fn selection_order(&self) -> Vec<BackendKind> {
        self.policy
            .order()
            .iter()
            .copied()
            .filter(|k| self.provider_for(*k).is_some())
            .collect()
    }

    /// The health-aware try-order for the next request:
    /// [`Self::selection_order`] stably partitioned healthy-first.
    /// Unhealthy backends stay in the list (demoted, not dropped):
    /// when every backend looks down, trying one beats failing without
    /// trying (ADR-0031).
    #[must_use]
    pub fn dispatch_order(&self) -> Vec<BackendKind> {
        let mut order = self.selection_order();
        // Stable sort: healthy (key `false`) before unhealthy (key
        // `true`); policy order preserved within each group. A health
        // flip racing the sort can at worst invert the ordering of the
        // (at most two) backends — both stay in the list, so the
        // cascade still tries every one; benign.
        order.sort_by_key(|k| !self.health.is_healthy(*k));
        order
    }

    /// Borrow the registered provider for `kind`, if any.
    fn provider_for(&self, kind: BackendKind) -> Option<&dyn InferenceProvider> {
        match kind {
            BackendKind::RemoteGpu => self.remote_gpu.as_deref(),
            BackendKind::LocalCpu => self.local_cpu.as_deref(),
        }
    }

    /// Dispatch a [`Tier0Request`]`<`[`GenerateRequest`]`>`.
    ///
    /// Feeds per-attempt health evidence (TASK-10) but writes no audit
    /// record — see [`Self::generate_with_ctx`] for the audited path.
    ///
    /// # Errors
    ///
    /// - The first **terminal** [`ProviderError`] from a tried backend,
    ///   or
    /// - [`ProviderError::AllBackendsFailed`] if every permitted+
    ///   registered backend failed retriably (or none were registered).
    pub async fn generate(
        &self,
        req: &Tier0Request<GenerateRequest>,
    ) -> Result<GenerateResponse, ProviderError> {
        self.route_generate(req.inner())
            .await
            .map(|r| r.value)
            .map_err(|f| f.error)
    }

    /// Dispatch a [`Tier0Request`]`<`[`ChatRequest`]`>`.
    ///
    /// # Errors
    ///
    /// As [`Self::generate`].
    pub async fn chat(
        &self,
        req: &Tier0Request<ChatRequest>,
    ) -> Result<ChatResponse, ProviderError> {
        self.route_chat(req.inner())
            .await
            .map(|r| r.value)
            .map_err(|f| f.error)
    }

    /// Dispatch a [`Tier0Request`]`<`[`EmbeddingsRequest`]`>`.
    ///
    /// # Errors
    ///
    /// As [`Self::generate`].
    pub async fn embeddings(
        &self,
        req: &Tier0Request<EmbeddingsRequest>,
    ) -> Result<EmbeddingsResponse, ProviderError> {
        self.route_embeddings(req.inner())
            .await
            .map(|r| r.value)
            .map_err(|f| f.error)
    }

    // ---- audited dispatch (TASK-10, DE-G5) ---------------------------------

    /// As [`Self::generate`], additionally recording exactly one
    /// [`AuditRecord`] (with `backend_used` + latency) through the
    /// configured [`AuditSink`] and returning the backend attribution.
    ///
    /// # Errors
    ///
    /// As [`Self::generate`]. The audit record is written on **every**
    /// outcome, success or failure.
    pub async fn generate_with_ctx(
        &self,
        req: &Tier0Request<GenerateRequest>,
        ctx: &RequestContext,
    ) -> Result<Routed<GenerateResponse>, ProviderError> {
        let started = std::time::Instant::now();
        let result = self.route_generate(req.inner()).await;
        self.audit_outcome(
            ctx,
            started,
            result.as_ref().map(|r| (r.backend_used, r.value.tokens)),
        );
        result.map_err(|f| f.error)
    }

    /// As [`Self::chat`], with auditing — see [`Self::generate_with_ctx`].
    ///
    /// # Errors
    ///
    /// As [`Self::generate`].
    pub async fn chat_with_ctx(
        &self,
        req: &Tier0Request<ChatRequest>,
        ctx: &RequestContext,
    ) -> Result<Routed<ChatResponse>, ProviderError> {
        let started = std::time::Instant::now();
        let result = self.route_chat(req.inner()).await;
        self.audit_outcome(
            ctx,
            started,
            result.as_ref().map(|r| (r.backend_used, r.value.tokens)),
        );
        result.map_err(|f| f.error)
    }

    /// As [`Self::embeddings`], with auditing — see
    /// [`Self::generate_with_ctx`]. Embeddings report `0` output tokens
    /// (the response is a vector, not generated text).
    ///
    /// # Errors
    ///
    /// As [`Self::generate`].
    pub async fn embeddings_with_ctx(
        &self,
        req: &Tier0Request<EmbeddingsRequest>,
        ctx: &RequestContext,
    ) -> Result<Routed<EmbeddingsResponse>, ProviderError> {
        let started = std::time::Instant::now();
        let result = self.route_embeddings(req.inner()).await;
        self.audit_outcome(ctx, started, result.as_ref().map(|r| (r.backend_used, 0)));
        result.map_err(|f| f.error)
    }

    // ---- health probing (TASK-10, DE-G3) -----------------------------------

    /// Run one health-probe round: call [`InferenceProvider::health`] on
    /// every policy-permitted, registered backend and feed the result
    /// into the hysteresis trackers (emitting a status event on any
    /// transition). Returns each probed backend with its raw probe
    /// verdict, for logging/tests.
    ///
    /// This is the recovery path for demoted backends (they receive no
    /// request traffic, so only the probe can observe them coming back).
    /// Drive it on a timer with [`spawn_periodic_health_probe`].
    pub async fn probe_health_once(&self) -> Vec<(BackendKind, bool)> {
        let mut probed = Vec::new();
        for kind in self.selection_order() {
            let Some(provider) = self.provider_for(kind) else {
                continue;
            };
            let status = provider.health().await;
            self.health.observe(kind, status.healthy);
            probed.push((kind, status.healthy));
        }
        probed
    }

    // ---- internal routing core ----------------------------------------------

    /// Route one generate call along [`Self::dispatch_order`], feeding
    /// health evidence per attempt. See the type-level docs for the
    /// retriable/terminal semantics.
    ///
    /// The three `route_*` methods are deliberately parallel (the same
    /// cascade over the three provider operations); a generic core over
    /// `dyn` providers would need boxed-future HRTB plumbing that costs
    /// more clarity than this 3-way symmetry.
    async fn route_generate(
        &self,
        inner: &GenerateRequest,
    ) -> Result<Routed<GenerateResponse>, RouteFailure> {
        let mut tried = 0usize;
        let mut last: Option<ProviderError> = None;
        for kind in self.dispatch_order() {
            let Some(provider) = self.provider_for(kind) else {
                continue;
            };
            tried += 1;
            match provider.generate(inner).await {
                Ok(value) => {
                    self.health.observe(kind, true);
                    return Ok(Routed {
                        value,
                        backend_used: kind,
                    });
                }
                Err(e) if e.is_retriable() => {
                    self.health.observe(kind, false);
                    last = Some(e);
                }
                // Terminal: the backend answered (connectivity proven)
                // but rejected the request — health-neutral (ADR-0031),
                // attributed to the backend that answered.
                Err(error) => {
                    return Err(RouteFailure {
                        error,
                        backend: Some(kind),
                    });
                }
            }
        }
        Err(RouteFailure {
            error: Self::exhausted(tried, last),
            backend: None,
        })
    }

    /// Route one chat call — see [`Self::route_generate`].
    async fn route_chat(&self, inner: &ChatRequest) -> Result<Routed<ChatResponse>, RouteFailure> {
        let mut tried = 0usize;
        let mut last: Option<ProviderError> = None;
        for kind in self.dispatch_order() {
            let Some(provider) = self.provider_for(kind) else {
                continue;
            };
            tried += 1;
            match provider.chat(inner).await {
                Ok(value) => {
                    self.health.observe(kind, true);
                    return Ok(Routed {
                        value,
                        backend_used: kind,
                    });
                }
                Err(e) if e.is_retriable() => {
                    self.health.observe(kind, false);
                    last = Some(e);
                }
                Err(error) => {
                    return Err(RouteFailure {
                        error,
                        backend: Some(kind),
                    });
                }
            }
        }
        Err(RouteFailure {
            error: Self::exhausted(tried, last),
            backend: None,
        })
    }

    /// Route one embeddings call — see [`Self::route_generate`].
    async fn route_embeddings(
        &self,
        inner: &EmbeddingsRequest,
    ) -> Result<Routed<EmbeddingsResponse>, RouteFailure> {
        let mut tried = 0usize;
        let mut last: Option<ProviderError> = None;
        for kind in self.dispatch_order() {
            let Some(provider) = self.provider_for(kind) else {
                continue;
            };
            tried += 1;
            match provider.embeddings(inner).await {
                Ok(value) => {
                    self.health.observe(kind, true);
                    return Ok(Routed {
                        value,
                        backend_used: kind,
                    });
                }
                Err(e) if e.is_retriable() => {
                    self.health.observe(kind, false);
                    last = Some(e);
                }
                Err(error) => {
                    return Err(RouteFailure {
                        error,
                        backend: Some(kind),
                    });
                }
            }
        }
        Err(RouteFailure {
            error: Self::exhausted(tried, last),
            backend: None,
        })
    }

    /// Write the one-and-only [`AuditRecord`] for a `*_with_ctx`
    /// dispatch. `outcome` is `Ok((backend, output_tokens))` on
    /// success. On failure the status maps
    /// [`ProviderError::InvalidRequest`] to [`AuditStatus::Rejected`]
    /// and everything else to [`AuditStatus::Failed`]; `backend_used`
    /// is the backend that terminally answered, or `None` when no
    /// backend produced the outcome (all unreachable / none registered).
    fn audit_outcome(
        &self,
        ctx: &RequestContext,
        started: std::time::Instant,
        outcome: Result<(BackendKind, u32), &RouteFailure>,
    ) {
        let Some(sink) = self.audit.as_ref() else {
            return;
        };
        let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let (status, backend_used, output_token_count) = match outcome {
            Ok((kind, tokens)) => (AuditStatus::Ok, Some(kind), tokens),
            Err(failure) => {
                let status = match failure.error {
                    ProviderError::InvalidRequest(_) => AuditStatus::Rejected,
                    _ => AuditStatus::Failed,
                };
                (status, failure.backend, 0)
            }
        };
        sink.record_event(AuditRecord {
            timestamp_ns: ctx.timestamp_ns,
            session_id: ctx.session_id,
            capability_id: ctx.capability_id,
            model_id: ctx.model_id,
            tier: ctx.tier,
            input_token_count: ctx.input_token_count,
            output_token_count,
            latency_us,
            status,
            backend_used,
        });
    }

    /// Build the [`ProviderError::AllBackendsFailed`] returned when the
    /// cascade ran out of backends. `last` is the final retriable error,
    /// if any backend was actually tried.
    fn exhausted(tried: usize, last: Option<ProviderError>) -> ProviderError {
        ProviderError::AllBackendsFailed {
            tried,
            last: last.map_or_else(|| "no backend registered".to_owned(), |e| e.to_string()),
        }
    }
}

/// Internal: a routing failure plus the backend it is attributed to
/// (`Some` = that backend terminally answered; `None` = no backend
/// produced the outcome). Public APIs surface only the
/// [`ProviderError`]; the attribution feeds the audit record.
struct RouteFailure {
    error: ProviderError,
    backend: Option<BackendKind>,
}

// =============================================================================
// Periodic probe driver
// =============================================================================

/// Spawn a background task that calls
/// [`BackendRouter::probe_health_once`] every `period`, forever (until
/// the returned handle is aborted or the runtime shuts down).
///
/// This is the DE-G3 "periodic health-check": it is what lets a demoted
/// backend recover, since demoted backends receive no request traffic.
/// The period is the caller's policy decision (the desktop plan suggests
/// a few seconds); tests drive [`BackendRouter::probe_health_once`]
/// directly instead, keeping every health decision deterministic.
pub fn spawn_periodic_health_probe(
    router: Arc<BackendRouter>,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let probed = router.probe_health_once().await;
            tracing::debug!(?probed, "periodic backend health probe");
            tokio::time::sleep(period).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_req() -> Tier0Request<GenerateRequest> {
        Tier0Request::new(GenerateRequest {
            model: "gemma4:latest".to_owned(),
            prompt: "hi".to_owned(),
            max_tokens: 16,
        })
    }

    fn ok_response() -> GenerateResponse {
        GenerateResponse {
            text: "hello".to_owned(),
            tokens: 1,
        }
    }

    // ---- BackendKind / BackendPolicy ------------------------------------

    #[test]
    fn backend_labels_are_stable() {
        assert_eq!(BackendKind::RemoteGpu.label(), "remote_gpu");
        assert_eq!(BackendKind::LocalCpu.label(), "local_cpu");
    }

    #[test]
    fn policy_order_is_deterministic() {
        assert_eq!(
            BackendPolicy::PreferRemoteGpu.order(),
            &[BackendKind::RemoteGpu, BackendKind::LocalCpu]
        );
        assert_eq!(
            BackendPolicy::RemoteGpuOnly.order(),
            &[BackendKind::RemoteGpu]
        );
        assert_eq!(
            BackendPolicy::LocalCpuOnly.order(),
            &[BackendKind::LocalCpu]
        );
        assert_eq!(BackendPolicy::default(), BackendPolicy::PreferRemoteGpu);
    }

    #[test]
    fn error_retriability_classification() {
        assert!(ProviderError::Unavailable("x".into()).is_retriable());
        assert!(ProviderError::Transport("x".into()).is_retriable());
        assert!(!ProviderError::Backend("x".into()).is_retriable());
        assert!(!ProviderError::InvalidRequest("x".into()).is_retriable());
        assert!(
            !ProviderError::AllBackendsFailed {
                tried: 1,
                last: "x".into()
            }
            .is_retriable()
        );
    }

    // ---- BackendRouter selection ----------------------------------------

    #[tokio::test]
    async fn prefer_remote_gpu_uses_gpu_when_healthy() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_kind().return_const(BackendKind::RemoteGpu);
        gpu.expect_generate()
            .times(1)
            .returning(|_| Ok(ok_response()));
        // CPU must NOT be called when the GPU succeeds.
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_kind().return_const(BackendKind::LocalCpu);
        cpu.expect_generate().never();

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu));

        let resp = router.generate(&gen_req()).await.expect("gpu serves");
        assert_eq!(resp.text, "hello");
    }

    #[tokio::test]
    async fn retriable_gpu_error_falls_back_to_cpu() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_kind().return_const(BackendKind::RemoteGpu);
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Unavailable("refused".into())));
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_kind().return_const(BackendKind::LocalCpu);
        cpu.expect_generate()
            .times(1)
            .returning(|_| Ok(ok_response()));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu));

        let resp = router.generate(&gen_req()).await.expect("cpu fallback");
        assert_eq!(resp.text, "hello");
    }

    #[tokio::test]
    async fn terminal_gpu_error_does_not_fall_back() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_kind().return_const(BackendKind::RemoteGpu);
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Backend("bad model".into())));
        // A terminal error must NOT cascade to the CPU.
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_kind().return_const(BackendKind::LocalCpu);
        cpu.expect_generate().never();

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu));

        let err = router.generate(&gen_req()).await.expect_err("terminal");
        assert_eq!(err, ProviderError::Backend("bad model".into()));
    }

    #[tokio::test]
    async fn all_backends_retriable_failure_reports_count() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_kind().return_const(BackendKind::RemoteGpu);
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Unavailable("gpu down".into())));
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_kind().return_const(BackendKind::LocalCpu);
        cpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Transport("cpu busy".into())));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu));

        let err = router.generate(&gen_req()).await.expect_err("all fail");
        match err {
            ProviderError::AllBackendsFailed { tried, last } => {
                assert_eq!(tried, 2);
                assert!(last.contains("cpu busy"), "last error preserved: {last}");
            }
            other => panic!("expected AllBackendsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn local_cpu_only_policy_skips_gpu_entirely() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_kind().return_const(BackendKind::RemoteGpu);
        gpu.expect_generate().never();
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_kind().return_const(BackendKind::LocalCpu);
        cpu.expect_generate()
            .times(1)
            .returning(|_| Ok(ok_response()));

        let router = BackendRouter::new(BackendPolicy::LocalCpuOnly)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu));

        assert_eq!(router.selection_order(), vec![BackendKind::LocalCpu]);
        let resp = router.generate(&gen_req()).await.expect("cpu only");
        assert_eq!(resp.text, "hello");
    }

    #[tokio::test]
    async fn remote_gpu_only_does_not_fall_back_to_cpu() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_kind().return_const(BackendKind::RemoteGpu);
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Unavailable("down".into())));

        let router =
            BackendRouter::new(BackendPolicy::RemoteGpuOnly).with_remote_gpu(Box::new(gpu));

        let err = router.generate(&gen_req()).await.expect_err("no fallback");
        match err {
            ProviderError::AllBackendsFailed { tried, .. } => assert_eq!(tried, 1),
            other => panic!("expected AllBackendsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_backends_registered_reports_zero_tried() {
        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu);
        assert!(router.selection_order().is_empty());
        let err = router.generate(&gen_req()).await.expect_err("none");
        match err {
            ProviderError::AllBackendsFailed { tried, last } => {
                assert_eq!(tried, 0);
                assert_eq!(last, "no backend registered");
            }
            other => panic!("expected AllBackendsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn chat_and_embeddings_route_like_generate() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_kind().return_const(BackendKind::RemoteGpu);
        gpu.expect_chat().times(1).returning(|_| {
            Ok(ChatResponse {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: "hi".into(),
                },
                tokens: 1,
            })
        });
        gpu.expect_embeddings().times(1).returning(|_| {
            Ok(EmbeddingsResponse {
                embedding: vec![0.5, 0.25],
            })
        });

        let router =
            BackendRouter::new(BackendPolicy::PreferRemoteGpu).with_remote_gpu(Box::new(gpu));

        let chat = router
            .chat(&Tier0Request::new(ChatRequest {
                model: "m".into(),
                messages: vec![ChatMessage {
                    role: "user".into(),
                    content: "yo".into(),
                }],
            }))
            .await
            .expect("chat ok");
        assert_eq!(chat.message.content, "hi");

        let emb = router
            .embeddings(&Tier0Request::new(EmbeddingsRequest {
                model: "m".into(),
                input: "yo".into(),
            }))
            .await
            .expect("emb ok");
        assert_eq!(emb.embedding, vec![0.5, 0.25]);
    }

    // ---- Tier0/Tier1 typestate ------------------------------------------

    #[test]
    fn tier0_request_round_trips_inner() {
        let r = Tier0Request::new(42u32);
        assert_eq!(*r.inner(), 42);
        assert_eq!(r.into_inner(), 42);
    }

    #[test]
    fn tier1_request_is_distinct_and_holds_inner() {
        let r = Tier1Request::new(7u32);
        assert_eq!(*r.inner(), 7);
    }

    // ---- postcard round-trip (NCIP-Serde-004) ----------------------------

    #[test]
    fn wire_round_trip_generate() {
        let req = GenerateRequest {
            model: "gemma4:latest".into(),
            prompt: "hello world".into(),
            max_tokens: 128,
        };
        let bytes = nexacore_types::wire::encode_canonical(&req).expect("encode");
        let back: GenerateRequest = nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(req, back);
    }

    // =========================================================================
    // TASK-10: health-driven routing, recovery, hysteresis, audit
    // =========================================================================

    use health::BufferStatusSink;
    use nexacore_types::ai::BackendStatusEvent;

    use crate::audit::{AuditLog, InMemoryAuditLog};

    fn response(text: &str) -> GenerateResponse {
        GenerateResponse {
            text: text.to_owned(),
            tokens: 3,
        }
    }

    fn audit_ctx() -> RequestContext {
        RequestContext {
            session_id: SessionId::from_bytes([0x11; 16]),
            capability_id: CapabilityId::from_bytes([0x22; 16]),
            model_id: ModelId::from_bytes([0x33; 32]),
            tier: 0,
            timestamp_ns: 42,
            input_token_count: 7,
        }
    }

    fn shared_audit() -> Arc<parking_lot::Mutex<InMemoryAuditLog>> {
        Arc::new(parking_lot::Mutex::new(InMemoryAuditLog::new()))
    }

    // ---- failover + demotion + recovery (DE-G3) --------------------------

    #[tokio::test]
    async fn unhealthy_gpu_is_skipped_on_subsequent_requests() {
        let mut gpu = MockInferenceProvider::new();
        // The GPU must be tried exactly ONCE: the first request demotes
        // it (fail_threshold = 1); the second request must go straight
        // to the CPU without touching the GPU again.
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Unavailable("down".into())));
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_generate()
            .times(2)
            .returning(|_| Ok(response("cpu")));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu));

        // Request 1: failover GPU -> CPU within the SAME request.
        let r1 = router.generate(&gen_req()).await.expect("cpu serves");
        assert_eq!(r1.text, "cpu");
        assert!(!router.health().is_healthy(BackendKind::RemoteGpu));

        // The dispatch order now demotes the GPU; selection_order (the
        // configured order) is unchanged.
        assert_eq!(
            router.dispatch_order(),
            vec![BackendKind::LocalCpu, BackendKind::RemoteGpu]
        );
        assert_eq!(
            router.selection_order(),
            vec![BackendKind::RemoteGpu, BackendKind::LocalCpu]
        );

        // Request 2: CPU first, GPU untouched (mock would panic on a
        // second generate call).
        let r2 = router.generate(&gen_req()).await.expect("cpu again");
        assert_eq!(r2.text, "cpu");
    }

    #[tokio::test]
    async fn gpu_recovers_after_three_consecutive_healthy_probes() {
        let events = Arc::new(BufferStatusSink::new());

        let mut seq = mockall::Sequence::new();
        let mut gpu = MockInferenceProvider::new();
        // 1) First request: GPU refuses -> demoted.
        gpu.expect_generate()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Err(ProviderError::Unavailable("down".into())));
        // 2) Three healthy probes -> recovery (recover_threshold = 3).
        gpu.expect_health()
            .times(3)
            .in_sequence(&mut seq)
            .returning(HealthStatus::ok);
        // 3) Post-recovery request: GPU serves again.
        gpu.expect_generate()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(response("gpu")));

        let mut cpu = MockInferenceProvider::new();
        cpu.expect_generate()
            .times(1)
            .returning(|_| Ok(response("cpu")));
        cpu.expect_health().times(3).returning(HealthStatus::ok);

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu))
            .with_health(HealthPolicy::default(), Box::new(events.clone()));

        // GPU down -> CPU serves; GPU demoted.
        let r1 = router.generate(&gen_req()).await.expect("fallback");
        assert_eq!(r1.text, "cpu");
        assert!(!router.health().is_healthy(BackendKind::RemoteGpu));

        // Hysteresis: two healthy probes are NOT enough …
        router.probe_health_once().await;
        router.probe_health_once().await;
        assert!(!router.health().is_healthy(BackendKind::RemoteGpu));
        // … the third one recovers the GPU.
        router.probe_health_once().await;
        assert!(router.health().is_healthy(BackendKind::RemoteGpu));

        // Traffic returns to the GPU.
        let r2 = router.generate(&gen_req()).await.expect("gpu back");
        assert_eq!(r2.text, "gpu");

        // Exactly two transitions were emitted: down, then up.
        assert_eq!(
            events.events(),
            vec![
                BackendStatusEvent {
                    backend: BackendKind::RemoteGpu,
                    healthy: false,
                    degraded: false,
                },
                BackendStatusEvent {
                    backend: BackendKind::RemoteGpu,
                    healthy: true,
                    degraded: false,
                },
            ]
        );
    }

    #[tokio::test]
    async fn intermittent_gpu_health_does_not_flip_flop() {
        let events = Arc::new(BufferStatusSink::new());

        // Probe results alternate: fail, ok, fail, ok, … — an
        // intermittent backend. With recover_threshold = 3 it must stay
        // demoted after the first failure: exactly ONE event, no
        // flip-flopping.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_health().returning(move || {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n % 2 == 0 {
                HealthStatus::unhealthy("flapping")
            } else {
                HealthStatus::ok()
            }
        });
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_health().returning(HealthStatus::ok);
        cpu.expect_generate()
            .times(4)
            .returning(|_| Ok(response("cpu")));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu))
            .with_health(HealthPolicy::default(), Box::new(events.clone()));

        for _ in 0..8 {
            router.probe_health_once().await;
        }
        assert!(!router.health().is_healthy(BackendKind::RemoteGpu));
        assert_eq!(
            events.events(),
            vec![BackendStatusEvent {
                backend: BackendKind::RemoteGpu,
                healthy: false,
                degraded: false,
            }],
            "one demotion, zero flip-flops"
        );

        // Requests flow steadily to the CPU throughout (the demoted GPU
        // is never tried: the CPU answers first every time).
        for _ in 0..4 {
            let r = router.generate(&gen_req()).await.expect("cpu");
            assert_eq!(r.text, "cpu");
        }
    }

    #[tokio::test]
    async fn all_backends_unhealthy_are_still_tried_as_last_resort() {
        // Both backends fail retriably twice (two requests). Demotion
        // must never remove them from the dispatch order entirely —
        // otherwise the second request would fail with `tried: 0`
        // without even attempting.
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate()
            .times(2)
            .returning(|_| Err(ProviderError::Unavailable("gpu down".into())));
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_generate()
            .times(2)
            .returning(|_| Err(ProviderError::Unavailable("cpu down".into())));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu));

        for _ in 0..2 {
            let err = router.generate(&gen_req()).await.expect_err("all down");
            match err {
                ProviderError::AllBackendsFailed { tried, .. } => assert_eq!(tried, 2),
                other => panic!("expected AllBackendsFailed, got {other:?}"),
            }
        }
        assert_eq!(router.dispatch_order().len(), 2, "demoted, not dropped");
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_probe_task_drives_recovery() {
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_health().returning(HealthStatus::ok);

        let router = Arc::new(
            BackendRouter::new(BackendPolicy::RemoteGpuOnly).with_remote_gpu(Box::new(gpu)),
        );
        // Demote the GPU directly (as a failed request would).
        router.health().observe(BackendKind::RemoteGpu, false);
        assert!(!router.health().is_healthy(BackendKind::RemoteGpu));

        let handle = spawn_periodic_health_probe(router.clone(), std::time::Duration::from_secs(1));
        // Paused tokio time: sleeping advances the virtual clock and lets
        // the probe task run ≥ 3 rounds (recover_threshold).
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert!(
            router.health().is_healthy(BackendKind::RemoteGpu),
            "the periodic probe is the recovery path"
        );
        handle.abort();
    }

    // ---- audit: exactly one record per request, backend_used (DE-G5) ----

    #[tokio::test]
    async fn audited_success_records_one_record_with_backend_used_gpu() {
        let log = shared_audit();
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate()
            .times(1)
            .returning(|_| Ok(response("gpu")));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_audit(log.clone());

        let routed = router
            .generate_with_ctx(&gen_req(), &audit_ctx())
            .await
            .expect("ok");
        assert_eq!(routed.backend_used, BackendKind::RemoteGpu);
        assert_eq!(routed.value.text, "gpu");

        let rec = {
            let guard = log.lock();
            assert_eq!(guard.count(), 1, "exactly one record per request");
            guard.iter().next().expect("one record").clone()
        };
        assert_eq!(rec.backend_used, Some(BackendKind::RemoteGpu));
        assert_eq!(rec.status, crate::audit::AuditStatus::Ok);
        assert_eq!(rec.timestamp_ns, 42);
        assert_eq!(rec.input_token_count, 7);
        assert_eq!(rec.output_token_count, 3);
        assert_eq!(rec.tier, 0);
        assert_eq!(rec.session_id, SessionId::from_bytes([0x11; 16]));
    }

    #[tokio::test]
    async fn audited_failover_records_backend_used_cpu() {
        let log = shared_audit();
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Unavailable("down".into())));
        let mut cpu = MockInferenceProvider::new();
        cpu.expect_generate()
            .times(1)
            .returning(|_| Ok(response("cpu")));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_local_cpu(Box::new(cpu))
            .with_audit(log.clone());

        let routed = router
            .generate_with_ctx(&gen_req(), &audit_ctx())
            .await
            .expect("cpu serves");
        assert_eq!(routed.backend_used, BackendKind::LocalCpu);

        let rec = {
            let guard = log.lock();
            assert_eq!(guard.count(), 1, "failover is still ONE request");
            guard.iter().next().expect("one record").clone()
        };
        assert_eq!(rec.backend_used, Some(BackendKind::LocalCpu));
        assert_eq!(rec.status, crate::audit::AuditStatus::Ok);
    }

    #[tokio::test]
    async fn audited_terminal_failure_attributes_the_answering_backend() {
        let log = shared_audit();
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Backend("bad model".into())));

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_audit(log.clone());

        router
            .generate_with_ctx(&gen_req(), &audit_ctx())
            .await
            .expect_err("terminal");

        let rec = {
            let guard = log.lock();
            assert_eq!(guard.count(), 1);
            guard.iter().next().expect("one record").clone()
        };
        assert_eq!(rec.status, crate::audit::AuditStatus::Failed);
        assert_eq!(
            rec.backend_used,
            Some(BackendKind::RemoteGpu),
            "the GPU answered (terminally) — attribute it"
        );
    }

    #[tokio::test]
    async fn audited_all_backends_failed_records_no_backend() {
        let log = shared_audit();
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_generate()
            .times(1)
            .returning(|_| Err(ProviderError::Unavailable("down".into())));

        let router = BackendRouter::new(BackendPolicy::RemoteGpuOnly)
            .with_remote_gpu(Box::new(gpu))
            .with_audit(log.clone());

        router
            .generate_with_ctx(&gen_req(), &audit_ctx())
            .await
            .expect_err("all failed");

        let rec = {
            let guard = log.lock();
            assert_eq!(guard.count(), 1);
            guard.iter().next().expect("one record").clone()
        };
        assert_eq!(rec.status, crate::audit::AuditStatus::Failed);
        assert_eq!(rec.backend_used, None, "no backend produced the outcome");
    }

    #[tokio::test]
    async fn audited_chat_and_embeddings_record_one_record_each() {
        let log = shared_audit();
        let mut gpu = MockInferenceProvider::new();
        gpu.expect_chat().times(1).returning(|_| {
            Ok(ChatResponse {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: "hi".into(),
                },
                tokens: 5,
            })
        });
        gpu.expect_embeddings().times(1).returning(|_| {
            Ok(EmbeddingsResponse {
                embedding: vec![0.5],
            })
        });

        let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(gpu))
            .with_audit(log.clone());

        let chat = router
            .chat_with_ctx(
                &Tier0Request::new(ChatRequest {
                    model: "m".into(),
                    messages: vec![ChatMessage {
                        role: "user".into(),
                        content: "yo".into(),
                    }],
                }),
                &audit_ctx(),
            )
            .await
            .expect("chat ok");
        assert_eq!(chat.backend_used, BackendKind::RemoteGpu);

        let emb = router
            .embeddings_with_ctx(
                &Tier0Request::new(EmbeddingsRequest {
                    model: "m".into(),
                    input: "yo".into(),
                }),
                &audit_ctx(),
            )
            .await
            .expect("emb ok");
        assert_eq!(emb.backend_used, BackendKind::RemoteGpu);

        let tokens: Vec<u32> = {
            let guard = log.lock();
            assert_eq!(guard.count(), 2, "one record per request, two requests");
            guard.iter().map(|r| r.output_token_count).collect()
        };
        assert_eq!(tokens, vec![5, 0], "chat reports tokens; embeddings 0");
    }

    // ---- proptest: the audit record never contains the prompt (PII) ------

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]
        #[test]
        fn proptest_audit_record_never_contains_prompt(suffix in "[a-zA-Z0-9]{8,64}") {
            // A distinctive marker prevents trivial false matches; the
            // assertion scans the canonical encoding of the produced
            // record for the prompt bytes.
            let prompt = format!("PII-MARKER-{suffix}");

            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime");
            let log = shared_audit();
            let mut gpu = MockInferenceProvider::new();
            gpu.expect_generate().returning(|_| Ok(response("ok")));
            let router = BackendRouter::new(BackendPolicy::PreferRemoteGpu)
                .with_remote_gpu(Box::new(gpu))
                .with_audit(log.clone());

            let req = Tier0Request::new(GenerateRequest {
                model: "gemma4:latest".into(),
                prompt: prompt.clone(),
                max_tokens: 0,
            });
            rt.block_on(async {
                router
                    .generate_with_ctx(&req, &audit_ctx())
                    .await
                    .expect("ok");
            });

            let rec = {
                let guard = log.lock();
                guard.iter().next().expect("one record").clone()
            };
            let bytes = nexacore_types::wire::encode_canonical(&rec).expect("encode");
            proptest::prop_assert!(
                !bytes
                    .windows(prompt.len())
                    .any(|w| w == prompt.as_bytes()),
                "audit record must never contain prompt bytes"
            );
        }
    }
}

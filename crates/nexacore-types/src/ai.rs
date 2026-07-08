//! AI backend vocabulary shared across the IPC boundary (TASK-10, DE-G5).
//!
//! The runtime's `BackendRouter` (in `nexacore-runtime`) routes Tier-0
//! inference between a remote user-owned GPU and the on-device CPU
//! engine, and emits a status event whenever a backend's health state
//! changes. The UI status bar (TASK-21 / DE-C6) consumes those events in
//! a *different process*, so the types cross IPC and therefore live here,
//! at the bottom of the dependency tree, encoded with the canonical
//! postcard wire format ([`crate::wire`], `NCIP-Serde-004`).
//!
//! [`BackendKind`] originated in `nexacore-runtime::provider` (TASK-08) and
//! moved here unchanged in TASK-10 (ADR-0031); `nexacore-runtime` re-exports
//! it, and the variant order is preserved so the postcard encoding is
//! identical.

use serde::{Deserialize, Serialize};

/// The closed set of inference backends the runtime can route to.
///
/// Both variants live **inside Tier 0** (local-node control): `RemoteGpu`
/// is the user-owned GPU box on the LAN/Tailscale, `LocalCpu` is the
/// on-device CPU engine. Neither sends data off the user's own
/// infrastructure (that would be Tier 1+, gated by the runtime's tier
/// router).
///
/// # Wire encoding
///
/// Serialized as a postcard unit-enum discriminant. **Variant order is
/// wire-stable** (`RemoteGpu` = 0, `LocalCpu` = 1); reordering or
/// inserting variants is a wire-format breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendKind {
    /// A user-owned GPU machine reached over the network (the Ollama
    /// HTTP client, TASK-09). Preferred when healthy: fastest.
    RemoteGpu,
    /// The on-device CPU inference engine (TASK-12). Always available as
    /// the last-resort fallback; may be flagged `degraded` for large
    /// models (the desktop plan's §9 honesty contract).
    LocalCpu,
}

impl BackendKind {
    /// Stable lowercase label for logs / the `backend_used` audit field
    /// (TASK-10). Kept ASCII + hyphen-free so it slots into structured
    /// log keys without escaping.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RemoteGpu => "remote_gpu",
            Self::LocalCpu => "local_cpu",
        }
    }
}

/// A backend health-state transition, emitted by the runtime's health
/// monitor whenever a backend flips between healthy and unhealthy
/// (TASK-10, DE-G5).
///
/// This is the payload the UI status bar (TASK-21) consumes to render
/// the backend indicator (e.g. "🟢 GPU" / "🟡 CPU"). It is emitted only
/// on *transitions* (never per-request), so consumers can treat each
/// event as a state change rather than a heartbeat.
///
/// The event deliberately carries **no timestamp**: the runtime's health
/// decisions are deterministic (counter-based hysteresis, no clock), and
/// consumers that need one stamp arrival time. It also carries no detail
/// string — health *reasons* stay in the runtime's tracing logs, keeping
/// this wire type free of any text channel that could leak content.
///
/// # Example
///
/// ```rust
/// use nexacore_types::{
///     ai::{BackendKind, BackendStatusEvent},
///     wire::{decode_canonical, encode_canonical},
/// };
///
/// let event = BackendStatusEvent {
///     backend: BackendKind::RemoteGpu,
///     healthy: false,
///     degraded: false,
/// };
/// let bytes = encode_canonical(&event).expect("encode");
/// let back: BackendStatusEvent = decode_canonical(&bytes).expect("decode");
/// assert_eq!(back, event);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStatusEvent {
    /// Which backend changed state.
    pub backend: BackendKind,
    /// The new health state: `true` = the backend is believed able to
    /// serve requests, `false` = it is down/unreachable.
    pub healthy: bool,
    /// `true` when the backend serves with explicitly reduced
    /// performance expectations — the desktop plan's §9 honesty
    /// contract (TASK-12: the Phase-2 `LocalCpu` engine on real models).
    /// The UI renders it distinctly (e.g. "🟡 CPU").
    ///
    /// **Wire note:** appended in TASK-12 (pre-release postcard change;
    /// no persisted consumers existed).
    pub degraded: bool,
}

// =============================================================================
// AI syscall relay wire types (TASK-11, DE-G6 — ADR-0032)
// =============================================================================

use alloc::{string::String, vec::Vec};

/// Hard ceiling on AI relay payloads (4096 bytes).
///
/// Bounds [`AiSyscallRequest::input_data`] / capability bytes and
/// [`AiSyscallResponse::output_data`], matching the kernel's shared IPC
/// `MAX_PAYLOAD`. The kernel enforces it on the copy path
/// (`copy_from_user_vec`); the runtime service re-checks it on decode
/// (defence in depth — the counterpart is untrusted).
pub const AI_MAX_PAYLOAD: usize = 4096;

/// AI syscall numbers, the kernel ABI contract (`nexacore-kernel`
/// `syscall.rs` numbers 80–84).
///
/// | Number | Name | Purpose |
/// |--------|------|---------|
/// | 80 | `Invoke` | Single-turn text generation / completion |
/// | 81 | `Stream` | Streaming text generation |
/// | 82 | `Embed` | Dense vector embedding |
/// | 83 | `Classify` | Label classification |
/// | 84 | `Transcribe` | Speech-to-text |
///
/// # Wire encoding
///
/// Serialized as a postcard unit-enum discriminant (variant **index**
/// 0–4, not the syscall number). **Variant order is wire-stable**;
/// reordering is a wire-format breaking change. These types originated
/// in `nexacore-runtime::relay` (Sprint 11.a) and moved here in TASK-11 so
/// the kernel and the Ring 3 service image (both `no_std`) share them;
/// `nexacore-runtime` re-exports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AiSyscallNumber {
    /// Syscall 80 — single-turn inference (request/response).
    Invoke = 80,
    /// Syscall 81 — streaming inference (token-by-token delivery).
    Stream = 81,
    /// Syscall 82 — dense vector embedding.
    Embed = 82,
    /// Syscall 83 — multi-label classification.
    Classify = 83,
    /// Syscall 84 — speech-to-text transcription.
    Transcribe = 84,
}

impl AiSyscallNumber {
    /// Return the numeric kernel syscall number.
    ///
    /// ```rust
    /// use nexacore_types::ai::AiSyscallNumber;
    /// assert_eq!(AiSyscallNumber::Invoke.as_u32(), 80);
    /// assert_eq!(AiSyscallNumber::Transcribe.as_u32(), 84);
    /// ```
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Try to construct an [`AiSyscallNumber`] from a raw kernel syscall
    /// number. Returns `None` outside the AI range (80–84).
    ///
    /// ```rust
    /// use nexacore_types::ai::AiSyscallNumber;
    /// assert_eq!(AiSyscallNumber::from_u32(82), Some(AiSyscallNumber::Embed));
    /// assert_eq!(AiSyscallNumber::from_u32(0), None);
    /// assert_eq!(AiSyscallNumber::from_u32(85), None);
    /// ```
    #[must_use]
    pub const fn from_u32(n: u32) -> Option<Self> {
        match n {
            80 => Some(Self::Invoke),
            81 => Some(Self::Stream),
            82 => Some(Self::Embed),
            83 => Some(Self::Classify),
            84 => Some(Self::Transcribe),
            _ => None,
        }
    }
}

/// A kernel→runtime AI syscall relay request (postcard over IPC).
///
/// The kernel packs the calling process's syscall arguments into this
/// structure and relays it to the runtime service over the 2-channel
/// rendezvous (`ai` request channel / `ai_reply` reply channel — the
/// same pattern as the NET relay). The runtime decodes it and serves it
/// through `SessionManager` + `BackendRouter`.
///
/// # Field notes
///
/// - `model_id_bytes`: compact 16-byte model identifier; the runtime
///   zero-extends it to the 32-byte `ModelId` (high half = these bytes,
///   low half zeroed — `NCIP-Agent-Arch-022 §S9`).
/// - `capability`: opaque session-capability bytes the serving layer
///   validates (`SessionCapability` well-formedness in Sprint 11.a;
///   full Ed25519 token verification is TASK-S11.E). **TASK-11
///   placeholder:** the kernel fills a minimal well-formed token for
///   Ring 3 callers until per-process capability material lands
///   (ADR-0032) — the gating contract is exercised end-to-end and
///   enforced service-side.
/// - `input_data`: opaque payload (≤ [`AI_MAX_PAYLOAD`]), UTF-8 prompt
///   for `Invoke`/`Stream`, raw text for `Embed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiSyscallRequest {
    /// Which AI syscall was invoked.
    pub syscall: AiSyscallNumber,
    /// Compact 16-byte model identifier (zero-extended by the runtime).
    pub model_id_bytes: [u8; 16],
    /// Opaque session-capability bytes (validated service-side).
    pub capability: Vec<u8>,
    /// Opaque input payload (≤ [`AI_MAX_PAYLOAD`]).
    pub input_data: Vec<u8>,
    /// Caller-assigned monotonic request ID for end-to-end correlation.
    pub request_id: u64,
    /// PID of the process that issued the syscall (audit only).
    pub caller_pid: u64,
}

/// The runtime→kernel AI syscall relay response.
///
/// The kernel copies `output_data` into the calling process's buffer
/// (bounded by the caller-supplied capacity) and surfaces an errno when
/// `success` is `false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiSyscallResponse {
    /// Echoes [`AiSyscallRequest::request_id`] for correlation.
    pub request_id: u64,
    /// `true` if inference succeeded; `false` on any error.
    pub success: bool,
    /// Opaque output payload (≤ [`AI_MAX_PAYLOAD`]), empty on error.
    pub output_data: Vec<u8>,
    /// Wall-clock latency of the full relay dispatch in microseconds.
    pub latency_us: u64,
    /// Human-readable error description when `success` is `false`.
    /// Carries no caller content (no prompt echo) — errors are
    /// classification + cause only.
    pub error_message: Option<String>,
}

impl AiSyscallResponse {
    /// Build an error response for `request_id` (canonical failure
    /// constructor: `success = false`, empty output).
    #[must_use]
    pub fn error(request_id: u64, latency_us: u64, message: impl Into<String>) -> Self {
        Self {
            request_id,
            success: false,
            output_data: Vec::new(),
            latency_us,
            error_message: Some(message.into()),
        }
    }
}

// =============================================================================
// `ai_stream` syscall ABI (WS5-03.1, ADR-0032 § Stream)
// =============================================================================

/// Hard ceiling on the number of tokens a single `ai_stream` session may
/// generate (bounds runtime work and the caller's receive loop).
pub const AI_STREAM_MAX_TOKENS: u32 = 8192;

/// Hard ceiling on the decoded-text bytes a single [`AiTokenChunk`] may carry.
///
/// A chunk usually holds one detokenized token (a few bytes); this bounds the
/// pathological case (a single token decoding to a long grapheme cluster) so a
/// hostile or buggy producer cannot inflate a chunk past a small fixed size.
pub const AI_STREAM_CHUNK_MAX_TEXT: usize = 256;

/// An opaque handle to an open `ai_stream` session.
///
/// The runtime allocates one per [`AiStreamRequest`] it accepts (returned in
/// [`AiStreamOpened::handle`]) and stamps every [`AiTokenChunk`] of that session
/// with it, so a caller multiplexing several streams on one channel can route
/// each chunk. Like the other identifier newtypes in this crate it has **no
/// `Display`** — surface it through [`AiStreamHandle::get`] when needed.
///
/// # Wire encoding
///
/// A postcard `u64` varint (the inner value).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AiStreamHandle(pub u64);

impl AiStreamHandle {
    /// Wraps a raw handle value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw handle value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why an [`AiStreamRequest`] or [`AiTokenChunk`] was rejected by its
/// host-side `validate` check (mirrors the kernel's `EINVAL` reasons).
///
/// This is a local validation verdict, **not** a wire type — it never crosses
/// IPC, so it carries no `Serialize`/`Deserialize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AiStreamReject {
    /// `input_data` exceeds [`AI_MAX_PAYLOAD`].
    InputTooLarge,
    /// `capability` exceeds [`AI_MAX_PAYLOAD`].
    CapabilityTooLarge,
    /// `max_tokens` was zero — a stream must request at least one token.
    NoTokensRequested,
    /// `max_tokens` exceeds [`AI_STREAM_MAX_TOKENS`].
    TooManyTokens,
    /// A chunk's `text` exceeds [`AI_STREAM_CHUNK_MAX_TEXT`].
    ChunkTextTooLarge,
}

impl core::fmt::Display for AiStreamReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::InputTooLarge => "ai_stream: input payload exceeds AI_MAX_PAYLOAD",
            Self::CapabilityTooLarge => "ai_stream: capability exceeds AI_MAX_PAYLOAD",
            Self::NoTokensRequested => "ai_stream: max_tokens must be at least 1",
            Self::TooManyTokens => "ai_stream: max_tokens exceeds AI_STREAM_MAX_TOKENS",
            Self::ChunkTextTooLarge => "ai_stream: chunk text exceeds AI_STREAM_CHUNK_MAX_TEXT",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for AiStreamReject {}

/// A request to open an `ai_stream` session (postcard over the `ai` relay
/// channel, like [`AiSyscallRequest`] but stream-specific).
///
/// The runtime decodes it, opens a generation session, and replies with an
/// [`AiStreamOpened`] carrying the [`AiStreamHandle`]; the generated tokens then
/// flow back as a sequence of [`AiTokenChunk`]s over the caller's stream
/// channel. The field semantics match [`AiSyscallRequest`]; `max_tokens` is the
/// stream-specific generation cap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiStreamRequest {
    /// Compact 16-byte model identifier (zero-extended by the runtime).
    pub model_id_bytes: [u8; 16],
    /// Opaque session-capability bytes (validated service-side).
    pub capability: Vec<u8>,
    /// Opaque prompt payload (≤ [`AI_MAX_PAYLOAD`]), UTF-8 for text models.
    pub input_data: Vec<u8>,
    /// Caller-assigned monotonic request ID for end-to-end correlation.
    pub request_id: u64,
    /// PID of the process that issued the syscall (audit only).
    pub caller_pid: u64,
    /// Maximum number of tokens to generate (1..=[`AI_STREAM_MAX_TOKENS`]).
    pub max_tokens: u32,
}

impl AiStreamRequest {
    /// Validates the request against the ABI bounds the kernel enforces.
    ///
    /// # Errors
    ///
    /// An [`AiStreamReject`] naming the first bound violated.
    pub fn validate(&self) -> Result<(), AiStreamReject> {
        if self.input_data.len() > AI_MAX_PAYLOAD {
            return Err(AiStreamReject::InputTooLarge);
        }
        if self.capability.len() > AI_MAX_PAYLOAD {
            return Err(AiStreamReject::CapabilityTooLarge);
        }
        if self.max_tokens == 0 {
            return Err(AiStreamReject::NoTokensRequested);
        }
        if self.max_tokens > AI_STREAM_MAX_TOKENS {
            return Err(AiStreamReject::TooManyTokens);
        }
        Ok(())
    }
}

/// The runtime's reply to an [`AiStreamRequest`]: the allocated stream handle,
/// or an error if the session could not be opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiStreamOpened {
    /// Echoes [`AiStreamRequest::request_id`] for correlation.
    pub request_id: u64,
    /// `true` if the session opened; `false` on any error.
    pub success: bool,
    /// The session handle when `success` is `true`, else `None`.
    pub handle: Option<AiStreamHandle>,
    /// Human-readable error description when `success` is `false` (no caller
    /// content — classification + cause only).
    pub error_message: Option<String>,
}

impl AiStreamOpened {
    /// A success reply carrying `handle`.
    #[must_use]
    pub fn ok(request_id: u64, handle: AiStreamHandle) -> Self {
        Self {
            request_id,
            success: true,
            handle: Some(handle),
            error_message: None,
        }
    }

    /// An error reply (no handle).
    #[must_use]
    pub fn error(request_id: u64, message: impl Into<String>) -> Self {
        Self {
            request_id,
            success: false,
            handle: None,
            error_message: Some(message.into()),
        }
    }
}

/// One streamed token of an `ai_stream` session (postcard over the caller's
/// stream channel).
///
/// Tokens arrive in order (`seq` monotonic from 0); the final token of a
/// session sets `is_last`. `text` is the incrementally detokenized UTF-8 for
/// this token and may be empty when the token completes only part of a
/// multi-token grapheme (the detokenizer buffers across boundaries).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiTokenChunk {
    /// The session this chunk belongs to.
    pub handle: AiStreamHandle,
    /// Echoes [`AiStreamRequest::request_id`] for correlation.
    pub request_id: u64,
    /// Zero-based position of this token within the session.
    pub seq: u32,
    /// The generated token (vocabulary index).
    pub token: u32,
    /// Incrementally detokenized UTF-8 bytes (≤ [`AI_STREAM_CHUNK_MAX_TEXT`]).
    pub text: Vec<u8>,
    /// `true` if this is the final token of the session.
    pub is_last: bool,
}

impl AiTokenChunk {
    /// Builds a token chunk.
    #[must_use]
    pub fn new(
        handle: AiStreamHandle,
        request_id: u64,
        seq: u32,
        token: u32,
        text: Vec<u8>,
        is_last: bool,
    ) -> Self {
        Self {
            handle,
            request_id,
            seq,
            token,
            text,
            is_last,
        }
    }

    /// Validates the chunk's `text` against [`AI_STREAM_CHUNK_MAX_TEXT`].
    ///
    /// # Errors
    ///
    /// [`AiStreamReject::ChunkTextTooLarge`] if the text is over the bound.
    pub fn validate(&self) -> Result<(), AiStreamReject> {
        if self.text.len() > AI_STREAM_CHUNK_MAX_TEXT {
            return Err(AiStreamReject::ChunkTextTooLarge);
        }
        Ok(())
    }
}

// =============================================================================
// `ai_embed` syscall ABI (WS5-03.4)
// =============================================================================

/// Hard ceiling on an embedding vector's dimension.
///
/// Bounds [`AiEmbedding::vector`] so a hostile or misconfigured model cannot
/// force the caller to allocate an unbounded float array. Comfortably above any
/// current sentence-embedding width (typically 384–4096).
pub const AI_EMBED_MAX_DIM: usize = 8192;

/// Why an [`AiEmbedRequest`] or [`AiEmbedding`] failed its host-side `validate`
/// check (mirrors the kernel's `EINVAL` reasons).
///
/// A local validation verdict, **not** a wire type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::enum_variant_names,
    reason = "the shared `TooLarge` postfix is meaningful — every variant is a size-limit rejection"
)]
pub enum AiEmbedReject {
    /// `input_data` exceeds [`AI_MAX_PAYLOAD`].
    InputTooLarge,
    /// `capability` exceeds [`AI_MAX_PAYLOAD`].
    CapabilityTooLarge,
    /// The embedding vector exceeds [`AI_EMBED_MAX_DIM`] dimensions.
    DimTooLarge,
}

impl core::fmt::Display for AiEmbedReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::InputTooLarge => "ai_embed: input payload exceeds AI_MAX_PAYLOAD",
            Self::CapabilityTooLarge => "ai_embed: capability exceeds AI_MAX_PAYLOAD",
            Self::DimTooLarge => "ai_embed: embedding dimension exceeds AI_EMBED_MAX_DIM",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for AiEmbedReject {}

/// A request to compute a dense embedding for a piece of text (postcard over the
/// `ai` relay channel).
///
/// The runtime runs the model's encoder over `input_data` and returns the
/// pooled hidden state as an [`AiEmbedding`]. Field semantics match
/// [`AiSyscallRequest`]; `normalize` is the embedding-specific control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiEmbedRequest {
    /// Compact 16-byte model identifier (zero-extended by the runtime).
    pub model_id_bytes: [u8; 16],
    /// Opaque session-capability bytes (validated service-side).
    pub capability: Vec<u8>,
    /// UTF-8 text to embed (≤ [`AI_MAX_PAYLOAD`]).
    pub input_data: Vec<u8>,
    /// Caller-assigned monotonic request ID for end-to-end correlation.
    pub request_id: u64,
    /// PID of the process that issued the syscall (audit only).
    pub caller_pid: u64,
    /// When `true`, the runtime L2-normalizes the returned vector (so a dot
    /// product is the cosine similarity).
    pub normalize: bool,
}

impl AiEmbedRequest {
    /// Validates the request against the ABI bounds the kernel enforces.
    ///
    /// # Errors
    ///
    /// An [`AiEmbedReject`] naming the first bound violated.
    pub fn validate(&self) -> Result<(), AiEmbedReject> {
        if self.input_data.len() > AI_MAX_PAYLOAD {
            return Err(AiEmbedReject::InputTooLarge);
        }
        if self.capability.len() > AI_MAX_PAYLOAD {
            return Err(AiEmbedReject::CapabilityTooLarge);
        }
        Ok(())
    }
}

/// The runtime's reply to an [`AiEmbedRequest`]: the dense embedding vector, or
/// an error.
///
/// Carries `f32` data, so it is `PartialEq` but not `Eq`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AiEmbedding {
    /// Echoes [`AiEmbedRequest::request_id`] for correlation.
    pub request_id: u64,
    /// `true` if embedding succeeded; `false` on any error.
    pub success: bool,
    /// The dense embedding (empty on error), at most [`AI_EMBED_MAX_DIM`] wide.
    pub vector: Vec<f32>,
    /// Human-readable error description when `success` is `false` (no caller
    /// content — classification + cause only).
    pub error_message: Option<String>,
}

impl AiEmbedding {
    /// A success reply carrying `vector`.
    #[must_use]
    pub fn ok(request_id: u64, vector: Vec<f32>) -> Self {
        Self {
            request_id,
            success: true,
            vector,
            error_message: None,
        }
    }

    /// An error reply (empty vector).
    #[must_use]
    pub fn error(request_id: u64, message: impl Into<String>) -> Self {
        Self {
            request_id,
            success: false,
            vector: Vec::new(),
            error_message: Some(message.into()),
        }
    }

    /// The embedding dimension (vector length).
    #[must_use]
    pub fn dim(&self) -> usize {
        self.vector.len()
    }

    /// Validates the embedding's dimension against [`AI_EMBED_MAX_DIM`].
    ///
    /// # Errors
    ///
    /// [`AiEmbedReject::DimTooLarge`] if the vector is over the bound.
    pub fn validate(&self) -> Result<(), AiEmbedReject> {
        if self.vector.len() > AI_EMBED_MAX_DIM {
            return Err(AiEmbedReject::DimTooLarge);
        }
        Ok(())
    }
}

// =============================================================================
// `ai_classify` syscall ABI (WS5-03.6)
// =============================================================================

/// Hard ceiling on the number of `(label, score)` pairs a classification may
/// return.
///
/// Bounds [`AiClassification::labels`] (and the request's `top_k`) so a hostile
/// or misconfigured model cannot force the caller to allocate an unbounded
/// result set. Comfortably above any practical label set served over the relay.
pub const AI_CLASSIFY_MAX_LABELS: usize = 256;

/// Hard ceiling on a single class label's UTF-8 byte length.
///
/// Bounds [`ScoredLabel::label`] so one pathological label cannot inflate a
/// response past a small fixed size.
pub const AI_CLASSIFY_LABEL_MAX_LEN: usize = 128;

/// Why an [`AiClassifyRequest`], [`ScoredLabel`], or [`AiClassification`] failed
/// its host-side `validate` check (mirrors the kernel's `EINVAL` reasons).
///
/// A local validation verdict, **not** a wire type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AiClassifyReject {
    /// `input_data` exceeds [`AI_MAX_PAYLOAD`].
    InputTooLarge,
    /// `capability` exceeds [`AI_MAX_PAYLOAD`].
    CapabilityTooLarge,
    /// `top_k` (request) or the returned label count (response) exceeds
    /// [`AI_CLASSIFY_MAX_LABELS`].
    TooManyLabels,
    /// A label's UTF-8 length exceeds [`AI_CLASSIFY_LABEL_MAX_LEN`].
    LabelTooLong,
    /// A score is not a finite value in `[0.0, 1.0]`.
    ScoreOutOfRange,
}

impl core::fmt::Display for AiClassifyReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::InputTooLarge => "ai_classify: input payload exceeds AI_MAX_PAYLOAD",
            Self::CapabilityTooLarge => "ai_classify: capability exceeds AI_MAX_PAYLOAD",
            Self::TooManyLabels => "ai_classify: label count exceeds AI_CLASSIFY_MAX_LABELS",
            Self::LabelTooLong => "ai_classify: label exceeds AI_CLASSIFY_LABEL_MAX_LEN",
            Self::ScoreOutOfRange => "ai_classify: score is not a finite value in [0.0, 1.0]",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for AiClassifyReject {}

/// A request to classify a piece of text into labels (postcard over the `ai`
/// relay channel).
///
/// The runtime runs the model's classification head over `input_data` and
/// returns the scored labels as an [`AiClassification`]. Field semantics match
/// [`AiSyscallRequest`]; `top_k` is the classification-specific control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiClassifyRequest {
    /// Compact 16-byte model identifier (zero-extended by the runtime).
    pub model_id_bytes: [u8; 16],
    /// Opaque session-capability bytes (validated service-side).
    pub capability: Vec<u8>,
    /// UTF-8 text to classify (≤ [`AI_MAX_PAYLOAD`]).
    pub input_data: Vec<u8>,
    /// Caller-assigned monotonic request ID for end-to-end correlation.
    pub request_id: u64,
    /// PID of the process that issued the syscall (audit only).
    pub caller_pid: u64,
    /// Maximum number of top-scoring labels to return, ordered by descending
    /// score. `0` requests every label the model exposes (still capped at
    /// [`AI_CLASSIFY_MAX_LABELS`]).
    pub top_k: u32,
}

impl AiClassifyRequest {
    /// Validates the request against the ABI bounds the kernel enforces.
    ///
    /// # Errors
    ///
    /// An [`AiClassifyReject`] naming the first bound violated.
    pub fn validate(&self) -> Result<(), AiClassifyReject> {
        if self.input_data.len() > AI_MAX_PAYLOAD {
            return Err(AiClassifyReject::InputTooLarge);
        }
        if self.capability.len() > AI_MAX_PAYLOAD {
            return Err(AiClassifyReject::CapabilityTooLarge);
        }
        // `top_k` always fits a `usize` on every real target; treat the
        // impossible 16-bit-`usize` overflow as "too many" rather than casting.
        let top_k = usize::try_from(self.top_k).unwrap_or(usize::MAX);
        if top_k > AI_CLASSIFY_MAX_LABELS {
            return Err(AiClassifyReject::TooManyLabels);
        }
        Ok(())
    }
}

/// One `(label, score)` pair from a classification result.
///
/// `score` is the model's confidence for `label`, a softmax probability in
/// `[0.0, 1.0]`. Carries `f32`, so it is `PartialEq` but not `Eq`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScoredLabel {
    /// The class label (UTF-8, ≤ [`AI_CLASSIFY_LABEL_MAX_LEN`] bytes).
    pub label: String,
    /// Confidence for `label`, a softmax probability in `[0.0, 1.0]`.
    pub score: f32,
}

impl ScoredLabel {
    /// Builds a scored label.
    #[must_use]
    pub fn new(label: impl Into<String>, score: f32) -> Self {
        Self {
            label: label.into(),
            score,
        }
    }

    /// Validates the label length and the score range.
    ///
    /// # Errors
    ///
    /// [`AiClassifyReject::LabelTooLong`] if `label` is over the byte bound, or
    /// [`AiClassifyReject::ScoreOutOfRange`] if `score` is not a finite value in
    /// `[0.0, 1.0]` (the range check also rejects `NaN`/infinities).
    pub fn validate(&self) -> Result<(), AiClassifyReject> {
        if self.label.len() > AI_CLASSIFY_LABEL_MAX_LEN {
            return Err(AiClassifyReject::LabelTooLong);
        }
        if !(0.0..=1.0).contains(&self.score) {
            return Err(AiClassifyReject::ScoreOutOfRange);
        }
        Ok(())
    }
}

/// The runtime's reply to an [`AiClassifyRequest`]: the scored labels (ordered
/// by descending score), or an error.
///
/// Carries `f32` scores, so it is `PartialEq` but not `Eq`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AiClassification {
    /// Echoes [`AiClassifyRequest::request_id`] for correlation.
    pub request_id: u64,
    /// `true` if classification succeeded; `false` on any error.
    pub success: bool,
    /// The scored labels (empty on error), at most [`AI_CLASSIFY_MAX_LABELS`]
    /// long, ordered by descending [`ScoredLabel::score`].
    pub labels: Vec<ScoredLabel>,
    /// Human-readable error description when `success` is `false` (no caller
    /// content — classification + cause only).
    pub error_message: Option<String>,
}

impl AiClassification {
    /// A success reply carrying `labels`.
    #[must_use]
    pub fn ok(request_id: u64, labels: Vec<ScoredLabel>) -> Self {
        Self {
            request_id,
            success: true,
            labels,
            error_message: None,
        }
    }

    /// An error reply (no labels).
    #[must_use]
    pub fn error(request_id: u64, message: impl Into<String>) -> Self {
        Self {
            request_id,
            success: false,
            labels: Vec::new(),
            error_message: Some(message.into()),
        }
    }

    /// The number of returned labels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// `true` when no labels were returned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// The highest-scoring label — the first, by the descending-score
    /// convention. `None` for an empty/error result.
    #[must_use]
    pub fn best(&self) -> Option<&ScoredLabel> {
        self.labels.first()
    }

    /// Validates the label count and every label.
    ///
    /// # Errors
    ///
    /// [`AiClassifyReject::TooManyLabels`] if the count is over the bound, else
    /// the first per-label rejection from [`ScoredLabel::validate`].
    pub fn validate(&self) -> Result<(), AiClassifyReject> {
        if self.labels.len() > AI_CLASSIFY_MAX_LABELS {
            return Err(AiClassifyReject::TooManyLabels);
        }
        for label in &self.labels {
            label.validate()?;
        }
        Ok(())
    }
}

// =============================================================================
// `ai_transcribe` syscall ABI (WS5-03.8) — hooked to the audio buffer (WS2-10)
// =============================================================================

/// Hard ceiling on the referenced audio of one `ai_transcribe` request, in
/// bytes (16 `MiB` ≈ several minutes of 16 kHz mono PCM).
///
/// Captured audio is far larger than the 4 `KiB` relay payload, so an
/// `ai_transcribe` request **references** a captured buffer (an
/// [`AudioBufferRef`] the audio stack — WS2-10 — fills) rather than inlining
/// the samples; this bounds how much the runtime maps and decodes per call.
pub const AI_TRANSCRIBE_MAX_AUDIO_BYTES: usize = 16 * 1024 * 1024;

/// Hard ceiling on the transcript text the runtime returns (64 `KiB`).
pub const AI_TRANSCRIBE_MAX_TEXT: usize = 64 * 1024;

/// Largest PCM channel count the ABI accepts.
pub const AI_TRANSCRIBE_MAX_CHANNELS: u8 = 8;

/// Largest PCM sample rate the ABI accepts, in Hz.
pub const AI_TRANSCRIBE_MAX_SAMPLE_RATE: u32 = 384_000;

/// Largest BCP-47 language tag the ABI accepts, in bytes (e.g. `en`,
/// `zh-Hant`).
pub const AI_TRANSCRIBE_MAX_LANGUAGE_LEN: usize = 16;

/// PCM sample encoding of a captured audio buffer.
///
/// # Wire encoding
///
/// A postcard unit-enum discriminant. **Variant order is wire-stable**
/// (`S16Le` = 0, `F32Le` = 1); reordering is a wire-format breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PcmEncoding {
    /// Signed 16-bit little-endian samples.
    S16Le,
    /// 32-bit IEEE-754 float little-endian samples.
    F32Le,
}

impl PcmEncoding {
    /// Bytes per single-channel sample (2 for `S16Le`, 4 for `F32Le`).
    #[must_use]
    pub const fn bytes_per_sample(self) -> usize {
        match self {
            Self::S16Le => 2,
            Self::F32Le => 4,
        }
    }
}

/// The PCM layout of a captured audio buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AudioFormat {
    /// Sample rate in Hz (e.g. 16000 for speech models).
    pub sample_rate: u32,
    /// Interleaved channel count (1 = mono, 2 = stereo).
    pub channels: u8,
    /// How each sample is encoded.
    pub encoding: PcmEncoding,
}

impl AudioFormat {
    /// Bytes per interleaved frame (`bytes_per_sample × channels`).
    #[must_use]
    pub fn frame_size(self) -> usize {
        self.encoding.bytes_per_sample() * usize::from(self.channels)
    }

    /// Validates the channel count and sample rate against the ABI bounds.
    ///
    /// # Errors
    ///
    /// [`AiTranscribeReject::InvalidChannels`] or
    /// [`AiTranscribeReject::InvalidSampleRate`] for an out-of-range field.
    pub fn validate(self) -> Result<(), AiTranscribeReject> {
        if self.channels == 0 || self.channels > AI_TRANSCRIBE_MAX_CHANNELS {
            return Err(AiTranscribeReject::InvalidChannels);
        }
        if self.sample_rate == 0 || self.sample_rate > AI_TRANSCRIBE_MAX_SAMPLE_RATE {
            return Err(AiTranscribeReject::InvalidSampleRate);
        }
        Ok(())
    }
}

/// A reference to a captured audio buffer the runtime transcribes.
///
/// `handle` identifies the shared capture buffer the audio stack (WS2-10)
/// produced; `len_bytes` is the number of valid PCM bytes in it, laid out per
/// `format`. The runtime maps the buffer and decodes `len_bytes` of samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioBufferRef {
    /// Opaque handle to the captured shared audio buffer (from WS2-10 capture).
    pub handle: u64,
    /// The PCM layout of the buffer.
    pub format: AudioFormat,
    /// Number of valid PCM bytes (≤ [`AI_TRANSCRIBE_MAX_AUDIO_BYTES`]).
    pub len_bytes: u64,
}

impl AudioBufferRef {
    /// Number of whole PCM frames in the buffer (`len_bytes / frame_size`).
    ///
    /// `None` if the frame size is zero (an unvalidated zero-channel format) or
    /// `len_bytes` overflows `usize` on this target.
    #[must_use]
    pub fn num_frames(self) -> Option<usize> {
        let len = usize::try_from(self.len_bytes).ok()?;
        len.checked_div(self.format.frame_size())
    }

    /// Validates the format and the buffer length.
    ///
    /// # Errors
    ///
    /// An [`AiTranscribeReject`] for the first violated bound: a bad format,
    /// empty audio, audio over [`AI_TRANSCRIBE_MAX_AUDIO_BYTES`], or a length
    /// that is not a whole number of frames.
    pub fn validate(self) -> Result<(), AiTranscribeReject> {
        self.format.validate()?;
        let len = usize::try_from(self.len_bytes).unwrap_or(usize::MAX);
        if len == 0 {
            return Err(AiTranscribeReject::EmptyAudio);
        }
        if len > AI_TRANSCRIBE_MAX_AUDIO_BYTES {
            return Err(AiTranscribeReject::AudioTooLarge);
        }
        // `checked_rem` avoids the modulo operator and a zero frame size.
        if len.checked_rem(self.format.frame_size()) != Some(0) {
            return Err(AiTranscribeReject::UnalignedAudio);
        }
        Ok(())
    }
}

/// Why an `ai_transcribe` request or response failed its host-side `validate`
/// check (mirrors the kernel's `EINVAL` reasons).
///
/// A local validation verdict, **not** a wire type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AiTranscribeReject {
    /// `capability` exceeds [`AI_MAX_PAYLOAD`].
    CapabilityTooLarge,
    /// The referenced audio buffer is empty (`len_bytes == 0`).
    EmptyAudio,
    /// The referenced audio exceeds [`AI_TRANSCRIBE_MAX_AUDIO_BYTES`].
    AudioTooLarge,
    /// `len_bytes` is not a whole number of PCM frames for the format.
    UnalignedAudio,
    /// `channels` is zero or exceeds [`AI_TRANSCRIBE_MAX_CHANNELS`].
    InvalidChannels,
    /// `sample_rate` is zero or exceeds [`AI_TRANSCRIBE_MAX_SAMPLE_RATE`].
    InvalidSampleRate,
    /// A language tag exceeds [`AI_TRANSCRIBE_MAX_LANGUAGE_LEN`].
    LanguageTagTooLong,
    /// The transcript text exceeds [`AI_TRANSCRIBE_MAX_TEXT`].
    TextTooLarge,
}

impl core::fmt::Display for AiTranscribeReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::CapabilityTooLarge => "ai_transcribe: capability exceeds AI_MAX_PAYLOAD",
            Self::EmptyAudio => "ai_transcribe: referenced audio buffer is empty",
            Self::AudioTooLarge => "ai_transcribe: audio exceeds AI_TRANSCRIBE_MAX_AUDIO_BYTES",
            Self::UnalignedAudio => "ai_transcribe: audio length is not a whole number of frames",
            Self::InvalidChannels => "ai_transcribe: channel count is zero or exceeds the maximum",
            Self::InvalidSampleRate => "ai_transcribe: sample rate is zero or exceeds the maximum",
            Self::LanguageTagTooLong => {
                "ai_transcribe: language tag exceeds AI_TRANSCRIBE_MAX_LANGUAGE_LEN"
            }
            Self::TextTooLarge => "ai_transcribe: transcript exceeds AI_TRANSCRIBE_MAX_TEXT",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for AiTranscribeReject {}

/// A request to transcribe a captured audio buffer to text (postcard over the
/// `ai` relay channel).
///
/// The audio itself is referenced via [`AudioBufferRef`] (it does not fit the
/// inline payload); `language` is an optional BCP-47 hint for the model. Field
/// semantics otherwise match [`AiSyscallRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiTranscribeRequest {
    /// Compact 16-byte model identifier (zero-extended by the runtime).
    pub model_id_bytes: [u8; 16],
    /// Opaque session-capability bytes (validated service-side).
    pub capability: Vec<u8>,
    /// Caller-assigned monotonic request ID for end-to-end correlation.
    pub request_id: u64,
    /// PID of the process that issued the syscall (audit only).
    pub caller_pid: u64,
    /// The captured audio buffer to transcribe.
    pub audio: AudioBufferRef,
    /// Optional BCP-47 language hint (≤ [`AI_TRANSCRIBE_MAX_LANGUAGE_LEN`]).
    pub language: Option<String>,
}

impl AiTranscribeRequest {
    /// Validates the request against the ABI bounds the kernel enforces.
    ///
    /// # Errors
    ///
    /// An [`AiTranscribeReject`] naming the first bound violated.
    pub fn validate(&self) -> Result<(), AiTranscribeReject> {
        if self.capability.len() > AI_MAX_PAYLOAD {
            return Err(AiTranscribeReject::CapabilityTooLarge);
        }
        self.audio.validate()?;
        if self
            .language
            .as_ref()
            .is_some_and(|l| l.len() > AI_TRANSCRIBE_MAX_LANGUAGE_LEN)
        {
            return Err(AiTranscribeReject::LanguageTagTooLong);
        }
        Ok(())
    }
}

/// The runtime's reply to an [`AiTranscribeRequest`]: the transcript text (and
/// optional detected language), or an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiTranscription {
    /// Echoes [`AiTranscribeRequest::request_id`] for correlation.
    pub request_id: u64,
    /// `true` if transcription succeeded; `false` on any error.
    pub success: bool,
    /// The transcript (empty on error), at most [`AI_TRANSCRIBE_MAX_TEXT`]
    /// bytes.
    pub text: String,
    /// The detected BCP-47 language when the model reports one.
    pub language: Option<String>,
    /// Human-readable error description when `success` is `false` (no caller
    /// content — classification + cause only).
    pub error_message: Option<String>,
}

impl AiTranscription {
    /// A success reply carrying `text` (no detected language).
    #[must_use]
    pub fn ok(request_id: u64, text: impl Into<String>) -> Self {
        Self {
            request_id,
            success: true,
            text: text.into(),
            language: None,
            error_message: None,
        }
    }

    /// A success reply carrying `text` and the detected `language`.
    #[must_use]
    pub fn ok_with_language(
        request_id: u64,
        text: impl Into<String>,
        language: impl Into<String>,
    ) -> Self {
        Self {
            request_id,
            success: true,
            text: text.into(),
            language: Some(language.into()),
            error_message: None,
        }
    }

    /// An error reply (empty transcript).
    #[must_use]
    pub fn error(request_id: u64, message: impl Into<String>) -> Self {
        Self {
            request_id,
            success: false,
            text: String::new(),
            language: None,
            error_message: Some(message.into()),
        }
    }

    /// Validates the transcript and language lengths.
    ///
    /// # Errors
    ///
    /// [`AiTranscribeReject::TextTooLarge`] or
    /// [`AiTranscribeReject::LanguageTagTooLong`] for an over-bound field.
    pub fn validate(&self) -> Result<(), AiTranscribeReject> {
        if self.text.len() > AI_TRANSCRIBE_MAX_TEXT {
            return Err(AiTranscribeReject::TextTooLarge);
        }
        if self
            .language
            .as_ref()
            .is_some_and(|l| l.len() > AI_TRANSCRIBE_MAX_LANGUAGE_LEN)
        {
            return Err(AiTranscribeReject::LanguageTagTooLong);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_canonical, encode_canonical};

    #[test]
    fn backend_kind_labels_are_stable() {
        assert_eq!(BackendKind::RemoteGpu.label(), "remote_gpu");
        assert_eq!(BackendKind::LocalCpu.label(), "local_cpu");
    }

    #[test]
    fn backend_kind_wire_discriminants_are_stable() {
        // Pin the postcard discriminants: RemoteGpu = 0, LocalCpu = 1.
        // A failure here means the variant order changed — a wire-format
        // breaking change that must not happen silently.
        let gpu = encode_canonical(&BackendKind::RemoteGpu).expect("encode");
        let cpu = encode_canonical(&BackendKind::LocalCpu).expect("encode");
        assert_eq!(gpu, alloc::vec![0]);
        assert_eq!(cpu, alloc::vec![1]);
    }

    #[test]
    fn backend_status_event_round_trips() {
        for (backend, healthy, degraded) in [
            (BackendKind::RemoteGpu, true, false),
            (BackendKind::RemoteGpu, false, false),
            (BackendKind::LocalCpu, true, true),
            (BackendKind::LocalCpu, false, true),
        ] {
            let event = BackendStatusEvent {
                backend,
                healthy,
                degraded,
            };
            let bytes = encode_canonical(&event).expect("encode");
            let back: BackendStatusEvent = decode_canonical(&bytes).expect("decode");
            assert_eq!(back, event);
        }
    }

    // ---- AI syscall relay wire types (TASK-11) ---------------------------

    #[test]
    fn ai_syscall_number_maps_kernel_abi() {
        for n in 80u32..=84 {
            let v = AiSyscallNumber::from_u32(n).expect("in range");
            assert_eq!(v.as_u32(), n);
        }
        assert!(AiSyscallNumber::from_u32(79).is_none());
        assert!(AiSyscallNumber::from_u32(85).is_none());
    }

    #[test]
    fn ai_syscall_number_wire_discriminants_are_stable() {
        // postcard encodes the variant INDEX (0..=4), not the syscall
        // number — pin it so reordering cannot slip through silently.
        let invoke = encode_canonical(&AiSyscallNumber::Invoke).expect("encode");
        let transcribe = encode_canonical(&AiSyscallNumber::Transcribe).expect("encode");
        assert_eq!(invoke, alloc::vec![0]);
        assert_eq!(transcribe, alloc::vec![4]);
    }

    #[test]
    fn ai_syscall_request_round_trips() {
        let req = AiSyscallRequest {
            syscall: AiSyscallNumber::Invoke,
            model_id_bytes: [0xAB; 16],
            capability: alloc::vec![0x01, 0x02],
            input_data: alloc::vec![b'h', b'i'],
            request_id: 42,
            caller_pid: 7,
        };
        let bytes = encode_canonical(&req).expect("encode");
        let back: AiSyscallRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn ai_syscall_response_round_trips_success_and_error() {
        let ok = AiSyscallResponse {
            request_id: 1,
            success: true,
            output_data: alloc::vec![1, 2, 3],
            latency_us: 99,
            error_message: None,
        };
        let bytes = encode_canonical(&ok).expect("encode");
        let back: AiSyscallResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ok);

        let err = AiSyscallResponse::error(2, 5, "nope");
        assert!(!err.success);
        assert!(err.output_data.is_empty());
        let bytes = encode_canonical(&err).expect("encode");
        let back: AiSyscallResponse = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, err);
    }

    #[test]
    fn ai_max_payload_matches_kernel_bound() {
        assert_eq!(AI_MAX_PAYLOAD, 4096);
    }

    // ---- ai_stream syscall ABI (WS5-03.1) --------------------------------

    #[test]
    fn ai_stream_handle_wraps_and_unwraps() {
        let h = AiStreamHandle::new(0xDEAD_BEEF);
        assert_eq!(h.get(), 0xDEAD_BEEF);
        assert_eq!(AiStreamHandle(7), AiStreamHandle::new(7));
        // Encodes as the bare inner u64 (postcard varint).
        let bytes = encode_canonical(&AiStreamHandle::new(1)).expect("encode");
        let back: AiStreamHandle = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, AiStreamHandle::new(1));
    }

    fn sample_request() -> AiStreamRequest {
        AiStreamRequest {
            model_id_bytes: [0x11; 16],
            capability: alloc::vec![0x01],
            input_data: alloc::vec![b'h', b'i'],
            request_id: 9,
            caller_pid: 3,
            max_tokens: 128,
        }
    }

    #[test]
    fn ai_stream_request_round_trips() {
        let req = sample_request();
        let bytes = encode_canonical(&req).expect("encode");
        let back: AiStreamRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn ai_stream_request_validate_accepts_and_rejects() {
        assert_eq!(sample_request().validate(), Ok(()));

        let mut big_input = sample_request();
        big_input.input_data = alloc::vec![0u8; AI_MAX_PAYLOAD + 1];
        assert_eq!(big_input.validate(), Err(AiStreamReject::InputTooLarge));

        let mut big_cap = sample_request();
        big_cap.capability = alloc::vec![0u8; AI_MAX_PAYLOAD + 1];
        assert_eq!(big_cap.validate(), Err(AiStreamReject::CapabilityTooLarge));

        let mut zero = sample_request();
        zero.max_tokens = 0;
        assert_eq!(zero.validate(), Err(AiStreamReject::NoTokensRequested));

        let mut too_many = sample_request();
        too_many.max_tokens = AI_STREAM_MAX_TOKENS + 1;
        assert_eq!(too_many.validate(), Err(AiStreamReject::TooManyTokens));

        // The exact bound is accepted.
        let mut at_limit = sample_request();
        at_limit.max_tokens = AI_STREAM_MAX_TOKENS;
        assert_eq!(at_limit.validate(), Ok(()));
    }

    #[test]
    fn ai_stream_opened_ok_and_error_round_trip() {
        let ok = AiStreamOpened::ok(9, AiStreamHandle::new(5));
        assert!(ok.success);
        assert_eq!(ok.handle, Some(AiStreamHandle::new(5)));
        let bytes = encode_canonical(&ok).expect("encode");
        let back: AiStreamOpened = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ok);

        let err = AiStreamOpened::error(9, "no capacity");
        assert!(!err.success);
        assert!(err.handle.is_none());
        let bytes = encode_canonical(&err).expect("encode");
        let back: AiStreamOpened = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, err);
    }

    #[test]
    fn ai_token_chunk_round_trips_and_validates() {
        let chunk = AiTokenChunk::new(AiStreamHandle::new(5), 9, 0, 1234, alloc::vec![b'h'], false);
        let bytes = encode_canonical(&chunk).expect("encode");
        let back: AiTokenChunk = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, chunk);
        assert_eq!(chunk.validate(), Ok(()));

        let last = AiTokenChunk::new(AiStreamHandle::new(5), 9, 7, 2, Vec::new(), true);
        assert!(last.is_last);
        assert_eq!(last.validate(), Ok(()));

        let mut huge = chunk;
        huge.text = alloc::vec![0u8; AI_STREAM_CHUNK_MAX_TEXT + 1];
        assert_eq!(huge.validate(), Err(AiStreamReject::ChunkTextTooLarge));
    }

    #[test]
    fn ai_stream_reject_displays_cause() {
        use core::fmt::Write as _;
        let mut s = String::new();
        write!(s, "{}", AiStreamReject::TooManyTokens).expect("write");
        assert!(s.contains("AI_STREAM_MAX_TOKENS"));
    }

    // ---- ai_embed syscall ABI (WS5-03.4) ---------------------------------

    fn sample_embed_request() -> AiEmbedRequest {
        AiEmbedRequest {
            model_id_bytes: [0x22; 16],
            capability: alloc::vec![0x09],
            input_data: alloc::vec![b'h', b'i'],
            request_id: 11,
            caller_pid: 4,
            normalize: true,
        }
    }

    #[test]
    fn ai_embed_request_round_trips() {
        let req = sample_embed_request();
        let bytes = encode_canonical(&req).expect("encode");
        let back: AiEmbedRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn ai_embed_request_validate_accepts_and_rejects() {
        assert_eq!(sample_embed_request().validate(), Ok(()));

        let mut big_input = sample_embed_request();
        big_input.input_data = alloc::vec![0u8; AI_MAX_PAYLOAD + 1];
        assert_eq!(big_input.validate(), Err(AiEmbedReject::InputTooLarge));

        let mut big_cap = sample_embed_request();
        big_cap.capability = alloc::vec![0u8; AI_MAX_PAYLOAD + 1];
        assert_eq!(big_cap.validate(), Err(AiEmbedReject::CapabilityTooLarge));
    }

    #[test]
    fn ai_embedding_round_trips_and_reports_dim() {
        let emb = AiEmbedding::ok(11, alloc::vec![0.0, 1.0, -2.5, 3.25]);
        assert!(emb.success);
        assert_eq!(emb.dim(), 4);
        assert_eq!(emb.validate(), Ok(()));
        let bytes = encode_canonical(&emb).expect("encode");
        let back: AiEmbedding = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, emb);

        let err = AiEmbedding::error(11, "no model");
        assert!(!err.success);
        assert_eq!(err.dim(), 0);
        let bytes = encode_canonical(&err).expect("encode");
        let back: AiEmbedding = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, err);
    }

    #[test]
    fn ai_embedding_validate_rejects_oversize_dim() {
        let huge = AiEmbedding::ok(1, alloc::vec![0.0_f32; AI_EMBED_MAX_DIM + 1]);
        assert_eq!(huge.validate(), Err(AiEmbedReject::DimTooLarge));
        // The exact bound is accepted.
        let at_limit = AiEmbedding::ok(1, alloc::vec![0.0_f32; AI_EMBED_MAX_DIM]);
        assert_eq!(at_limit.validate(), Ok(()));
    }

    // ---- ai_classify syscall ABI (WS5-03.6) ------------------------------

    fn sample_classify_request() -> AiClassifyRequest {
        AiClassifyRequest {
            model_id_bytes: [0x33; 16],
            capability: alloc::vec![0x07],
            input_data: alloc::vec![b'o', b'k'],
            request_id: 13,
            caller_pid: 5,
            top_k: 3,
        }
    }

    #[test]
    fn ai_classify_request_round_trips() {
        let req = sample_classify_request();
        let bytes = encode_canonical(&req).expect("encode");
        let back: AiClassifyRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn ai_classify_request_validate_accepts_and_rejects() {
        assert_eq!(sample_classify_request().validate(), Ok(()));

        // `top_k == 0` means "all labels" and is accepted.
        let mut all = sample_classify_request();
        all.top_k = 0;
        assert_eq!(all.validate(), Ok(()));

        let mut big_input = sample_classify_request();
        big_input.input_data = alloc::vec![0u8; AI_MAX_PAYLOAD + 1];
        assert_eq!(big_input.validate(), Err(AiClassifyReject::InputTooLarge));

        let mut big_cap = sample_classify_request();
        big_cap.capability = alloc::vec![0u8; AI_MAX_PAYLOAD + 1];
        assert_eq!(
            big_cap.validate(),
            Err(AiClassifyReject::CapabilityTooLarge)
        );

        let max_labels = u32::try_from(AI_CLASSIFY_MAX_LABELS).expect("fits u32");
        let mut too_many = sample_classify_request();
        too_many.top_k = max_labels + 1;
        assert_eq!(too_many.validate(), Err(AiClassifyReject::TooManyLabels));

        // The exact bound is accepted.
        let mut at_limit = sample_classify_request();
        at_limit.top_k = max_labels;
        assert_eq!(at_limit.validate(), Ok(()));
    }

    #[test]
    fn scored_label_validate_accepts_and_rejects() {
        assert_eq!(ScoredLabel::new("positive", 0.5).validate(), Ok(()));
        // Range endpoints are accepted.
        assert_eq!(ScoredLabel::new("p", 0.0).validate(), Ok(()));
        assert_eq!(ScoredLabel::new("p", 1.0).validate(), Ok(()));

        let long = String::from_utf8(alloc::vec![b'a'; AI_CLASSIFY_LABEL_MAX_LEN + 1])
            .expect("ascii is valid utf-8");
        assert_eq!(
            ScoredLabel::new(long, 0.5).validate(),
            Err(AiClassifyReject::LabelTooLong)
        );

        for bad in [1.5_f32, -0.1, f32::NAN, f32::INFINITY] {
            assert_eq!(
                ScoredLabel::new("x", bad).validate(),
                Err(AiClassifyReject::ScoreOutOfRange)
            );
        }
    }

    #[test]
    fn ai_classification_round_trips_and_reports_best() {
        let labels = alloc::vec![
            ScoredLabel::new("positive", 0.9),
            ScoredLabel::new("neutral", 0.08),
            ScoredLabel::new("negative", 0.02),
        ];
        let res = AiClassification::ok(13, labels);
        assert!(res.success);
        assert_eq!(res.len(), 3);
        assert!(!res.is_empty());
        let best = res.best().expect("non-empty");
        // Struct equality (derived `PartialEq`) avoids a direct float compare.
        assert_eq!(*best, ScoredLabel::new("positive", 0.9));
        assert_eq!(res.validate(), Ok(()));
        let bytes = encode_canonical(&res).expect("encode");
        let back: AiClassification = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, res);

        let err = AiClassification::error(13, "no head");
        assert!(!err.success);
        assert!(err.is_empty());
        assert!(err.best().is_none());
        let bytes = encode_canonical(&err).expect("encode");
        let back: AiClassification = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, err);
    }

    #[test]
    fn ai_classification_validate_rejects_count_and_bad_labels() {
        let too_many = AiClassification::ok(
            1,
            alloc::vec![ScoredLabel::new("x", 0.5); AI_CLASSIFY_MAX_LABELS + 1],
        );
        assert_eq!(too_many.validate(), Err(AiClassifyReject::TooManyLabels));

        // The exact bound is accepted.
        let at_limit = AiClassification::ok(
            1,
            alloc::vec![ScoredLabel::new("x", 0.5); AI_CLASSIFY_MAX_LABELS],
        );
        assert_eq!(at_limit.validate(), Ok(()));

        // A per-label rejection propagates.
        let bad_score = AiClassification::ok(1, alloc::vec![ScoredLabel::new("x", 2.0)]);
        assert_eq!(bad_score.validate(), Err(AiClassifyReject::ScoreOutOfRange));
    }

    #[test]
    fn ai_classify_reject_displays_cause() {
        use core::fmt::Write as _;
        let mut s = String::new();
        write!(s, "{}", AiClassifyReject::TooManyLabels).expect("write");
        assert!(s.contains("AI_CLASSIFY_MAX_LABELS"));
    }

    // ---- ai_transcribe syscall ABI (WS5-03.8) ----------------------------

    fn sample_format() -> AudioFormat {
        AudioFormat {
            sample_rate: 16_000,
            channels: 1,
            encoding: PcmEncoding::S16Le,
        }
    }

    fn sample_audio() -> AudioBufferRef {
        AudioBufferRef {
            handle: 0xAB,
            format: sample_format(),
            len_bytes: 3200, // 100 ms of 16 kHz mono S16 = 1600 frames.
        }
    }

    fn sample_transcribe_request() -> AiTranscribeRequest {
        AiTranscribeRequest {
            model_id_bytes: [0x44; 16],
            capability: alloc::vec![0x05],
            request_id: 21,
            caller_pid: 6,
            audio: sample_audio(),
            language: Some(String::from("en")),
        }
    }

    #[test]
    fn pcm_encoding_wire_discriminants_are_stable() {
        let s16 = encode_canonical(&PcmEncoding::S16Le).expect("encode");
        let f32 = encode_canonical(&PcmEncoding::F32Le).expect("encode");
        assert_eq!(s16, alloc::vec![0]);
        assert_eq!(f32, alloc::vec![1]);
        assert_eq!(PcmEncoding::S16Le.bytes_per_sample(), 2);
        assert_eq!(PcmEncoding::F32Le.bytes_per_sample(), 4);
    }

    #[test]
    fn audio_format_frame_size_and_validate() {
        assert_eq!(sample_format().frame_size(), 2); // mono S16
        let stereo_f32 = AudioFormat {
            sample_rate: 48_000,
            channels: 2,
            encoding: PcmEncoding::F32Le,
        };
        assert_eq!(stereo_f32.frame_size(), 8); // 2 ch * 4 bytes

        assert_eq!(sample_format().validate(), Ok(()));
        let zero_ch = AudioFormat {
            channels: 0,
            ..sample_format()
        };
        assert_eq!(zero_ch.validate(), Err(AiTranscribeReject::InvalidChannels));
        let many_ch = AudioFormat {
            channels: AI_TRANSCRIBE_MAX_CHANNELS + 1,
            ..sample_format()
        };
        assert_eq!(many_ch.validate(), Err(AiTranscribeReject::InvalidChannels));
        let zero_rate = AudioFormat {
            sample_rate: 0,
            ..sample_format()
        };
        assert_eq!(
            zero_rate.validate(),
            Err(AiTranscribeReject::InvalidSampleRate)
        );
        let fast = AudioFormat {
            sample_rate: AI_TRANSCRIBE_MAX_SAMPLE_RATE + 1,
            ..sample_format()
        };
        assert_eq!(fast.validate(), Err(AiTranscribeReject::InvalidSampleRate));
    }

    #[test]
    fn audio_buffer_ref_validate_and_frame_count() {
        assert_eq!(sample_audio().validate(), Ok(()));
        assert_eq!(sample_audio().num_frames(), Some(1600));

        let empty = AudioBufferRef {
            len_bytes: 0,
            ..sample_audio()
        };
        assert_eq!(empty.validate(), Err(AiTranscribeReject::EmptyAudio));

        let big = AudioBufferRef {
            len_bytes: u64::try_from(AI_TRANSCRIBE_MAX_AUDIO_BYTES).expect("fits") + 2,
            ..sample_audio()
        };
        assert_eq!(big.validate(), Err(AiTranscribeReject::AudioTooLarge));

        // F32Le stereo -> frame size 8; 10 bytes is not a whole frame.
        let unaligned = AudioBufferRef {
            handle: 1,
            format: AudioFormat {
                sample_rate: 48_000,
                channels: 2,
                encoding: PcmEncoding::F32Le,
            },
            len_bytes: 10,
        };
        assert_eq!(
            unaligned.validate(),
            Err(AiTranscribeReject::UnalignedAudio)
        );
    }

    #[test]
    fn ai_transcribe_request_round_trips() {
        let req = sample_transcribe_request();
        let bytes = encode_canonical(&req).expect("encode");
        let back: AiTranscribeRequest = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn ai_transcribe_request_validate_accepts_and_rejects() {
        assert_eq!(sample_transcribe_request().validate(), Ok(()));

        let mut big_cap = sample_transcribe_request();
        big_cap.capability = alloc::vec![0u8; AI_MAX_PAYLOAD + 1];
        assert_eq!(
            big_cap.validate(),
            Err(AiTranscribeReject::CapabilityTooLarge)
        );

        // A bad audio buffer propagates its rejection.
        let mut bad_audio = sample_transcribe_request();
        bad_audio.audio.len_bytes = 0;
        assert_eq!(bad_audio.validate(), Err(AiTranscribeReject::EmptyAudio));

        let mut long_lang = sample_transcribe_request();
        long_lang.language = Some(
            String::from_utf8(alloc::vec![b'a'; AI_TRANSCRIBE_MAX_LANGUAGE_LEN + 1])
                .expect("ascii is valid utf-8"),
        );
        assert_eq!(
            long_lang.validate(),
            Err(AiTranscribeReject::LanguageTagTooLong)
        );
    }

    #[test]
    fn ai_transcription_round_trips_and_validates() {
        let ok = AiTranscription::ok(21, "hello world");
        assert!(ok.success);
        assert!(ok.language.is_none());
        assert_eq!(ok.validate(), Ok(()));
        let bytes = encode_canonical(&ok).expect("encode");
        let back: AiTranscription = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, ok);

        let with_lang = AiTranscription::ok_with_language(21, "ciao", "it");
        assert_eq!(with_lang.language.as_deref(), Some("it"));
        let bytes = encode_canonical(&with_lang).expect("encode");
        let back: AiTranscription = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, with_lang);

        let err = AiTranscription::error(21, "no audio model");
        assert!(!err.success);
        assert!(err.text.is_empty());
        let bytes = encode_canonical(&err).expect("encode");
        let back: AiTranscription = decode_canonical(&bytes).expect("decode");
        assert_eq!(back, err);
    }

    #[test]
    fn ai_transcription_validate_rejects_oversize_fields() {
        let big_text = AiTranscription::ok(
            1,
            String::from_utf8(alloc::vec![b'a'; AI_TRANSCRIBE_MAX_TEXT + 1])
                .expect("ascii is valid utf-8"),
        );
        assert_eq!(big_text.validate(), Err(AiTranscribeReject::TextTooLarge));

        let long_lang = AiTranscription::ok_with_language(
            1,
            "x",
            String::from_utf8(alloc::vec![b'a'; AI_TRANSCRIBE_MAX_LANGUAGE_LEN + 1])
                .expect("ascii is valid utf-8"),
        );
        assert_eq!(
            long_lang.validate(),
            Err(AiTranscribeReject::LanguageTagTooLong)
        );
    }

    #[test]
    fn ai_transcribe_reject_displays_cause() {
        use core::fmt::Write as _;
        let mut s = String::new();
        write!(s, "{}", AiTranscribeReject::AudioTooLarge).expect("write");
        assert!(s.contains("AI_TRANSCRIBE_MAX_AUDIO_BYTES"));
    }
}

//! Inference session lifecycle and client-facing request/response API.
//!
//! This module is the primary **external** interface through which application
//! code drives the NexaCore OS AI runtime.  It provides:
//!
//! - [`crate::serving::InferenceSession`] — a state-machine record representing one client
//!   session over its lifetime (`Open` → `Active` → `Closing` → `Closed`).
//! - [`crate::serving::SessionManager`] — owns the live session map and integrates with the
//!   [`crate::batch::BatchScheduler`] to enqueue and drain inference work.
//! - [`crate::serving::ServingRequest`] / [`crate::serving::ServingResponse`] / [`crate::serving::StreamChunk`] — wire types
//!   distinct from the lower-level [`crate::inference`] types; serializable
//!   with `postcard` via [`nexacore_types::wire`].
//! - [`crate::serving::SessionCapability`] — a minimal opaque token used to gate every entry
//!   point.  See the [Capability gating](#capability-gating) section below.
//!
//! # Capability gating
//!
//! Every public entry point checks that the caller supplies a
//! [`crate::serving::SessionCapability`] that is *well-formed*: its inner byte slice is
//! non-empty, the first byte is non-zero, and the total length is in the range
//! `[`[`crate::serving::SessionCapability::MIN_LEN`]`, `[`crate::serving::SessionCapability::MAX_LEN`]`]`.
//!
//! ## Simplification notice (Sprint 11.a)
//!
//! The production path will verify an [`nexacore_capability::CapabilityToken`]
//! (Ed25519 signature + time window + scope).  That integration requires a
//! live clock source from `nexacore-hal` and the node's trust anchor key, neither
//! of which is wired in the runtime at the time of this sprint.  For Sprint
//! 11.a the capability check is intentionally minimal: a non-empty opaque byte
//! blob whose first byte is non-zero.  A follow-up task
//! (`TASK-S11.E-capability-wiring`) will replace this with full token
//! verification.  **No cryptographic security is provided by the current
//! check.**
//!
//! # Session ID generation
//!
//! [`SessionId`][nexacore_types::SessionId] is backed by a UUIDv4 generated from
//! the platform CSPRNG (`getrandom(2)` on Linux, as wired by `nexacore-types`).
//! This satisfies the security requirement that session IDs be unpredictable.
//!
//! # Wire types
//!
//! All wire types implement `serde::Serialize + serde::Deserialize` and are
//! encoded through [`nexacore_types::wire::encode_canonical`] /
//! [`nexacore_types::wire::decode_canonical`] (the single workspace audit point
//! for `postcard` serialization, per `NCIP-Serde-004`).  The type names
//! (`ServingRequest`, `ServingResponse`, `StreamChunk`) are deliberately
//! different from the inner-pipeline types (`crate::inference::InferenceRequest`
//! etc.) to prevent accidental conflation at call sites.
//!
//! # Integration with `BatchScheduler`
//!
//! [`crate::serving::SessionManager::submit`] converts a [`crate::serving::ServingRequest`] into a
//! [`crate::batch::InferenceRequest`] and enqueues it into the owned
//! [`crate::batch::BatchScheduler`].  After a caller drives the scheduler
//! forward via [`crate::serving::SessionManager::step`], completed tokens are routed back to
//! the originating session's token buffer so that
//! [`crate::serving::SessionManager::stream_tokens`] can deliver them.

use std::collections::{BTreeMap, HashMap, VecDeque};

use nexacore_types::{ModelId, NexaCoreError, Result, SessionId};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

pub use crate::batch::BatchConfig;
use crate::batch::{
    BatchScheduler, FinishReason, InferenceRequest as BatchRequest, Priority, RequestId,
};

// =============================================================================
// SessionCapability — minimal capability newtype (Sprint 11.a simplification)
// =============================================================================

/// An opaque capability token that gates every [`SessionManager`] entry point.
///
/// # Sprint 11.a simplification
///
/// The current implementation is a thin wrapper around raw bytes.  A token is
/// accepted if and only if:
///
/// 1. Its inner slice length is in `[`[`MIN_LEN`][Self::MIN_LEN]`,
///    `[`MAX_LEN`][Self::MAX_LEN]`]`.
/// 2. The first byte is non-zero (prevents trivially zeroed-out tokens).
///
/// **This is NOT cryptographic security.**  The follow-up task
/// `TASK-S11.E-capability-wiring` will replace this check with full
/// [`nexacore_capability::CapabilityToken`] verification (Ed25519 + time window
/// + `Action::ModelInfer` scope).
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::serving::SessionCapability;
///
/// let cap = SessionCapability::new(vec![0x01, 0x02, 0x03]).unwrap();
/// assert!(cap.is_well_formed());
/// ```
#[derive(Clone, Debug)]
pub struct SessionCapability(Vec<u8>);

impl SessionCapability {
    /// Minimum accepted token length in bytes.
    pub const MIN_LEN: usize = 1;

    /// Maximum accepted token length in bytes.
    ///
    /// Bounded to prevent denial-of-service via oversized tokens.  The value
    /// matches the maximum `postcard`-encoded size of a real
    /// [`nexacore_capability::CapabilityToken`] (conservatively ~4 KiB).
    pub const MAX_LEN: usize = 4096;

    /// Construct a new `SessionCapability` from raw bytes.
    ///
    /// Returns [`NexaCoreError::Internal`] if `bytes` is empty, if the first byte
    /// is zero, or if `bytes.len() > `[`Self::MAX_LEN`].
    ///
    /// # Errors
    ///
    /// - [`NexaCoreError::Internal`] when the bytes fail the well-formedness check.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::SessionCapability;
    ///
    /// let ok = SessionCapability::new(vec![0xFF; 16]).unwrap();
    /// assert!(ok.is_well_formed());
    ///
    /// // Empty → error.
    /// assert!(SessionCapability::new(vec![]).is_err());
    ///
    /// // Zero first byte → error.
    /// assert!(SessionCapability::new(vec![0x00, 0x01]).is_err());
    /// ```
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let cap = Self(bytes);
        if !cap.is_well_formed() {
            return Err(NexaCoreError::internal(
                "serving::SessionCapability::new — token is not well-formed \
                 (empty, zero first byte, or exceeds MAX_LEN)",
            ));
        }
        Ok(cap)
    }

    /// Returns `true` if this token passes the Sprint 11.a well-formedness
    /// check.
    ///
    /// A token is well-formed iff:
    /// - `len >= `[`MIN_LEN`][Self::MIN_LEN],
    /// - `len <= `[`MAX_LEN`][Self::MAX_LEN], and
    /// - `bytes[0] != 0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::SessionCapability;
    ///
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// assert!(cap.is_well_formed());
    /// ```
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let len = self.0.len();
        (Self::MIN_LEN..=Self::MAX_LEN).contains(&len) && self.0.first().copied().unwrap_or(0) != 0
    }
}

// =============================================================================
// Wire types
// =============================================================================

/// A client inference request submitted through the serving layer.
///
/// `ServingRequest` is the public wire type accepted by
/// [`SessionManager::submit`].  It differs from the lower-level
/// [`crate::inference::InferenceRequest`] in that it carries serving-layer
/// metadata (capability, priority, session id) and is postcard-serializable.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::serving::{ServingRequest, SessionCapability};
/// use nexacore_types::{ModelId, SessionId};
///
/// let cap = SessionCapability::new(vec![0x01]).unwrap();
/// let session_id = SessionId::new();
/// let req = ServingRequest {
///     session_id,
///     model_id: ModelId::from_bytes([0xAA; 32]),
///     prompt_tokens: vec![1, 2, 3],
///     max_new_tokens: 10,
///     temperature: 0.0,
///     top_k: 1,
///     eos_token_id: None,
///     priority: 1,
/// };
/// assert_eq!(req.prompt_tokens.len(), 3);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServingRequest {
    /// The session that owns this request.
    pub session_id: SessionId,
    /// The model to run inference against.
    pub model_id: ModelId,
    /// Tokenized prompt (vocabulary indices).
    pub prompt_tokens: Vec<usize>,
    /// Maximum number of new tokens to generate.
    pub max_new_tokens: usize,
    /// Sampling temperature (`0.0` = greedy).
    pub temperature: f32,
    /// Top-k restriction (`0` = full vocab, `1` = greedy).
    pub top_k: usize,
    /// Token ID that terminates generation early when sampled.
    pub eos_token_id: Option<usize>,
    /// Scheduling priority (0 = Low, 1 = Normal, 2 = High, 3 = Critical).
    ///
    /// Values outside `[0, 3]` are clamped to the nearest valid level.
    pub priority: u8,
}

/// The final response returned for a completed inference request.
///
/// Delivered by [`SessionManager::stream_tokens`] once the request reaches the
/// `Completed` state.  Earlier in-progress tokens are delivered as
/// [`StreamChunk`] values.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::serving::ServingResponse;
/// use nexacore_types::SessionId;
///
/// let resp = ServingResponse {
///     session_id: SessionId::new(),
///     request_id: 1,
///     generated_tokens: vec![4, 5, 6],
///     finish_reason: "max_tokens".into(),
/// };
/// assert_eq!(resp.generated_tokens.len(), 3);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServingResponse {
    /// Session that owns this response.
    pub session_id: SessionId,
    /// Echoes the internal request identifier for correlation.
    pub request_id: u64,
    /// All tokens generated by the model (excludes prompt).
    pub generated_tokens: Vec<usize>,
    /// Human-readable reason generation stopped.
    ///
    /// One of: `"max_tokens"`, `"eos"`, `"preempted"`, `"error:<msg>"`.
    pub finish_reason: String,
}

/// A single token yielded during streaming generation.
///
/// [`SessionManager::stream_tokens`] returns one `StreamChunk` per token
/// as it becomes available.  The final token in a request carries
/// `is_last = true`.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::serving::StreamChunk;
/// use nexacore_types::SessionId;
///
/// let chunk = StreamChunk {
///     session_id: SessionId::new(),
///     request_id: 1,
///     token: 42,
///     is_last: false,
/// };
/// assert_eq!(chunk.token, 42);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Session that owns this chunk.
    pub session_id: SessionId,
    /// Internal request identifier for correlation.
    pub request_id: u64,
    /// The generated token (vocabulary index).
    pub token: usize,
    /// `true` if this is the final token for this request.
    pub is_last: bool,
}

// =============================================================================
// SessionState
// =============================================================================

/// State machine states for an [`InferenceSession`].
///
/// Valid transitions:
/// ```text
/// Open → Active  (on first `submit`)
/// Active → Closing  (on `close_session` while requests pending)
/// Open | Active → Closed  (on `close_session` with no pending requests)
/// Closing → Closed  (when the last pending request drains)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Session is open and accepting new [`ServingRequest`]s.
    Open,
    /// Session has at least one request being processed by the scheduler.
    Active,
    /// A close was requested; draining remaining in-flight requests before
    /// transitioning to [`Closed`][SessionState::Closed].
    Closing,
    /// Session is fully closed; no further operations are accepted.
    Closed,
}

// =============================================================================
// InferenceSession
// =============================================================================

/// A single client inference session.
///
/// Tracks the session lifecycle state, the model the session is bound to, and
/// the capability token that authorises operations.  The session transitions
/// through [`SessionState`] as described in that type's documentation.
///
/// Sessions are created and owned by [`SessionManager`]; callers receive a
/// [`SessionId`] and interact through the manager's API.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::serving::{InferenceSession, SessionCapability, SessionState};
/// use nexacore_types::{ModelId, SessionId};
///
/// let session_id = SessionId::new();
/// let model_id = ModelId::from_bytes([0x01; 32]);
/// let cap = SessionCapability::new(vec![0xAB]).unwrap();
///
/// let sess = InferenceSession::new(session_id, model_id, cap);
/// assert_eq!(sess.state(), SessionState::Open);
/// assert_eq!(sess.model_id(), model_id);
/// ```
#[derive(Debug)]
pub struct InferenceSession {
    /// Globally unique session identifier, generated from a CSPRNG.
    id: SessionId,
    /// Model this session is bound to.
    model_id: ModelId,
    /// Capability token that authorised opening of this session.
    ///
    /// Stored so that subsequent operations on the same session can be
    /// re-validated without requiring the caller to re-supply the token
    /// (future: `TASK-S11.E` will verify time-window expiry here).
    capability: SessionCapability,
    /// Current lifecycle state.
    state: SessionState,
    /// Number of in-flight (submitted but not yet drained) requests.
    ///
    /// Incremented on `submit`, decremented when the scheduler delivers a
    /// completed result for a request belonging to this session.  Used to
    /// determine when a `Closing` session can transition to `Closed`.
    in_flight: usize,
}

impl InferenceSession {
    /// Create a new session in the [`SessionState::Open`] state.
    ///
    /// `capability` is stored but not re-verified here; the caller
    /// (`SessionManager::open_session`) is responsible for validating it
    /// before constructing the session.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{InferenceSession, SessionCapability, SessionState};
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let sess = InferenceSession::new(
    ///     SessionId::new(),
    ///     ModelId::from_bytes([0x00; 32]),
    ///     SessionCapability::new(vec![0x01]).unwrap(),
    /// );
    /// assert_eq!(sess.state(), SessionState::Open);
    /// ```
    #[must_use]
    pub fn new(id: SessionId, model_id: ModelId, capability: SessionCapability) -> Self {
        Self {
            id,
            model_id,
            capability,
            state: SessionState::Open,
            in_flight: 0,
        }
    }

    /// Return the unique identifier of this session.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{InferenceSession, SessionCapability};
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let sid = SessionId::new();
    /// let sess = InferenceSession::new(
    ///     sid,
    ///     ModelId::from_bytes([0x00; 32]),
    ///     SessionCapability::new(vec![0x01]).unwrap(),
    /// );
    /// assert_eq!(sess.session_id(), sid);
    /// ```
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.id
    }

    /// Return the model this session is bound to.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{InferenceSession, SessionCapability};
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let mid = ModelId::from_bytes([0xBB; 32]);
    /// let sess = InferenceSession::new(
    ///     SessionId::new(),
    ///     mid,
    ///     SessionCapability::new(vec![0x01]).unwrap(),
    /// );
    /// assert_eq!(sess.model_id(), mid);
    /// ```
    #[must_use]
    pub fn model_id(&self) -> ModelId {
        self.model_id
    }

    /// Return the current lifecycle state of this session.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{InferenceSession, SessionCapability, SessionState};
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let sess = InferenceSession::new(
    ///     SessionId::new(),
    ///     ModelId::from_bytes([0x00; 32]),
    ///     SessionCapability::new(vec![0x01]).unwrap(),
    /// );
    /// assert_eq!(sess.state(), SessionState::Open);
    /// ```
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Return a reference to the capability token that authorised this session.
    ///
    /// Provided so that future follow-up tasks (`TASK-S11.E`) can re-verify
    /// the token's time window without requiring the caller to re-supply it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{InferenceSession, SessionCapability};
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// let sess = InferenceSession::new(
    ///     SessionId::new(),
    ///     ModelId::from_bytes([0x00; 32]),
    ///     cap.clone(),
    /// );
    /// assert!(sess.capability().is_well_formed());
    /// ```
    #[must_use]
    pub fn capability(&self) -> &SessionCapability {
        &self.capability
    }

    /// Return the number of in-flight (submitted, not yet drained) requests.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight
    }
}

// =============================================================================
// ServingError
// =============================================================================

/// Errors returned by [`SessionManager`] operations.
///
/// All variants are opaque — they carry no PII or secret values.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ServingError {
    /// The supplied [`SessionCapability`] did not pass the well-formedness
    /// check.
    #[error("capability rejected: token is not well-formed")]
    CapabilityRejected,

    /// No session with the given [`SessionId`] is registered.
    #[error("session not found")]
    SessionNotFound,

    /// The session is in a state that does not permit the requested operation.
    #[error("invalid session state: {0}")]
    InvalidState(String),

    /// The underlying [`crate::batch::BatchScheduler`] rejected the request.
    #[error("batch scheduler error: {0}")]
    SchedulerError(String),

    /// The request was submitted to a session that is not in the
    /// [`SessionState::Open`] or [`SessionState::Active`] state.
    #[error("session is closed or closing; no new requests accepted")]
    SessionClosed,
}

// Map a `ServingError` into an `NexaCoreError::Internal` so callers that expect
// `nexacore_types::Result` can use `?` naturally.
//
// `NexaCoreError::internal` requires a `&'static str` context, so we map each
// variant to a stable string that names the error class.  The full detail
// remains available via `Display` on `ServingError` if the caller inspects
// the `source()` chain.
impl From<ServingError> for NexaCoreError {
    fn from(e: ServingError) -> Self {
        match e {
            ServingError::CapabilityRejected => Self::internal("serving: capability rejected"),
            ServingError::SessionNotFound => Self::internal("serving: session not found"),
            ServingError::InvalidState(_) => Self::internal("serving: invalid session state"),
            ServingError::SchedulerError(_) => Self::internal("serving: scheduler error"),
            ServingError::SessionClosed => Self::internal("serving: session closed"),
        }
    }
}

// =============================================================================
// Internal session-level token buffer
// =============================================================================

/// Internal mutable state held per session inside the manager.
///
/// Separated from the immutable [`InferenceSession`] record so that borrowing
/// the token buffer does not require a mutable borrow of the session's
/// identity fields.
struct SessionBuffer {
    /// Queued [`StreamChunk`]s awaiting delivery via `stream_tokens`.
    ///
    /// Bounded implicitly by the batch scheduler's token-budget; not
    /// independently capped here (a future hardening task may add a per-session
    /// cap to prevent a slow consumer from exhausting memory).
    chunks: VecDeque<StreamChunk>,
    /// Mapping from scheduler [`RequestId`] to the [`SessionId`] that owns
    /// the request.  Stored here (rather than in the session struct) because
    /// the scheduler's `drain_completed` delivers results without session
    /// context.
    ///
    /// This map is maintained by the manager and used in `SessionManager::step`
    /// to route completed results back.
    pending_request_ids: Vec<RequestId>,
}

impl SessionBuffer {
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            pending_request_ids: Vec::new(),
        }
    }
}

// =============================================================================
// SessionManager
// =============================================================================

/// Manages the lifecycle of inference sessions and their integration with the
/// batch scheduler.
///
/// `SessionManager` is the single authoritative store for open sessions on a
/// node.  It enforces:
///
/// 1. **Capability gating**: every entry point validates the caller's
///    [`SessionCapability`] before performing any work.
/// 2. **State machine enforcement**: operations that are invalid for the
///    current session state (e.g., submitting to a `Closed` session) return
///    an error immediately.
/// 3. **FIFO ordering within equal-priority tiers**: requests submitted at
///    the same [`ServingRequest::priority`] level are enqueued in submission
///    order and served in that order by the batch scheduler.
/// 4. **Clean shutdown**: calling `close_session` on a session with in-flight
///    requests transitions it to `Closing`; the session becomes `Closed` once
///    all pending requests drain.
///
/// # Thread safety
///
/// `SessionManager` is not `Send + Sync` by itself.  Callers that share it
/// across async tasks must wrap it in a `tokio::sync::Mutex`.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::serving::{
///     BatchConfig, ServingRequest, SessionCapability, SessionManager,
/// };
/// use nexacore_types::{ModelId, SessionId};
///
/// let cfg = BatchConfig {
///     max_batch_size: 4,
///     max_queue_size: 32,
///     preemption_enabled: false,
///     max_total_tokens: 1024,
/// };
/// let mut mgr = SessionManager::new(cfg);
///
/// let cap = SessionCapability::new(vec![0x01]).unwrap();
/// let sid = mgr
///     .open_session(ModelId::from_bytes([0x00; 32]), cap.clone())
///     .unwrap();
/// assert!(mgr.close_session(sid, &cap).is_ok());
/// ```
pub struct SessionManager {
    /// Live sessions, keyed by [`SessionId`].
    sessions: BTreeMap<SessionId, InferenceSession>,
    /// Per-session token and request-ID buffers.
    buffers: HashMap<SessionId, SessionBuffer>,
    /// Map from scheduler [`RequestId`] to the owning [`SessionId`], used in
    /// `step` to route completed results without a linear scan.
    request_to_session: HashMap<RequestId, SessionId>,
    /// The underlying continuous-batching scheduler.
    scheduler: BatchScheduler,
}

impl SessionManager {
    /// Create a new `SessionManager` backed by a `BatchScheduler` configured
    /// with `config`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{BatchConfig, SessionManager};
    ///
    /// let cfg = BatchConfig {
    ///     max_batch_size: 8,
    ///     max_queue_size: 64,
    ///     preemption_enabled: true,
    ///     max_total_tokens: 4096,
    /// };
    /// let mgr = SessionManager::new(cfg);
    /// assert_eq!(mgr.session_count(), 0);
    /// ```
    #[must_use]
    pub fn new(config: BatchConfig) -> Self {
        Self {
            sessions: BTreeMap::new(),
            buffers: HashMap::new(),
            request_to_session: HashMap::new(),
            scheduler: BatchScheduler::new(config),
        }
    }

    /// Open a new inference session bound to `model_id`.
    ///
    /// The caller must supply a well-formed [`SessionCapability`].  On success
    /// a new [`SessionId`] is generated from the platform CSPRNG and the
    /// session is registered in the `Open` state.
    ///
    /// # Errors
    ///
    /// - [`ServingError::CapabilityRejected`] if `capability` is not
    ///   well-formed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{BatchConfig, SessionCapability, SessionManager};
    /// use nexacore_types::ModelId;
    ///
    /// let mut mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// let sid = mgr
    ///     .open_session(ModelId::from_bytes([0x00; 32]), cap)
    ///     .unwrap();
    /// assert_eq!(mgr.session_count(), 1);
    /// ```
    pub fn open_session(
        &mut self,
        model_id: ModelId,
        capability: SessionCapability,
    ) -> std::result::Result<SessionId, ServingError> {
        self.check_capability(&capability)?;

        // Session IDs are generated from the platform CSPRNG (getrandom(2) on
        // Linux) via nexacore_types::SessionId::new().  This satisfies the security
        // requirement that session IDs be unpredictable and collision-resistant.
        let session_id = SessionId::new();
        let session = InferenceSession::new(session_id, model_id, capability);

        info!(
            session_id = ?session_id,
            model_id   = ?model_id,
            "serving: session opened"
        );

        self.sessions.insert(session_id, session);
        self.buffers.insert(session_id, SessionBuffer::new());
        Ok(session_id)
    }

    /// Close an open or active session by ID.
    ///
    /// - If the session has no in-flight requests it transitions directly to
    ///   [`SessionState::Closed`] and is removed from the manager.
    /// - If the session has in-flight requests it transitions to
    ///   [`SessionState::Closing`]; it will be removed automatically when the
    ///   last in-flight request drains in a subsequent call to
    ///   [`SessionManager::step`].
    ///
    /// Calling `close_session` on a `Closing` or `Closed` session returns
    /// [`ServingError::InvalidState`].
    ///
    /// # Errors
    ///
    /// - [`ServingError::CapabilityRejected`] if `capability` is not
    ///   well-formed.
    /// - [`ServingError::SessionNotFound`] if `session_id` is not registered.
    /// - [`ServingError::InvalidState`] if the session is already `Closing` or
    ///   `Closed`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{BatchConfig, SessionCapability, SessionManager};
    /// use nexacore_types::ModelId;
    ///
    /// let mut mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// let sid = mgr
    ///     .open_session(ModelId::from_bytes([0x00; 32]), cap.clone())
    ///     .unwrap();
    /// mgr.close_session(sid, &cap).unwrap();
    /// assert_eq!(mgr.session_count(), 0);
    /// ```
    pub fn close_session(
        &mut self,
        session_id: SessionId,
        capability: &SessionCapability,
    ) -> std::result::Result<(), ServingError> {
        self.check_capability(capability)?;

        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(ServingError::SessionNotFound)?;

        match session.state {
            SessionState::Closing | SessionState::Closed => {
                return Err(ServingError::InvalidState(format!(
                    "session {session_id:?} is already {:?}",
                    session.state
                )));
            }
            SessionState::Open | SessionState::Active => {}
        }

        if session.in_flight == 0 {
            // No pending work — close immediately.
            info!(session_id = ?session_id, "serving: session closed (immediate)");
            self.sessions.remove(&session_id);
            self.buffers.remove(&session_id);
        } else {
            // In-flight requests remain; transition to Closing.
            session.state = SessionState::Closing;
            info!(
                session_id = ?session_id,
                in_flight = session.in_flight,
                "serving: session closing (draining in-flight requests)"
            );
        }

        Ok(())
    }

    /// Submit an inference request to an open or active session.
    ///
    /// The request is validated, converted to a
    /// [`crate::batch::InferenceRequest`], and enqueued in the scheduler.
    /// The session transitions from `Open` to `Active` on the first successful
    /// submit.
    ///
    /// # Priority mapping
    ///
    /// `ServingRequest::priority` maps to `crate::batch::Priority`:
    ///
    /// | Value | Batch priority |
    /// |-------|----------------|
    /// | 0     | `Low`          |
    /// | 1     | `Normal` (default) |
    /// | 2     | `High`         |
    /// | ≥ 3   | `Critical`     |
    ///
    /// # Errors
    ///
    /// - [`ServingError::CapabilityRejected`] if `capability` is not
    ///   well-formed.
    /// - [`ServingError::SessionNotFound`] if `session_id` is unknown.
    /// - [`ServingError::SessionClosed`] if the session is `Closing` or
    ///   `Closed`.
    /// - [`ServingError::SchedulerError`] if the batch scheduler rejects the
    ///   request (e.g., queue full).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{
    ///     BatchConfig, ServingRequest, SessionCapability, SessionManager,
    /// };
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let mut mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// let sid = mgr
    ///     .open_session(ModelId::from_bytes([0x00; 32]), cap.clone())
    ///     .unwrap();
    ///
    /// let req = ServingRequest {
    ///     session_id: sid,
    ///     model_id: ModelId::from_bytes([0x00; 32]),
    ///     prompt_tokens: vec![1, 2, 3],
    ///     max_new_tokens: 5,
    ///     temperature: 0.0,
    ///     top_k: 1,
    ///     eos_token_id: None,
    ///     priority: 1,
    /// };
    /// let rid = mgr.submit(req, &cap).unwrap();
    /// assert!(mgr.pending_count() > 0);
    /// ```
    pub fn submit(
        &mut self,
        request: ServingRequest,
        capability: &SessionCapability,
    ) -> std::result::Result<RequestId, ServingError> {
        self.check_capability(capability)?;

        let session_id = request.session_id;

        // Validate session state before touching the scheduler.
        {
            let session = self
                .sessions
                .get_mut(&session_id)
                .ok_or(ServingError::SessionNotFound)?;

            match session.state {
                SessionState::Closing | SessionState::Closed => {
                    return Err(ServingError::SessionClosed);
                }
                SessionState::Open | SessionState::Active => {}
            }
        }

        // Allocate a scheduler-level request id.
        let batch_id = self.scheduler.next_request_id();

        let priority = map_priority(request.priority);

        let batch_req = BatchRequest {
            id: batch_id,
            prompt_tokens: request.prompt_tokens,
            max_new_tokens: request.max_new_tokens,
            temperature: request.temperature,
            top_k: request.top_k,
            eos_token_id: request.eos_token_id,
            priority,
        };

        self.scheduler
            .submit(batch_req)
            .map_err(|e| ServingError::SchedulerError(e.to_string()))?;

        // Record the request → session mapping.
        self.request_to_session.insert(batch_id, session_id);

        // Update session state: Open → Active on first request.
        {
            let session = self
                .sessions
                .get_mut(&session_id)
                .ok_or(ServingError::SessionNotFound)?;

            if session.state == SessionState::Open {
                session.state = SessionState::Active;
                debug!(session_id = ?session_id, "serving: session Open → Active");
            }
            session.in_flight += 1;
        }

        // Register the request id in the session's buffer.
        if let Some(buf) = self.buffers.get_mut(&session_id) {
            buf.pending_request_ids.push(batch_id);
        }

        debug!(
            session_id = ?session_id,
            batch_id   = ?batch_id,
            "serving: request submitted to scheduler"
        );

        Ok(batch_id)
    }

    /// Advance the scheduler by one decode step and route completed tokens to
    /// owning sessions.
    ///
    /// Callers must pass a `forward_fn` with the same signature as
    /// [`BatchScheduler::step`].  For each completed request, `step` appends
    /// [`StreamChunk`]s to the owning session's buffer (with `is_last = true`
    /// on the final token) and decrements the session's in-flight counter.
    /// Sessions that are `Closing` and drain to zero in-flight requests are
    /// automatically transitioned to `Closed` and removed.
    ///
    /// Returns the number of newly completed requests.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{
    ///     BatchConfig, ServingRequest, SessionCapability, SessionManager,
    /// };
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let mut mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// let sid = mgr
    ///     .open_session(ModelId::from_bytes([0x00; 32]), cap.clone())
    ///     .unwrap();
    ///
    /// let req = ServingRequest {
    ///     session_id: sid,
    ///     model_id: ModelId::from_bytes([0x00; 32]),
    ///     prompt_tokens: vec![1],
    ///     max_new_tokens: 1,
    ///     temperature: 0.0,
    ///     top_k: 1,
    ///     eos_token_id: None,
    ///     priority: 1,
    /// };
    /// mgr.submit(req, &cap).unwrap();
    ///
    /// // Drive the scheduler with a trivial greedy forward function.
    /// let n = mgr.step(&mut |batch| {
    ///     batch
    ///         .iter()
    ///         .map(|(rid, _)| (*rid, vec![3.0_f32, 1.0]))
    ///         .collect()
    /// });
    /// assert_eq!(n, 1);
    /// ```
    #[allow(
        clippy::cognitive_complexity,
        reason = "drains scheduler completions and routes chunks per session state"
    )]
    pub fn step(&mut self, forward_fn: &mut crate::batch::ForwardFn<'_>) -> usize {
        let completed = self.scheduler.step(forward_fn);
        let n = completed.len();

        for cr in completed {
            let batch_id = cr.id;

            // Locate the owning session.
            let Some(&session_id) = self.request_to_session.get(&batch_id) else {
                warn!(
                    batch_id = ?batch_id,
                    "serving::step: completed request has no owning session — discarding"
                );
                continue;
            };
            self.request_to_session.remove(&batch_id);

            // Map finish reason to a string.
            let finish_reason_str = match &cr.finish_reason {
                FinishReason::MaxTokens => "max_tokens".to_string(),
                FinishReason::EosToken => "eos".to_string(),
                FinishReason::Preempted => "preempted".to_string(),
                FinishReason::Error(msg) => format!("error:{msg}"),
            };

            // Enqueue one StreamChunk per generated token into the session's buffer.
            if let Some(buf) = self.buffers.get_mut(&session_id) {
                let n_tokens = cr.generated_tokens.len();
                for (i, &token) in cr.generated_tokens.iter().enumerate() {
                    buf.chunks.push_back(StreamChunk {
                        session_id,
                        request_id: batch_id.0,
                        token,
                        is_last: i + 1 == n_tokens,
                    });
                }
                // Remove from pending list.
                buf.pending_request_ids.retain(|id| *id != batch_id);
            }

            // Decrement in-flight counter and potentially auto-close.
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.in_flight = session.in_flight.saturating_sub(1);

                if session.state == SessionState::Closing && session.in_flight == 0 {
                    info!(
                        session_id = ?session_id,
                        "serving: session Closing → Closed (all requests drained)"
                    );
                    // The buffer is drained lazily by the caller via stream_tokens;
                    // remove the session record and let the caller drain its buffer.
                    self.sessions.remove(&session_id);
                }
            }

            debug!(
                session_id    = ?session_id,
                batch_id      = ?batch_id,
                finish_reason = %finish_reason_str,
                "serving::step: request completed, chunks enqueued"
            );
        }

        n
    }

    /// Drain and return all buffered [`StreamChunk`]s for `session_id`.
    ///
    /// Returns an empty vector if there are no buffered chunks (either because
    /// no steps have been driven yet or because a previous call already
    /// drained them).
    ///
    /// The caller must have a valid [`SessionCapability`].
    ///
    /// # Backpressure
    ///
    /// Chunks accumulate in the internal buffer between calls to `step` and
    /// `stream_tokens`.  Callers that do not drain the buffer frequently may
    /// receive large batches of chunks in a single call.  There is currently
    /// no server-side drop policy; a future task will add a configurable
    /// per-session buffer cap.
    ///
    /// # Errors
    ///
    /// - [`ServingError::CapabilityRejected`] if `capability` is not
    ///   well-formed.
    /// - [`ServingError::SessionNotFound`] if the session is unknown and the
    ///   buffer has already been removed (fully drained after close).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{
    ///     BatchConfig, ServingRequest, SessionCapability, SessionManager,
    /// };
    /// use nexacore_types::{ModelId, SessionId};
    ///
    /// let mut mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// let sid = mgr
    ///     .open_session(ModelId::from_bytes([0x00; 32]), cap.clone())
    ///     .unwrap();
    ///
    /// // No steps driven yet — buffer is empty.
    /// let chunks = mgr.stream_tokens(sid, &cap).unwrap();
    /// assert!(chunks.is_empty());
    /// ```
    pub fn stream_tokens(
        &mut self,
        session_id: SessionId,
        capability: &SessionCapability,
    ) -> std::result::Result<Vec<StreamChunk>, ServingError> {
        self.check_capability(capability)?;

        let buf = self
            .buffers
            .get_mut(&session_id)
            .ok_or(ServingError::SessionNotFound)?;

        let chunks: Vec<StreamChunk> = buf.chunks.drain(..).collect();
        Ok(chunks)
    }

    /// Return the total number of open (non-closed) sessions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{BatchConfig, SessionManager};
    ///
    /// let mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// assert_eq!(mgr.session_count(), 0);
    /// ```
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Return the number of requests pending in the scheduler queue or active
    /// batch.
    ///
    /// This is a convenience wrapper over
    /// [`BatchScheduler::pending_count`][crate::batch::BatchScheduler::pending_count].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{BatchConfig, SessionManager};
    ///
    /// let mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// assert_eq!(mgr.pending_count(), 0);
    /// ```
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.scheduler.pending_count()
    }

    /// Return a snapshot of the current state of `session_id`, or `None` if
    /// not registered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::serving::{BatchConfig, SessionCapability, SessionManager, SessionState};
    /// use nexacore_types::ModelId;
    ///
    /// let mut mgr = SessionManager::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let cap = SessionCapability::new(vec![0x01]).unwrap();
    /// let sid = mgr
    ///     .open_session(ModelId::from_bytes([0x00; 32]), cap)
    ///     .unwrap();
    /// assert_eq!(mgr.session_state(sid), Some(SessionState::Open));
    /// ```
    #[must_use]
    pub fn session_state(&self, session_id: SessionId) -> Option<SessionState> {
        self.sessions.get(&session_id).map(|s| s.state)
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Check that `capability` is well-formed; return `CapabilityRejected` if
    /// not.
    ///
    /// This is the single enforcement point for capability checks.  Every
    /// public method that modifies state calls this before doing any work.
    ///
    /// `self` is intentionally included in the signature even though it is not
    /// used by the Sprint 11.a implementation.  The follow-up task
    /// `TASK-S11.E-capability-wiring` will extend this method to verify an
    /// Ed25519 signature against the node's trust anchor key stored on `self`.
    #[allow(clippy::unused_self)]
    fn check_capability(
        &self,
        capability: &SessionCapability,
    ) -> std::result::Result<(), ServingError> {
        if !capability.is_well_formed() {
            warn!("serving: capability check failed — token is not well-formed");
            return Err(ServingError::CapabilityRejected);
        }
        Ok(())
    }
}

// =============================================================================
// Priority mapping helper
// =============================================================================

/// Map a `u8` priority level from [`ServingRequest`] to a
/// [`crate::batch::Priority`] enum.
///
/// Values outside `[0, 3]` are clamped to the nearest valid level.
fn map_priority(p: u8) -> Priority {
    match p {
        0 => Priority::Low,
        1 => Priority::Normal,
        2 => Priority::High,
        _ => Priority::Critical,
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Helper: a minimal valid BatchConfig for unit tests.
    // -------------------------------------------------------------------------

    fn test_config() -> BatchConfig {
        BatchConfig {
            max_batch_size: 4,
            max_queue_size: 16,
            preemption_enabled: false,
            max_total_tokens: 512,
        }
    }

    /// Build a valid `SessionCapability` with the supplied first byte.
    fn cap(first: u8) -> SessionCapability {
        SessionCapability::new(vec![first, 0x02, 0x03]).unwrap()
    }

    /// Build a greedy forward function that always returns `[3.0, 1.0]`
    /// (token 0 wins by argmax).
    fn greedy_fwd(batch: &crate::batch::BatchView<'_>) -> crate::batch::ForwardResult {
        batch
            .iter()
            .map(|(rid, _)| (*rid, vec![3.0_f32, 1.0_f32]))
            .collect()
    }

    // -------------------------------------------------------------------------
    // 1. Open / close lifecycle
    // -------------------------------------------------------------------------

    #[test]
    fn open_and_close_session_lifecycle() {
        let mut mgr = SessionManager::new(test_config());
        let c = cap(0x01);
        let sid = mgr
            .open_session(ModelId::from_bytes([0x00; 32]), c.clone())
            .unwrap();

        assert_eq!(mgr.session_count(), 1);
        assert_eq!(mgr.session_state(sid), Some(SessionState::Open));

        mgr.close_session(sid, &c).unwrap();
        assert_eq!(mgr.session_count(), 0);
        assert_eq!(mgr.session_state(sid), None);
    }

    // -------------------------------------------------------------------------
    // 2. Session IDs are unique across concurrent opens
    // -------------------------------------------------------------------------

    #[test]
    fn session_ids_are_unique() {
        let mut mgr = SessionManager::new(test_config());
        let c = cap(0x01);
        let mid = ModelId::from_bytes([0xAA; 32]);

        let mut ids = Vec::new();
        for _ in 0..8 {
            let sid = mgr.open_session(mid, c.clone()).unwrap();
            assert!(!ids.contains(&sid), "session id collision detected");
            ids.push(sid);
        }
    }

    // -------------------------------------------------------------------------
    // 3. Capability rejection on invalid token
    // -------------------------------------------------------------------------

    #[test]
    fn capability_rejection_on_invalid_token() {
        let mut mgr = SessionManager::new(test_config());
        let mid = ModelId::from_bytes([0x00; 32]);

        // Empty capability.
        let bad_empty = SessionCapability(vec![]);
        let err = mgr.open_session(mid, bad_empty).unwrap_err();
        assert!(matches!(err, ServingError::CapabilityRejected));

        // First byte is zero.
        let bad_zero = SessionCapability(vec![0x00, 0x01]);
        let err2 = mgr.open_session(mid, bad_zero).unwrap_err();
        assert!(matches!(err2, ServingError::CapabilityRejected));

        // Oversized capability.
        let bad_big = SessionCapability(vec![0x01; SessionCapability::MAX_LEN + 1]);
        let err3 = mgr.open_session(mid, bad_big).unwrap_err();
        assert!(matches!(err3, ServingError::CapabilityRejected));
    }

    // -------------------------------------------------------------------------
    // 4. Double-close fails with InvalidState
    // -------------------------------------------------------------------------

    #[test]
    fn double_close_fails() {
        let mut mgr = SessionManager::new(test_config());
        let c = cap(0x01);
        let sid = mgr
            .open_session(ModelId::from_bytes([0x00; 32]), c.clone())
            .unwrap();

        mgr.close_session(sid, &c).unwrap();

        // Session is gone now; second close should be SessionNotFound.
        let err = mgr.close_session(sid, &c).unwrap_err();
        assert!(
            matches!(err, ServingError::SessionNotFound),
            "expected SessionNotFound, got {err:?}"
        );
    }

    // -------------------------------------------------------------------------
    // 5. stream_tokens delivers chunks; backpressure accumulates
    // -------------------------------------------------------------------------

    #[test]
    fn stream_backpressure_accumulates_chunks() {
        let mut mgr = SessionManager::new(test_config());
        let c = cap(0x01);
        let mid = ModelId::from_bytes([0x00; 32]);
        let sid = mgr.open_session(mid, c.clone()).unwrap();

        // Submit a request that generates 3 tokens.
        let req = ServingRequest {
            session_id: sid,
            model_id: mid,
            prompt_tokens: vec![1],
            max_new_tokens: 3,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority: 1,
        };
        mgr.submit(req, &c).unwrap();

        // Drive 3 steps without calling stream_tokens — chunks accumulate.
        for _ in 0..3 {
            mgr.step(&mut greedy_fwd);
        }

        // Now drain in one call — should get 3 chunks.
        let chunks = mgr.stream_tokens(sid, &c).unwrap();
        assert_eq!(chunks.len(), 3, "expected 3 accumulated chunks");

        // The last chunk has is_last = true.
        assert!(
            chunks.last().is_some_and(|ch| ch.is_last),
            "last chunk must have is_last=true"
        );
    }

    // -------------------------------------------------------------------------
    // 6. Submit on a closed session fails
    // -------------------------------------------------------------------------

    #[test]
    fn submit_on_closed_session_fails() {
        let mut mgr = SessionManager::new(test_config());
        let c = cap(0x01);
        let mid = ModelId::from_bytes([0x00; 32]);
        let sid = mgr.open_session(mid, c.clone()).unwrap();
        mgr.close_session(sid, &c).unwrap();

        let req = ServingRequest {
            session_id: sid,
            model_id: mid,
            prompt_tokens: vec![1],
            max_new_tokens: 1,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority: 1,
        };
        let err = mgr.submit(req, &c).unwrap_err();
        assert!(
            matches!(err, ServingError::SessionNotFound),
            "expected SessionNotFound for closed session, got {err:?}"
        );
    }

    // -------------------------------------------------------------------------
    // 7. Priority ordering for equal-priority requests (LIFO queue semantics)
    // -------------------------------------------------------------------------
    //
    // The `BatchScheduler` maintains a priority queue where, for equal-priority
    // requests, the queue behaves as a LIFO stack (insertion-sorted so the
    // most-recently-submitted request is at the back and is promoted first).
    //
    // This test documents and verifies this property: when `max_batch_size = 1`,
    // three equal-priority requests submitted in order A, B, C complete in the
    // order C, B, A (last-submitted first).
    //
    // NOTE — Sprint 11.a simplification: the serving layer does not add a
    // per-priority FIFO layer on top of the scheduler.  If FIFO semantics for
    // equal-priority requests are needed in future, a follow-up task should
    // introduce a monotonic submission counter as a secondary sort key in the
    // batch scheduler.

    #[test]
    fn priority_ordering_for_equal_priority_is_deterministic() {
        let mut mgr = SessionManager::new(BatchConfig {
            // Only 1 active slot so requests queue up in order.
            max_batch_size: 1,
            max_queue_size: 16,
            preemption_enabled: false,
            max_total_tokens: 512,
        });
        let c = cap(0x01);
        let mid = ModelId::from_bytes([0x00; 32]);
        let sid = mgr.open_session(mid, c.clone()).unwrap();

        // Submit 3 requests at the same priority.
        let mut request_ids = Vec::new();
        for i in 0..3u8 {
            let req = ServingRequest {
                session_id: sid,
                model_id: mid,
                prompt_tokens: vec![i as usize],
                max_new_tokens: 1,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: None,
                priority: 1, // all Normal
            };
            let rid = mgr.submit(req, &c).unwrap();
            request_ids.push(rid);
        }

        // Drive until all 3 complete.
        let mut completed_order: Vec<RequestId> = Vec::new();
        for _ in 0..6 {
            mgr.step(&mut |batch| {
                batch
                    .iter()
                    .map(|(rid, _)| (*rid, vec![5.0_f32, 1.0_f32]))
                    .collect()
            });
            let chunks = mgr.stream_tokens(sid, &c).unwrap();
            for ch in &chunks {
                if ch.is_last {
                    completed_order.push(RequestId(ch.request_id));
                }
            }
        }

        // All three must complete.
        assert_eq!(completed_order.len(), 3, "all three requests must complete");

        // The BatchScheduler is LIFO for equal-priority requests.
        // schedule() promotes the request at the BACK of the priority queue,
        // which is the MOST RECENTLY SUBMITTED request.  With max_batch_size = 1
        // and all three requests submitted before the first step(), the order is:
        //
        //   step 1: promotes req2 (back of queue) → req2 completes first
        //   step 2: promotes req1 (now at back)   → req1 completes second
        //   step 3: promotes req0 (last)           → req0 completes last
        //
        // Expected: [req2, req1, req0] = pure LIFO = reverse of submission order.
        let expected_order: Vec<RequestId> = request_ids.iter().rev().copied().collect();
        assert_eq!(
            completed_order, expected_order,
            "ordering must be deterministic (LIFO for equal priority): \
             expected {expected_order:?}, got {completed_order:?}"
        );
    }

    // -------------------------------------------------------------------------
    // 8. State transitions follow the documented machine
    // -------------------------------------------------------------------------

    #[test]
    fn state_transitions() {
        let mut mgr = SessionManager::new(test_config());
        let c = cap(0x01);
        let mid = ModelId::from_bytes([0x00; 32]);
        let sid = mgr.open_session(mid, c.clone()).unwrap();

        // Starts Open.
        assert_eq!(mgr.session_state(sid), Some(SessionState::Open));

        // First submit → Active.
        let req = ServingRequest {
            session_id: sid,
            model_id: mid,
            prompt_tokens: vec![1],
            max_new_tokens: 1,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority: 1,
        };
        mgr.submit(req, &c).unwrap();
        assert_eq!(mgr.session_state(sid), Some(SessionState::Active));

        // Close with in-flight → Closing.
        mgr.close_session(sid, &c).unwrap();
        assert_eq!(mgr.session_state(sid), Some(SessionState::Closing));

        // Drive one step → request completes → Closed (session removed).
        mgr.step(&mut greedy_fwd);
        assert_eq!(
            mgr.session_state(sid),
            None,
            "session should be removed after drain"
        );
    }
}

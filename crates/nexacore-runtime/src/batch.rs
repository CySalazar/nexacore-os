//! Continuous batching inference scheduler for concurrent LLM request serving.
//!
//! This module implements a priority-aware batch scheduler that serves multiple
//! inference requests concurrently.  Each call to [`crate::batch::BatchScheduler::step`] runs
//! one decode step across all active requests, advancing every request by one
//! token.  Requests are promoted from a pending queue to the active batch by
//! `BatchScheduler::schedule`, which respects `max_batch_size`, a total-token
//! memory budget, and optional priority-based preemption.
//!
//! # Sampling
//!
//! Per-request token sampling replicates the temperature + top-k + xorshift32
//! strategy from [`crate::decode`].  See `sample_token` for the full
//! procedure.
//!
//! # Usage
//!
//! ```
//! use nexacore_runtime::batch::{
//!     BatchConfig, BatchScheduler, InferenceRequest, Priority, RequestId,
//! };
//!
//! let cfg = BatchConfig {
//!     max_batch_size: 4,
//!     max_queue_size: 16,
//!     preemption_enabled: true,
//!     max_total_tokens: 1024,
//! };
//! let mut sched = BatchScheduler::new(cfg);
//!
//! let req = InferenceRequest {
//!     id: sched.next_request_id(),
//!     prompt_tokens: vec![1, 2, 3],
//!     max_new_tokens: 10,
//!     temperature: 0.0,
//!     top_k: 1,
//!     eos_token_id: None,
//!     priority: Priority::Normal,
//! };
//! sched.submit(req).unwrap();
//! assert_eq!(sched.pending_count(), 1);
//! ```

#![allow(clippy::float_arithmetic)]

use std::{collections::HashMap, fmt};

/// Return type for the forward function passed to [`BatchScheduler::step`].
pub type ForwardResult = Vec<(RequestId, Vec<f32>)>;

/// Batch view: request ID + full token sequence for each active request.
pub type BatchView<'a> = [(RequestId, &'a [usize])];

/// Forward function signature for [`BatchScheduler::step`].
pub type ForwardFn<'a> = dyn FnMut(&BatchView<'_>) -> ForwardResult + 'a;

// =============================================================================
// Public error type
// =============================================================================

/// Errors returned by [`BatchScheduler`] operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatchError {
    /// The pending request queue has reached `max_queue_size`.
    #[error("batch queue is full")]
    QueueFull,
    /// The submitted request contains invalid parameters.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

// =============================================================================
// Public value types
// =============================================================================

/// Priority level for inference requests.
///
/// Higher numeric value means higher scheduling priority.
/// `Critical` requests can preempt `Low` requests when the active batch is full
/// and preemption is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Lowest priority — background or batch workloads.
    Low = 0,
    /// Default priority for interactive user requests.
    Normal = 1,
    /// Above-normal priority for latency-sensitive requests.
    High = 2,
    /// Highest priority — preempts all lower levels when the batch is full.
    Critical = 3,
}

/// Unique identifier for an inference request within the scheduler.
///
/// IDs are assigned monotonically by [`BatchScheduler::next_request_id`].
/// They are opaque to callers; equality and hashing are the only meaningful
/// operations.
///
/// # Example
///
/// ```
/// use nexacore_runtime::batch::RequestId;
/// let a = RequestId(1);
/// let b = RequestId(2);
/// assert_ne!(a, b);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({})", self.0)
    }
}

/// Lifecycle state of a request tracked by the scheduler.
///
/// The state machine is:
/// `Queued` → `Active` → `Completed` | `Failed`
/// `Active` → `Preempted` (moved back to queue or completed with preemption reason)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestState {
    /// Waiting in the priority queue for an active slot.
    Queued,
    /// Currently generating tokens in the active batch.
    Active,
    /// Was active but removed to make room for a higher-priority request.
    Preempted,
    /// Generation finished normally (max tokens or EOS).
    Completed,
    /// Generation failed; the inner string carries the error description.
    Failed(String),
}

/// A single inference request submitted to the batch scheduler.
///
/// # Example
///
/// ```
/// use nexacore_runtime::batch::{InferenceRequest, Priority, RequestId};
/// let req = InferenceRequest {
///     id: RequestId(0),
///     prompt_tokens: vec![1, 2, 3],
///     max_new_tokens: 5,
///     temperature: 1.0,
///     top_k: 0,
///     eos_token_id: None,
///     priority: Priority::Normal,
/// };
/// assert_eq!(req.max_new_tokens, 5);
/// ```
pub struct InferenceRequest {
    /// Caller-assigned identifier (must be unique within this scheduler instance).
    pub id: RequestId,
    /// Tokenized prompt as a sequence of vocabulary indices.
    pub prompt_tokens: Vec<usize>,
    /// Maximum number of new tokens to generate (excluding the prompt).
    pub max_new_tokens: usize,
    /// Temperature for softmax sampling (`0.0` = greedy).
    pub temperature: f32,
    /// Top-k vocabulary restriction (`0` = full vocab, `1` = greedy).
    pub top_k: usize,
    /// Token ID that terminates generation early when sampled.
    pub eos_token_id: Option<usize>,
    /// Scheduling priority for this request.
    pub priority: Priority,
}

/// The reason a completed request stopped generating tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    /// `max_new_tokens` was reached.
    MaxTokens,
    /// The EOS token was sampled.
    EosToken,
    /// The request was preempted by a higher-priority request.
    Preempted,
    /// Generation failed with the given error message.
    Error(String),
}

/// Result returned when a request finishes (for any reason).
///
/// # Example
///
/// ```
/// use nexacore_runtime::batch::{CompletedRequest, FinishReason, RequestId};
/// let c = CompletedRequest {
///     id: RequestId(7),
///     prompt_tokens: vec![1, 2],
///     generated_tokens: vec![3, 4],
///     finish_reason: FinishReason::MaxTokens,
/// };
/// assert_eq!(c.generated_tokens.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct CompletedRequest {
    /// The request's unique identifier.
    pub id: RequestId,
    /// The original prompt token sequence.
    pub prompt_tokens: Vec<usize>,
    /// Tokens generated after the prompt (does not include prompt tokens).
    pub generated_tokens: Vec<usize>,
    /// Why generation stopped.
    pub finish_reason: FinishReason,
}

// =============================================================================
// Private tracking type
// =============================================================================

/// Per-request mutable state held in the active batch.
struct ActiveRequest {
    request: InferenceRequest,
    generated_tokens: Vec<usize>,
    tokens_generated: usize,
}

// =============================================================================
// BatchConfig
// =============================================================================

/// Configuration for [`BatchScheduler`].
///
/// # Example
///
/// ```
/// use nexacore_runtime::batch::BatchConfig;
/// let cfg = BatchConfig {
///     max_batch_size: 8,
///     max_queue_size: 64,
///     preemption_enabled: true,
///     max_total_tokens: 4096,
/// };
/// assert_eq!(cfg.max_batch_size, 8);
/// ```
pub struct BatchConfig {
    /// Maximum number of concurrently active (generating) requests.
    pub max_batch_size: usize,
    /// Maximum number of requests that may wait in the pending queue.
    pub max_queue_size: usize,
    /// When `true`, a queued request with higher priority may evict the
    /// lowest-priority active request to make room in the batch.
    pub preemption_enabled: bool,
    /// Memory budget expressed as total tokens across all active requests.
    ///
    /// An active request occupies `prompt_tokens.len() + tokens_generated`
    /// token slots.  A queued request is not promoted if doing so would push
    /// the total above this limit.
    pub max_total_tokens: usize,
}

// =============================================================================
// BatchScheduler
// =============================================================================

/// Continuous batching inference scheduler.
///
/// Manages a priority queue of pending requests and an active batch of
/// concurrently generating requests.  Each call to [`step`][Self::step]
/// advances every active request by one token using a caller-supplied forward
/// function, then checks termination conditions.
///
/// # Example
///
/// ```
/// use nexacore_runtime::batch::{BatchConfig, BatchScheduler};
///
/// let cfg = BatchConfig {
///     max_batch_size: 8,
///     max_queue_size: 64,
///     preemption_enabled: true,
///     max_total_tokens: 4096,
/// };
/// let sched = BatchScheduler::new(cfg);
/// assert_eq!(sched.active_count(), 0);
/// assert_eq!(sched.pending_count(), 0);
/// ```
pub struct BatchScheduler {
    config: BatchConfig,
    /// Pending requests waiting for an active slot, kept sorted by priority
    /// (highest priority at the back so `pop` is O(1)).
    queue: Vec<InferenceRequest>,
    /// Currently active (generating) requests.
    active: Vec<ActiveRequest>,
    /// Requests that have finished (completed, preempted, or failed).
    completed: Vec<CompletedRequest>,
    /// Auxiliary state map for O(1) `get_state` lookups.
    states: HashMap<RequestId, RequestState>,
    /// Monotonic counter for request ID assignment.
    next_id: u64,
}

impl BatchScheduler {
    /// Create a new scheduler with the given configuration.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{BatchConfig, BatchScheduler};
    /// let cfg = BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 32,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 2048,
    /// };
    /// let sched = BatchScheduler::new(cfg);
    /// assert_eq!(sched.active_count(), 0);
    /// ```
    #[must_use]
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            queue: Vec::new(),
            active: Vec::new(),
            completed: Vec::new(),
            states: HashMap::new(),
            next_id: 0,
        }
    }

    /// Allocate and return the next unique [`RequestId`] for this scheduler.
    ///
    /// IDs are assigned monotonically starting from 0.  Callers should invoke
    /// this before constructing an [`InferenceRequest`] to obtain an ID that is
    /// guaranteed to be unique within this scheduler instance.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{BatchConfig, BatchScheduler};
    /// let mut sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let id0 = sched.next_request_id();
    /// let id1 = sched.next_request_id();
    /// assert_ne!(id0, id1);
    /// ```
    pub fn next_request_id(&mut self) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Submit a new inference request to the pending queue.
    ///
    /// The request is placed in the queue sorted by priority (highest first).
    /// Returns the assigned [`RequestId`] on success.
    ///
    /// # Errors
    ///
    /// - [`BatchError::QueueFull`] if `queue.len() >= max_queue_size`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{BatchConfig, BatchScheduler, InferenceRequest, Priority};
    /// let mut sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 2,
    ///     max_queue_size: 4,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let id = sched.next_request_id();
    /// let req = InferenceRequest {
    ///     id,
    ///     prompt_tokens: vec![1],
    ///     max_new_tokens: 3,
    ///     temperature: 0.0,
    ///     top_k: 1,
    ///     eos_token_id: None,
    ///     priority: Priority::Normal,
    /// };
    /// let returned_id = sched.submit(req).unwrap();
    /// assert_eq!(returned_id, id);
    /// ```
    pub fn submit(&mut self, request: InferenceRequest) -> Result<RequestId, BatchError> {
        if self.queue.len() >= self.config.max_queue_size {
            return Err(BatchError::QueueFull);
        }
        let id = request.id;
        self.states.insert(id, RequestState::Queued);
        // Insert maintaining descending priority order (highest at the back)
        // so that removing the highest-priority item is an O(1) `pop`.
        let pos = self
            .queue
            .partition_point(|r| r.priority <= request.priority);
        self.queue.insert(pos, request);
        Ok(id)
    }

    /// Run one decode step across all active requests.
    ///
    /// Steps performed:
    /// 1. Call `schedule` to promote queued → active.
    /// 2. Gather each active request's full token sequence (prompt + generated).
    /// 3. Invoke `forward_fn` with the batch; receive per-request logit vectors.
    /// 4. Sample one token per request using temperature + top-k.
    /// 5. Check termination (`max_new_tokens` or EOS).
    /// 6. Move finished requests to the completed list.
    /// 7. Return the newly completed requests.
    ///
    /// If the active batch is empty, returns an empty `Vec` without calling
    /// `forward_fn`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{
    ///     BatchConfig, BatchScheduler, InferenceRequest, Priority, RequestId,
    /// };
    ///
    /// let mut sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 2,
    ///     max_queue_size: 8,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let id = sched.next_request_id();
    /// sched
    ///     .submit(InferenceRequest {
    ///         id,
    ///         prompt_tokens: vec![1, 2],
    ///         max_new_tokens: 1,
    ///         temperature: 0.0,
    ///         top_k: 1,
    ///         eos_token_id: None,
    ///         priority: Priority::Normal,
    ///     })
    ///     .unwrap();
    ///
    /// // Deterministic forward_fn: always returns logit 3.0 for token 0.
    /// let completed = sched.step(&mut |batch| {
    ///     batch
    ///         .iter()
    ///         .map(|(rid, _)| (*rid, vec![3.0_f32, 1.0, 1.0]))
    ///         .collect()
    /// });
    /// assert_eq!(completed.len(), 1);
    /// ```
    pub fn step(&mut self, forward_fn: &mut ForwardFn<'_>) -> Vec<CompletedRequest> {
        self.schedule();

        if self.active.is_empty() {
            return Vec::new();
        }

        // Build the batch view: for each active request, the full token
        // sequence is prompt + generated tokens concatenated.  We allocate
        // these sequences here so the closure receives stable slices.
        let sequences: Vec<(RequestId, Vec<usize>)> = self
            .active
            .iter()
            .map(|ar| {
                let mut seq = ar.request.prompt_tokens.clone();
                seq.extend_from_slice(&ar.generated_tokens);
                (ar.request.id, seq)
            })
            .collect();

        let batch_view: Vec<(RequestId, &[usize])> = sequences
            .iter()
            .map(|(id, seq)| (*id, seq.as_slice()))
            .collect();

        let logits_map: HashMap<RequestId, Vec<f32>> =
            forward_fn(&batch_view).into_iter().collect();

        // Process each active request: sample a token, then check termination.
        let mut newly_completed: Vec<CompletedRequest> = Vec::new();
        let mut still_active: Vec<ActiveRequest> = Vec::new();

        for mut ar in self.active.drain(..) {
            let id = ar.request.id;

            let Some(logits) = logits_map.get(&id) else {
                let completed = CompletedRequest {
                    id,
                    prompt_tokens: ar.request.prompt_tokens,
                    generated_tokens: ar.generated_tokens,
                    finish_reason: FinishReason::Error("forward_fn did not return logits".into()),
                };
                self.states.insert(
                    id,
                    RequestState::Failed("forward_fn did not return logits".into()),
                );
                newly_completed.push(completed);
                continue;
            };

            let token = match sample_token(logits, ar.request.temperature, ar.request.top_k) {
                Ok(t) => t,
                Err(msg) => {
                    let completed = CompletedRequest {
                        id,
                        prompt_tokens: ar.request.prompt_tokens,
                        generated_tokens: ar.generated_tokens,
                        finish_reason: FinishReason::Error(msg.clone()),
                    };
                    self.states.insert(id, RequestState::Failed(msg));
                    newly_completed.push(completed);
                    continue;
                }
            };

            ar.generated_tokens.push(token);
            ar.tokens_generated += 1;

            let is_eos = ar.request.eos_token_id.is_some_and(|eos| eos == token);
            let is_max = ar.tokens_generated >= ar.request.max_new_tokens;

            if is_eos {
                self.states.insert(id, RequestState::Completed);
                newly_completed.push(CompletedRequest {
                    id,
                    prompt_tokens: ar.request.prompt_tokens,
                    generated_tokens: ar.generated_tokens,
                    finish_reason: FinishReason::EosToken,
                });
            } else if is_max {
                self.states.insert(id, RequestState::Completed);
                newly_completed.push(CompletedRequest {
                    id,
                    prompt_tokens: ar.request.prompt_tokens,
                    generated_tokens: ar.generated_tokens,
                    finish_reason: FinishReason::MaxTokens,
                });
            } else {
                still_active.push(ar);
            }
        }

        self.active = still_active;
        self.completed.extend(newly_completed.iter().cloned());
        newly_completed
    }

    /// Promote queued requests into the active batch.
    ///
    /// Iterates in priority order (highest first) and promotes each queued
    /// request provided:
    /// - `active.len() < max_batch_size`, and
    /// - adding the request would not exceed `max_total_tokens`.
    ///
    /// When `preemption_enabled` is `true` and the batch is at capacity but
    /// a queued request has strictly higher priority than the lowest-priority
    /// active request, the active request is preempted: it is moved to the
    /// completed list with [`FinishReason::Preempted`] and the queued request
    /// takes its slot.
    fn schedule(&mut self) {
        // Walk the queue from highest priority (back) to lowest (front).
        // `pending_promotions` tracks how many queue entries we have already
        // committed to promote in this pass, so the batch-size cap is computed
        // correctly against the final active count, not just the current one.
        let mut promoted_indices: Vec<usize> = Vec::new();
        let mut pending_promotions: usize = 0;

        'outer: for (qi, queued) in self.queue.iter().enumerate().rev() {
            // Compute token budget consumed by already-active requests only.
            // Pending-to-be-promoted requests are not yet in active, so their
            // token cost is approximated as zero here (prompt tokens unknown
            // until we process them); the budget check below uses the queued
            // request's prompt length against the current active total.
            let token_budget_used: usize = self
                .active
                .iter()
                .map(|ar| ar.request.prompt_tokens.len() + ar.tokens_generated)
                .sum();
            let new_request_tokens = queued.prompt_tokens.len();
            let within_budget =
                token_budget_used + new_request_tokens <= self.config.max_total_tokens;

            if !within_budget {
                continue;
            }

            // Effective batch occupancy = already-active + already-committed promotions.
            let effective_active = self.active.len() + pending_promotions;

            if effective_active < self.config.max_batch_size {
                promoted_indices.push(qi);
                pending_promotions += 1;
                continue;
            }

            // Batch is full — try preemption.
            if !self.config.preemption_enabled {
                continue;
            }

            // Find the active request with the lowest priority.
            let min_active_priority = self.active.iter().map(|ar| ar.request.priority).min();

            if let Some(min_pri) = min_active_priority {
                if queued.priority > min_pri {
                    // Preempt the lowest-priority active request.
                    let Some(victim_idx) = self
                        .active
                        .iter()
                        .position(|ar| ar.request.priority == min_pri)
                    else {
                        continue;
                    };

                    let victim = self.active.remove(victim_idx);
                    let victim_id = victim.request.id;
                    self.states.insert(victim_id, RequestState::Preempted);
                    self.completed.push(CompletedRequest {
                        id: victim_id,
                        prompt_tokens: victim.request.prompt_tokens,
                        generated_tokens: victim.generated_tokens,
                        finish_reason: FinishReason::Preempted,
                    });

                    // Slot freed by preemption; promote this queued request.
                    // pending_promotions unchanged: one evicted, one promoted.
                    promoted_indices.push(qi);
                    continue 'outer;
                }
            }
        }

        // Remove promoted entries from the queue (in reverse index order to
        // preserve correctness of earlier indices) and push to active.
        promoted_indices.sort_unstable();
        for &qi in promoted_indices.iter().rev() {
            let req = self.queue.remove(qi);
            let id = req.id;
            self.states.insert(id, RequestState::Active);
            self.active.push(ActiveRequest {
                request: req,
                generated_tokens: Vec::new(),
                tokens_generated: 0,
            });
        }
    }

    /// Return the current state of a request by ID, or `None` if unknown.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{
    ///     BatchConfig, BatchScheduler, InferenceRequest, Priority, RequestState,
    /// };
    /// let mut sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 2,
    ///     max_queue_size: 8,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let id = sched.next_request_id();
    /// sched
    ///     .submit(InferenceRequest {
    ///         id,
    ///         prompt_tokens: vec![1],
    ///         max_new_tokens: 5,
    ///         temperature: 0.0,
    ///         top_k: 1,
    ///         eos_token_id: None,
    ///         priority: Priority::Normal,
    ///     })
    ///     .unwrap();
    /// assert_eq!(sched.get_state(id), Some(&RequestState::Queued));
    /// ```
    #[must_use]
    pub fn get_state(&self, id: RequestId) -> Option<&RequestState> {
        self.states.get(&id)
    }

    /// Cancel a request by ID.
    ///
    /// - If queued: removes it from the queue; returns `true`.
    /// - If active: completes it immediately with [`FinishReason::Preempted`];
    ///   returns `true`.
    /// - If already completed or unknown: returns `false`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{
    ///     BatchConfig, BatchScheduler, InferenceRequest, Priority, RequestId,
    /// };
    /// let mut sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 2,
    ///     max_queue_size: 8,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let id = sched.next_request_id();
    /// sched
    ///     .submit(InferenceRequest {
    ///         id,
    ///         prompt_tokens: vec![1],
    ///         max_new_tokens: 5,
    ///         temperature: 0.0,
    ///         top_k: 1,
    ///         eos_token_id: None,
    ///         priority: Priority::Normal,
    ///     })
    ///     .unwrap();
    /// assert!(sched.cancel(id));
    /// assert!(!sched.cancel(RequestId(999)));
    /// ```
    pub fn cancel(&mut self, id: RequestId) -> bool {
        // Try the queue first.
        if let Some(pos) = self.queue.iter().position(|r| r.id == id) {
            self.queue.remove(pos);
            self.states.insert(id, RequestState::Preempted);
            return true;
        }

        // Try the active batch.
        if let Some(pos) = self.active.iter().position(|ar| ar.request.id == id) {
            let victim = self.active.remove(pos);
            self.states.insert(id, RequestState::Preempted);
            self.completed.push(CompletedRequest {
                id,
                prompt_tokens: victim.request.prompt_tokens,
                generated_tokens: victim.generated_tokens,
                finish_reason: FinishReason::Preempted,
            });
            return true;
        }

        false
    }

    /// Return the total number of active and queued (pending) requests.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{BatchConfig, BatchScheduler};
    /// let sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// assert_eq!(sched.pending_count(), 0);
    /// ```
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.active.len() + self.queue.len()
    }

    /// Return the number of currently active (generating) requests.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{BatchConfig, BatchScheduler};
    /// let sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// assert_eq!(sched.active_count(), 0);
    /// ```
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Drain and return all completed requests, clearing the internal list.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_runtime::batch::{BatchConfig, BatchScheduler};
    /// let mut sched = BatchScheduler::new(BatchConfig {
    ///     max_batch_size: 4,
    ///     max_queue_size: 16,
    ///     preemption_enabled: false,
    ///     max_total_tokens: 512,
    /// });
    /// let drained = sched.drain_completed();
    /// assert!(drained.is_empty());
    /// ```
    pub fn drain_completed(&mut self) -> Vec<CompletedRequest> {
        std::mem::take(&mut self.completed)
    }
}

// =============================================================================
// Private sampling helpers
// =============================================================================

/// Apply temperature + top-k filtering and sample a token index from `logits`.
///
/// Returns the sampled token as a `usize` vocabulary index, or an error string
/// describing the failure.
///
/// # Procedure
///
/// 1. Empty logits → error.
/// 2. `temperature == 0.0` or `top_k == 1` → argmax (greedy).
/// 3. Divide logits by `temperature`; compute numerically stable softmax.
/// 4. If `top_k > 0 && top_k < vocab_size`: zero out all but the top-k
///    entries and renormalize.
/// 5. Sample via inverse-CDF with a deterministic xorshift32 PRNG seeded
///    by the bit pattern of the first logit value.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn sample_token(logits: &[f32], temperature: f32, top_k: usize) -> Result<usize, String> {
    if logits.is_empty() {
        return Err("batch::sample_token: empty logits".into());
    }

    // Greedy path: temperature = 0 or top_k = 1.
    if temperature == 0.0 || top_k == 1 {
        return Ok(logits
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(0, |(i, _)| i));
    }

    // Temperature scaling.
    let scaled: Vec<f32> = logits.iter().map(|&l| l / temperature).collect();

    // Numerically stable softmax.
    let max_l = scaled.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut probs: Vec<f32> = scaled.iter().map(|&l| (l - max_l).exp()).collect();
    let sum_exp: f32 = probs.iter().sum();
    if sum_exp == 0.0 {
        let uniform = 1.0_f32 / logits.len() as f32;
        probs.iter_mut().for_each(|p| *p = uniform);
    } else {
        probs.iter_mut().for_each(|p| *p /= sum_exp);
    }

    // Top-k filtering.
    let effective_k = if top_k == 0 || top_k >= probs.len() {
        probs.len()
    } else {
        top_k
    };

    if effective_k < probs.len() {
        let mut indices: Vec<usize> = (0..probs.len()).collect();
        indices.sort_unstable_by(|&a, &b| {
            probs
                .get(b)
                .and_then(|pb| probs.get(a).map(|pa| pb.partial_cmp(pa)))
                .flatten()
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for &idx in indices.get(effective_k..).unwrap_or(&[]) {
            if let Some(p) = probs.get_mut(idx) {
                *p = 0.0;
            }
        }
        let new_sum: f32 = probs.iter().sum();
        if new_sum > 0.0 {
            probs.iter_mut().for_each(|p| *p /= new_sum);
        }
    }

    // Deterministic xorshift32 PRNG seeded from first logit's bit pattern.
    let seed_bits = logits.first().copied().unwrap_or(1.0_f32).to_bits();
    let seed = if seed_bits == 0 { 1 } else { seed_bits };
    let rand_val = xorshift32(seed);
    let u = (rand_val as f32) / (u32::MAX as f32);

    // Inverse-CDF sampling.
    let mut cumsum = 0.0_f32;
    for (idx, &p) in probs.iter().enumerate() {
        cumsum += p;
        if u < cumsum {
            return Ok(idx);
        }
    }

    // Fallback: last non-zero entry (handles floating-point rounding).
    Ok(probs
        .iter()
        .enumerate()
        .rev()
        .find(|&(_, &p)| p > 0.0)
        .map_or(0, |(i, _)| i))
}

/// Canonical xorshift32 PRNG (Marsaglia, 2003).
///
/// Used for reproducible, seed-deterministic token sampling.
/// Not suitable for cryptographic use.
#[inline]
fn xorshift32(mut state: u32) -> u32 {
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
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Build a `BatchConfig` with sensible defaults for most tests.
    fn default_config() -> BatchConfig {
        BatchConfig {
            max_batch_size: 8,
            max_queue_size: 64,
            preemption_enabled: true,
            max_total_tokens: 4096,
        }
    }

    /// Build a minimal `InferenceRequest` with the given ID and priority.
    fn make_request(id: RequestId, priority: Priority) -> InferenceRequest {
        InferenceRequest {
            id,
            prompt_tokens: vec![1, 2, 3],
            max_new_tokens: 10,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority,
        }
    }

    /// A `forward_fn` that always returns token index 0 (logit 1.0 for token 0,
    /// 0.0 for everything else) — deterministic greedy output of token 0.
    fn greedy_zero_forward(batch: &[(RequestId, &[usize])]) -> Vec<(RequestId, Vec<f32>)> {
        batch
            .iter()
            .map(|(id, _)| (*id, vec![1.0_f32, 0.0, 0.0, 0.0]))
            .collect()
    }

    // -------------------------------------------------------------------------
    // Test 1: new_scheduler_empty
    // -------------------------------------------------------------------------

    #[test]
    fn new_scheduler_empty() {
        let sched = BatchScheduler::new(default_config());
        assert_eq!(sched.active_count(), 0);
        assert_eq!(sched.pending_count(), 0);
    }

    // -------------------------------------------------------------------------
    // Test 2: submit_returns_unique_ids
    // -------------------------------------------------------------------------

    #[test]
    fn submit_returns_unique_ids() {
        let mut sched = BatchScheduler::new(default_config());
        let id0 = sched.next_request_id();
        let id1 = sched.next_request_id();
        let id2 = sched.next_request_id();
        let r0 = sched.submit(make_request(id0, Priority::Normal)).unwrap();
        let r1 = sched.submit(make_request(id1, Priority::Normal)).unwrap();
        let r2 = sched.submit(make_request(id2, Priority::Normal)).unwrap();
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);
        assert_ne!(r0, r2);
    }

    // -------------------------------------------------------------------------
    // Test 3: submit_rejects_when_queue_full
    // -------------------------------------------------------------------------

    #[test]
    fn submit_rejects_when_queue_full() {
        let mut sched = BatchScheduler::new(BatchConfig {
            max_batch_size: 8,
            max_queue_size: 2,
            preemption_enabled: false,
            max_total_tokens: 4096,
        });
        let id0 = sched.next_request_id();
        let id1 = sched.next_request_id();
        let id2 = sched.next_request_id();
        sched.submit(make_request(id0, Priority::Normal)).unwrap();
        sched.submit(make_request(id1, Priority::Normal)).unwrap();
        let err = sched
            .submit(make_request(id2, Priority::Normal))
            .unwrap_err();
        assert_eq!(err, BatchError::QueueFull);
    }

    // -------------------------------------------------------------------------
    // Test 4: schedule_promotes_to_active
    // -------------------------------------------------------------------------

    #[test]
    fn schedule_promotes_to_active() {
        let mut sched = BatchScheduler::new(default_config());
        let id = sched.next_request_id();
        sched.submit(make_request(id, Priority::Normal)).unwrap();
        assert_eq!(sched.active_count(), 0);

        // step() calls schedule() internally; using a noop forward_fn.
        sched.step(&mut greedy_zero_forward);
        assert_eq!(sched.active_count(), 1);
    }

    // -------------------------------------------------------------------------
    // Test 5: schedule_respects_max_batch_size
    // -------------------------------------------------------------------------

    #[test]
    fn schedule_respects_max_batch_size() {
        let mut sched = BatchScheduler::new(BatchConfig {
            max_batch_size: 2,
            max_queue_size: 64,
            preemption_enabled: false,
            max_total_tokens: 4096,
        });
        for _ in 0..5 {
            let id = sched.next_request_id();
            sched.submit(make_request(id, Priority::Normal)).unwrap();
        }
        sched.step(&mut greedy_zero_forward);
        assert_eq!(sched.active_count(), 2);
        assert_eq!(sched.queue.len(), 3);
    }

    // -------------------------------------------------------------------------
    // Test 6: schedule_priority_ordering
    // -------------------------------------------------------------------------

    #[test]
    fn schedule_priority_ordering() {
        let mut sched = BatchScheduler::new(BatchConfig {
            max_batch_size: 1,
            max_queue_size: 64,
            preemption_enabled: false,
            max_total_tokens: 4096,
        });
        let id_low = sched.next_request_id();
        let id_high = sched.next_request_id();
        // Submit low first, then high.
        sched.submit(make_request(id_low, Priority::Low)).unwrap();
        sched.submit(make_request(id_high, Priority::High)).unwrap();

        // schedule() should promote the High-priority request.
        sched.step(&mut greedy_zero_forward);
        assert_eq!(sched.active_count(), 1);
        assert_eq!(
            sched.get_state(id_high),
            Some(&RequestState::Active),
            "High-priority request should be active"
        );
        assert_eq!(
            sched.get_state(id_low),
            Some(&RequestState::Queued),
            "Low-priority request should still be queued"
        );
    }

    // -------------------------------------------------------------------------
    // Test 7: preemption_replaces_low_priority
    // -------------------------------------------------------------------------

    #[test]
    fn preemption_replaces_low_priority() {
        let mut sched = BatchScheduler::new(BatchConfig {
            max_batch_size: 1,
            max_queue_size: 64,
            preemption_enabled: true,
            max_total_tokens: 4096,
        });

        // Get a Low-priority request active first.
        let id_low = sched.next_request_id();
        sched.submit(make_request(id_low, Priority::Low)).unwrap();
        sched.step(&mut greedy_zero_forward);
        assert_eq!(sched.active_count(), 1);

        // Submit a Critical request while batch is full.
        let id_crit = sched.next_request_id();
        sched
            .submit(make_request(id_crit, Priority::Critical))
            .unwrap();

        // Next step triggers schedule() which should preempt Low for Critical.
        sched.step(&mut greedy_zero_forward);

        assert_eq!(sched.active_count(), 1);
        assert_eq!(
            sched.get_state(id_crit),
            Some(&RequestState::Active),
            "Critical request should now be active"
        );
        assert_eq!(
            sched.get_state(id_low),
            Some(&RequestState::Preempted),
            "Low request should be marked Preempted"
        );
    }

    // -------------------------------------------------------------------------
    // Test 8: preemption_disabled_no_replacement
    // -------------------------------------------------------------------------

    #[test]
    fn preemption_disabled_no_replacement() {
        let mut sched = BatchScheduler::new(BatchConfig {
            max_batch_size: 1,
            max_queue_size: 64,
            preemption_enabled: false,
            max_total_tokens: 4096,
        });

        let id_low = sched.next_request_id();
        sched.submit(make_request(id_low, Priority::Low)).unwrap();
        sched.step(&mut greedy_zero_forward);
        assert_eq!(sched.active_count(), 1);

        let id_crit = sched.next_request_id();
        sched
            .submit(make_request(id_crit, Priority::Critical))
            .unwrap();
        sched.step(&mut greedy_zero_forward);

        // With preemption disabled, Low stays active.
        assert_eq!(
            sched.get_state(id_low),
            Some(&RequestState::Active),
            "Low request should remain active (preemption disabled)"
        );
        assert_eq!(
            sched.get_state(id_crit),
            Some(&RequestState::Queued),
            "Critical request should remain queued"
        );
    }

    // -------------------------------------------------------------------------
    // Test 9: step_generates_one_token
    // -------------------------------------------------------------------------

    #[test]
    fn step_generates_one_token() {
        let mut sched = BatchScheduler::new(default_config());
        let id = sched.next_request_id();
        sched
            .submit(InferenceRequest {
                id,
                prompt_tokens: vec![10, 20],
                max_new_tokens: 5,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: None,
                priority: Priority::Normal,
            })
            .unwrap();

        sched.step(&mut greedy_zero_forward);

        // After one step the request is active with 1 generated token.
        assert_eq!(sched.active_count(), 1);
        let ar = &sched.active[0];
        assert_eq!(ar.tokens_generated, 1);
        assert_eq!(ar.generated_tokens.len(), 1);
    }

    // -------------------------------------------------------------------------
    // Test 10: step_completes_on_max_tokens
    // -------------------------------------------------------------------------

    #[test]
    fn step_completes_on_max_tokens() {
        let mut sched = BatchScheduler::new(default_config());
        let id = sched.next_request_id();
        sched
            .submit(InferenceRequest {
                id,
                prompt_tokens: vec![1],
                max_new_tokens: 3,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: None,
                priority: Priority::Normal,
            })
            .unwrap();

        let mut completed_all: Vec<CompletedRequest> = Vec::new();
        for _ in 0..4 {
            let c = sched.step(&mut greedy_zero_forward);
            completed_all.extend(c);
        }

        assert_eq!(completed_all.len(), 1);
        assert_eq!(completed_all[0].id, id);
        assert_eq!(completed_all[0].finish_reason, FinishReason::MaxTokens);
        assert_eq!(completed_all[0].generated_tokens.len(), 3);
        assert_eq!(sched.active_count(), 0);
    }

    // -------------------------------------------------------------------------
    // Test 11: step_completes_on_eos
    // -------------------------------------------------------------------------

    #[test]
    fn step_completes_on_eos() {
        let mut sched = BatchScheduler::new(default_config());
        let id = sched.next_request_id();
        // greedy_zero_forward always returns token 0; set eos_token_id = 0.
        sched
            .submit(InferenceRequest {
                id,
                prompt_tokens: vec![1],
                max_new_tokens: 10,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: Some(0),
                priority: Priority::Normal,
            })
            .unwrap();

        let completed = sched.step(&mut greedy_zero_forward);

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].finish_reason, FinishReason::EosToken);
        assert_eq!(sched.active_count(), 0);
    }

    // -------------------------------------------------------------------------
    // Test 12: cancel_removes_queued
    // -------------------------------------------------------------------------

    #[test]
    fn cancel_removes_queued() {
        let mut sched = BatchScheduler::new(default_config());
        let id = sched.next_request_id();
        sched.submit(make_request(id, Priority::Normal)).unwrap();
        assert_eq!(sched.pending_count(), 1);

        let removed = sched.cancel(id);
        assert!(removed, "cancel should return true for a queued request");
        assert_eq!(sched.pending_count(), 0);
    }

    // -------------------------------------------------------------------------
    // Test 13: cancel_active_request
    // -------------------------------------------------------------------------

    #[test]
    fn cancel_active_request() {
        let mut sched = BatchScheduler::new(default_config());
        let id = sched.next_request_id();
        sched.submit(make_request(id, Priority::Normal)).unwrap();

        // Promote to active.
        sched.step(&mut greedy_zero_forward);
        assert_eq!(sched.active_count(), 1);

        let removed = sched.cancel(id);
        assert!(removed, "cancel should return true for an active request");
        assert_eq!(sched.active_count(), 0);

        assert_eq!(sched.get_state(id), Some(&RequestState::Preempted));

        // The completed list should contain the cancelled request.
        let drained = sched.drain_completed();
        let found = drained.iter().find(|c| c.id == id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().finish_reason, FinishReason::Preempted);
    }

    // -------------------------------------------------------------------------
    // Test 14: cancel_unknown_returns_false
    // -------------------------------------------------------------------------

    #[test]
    fn cancel_unknown_returns_false() {
        let mut sched = BatchScheduler::new(default_config());
        assert!(!sched.cancel(RequestId(999)));
    }

    // -------------------------------------------------------------------------
    // Test 15: drain_completed_empties
    // -------------------------------------------------------------------------

    #[test]
    fn drain_completed_empties() {
        let mut sched = BatchScheduler::new(default_config());
        let id = sched.next_request_id();
        sched
            .submit(InferenceRequest {
                id,
                prompt_tokens: vec![1],
                max_new_tokens: 1,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: None,
                priority: Priority::Normal,
            })
            .unwrap();

        // Run until complete.
        for _ in 0..3 {
            sched.step(&mut greedy_zero_forward);
        }

        let first_drain = sched.drain_completed();
        assert!(
            !first_drain.is_empty(),
            "should have at least one completion"
        );

        let second_drain = sched.drain_completed();
        assert!(second_drain.is_empty(), "second drain should be empty");
    }

    // -------------------------------------------------------------------------
    // Test 16: full_lifecycle
    // -------------------------------------------------------------------------

    #[test]
    fn full_lifecycle() {
        let mut sched = BatchScheduler::new(BatchConfig {
            max_batch_size: 3,
            max_queue_size: 16,
            preemption_enabled: true,
            max_total_tokens: 4096,
        });

        let id_low = sched.next_request_id();
        let id_normal = sched.next_request_id();
        let id_high = sched.next_request_id();

        sched
            .submit(InferenceRequest {
                id: id_low,
                prompt_tokens: vec![1],
                max_new_tokens: 2,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: None,
                priority: Priority::Low,
            })
            .unwrap();
        sched
            .submit(InferenceRequest {
                id: id_normal,
                prompt_tokens: vec![2],
                max_new_tokens: 2,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: None,
                priority: Priority::Normal,
            })
            .unwrap();
        sched
            .submit(InferenceRequest {
                id: id_high,
                prompt_tokens: vec![3],
                max_new_tokens: 2,
                temperature: 0.0,
                top_k: 1,
                eos_token_id: None,
                priority: Priority::High,
            })
            .unwrap();

        let mut all_completed: Vec<CompletedRequest> = Vec::new();
        for _ in 0..10 {
            let c = sched.step(&mut greedy_zero_forward);
            all_completed.extend(c);
            if sched.active_count() == 0 && sched.queue.is_empty() {
                break;
            }
        }

        // All three requests must appear in completions.
        assert_eq!(all_completed.len(), 3, "all 3 requests must complete");
        let ids: Vec<RequestId> = all_completed.iter().map(|c| c.id).collect();
        assert!(ids.contains(&id_low));
        assert!(ids.contains(&id_normal));
        assert!(ids.contains(&id_high));

        for c in &all_completed {
            assert_eq!(
                c.finish_reason,
                FinishReason::MaxTokens,
                "request {:?} should finish with MaxTokens",
                c.id
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test 17: step_with_empty_batch_is_noop
    // -------------------------------------------------------------------------

    #[test]
    fn step_with_empty_batch_is_noop() {
        let mut sched = BatchScheduler::new(default_config());
        let mut called = false;
        let completed = sched.step(&mut |_batch| {
            called = true;
            vec![]
        });
        assert!(
            !called,
            "forward_fn should not be called when batch is empty"
        );
        assert!(completed.is_empty());
    }
}

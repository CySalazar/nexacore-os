//! `ai` — the SDK's AI invocation surface (TASK-13, ADR-0035 D3).
//!
//! One-line inference for applications: a
//! [`ServingInvoker`](crate::ai::ServingInvoker) wraps the runtime's
//! [`ServingRelay`](nexacore_runtime::relay::ServingRelay) and turns `prompt in → answer out` while
//! the relay enforces the session lifecycle, capability well-formedness,
//! and the [`BackendRouter`](nexacore_runtime::provider::BackendRouter)
//! audited dispatch (one `AuditRecord` with `backend_used` per request,
//! TASK-10).
//!
//! The invoker is deliberately thin: it owns the capability bytes and
//! the compact model id, builds the canonical
//! [`AiSyscallRequest`](nexacore_runtime::relay::AiSyscallRequest), and
//! maps the structured response into `Result<String, AiError>`.  Privacy
//! note: this surface does NOT run PII preprocessing — that belongs to
//! the agent path ([`crate::agent::BridgeLink`], which routes through
//! `OrchestratorBridge`).  Applications that handle user-authored text
//! should prefer the agent path.

use nexacore_runtime::relay::{AiSyscallNumber, AiSyscallRequest, IntentDispatcher, ServingRelay};
use thiserror::Error;

// =============================================================================
// Errors
// =============================================================================

/// Why an SDK inference call failed.
#[derive(Debug, Error)]
pub enum AiError {
    /// The runtime rejected or failed the request; the message carries
    /// the relay's structured error (no PII).
    #[error("runtime error: {0}")]
    Runtime(String),
    /// The reply payload was not valid UTF-8 text.
    #[error("reply is not valid UTF-8")]
    Encoding,
}

// =============================================================================
// ServingInvoker
// =============================================================================

/// High-level inference entry point over a [`ServingRelay`].
///
/// # Example
///
/// ```no_run
/// # use std::sync::Arc;
/// # use nexacore_runtime::provider::{BackendPolicy, BackendRouter};
/// # use nexacore_runtime::batch::BatchConfig;
/// # use nexacore_runtime::relay::ServingRelay;
/// # use nexacore_runtime::serving::SessionManager;
/// use nexacore_sdk::ai::ServingInvoker;
///
/// # #[tokio::main]
/// # async fn main() {
/// # let router = Arc::new(BackendRouter::new(BackendPolicy::PreferRemoteGpu));
/// # let manager = SessionManager::new(BatchConfig {
/// #     max_batch_size: 4, max_queue_size: 16,
/// #     preemption_enabled: false, max_total_tokens: 512,
/// # });
/// let relay = ServingRelay::new(manager, router);
/// let invoker = ServingInvoker::new(relay);
/// let answer = invoker.invoke("what is 2+2?", 1).await;
/// # let _ = answer;
/// # }
/// ```
pub struct ServingInvoker {
    /// The session-gated dispatch path (TASK-11).
    relay: ServingRelay,
    /// Opaque session-capability bytes presented on every request.
    /// Minimal well-formed token until TASK-S11.E lands real material.
    capability: Vec<u8>,
    /// Compact 16-byte model id (kernel ABI form).
    model_id: [u8; 16],
}

impl ServingInvoker {
    /// Build an invoker with the default capability token and model id.
    #[must_use]
    pub fn new(relay: ServingRelay) -> Self {
        Self {
            relay,
            capability: vec![0x01],
            model_id: *b"omni-sdk-default",
        }
    }

    /// Override the capability bytes (builder style).
    #[must_use]
    pub fn with_capability(mut self, capability: Vec<u8>) -> Self {
        self.capability = capability;
        self
    }

    /// Override the compact model id (builder style).
    #[must_use]
    pub fn with_model_id(mut self, model_id: [u8; 16]) -> Self {
        self.model_id = model_id;
        self
    }

    /// Run one inference round-trip: `prompt` in, model text out.
    ///
    /// # Errors
    ///
    /// - [`AiError::Runtime`] — the relay reported a failure (capability
    ///   rejected, session error, provider error, …).
    /// - [`AiError::Encoding`] — the reply bytes were not UTF-8.
    pub async fn invoke(&self, prompt: &str, request_id: u64) -> Result<String, AiError> {
        let request = AiSyscallRequest {
            syscall: AiSyscallNumber::Invoke,
            model_id_bytes: self.model_id,
            capability: self.capability.clone(),
            input_data: prompt.as_bytes().to_vec(),
            request_id,
            caller_pid: 0,
        };

        let response = IntentDispatcher::dispatch(&self.relay, request).await;
        if !response.success {
            return Err(AiError::Runtime(
                response
                    .error_message
                    .unwrap_or_else(|| String::from("unknown runtime error")),
            ));
        }
        String::from_utf8(response.output_data).map_err(|_| AiError::Encoding)
    }
}

impl std::fmt::Debug for ServingInvoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServingInvoker")
            .field("model_id", &self.model_id)
            .finish_non_exhaustive()
    }
}

//! `runtime_link` — the injectable seam between agents and the AI
//! runtime (TASK-13 / ADR-0035 D2).
//!
//! The five-agent architecture (NCIP-022) classifies and routes intents,
//! but until TASK-13 no agent ever *invoked* inference — the
//! [`TaskAgent`](crate::task::TaskAgent) answered with a synthetic
//! summary.  [`RuntimeLink`] is the seam that closes the loop: when a
//! Task agent holds a link and the intent calls for generative
//! reasoning, the operation result carries the REAL model answer.
//!
//! # Design (ADR-0035 D2)
//!
//! - The link is **optional**: an agent without one behaves exactly as
//!   before (the pre-TASK-13 test suite pins that behaviour).
//! - The trait is deliberately tiny (`prompt in → text out`) so tests
//!   inject a two-line mock and production injects
//!   `nexacore_sdk::agent::BridgeLink`, which drives
//!   `OrchestratorBridge<ServingRelay>` (PII preprocess → session-gated
//!   serving → `BackendRouter` audited dispatch → PII detokenize).
//! - Security-mode semantics (Standard/High-Risk/Emergency) are NOT
//!   moved here: pre-authorisation, veto, and autonomy clamps stay in
//!   their NCIP-022 homes — the link is pure transport to the runtime.

use async_trait::async_trait;
use thiserror::Error;

// =============================================================================
// Errors
// =============================================================================

/// Why a [`RuntimeLink`] call failed.
///
/// Carried back to the user inside the operation summary; never panics.
#[derive(Debug, Error)]
pub enum RuntimeLinkError {
    /// The runtime reported a failure (provider error, session error,
    /// malformed reply, …) — the message is the human-readable cause.
    #[error("inference failed: {0}")]
    Inference(String),
}

// =============================================================================
// RuntimeLink
// =============================================================================

/// Transport seam from an agent to the AI runtime.
///
/// Implementations:
///
/// - `nexacore_sdk::agent::BridgeLink` — production: drives
///   `OrchestratorBridge<ServingRelay>` so the prompt reaches a REAL
///   backend (`backend_used` audited by the router, TASK-10).
/// - test mocks — any fixed-reply implementation (see
///   [`crate::task`] tests).
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use nexacore_agent::runtime_link::{RuntimeLink, RuntimeLinkError};
///
/// struct FixedLink;
///
/// #[async_trait]
/// impl RuntimeLink for FixedLink {
///     async fn infer(&self, prompt: &str, _request_id: u64) -> Result<String, RuntimeLinkError> {
///         Ok(format!("echo: {prompt}"))
///     }
/// }
/// ```
#[async_trait]
pub trait RuntimeLink: Send + Sync {
    /// Run one inference round-trip: user prompt in, model text out.
    ///
    /// `request_id` correlates the call across agent messages, runtime
    /// audit records, and (on hardware) serial audit lines.
    ///
    /// # Errors
    ///
    /// [`RuntimeLinkError::Inference`] with a human-readable cause; the
    /// caller folds it into a failed operation result (no panics).
    async fn infer(&self, prompt: &str, request_id: u64) -> Result<String, RuntimeLinkError>;
}

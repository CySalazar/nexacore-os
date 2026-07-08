//! # `nexacore-sdk`
//!
//! Application SDK for NexaCore OS.
//!
//! High-level Rust API used by applications to invoke AI capabilities,
//! interact with agents, and handle encrypted data types. The SDK is the
//! primary integration surface for third-party developers.
//!
//! ## Status
//!
//! v0.2 — first real surface (TASK-13, ADR-0035 D3): [`ai`] exposes the
//! serving invocation API and [`agent`] bridges the five-agent
//! architecture (NCIP-022) to the runtime. [`data`] remains scaffold.
//!
//! ## Design rationale
//!
//! - **Ergonomics matters**: the SDK is the surface where adoption-by-
//!   developers is won or lost. APIs are designed for the common case to
//!   be one line.
//! - **Capabilities are first-class**: every API takes a capability token.
//!   Applications cannot "forget" to authenticate; the type system requires
//!   it.
//! - **Encrypted types propagate**: an `EncryptedString` cannot be
//!   converted to a `String` outside a TEE; the SDK preserves this through
//!   its own API.
//! - **Async-first**: every I/O / inference API is async.
//!
//! ## Modules
//!
//! - [`prelude`] — convenience re-exports for `use nexacore_sdk::prelude::*;`.
//! - [`ai`] — AI invocation API.
//! - [`agent`] — agent framework integration.
//! - [`data`] — encrypted-data-type integration.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-sdk")]
#![deny(missing_docs)]

/// Convenience re-exports for `use nexacore_sdk::prelude::*;`.
pub mod prelude {
    pub use nexacore_agent::runtime_link::{RuntimeLink, RuntimeLinkError};

    pub use crate::{
        agent::BridgeLink,
        ai::{AiError, ServingInvoker},
    };
}

/// AI invocation API (TASK-13, ADR-0035 D3).
///
/// [`ai::ServingInvoker`] is the one-line entry point for applications:
/// prompt in, model answer out, served through the session-gated
/// [`ServingRelay`](nexacore_runtime::relay::ServingRelay) and the
/// [`BackendRouter`](nexacore_runtime::provider::BackendRouter) audited
/// dispatch (`backend_used` recorded per request, TASK-10).
pub mod ai;

/// Agent framework integration (TASK-13, ADR-0035 D3).
///
/// [`agent::BridgeLink`] implements
/// [`RuntimeLink`](nexacore_agent::runtime_link::RuntimeLink) over
/// `OrchestratorBridge<ServingRelay>`, closing the loop
/// prompt → agent → bridge (PII preprocess) → serving → provider.
pub mod agent;

/// Encrypted-data-type integration.
pub mod data {
    // TODO(phase-2): re-exports + helpers for encrypted types.
}

#[cfg(test)]
mod tests {
    /// Placeholder test asserting the crate compiles.
    #[test]
    fn placeholder() {}
}

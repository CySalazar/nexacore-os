//! `agent` — five-agent architecture ↔ runtime integration (TASK-13,
//! ADR-0035 D3).
//!
//! [`BridgeLink`](crate::agent::BridgeLink) is the production implementation of
//! [`RuntimeLink`](nexacore_agent::runtime_link::RuntimeLink): it drives an
//! [`OrchestratorBridge`](nexacore_runtime::orchestrator_bridge::OrchestratorBridge)
//! instantiated over the REAL dispatch path
//! ([`ServingRelay`](nexacore_runtime::relay::ServingRelay)), so a prompt delegated by the
//! [`TaskAgent`](nexacore_agent::task::TaskAgent) traverses
//!
//! ```text
//! agent → bridge (PII preprocess) → serving (session + capability)
//!       → BackendRouter (audited; backend_used) → provider → answer
//! ```
//!
//! and the PII detokenisation runs on the way back — the full NCIP-022 →
//! runtime loop with no stub in the middle (DE-G7).

use async_trait::async_trait;
use nexacore_agent::runtime_link::{RuntimeLink, RuntimeLinkError};
use nexacore_runtime::{orchestrator_bridge::OrchestratorBridge, relay::ServingRelay};
use nexacore_types::ModelId;

// =============================================================================
// BridgeLink
// =============================================================================

/// Production [`RuntimeLink`]: agent intents → `OrchestratorBridge` →
/// [`ServingRelay`] → [`BackendRouter`](nexacore_runtime::provider::BackendRouter).
///
/// # Example
///
/// ```no_run
/// # use std::sync::Arc;
/// # use nexacore_runtime::provider::{BackendPolicy, BackendRouter};
/// # use nexacore_runtime::batch::BatchConfig;
/// # use nexacore_runtime::relay::ServingRelay;
/// # use nexacore_runtime::serving::SessionManager;
/// use nexacore_agent::task::TaskAgent;
/// use nexacore_sdk::agent::BridgeLink;
/// use nexacore_types::AgentId;
///
/// # let router = Arc::new(BackendRouter::new(BackendPolicy::PreferRemoteGpu));
/// # let manager = SessionManager::new(BatchConfig {
/// #     max_batch_size: 4, max_queue_size: 16,
/// #     preemption_enabled: false, max_total_tokens: 512,
/// # });
/// let relay = ServingRelay::new(manager, router);
/// let link = Arc::new(BridgeLink::new(relay));
/// let agent = TaskAgent::new(AgentId::new()).with_runtime_link(link);
/// ```
pub struct BridgeLink {
    /// Bridge over the REAL dispatch path (ADR-0035 D1).
    bridge: OrchestratorBridge<ServingRelay>,
    /// Model identity attached to every intent.
    model_id: ModelId,
}

impl BridgeLink {
    /// Build a link over `relay` with a zeroed model id (the Phase 2
    /// providers do not key on it; real model routing is TASK-16+).
    #[must_use]
    pub fn new(relay: ServingRelay) -> Self {
        Self {
            bridge: OrchestratorBridge::new(relay),
            model_id: ModelId::from_bytes([0u8; 32]),
        }
    }

    /// Override the model id (builder style).
    #[must_use]
    pub fn with_model_id(mut self, model_id: ModelId) -> Self {
        self.model_id = model_id;
        self
    }
}

#[async_trait]
impl RuntimeLink for BridgeLink {
    async fn infer(&self, prompt: &str, request_id: u64) -> Result<String, RuntimeLinkError> {
        let result = self
            .bridge
            .process_intent(prompt, self.model_id, request_id)
            .await;
        if result.success {
            Ok(result.response_text)
        } else {
            Err(RuntimeLinkError::Inference(result.response_text))
        }
    }
}

impl std::fmt::Debug for BridgeLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeLink").finish_non_exhaustive()
    }
}

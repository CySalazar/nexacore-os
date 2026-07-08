//! TASK-13 (DE-G7) host acceptance: prompt → Orchestrator → Task agent →
//! runtime (mock provider) → answer.
//!
//! Pins the PLAN.md TASK-13 host criterion end-to-end:
//!
//! 1. The **Orchestrator Agent** classifies the user intent and routes it
//!    to the Task agent (NCIP-022 dispatch).
//! 2. The **Task agent**, holding a [`BridgeLink`], serves the
//!    inference-class intent through
//!    `OrchestratorBridge<ServingRelay>` — the REAL dispatch path
//!    (session gating + `BackendRouter` audited dispatch), with a mock
//!    provider at the end so the answer is deterministic.
//! 3. The reply’s `OperationResult.summary` carries the model answer.
//!
//! The audit trail is asserted too: the router records exactly one
//! `AuditRecord` with `backend_used = RemoteGpu` for the served prompt.

// Integration tests are separate compilation units not covered by the
// crate-root allow set; `expect`/`panic`/indexing failures ARE the test
// failing, which is the intended behaviour. The early-drop lint trips on
// the audit-lock guard held across asserts — deliberate (the lock IS the
// read transaction).
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening
)]

use std::sync::Arc;

use async_trait::async_trait;
use nexacore_agent::{
    agent::{Agent, AgentKind},
    message::{AgentMessage, IntentClass, IntentPayload, MessageId, MessageKind, MessagePayload},
    mode::OperationalMode,
    orchestrator::OrchestratorAgent,
    task::TaskAgent,
};
use nexacore_runtime::{
    audit::{AuditLog, AuditSink, InMemoryAuditLog},
    batch::BatchConfig,
    provider::{
        BackendKind, BackendPolicy, BackendRouter, GenerateResponse, HealthStatus,
        InferenceProvider,
    },
    relay::ServingRelay,
    serving::SessionManager,
};
use nexacore_sdk::agent::BridgeLink;
use nexacore_types::AgentId;
use parking_lot::Mutex;

// =============================================================================
// Mock provider (the "runtime mock" of the acceptance criterion)
// =============================================================================

/// Deterministic provider standing in for the GPU backend.
struct EchoProvider;

#[async_trait]
impl InferenceProvider for EchoProvider {
    fn kind(&self) -> BackendKind {
        BackendKind::RemoteGpu
    }

    async fn generate(
        &self,
        req: &nexacore_runtime::provider::GenerateRequest,
    ) -> Result<GenerateResponse, nexacore_runtime::provider::ProviderError> {
        Ok(GenerateResponse {
            text: format!("MOCK-ANSWER:{}", req.prompt),
            tokens: 1,
        })
    }

    async fn chat(
        &self,
        _req: &nexacore_runtime::provider::ChatRequest,
    ) -> Result<nexacore_runtime::provider::ChatResponse, nexacore_runtime::provider::ProviderError>
    {
        Err(nexacore_runtime::provider::ProviderError::Backend(
            "unused".into(),
        ))
    }

    async fn embeddings(
        &self,
        _req: &nexacore_runtime::provider::EmbeddingsRequest,
    ) -> Result<
        nexacore_runtime::provider::EmbeddingsResponse,
        nexacore_runtime::provider::ProviderError,
    > {
        Err(nexacore_runtime::provider::ProviderError::Backend(
            "unused".into(),
        ))
    }

    async fn health(&self) -> HealthStatus {
        HealthStatus::ok()
    }
}

// =============================================================================
// Harness
// =============================================================================

/// Build the real serving stack over the mock provider, with an audit
/// log attached so `backend_used` is assertable.
fn serving_relay(audit: Arc<Mutex<InMemoryAuditLog>>) -> ServingRelay {
    let router = Arc::new(
        BackendRouter::new(BackendPolicy::PreferRemoteGpu)
            .with_remote_gpu(Box::new(EchoProvider))
            .with_audit(audit as Arc<dyn AuditSink>),
    );
    let manager = SessionManager::new(BatchConfig {
        max_batch_size: 4,
        max_queue_size: 16,
        preemption_enabled: false,
        max_total_tokens: 512,
    });
    ServingRelay::new(manager, router)
}

fn agent_id(seed: u8) -> AgentId {
    AgentId::from_bytes([seed; 16])
}

fn intent(content: &str, request_id: u64) -> AgentMessage {
    AgentMessage {
        id: MessageId::from_raw(request_id),
        from: agent_id(0xAA),
        to: agent_id(0xBB),
        timestamp: 0,
        kind: MessageKind::Dispatch,
        payload: MessagePayload::Intent(IntentPayload {
            classification: IntentClass::Task,
            content: content.to_owned(),
            request_id,
        }),
        capabilities: vec![],
        mode: OperationalMode::Standard,
    }
}

// =============================================================================
// E2E
// =============================================================================

/// PLAN.md TASK-13 host criterion: prompt → Orchestrator → Task agent →
/// runtime mock → answer.
#[tokio::test]
async fn prompt_traverses_orchestrator_task_agent_and_runtime() {
    // "compare" is BOTH an Orchestrator Task-class keyword AND a bridge
    // INFERENCE_KEYWORDS member — the intent routes to the Task agent
    // and the Task agent serves it through the runtime.
    const PROMPT: &str = "compare 2+2 and 3+1";
    const REQUEST_ID: u64 = 77;

    // ── Step 1: the Orchestrator classifies and routes the intent. ──
    let mut orchestrator = OrchestratorAgent::new(agent_id(0x01));
    orchestrator.spawn().await.expect("orchestrator spawns");

    let routed = orchestrator
        .handle_message(intent(PROMPT, REQUEST_ID))
        .await
        .expect("orchestrator handles the intent");
    let MessagePayload::OperationResult(classification) = &routed.payload else {
        panic!("unexpected orchestrator payload: {routed:?}");
    };
    assert!(
        classification
            .summary
            .contains(&AgentKind::Task.to_string())
            || classification.summary.to_lowercase().contains("task"),
        "intent must dispatch to the Task agent: {}",
        classification.summary
    );

    // ── Step 2: the Task agent serves it through the REAL path. ──
    let audit = Arc::new(Mutex::new(InMemoryAuditLog::new()));
    let link = Arc::new(BridgeLink::new(serving_relay(Arc::clone(&audit))));
    let mut task_agent = TaskAgent::new(agent_id(0x02)).with_runtime_link(link);
    task_agent.spawn().await.expect("task agent spawns");

    let reply = task_agent
        .handle_message(intent(PROMPT, REQUEST_ID))
        .await
        .expect("task agent handles the intent");

    // ── Step 3: the operation result carries the model answer. ──
    let MessagePayload::OperationResult(result) = &reply.payload else {
        panic!("unexpected task payload: {reply:?}");
    };
    assert!(result.success, "inference must succeed: {result:?}");
    assert_eq!(result.request_id, REQUEST_ID);
    assert!(
        result.summary.starts_with("MOCK-ANSWER:"),
        "summary must be the model answer, got: {}",
        result.summary
    );
    assert!(
        result.summary.contains("2+2"),
        "the prompt must reach the provider intact: {}",
        result.summary
    );

    // ── Audit: exactly one record, served by the (mock) RemoteGpu. ──
    let log = audit.lock();
    let records: Vec<_> = log.iter().collect();
    assert_eq!(records.len(), 1, "one AuditRecord per request (TASK-10)");
    assert_eq!(
        records[0].backend_used,
        Some(BackendKind::RemoteGpu),
        "backend_used must be recorded"
    );
}

/// Failure honesty: with NO provider registered, the Task agent reports
/// a clean failed result (never a panic, never a fabricated answer).
#[tokio::test]
async fn runtime_failure_folds_into_failed_operation_result() {
    let router = Arc::new(BackendRouter::new(BackendPolicy::PreferRemoteGpu));
    let manager = SessionManager::new(BatchConfig {
        max_batch_size: 4,
        max_queue_size: 16,
        preemption_enabled: false,
        max_total_tokens: 512,
    });
    let link = Arc::new(BridgeLink::new(ServingRelay::new(manager, router)));

    let mut task_agent = TaskAgent::new(agent_id(0x03)).with_runtime_link(link);
    task_agent.spawn().await.expect("task agent spawns");

    let reply = task_agent
        .handle_message(intent("explain the boot sequence", 5))
        .await
        .expect("handler never panics");
    let MessagePayload::OperationResult(result) = &reply.payload else {
        panic!("unexpected payload: {reply:?}");
    };
    assert!(!result.success, "no backend → failed result: {result:?}");
}

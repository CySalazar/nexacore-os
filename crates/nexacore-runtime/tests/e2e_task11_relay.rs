//! E2E integration test for TASK-11 (DE-G6): simulated kernel AI syscall
//! → postcard wire → `ServingRelay` → `SessionManager` + `BackendRouter`
//! (mock provider) → postcard wire → response back to the "caller".
//!
//! This exercises EXACTLY the bytes the kernel relay will move over the
//! 2-channel IPC rendezvous: the test plays the kernel role (encode the
//! request, decode the response) against the real runtime serving stack,
//! so the wire contract is pinned host-side before the Ring 3 image and
//! the kernel handler ship (ADR-0032).
//!
//! The session open/submit/stream/close *batch-path* lifecycle is
//! covered by `tests/e2e_sprint11_serving.rs`; here the lifecycle
//! assertion is that every dispatch leaves the session table empty
//! (open → serve → close inside the relay).

// Integration tests are separate compilation units not covered by the
// crate-root allow set; `unwrap`/`expect` panics the test on failure,
// which is the intended behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use nexacore_runtime::{
    provider::{BackendPolicy, BackendRouter, GenerateResponse, InferenceProvider},
    relay::ServingRelay,
    serving::{BatchConfig, SessionManager},
};
use nexacore_types::{
    ai::{AI_MAX_PAYLOAD, AiSyscallNumber, AiSyscallRequest, AiSyscallResponse},
    wire::{decode_canonical, encode_canonical},
};

/// A deterministic mock provider standing in for the GPU backend: echoes
/// the prompt with a fixed prefix, like the Ring 3 service image's mock.
struct EchoProvider;

#[async_trait::async_trait]
impl InferenceProvider for EchoProvider {
    fn kind(&self) -> nexacore_runtime::provider::BackendKind {
        nexacore_runtime::provider::BackendKind::RemoteGpu
    }

    async fn generate(
        &self,
        req: &nexacore_runtime::provider::GenerateRequest,
    ) -> Result<GenerateResponse, nexacore_runtime::provider::ProviderError> {
        Ok(GenerateResponse {
            text: format!("MOCK:{}", req.prompt),
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
        Ok(nexacore_runtime::provider::EmbeddingsResponse {
            embedding: vec![1.0, 2.0],
        })
    }

    async fn health(&self) -> nexacore_runtime::provider::HealthStatus {
        nexacore_runtime::provider::HealthStatus::ok()
    }
}

fn relay() -> ServingRelay {
    let router = Arc::new(
        BackendRouter::new(BackendPolicy::PreferRemoteGpu).with_remote_gpu(Box::new(EchoProvider)),
    );
    let manager = SessionManager::new(BatchConfig {
        max_batch_size: 4,
        max_queue_size: 16,
        preemption_enabled: false,
        max_total_tokens: 512,
    });
    ServingRelay::new(manager, router)
}

/// Play the kernel: postcard-encode the request, hand the BYTES to the
/// service side, decode the response BYTES that come back.
async fn kernel_round_trip(relay: &ServingRelay, req: &AiSyscallRequest) -> AiSyscallResponse {
    // Kernel side: encode (this is what travels on the `ai` channel).
    let wire_req = encode_canonical(req).expect("kernel-side encode");
    assert!(
        wire_req.len() <= AI_MAX_PAYLOAD + 64,
        "request wire stays near the payload bound"
    );

    // Service side: decode exactly those bytes, dispatch, encode reply.
    let decoded: AiSyscallRequest = decode_canonical(&wire_req).expect("service-side decode");
    let resp = relay.dispatch(decoded).await;
    let wire_resp = encode_canonical(&resp).expect("service-side encode");

    // Kernel side: decode the reply bytes (what travels on `ai_reply`).
    decode_canonical(&wire_resp).expect("kernel-side decode")
}

#[tokio::test]
async fn e2e_simulated_ai_syscall_through_wire_and_mock_provider() {
    let relay = relay();
    let req = AiSyscallRequest {
        syscall: AiSyscallNumber::Invoke,
        model_id_bytes: [0x42; 16],
        capability: vec![0x01],
        input_data: b"hello from ring3".to_vec(),
        request_id: 77,
        caller_pid: 6,
    };

    let resp = kernel_round_trip(&relay, &req).await;
    assert!(resp.success, "{:?}", resp.error_message);
    assert_eq!(resp.request_id, 77);
    assert_eq!(resp.output_data, b"MOCK:hello from ring3");
    assert_eq!(relay.session_count().await, 0, "session closed");
}

#[tokio::test]
async fn e2e_embed_round_trips_vector_over_the_wire() {
    let relay = relay();
    let req = AiSyscallRequest {
        syscall: AiSyscallNumber::Embed,
        model_id_bytes: [0x42; 16],
        capability: vec![0x01],
        input_data: b"embed me".to_vec(),
        request_id: 78,
        caller_pid: 6,
    };

    let resp = kernel_round_trip(&relay, &req).await;
    assert!(resp.success, "{:?}", resp.error_message);
    let v: Vec<f32> = decode_canonical(&resp.output_data).expect("vector");
    assert_eq!(v, vec![1.0, 2.0]);
}

#[tokio::test]
async fn e2e_negative_no_capability_is_clean_error_over_the_wire() {
    let relay = relay();
    let req = AiSyscallRequest {
        syscall: AiSyscallNumber::Invoke,
        model_id_bytes: [0x42; 16],
        capability: vec![], // caller "without capability"
        input_data: b"hi".to_vec(),
        request_id: 79,
        caller_pid: 6,
    };

    let resp = kernel_round_trip(&relay, &req).await;
    assert!(!resp.success);
    assert!(resp.output_data.is_empty());
    assert!(resp.error_message.unwrap().contains("capability"));
}

#[tokio::test]
async fn e2e_negative_oversized_payload_is_clean_error_over_the_wire() {
    let relay = relay();
    let req = AiSyscallRequest {
        syscall: AiSyscallNumber::Invoke,
        model_id_bytes: [0x42; 16],
        capability: vec![0x01],
        input_data: vec![b'x'; AI_MAX_PAYLOAD + 1],
        request_id: 80,
        caller_pid: 6,
    };

    // The kernel bounds this before encoding in production; the service
    // must ALSO reject it (defence in depth — counterpart untrusted).
    let resp = kernel_round_trip(&relay, &req).await;
    assert!(!resp.success);
    assert!(resp.error_message.unwrap().contains("AI_MAX_PAYLOAD"));
}

#[tokio::test]
async fn e2e_sequential_requests_reuse_relay_cleanly() {
    // Several requests through the same relay: every one gets exactly
    // one response with its own request_id, and no session leaks.
    let relay = relay();
    for rid in 0..5u64 {
        let req = AiSyscallRequest {
            syscall: AiSyscallNumber::Invoke,
            model_id_bytes: [0x42; 16],
            capability: vec![0x01],
            input_data: format!("req {rid}").into_bytes(),
            request_id: rid,
            caller_pid: 6,
        };
        let resp = kernel_round_trip(&relay, &req).await;
        assert!(resp.success);
        assert_eq!(resp.request_id, rid);
        assert_eq!(resp.output_data, format!("MOCK:req {rid}").into_bytes());
    }
    assert_eq!(relay.session_count().await, 0);
}

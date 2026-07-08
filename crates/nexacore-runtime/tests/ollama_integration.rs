//! Integration tests for the `OllamaProvider` + `TokioTcpTransport`
//! against a real TCP socket — TASK-09 (DE-G2).
//!
//! Two layers:
//!
//! 1. **Loopback mock server (always on):** a throwaway `tokio` TCP
//!    listener on `127.0.0.1:0` speaks a canned HTTP/1.1 Ollama response.
//!    This exercises the *real* [`TokioTcpTransport`] (connect → write →
//!    bounded read to EOF) end-to-end, on every `cargo test`, with no dev
//!    infrastructure.
//! 2. **Real Ollama (feature-gated):** `GET /api/tags` against the dev
//!    LXC 101, asserting `gemma4:latest` is present. Behind the
//!    `ollama-integration-tests` feature (off by default / in CI) because
//!    it needs reachable dev network.
//!
//! Run the loopback layer with `cargo test -p nexacore-runtime --test
//! ollama_integration`; add `--features ollama-integration-tests` for the
//! real-Ollama layer.

// Integration tests are separate compilation units not covered by the
// crate-root allow set; `unwrap`/`expect` here panics the test on failure,
// which is the intended behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use nexacore_runtime::provider::{
    ChatRequest, GenerateRequest, InferenceProvider,
    ollama::{OllamaConfig, OllamaEndpoint, OllamaProvider, TokioTcpTransport},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// Spawn a one-shot loopback HTTP server that returns `response_body` as
/// the body of a `200 OK`, after draining the client's request. Returns
/// the bound port. The task serves exactly `n` connections then exits.
async fn spawn_mock_ollama(response_body: &'static str, n: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        for _ in 0..n {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Drain the request headers (read until \r\n\r\n or a bounded
            // amount); we do not need the body for these canned responses.
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
            // Drop closes the socket → client sees EOF (Connection: close).
        }
    });
    port
}

fn provider_for(port: u16) -> OllamaProvider<TokioTcpTransport> {
    let cfg = OllamaConfig::new(
        vec![OllamaEndpoint::new("127.0.0.1", port)],
        "gemma4:latest",
    )
    .unwrap();
    let transport = TokioTcpTransport::new(Duration::from_secs(2), Duration::from_secs(5));
    OllamaProvider::new(cfg, transport)
}

#[tokio::test]
async fn tokio_transport_generate_against_loopback() {
    let port = spawn_mock_ollama(r#"{"response":"hello from loopback","eval_count":5}"#, 1).await;
    let provider = provider_for(port);
    let resp = provider
        .generate(&GenerateRequest {
            model: "ignored".to_owned(),
            prompt: "hi".to_owned(),
            max_tokens: 8,
        })
        .await
        .expect("loopback generate");
    assert_eq!(resp.text, "hello from loopback");
    assert_eq!(resp.tokens, 5);
}

#[tokio::test]
async fn tokio_transport_chat_against_loopback() {
    let port = spawn_mock_ollama(
        r#"{"message":{"role":"assistant","content":"4"},"eval_count":2}"#,
        1,
    )
    .await;
    let provider = provider_for(port);
    let resp = provider
        .chat(&ChatRequest {
            model: "ignored".to_owned(),
            messages: vec![nexacore_runtime::provider::ChatMessage {
                role: "user".to_owned(),
                content: "2+2?".to_owned(),
            }],
        })
        .await
        .expect("loopback chat");
    assert_eq!(resp.message.content, "4");
}

#[tokio::test]
async fn tokio_transport_health_against_loopback() {
    let port = spawn_mock_ollama(r#"{"models":[{"name":"gemma4:latest"}]}"#, 2).await;
    let provider = provider_for(port);
    let health = provider.health().await;
    assert!(health.healthy, "{health:?}");
    let models = provider.list_models().await.expect("models");
    assert!(models.iter().any(|m| m == "gemma4:latest"), "{models:?}");
}

#[tokio::test]
async fn tokio_transport_connect_refused_is_unavailable() {
    // Nothing is listening on this port → connect refused → Unavailable
    // (retriable). Using a port we never bound.
    let cfg =
        OllamaConfig::new(vec![OllamaEndpoint::new("127.0.0.1", 1)], "gemma4:latest").unwrap();
    let transport = TokioTcpTransport::new(Duration::from_millis(500), Duration::from_secs(2));
    let provider = OllamaProvider::new(cfg, transport);
    let err = provider
        .generate(&GenerateRequest {
            model: "m".to_owned(),
            prompt: "p".to_owned(),
            max_tokens: 0,
        })
        .await
        .expect_err("refused");
    assert!(err.is_retriable(), "{err:?}");
}

/// Real Ollama on the dev LXC 101 — feature-gated (needs dev network).
#[cfg(feature = "ollama-integration-tests")]
#[tokio::test]
async fn real_ollama_tags_lists_gemma() {
    let provider = OllamaProvider::new(OllamaConfig::dev_default(), TokioTcpTransport::default());
    let models = provider
        .list_models()
        .await
        .expect("GET /api/tags against real Ollama");
    assert!(
        models.iter().any(|m| m.contains("gemma4")),
        "expected gemma4 in {models:?}"
    );
}

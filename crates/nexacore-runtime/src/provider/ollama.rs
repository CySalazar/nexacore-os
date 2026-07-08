//! `OllamaProvider` — the `RemoteGpu` backend (TASK-09, DE-G2).
//!
//! A minimal HTTP/1.1 client that speaks the [Ollama](https://ollama.com)
//! API (`/api/generate`, `/api/chat`, `/api/embeddings`, `/api/tags`),
//! implementing [`InferenceProvider`] so the [`super::BackendRouter`] can
//! route `RemoteGpu` traffic to a user-owned GPU box.
//!
//! ## Transport is abstracted (ADR-0030)
//!
//! The HTTP *protocol* logic (request shaping, response parsing, JSON
//! marshalling, endpoint failover, bounded reads) lives here; the
//! *transport* (how bytes reach the wire) is the [`HttpTransport`] trait.
//! That decoupling lets the exact same provider:
//!
//! - run against a real Ollama over `std`/`tokio` TCP on a dev host
//!   ([`TokioTcpTransport`]) — the integration test + the eventual host
//!   build of the runtime service;
//! - be unit-tested against an in-memory mock transport (no socket, no
//!   port binding) for request-shaping + parsing + error-handling; and
//! - later run **inside NexaCore OS (Ring 3)** over `nexacore-net` via `nexacore-usys`
//!   NET syscalls — the chain proven in TASK-05 — by supplying an
//!   `nexacore-usys`-backed `HttpTransport`. That binding is the integration
//!   point of TASK-11 (syscall AI → runtime → provider); it is **not** in
//!   TASK-09's scope, and the trait is the seam that keeps this module
//!   identical across all three.
//!
//! ## Untrusted input
//!
//! The response comes off the network and is **not trusted**:
//!
//! - [`HttpTransport::round_trip`] reads at most `max_response_bytes`
//!   (configured, default [`DEFAULT_MAX_RESPONSE_BYTES`]); an oversize
//!   response is a clean error, never an unbounded allocation.
//! - JSON parsing maps any malformation to [`ProviderError::Backend`] —
//!   no panic, no `unwrap` on parsed data.
//!
//! ## Configuration, not hard-coding
//!
//! Endpoints and the model live in [`OllamaConfig`]; the provider hard-codes
//! none of them. The dev defaults (localhost `127.0.0.1:11434` primary,
//! example `192.0.2.11:11434` fallback, model `gemma4:latest`) are
//! offered by [`OllamaConfig::dev_default`] for convenience but are just a
//! constructor — callers supply their own in production (TASK-23 Settings).

use async_trait::async_trait;
use nexacore_cmd_curl::{HttpMethod, HttpRequest, HttpResponse, build_request, parse_response};
use serde::{Deserialize, Serialize};

use super::{
    BackendKind, ChatRequest, ChatResponse, EmbeddingsRequest, EmbeddingsResponse, GenerateRequest,
    GenerateResponse, HealthStatus, InferenceProvider, ProviderError,
};

/// Default upper bound on a single response body, in bytes (8 MiB).
///
/// The transport refuses to buffer more than this from the network, so a
/// hostile or buggy server cannot drive an unbounded allocation. 8 MiB
/// comfortably holds any non-streaming completion or the `/api/tags`
/// model list while still being a hard ceiling.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Default connect timeout for [`TokioTcpTransport`].
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 3_000;

/// Default per-read timeout for [`TokioTcpTransport`].
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 30_000;

// =============================================================================
// HttpTransport
// =============================================================================

/// The byte-level transport the [`OllamaProvider`] sends requests over.
///
/// One method: connect to `host:port`, send the already-serialised HTTP
/// request, and return the complete raw response bytes (the server is
/// asked to `Connection: close`, so "complete" = read to EOF). The
/// implementation MUST NOT buffer more than `max_response_bytes`.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Round-trip `request` to `host:port` and return the raw response.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::Unavailable`] — could not connect (retriable;
    ///   the provider falls through to the next endpoint).
    /// - [`ProviderError::Transport`] — a mid-request I/O failure
    ///   (retriable).
    /// - [`ProviderError::Backend`] — the response exceeded
    ///   `max_response_bytes` (terminal — a server flooding us is not a
    ///   connectivity problem another endpoint would fix).
    async fn round_trip(
        &self,
        host: &str,
        port: u16,
        request: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, ProviderError>;
}

// =============================================================================
// TokioTcpTransport
// =============================================================================

/// A [`HttpTransport`] over `std`/`tokio` TCP, for the dev host build and
/// the integration test.
///
/// Reads are bounded (`max_response_bytes`) and both connect and read are
/// time-bounded so a black-hole endpoint cannot hang the caller.
#[derive(Clone, Debug)]
pub struct TokioTcpTransport {
    connect_timeout: std::time::Duration,
    read_timeout: std::time::Duration,
}

impl TokioTcpTransport {
    /// Construct with explicit timeouts.
    #[must_use]
    pub fn new(connect_timeout: std::time::Duration, read_timeout: std::time::Duration) -> Self {
        Self {
            connect_timeout,
            read_timeout,
        }
    }
}

impl Default for TokioTcpTransport {
    fn default() -> Self {
        Self::new(
            std::time::Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            std::time::Duration::from_millis(DEFAULT_READ_TIMEOUT_MS),
        )
    }
}

#[async_trait]
impl HttpTransport for TokioTcpTransport {
    async fn round_trip(
        &self,
        host: &str,
        port: u16,
        request: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, ProviderError> {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpStream,
            time::timeout,
        };

        let connect = TcpStream::connect((host, port));
        let mut stream = timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| ProviderError::Unavailable(format!("connect timeout to {host}:{port}")))?
            .map_err(|e| ProviderError::Unavailable(format!("connect {host}:{port}: {e}")))?;

        stream
            .write_all(request)
            .await
            .map_err(|e| ProviderError::Transport(format!("write: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| ProviderError::Transport(format!("flush: {e}")))?;

        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = timeout(self.read_timeout, stream.read(&mut chunk))
                .await
                .map_err(|_| ProviderError::Transport("read timeout".to_owned()))?
                .map_err(|e| ProviderError::Transport(format!("read: {e}")))?;
            if n == 0 {
                break; // EOF — server closed (Connection: close).
            }
            // Bound BEFORE extending so `buf` never exceeds the cap.
            if buf.len().saturating_add(n) > max_response_bytes {
                return Err(ProviderError::Backend(format!(
                    "response exceeds {max_response_bytes}-byte cap"
                )));
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
        Ok(buf)
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// One Ollama endpoint (`host:port`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OllamaEndpoint {
    /// Hostname or IP literal.
    pub host: String,
    /// TCP port (Ollama's default is `11434`).
    pub port: u16,
}

impl OllamaEndpoint {
    /// Construct an endpoint.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// Where (and as which model) the [`OllamaProvider`] talks to Ollama.
///
/// `endpoints` is tried in order (primary first, fallbacks after) on a
/// *connectivity* failure — the LAN address first, the Tailscale address
/// as backup. None of this is hard-coded in the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OllamaConfig {
    /// Ordered endpoints; index 0 is primary.
    endpoints: Vec<OllamaEndpoint>,
    /// Model name sent in each request (e.g. `"gemma4:latest"`).
    model: String,
    /// Hard ceiling on a single response body.
    max_response_bytes: usize,
}

impl OllamaConfig {
    /// Build a config from an explicit endpoint list and model.
    ///
    /// # Errors
    ///
    /// [`ProviderError::InvalidRequest`] if `endpoints` is empty or
    /// `model` is blank — a provider with nowhere to connect or no model
    /// is unusable, so reject it at construction rather than per-request.
    pub fn new(
        endpoints: Vec<OllamaEndpoint>,
        model: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let model = model.into();
        if endpoints.is_empty() {
            return Err(ProviderError::InvalidRequest(
                "OllamaConfig needs at least one endpoint".to_owned(),
            ));
        }
        if model.trim().is_empty() {
            return Err(ProviderError::InvalidRequest(
                "OllamaConfig needs a non-empty model".to_owned(),
            ));
        }
        Ok(Self {
            endpoints,
            model,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// The dev-environment default: localhost primary + example fallback,
    /// model `gemma4:latest`. A convenience constructor — production
    /// callers build their own [`OllamaConfig`] from user settings
    /// (TASK-23). Ollama listens on `127.0.0.1:11434` by default; the
    /// second endpoint is an RFC 5737 documentation address, replaced by
    /// a real backend host via user settings.
    #[must_use]
    pub fn dev_default() -> Self {
        // Unwrap is sound: the literal endpoint list is non-empty and the
        // model is non-blank, so `new` cannot return `Err` here.
        Self::new(
            vec![
                OllamaEndpoint::new("127.0.0.1", 11434),
                OllamaEndpoint::new("192.0.2.11", 11434),
            ],
            "gemma4:latest",
        )
        .unwrap_or_else(|_| unreachable!("dev_default endpoints/model are valid by construction"))
    }

    /// Override the response-size ceiling (builder style).
    #[must_use]
    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }

    /// The configured endpoints (primary first).
    #[must_use]
    pub fn endpoints(&self) -> &[OllamaEndpoint] {
        &self.endpoints
    }

    /// The configured model name.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The configured response-size ceiling.
    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

// =============================================================================
// Ollama JSON wire shapes (internal)
// =============================================================================
//
// These mirror the Ollama HTTP API JSON. They are private: the public
// surface is the `provider` module's backend-neutral request/response
// types. `#[serde(default)]` on response fields makes parsing tolerant of
// fields Ollama omits in some modes.

#[derive(Serialize)]
struct GenerateBody<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<GenOptions>,
}

#[derive(Serialize)]
struct GenOptions {
    num_predict: u32,
}

#[derive(Serialize)]
struct ChatBody<'a> {
    model: &'a str,
    messages: Vec<WireMsg<'a>>,
    stream: bool,
}

#[derive(Serialize)]
struct WireMsg<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct EmbeddingsBody<'a> {
    model: &'a str,
    prompt: &'a str,
}

#[derive(Deserialize, Default)]
struct GenerateChunk {
    #[serde(default)]
    response: String,
    #[serde(default)]
    eval_count: u32,
    /// Why generation stopped. A real answer reports `"stop"`/`"length"`; a
    /// non-resident model (cold / mid-(un)load) replies with an empty
    /// `response` and `"load"`/`"unload"` — not a real answer (ADR-0050).
    #[serde(default)]
    done_reason: String,
}

#[derive(Deserialize, Default)]
struct ChatChunk {
    #[serde(default)]
    message: ChatMsgOwned,
    #[serde(default)]
    eval_count: u32,
}

#[derive(Deserialize, Default)]
struct ChatMsgOwned {
    #[serde(default)]
    role: String,
    #[serde(default)]
    content: String,
}

#[derive(Deserialize)]
struct EmbeddingsResp {
    #[serde(default)]
    embedding: Vec<f32>,
}

#[derive(Deserialize)]
struct TagsResp {
    #[serde(default)]
    models: Vec<TagModel>,
}

#[derive(Deserialize)]
struct TagModel {
    #[serde(default)]
    name: String,
}

// =============================================================================
// OllamaProvider
// =============================================================================

/// The `RemoteGpu` [`InferenceProvider`]: HTTP/1.1 to Ollama, generic
/// over the [`HttpTransport`].
pub struct OllamaProvider<T: HttpTransport> {
    config: OllamaConfig,
    transport: T,
}

impl<T: HttpTransport> OllamaProvider<T> {
    /// Construct a provider from a config and a transport.
    #[must_use]
    pub fn new(config: OllamaConfig, transport: T) -> Self {
        Self { config, transport }
    }

    /// Borrow the config.
    #[must_use]
    pub fn config(&self) -> &OllamaConfig {
        &self.config
    }

    /// JSON `Content-Type` + `Accept` headers shared by every POST.
    fn json_headers() -> Vec<(String, String)> {
        vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
        ]
    }

    /// Send one request, trying each configured endpoint in order until
    /// one connects. Returns the parsed [`HttpResponse`] (status not yet
    /// checked — the caller maps status to a provider result).
    ///
    /// Endpoint failover triggers only on a **retriable** transport error
    /// ([`ProviderError::is_retriable`]); a terminal error (oversize
    /// response) returns immediately.
    async fn send(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Vec<u8>>,
        headers: Vec<(String, String)>,
    ) -> Result<HttpResponse, ProviderError> {
        let mut last: Option<ProviderError> = None;
        for ep in &self.config.endpoints {
            let req = HttpRequest {
                method,
                host: ep.host.clone(),
                port: ep.port,
                path: path.to_owned(),
                headers: headers.clone(),
                body: body.clone(),
            };
            let wire = build_request(&req);
            match self
                .transport
                .round_trip(&ep.host, ep.port, &wire, self.config.max_response_bytes)
                .await
            {
                Ok(raw) => {
                    return parse_response(&raw).ok_or_else(|| {
                        ProviderError::Backend("malformed HTTP response from ollama".to_owned())
                    });
                }
                Err(e) if e.is_retriable() => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            ProviderError::Unavailable("no ollama endpoint reachable".to_owned())
        }))
    }

    /// Map an HTTP status to success/terminal error. 2xx passes; anything
    /// else is a [`ProviderError::Backend`] (terminal — the server
    /// answered, so another endpoint would not help).
    fn check_status(resp: &HttpResponse) -> Result<(), ProviderError> {
        if (200..=299).contains(&resp.status_code) {
            Ok(())
        } else {
            Err(ProviderError::Backend(format!(
                "ollama HTTP {} {}",
                resp.status_code, resp.status_text
            )))
        }
    }

    /// List the model names Ollama reports from `GET /api/tags`.
    ///
    /// Used by [`InferenceProvider::health`] and by the integration test.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] on connectivity, non-2xx status, or malformed
    /// JSON.
    pub async fn list_models(&self) -> Result<Vec<String>, ProviderError> {
        let resp = self
            .send(
                HttpMethod::Get,
                "/api/tags",
                None,
                vec![("Accept".to_owned(), "application/json".to_owned())],
            )
            .await?;
        Self::check_status(&resp)?;
        let text = std::str::from_utf8(&resp.body)
            .map_err(|_| ProviderError::Backend("non-UTF-8 /api/tags body".to_owned()))?;
        let tags: TagsResp = serde_json::from_str(text.trim())
            .map_err(|e| ProviderError::Backend(format!("/api/tags JSON: {e}")))?;
        Ok(tags.models.into_iter().map(|m| m.name).collect())
    }
}

/// Decode a body that is either a single JSON object or newline-delimited
/// JSON (Ollama's streaming form), applying `per_chunk` to every decoded
/// `C` and folding the results.
///
/// Single-object bodies (the `stream:false` case we request) decode in
/// one shot; if that fails, the body is treated as NDJSON and each
/// non-empty line is decoded — making the parser robust to a server that
/// streams anyway. Any malformation is a clean [`ProviderError::Backend`];
/// the input is already length-bounded by the transport, so this never
/// allocates without bound.
fn fold_ndjson<C, F>(body: &[u8], mut per_chunk: F) -> Result<(), ProviderError>
where
    C: for<'de> Deserialize<'de>,
    F: FnMut(C),
{
    let text = std::str::from_utf8(body)
        .map_err(|_| ProviderError::Backend("non-UTF-8 response body".to_owned()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(ProviderError::Backend("empty response body".to_owned()));
    }
    // Fast path: one complete JSON object.
    if let Ok(one) = serde_json::from_str::<C>(trimmed) {
        per_chunk(one);
        return Ok(());
    }
    // NDJSON path: one object per line.
    let mut any = false;
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let chunk: C = serde_json::from_str(line)
            .map_err(|e| ProviderError::Backend(format!("response JSON: {e}")))?;
        per_chunk(chunk);
        any = true;
    }
    if any {
        Ok(())
    } else {
        Err(ProviderError::Backend(
            "no JSON objects in response".to_owned(),
        ))
    }
}

#[async_trait]
impl<T: HttpTransport> InferenceProvider for OllamaProvider<T> {
    fn kind(&self) -> BackendKind {
        BackendKind::RemoteGpu
    }

    async fn generate(&self, req: &GenerateRequest) -> Result<GenerateResponse, ProviderError> {
        let body = serde_json::to_vec(&GenerateBody {
            model: &self.config.model,
            prompt: &req.prompt,
            stream: false,
            options: (req.max_tokens > 0).then_some(GenOptions {
                num_predict: req.max_tokens,
            }),
        })
        .map_err(|e| ProviderError::InvalidRequest(format!("encode /api/generate: {e}")))?;

        let resp = self
            .send(
                HttpMethod::Post,
                "/api/generate",
                Some(body),
                Self::json_headers(),
            )
            .await?;
        Self::check_status(&resp)?;

        let mut text = String::new();
        let mut tokens = 0u32;
        let mut done_reason = String::new();
        fold_ndjson::<GenerateChunk, _>(&resp.body, |c| {
            text.push_str(&c.response);
            if c.eval_count > 0 {
                tokens = c.eval_count;
            }
            if !c.done_reason.is_empty() {
                done_reason = c.done_reason;
            }
        })?;

        // A non-resident / loading model replies with an empty completion and
        // a `done_reason` other than "stop" ("load"/"unload"). Surface that as
        // a retriable `Unavailable` so the `BackendRouter` retries / fails
        // over — never a "successful empty answer" (the M1 empty-output bug;
        // ADR-0050). An empty answer WITH `done_reason == "stop"` is a genuine
        // (if rare) completion and is passed through.
        if text.is_empty() && !done_reason.is_empty() && done_reason != "stop" {
            return Err(ProviderError::Unavailable(format!(
                "ollama model not ready (done_reason={done_reason})"
            )));
        }

        Ok(GenerateResponse { text, tokens })
    }

    async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let messages: Vec<WireMsg<'_>> = req
            .messages
            .iter()
            .map(|m| WireMsg {
                role: &m.role,
                content: &m.content,
            })
            .collect();
        let body = serde_json::to_vec(&ChatBody {
            model: &self.config.model,
            messages,
            stream: false,
        })
        .map_err(|e| ProviderError::InvalidRequest(format!("encode /api/chat: {e}")))?;

        let resp = self
            .send(
                HttpMethod::Post,
                "/api/chat",
                Some(body),
                Self::json_headers(),
            )
            .await?;
        Self::check_status(&resp)?;

        let mut content = String::new();
        let mut role = String::new();
        let mut tokens = 0u32;
        fold_ndjson::<ChatChunk, _>(&resp.body, |c| {
            content.push_str(&c.message.content);
            if !c.message.role.is_empty() {
                role = c.message.role;
            }
            if c.eval_count > 0 {
                tokens = c.eval_count;
            }
        })?;
        let role = if role.is_empty() {
            "assistant".to_owned()
        } else {
            role
        };
        Ok(ChatResponse {
            message: super::ChatMessage { role, content },
            tokens,
        })
    }

    async fn embeddings(
        &self,
        req: &EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, ProviderError> {
        let body = serde_json::to_vec(&EmbeddingsBody {
            model: &self.config.model,
            prompt: &req.input,
        })
        .map_err(|e| ProviderError::InvalidRequest(format!("encode /api/embeddings: {e}")))?;

        let resp = self
            .send(
                HttpMethod::Post,
                "/api/embeddings",
                Some(body),
                Self::json_headers(),
            )
            .await?;
        Self::check_status(&resp)?;

        let text = std::str::from_utf8(&resp.body)
            .map_err(|_| ProviderError::Backend("non-UTF-8 embeddings body".to_owned()))?;
        let parsed: EmbeddingsResp = serde_json::from_str(text.trim())
            .map_err(|e| ProviderError::Backend(format!("embeddings JSON: {e}")))?;
        Ok(EmbeddingsResponse {
            embedding: parsed.embedding,
        })
    }

    async fn health(&self) -> HealthStatus {
        // health never errors (per the trait): an unreachable backend is
        // `healthy: false`, not an `Err`.
        match self.list_models().await {
            Ok(_) => HealthStatus::ok(),
            Err(e) => HealthStatus::unhealthy(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// In-memory mock transport: a closure decides the response (or error)
    /// per call, and every request's wire bytes are captured for
    /// request-shaping assertions.
    struct MockTransport<F>
    where
        F: Fn(&str, u16, &[u8]) -> Result<Vec<u8>, ProviderError> + Send + Sync,
    {
        handler: F,
        captured: Mutex<Vec<Vec<u8>>>,
    }

    impl<F> MockTransport<F>
    where
        F: Fn(&str, u16, &[u8]) -> Result<Vec<u8>, ProviderError> + Send + Sync,
    {
        fn new(handler: F) -> Self {
            Self {
                handler,
                captured: Mutex::new(Vec::new()),
            }
        }

        fn last_request(&self) -> Vec<u8> {
            self.captured
                .lock()
                .expect("mock lock")
                .last()
                .cloned()
                .unwrap_or_default()
        }

        fn call_count(&self) -> usize {
            self.captured.lock().expect("mock lock").len()
        }
    }

    #[async_trait]
    impl<F> HttpTransport for MockTransport<F>
    where
        F: Fn(&str, u16, &[u8]) -> Result<Vec<u8>, ProviderError> + Send + Sync,
    {
        async fn round_trip(
            &self,
            host: &str,
            port: u16,
            request: &[u8],
            _max: usize,
        ) -> Result<Vec<u8>, ProviderError> {
            self.captured
                .lock()
                .expect("mock lock")
                .push(request.to_vec());
            (self.handler)(host, port, request)
        }
    }

    /// A canned HTTP/1.1 200 response carrying `body`.
    fn http_200(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn one_endpoint() -> OllamaConfig {
        OllamaConfig::new(
            vec![OllamaEndpoint::new("127.0.0.1", 11434)],
            "gemma4:latest",
        )
        .expect("valid config")
    }

    // ---- config -----------------------------------------------------------

    #[test]
    fn config_rejects_empty_endpoints_and_model() {
        assert!(OllamaConfig::new(vec![], "m").is_err());
        assert!(OllamaConfig::new(vec![OllamaEndpoint::new("h", 1)], "  ").is_err());
    }

    #[test]
    fn dev_default_has_primary_then_fallback() {
        let cfg = OllamaConfig::dev_default();
        assert_eq!(cfg.endpoints()[0], OllamaEndpoint::new("127.0.0.1", 11434));
        assert_eq!(cfg.endpoints()[1], OllamaEndpoint::new("192.0.2.11", 11434));
        assert_eq!(cfg.model(), "gemma4:latest");
    }

    // ---- request shaping --------------------------------------------------

    #[tokio::test]
    async fn generate_shapes_post_to_api_generate() {
        let transport =
            MockTransport::new(|_, _, _| Ok(http_200(r#"{"response":"hello","eval_count":3}"#)));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let resp = provider
            .generate(&GenerateRequest {
                model: "ignored-router-sets-cfg-model".to_owned(),
                prompt: "hi there".to_owned(),
                max_tokens: 16,
            })
            .await
            .expect("ok");
        assert_eq!(resp.text, "hello");
        assert_eq!(resp.tokens, 3);

        let raw = String::from_utf8(provider.transport.last_request()).unwrap();
        assert!(raw.starts_with("POST /api/generate HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains("Host: 127.0.0.1:11434\r\n"), "{raw}");
        assert!(raw.contains("Content-Type: application/json\r\n"), "{raw}");
        // Body uses the CONFIG model, not the request's model field, and
        // requests a non-streaming response.
        assert!(raw.contains(r#""model":"gemma4:latest""#), "{raw}");
        assert!(raw.contains(r#""prompt":"hi there""#), "{raw}");
        assert!(raw.contains(r#""stream":false"#), "{raw}");
        assert!(raw.contains(r#""num_predict":16"#), "{raw}");
    }

    #[tokio::test]
    async fn generate_omits_num_predict_when_max_tokens_zero() {
        let transport = MockTransport::new(|_, _, _| Ok(http_200(r#"{"response":"x"}"#)));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect("ok");
        let raw = String::from_utf8(provider.transport.last_request()).unwrap();
        assert!(
            !raw.contains("num_predict"),
            "no options when max_tokens=0: {raw}"
        );
    }

    #[tokio::test]
    async fn chat_shapes_post_and_parses_message() {
        let transport = MockTransport::new(|_, _, _| {
            Ok(http_200(
                r#"{"message":{"role":"assistant","content":"4"},"eval_count":2}"#,
            ))
        });
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let resp = provider
            .chat(&ChatRequest {
                model: "m".to_owned(),
                messages: vec![super::super::ChatMessage {
                    role: "user".to_owned(),
                    content: "what is 2+2?".to_owned(),
                }],
            })
            .await
            .expect("ok");
        assert_eq!(resp.message.role, "assistant");
        assert_eq!(resp.message.content, "4");
        assert_eq!(resp.tokens, 2);

        let raw = String::from_utf8(provider.transport.last_request()).unwrap();
        assert!(raw.starts_with("POST /api/chat HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains(r#""role":"user""#), "{raw}");
        assert!(raw.contains(r#""content":"what is 2+2?""#), "{raw}");
    }

    #[tokio::test]
    async fn embeddings_shapes_post_and_parses_vector() {
        let transport =
            MockTransport::new(|_, _, _| Ok(http_200(r#"{"embedding":[0.1,0.2,0.3]}"#)));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let resp = provider
            .embeddings(&EmbeddingsRequest {
                model: "m".to_owned(),
                input: "embed me".to_owned(),
            })
            .await
            .expect("ok");
        assert_eq!(resp.embedding, vec![0.1, 0.2, 0.3]);
        let raw = String::from_utf8(provider.transport.last_request()).unwrap();
        assert!(
            raw.starts_with("POST /api/embeddings HTTP/1.1\r\n"),
            "{raw}"
        );
        assert!(raw.contains(r#""prompt":"embed me""#), "{raw}");
    }

    #[tokio::test]
    async fn health_uses_get_api_tags() {
        let transport =
            MockTransport::new(|_, _, _| Ok(http_200(r#"{"models":[{"name":"gemma4:latest"}]}"#)));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let health = provider.health().await;
        assert!(health.healthy, "{health:?}");
        let raw = String::from_utf8(provider.transport.last_request()).unwrap();
        assert!(raw.starts_with("GET /api/tags HTTP/1.1\r\n"), "{raw}");

        let models = provider.list_models().await.expect("ok");
        assert_eq!(models, vec!["gemma4:latest".to_owned()]);
    }

    // ---- streaming (NDJSON) -----------------------------------------------

    #[tokio::test]
    async fn generate_parses_ndjson_multi_chunk() {
        // Ollama streamed three line-delimited objects; the provider must
        // concatenate `response` and take the final `eval_count`.
        let body = "{\"response\":\"hel\"}\n{\"response\":\"lo\"}\n{\"response\":\"!\",\"eval_count\":7}\n";
        let transport = MockTransport::new(move |_, _, _| Ok(http_200(body)));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let resp = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect("ok");
        assert_eq!(resp.text, "hello!");
        assert_eq!(resp.tokens, 7);
    }

    // ---- model-not-ready (ADR-0050) ---------------------------------------

    #[tokio::test]
    async fn generate_empty_load_response_is_retriable_not_ready() {
        // A non-resident model answers 200 with an empty response and
        // done_reason "load": it must be a RETRIABLE error, never a
        // "successful empty answer" (the M1 empty-output bug).
        let transport = MockTransport::new(|_, _, _| {
            Ok(http_200(
                r#"{"response":"","done":true,"done_reason":"load"}"#,
            ))
        });
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let err = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "what is 2+2?".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect_err("not-ready must be an error, not empty success");
        assert!(matches!(err, ProviderError::Unavailable(_)), "{err:?}");
        assert!(
            err.is_retriable(),
            "model-not-ready should be retriable: {err:?}"
        );
    }

    #[tokio::test]
    async fn generate_empty_stop_response_is_passed_through() {
        // A resident model that genuinely produced no tokens reports
        // done_reason "stop": that is a valid (if empty) answer, NOT a
        // not-ready error.
        let transport = MockTransport::new(|_, _, _| {
            Ok(http_200(
                r#"{"response":"","done":true,"done_reason":"stop"}"#,
            ))
        });
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let resp = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect("empty+stop is a valid answer, not an error");
        assert_eq!(resp.text, "");
    }

    // ---- error handling ---------------------------------------------------

    #[tokio::test]
    async fn http_500_is_terminal_backend_error() {
        let transport = MockTransport::new(|_, _, _| {
            Ok(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec())
        });
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let err = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect_err("5xx");
        assert!(matches!(err, ProviderError::Backend(_)), "{err:?}");
        assert!(!err.is_retriable());
    }

    #[tokio::test]
    async fn malformed_json_is_clean_backend_error_no_panic() {
        let transport =
            MockTransport::new(|_, _, _| Ok(http_200("this is { not ] valid json at all")));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let err = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect_err("malformed");
        assert!(matches!(err, ProviderError::Backend(_)), "{err:?}");
    }

    #[tokio::test]
    async fn malformed_http_response_is_backend_error() {
        let transport = MockTransport::new(|_, _, _| Ok(b"not even an http response".to_vec()));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let err = provider
            .embeddings(&EmbeddingsRequest {
                model: "m".to_owned(),
                input: "x".to_owned(),
            })
            .await
            .expect_err("bad http");
        assert!(matches!(err, ProviderError::Backend(_)), "{err:?}");
    }

    #[tokio::test]
    async fn transport_unavailable_propagates_when_single_endpoint() {
        let transport =
            MockTransport::new(|_, _, _| Err(ProviderError::Unavailable("refused".to_owned())));
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let err = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect_err("down");
        assert!(err.is_retriable(), "{err:?}");
    }

    // ---- endpoint failover ------------------------------------------------

    #[tokio::test]
    async fn endpoint_failover_primary_to_secondary() {
        // First endpoint refuses; the provider must try the second.
        let cfg = OllamaConfig::new(
            vec![
                OllamaEndpoint::new("127.0.0.1", 11434),
                OllamaEndpoint::new("192.0.2.11", 11434),
            ],
            "gemma4:latest",
        )
        .unwrap();
        let transport = MockTransport::new(|host, _, _| {
            if host == "127.0.0.1" {
                Err(ProviderError::Unavailable("primary down".to_owned()))
            } else {
                Ok(http_200(r#"{"response":"via fallback"}"#))
            }
        });
        let provider = OllamaProvider::new(cfg, transport);
        let resp = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect("failover");
        assert_eq!(resp.text, "via fallback");
        assert_eq!(provider.transport.call_count(), 2, "tried both endpoints");
    }

    #[tokio::test]
    async fn oversize_response_is_bounded_error() {
        // The mock reports the transport-level oversize error the real
        // TokioTcpTransport would produce; the provider surfaces it
        // cleanly (terminal), never OOMing.
        let transport = MockTransport::new(|_, _, _| {
            Err(ProviderError::Backend(
                "response exceeds 1024-byte cap".to_owned(),
            ))
        });
        let provider = OllamaProvider::new(one_endpoint(), transport);
        let err = provider
            .generate(&GenerateRequest {
                model: "m".to_owned(),
                prompt: "p".to_owned(),
                max_tokens: 0,
            })
            .await
            .expect_err("oversize");
        assert!(matches!(err, ProviderError::Backend(_)), "{err:?}");
        assert!(!err.is_retriable());
    }
}

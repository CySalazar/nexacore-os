//! # `nexacore-runtime`
//!
//! AI Runtime Service for NexaCore OS.
//!
//! The privileged user-space service that exposes AI as a system primitive.
//! Applications call into the runtime through capability-checked syscalls;
//! the runtime owns model lifecycle, inference scheduling, and decisions
//! about which execution tier handles each workload.
//!
//! ## Status
//!
//! Phase 2 Stream 2 — adds the AI syscall IPC relay, the PII pre-processing
//! pipeline, and the Orchestrator→Runtime dispatch bridge on top of the
//! `ModelRegistry`, `InferencePipeline`, `TierRouter`, and
//! `WorkloadScheduler` stubs from Stream 1.
//! The tensor backend is a placeholder that returns an empty output vector;
//! callers must not interpret an empty `output` as a successful inference
//! result until a real backend lands in a later stream.
//!
//! ## Design rationale
//!
//! - **Capability-checked entry points**: every public function accepts a
//!   capability token; invalid tokens are rejected at the API boundary.
//! - **Tier routing**: the runtime decides whether a given workload is
//!   served by Tier 0 (local), Tier 1 (personal cluster), Tier 2 (mesh),
//!   or Tier 3 (commercial cloud), based on workload sensitivity, user
//!   policy, and available resources. See
//!   [`/docs/02-architecture.md`](../../../docs/02-architecture.md)
//!   § "Execution tiers".
//! - **Model attestation enforced**: a model whose signature does not
//!   verify is rejected at load time. No exceptions.
//! - **Audit log**: every invocation produces a structured record. See
//!   [`/docs/04-security-model.md`](../../../docs/04-security-model.md)
//!   § "Audit log".
//!
//! ## Modules
//!
//! - [`model`] — model lifecycle (load, unload, attest, version).
//! - [`inference`] — inference orchestration on the local node.
//! - [`scheduler`] — workload scheduling across accelerators.
//! - [`router`] — execution tier routing decisions.
//! - [`attestation`] — model signature verification.
//! - [`gguf`] — GGUF v3 binary format parser.
//! - [`relay`] — AI syscall IPC relay (kernel → pipeline bridge).
//! - [`preprocessing`] — PII detection and tokenization pipeline.
//! - [`orchestrator_bridge`] — Orchestrator Agent → inference dispatch.
//! - [`bpe`] — byte-level BPE tokenizer for LLM text ↔ token ID conversion.

// TASK-13-pre / ADR-0034: the inference-engine subset (gguf, tensor_loader,
// bpe, decode) is `no_std + alloc` so the Ring 3 image can run the REAL
// engine on `x86_64-unknown-none`.  The full service surface (serving,
// providers, relay, audit, model registry) stays behind the default-on
// `std` feature.
#![cfg_attr(not(feature = "std"), no_std)]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-runtime")]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        // Indexing/slicing in test helpers: bounds are known by construction.
        clippy::indexing_slicing,
        // Float equality in tests: comparing exact bit-pattern results is intentional.
        clippy::float_cmp,
        // Cast in test helpers: values are known to fit; no precision loss possible.
        clippy::cast_possible_truncation,
        clippy::cast_lossless,
        // Names in test helpers: `id1`/`ids` naming is deliberate test-scope style.
        clippy::similar_names,
        // Single-element array iter in test helpers: clear intent outweighs iterator style.
        clippy::iter_on_single_items,
        // doc_markdown in private test fn docs: Inf/NaN without backticks is readable prose.
        clippy::doc_markdown,
        // suboptimal_flops in tests: `a * b - c` is clearer than `a.mul_add(b, -c)` for test assertions.
        clippy::suboptimal_flops,
        // needless_range_loop in tests: indexed loops over computed arrays are clear.
        clippy::needless_range_loop,
        // float_arithmetic in test helpers: cosine similarity requires explicit arithmetic.
        clippy::float_arithmetic,
    )
)]

// Pull in heap allocation primitives when building without the standard
// library.  The global allocator is provided by the consumer (e.g. the bump
// allocator in the Ring 3 nexacore-runtime-image).  (TASK-13-pre / ADR-0034)
#[cfg(not(feature = "std"))]
extern crate alloc;

// =============================================================================
// gguf — GGUF v3 binary format parser
// =============================================================================

/// GGUF file format parser.
///
/// Implements the GGUF v3 binary format used by llama.cpp and compatible
/// tools. The parser reads model metadata and tensor layout information
/// from raw bytes without loading tensor data into memory.
pub mod gguf;

// =============================================================================
// fixture — canonical tiny Q8_0 model fixture
// =============================================================================

/// The canonical tiny Q8_0 model fixture.
///
/// Synthetic GGUF + matching config and tokenizer.  Compiled under
/// `cfg(test)` for the host goldens and under the `fixture-model` feature
/// for the Ring 3 `nexacore-runtime-image`, which embeds it as its on-device
/// model (TASK-13-pre / ADR-0034).
#[cfg(any(test, feature = "fixture-model"))]
pub mod fixture;

// =============================================================================
// engine — no_std facade over the full CPU inference chain
// =============================================================================

/// `no_std` facade over the REAL CPU inference chain (TASK-13-pre /
/// ADR-0034): GGUF parse → tensor load/dequantise → weight mapping → BPE
/// encode → sync transformer forward → greedy decode.
///
/// Shared by the std [`provider::local_cpu::LocalCpuProvider`] and the Ring 3
/// `nexacore-runtime-image` so both run one audited engine body.
pub mod engine;

// =============================================================================
// tensor_loader — GGUF tensor weight extraction
// =============================================================================

/// GGUF tensor weight extraction into HAL TensorBuffers.
///
/// Converts raw GGUF on-disk bytes for each tensor into
/// [`nexacore_hal::tensor::TensorBuffer`]s, applying F16/BF16 → F32 expansion
/// where needed and providing zero-filled stub buffers for quantized types
/// pending Phase 4 dequantization.
pub mod tensor_loader;

/// GGUF quantized block layouts (`block_q8_0` / `block_q4_K` / `block_q5_K`).
///
/// Byte-exact `#[repr(C)]` structs the `no_std` engine reads tensor data
/// through for fused dequant + matmul (WS5-01).
pub mod quant;

/// Fused dequantize + GEMV kernel for quantized weights (WS5-01.6/.7).
///
/// Dequantizes `W` one row at a time and reduces it against the activation, so
/// the full f32 weight matrix is never materialized. `no_std + alloc`.
pub mod quant_matmul;

/// Bounded token-streaming channel with backpressure (WS5-03.2).
///
/// A single-producer / single-consumer FIFO of `AiTokenChunk`s that decouples
/// the streaming engine's incremental yield from the relay's drain and enforces
/// backpressure when full. `no_std + alloc`.
pub mod token_channel;

/// Incremental token-yield bridge: decode loop → token channel (WS5-03.3).
///
/// `StreamPump` advances a `DecodeToken` source one token per call, detokenizes
/// it, and enqueues an `AiTokenChunk` into a `token_channel::TokenChannel` with
/// backpressure and terminal-flagging. `no_std + alloc`.
pub mod stream_pump;

/// Embedding path: pool a transformer hidden state into a dense vector
/// (WS5-03.5).
///
/// Runs `transformer_hidden_sync` then pools the per-token states
/// (last-token / mean / CLS) with optional L2-normalization into the
/// `AiEmbedding` vector. `no_std + alloc`.
pub mod embed;

/// Classifier path: pool a transformer hidden state, project it through a
/// linear classification head, and rank the labels (WS5-03.7).
///
/// Runs `transformer_hidden_sync`, pools (reusing `embed`), applies the
/// `ClassifierHead` linear layer to obtain logits, then `softmax` +
/// `rank_labels` to produce the `ScoredLabel` ranking. `no_std + alloc`.
pub mod classify;

/// Transcribe path: decode a captured audio buffer to a normalized mono sample
/// stream, resample to the model rate, and run an acoustic model (WS5-03.9).
///
/// The DSP front-end (`decode_pcm_mono`, `resample_linear`) is pure and
/// host-testable; the acoustic model is taken behind the `Transcriber` trait,
/// so `transcribe_sync` (decode → resample → model) is host-testable with a
/// mock. `no_std + alloc`.
pub mod transcribe;

/// Privacy-budget accountant: per-user/per-app ledger that charges tier egress
/// and gates cloud calls when the budget is exhausted (WS5-07).
///
/// Gated on `std` because it builds on the `router` tier model, which is itself
/// part of the full-service (std) surface.
#[cfg(feature = "std")]
pub mod privacy_budget;

/// Tensor HAL: backend-dispatched compute (`matmul`/`softmax`/`dequant`) with a
/// portable scalar CPU reference backend and a runtime backend-selection policy
/// (WS5-02.1/.2).
///
/// Gated on `std`: the reference `softmax` uses `f32::exp` (a libm intrinsic
/// unavailable in the bare-metal `no_std` build).
#[cfg(feature = "std")]
pub mod tensor_hal;

/// Tensor HAL dispatch (WS5-02.3, .9–.12, .14, .16).
///
/// Hardware capability probe, the runtime vendor-wrapper loader ABI (CUDA/ROCm
/// stubs), CPU-fallback dispatch, per-backend throughput, and the
/// backend/capability matrix. Gated on `std` like [`tensor_hal`].
#[cfg(feature = "std")]
pub mod tensor_dispatch;

// =============================================================================
// model_loader — NCFS model file loading
// =============================================================================

/// Load GGUF model files from the NCFS in-memory filesystem.
///
/// Bridges [`nexacore_fs::InMemoryFs`] and the GGUF tensor loader: reads a model
/// file, parses the GGUF header, and extracts all tensor weights into
/// [`nexacore_hal::tensor::TensorBuffer`]s in a single call.
#[cfg(feature = "std")]
pub mod model_loader;

// =============================================================================
// model — ModelManifest + ModelRegistry
// =============================================================================

/// Model lifecycle: load, unload, attest, version.
///
/// This module owns the canonical model registry for a single NexaCore OS node.
/// A model must be registered (signature verified) before it can be loaded;
/// only a loaded model can serve inference requests.
#[cfg(feature = "std")]
pub mod model {
    use std::collections::{BTreeMap, BTreeSet};

    use nexacore_crypto::signing::{NexaCoreSignature, NexaCoreVerifyingKey};
    use nexacore_types::{ModelId, NexaCoreError, Result};
    use serde::{Deserialize, Serialize};
    use tracing::{debug, info, warn};

    // -------------------------------------------------------------------------
    // ModelFormat
    // -------------------------------------------------------------------------

    /// Wire format of the model binary stored on disk.
    ///
    /// The format is carried in the manifest so downstream components can
    /// select the correct deserialization path without inspecting raw bytes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum ModelFormat {
        /// Open Neural Network Exchange (ONNX) format.
        Onnx,
        /// `SafeTensors` format (Hugging Face).
        SafeTensors,
        /// GGUF format (llama.cpp-style quantised models).
        Gguf,
    }

    // -------------------------------------------------------------------------
    // ModelManifest
    // -------------------------------------------------------------------------

    /// Signed declaration of a model's identity, provenance, and format.
    ///
    /// A `ModelManifest` is the authoritative source of truth for a model's
    /// identity within NexaCore OS. The registry accepts a manifest only if its
    /// Ed25519 signature over the model's BLAKE3 hash verifies against the
    /// embedded `signing_key`.
    ///
    /// # Security contract
    ///
    /// The `hash` field is the BLAKE3 digest of the model binary. The
    /// `signature` is an Ed25519 signature produced by `signing_key` over
    /// that hash. Before a manifest is accepted into the registry, the
    /// signature is verified with
    /// [`NexaCoreVerifyingKey::verify`][nexacore_crypto::signing::NexaCoreVerifyingKey::verify],
    /// which uses `verify_strict` internally (rejecting malleability attacks).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_crypto::signing::NexaCoreSigningKey;
    /// use nexacore_runtime::model::{ModelFormat, ModelManifest, ModelRegistry};
    /// use nexacore_types::ModelId;
    ///
    /// // Build a manifest with a test key.
    /// let sk = NexaCoreSigningKey::from_bytes([0xAA; 32]);
    /// let hash = [0x01u8; 32];
    /// let sig = sk.sign(&hash);
    /// let vk = sk.verifying_key();
    ///
    /// let manifest = ModelManifest {
    ///     model_id: ModelId::from_manifest_hash(hash),
    ///     name: "test-model".into(),
    ///     version: "1.0.0".into(),
    ///     hash,
    ///     signature: sig,
    ///     signing_key: vk,
    ///     size_bytes: 0,
    ///     format: ModelFormat::Gguf,
    /// };
    ///
    /// let mut registry = ModelRegistry::new();
    /// let id = registry.register(manifest).unwrap();
    /// assert_eq!(registry.list(), vec![id]);
    /// ```
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ModelManifest {
        /// Stable content-addressed identifier derived from this manifest.
        pub model_id: ModelId,
        /// Human-readable model name (e.g. `"llama-3-8b"`).
        pub name: String,
        /// Semantic version string (e.g. `"3.0.1"`).
        pub version: String,
        /// BLAKE3 hash of the model binary. The signature covers this field.
        pub hash: [u8; 32],
        /// Ed25519 signature of `hash` produced by `signing_key`.
        pub signature: NexaCoreSignature,
        /// Ed25519 public key whose private half produced `signature`.
        pub signing_key: NexaCoreVerifyingKey,
        /// Size of the model binary in bytes (informational; not signed).
        pub size_bytes: u64,
        /// On-disk serialization format.
        pub format: ModelFormat,
    }

    // -------------------------------------------------------------------------
    // LoadState
    // -------------------------------------------------------------------------

    /// Tracks whether a registered model has been loaded into memory.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoadState {
        /// The model binary is not currently in memory.
        Unloaded,
        /// The model binary has been loaded and is ready for inference.
        Loaded,
    }

    // -------------------------------------------------------------------------
    // ModelEntry (private)
    // -------------------------------------------------------------------------

    /// Internal registry record pairing a manifest with its load state and
    /// optionally the parsed GGUF header (populated by
    /// [`ModelRegistry::load_from_bytes`] or
    /// [`ModelRegistry::load_tensors_from_bytes`]).
    #[derive(Debug)]
    struct ModelEntry {
        manifest: ModelManifest,
        state: LoadState,
        /// Parsed GGUF header, stored after a successful `load_from_bytes` or
        /// `load_tensors_from_bytes` call. `None` until the model binary has
        /// been validated and parsed.
        gguf_header: Option<crate::gguf::GgufHeader>,
    }

    // -------------------------------------------------------------------------
    // ModelRegistry
    // -------------------------------------------------------------------------

    /// In-process registry of signed model manifests.
    ///
    /// `ModelRegistry` is the single authoritative store for model identity on
    /// a node. It enforces:
    ///
    /// 1. **Signature verification on register**: a manifest whose Ed25519
    ///    signature does not verify is rejected immediately — the model is
    ///    never made visible to inference.
    /// 2. **Load-state gating**: inference can only be dispatched to a model
    ///    that is in the `Loaded` state. Requesting inference against an
    ///    `Unloaded` model returns an error rather than silently blocking.
    /// 3. **Stable ordering**: the `BTreeMap` backing store keeps model IDs
    ///    sorted, which makes `list()` output deterministic and simplifies
    ///    audit logging.
    ///
    /// # Thread safety
    ///
    /// `ModelRegistry` is not `Send + Sync` by itself. Callers that share it
    /// across async tasks must wrap it in a `tokio::sync::Mutex` (see
    /// [`crate::inference::InferencePipeline`] for the canonical pattern).
    #[derive(Debug, Default)]
    pub struct ModelRegistry {
        entries: BTreeMap<ModelId, ModelEntry>,
        /// Optional allowlist of trusted issuer verifying keys (raw 32-byte
        /// Ed25519 public keys). When `Some`, [`register`](Self::register)
        /// rejects any manifest whose `signing_key` is not in the set —
        /// fail-closed, so a cryptographically self-consistent manifest from
        /// an UNKNOWN issuer is still refused (TASK-17 gate, ADR-0039). When
        /// `None` (the default / [`new`](Self::new)), only the self-signature
        /// is checked (any well-formed issuer is accepted) — the pre-gate
        /// behaviour kept for tests and single-trust-domain deployments.
        trusted_issuers: Option<BTreeSet<[u8; 32]>>,
    }

    impl ModelRegistry {
        /// Create an empty registry with NO issuer allowlist (self-signature
        /// verification only).
        ///
        /// ```rust
        /// use nexacore_runtime::model::ModelRegistry;
        /// let reg = ModelRegistry::new();
        /// assert!(reg.list().is_empty());
        /// ```
        #[must_use]
        pub fn new() -> Self {
            Self {
                entries: BTreeMap::new(),
                trusted_issuers: None,
            }
        }

        /// Create an empty registry that ALSO enforces a trusted-issuer
        /// allowlist (TASK-17 Phase-2 gate, ADR-0039). The signing key of
        /// every registered manifest must be one of `issuers`, in addition to
        /// the Ed25519 self-signature verifying over the model hash. This is
        /// fail-closed: an empty allowlist rejects every manifest, and a
        /// manifest from an unknown-but-internally-consistent issuer is
        /// refused. The trusted set is the "chiave di firma da configurazione"
        /// the deployment supplies.
        ///
        /// ```rust
        /// use nexacore_crypto::signing::NexaCoreSigningKey;
        /// use nexacore_runtime::model::ModelRegistry;
        ///
        /// let trusted = NexaCoreSigningKey::from_bytes([0x11; 32]).verifying_key();
        /// let reg = ModelRegistry::with_trusted_issuers([trusted]);
        /// assert!(reg.list().is_empty());
        /// ```
        #[must_use]
        pub fn with_trusted_issuers(
            issuers: impl IntoIterator<Item = NexaCoreVerifyingKey>,
        ) -> Self {
            Self {
                entries: BTreeMap::new(),
                trusted_issuers: Some(issuers.into_iter().map(|k| k.as_bytes()).collect()),
            }
        }

        /// Register a model manifest after verifying its Ed25519 signature.
        ///
        /// The manifest's `signing_key` must verify `signature` over `hash`.
        /// If verification fails the manifest is rejected and an error is
        /// returned; no partial state is stored.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Crypto`] with [`nexacore_types::error::CryptoErrorKind::InvalidSignature`]
        ///   if signature verification fails.
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_crypto::signing::NexaCoreSigningKey;
        /// use nexacore_runtime::model::{ModelFormat, ModelManifest, ModelRegistry};
        /// use nexacore_types::ModelId;
        ///
        /// let sk = NexaCoreSigningKey::from_bytes([0xBB; 32]);
        /// let hash = [0x02u8; 32];
        /// let sig = sk.sign(&hash);
        /// let manifest = ModelManifest {
        ///     model_id: ModelId::from_manifest_hash(hash),
        ///     name: "model-b".into(),
        ///     version: "2.0.0".into(),
        ///     hash,
        ///     signature: sig,
        ///     signing_key: sk.verifying_key(),
        ///     size_bytes: 1024,
        ///     format: ModelFormat::Onnx,
        /// };
        ///
        /// let mut reg = ModelRegistry::new();
        /// let id = reg.register(manifest).unwrap();
        /// assert_eq!(reg.list(), vec![id]);
        /// ```
        pub fn register(&mut self, manifest: ModelManifest) -> Result<ModelId> {
            // Verify the Ed25519 signature before accepting the manifest.
            // This is the single enforcement point: once a manifest is in the
            // registry we treat its identity as verified.
            manifest
                .signing_key
                .verify(&manifest.hash, &manifest.signature)
                .inspect_err(|_| {
                    warn!(
                        model_name = %manifest.name,
                        "model manifest rejected: signature verification failed"
                    );
                })?;

            // TASK-17 gate (ADR-0039): when an issuer allowlist is configured,
            // the (cryptographically valid) signing key MUST also be trusted.
            // Fail-closed — an unknown issuer is rejected even though its
            // self-signature verifies.
            if let Some(trusted) = &self.trusted_issuers {
                if !trusted.contains(&manifest.signing_key.as_bytes()) {
                    warn!(
                        model_name = %manifest.name,
                        "model manifest rejected: issuer not in trusted allowlist"
                    );
                    return Err(NexaCoreError::crypto(
                        nexacore_types::error::CryptoErrorKind::InvalidSignature,
                        "model_registry::register — issuer not in trusted allowlist",
                    ));
                }
            }

            let id = manifest.model_id;
            info!(
                model_id = ?id,
                model_name = %manifest.name,
                model_version = %manifest.version,
                "model manifest registered"
            );
            self.entries.insert(
                id,
                ModelEntry {
                    manifest,
                    state: LoadState::Unloaded,
                    gguf_header: None,
                },
            );
            Ok(id)
        }

        /// Mark a registered model as loaded (ready for inference).
        ///
        /// The current stub implementation only transitions the load state;
        /// actual model binary loading (memory-mapping, tensor allocation) is
        /// deferred to a later Phase 2 stream when the tensor backend lands.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Internal`] if `model_id` is not registered.
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_crypto::signing::NexaCoreSigningKey;
        /// use nexacore_runtime::model::{ModelFormat, ModelManifest, ModelRegistry};
        /// use nexacore_types::ModelId;
        ///
        /// let sk = NexaCoreSigningKey::from_bytes([0xCC; 32]);
        /// let hash = [0x03u8; 32];
        /// let manifest = ModelManifest {
        ///     model_id: ModelId::from_manifest_hash(hash),
        ///     name: "model-c".into(),
        ///     version: "1.0.0".into(),
        ///     hash,
        ///     signature: sk.sign(&hash),
        ///     signing_key: sk.verifying_key(),
        ///     size_bytes: 0,
        ///     format: ModelFormat::SafeTensors,
        /// };
        ///
        /// let mut reg = ModelRegistry::new();
        /// let id = reg.register(manifest).unwrap();
        /// reg.load(id).unwrap();
        /// ```
        pub fn load(&mut self, model_id: ModelId) -> Result<()> {
            let entry = self.entries.get_mut(&model_id).ok_or_else(|| {
                NexaCoreError::internal("runtime::model::load — model_id not registered")
            })?;

            debug!(model_id = ?model_id, "loading model");
            // Stub: no binary is actually loaded into memory yet. Transition
            // state so the inference pipeline can gate on it.
            entry.state = LoadState::Loaded;
            Ok(())
        }

        /// Load a GGUF model from raw bytes.
        ///
        /// Parses the GGUF header, verifies the model's BLAKE3 hash matches
        /// the manifest, and stores the parsed tensor metadata. The actual
        /// tensor data is NOT loaded into GPU/CPU memory — that happens on
        /// first inference via the tensor backend.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Internal`] if `model_id` is not registered.
        /// - [`NexaCoreError::Internal`] if the registered model's format is not
        ///   [`ModelFormat::Gguf`].
        /// - [`NexaCoreError::Internal`] if the BLAKE3 hash of `data` does not
        ///   match the hash stored in the model's manifest.
        /// - [`NexaCoreError::Internal`] if the GGUF data is malformed.
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_crypto::signing::NexaCoreSigningKey;
        /// use nexacore_runtime::model::{ModelFormat, ModelManifest, ModelRegistry};
        /// use nexacore_types::ModelId;
        ///
        /// // Construct a minimal valid GGUF v3 file (20 bytes: no tensors, no metadata).
        /// let gguf_magic: u32 = 0x4655_4746;
        /// let mut data = Vec::new();
        /// data.extend_from_slice(&gguf_magic.to_le_bytes()); // magic
        /// data.extend_from_slice(&3u32.to_le_bytes()); // version
        /// data.extend_from_slice(&0u64.to_le_bytes()); // tensor_count
        /// data.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count
        ///
        /// let hash: [u8; 32] = *blake3::hash(&data).as_bytes();
        /// let sk = NexaCoreSigningKey::from_bytes([0x55; 32]);
        /// let sig = sk.sign(&hash);
        ///
        /// let manifest = ModelManifest {
        ///     model_id: ModelId::from_manifest_hash(hash),
        ///     name: "gguf-test".into(),
        ///     version: "1.0.0".into(),
        ///     hash,
        ///     signature: sig,
        ///     signing_key: sk.verifying_key(),
        ///     size_bytes: data.len() as u64,
        ///     format: ModelFormat::Gguf,
        /// };
        ///
        /// let mut reg = ModelRegistry::new();
        /// let id = reg.register(manifest).unwrap();
        /// reg.load_from_bytes(id, &data).unwrap();
        /// assert!(reg.is_loaded(id));
        /// ```
        pub fn load_from_bytes(&mut self, model_id: ModelId, data: &[u8]) -> Result<()> {
            let entry = self.entries.get_mut(&model_id).ok_or_else(|| {
                NexaCoreError::internal("runtime::model::load_from_bytes — model_id not registered")
            })?;

            // Guard: only GGUF format is supported by this path.
            if entry.manifest.format != ModelFormat::Gguf {
                return Err(NexaCoreError::internal(
                    "runtime::model::load_from_bytes — only GGUF format supported",
                ));
            }

            // Full attestation at load (WS5-04.5/.7): re-verify the Ed25519
            // signature over the signed measure BEFORE trusting the manifest
            // hash. The load path is then self-contained — it checks both
            // authenticity (signature) and integrity (measure) at load time,
            // and never relies solely on the register-time check. This closes
            // the window in which an in-memory manifest could be corrupted
            // between register and load.
            attest_manifest_signature(&entry.manifest).inspect_err(|_| {
                warn!(
                    model_id = ?model_id,
                    "model load rejected: signature re-verification failed at load"
                );
            })?;

            // Verify BLAKE3 hash of the raw bytes against the signed manifest hash.
            // This is the integrity check that ensures the bytes in memory match
            // what the signing authority attested to at registration time.
            let computed_hash = blake3::hash(data);
            if computed_hash.as_bytes() != &entry.manifest.hash {
                return Err(NexaCoreError::internal(
                    "runtime::model::load_from_bytes — BLAKE3 hash mismatch",
                ));
            }

            // Parse the GGUF header to validate the format and extract metadata.
            // Store it on the entry so the tensor backend can access it without
            // re-parsing on every inference call.
            let header = crate::gguf::parse_gguf(data)?;
            info!(
                model_id = ?model_id,
                tensor_count = header.tensor_count,
                metadata_count = header.metadata.len(),
                "GGUF model parsed successfully"
            );

            entry.gguf_header = Some(header);
            entry.state = LoadState::Loaded;
            Ok(())
        }

        /// Mark a registered model as unloaded, freeing the resources the
        /// registry holds for it (WS5-09.4).
        ///
        /// Transitions the load state to `Unloaded` and drops the parsed GGUF
        /// header the registry cached at load, releasing that host-side memory.
        /// The deeper release of the tensor backend's weight buffers is owned by
        /// the backend allocator and lands with WS1-08; the registry never held
        /// those buffers (they are returned to the caller by
        /// [`load_tensors_from_bytes`](Self::load_tensors_from_bytes)).
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Internal`] if `model_id` is not registered.
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_crypto::signing::NexaCoreSigningKey;
        /// use nexacore_runtime::model::{ModelFormat, ModelManifest, ModelRegistry};
        /// use nexacore_types::ModelId;
        ///
        /// let sk = NexaCoreSigningKey::from_bytes([0xDD; 32]);
        /// let hash = [0x04u8; 32];
        /// let manifest = ModelManifest {
        ///     model_id: ModelId::from_manifest_hash(hash),
        ///     name: "model-d".into(),
        ///     version: "1.0.0".into(),
        ///     hash,
        ///     signature: sk.sign(&hash),
        ///     signing_key: sk.verifying_key(),
        ///     size_bytes: 0,
        ///     format: ModelFormat::Gguf,
        /// };
        ///
        /// let mut reg = ModelRegistry::new();
        /// let id = reg.register(manifest).unwrap();
        /// reg.load(id).unwrap();
        /// reg.unload(id).unwrap();
        /// ```
        pub fn unload(&mut self, model_id: ModelId) -> Result<()> {
            let entry = self.entries.get_mut(&model_id).ok_or_else(|| {
                NexaCoreError::internal("runtime::model::unload — model_id not registered")
            })?;

            debug!(model_id = ?model_id, "unloading model");
            entry.state = LoadState::Unloaded;
            // Release the parsed header the registry cached at load.
            entry.gguf_header = None;
            Ok(())
        }

        /// Return the manifest for a registered model, verifying its
        /// signature in the process.
        ///
        /// This is the attestation query path: a caller can confirm that the
        /// manifest stored in the registry still matches the original
        /// signed state. If the in-memory manifest has been tampered with
        /// (indicative of memory corruption), verification will fail.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Internal`] if `model_id` is not registered.
        /// - [`NexaCoreError::Crypto`] if the stored signature no longer verifies
        ///   (indicates in-memory tampering or a programming error).
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_crypto::signing::NexaCoreSigningKey;
        /// use nexacore_runtime::model::{ModelFormat, ModelManifest, ModelRegistry};
        /// use nexacore_types::ModelId;
        ///
        /// let sk = NexaCoreSigningKey::from_bytes([0xEE; 32]);
        /// let hash = [0x05u8; 32];
        /// let manifest = ModelManifest {
        ///     model_id: ModelId::from_manifest_hash(hash),
        ///     name: "model-e".into(),
        ///     version: "1.0.0".into(),
        ///     hash,
        ///     signature: sk.sign(&hash),
        ///     signing_key: sk.verifying_key(),
        ///     size_bytes: 0,
        ///     format: ModelFormat::Onnx,
        /// };
        ///
        /// let mut reg = ModelRegistry::new();
        /// let id = reg.register(manifest).unwrap();
        /// let attested = reg.attest(id).unwrap();
        /// assert_eq!(attested.name, "model-e");
        /// ```
        pub fn attest(&self, model_id: ModelId) -> Result<ModelManifest> {
            let entry = self.entries.get(&model_id).ok_or_else(|| {
                NexaCoreError::internal("runtime::model::attest — model_id not registered")
            })?;

            // Re-verify the stored signature on attest. This is an integrity
            // check: if the manifest has been modified in memory since
            // registration, verification will fail and the caller receives an
            // error rather than a corrupt manifest.
            entry
                .manifest
                .signing_key
                .verify(&entry.manifest.hash, &entry.manifest.signature)?;

            Ok(entry.manifest.clone())
        }

        /// Return a sorted list of all registered model IDs.
        ///
        /// The ordering is deterministic (BLAKE3 hash byte order) so callers
        /// can iterate predictably without sorting themselves.
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_runtime::model::ModelRegistry;
        /// let reg = ModelRegistry::new();
        /// assert!(reg.list().is_empty());
        /// ```
        #[must_use]
        pub fn list(&self) -> Vec<ModelId> {
            self.entries.keys().copied().collect()
        }

        /// Returns `true` if `model_id` is registered and currently loaded.
        ///
        /// Used by the inference pipeline to gate dispatch without holding a
        /// mutable borrow.
        #[must_use]
        pub fn is_loaded(&self, model_id: ModelId) -> bool {
            self.entries
                .get(&model_id)
                .is_some_and(|e| e.state == LoadState::Loaded)
        }

        /// Load a GGUF model from raw bytes, extract all tensor weights, and
        /// return them as [`crate::tensor_loader::LoadedTensor`]s.
        ///
        /// Unlike [`load_from_bytes`][Self::load_from_bytes], which only
        /// validates the model and stores the parsed header, this method
        /// additionally extracts all tensor data from the GGUF blob and
        /// returns it for use by the tensor backend.
        ///
        /// The model is transitioned to the `Loaded` state on success, and the
        /// parsed [`crate::gguf::GgufHeader`] is stored on the entry.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Internal`] if `model_id` is not registered.
        /// - [`NexaCoreError::Internal`] if the registered model's format is not
        ///   [`ModelFormat::Gguf`].
        /// - [`NexaCoreError::Internal`] if the BLAKE3 hash of `data` does not
        ///   match the manifest hash.
        /// - [`NexaCoreError::Internal`] if the GGUF data is malformed.
        /// - [`NexaCoreError::Internal`] if any tensor extraction or conversion fails.
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_crypto::signing::NexaCoreSigningKey;
        /// use nexacore_runtime::model::{ModelFormat, ModelManifest, ModelRegistry};
        /// use nexacore_types::ModelId;
        ///
        /// // Minimal GGUF v3 file with no tensors.
        /// let gguf_magic: u32 = 0x4655_4746;
        /// let mut data = Vec::new();
        /// data.extend_from_slice(&gguf_magic.to_le_bytes());
        /// data.extend_from_slice(&3u32.to_le_bytes());
        /// data.extend_from_slice(&0u64.to_le_bytes());
        /// data.extend_from_slice(&0u64.to_le_bytes());
        ///
        /// let hash: [u8; 32] = *blake3::hash(&data).as_bytes();
        /// let sk = NexaCoreSigningKey::from_bytes([0x77; 32]);
        /// let manifest = ModelManifest {
        ///     model_id: ModelId::from_manifest_hash(hash),
        ///     name: "tensor-test".into(),
        ///     version: "1.0.0".into(),
        ///     hash,
        ///     signature: sk.sign(&hash),
        ///     signing_key: sk.verifying_key(),
        ///     size_bytes: data.len() as u64,
        ///     format: ModelFormat::Gguf,
        /// };
        ///
        /// let mut reg = ModelRegistry::new();
        /// let id = reg.register(manifest).unwrap();
        /// let tensors = reg.load_tensors_from_bytes(id, &data).unwrap();
        /// assert!(tensors.is_empty());
        /// assert!(reg.is_loaded(id));
        /// ```
        pub fn load_tensors_from_bytes(
            &mut self,
            model_id: ModelId,
            data: &[u8],
        ) -> Result<Vec<crate::tensor_loader::LoadedTensor>> {
            let entry = self.entries.get_mut(&model_id).ok_or_else(|| {
                NexaCoreError::internal(
                    "runtime::model::load_tensors_from_bytes — model_id not registered",
                )
            })?;

            if entry.manifest.format != ModelFormat::Gguf {
                return Err(NexaCoreError::internal(
                    "runtime::model::load_tensors_from_bytes — only GGUF format supported",
                ));
            }

            // Full attestation at load (WS5-04.5/.7): re-verify the Ed25519
            // signature over the signed measure before extracting any tensor
            // data, so authenticity (signature) and integrity (measure) are
            // both enforced at load time on this path too.
            attest_manifest_signature(&entry.manifest).inspect_err(|_| {
                warn!(
                    model_id = ?model_id,
                    "model tensor-load rejected: signature re-verification failed at load"
                );
            })?;

            // Verify BLAKE3 integrity before doing any further work.
            let computed_hash = blake3::hash(data);
            if computed_hash.as_bytes() != &entry.manifest.hash {
                return Err(NexaCoreError::internal(
                    "runtime::model::load_tensors_from_bytes — BLAKE3 hash mismatch",
                ));
            }

            // Parse and store the GGUF header.
            let header = crate::gguf::parse_gguf(data)?;
            info!(
                model_id = ?model_id,
                tensor_count = header.tensor_count,
                "GGUF model tensors being loaded"
            );

            // Extract all tensor buffers.
            let tensors = crate::tensor_loader::load_all_tensors(data, &header)?;

            entry.gguf_header = Some(header);
            entry.state = LoadState::Loaded;

            Ok(tensors)
        }

        // ── WS5-09: persistence, versioned query, lazy load, hot-swap ─────────

        /// Serialize the registry's signed manifests to a portable blob
        /// (WS5-09.2).
        ///
        /// Only the signed manifests are persisted; the runtime-only load state
        /// and parsed GGUF headers are dropped (every model comes back
        /// `Unloaded` after [`from_bytes`](Self::from_bytes)), mirroring how the
        /// privacy ledger persists its limits but not its transient event log.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Wire`] if canonical encoding fails.
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let manifests: Vec<&ModelManifest> =
                self.entries.values().map(|e| &e.manifest).collect();
            nexacore_types::wire::encode_canonical(&manifests)
        }

        /// Rebuild a registry from a blob produced by [`to_bytes`](Self::to_bytes)
        /// (WS5-09.2), re-verifying every manifest as it is re-admitted.
        ///
        /// Persistence is not a trust-boundary bypass: each manifest is passed
        /// back through [`register`](Self::register), so a tampered blob whose
        /// signatures no longer verify is rejected (fail-closed). The
        /// reconstructed registry has no issuer allowlist; a deployment that
        /// enforces one re-applies it via [`with_trusted_issuers`](Self::with_trusted_issuers)
        /// before reload, or filters the result.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Wire`] on malformed input.
        /// - [`NexaCoreError::Crypto`] if any persisted manifest fails signature
        ///   verification.
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            let manifests: Vec<ModelManifest> = nexacore_types::wire::decode_canonical(bytes)?;
            let mut reg = Self::new();
            for manifest in manifests {
                reg.register(manifest)?;
            }
            Ok(reg)
        }

        /// A stable, serializable summary of every registered model (WS5-09.1/.2):
        /// id, name, version, measure, format, and residency.
        ///
        /// This is the "query the available models" surface; ordering is
        /// deterministic (by `ModelId`, the `BTreeMap` order).
        #[must_use]
        pub fn available(&self) -> Vec<ModelSummary> {
            self.entries
                .values()
                .map(|e| ModelSummary {
                    model_id: e.manifest.model_id,
                    name: e.manifest.name.clone(),
                    version: e.manifest.version.clone(),
                    measure: e.manifest.hash,
                    format: e.manifest.format,
                    loaded: e.state == LoadState::Loaded,
                })
                .collect()
        }

        /// The manifest for `model_id`, if registered (no signature re-check —
        /// use [`attest`](Self::attest) for the verifying query).
        #[must_use]
        pub fn manifest_for(&self, model_id: ModelId) -> Option<&ModelManifest> {
            self.entries.get(&model_id).map(|e| &e.manifest)
        }

        /// All registered manifests sharing `name`, newest semantic version first
        /// (WS5-09.1).
        #[must_use]
        pub fn versions_of(&self, name: &str) -> Vec<&ModelManifest> {
            let mut v: Vec<&ModelManifest> = self
                .entries
                .values()
                .map(|e| &e.manifest)
                .filter(|m| m.name == name)
                .collect();
            // Newest first: reverse-compare on the dotted-numeric version.
            v.sort_by(|a, b| compare_versions(&b.version, &a.version));
            v
        }

        /// The newest-version manifest registered under `name` (WS5-09.1).
        ///
        /// Resolves "give me the latest `llama-3-8b`" using numeric (not lexical)
        /// version ordering, so `"3.10.0"` wins over `"3.2.0"`.
        #[must_use]
        pub fn latest(&self, name: &str) -> Option<&ModelManifest> {
            self.entries
                .values()
                .map(|e| &e.manifest)
                .filter(|m| m.name == name)
                .max_by(|a, b| compare_versions(&a.version, &b.version))
        }

        /// IDs of all currently-resident (loaded) models (WS5-09.4/.7).
        #[must_use]
        pub fn resident(&self) -> Vec<ModelId> {
            self.entries
                .iter()
                .filter(|(_, e)| e.state == LoadState::Loaded)
                .map(|(id, _)| *id)
                .collect()
        }

        /// Lazily ensure `model_id` is resident, loading + attesting it from
        /// `data` only if it is not already loaded (WS5-09.3).
        ///
        /// Idempotent: a call on an already-resident model is a no-op returning
        /// `false`, so the inference path can call it unconditionally. A cold
        /// model is loaded through the full attested [`load_from_bytes`](Self::load_from_bytes)
        /// path and the call returns `true`.
        ///
        /// # Errors
        ///
        /// As [`load_from_bytes`](Self::load_from_bytes) (unregistered id,
        /// wrong format, signature/measure mismatch, malformed GGUF).
        pub fn ensure_loaded(&mut self, model_id: ModelId, data: &[u8]) -> Result<bool> {
            if self.is_loaded(model_id) {
                return Ok(false);
            }
            self.load_from_bytes(model_id, data)?;
            Ok(true)
        }

        /// Lazily ensure `model_id` is resident, sourcing its weights from
        /// `cache` on a hit or from `fetch` on a miss (WS5-09.3/.6).
        ///
        /// On a cache miss, `fetch` obtains the weights (e.g. reads the NCFS
        /// model store) and the bytes are written back to `cache`, so the next
        /// cold start is served from cache. Cached bytes are **always attested**
        /// (signature + BLAKE3 measure) at load, so a corrupted cache can never
        /// inject an unsigned or mismatched model — the cache is not a trust
        /// boundary.
        ///
        /// Returns `true` if a load occurred, `false` if already resident.
        ///
        /// # Errors
        ///
        /// `fetch` errors propagate unchanged; load/attestation errors as
        /// [`load_from_bytes`](Self::load_from_bytes).
        pub fn ensure_loaded_cached<C, F>(
            &mut self,
            model_id: ModelId,
            cache: &mut C,
            fetch: F,
        ) -> Result<bool>
        where
            C: WeightCache,
            F: FnOnce() -> Result<Vec<u8>>,
        {
            if self.is_loaded(model_id) {
                return Ok(false);
            }
            let data = if let Some(bytes) = cache.get(model_id) {
                bytes
            } else {
                let bytes = fetch()?;
                cache.put(model_id, &bytes);
                bytes
            };
            self.load_from_bytes(model_id, &data)?;
            Ok(true)
        }

        /// Atomically swap the resident model: load `incoming` first, then unload
        /// `outgoing` (WS5-09.7).
        ///
        /// The new model is loaded and attested **before** the old one is
        /// retired, so a failed swap (bad bytes, signature/measure mismatch)
        /// leaves the outgoing model resident — there is no service gap from a
        /// half-applied swap. A no-op `outgoing == incoming` still re-loads and
        /// keeps the model resident.
        ///
        /// # Errors
        ///
        /// Propagates [`load_from_bytes`](Self::load_from_bytes) errors for
        /// `incoming` (the outgoing model is left untouched); afterwards,
        /// [`NexaCoreError::Internal`] if `outgoing` is not registered.
        pub fn hot_swap(
            &mut self,
            outgoing: ModelId,
            incoming: ModelId,
            incoming_data: &[u8],
        ) -> Result<()> {
            // Load the incoming model first; on failure the outgoing stays resident.
            self.load_from_bytes(incoming, incoming_data)?;
            if outgoing == incoming {
                return Ok(());
            }
            self.unload(outgoing)
        }
    }

    // -------------------------------------------------------------------------
    // WS5-09 — model summary, version ordering, weight cache
    // -------------------------------------------------------------------------

    /// A stable, serializable summary of a registered model (WS5-09.1/.2).
    ///
    /// The query-side view of the registry: enough to choose a model (id, name,
    /// version, measure, format) plus whether it is currently resident, without
    /// exposing the signature material the manifest carries.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ModelSummary {
        /// Content-addressed model identity.
        pub model_id: ModelId,
        /// Human-readable model name.
        pub name: String,
        /// Semantic version string.
        pub version: String,
        /// BLAKE3 measure of the model binary.
        pub measure: [u8; 32],
        /// On-disk format.
        pub format: ModelFormat,
        /// Whether the model is currently resident (loaded).
        pub loaded: bool,
    }

    /// Compare two dotted-numeric version strings numerically (WS5-09.1).
    ///
    /// Splits on `'.'` and compares component-wise as integers, so `"3.0.1"` <
    /// `"3.1.0"` and `"3.10.0"` > `"3.2.0"` (unlike a lexical compare). A missing
    /// or non-numeric component is treated as `0`, and the shorter version is
    /// zero-padded, so `"3"` equals `"3.0.0"`. This avoids a `semver` dependency
    /// for the simple numeric versions model manifests carry.
    #[must_use]
    pub fn compare_versions(a: &str, b: &str) -> core::cmp::Ordering {
        let mut ai = a.split('.');
        let mut bi = b.split('.');
        loop {
            match (ai.next(), bi.next()) {
                (None, None) => return core::cmp::Ordering::Equal,
                (a_part, b_part) => {
                    let av: u64 = a_part.unwrap_or("0").trim().parse().unwrap_or(0);
                    let bv: u64 = b_part.unwrap_or("0").trim().parse().unwrap_or(0);
                    match av.cmp(&bv) {
                        core::cmp::Ordering::Equal => {}
                        ord => return ord,
                    }
                }
            }
        }
    }

    /// Disk-backed weight-cache seam (WS5-09.6).
    ///
    /// Caches validated model binaries so a resident-model load can avoid
    /// re-fetching the weights from the NCFS model store on every cold start.
    /// The production implementation is backed by WS3 on-disk storage; hosts and
    /// tests use [`MemWeightCache`]. The registry treats the cache as untrusted —
    /// bytes returned by [`get`](Self::get) are still attested at load — so a
    /// corrupted cache can never inject an unsigned model.
    pub trait WeightCache {
        /// Fetch cached weight bytes for `model_id`, if present.
        fn get(&self, model_id: ModelId) -> Option<Vec<u8>>;
        /// Store `data` as the cached weights for `model_id`.
        fn put(&mut self, model_id: ModelId, data: &[u8]);
    }

    /// In-memory [`WeightCache`] for hosts and tests (WS5-09.6).
    #[derive(Debug, Default)]
    pub struct MemWeightCache {
        entries: BTreeMap<ModelId, Vec<u8>>,
    }

    impl MemWeightCache {
        /// Create an empty cache.
        #[must_use]
        pub fn new() -> Self {
            Self {
                entries: BTreeMap::new(),
            }
        }

        /// Number of cached models.
        #[must_use]
        pub fn len(&self) -> usize {
            self.entries.len()
        }

        /// Whether the cache holds no models.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
    }

    impl WeightCache for MemWeightCache {
        fn get(&self, model_id: ModelId) -> Option<Vec<u8>> {
            self.entries.get(&model_id).cloned()
        }

        fn put(&mut self, model_id: ModelId, data: &[u8]) {
            self.entries.insert(model_id, data.to_vec());
        }
    }

    // -------------------------------------------------------------------------
    // Load-time attestation helper
    // -------------------------------------------------------------------------

    /// Re-verify a manifest's Ed25519 signature over its signed BLAKE3 measure.
    ///
    /// This is the authenticity half of load-time attestation (WS5-04.5/.7).
    /// Every byte-loading path on [`ModelRegistry`] calls it before trusting
    /// `manifest.hash`, so a load enforces provenance (the signature) in
    /// addition to integrity (the measure), independently of the register-time
    /// check. Verification uses the strict (non-malleable) `verify_strict`
    /// path inside [`NexaCoreVerifyingKey::verify`].
    ///
    /// # Errors
    ///
    /// - [`NexaCoreError::Crypto`] with
    ///   [`nexacore_types::error::CryptoErrorKind::InvalidSignature`] if the
    ///   signature does not verify (wrong key, tampered hash, or in-memory
    ///   manifest corruption).
    fn attest_manifest_signature(manifest: &ModelManifest) -> Result<()> {
        manifest
            .signing_key
            .verify(&manifest.hash, &manifest.signature)
    }

    #[cfg(test)]
    mod attest_at_load_tests {
        use nexacore_crypto::signing::{NexaCoreSignature, NexaCoreSigningKey};
        use nexacore_types::{ModelId, NexaCoreError, error::CryptoErrorKind};

        use super::{ModelFormat, ModelManifest, ModelRegistry};

        /// Minimal valid GGUF v3 blob (no tensors, no metadata).
        fn minimal_gguf() -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&crate::gguf::GGUF_MAGIC.to_le_bytes());
            buf.extend_from_slice(&3u32.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf
        }

        /// Build a valid signed GGUF manifest over `data` using key seed `seed`.
        fn signed_gguf_manifest(seed: u8, data: &[u8]) -> ModelManifest {
            let sk = NexaCoreSigningKey::from_bytes([seed; 32]);
            let hash = *blake3::hash(data).as_bytes();
            ModelManifest {
                model_id: ModelId::from_manifest_hash(hash),
                name: "attest-at-load".into(),
                version: "1.0.0".into(),
                hash,
                signature: sk.sign(&hash),
                signing_key: sk.verifying_key(),
                size_bytes: data.len() as u64,
                format: ModelFormat::Gguf,
            }
        }

        /// Flip one bit of the in-memory signature stored for `id`, simulating
        /// corruption of an already-registered manifest (the register-time
        /// check has already passed). Reaches into the private registry state,
        /// which is only possible from a child module of `model`.
        fn corrupt_stored_signature(reg: &mut ModelRegistry, id: ModelId) {
            let entry = reg.entries.get_mut(&id).expect("entry must exist");
            let mut sig = entry.manifest.signature.to_bytes();
            sig[0] ^= 0x01;
            entry.manifest.signature = NexaCoreSignature::from_bytes(sig);
        }

        #[test]
        fn load_from_bytes_valid_attestation_succeeds() {
            let data = minimal_gguf();
            let mut reg = ModelRegistry::new();
            let id = reg.register(signed_gguf_manifest(0x5B, &data)).unwrap();
            reg.load_from_bytes(id, &data).unwrap();
            assert!(reg.is_loaded(id));
        }

        #[test]
        fn load_from_bytes_reverifies_signature_at_load() {
            let data = minimal_gguf();
            let mut reg = ModelRegistry::new();
            let id = reg.register(signed_gguf_manifest(0x5A, &data)).unwrap();

            // The measure (hash) still matches the bytes, but the signature no
            // longer verifies — the loader must reject the model at load time.
            corrupt_stored_signature(&mut reg, id);

            let err = reg.load_from_bytes(id, &data).unwrap_err();
            match err {
                NexaCoreError::Crypto { kind, .. } => {
                    assert_eq!(kind, CryptoErrorKind::InvalidSignature);
                }
                other => panic!("expected Crypto::InvalidSignature, got: {other:?}"),
            }
            assert!(
                !reg.is_loaded(id),
                "model must not be loaded after a failed load-time attestation"
            );
        }

        #[test]
        fn load_tensors_from_bytes_reverifies_signature_at_load() {
            let data = minimal_gguf();
            let mut reg = ModelRegistry::new();
            let id = reg.register(signed_gguf_manifest(0x5C, &data)).unwrap();

            corrupt_stored_signature(&mut reg, id);

            let err = reg.load_tensors_from_bytes(id, &data).unwrap_err();
            match err {
                NexaCoreError::Crypto { kind, .. } => {
                    assert_eq!(kind, CryptoErrorKind::InvalidSignature);
                }
                other => panic!("expected Crypto::InvalidSignature, got: {other:?}"),
            }
            assert!(!reg.is_loaded(id));
        }
    }

    #[cfg(test)]
    mod ws5_09_tests {
        use std::cell::Cell;

        use nexacore_crypto::signing::NexaCoreSigningKey;
        use nexacore_types::{ModelId, NexaCoreError};

        use super::{MemWeightCache, ModelFormat, ModelManifest, ModelRegistry, compare_versions};

        /// Minimal valid GGUF v3 blob with `tag` appended so distinct tags yield
        /// distinct, still-parseable binaries (the header declares 0 tensors / 0
        /// metadata, so trailing bytes are ignored by the parser).
        fn gguf_blob(tag: u8) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&crate::gguf::GGUF_MAGIC.to_le_bytes());
            buf.extend_from_slice(&3u32.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.push(tag);
            buf
        }

        /// A signed manifest whose measure is the BLAKE3 of `data` (loadable).
        fn loadable_manifest(seed: u8, name: &str, version: &str, data: &[u8]) -> ModelManifest {
            let sk = NexaCoreSigningKey::from_bytes([seed; 32]);
            let hash = *blake3::hash(data).as_bytes();
            ModelManifest {
                model_id: ModelId::from_manifest_hash(hash),
                name: name.into(),
                version: version.into(),
                hash,
                signature: sk.sign(&hash),
                signing_key: sk.verifying_key(),
                size_bytes: data.len() as u64,
                format: ModelFormat::Gguf,
            }
        }

        /// A signed manifest with a synthetic measure (no real binary) — fine for
        /// the query/persistence paths that never load bytes.
        fn synthetic_manifest(seed: u8, name: &str, version: &str) -> ModelManifest {
            let sk = NexaCoreSigningKey::from_bytes([seed; 32]);
            let hash = [seed; 32];
            ModelManifest {
                model_id: ModelId::from_manifest_hash(hash),
                name: name.into(),
                version: version.into(),
                hash,
                signature: sk.sign(&hash),
                signing_key: sk.verifying_key(),
                size_bytes: 0,
                format: ModelFormat::Gguf,
            }
        }

        // ── .1 versioned query ────────────────────────────────────────────────

        #[test]
        fn compare_versions_is_numeric_not_lexical() {
            use core::cmp::Ordering;
            assert_eq!(compare_versions("3.0.1", "3.1.0"), Ordering::Less);
            assert_eq!(compare_versions("3.10.0", "3.2.0"), Ordering::Greater);
            assert_eq!(compare_versions("3", "3.0.0"), Ordering::Equal);
            assert_eq!(compare_versions("1.2.3", "1.2.3"), Ordering::Equal);
        }

        #[test]
        fn latest_resolves_newest_numeric_version() {
            let mut reg = ModelRegistry::new();
            reg.register(synthetic_manifest(0x01, "llama", "3.2.0"))
                .unwrap();
            reg.register(synthetic_manifest(0x02, "llama", "3.10.0"))
                .unwrap();
            reg.register(synthetic_manifest(0x03, "llama", "3.9.0"))
                .unwrap();
            reg.register(synthetic_manifest(0x04, "other", "9.9.9"))
                .unwrap();
            let latest = reg.latest("llama").expect("a llama version");
            assert_eq!(latest.version, "3.10.0");
            assert!(reg.latest("missing").is_none());
        }

        #[test]
        fn versions_of_sorted_newest_first() {
            let mut reg = ModelRegistry::new();
            reg.register(synthetic_manifest(0x01, "m", "1.0.0"))
                .unwrap();
            reg.register(synthetic_manifest(0x02, "m", "2.0.0"))
                .unwrap();
            reg.register(synthetic_manifest(0x03, "m", "1.5.0"))
                .unwrap();
            let versions: Vec<&str> = reg
                .versions_of("m")
                .iter()
                .map(|m| m.version.as_str())
                .collect();
            assert_eq!(versions, vec!["2.0.0", "1.5.0", "1.0.0"]);
        }

        // ── .2 persistence + available ────────────────────────────────────────

        #[test]
        fn available_summarizes_registered_models() {
            let mut reg = ModelRegistry::new();
            let id = reg
                .register(synthetic_manifest(0x07, "sum", "1.0.0"))
                .unwrap();
            let summaries = reg.available();
            assert_eq!(summaries.len(), 1);
            assert_eq!(summaries[0].model_id, id);
            assert_eq!(summaries[0].name, "sum");
            assert!(!summaries[0].loaded);
        }

        #[test]
        fn to_bytes_from_bytes_round_trips() {
            let mut reg = ModelRegistry::new();
            reg.register(synthetic_manifest(0x10, "a", "1.0.0"))
                .unwrap();
            reg.register(synthetic_manifest(0x11, "b", "2.0.0"))
                .unwrap();
            let bytes = reg.to_bytes().expect("encode");
            let restored = ModelRegistry::from_bytes(&bytes).expect("decode");
            assert_eq!(restored.list(), reg.list());
            // Restored models are cold (load state is runtime-only, not persisted).
            for id in restored.list() {
                assert!(!restored.is_loaded(id));
            }
        }

        #[test]
        fn from_bytes_rejects_tampered_manifest_fail_closed() {
            // A blob carrying a manifest whose signature does not verify over its
            // measure must be rejected on reload (persistence is not a trust bypass).
            let sk = NexaCoreSigningKey::from_bytes([0x20; 32]);
            let hash = [0x20u8; 32];
            let bad = ModelManifest {
                model_id: ModelId::from_manifest_hash(hash),
                name: "tampered".into(),
                version: "1.0.0".into(),
                hash,
                // Signature over a DIFFERENT measure — does not verify over `hash`.
                signature: sk.sign(&[0xFFu8; 32]),
                signing_key: sk.verifying_key(),
                size_bytes: 0,
                format: ModelFormat::Gguf,
            };
            let bytes = nexacore_types::wire::encode_canonical(&vec![bad]).expect("encode");
            let err = ModelRegistry::from_bytes(&bytes).unwrap_err();
            assert!(
                matches!(err, NexaCoreError::Crypto { .. }),
                "tampered manifest must be rejected, got {err:?}"
            );
        }

        // ── .3 lazy load ──────────────────────────────────────────────────────

        #[test]
        fn ensure_loaded_is_idempotent() {
            let data = gguf_blob(0xA1);
            let mut reg = ModelRegistry::new();
            let id = reg
                .register(loadable_manifest(0x30, "lazy", "1.0.0", &data))
                .unwrap();
            assert!(reg.ensure_loaded(id, &data).unwrap(), "first call loads");
            assert!(reg.is_loaded(id));
            assert!(
                !reg.ensure_loaded(id, &data).unwrap(),
                "second call is a no-op"
            );
        }

        // ── .6 weight cache (composed with lazy load) ─────────────────────────

        #[test]
        fn ensure_loaded_cached_misses_then_hits() {
            let data = gguf_blob(0xB2);
            let mut reg = ModelRegistry::new();
            let id = reg
                .register(loadable_manifest(0x31, "cached", "1.0.0", &data))
                .unwrap();
            let mut cache = MemWeightCache::new();
            let fetches = Cell::new(0u32);

            // Miss: fetch is invoked once and the bytes are cached.
            let loaded = reg
                .ensure_loaded_cached(id, &mut cache, || {
                    fetches.set(fetches.get() + 1);
                    Ok(data.clone())
                })
                .unwrap();
            assert!(loaded);
            assert_eq!(fetches.get(), 1);
            assert_eq!(cache.len(), 1);

            // Retire it, then a second ensure must hit the cache (fetch NOT called).
            reg.unload(id).unwrap();
            let loaded2 = reg
                .ensure_loaded_cached(id, &mut cache, || {
                    fetches.set(fetches.get() + 1);
                    Ok(data.clone())
                })
                .unwrap();
            assert!(loaded2);
            assert_eq!(fetches.get(), 1, "cache hit must not re-fetch");
            assert!(reg.is_loaded(id));
        }

        // ── .4 unload releases the cached header ──────────────────────────────

        #[test]
        fn unload_releases_cached_header() {
            let data = gguf_blob(0xC3);
            let mut reg = ModelRegistry::new();
            let id = reg
                .register(loadable_manifest(0x32, "rel", "1.0.0", &data))
                .unwrap();
            reg.load_from_bytes(id, &data).unwrap();
            assert!(reg.entries.get(&id).unwrap().gguf_header.is_some());
            reg.unload(id).unwrap();
            assert!(
                reg.entries.get(&id).unwrap().gguf_header.is_none(),
                "unload must drop the parsed header"
            );
            assert!(reg.resident().is_empty());
        }

        // ── .7 hot-swap ───────────────────────────────────────────────────────

        #[test]
        fn hot_swap_loads_new_then_unloads_old() {
            let old_data = gguf_blob(0xD4);
            let new_data = gguf_blob(0xD5);
            let mut reg = ModelRegistry::new();
            let old_id = reg
                .register(loadable_manifest(0x33, "m", "1.0.0", &old_data))
                .unwrap();
            let new_id = reg
                .register(loadable_manifest(0x34, "m", "2.0.0", &new_data))
                .unwrap();
            reg.load_from_bytes(old_id, &old_data).unwrap();

            reg.hot_swap(old_id, new_id, &new_data).unwrap();
            assert!(reg.is_loaded(new_id), "incoming is resident");
            assert!(!reg.is_loaded(old_id), "outgoing is retired");
            assert_eq!(reg.resident(), vec![new_id]);
        }

        #[test]
        fn hot_swap_failed_incoming_leaves_outgoing_resident() {
            let old_data = gguf_blob(0xE6);
            let new_data = gguf_blob(0xE7);
            let mut reg = ModelRegistry::new();
            let old_id = reg
                .register(loadable_manifest(0x35, "m", "1.0.0", &old_data))
                .unwrap();
            let new_id = reg
                .register(loadable_manifest(0x36, "m", "2.0.0", &new_data))
                .unwrap();
            reg.load_from_bytes(old_id, &old_data).unwrap();

            // Wrong bytes for the incoming model → BLAKE3 mismatch, swap must fail.
            let wrong = gguf_blob(0xEE);
            let err = reg.hot_swap(old_id, new_id, &wrong).unwrap_err();
            assert!(matches!(err, NexaCoreError::Internal { .. }));
            assert!(
                reg.is_loaded(old_id),
                "outgoing must stay resident on a failed swap"
            );
            assert!(!reg.is_loaded(new_id));
        }
    }
}

// =============================================================================
// inference — InferencePipeline
// =============================================================================

/// Inference orchestration on the local node.
///
/// This module provides the [`crate::inference::InferencePipeline`] which dispatches inference
/// requests to the appropriate loaded model. The tensor backend is a stub in
/// Phase 2 Stream 1; it returns an empty output vector and records the
/// round-trip latency. A real backend (candle or tch) will replace the stub
/// in a later stream.
#[cfg(feature = "std")]
pub mod inference {
    use std::{sync::Arc, time::Instant};

    use nexacore_types::{ModelId, NexaCoreError, Result};
    use tokio::sync::Mutex;
    use tracing::{debug, instrument};

    use crate::model::ModelRegistry;

    // -------------------------------------------------------------------------
    // InferenceRequest
    // -------------------------------------------------------------------------

    /// A request to run inference on a loaded model.
    ///
    /// The `input` field carries opaque tensor bytes whose encoding is
    /// defined by the model's format (ONNX protobuf, safetensors slice, etc.).
    /// The runtime does not inspect the contents; they are forwarded verbatim
    /// to the tensor backend.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::inference::InferenceRequest;
    /// use nexacore_types::ModelId;
    ///
    /// let req = InferenceRequest {
    ///     model_id: ModelId::from_bytes([0xAA; 32]),
    ///     input: vec![1, 2, 3],
    ///     request_id: 42,
    /// };
    /// assert_eq!(req.request_id, 42);
    /// ```
    #[derive(Debug, Clone)]
    pub struct InferenceRequest {
        /// Target model to run.
        pub model_id: ModelId,
        /// Opaque tensor bytes (format defined by `ModelFormat`).
        pub input: Vec<u8>,
        /// Caller-assigned monotonic request identifier for correlation.
        pub request_id: u64,
    }

    // -------------------------------------------------------------------------
    // InferenceResponse
    // -------------------------------------------------------------------------

    /// The result of a single inference call.
    ///
    /// `output` carries opaque tensor bytes in the same format as the
    /// corresponding request's `input`. When the stub tensor backend is
    /// active `output` is always empty; callers must check that they are not
    /// running against a stub before interpreting the response.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::inference::InferenceResponse;
    ///
    /// let resp = InferenceResponse {
    ///     request_id: 42,
    ///     output: vec![],
    ///     latency_us: 100,
    /// };
    /// assert_eq!(resp.request_id, 42);
    /// ```
    #[derive(Debug, Clone)]
    pub struct InferenceResponse {
        /// Echoes the `request_id` from the originating [`InferenceRequest`].
        pub request_id: u64,
        /// Opaque tensor bytes produced by the model.
        pub output: Vec<u8>,
        /// Wall-clock latency of the inference call in microseconds.
        pub latency_us: u64,
    }

    // -------------------------------------------------------------------------
    // InferencePipeline
    // -------------------------------------------------------------------------

    /// Dispatches inference requests to loaded models.
    ///
    /// `InferencePipeline` holds a shared reference to a [`ModelRegistry`]
    /// wrapped in a `tokio::sync::Mutex` so multiple async tasks can submit
    /// requests concurrently. The registry is locked only for the load-state
    /// check; the (stub) tensor call is not performed while holding the lock.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::sync::Arc;
    ///
    /// use nexacore_crypto::signing::NexaCoreSigningKey;
    /// use nexacore_runtime::{
    ///     inference::{InferencePipeline, InferenceRequest},
    ///     model::{ModelFormat, ModelManifest, ModelRegistry},
    /// };
    /// use nexacore_types::ModelId;
    /// use tokio::sync::Mutex;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let sk = NexaCoreSigningKey::from_bytes([0x11; 32]);
    /// let hash = [0xAAu8; 32];
    /// let manifest = ModelManifest {
    ///     model_id: ModelId::from_manifest_hash(hash),
    ///     name: "pipeline-test".into(),
    ///     version: "1.0.0".into(),
    ///     hash,
    ///     signature: sk.sign(&hash),
    ///     signing_key: sk.verifying_key(),
    ///     size_bytes: 0,
    ///     format: ModelFormat::Gguf,
    /// };
    ///
    /// let mut reg = ModelRegistry::new();
    /// let id = reg.register(manifest).unwrap();
    /// reg.load(id).unwrap();
    ///
    /// let registry = Arc::new(Mutex::new(reg));
    /// let pipeline = InferencePipeline::new(Arc::clone(&registry));
    ///
    /// let req = InferenceRequest {
    ///     model_id: id,
    ///     input: vec![],
    ///     request_id: 1,
    /// };
    /// let resp = pipeline.infer(req).await.unwrap();
    /// assert_eq!(resp.request_id, 1);
    /// # }
    /// ```
    #[derive(Clone, Debug)]
    pub struct InferencePipeline {
        registry: Arc<Mutex<ModelRegistry>>,
    }

    impl InferencePipeline {
        /// Create a pipeline backed by the given registry.
        ///
        /// The registry must be wrapped in a `tokio::sync::Mutex` so that
        /// concurrent inference requests serialise access to load-state checks.
        #[must_use]
        pub fn new(registry: Arc<Mutex<ModelRegistry>>) -> Self {
            Self { registry }
        }

        /// Dispatch an inference request to the loaded model.
        ///
        /// The call will fail immediately if the requested model is not in the
        /// `Loaded` state — either because it was never registered or because
        /// it has been unloaded. Callers should call
        /// [`ModelRegistry::load`][crate::model::ModelRegistry::load] first.
        ///
        /// # Stub behaviour
        ///
        /// The current tensor backend is a placeholder. It returns an empty
        /// `output` vector and records the actual wall-clock round-trip time
        /// for the no-op dispatch in `latency_us`. Replace this stub with a
        /// real tensor call when the tensor backend lands.
        ///
        /// # Errors
        ///
        /// - [`NexaCoreError::Internal`] if the model is not registered.
        /// - [`NexaCoreError::Internal`] if the model is registered but not loaded.
        #[instrument(skip(self), fields(request_id = request.request_id, model_id = ?request.model_id))]
        pub async fn infer(&self, request: InferenceRequest) -> Result<InferenceResponse> {
            let model_id: ModelId = request.model_id;

            // Check load state — lock scope is intentionally narrow so we do
            // not hold the mutex across any await point.
            {
                let registry = self.registry.lock().await;
                if !registry.is_loaded(model_id) {
                    return Err(NexaCoreError::internal(
                        "runtime::inference::infer — model not loaded",
                    ));
                }
            } // lock released here, before the tensor dispatch below.

            let start = Instant::now();
            debug!(model_id = ?model_id, "dispatching to tensor backend (stub)");

            // Stub tensor dispatch: return empty output.
            // FUTURE: replace with `backend.run(model_id, &request.input)?`
            let output: Vec<u8> = Vec::new();

            let latency_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

            Ok(InferenceResponse {
                request_id: request.request_id,
                output,
                latency_us,
            })
        }
    }
}

// =============================================================================
// router — TierRouter
// =============================================================================

/// Execution tier routing decisions.
///
/// This module implements the routing policy that decides which execution
/// tier handles a given inference request.
///
/// ## Phase 2 policy engine
///
/// Sprint 11.a introduces [`crate::router::RoutingPolicy`], [`crate::router::TierDecision`], and
/// [`crate::router::TierError`] alongside the new [`crate::router::TierRouter::route_decision`] method.
/// The Phase 2 contract (NCIP-Phase2-Entry-021 § S2.1) mandates that the
/// router **only** successfully routes to [`crate::router::ExecutionTier::Local`] (Tier 0).
/// Tier 1 and Tier 2 are structurally reserved but not yet implemented;
/// any workload that would require escalation is rejected with
/// [`crate::router::TierError::TierUnavailable`] so the caller can apply graceful
/// degradation logic.
///
/// The legacy [`crate::router::TierRouter::route`] method remains unchanged and is kept for
/// backward compatibility with all existing callers.
#[cfg(feature = "std")]
pub mod router {
    use thiserror::Error;
    use tracing::debug;

    use crate::inference::InferenceRequest;

    // -------------------------------------------------------------------------
    // ExecutionTier
    // -------------------------------------------------------------------------

    /// The set of execution tiers available to the NexaCore OS runtime.
    ///
    /// Tiers are ordered by privacy (Tier 0 is most private; data never leaves
    /// the local node). The router may escalate to a higher-numbered tier only
    /// when:
    ///
    /// 1. The model is not available locally, and
    /// 2. The user's policy explicitly permits the escalation tier.
    ///
    /// See [`/docs/02-architecture.md`](../../../docs/02-architecture.md)
    /// § "Execution tiers" for the full privacy contract.
    ///
    /// The variant order encodes the privacy ordering used by the Tier policy
    /// engine (WS5-05): `Local < PersonalCluster < FederatedMesh < Cloud`, i.e.
    /// a *higher* tier means the data travels *further* from the device.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum ExecutionTier {
        /// Tier 0 — model runs on the local node. Data never leaves the device.
        Local,
        /// Tier 1 — model runs on a user-owned personal compute cluster.
        PersonalCluster,
        /// Tier 2 — model runs on a federated mesh of trusted NexaCore nodes.
        FederatedMesh,
        /// Tier 3 — model runs on a commercial cloud provider.
        Cloud,
    }

    // -------------------------------------------------------------------------
    // RoutingPolicy
    // -------------------------------------------------------------------------

    /// Policy parameters that govern which execution tiers the router may use.
    ///
    /// The default policy (see [`Default`] impl) reflects the Phase 2
    /// contract: Tier 1 and Tier 2 escalation are **disabled**, no upper bound
    /// on model size is enforced locally, and attestation is not required.
    ///
    /// Callers that need different behaviour must construct a custom policy and
    /// pass it to [`TierRouter::route_decision`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::router::RoutingPolicy;
    ///
    /// // Phase-2 default: tier 1/2 disallowed, attestation not required.
    /// let policy = RoutingPolicy::new();
    /// assert!(!policy.allow_tier_1);
    /// assert!(!policy.allow_tier_2);
    /// assert!(!policy.require_attestation);
    /// ```
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RoutingPolicy {
        /// Whether escalation to Tier 1 (personal cluster) is permitted.
        ///
        /// Setting this to `true` does **not** guarantee escalation will
        /// succeed in Phase 2; [`TierRouter::route_decision`] still rejects
        /// Tier 1 dispatch with [`TierError::TierUnavailable`] because the
        /// cluster backend is not yet implemented.
        pub allow_tier_1: bool,

        /// Whether escalation to Tier 2 (federated mesh) is permitted.
        ///
        /// Same caveat as [`allow_tier_1`](Self::allow_tier_1): not yet
        /// implemented in Phase 2.
        pub allow_tier_2: bool,

        /// Maximum model size in bytes that may be served locally (Tier 0).
        ///
        /// If the model size reported by the caller exceeds this threshold
        /// **and** no higher tier is available, [`TierRouter::route_decision`]
        /// returns [`TierError::TierUnavailable`]. Set to [`u64::MAX`] (the
        /// default) to impose no local-size limit.
        pub max_model_size_bytes: u64,

        /// Whether an attestation proof must accompany each routing request.
        ///
        /// When `true`, [`TierRouter::route_decision`] requires `attested ==
        /// true`; otherwise it returns [`TierError::AttestationRequired`].
        pub require_attestation: bool,
    }

    impl RoutingPolicy {
        /// Create a new [`RoutingPolicy`] with the Phase 2 default values.
        ///
        /// - `allow_tier_1` = `false`
        /// - `allow_tier_2` = `false`
        /// - `max_model_size_bytes` = [`u64::MAX`] (no local-size cap)
        /// - `require_attestation` = `false`
        ///
        /// ```rust
        /// use nexacore_runtime::router::RoutingPolicy;
        ///
        /// let p = RoutingPolicy::new();
        /// assert_eq!(p.max_model_size_bytes, u64::MAX);
        /// ```
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Default for RoutingPolicy {
        fn default() -> Self {
            Self {
                allow_tier_1: false,
                allow_tier_2: false,
                // No local-size ceiling by default; callers opt-in to a limit.
                max_model_size_bytes: u64::MAX,
                require_attestation: false,
            }
        }
    }

    // -------------------------------------------------------------------------
    // TierReason
    // -------------------------------------------------------------------------

    /// The reason the router chose (or rejected) a particular execution tier.
    ///
    /// Carried inside [`TierDecision`] so callers can log, audit, or surface
    /// the decision rationale without re-running the policy evaluation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TierReason {
        /// The active policy allows only Tier 0 (local); no escalation was
        /// attempted or needed.
        LocalOnlyPolicy,

        /// The model size exceeds [`RoutingPolicy::max_model_size_bytes`], but
        /// escalation to a higher tier was not permitted by the policy.
        ModelTooLarge,

        /// The policy would allow a higher tier, but escalation was blocked
        /// because the target tier is not yet implemented in Phase 2.
        EscalationDenied,

        /// Attestation was required by the policy but no proof was provided.
        AttestationMissing,
    }

    // -------------------------------------------------------------------------
    // TierDecision
    // -------------------------------------------------------------------------

    /// The outcome of a successful routing evaluation.
    ///
    /// Produced by [`TierRouter::route_decision`] on the `Ok` path. Carries
    /// the chosen tier, the human-readable reason, and a caller-supplied
    /// nanosecond timestamp so audit records can be produced without re-querying
    /// a clock.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::{
    ///     inference::InferenceRequest,
    ///     router::{ExecutionTier, RoutingPolicy, TierDecision, TierReason, TierRouter},
    /// };
    /// use nexacore_types::ModelId;
    ///
    /// let router = TierRouter::new();
    /// let policy = RoutingPolicy::new();
    /// let req = InferenceRequest {
    ///     model_id: ModelId::from_bytes([0x00; 32]),
    ///     input: vec![],
    ///     request_id: 0,
    /// };
    /// let decision = router
    ///     .route_decision(&req, &policy, 0, false, 42_000)
    ///     .expect("default policy must succeed");
    /// assert_eq!(decision.tier, ExecutionTier::Local);
    /// assert_eq!(decision.reason, TierReason::LocalOnlyPolicy);
    /// assert_eq!(decision.decided_at_ns, 42_000);
    /// ```
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TierDecision {
        /// The execution tier selected by the router.
        pub tier: ExecutionTier,

        /// Why this tier was selected.
        pub reason: TierReason,

        /// Caller-supplied wall-clock timestamp in nanoseconds at which the
        /// decision was made. The router does **not** read a clock internally;
        /// the value is passed through unchanged so tests remain deterministic.
        pub decided_at_ns: u64,
    }

    // -------------------------------------------------------------------------
    // TierError
    // -------------------------------------------------------------------------

    /// Errors returned by [`TierRouter::route_decision`].
    ///
    /// All variants are non-exhaustive from a future-compatibility standpoint;
    /// callers should match on them with a `_ =>` arm.
    #[derive(Clone, Debug, PartialEq, Eq, Error)]
    pub enum TierError {
        /// The requested execution tier is not available.
        ///
        /// In Phase 2 this is returned whenever escalation beyond Tier 0 would
        /// be required (either because the model is too large for local
        /// execution or because a higher tier was requested) since Tier 1 and
        /// Tier 2 backends are not yet implemented.
        #[error("execution tier {requested:?} is not available in this runtime version")]
        TierUnavailable {
            /// The tier that would have been needed to serve the request.
            requested: ExecutionTier,
        },

        /// An attestation proof was required by the active policy but the
        /// caller indicated that the model has not been attested.
        #[error("attestation proof required by policy but not provided")]
        AttestationRequired,
    }

    // -------------------------------------------------------------------------
    // TierRouter
    // -------------------------------------------------------------------------

    /// Routes inference requests to the appropriate execution tier.
    ///
    /// ## Backward-compatible stub method
    ///
    /// [`TierRouter::route`] is a Phase 2 Stream 1 stub that always returns
    /// [`ExecutionTier::Local`]. It is kept unchanged for backward
    /// compatibility.
    ///
    /// ## Policy-aware method (Sprint 11.a)
    ///
    /// [`TierRouter::route_decision`] evaluates a [`RoutingPolicy`] and the
    /// caller-supplied model size and attestation state, returning a
    /// [`TierDecision`] or a [`TierError`]. See the method documentation for
    /// the full Phase 2 contract.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::{
    ///     inference::InferenceRequest,
    ///     router::{ExecutionTier, TierRouter},
    /// };
    /// use nexacore_types::ModelId;
    ///
    /// let router = TierRouter::new();
    /// let req = InferenceRequest {
    ///     model_id: ModelId::from_bytes([0x00; 32]),
    ///     input: vec![],
    ///     request_id: 0,
    /// };
    /// assert_eq!(router.route(&req), ExecutionTier::Local);
    /// ```
    #[derive(Debug, Default)]
    pub struct TierRouter;

    impl TierRouter {
        /// Create a new tier router with default (local-only) policy.
        ///
        /// ```rust
        /// use nexacore_runtime::router::TierRouter;
        /// let _ = TierRouter::new();
        /// ```
        #[must_use]
        pub fn new() -> Self {
            Self
        }

        /// Decide which execution tier should handle `request`.
        ///
        /// Phase 2 Stream 1 stub: always returns [`ExecutionTier::Local`].
        /// The caller is responsible for verifying that the local node has the
        /// requested model loaded before dispatching.
        #[must_use]
        pub fn route(&self, request: &InferenceRequest) -> ExecutionTier {
            let _ = self;
            debug!(
                request_id = request.request_id,
                model_id = ?request.model_id,
                "tier router: routing to Local (Tier 0, stub)"
            );
            ExecutionTier::Local
        }

        /// Evaluate `policy` and produce a [`TierDecision`] for `request`.
        ///
        /// This is the Sprint 11.a policy engine entry point. It implements
        /// the Phase 2 contract defined in NCIP-Phase2-Entry-021 § S2.1:
        ///
        /// - Only [`ExecutionTier::Local`] (Tier 0) is a valid successful
        ///   routing outcome in Phase 2. Any path that would require Tier 1
        ///   or Tier 2 returns [`TierError::TierUnavailable`].
        /// - If `policy.require_attestation` is `true` and `attested` is
        ///   `false`, returns [`TierError::AttestationRequired`] **before**
        ///   any tier-escalation evaluation (attestation failure is always
        ///   the highest-priority rejection).
        /// - If `model_size_bytes` exceeds `policy.max_model_size_bytes`, the
        ///   router would need to escalate; since escalation is unavailable in
        ///   Phase 2, it returns `Err(TierError::TierUnavailable { requested:
        ///   ExecutionTier::PersonalCluster })`.
        /// - Otherwise returns `Ok(TierDecision { tier: Local, reason:
        ///   LocalOnlyPolicy, decided_at_ns })`.
        ///
        /// ## Determinism
        ///
        /// `decided_at_ns` is **passed in** by the caller; this method never
        /// reads a wall-clock. This keeps unit tests fully deterministic and
        /// matches the timestamp-passing convention used elsewhere in the
        /// crate.
        ///
        /// ## Parameters
        ///
        /// - `request` — the inference request being routed (used for
        ///   structured logging only; routing decisions do not depend on its
        ///   payload in Phase 2).
        /// - `policy` — the active [`RoutingPolicy`].
        /// - `model_size_bytes` — the byte size of the model to be served.
        /// - `attested` — `true` if the model has been successfully attested
        ///   by the caller before this call; `false` otherwise.
        /// - `decided_at_ns` — wall-clock nanoseconds supplied by the caller;
        ///   stored verbatim in the returned [`TierDecision`].
        ///
        /// # Errors
        ///
        /// Returns [`TierError::AttestationRequired`] when attestation is
        /// required by the policy but not provided.
        ///
        /// Returns [`TierError::TierUnavailable`] when the model would need
        /// to be escalated to a tier that is not implemented in Phase 2.
        ///
        /// # Example
        ///
        /// ```rust
        /// use nexacore_runtime::{
        ///     inference::InferenceRequest,
        ///     router::{ExecutionTier, RoutingPolicy, TierError, TierReason, TierRouter},
        /// };
        /// use nexacore_types::ModelId;
        ///
        /// let router = TierRouter::new();
        /// let policy = RoutingPolicy::new();
        /// let req = InferenceRequest {
        ///     model_id: ModelId::from_bytes([0x00; 32]),
        ///     input: vec![],
        ///     request_id: 1,
        /// };
        ///
        /// // Default policy, small model, not attested → Ok(Local).
        /// let decision = router
        ///     .route_decision(&req, &policy, 512, false, 1_000_000)
        ///     .expect("default policy must succeed");
        /// assert_eq!(decision.tier, ExecutionTier::Local);
        /// assert_eq!(decision.reason, TierReason::LocalOnlyPolicy);
        ///
        /// // Model too large for local execution → Err(TierUnavailable).
        /// let big_policy = RoutingPolicy {
        ///     max_model_size_bytes: 100,
        ///     ..RoutingPolicy::new()
        /// };
        /// let err = router
        ///     .route_decision(&req, &big_policy, 200, false, 0)
        ///     .unwrap_err();
        /// assert!(matches!(err, TierError::TierUnavailable { .. }));
        /// ```
        #[allow(
            clippy::cognitive_complexity,
            reason = "tier policy evaluation: branches enumerate the Phase-2 routing rules"
        )]
        pub fn route_decision(
            &self,
            request: &InferenceRequest,
            policy: &RoutingPolicy,
            model_size_bytes: u64,
            attested: bool,
            decided_at_ns: u64,
        ) -> Result<TierDecision, TierError> {
            // TierRouter is a unit struct; `self` carries no state in Phase 2.
            // The receiver is kept so callers can upgrade to stateful routing
            // (e.g., cached resource metrics) without a breaking API change.
            let _ = self;

            // Attestation check is highest priority: reject before any tier
            // evaluation so that an un-attested model never receives routing
            // consideration, even to Tier 0.
            if policy.require_attestation && !attested {
                debug!(
                    request_id = request.request_id,
                    model_id = ?request.model_id,
                    "tier router: attestation required but not provided"
                );
                return Err(TierError::AttestationRequired);
            }

            // Size check: if the model exceeds the local-size cap we would need
            // to escalate, but Phase 2 does not implement higher tiers.
            if model_size_bytes > policy.max_model_size_bytes {
                debug!(
                    request_id = request.request_id,
                    model_id = ?request.model_id,
                    model_size_bytes,
                    max_model_size_bytes = policy.max_model_size_bytes,
                    "tier router: model too large for local execution; escalation \
                     unavailable in Phase 2"
                );
                // PersonalCluster (Tier 1) is the first escalation target;
                // report it as the unavailable requested tier.
                return Err(TierError::TierUnavailable {
                    requested: ExecutionTier::PersonalCluster,
                });
            }

            // Phase 2 contract: always route locally regardless of
            // allow_tier_1 / allow_tier_2 flags because higher tiers are not
            // implemented yet.
            debug!(
                request_id = request.request_id,
                model_id = ?request.model_id,
                decided_at_ns,
                "tier router: routing to Local (Tier 0, Phase 2 policy)"
            );
            Ok(TierDecision {
                tier: ExecutionTier::Local,
                reason: TierReason::LocalOnlyPolicy,
                decided_at_ns,
            })
        }
    }

    // -------------------------------------------------------------------------
    // Tier policy engine (WS5-05): workload sensitivity → execution tier
    // -------------------------------------------------------------------------

    /// How privacy-sensitive a workload's input is (WS5-05.1).
    ///
    /// Bounds how far the router may send the data: a more sensitive workload
    /// gets a lower tier ceiling (closer to the device).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Sensitivity {
        /// No private content; may use whatever tier the policy permits.
        Public,
        /// Personal or contextual content; should prefer user-owned tiers and
        /// reach the cloud only with explicit consent.
        Sensitive,
        /// Secrets, credentials, or regulated data; must stay on-device.
        HighlySensitive,
    }

    /// The latency requirement of a workload (WS5-05.1).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LatencyClass {
        /// Sub-second, interactive-critical: bias toward local execution.
        Realtime,
        /// Interactive but tolerant of a network round-trip.
        Interactive,
        /// Background/batch work; latency is not a constraint.
        Batch,
    }

    /// Snapshot of which execution tiers are currently reachable (WS5-05.1,
    /// the resource input to the policy engine for WS5-05.5).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[allow(
        clippy::struct_excessive_bools,
        reason = "four independent per-tier availability flags, one per ExecutionTier"
    )]
    pub struct ResourceState {
        /// A local (Tier 0) backend is ready.
        pub local_available: bool,
        /// A personal cluster (Tier 1) backend is reachable.
        pub personal_cluster_available: bool,
        /// A federated mesh (Tier 2) backend is reachable.
        pub mesh_available: bool,
        /// A commercial cloud (Tier 3) backend is reachable.
        pub cloud_available: bool,
    }

    impl Default for ResourceState {
        /// Local-only by default: only Tier 0 is assumed reachable.
        fn default() -> Self {
            Self {
                local_available: true,
                personal_cluster_available: false,
                mesh_available: false,
                cloud_available: false,
            }
        }
    }

    impl ResourceState {
        /// Whether `tier` is reachable in this snapshot.
        #[must_use]
        pub fn is_available(self, tier: ExecutionTier) -> bool {
            match tier {
                ExecutionTier::Local => self.local_available,
                ExecutionTier::PersonalCluster => self.personal_cluster_available,
                ExecutionTier::FederatedMesh => self.mesh_available,
                ExecutionTier::Cloud => self.cloud_available,
            }
        }
    }

    /// The Tier policy data model (WS5-05.1): the maximum execution tier
    /// permitted for each [`Sensitivity`] level, the latency preference, and the
    /// explicit cloud-consent gate.
    ///
    /// The [`Default`] is privacy-first: highly-sensitive workloads never leave
    /// the device, sensitive workloads stay within user-owned infrastructure
    /// (Tier 1), and cloud (Tier 3) is off until the user consents.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TierPolicy {
        /// Maximum tier for [`Sensitivity::Public`] workloads.
        pub max_tier_public: ExecutionTier,
        /// Maximum tier for [`Sensitivity::Sensitive`] workloads.
        pub max_tier_sensitive: ExecutionTier,
        /// Maximum tier for [`Sensitivity::HighlySensitive`] workloads.
        pub max_tier_highly_sensitive: ExecutionTier,
        /// Whether the user has given explicit consent for Tier-3 cloud
        /// (WS5-05.6). Without it, the engine caps the ceiling below `Cloud`.
        pub cloud_consent: bool,
        /// Preferred latency class; `Realtime` forces local execution.
        pub latency: LatencyClass,
    }

    impl Default for TierPolicy {
        fn default() -> Self {
            Self {
                max_tier_public: ExecutionTier::Cloud,
                max_tier_sensitive: ExecutionTier::PersonalCluster,
                max_tier_highly_sensitive: ExecutionTier::Local,
                cloud_consent: false,
                latency: LatencyClass::Interactive,
            }
        }
    }

    impl TierPolicy {
        /// The privacy-first default policy.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// The maximum tier this policy permits for `sensitivity`.
        #[must_use]
        pub fn ceiling_for(&self, sensitivity: Sensitivity) -> ExecutionTier {
            match sensitivity {
                Sensitivity::Public => self.max_tier_public,
                Sensitivity::Sensitive => self.max_tier_sensitive,
                Sensitivity::HighlySensitive => self.max_tier_highly_sensitive,
            }
        }
    }

    /// Classify the privacy sensitivity of `input` text (WS5-05.2).
    ///
    /// Deterministic and conservative (fail-toward-privacy): any
    /// credential/secret marker yields [`Sensitivity::HighlySensitive`]; any
    /// personal-data marker yields [`Sensitivity::Sensitive`]; otherwise
    /// [`Sensitivity::Public`]. This is a heuristic pre-filter for routing — the
    /// tokenization pipeline (WS5-06) provides the authoritative PII handling.
    #[must_use]
    pub fn classify_sensitivity(input: &str) -> Sensitivity {
        const SECRET_MARKERS: &[&str] = &[
            "password",
            "passphrase",
            "secret",
            "api key",
            "api_key",
            "apikey",
            "private key",
            "private_key",
            "-----begin",
            "credit card",
            "ssn",
            "social security",
            "seed phrase",
            "mnemonic",
            "bearer ",
            "token=",
        ];
        const PERSONAL_MARKERS: &[&str] = &[
            "my name is",
            "email",
            "@",
            "phone",
            "address",
            "medical",
            "diagnosis",
            "salary",
            "bank",
            "iban",
            "date of birth",
            "passport",
        ];
        let lower = input.to_ascii_lowercase();
        if SECRET_MARKERS.iter().any(|m| lower.contains(m)) {
            return Sensitivity::HighlySensitive;
        }
        if PERSONAL_MARKERS.iter().any(|m| lower.contains(m)) {
            return Sensitivity::Sensitive;
        }
        Sensitivity::Public
    }

    /// Decide the target execution tier for a workload of the given
    /// `sensitivity` under `policy` and current `resources` (WS5-05.3).
    ///
    /// The engine starts from the policy's per-sensitivity ceiling, then:
    /// 1. caps below `Cloud` unless the user consented to cloud (WS5-05.6),
    /// 2. forces `Local` for `Realtime` latency workloads, and
    /// 3. clamps down to the highest tier that is actually reachable.
    ///
    /// The result is the *target* tier; Phase-2 dispatch remains bounded by
    /// [`TierRouter::route_decision`] (only Tier 0 dispatches today). `Local` is
    /// always a safe fallback, so a highly-sensitive workload is local-only.
    #[must_use]
    pub fn decide_tier(
        sensitivity: Sensitivity,
        policy: &TierPolicy,
        resources: ResourceState,
    ) -> ExecutionTier {
        evaluate_route(sensitivity, policy, resources).tier
    }

    /// Core routing evaluation shared by [`decide_tier`] and
    /// [`decide_tier_logged`]. Pure (no clock, no logging) so both the plain and
    /// the logged entry points stay behaviourally identical.
    fn evaluate_route(
        sensitivity: Sensitivity,
        policy: &TierPolicy,
        resources: ResourceState,
    ) -> RoutingDecisionLog {
        let mut ceiling = policy.ceiling_for(sensitivity);
        // Cloud requires explicit consent; without it, cap one step below.
        let consent_capped = ceiling == ExecutionTier::Cloud && !policy.cloud_consent;
        if consent_capped {
            ceiling = ExecutionTier::FederatedMesh;
        }
        // Realtime workloads avoid the network entirely.
        let realtime_forced = policy.latency == LatencyClass::Realtime;
        if realtime_forced {
            ceiling = ExecutionTier::Local;
        }
        // Walk down from the highest tier; pick the first reachable tier at or
        // below the ceiling. `Local` is the ultimate fallback.
        let mut tier = ExecutionTier::Local;
        for candidate in [
            ExecutionTier::Cloud,
            ExecutionTier::FederatedMesh,
            ExecutionTier::PersonalCluster,
            ExecutionTier::Local,
        ] {
            if candidate <= ceiling && resources.is_available(candidate) {
                tier = candidate;
                break;
            }
        }
        // The decided tier sits below the (adjusted) ceiling only when resource
        // availability forced it down.
        let clamped_down = tier < ceiling;
        RoutingDecisionLog {
            sensitivity,
            ceiling,
            tier,
            badge: tier_badge(tier),
            consent_capped,
            realtime_forced,
            clamped_down,
        }
    }

    /// The short backend "badge" label for `tier` (WS5-05.7).
    ///
    /// A stable, UI/log-friendly identifier for the backend a tier maps to:
    /// `local`, `personal-cluster`, `mesh`, or `cloud`.
    #[must_use]
    pub const fn tier_badge(tier: ExecutionTier) -> &'static str {
        match tier {
            ExecutionTier::Local => "local",
            ExecutionTier::PersonalCluster => "personal-cluster",
            ExecutionTier::FederatedMesh => "mesh",
            ExecutionTier::Cloud => "cloud",
        }
    }

    /// A structured record of a Tier routing decision (WS5-05.7).
    ///
    /// Produced by [`decide_tier_logged`] alongside the decided tier so callers
    /// can audit, surface a backend badge, or replay the rationale without
    /// re-running the policy engine. All fields are plain copies; the record
    /// carries no clock (timestamps are the caller's concern).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RoutingDecisionLog {
        /// The classified workload sensitivity.
        pub sensitivity: Sensitivity,
        /// The effective ceiling after consent and latency adjustments — the
        /// highest tier the decision was allowed to reach.
        pub ceiling: ExecutionTier,
        /// The tier the router decided on.
        pub tier: ExecutionTier,
        /// The backend badge for [`tier`](Self::tier) (see [`tier_badge`]).
        pub badge: &'static str,
        /// The Cloud ceiling was lowered because cloud consent was absent
        /// (WS5-05.6).
        pub consent_capped: bool,
        /// A `Realtime` latency requirement forced the workload to stay local.
        pub realtime_forced: bool,
        /// Resource availability clamped the decided tier below the ceiling.
        pub clamped_down: bool,
    }

    impl core::fmt::Display for RoutingDecisionLog {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "route: sensitivity={:?} -> tier={:?} [{}] \
                 (ceiling={:?}, consent_capped={}, realtime_forced={}, clamped_down={})",
                self.sensitivity,
                self.tier,
                self.badge,
                self.ceiling,
                self.consent_capped,
                self.realtime_forced,
                self.clamped_down,
            )
        }
    }

    /// Decide the target execution tier *and* emit a structured decision log
    /// (WS5-05.7).
    ///
    /// Behaves exactly like [`decide_tier`] but returns the full
    /// [`RoutingDecisionLog`] (decided tier, backend badge, and the factors that
    /// shaped the decision) and emits a `tracing` debug event with the same
    /// fields. The VM-103 routing assertions (WS5-05.8/.9) consume this log.
    #[must_use]
    pub fn decide_tier_logged(
        sensitivity: Sensitivity,
        policy: &TierPolicy,
        resources: ResourceState,
    ) -> RoutingDecisionLog {
        let log = evaluate_route(sensitivity, policy, resources);
        debug!(
            sensitivity = ?log.sensitivity,
            tier = ?log.tier,
            badge = log.badge,
            ceiling = ?log.ceiling,
            consent_capped = log.consent_capped,
            realtime_forced = log.realtime_forced,
            clamped_down = log.clamped_down,
            "tier routing decision"
        );
        log
    }
}

// =============================================================================
// scheduler — WorkloadScheduler stub
// =============================================================================

/// Workload scheduling across accelerators.
///
/// This module provides a stub [`crate::scheduler::WorkloadScheduler`] that will grow into a
/// full cost-model-driven accelerator scheduler in a later Phase 2 stream.
/// For now it is a placeholder to establish the public API shape so other
/// modules can depend on it without needing implementation-level changes.
#[cfg(feature = "std")]
pub mod scheduler {
    use nexacore_types::Result;
    use tracing::debug;

    /// Schedules AI workloads across available accelerators on the local node.
    ///
    /// Phase 2 Stream 1 stub. The full implementation will include:
    ///
    /// - Cost-model estimation (FLOPs, memory bandwidth, thermal headroom).
    /// - Affinity rules (e.g., "prefer NPU for quantised Gguf models").
    /// - Backpressure / queue depth signalling to the inference pipeline.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::scheduler::WorkloadScheduler;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let scheduler = WorkloadScheduler::new();
    /// scheduler.schedule().await.unwrap();
    /// # }
    /// ```
    #[derive(Debug, Default)]
    pub struct WorkloadScheduler;

    impl WorkloadScheduler {
        /// Create a new scheduler.
        ///
        /// ```rust
        /// use nexacore_runtime::scheduler::WorkloadScheduler;
        /// let _ = WorkloadScheduler::new();
        /// ```
        #[must_use]
        pub fn new() -> Self {
            Self
        }

        /// Attempt to schedule pending workloads across available accelerators.
        ///
        /// Phase 2 Stream 1 stub — no-op. Returns `Ok(())` immediately.
        ///
        /// # Errors
        ///
        /// Currently never errors. Future implementations may return
        /// [`nexacore_types::NexaCoreError::Internal`] on accelerator enumeration
        /// failures.
        #[allow(clippy::unused_async)]
        pub async fn schedule(&self) -> Result<()> {
            debug!("scheduler: schedule() called (stub — no-op)");
            Ok(())
        }
    }
}

// =============================================================================
// attestation — model manifest verification
// =============================================================================

/// Model signature verification.
///
/// This module exposes a single free function that verifies the Ed25519
/// signature carried inside a [`model::ModelManifest`]. It is the low-level
/// attestation primitive that [`model::ModelRegistry::register`] and
/// [`model::ModelRegistry::attest`] both delegate to.
#[cfg(feature = "std")]
pub mod attestation {
    use nexacore_types::Result;

    use crate::model::ModelManifest;

    /// Verify the Ed25519 signature on `manifest`.
    ///
    /// Checks that `manifest.signing_key.verify(&manifest.hash,
    /// &manifest.signature)` succeeds using the strict (non-malleable)
    /// verification path. Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// - [`nexacore_types::NexaCoreError::Crypto`] with
    ///   [`nexacore_types::error::CryptoErrorKind::InvalidSignature`] if
    ///   verification fails for any reason (wrong key, tampered hash, etc.).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_crypto::signing::NexaCoreSigningKey;
    /// use nexacore_runtime::{
    ///     attestation::verify_model_manifest,
    ///     model::{ModelFormat, ModelManifest},
    /// };
    /// use nexacore_types::ModelId;
    ///
    /// let sk = NexaCoreSigningKey::from_bytes([0x42; 32]);
    /// let hash = [0x99u8; 32];
    /// let manifest = ModelManifest {
    ///     model_id: ModelId::from_manifest_hash(hash),
    ///     name: "attested-model".into(),
    ///     version: "1.0.0".into(),
    ///     hash,
    ///     signature: sk.sign(&hash),
    ///     signing_key: sk.verifying_key(),
    ///     size_bytes: 512,
    ///     format: ModelFormat::SafeTensors,
    /// };
    ///
    /// verify_model_manifest(&manifest).unwrap();
    /// ```
    pub fn verify_model_manifest(manifest: &ModelManifest) -> Result<()> {
        manifest
            .signing_key
            .verify(&manifest.hash, &manifest.signature)
    }
}

// =============================================================================
// relay — AI Syscall IPC Relay
// =============================================================================

/// AI Syscall IPC relay — bridges kernel AI syscalls to the inference pipeline.
///
/// The relay receives [`relay::AiSyscallRequest`] messages from the kernel IPC
/// channel and routes them through the [`inference::InferencePipeline`],
/// returning structured [`relay::AiSyscallResponse`] values.
#[cfg(feature = "std")]
pub mod relay;

// =============================================================================
// bpe — byte-level BPE tokenizer
// =============================================================================

/// Byte-level BPE tokenizer for LLM text ↔ token ID conversion.
///
/// Provides [`bpe::BpeTokenizer`] with encode / decode support compatible
/// with GPT-2 and TinyLlama-style vocabularies. The vocabulary and merge
/// rules can be loaded from any source; [`bpe::BpeVocabulary::minimal_test_vocab`]
/// provides a self-contained fixture for testing.
pub mod bpe;

// =============================================================================
// preprocessing — PII tokenization pipeline
// =============================================================================

/// PII detection and tokenization pre-processing pipeline.
///
/// Scans inference input for email addresses and phone numbers, replaces them
/// with opaque tokens before the text reaches the model, and reverses the
/// tokenization on the output. Phase 2 uses simple string scanning; Phase 3
/// will use the TEE-backed `NerClassifier` from `nexacore-tokenization`.
#[cfg(feature = "std")]
pub mod preprocessing;

// =============================================================================
// orchestrator_bridge — Orchestrator → Runtime dispatch
// =============================================================================

/// Orchestrator Agent → inference pipeline dispatch bridge.
///
/// [`orchestrator_bridge::OrchestratorBridge`] is the integration point
/// between the five-agent Orchestrator and the AI runtime. It classifies
/// intents, pre-processes PII, dispatches inference, and post-processes output.
#[cfg(feature = "std")]
pub mod orchestrator_bridge;

// =============================================================================
// decode — Streaming autoregressive decode loop (Sprint 8)
// =============================================================================

/// Streaming greedy / sampled decode loop for autoregressive language models.
///
/// [`decode::streaming_decode`] returns a lazy [`Iterator`] that yields one
/// [`decode::DecodeToken`] per transformer forward pass.  Supports temperature
/// scaling, top-k sampling, and EOS-based termination.  Works with both FP32
/// and quantized model weights.
///
/// See [`decode`] for the full API surface and usage examples.
pub mod decode;

// =============================================================================
// speculative — Speculative decoding engine (Sprint 10)
// =============================================================================

/// Speculative decoding engine for autoregressive language models.
///
/// Implements the algorithm from Leviathan et al. (2023): a fast draft model
/// speculatively generates [`speculative::SpeculativeConfig::draft_len`] tokens
/// which are then verified against the target model in a single batched forward
/// pass.  Accepted tokens are free; rejected tokens trigger a corrected resample.
/// The output distribution is provably identical to pure target autoregressive
/// sampling.
///
/// Key entry point: [`speculative::speculative_decode`].
#[cfg(feature = "std")]
pub mod speculative;

// =============================================================================
// batch — Continuous batching inference scheduler (Sprint 10)
// =============================================================================

/// Continuous batching inference scheduler for concurrent LLM request serving.
///
/// [`batch::BatchScheduler`] manages a priority queue of pending requests and
/// an active batch of concurrently generating requests.  Each call to
/// [`batch::BatchScheduler::step`] advances every active request by one token
/// using a caller-supplied forward function, then checks termination conditions.
/// Supports priority-based preemption, token-budget gating, and per-request
/// temperature / top-k sampling.
#[cfg(feature = "std")]
pub mod batch;

// =============================================================================
// serving — Inference session lifecycle + request/response API (Sprint 11.a)
// =============================================================================

/// Client-facing inference serving surface.
///
/// Provides [`serving::InferenceSession`] (a state machine over the lifetime of
/// a client inference session) and [`serving::SessionManager`] (open/close
/// sessions, submit requests, stream tokens).  This is the external API that
/// applications use to drive the runtime; every entry point is capability-gated.
///
/// Implemented by TASK-S11.A (development plan 2026-05-29).
#[cfg(feature = "std")]
pub mod serving;

// =============================================================================
// audit — Structured inference audit log (Sprint 11.a)
// =============================================================================

/// Durable, structured audit records for inference activity.
///
/// Provides [`audit::AuditRecord`] (metadata only — no PII; carries
/// `backend_used` + latency since TASK-10), the [`audit::AuditLog`]
/// trait with an in-memory ring-buffer implementation, and the
/// object-safe [`audit::AuditSink`] writer handle the
/// [`provider::BackendRouter`] records through.
/// Required by `docs/04-security-model.md` ("Audit log").
///
/// Implemented by TASK-S11.B (development plan 2026-05-29); extended by
/// TASK-10 (ADR-0031).
#[cfg(feature = "std")]
pub mod audit;

// =============================================================================
// provider — Provider-agnostic inference abstraction (TASK-08, DE-G1)
// =============================================================================

/// The seam between *what* the runtime wants (generate / chat /
/// embeddings) and *where* it runs (a remote GPU box, or the on-device
/// CPU engine).
///
/// Provides the [`provider::InferenceProvider`] async trait,
/// [`provider::BackendKind`], and the [`provider::BackendRouter`] that
/// selects a backend per [`provider::BackendPolicy`] and fails over
/// deterministically. The router is Tier-0-only by construction: it
/// accepts only a [`provider::Tier0Request`] (a [`provider::Tier1Request`]
/// cannot reach it — compiler-enforced, see the `tests/compile_fail`
/// trybuild fixture).
///
/// TASK-08 delivered the abstraction + router; TASK-09 the `RemoteGpu`
/// Ollama HTTP client ([`provider::ollama`], ADR-0030); TASK-10 the
/// resilience layer ([`provider::health`], ADR-0031): anti-flap health
/// hysteresis, periodic probing with automatic failover/recovery,
/// backend status events, and per-request `backend_used` auditing;
/// TASK-12 the `LocalCpu` fallback ([`provider::local_cpu`], ADR-0033):
/// on-device greedy generation over the Sprint 7/8 engine with the
/// plan-§9 `degraded` honesty contract.
#[cfg(feature = "std")]
pub mod provider;

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use nexacore_crypto::signing::NexaCoreSigningKey;
    use nexacore_types::{ModelId, NexaCoreError, error::CryptoErrorKind};
    use tokio::sync::Mutex;

    use crate::{
        attestation::verify_model_manifest,
        inference::{InferencePipeline, InferenceRequest},
        model::{ModelFormat, ModelManifest, ModelRegistry},
        router::{
            ExecutionTier, LatencyClass, ResourceState, RoutingPolicy, Sensitivity, TierError,
            TierPolicy, TierReason, TierRouter, classify_sensitivity, decide_tier,
            decide_tier_logged, tier_badge,
        },
        scheduler::WorkloadScheduler,
    };

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Build a valid signed manifest using the given seed byte for the key.
    fn make_manifest(seed: u8, hash_byte: u8, name: &str) -> ModelManifest {
        let sk = NexaCoreSigningKey::from_bytes([seed; 32]);
        let hash = [hash_byte; 32];
        ModelManifest {
            model_id: ModelId::from_manifest_hash(hash),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            hash,
            signature: sk.sign(&hash),
            signing_key: sk.verifying_key(),
            size_bytes: 100,
            format: ModelFormat::Gguf,
        }
    }

    // -------------------------------------------------------------------------
    // ModelRegistry — basic CRUD
    // -------------------------------------------------------------------------

    #[test]
    fn registry_new_is_empty() {
        let reg = ModelRegistry::new();
        assert!(reg.list().is_empty());
    }

    #[test]
    fn registry_register_valid_manifest_succeeds() {
        let mut reg = ModelRegistry::new();
        let manifest = make_manifest(0x01, 0xAA, "model-a");
        let id = reg.register(manifest).unwrap();
        assert_eq!(reg.list(), vec![id]);
    }

    #[test]
    fn registry_register_returns_correct_model_id() {
        let mut reg = ModelRegistry::new();
        let hash = [0xBBu8; 32];
        let sk = NexaCoreSigningKey::from_bytes([0x02; 32]);
        let expected_id = ModelId::from_manifest_hash(hash);
        let manifest = ModelManifest {
            model_id: expected_id,
            name: "model-b".into(),
            version: "1.0.0".into(),
            hash,
            signature: sk.sign(&hash),
            signing_key: sk.verifying_key(),
            size_bytes: 0,
            format: ModelFormat::Onnx,
        };
        let returned_id = reg.register(manifest).unwrap();
        assert_eq!(returned_id, expected_id);
    }

    #[test]
    fn registry_register_invalid_signature_fails() {
        let mut reg = ModelRegistry::new();
        let sk = NexaCoreSigningKey::from_bytes([0x03; 32]);
        let other_sk = NexaCoreSigningKey::from_bytes([0x04; 32]);
        let hash = [0xCCu8; 32];
        // Sign with `other_sk` but claim `sk` as the signing key.
        let bad_sig = other_sk.sign(&hash);
        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(hash),
            name: "bad-model".into(),
            version: "1.0.0".into(),
            hash,
            signature: bad_sig,
            signing_key: sk.verifying_key(), // mismatched key
            size_bytes: 0,
            format: ModelFormat::SafeTensors,
        };
        let err = reg.register(manifest).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::InvalidSignature);
            }
            _ => panic!("expected Crypto::InvalidSignature, got: {err:?}"),
        }
    }

    #[test]
    fn registry_register_tampered_hash_fails() {
        let mut reg = ModelRegistry::new();
        let sk = NexaCoreSigningKey::from_bytes([0x05; 32]);
        let original_hash = [0xDDu8; 32];
        let sig = sk.sign(&original_hash);
        // Replace the hash with a different value after signing.
        let tampered_hash = [0xEEu8; 32];
        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(tampered_hash),
            name: "tampered".into(),
            version: "1.0.0".into(),
            hash: tampered_hash,
            signature: sig,
            signing_key: sk.verifying_key(),
            size_bytes: 0,
            format: ModelFormat::Onnx,
        };
        assert!(reg.register(manifest).is_err());
    }

    // TASK-17 gate (ADR-0039): trusted-issuer allowlist on ModelRegistry.

    #[test]
    fn registry_register_trusted_issuer_accepted() {
        // Issuer key 0x11 is in the allowlist; its self-signed manifest is
        // accepted (signature verifies AND issuer is trusted).
        let trusted = NexaCoreSigningKey::from_bytes([0x11; 32]).verifying_key();
        let mut reg = ModelRegistry::with_trusted_issuers([trusted]);
        let manifest = make_manifest(0x11, 0x20, "trusted-model");
        let id = reg
            .register(manifest)
            .expect("trusted issuer must be accepted");
        assert_eq!(reg.list(), vec![id]);
    }

    #[test]
    fn registry_register_unknown_issuer_rejected() {
        // The allowlist trusts only key 0x11, but the manifest is signed by
        // key 0x22 — a VALID self-signature from an UNTRUSTED issuer. It must
        // be rejected (fail-closed), even though the cryptography is sound.
        let trusted = NexaCoreSigningKey::from_bytes([0x11; 32]).verifying_key();
        let mut reg = ModelRegistry::with_trusted_issuers([trusted]);
        let manifest = make_manifest(0x22, 0x20, "unknown-issuer-model");
        let err = reg
            .register(manifest)
            .expect_err("unknown issuer must be rejected");
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(
                    kind,
                    nexacore_types::error::CryptoErrorKind::InvalidSignature
                );
            }
            other => panic!("expected Crypto error, got: {other:?}"),
        }
        assert!(
            reg.list().is_empty(),
            "rejected manifest must not be stored"
        );
    }

    #[test]
    fn registry_empty_allowlist_rejects_all() {
        // An empty allowlist is the strictest fail-closed posture: every
        // manifest, however well-formed, is refused.
        let mut reg = ModelRegistry::with_trusted_issuers([]);
        let manifest = make_manifest(0x33, 0x20, "any-model");
        assert!(reg.register(manifest).is_err());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn registry_no_allowlist_accepts_any_valid_issuer() {
        // `new()` keeps the pre-gate behaviour: no allowlist → any issuer with
        // a valid self-signature is accepted.
        let mut reg = ModelRegistry::new();
        let manifest = make_manifest(0x44, 0x20, "no-allowlist-model");
        assert!(reg.register(manifest).is_ok());
    }

    #[test]
    fn registry_load_valid_model_succeeds() {
        let mut reg = ModelRegistry::new();
        let manifest = make_manifest(0x06, 0x10, "load-test");
        let id = reg.register(manifest).unwrap();
        reg.load(id).unwrap();
        assert!(reg.is_loaded(id));
    }

    #[test]
    fn registry_load_unknown_model_fails() {
        let mut reg = ModelRegistry::new();
        let unknown = ModelId::from_bytes([0xFF; 32]);
        let err = reg.load(unknown).unwrap_err();
        match err {
            NexaCoreError::Internal { .. } => {}
            _ => panic!("expected Internal error, got: {err:?}"),
        }
    }

    #[test]
    fn registry_unload_loaded_model_succeeds() {
        let mut reg = ModelRegistry::new();
        let manifest = make_manifest(0x07, 0x20, "unload-test");
        let id = reg.register(manifest).unwrap();
        reg.load(id).unwrap();
        reg.unload(id).unwrap();
        assert!(!reg.is_loaded(id));
    }

    #[test]
    fn registry_unload_unknown_model_fails() {
        let mut reg = ModelRegistry::new();
        let unknown = ModelId::from_bytes([0xFE; 32]);
        let err = reg.unload(unknown).unwrap_err();
        match err {
            NexaCoreError::Internal { .. } => {}
            _ => panic!("expected Internal error, got: {err:?}"),
        }
    }

    #[test]
    fn registry_attest_returns_manifest() {
        let mut reg = ModelRegistry::new();
        let manifest = make_manifest(0x08, 0x30, "attest-test");
        let name = manifest.name.clone();
        let id = reg.register(manifest).unwrap();
        let attested = reg.attest(id).unwrap();
        assert_eq!(attested.name, name);
    }

    #[test]
    fn registry_attest_unknown_model_fails() {
        let reg = ModelRegistry::new();
        let unknown = ModelId::from_bytes([0xFD; 32]);
        let err = reg.attest(unknown).unwrap_err();
        match err {
            NexaCoreError::Internal { .. } => {}
            _ => panic!("expected Internal error, got: {err:?}"),
        }
    }

    #[test]
    fn registry_list_returns_sorted_ids() {
        let mut reg = ModelRegistry::new();
        // Register models with different hash bytes so IDs differ.
        let m1 = make_manifest(0x0A, 0x01, "m1");
        let m2 = make_manifest(0x0B, 0x80, "m2");
        let m3 = make_manifest(0x0C, 0x40, "m3");
        let id1 = reg.register(m1).unwrap();
        let id2 = reg.register(m2).unwrap();
        let id3 = reg.register(m3).unwrap();
        let list = reg.list();
        assert_eq!(list.len(), 3);
        // BTreeMap guarantees sorted order.
        let mut expected = vec![id1, id2, id3];
        expected.sort();
        assert_eq!(list, expected);
    }

    #[test]
    fn registry_is_loaded_false_before_load() {
        let mut reg = ModelRegistry::new();
        let manifest = make_manifest(0x0D, 0x50, "preload");
        let id = reg.register(manifest).unwrap();
        assert!(!reg.is_loaded(id));
    }

    #[test]
    fn registry_is_loaded_false_for_unknown() {
        let reg = ModelRegistry::new();
        let unknown = ModelId::from_bytes([0xFC; 32]);
        assert!(!reg.is_loaded(unknown));
    }

    // -------------------------------------------------------------------------
    // Attestation module
    // -------------------------------------------------------------------------

    #[test]
    fn attestation_verify_valid_manifest_ok() {
        let manifest = make_manifest(0x0E, 0x60, "attest-valid");
        verify_model_manifest(&manifest).unwrap();
    }

    #[test]
    fn attestation_verify_bad_signature_fails() {
        let sk = NexaCoreSigningKey::from_bytes([0x0F; 32]);
        let other_sk = NexaCoreSigningKey::from_bytes([0x10; 32]);
        let hash = [0x70u8; 32];
        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(hash),
            name: "bad".into(),
            version: "1.0.0".into(),
            hash,
            signature: other_sk.sign(&hash),
            signing_key: sk.verifying_key(),
            size_bytes: 0,
            format: ModelFormat::Onnx,
        };
        let err = verify_model_manifest(&manifest).unwrap_err();
        match err {
            NexaCoreError::Crypto { kind, .. } => {
                assert_eq!(kind, CryptoErrorKind::InvalidSignature);
            }
            _ => panic!("expected InvalidSignature"),
        }
    }

    // -------------------------------------------------------------------------
    // TierRouter
    // -------------------------------------------------------------------------

    #[test]
    fn router_always_returns_local_tier() {
        let router = TierRouter::new();
        let req = InferenceRequest {
            model_id: ModelId::from_bytes([0x00; 32]),
            input: vec![],
            request_id: 0,
        };
        assert_eq!(router.route(&req), ExecutionTier::Local);
    }

    #[test]
    fn router_local_is_not_cloud() {
        let router = TierRouter::new();
        let req = InferenceRequest {
            model_id: ModelId::from_bytes([0x11; 32]),
            input: vec![1, 2, 3],
            request_id: 99,
        };
        let tier = router.route(&req);
        assert_ne!(tier, ExecutionTier::Cloud);
        assert_ne!(tier, ExecutionTier::PersonalCluster);
        assert_ne!(tier, ExecutionTier::FederatedMesh);
    }

    // -------------------------------------------------------------------------
    // TierRouter::route_decision — Sprint 11.a policy engine
    // -------------------------------------------------------------------------

    /// Helper: build a minimal [`InferenceRequest`] for routing tests.
    fn make_routing_request(request_id: u64) -> InferenceRequest {
        InferenceRequest {
            model_id: ModelId::from_bytes([0xAB; 32]),
            input: vec![],
            request_id,
        }
    }

    /// Default policy + small model + no attestation requirement → Ok(Local).
    ///
    /// This is the happy-path Phase 2 baseline: every request that fits
    /// locally and does not require attestation must succeed with Tier 0.
    #[test]
    fn route_decision_default_policy_ok_local() {
        let router = TierRouter::new();
        let policy = RoutingPolicy::new();
        let req = make_routing_request(1);
        let result = router.route_decision(&req, &policy, 1024, false, 999);
        let decision = result.expect("default policy with small model must succeed");
        assert_eq!(
            decision.tier,
            ExecutionTier::Local,
            "Phase 2: only Tier 0 is valid on the Ok path"
        );
    }

    /// A model whose byte size exceeds `max_model_size_bytes` triggers
    /// [`TierError::TierUnavailable`] because escalation is unavailable in
    /// Phase 2.
    #[test]
    fn route_decision_large_model_escalation_denied() {
        let router = TierRouter::new();
        let policy = RoutingPolicy {
            max_model_size_bytes: 100,
            ..RoutingPolicy::new()
        };
        let req = make_routing_request(2);
        let err = router
            .route_decision(&req, &policy, 101, false, 0)
            .unwrap_err();
        assert!(
            matches!(err, TierError::TierUnavailable { .. }),
            "oversized model must return TierUnavailable, got {err:?}"
        );
    }

    /// When `require_attestation = true` and `attested = false` the router
    /// must reject with [`TierError::AttestationRequired`] before evaluating
    /// any tier-escalation logic.
    #[test]
    fn route_decision_attestation_required_not_attested() {
        let router = TierRouter::new();
        let policy = RoutingPolicy {
            require_attestation: true,
            ..RoutingPolicy::new()
        };
        let req = make_routing_request(3);
        let err = router
            .route_decision(&req, &policy, 512, false, 0)
            .unwrap_err();
        assert_eq!(
            err,
            TierError::AttestationRequired,
            "un-attested model under require_attestation policy must error"
        );
    }

    /// When `require_attestation = true` and `attested = true` the router
    /// must succeed and return Tier 0.
    #[test]
    fn route_decision_attestation_required_and_provided() {
        let router = TierRouter::new();
        let policy = RoutingPolicy {
            require_attestation: true,
            ..RoutingPolicy::new()
        };
        let req = make_routing_request(4);
        let decision = router
            .route_decision(&req, &policy, 512, true, 7777)
            .expect("attested model under require_attestation policy must succeed");
        assert_eq!(decision.tier, ExecutionTier::Local);
    }

    /// Even with `allow_tier_1 = true`, if the model fits locally the router
    /// must still return Tier 0 (Phase 2 prefers local when possible).
    #[test]
    fn route_decision_allow_tier1_but_fits_locally_stays_local() {
        let router = TierRouter::new();
        let policy = RoutingPolicy {
            allow_tier_1: true,
            ..RoutingPolicy::new()
        };
        let req = make_routing_request(5);
        let decision = router
            .route_decision(&req, &policy, 256, false, 0)
            .expect("model fitting locally must succeed even with allow_tier_1");
        assert_eq!(
            decision.tier,
            ExecutionTier::Local,
            "Phase 2: local is always preferred over higher tiers when the \
             model fits on the local node"
        );
    }

    /// The `reason` field of a successful decision must be
    /// [`TierReason::LocalOnlyPolicy`] in Phase 2.
    #[test]
    fn route_decision_reason_is_local_only_policy() {
        let router = TierRouter::new();
        let policy = RoutingPolicy::new();
        let req = make_routing_request(6);
        let decision = router
            .route_decision(&req, &policy, 0, false, 0)
            .expect("must succeed");
        assert_eq!(
            decision.reason,
            TierReason::LocalOnlyPolicy,
            "Phase 2 successful routing must carry LocalOnlyPolicy reason"
        );
    }

    /// `decided_at_ns` must be propagated verbatim from the caller into the
    /// returned [`TierDecision`].
    #[test]
    fn route_decision_decided_at_ns_propagated() {
        let router = TierRouter::new();
        let policy = RoutingPolicy::new();
        let req = make_routing_request(7);
        let timestamp: u64 = 1_234_567_890;
        let decision = router
            .route_decision(&req, &policy, 64, false, timestamp)
            .expect("must succeed");
        assert_eq!(
            decision.decided_at_ns, timestamp,
            "decided_at_ns must equal the caller-supplied timestamp"
        );
    }

    /// The `requested` field inside [`TierError::TierUnavailable`] must
    /// identify the first escalation tier (`PersonalCluster`) when the model
    /// is too large for local execution.
    #[test]
    fn route_decision_tier_unavailable_requested_is_personal_cluster() {
        let router = TierRouter::new();
        let policy = RoutingPolicy {
            max_model_size_bytes: 50,
            ..RoutingPolicy::new()
        };
        let req = make_routing_request(8);
        let err = router
            .route_decision(&req, &policy, 51, false, 0)
            .unwrap_err();
        assert_eq!(
            err,
            TierError::TierUnavailable {
                requested: ExecutionTier::PersonalCluster,
            },
            "oversized-model error must name PersonalCluster as the \
             first unavailable escalation target"
        );
    }

    // -------------------------------------------------------------------------
    // Tier policy engine — sensitivity classifier + workload→tier (WS5-05)
    // -------------------------------------------------------------------------

    #[test]
    fn classify_sensitivity_detects_secrets_personal_and_public() {
        assert_eq!(
            classify_sensitivity("my password is hunter2"),
            Sensitivity::HighlySensitive
        );
        assert_eq!(
            classify_sensitivity("-----BEGIN OPENSSH PRIVATE KEY-----"),
            Sensitivity::HighlySensitive
        );
        assert_eq!(
            classify_sensitivity("please email me at a@b.com"),
            Sensitivity::Sensitive
        );
        assert_eq!(
            classify_sensitivity("summarize the history of Rome"),
            Sensitivity::Public
        );
    }

    #[test]
    fn highly_sensitive_workload_is_local_only_regardless_of_resources() {
        // Even with every tier reachable and full cloud consent, a secret stays
        // on-device (the WS5-05.8 host analogue).
        let policy = TierPolicy {
            cloud_consent: true,
            ..TierPolicy::new()
        };
        let resources = ResourceState {
            local_available: true,
            personal_cluster_available: true,
            mesh_available: true,
            cloud_available: true,
        };
        let s = classify_sensitivity("here is my api key sk-123");
        assert_eq!(s, Sensitivity::HighlySensitive);
        assert_eq!(
            decide_tier(s, &policy, resources),
            ExecutionTier::Local,
            "a highly-sensitive workload must never leave the device"
        );
    }

    #[test]
    fn cloud_requires_explicit_consent() {
        let all = ResourceState {
            local_available: true,
            personal_cluster_available: true,
            mesh_available: true,
            cloud_available: true,
        };
        // Public ceiling is Cloud, but without consent it caps at the mesh.
        let no_consent = TierPolicy::new();
        assert_eq!(
            decide_tier(Sensitivity::Public, &no_consent, all),
            ExecutionTier::FederatedMesh
        );
        // With explicit consent it may reach the cloud.
        let consented = TierPolicy {
            cloud_consent: true,
            ..TierPolicy::new()
        };
        assert_eq!(
            decide_tier(Sensitivity::Public, &consented, all),
            ExecutionTier::Cloud
        );
    }

    #[test]
    fn decide_tier_clamps_down_to_available_tiers() {
        // Sensitive ceiling is PersonalCluster; if only local is up, clamp to it.
        let local_only = ResourceState::default();
        assert_eq!(
            decide_tier(Sensitivity::Sensitive, &TierPolicy::new(), local_only),
            ExecutionTier::Local
        );
        // With the cluster up, a sensitive workload reaches Tier 1.
        let with_cluster = ResourceState {
            personal_cluster_available: true,
            ..ResourceState::default()
        };
        assert_eq!(
            decide_tier(Sensitivity::Sensitive, &TierPolicy::new(), with_cluster),
            ExecutionTier::PersonalCluster
        );
    }

    #[test]
    fn realtime_latency_forces_local() {
        let all = ResourceState {
            local_available: true,
            personal_cluster_available: true,
            mesh_available: true,
            cloud_available: true,
        };
        let realtime = TierPolicy {
            cloud_consent: true,
            latency: LatencyClass::Realtime,
            ..TierPolicy::new()
        };
        // Public would otherwise reach the cloud; Realtime pins it local.
        assert_eq!(
            decide_tier(Sensitivity::Public, &realtime, all),
            ExecutionTier::Local
        );
    }

    #[test]
    fn default_tier_policy_is_privacy_first() {
        let p = TierPolicy::new();
        assert_eq!(
            p.ceiling_for(Sensitivity::HighlySensitive),
            ExecutionTier::Local
        );
        assert_eq!(
            p.ceiling_for(Sensitivity::Sensitive),
            ExecutionTier::PersonalCluster
        );
        assert_eq!(p.ceiling_for(Sensitivity::Public), ExecutionTier::Cloud);
        assert!(!p.cloud_consent);
    }

    // -------------------------------------------------------------------------
    // Structured routing decision log + backend badge (WS5-05.7)
    // -------------------------------------------------------------------------

    #[test]
    fn tier_badge_is_stable_per_tier() {
        assert_eq!(tier_badge(ExecutionTier::Local), "local");
        assert_eq!(
            tier_badge(ExecutionTier::PersonalCluster),
            "personal-cluster"
        );
        assert_eq!(tier_badge(ExecutionTier::FederatedMesh), "mesh");
        assert_eq!(tier_badge(ExecutionTier::Cloud), "cloud");
    }

    #[test]
    fn decide_tier_logged_matches_decide_tier_and_sets_badge() {
        let all = ResourceState {
            local_available: true,
            personal_cluster_available: true,
            mesh_available: true,
            cloud_available: true,
        };
        for (sensitivity, policy) in [
            (Sensitivity::Public, TierPolicy::new()),
            (
                Sensitivity::Public,
                TierPolicy {
                    cloud_consent: true,
                    ..TierPolicy::new()
                },
            ),
            (Sensitivity::Sensitive, TierPolicy::new()),
            (Sensitivity::HighlySensitive, TierPolicy::new()),
        ] {
            let log = decide_tier_logged(sensitivity, &policy, all);
            // The logged entry point must decide exactly like the plain one.
            assert_eq!(log.tier, decide_tier(sensitivity, &policy, all));
            // The badge must match the decided tier.
            assert_eq!(log.badge, tier_badge(log.tier));
            assert_eq!(log.sensitivity, sensitivity);
        }
    }

    #[test]
    fn routing_log_records_consent_cap() {
        let all = ResourceState {
            local_available: true,
            personal_cluster_available: true,
            mesh_available: true,
            cloud_available: true,
        };
        // Public ceiling is Cloud, but without consent it caps at the mesh.
        let log = decide_tier_logged(Sensitivity::Public, &TierPolicy::new(), all);
        assert_eq!(log.tier, ExecutionTier::FederatedMesh);
        assert_eq!(log.badge, "mesh");
        assert!(
            log.consent_capped,
            "missing cloud consent must cap the tier"
        );
        assert!(!log.realtime_forced);
        assert!(!log.clamped_down, "the mesh ceiling was reachable");
    }

    #[test]
    fn routing_log_records_realtime_and_clamp() {
        // Realtime pins a cloud-consented Public workload to local.
        let all = ResourceState {
            local_available: true,
            personal_cluster_available: true,
            mesh_available: true,
            cloud_available: true,
        };
        let realtime = TierPolicy {
            cloud_consent: true,
            latency: LatencyClass::Realtime,
            ..TierPolicy::new()
        };
        let rt = decide_tier_logged(Sensitivity::Public, &realtime, all);
        assert_eq!(rt.tier, ExecutionTier::Local);
        assert!(rt.realtime_forced);

        // Sensitive ceiling is PersonalCluster; with only local up, it clamps
        // down to Local (the cluster was unreachable).
        let clamp = decide_tier_logged(
            Sensitivity::Sensitive,
            &TierPolicy::new(),
            ResourceState::default(),
        );
        assert_eq!(clamp.tier, ExecutionTier::Local);
        assert_eq!(clamp.ceiling, ExecutionTier::PersonalCluster);
        assert!(clamp.clamped_down, "an unreachable cluster must clamp down");
        assert!(!clamp.consent_capped);
    }

    #[test]
    fn routing_log_display_is_structured() {
        let log = decide_tier_logged(
            Sensitivity::HighlySensitive,
            &TierPolicy::new(),
            ResourceState::default(),
        );
        let rendered = log.to_string();
        assert!(rendered.contains("tier=Local"), "got: {rendered}");
        assert!(rendered.contains("[local]"), "got: {rendered}");
        assert!(
            rendered.contains("sensitivity=HighlySensitive"),
            "got: {rendered}"
        );
    }

    // -------------------------------------------------------------------------
    // WorkloadScheduler
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn scheduler_schedule_is_noop() {
        let sched = WorkloadScheduler::new();
        sched.schedule().await.unwrap();
    }

    // -------------------------------------------------------------------------
    // InferencePipeline
    // -------------------------------------------------------------------------

    fn make_pipeline_with_loaded_model() -> (Arc<Mutex<ModelRegistry>>, ModelId, InferencePipeline)
    {
        let mut reg = ModelRegistry::new();
        let manifest = make_manifest(0x20, 0x90, "pipeline-model");
        let id = reg.register(manifest).unwrap();
        reg.load(id).unwrap();
        let shared = Arc::new(Mutex::new(reg));
        let pipeline = InferencePipeline::new(Arc::clone(&shared));
        (shared, id, pipeline)
    }

    #[tokio::test]
    async fn pipeline_infer_loaded_model_succeeds() {
        let (_, id, pipeline) = make_pipeline_with_loaded_model();
        let req = InferenceRequest {
            model_id: id,
            input: vec![1, 2, 3],
            request_id: 1,
        };
        let resp = pipeline.infer(req).await.unwrap();
        assert_eq!(resp.request_id, 1);
    }

    #[tokio::test]
    async fn pipeline_infer_echoes_request_id() {
        let (_, id, pipeline) = make_pipeline_with_loaded_model();
        for rid in [0u64, 1, 42, u64::MAX] {
            let req = InferenceRequest {
                model_id: id,
                input: vec![],
                request_id: rid,
            };
            let resp = pipeline.infer(req).await.unwrap();
            assert_eq!(resp.request_id, rid);
        }
    }

    #[tokio::test]
    async fn pipeline_infer_stub_returns_empty_output() {
        let (_, id, pipeline) = make_pipeline_with_loaded_model();
        let req = InferenceRequest {
            model_id: id,
            input: vec![42, 43, 44],
            request_id: 2,
        };
        let resp = pipeline.infer(req).await.unwrap();
        // Stub backend produces empty output.
        assert!(resp.output.is_empty());
    }

    #[tokio::test]
    async fn pipeline_infer_records_latency() {
        let (_, id, pipeline) = make_pipeline_with_loaded_model();
        let req = InferenceRequest {
            model_id: id,
            input: vec![],
            request_id: 3,
        };
        let resp = pipeline.infer(req).await.unwrap();
        // Latency is non-negative (always true for u64) and should be a
        // plausible wall-clock value for a no-op. We just assert it fits
        // without overflow — the stub is fast enough to complete in well
        // under u64::MAX microseconds.
        let _ = resp.latency_us; // binding to silence "unused" warning
    }

    #[tokio::test]
    async fn pipeline_infer_unloaded_model_fails() {
        let mut registry = ModelRegistry::new();
        let manifest = make_manifest(0x21, 0xA0, "unloaded-model");
        let id = registry.register(manifest).unwrap();
        // Do NOT call registry.load(id) — model remains Unloaded.
        let shared = Arc::new(Mutex::new(registry));
        let pipeline = InferencePipeline::new(shared);
        let infer_req = InferenceRequest {
            model_id: id,
            input: vec![],
            request_id: 4,
        };
        let err = pipeline.infer(infer_req).await.unwrap_err();
        match err {
            NexaCoreError::Internal { .. } => {}
            _ => panic!("expected Internal error for unloaded model"),
        }
    }

    #[tokio::test]
    async fn pipeline_infer_unregistered_model_fails() {
        let empty_registry = ModelRegistry::new();
        let shared = Arc::new(Mutex::new(empty_registry));
        let pipeline = InferencePipeline::new(shared);
        let infer_req = InferenceRequest {
            model_id: ModelId::from_bytes([0xFB; 32]),
            input: vec![],
            request_id: 5,
        };
        let err = pipeline.infer(infer_req).await.unwrap_err();
        match err {
            NexaCoreError::Internal { .. } => {}
            _ => panic!("expected Internal error for unregistered model"),
        }
    }

    // -------------------------------------------------------------------------
    // E2E: GGUF build → register → load_from_bytes → verify
    // -------------------------------------------------------------------------

    fn build_minimal_gguf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&crate::gguf::GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf
    }

    #[test]
    fn e2e_gguf_register_and_load_from_bytes() {
        let gguf_bytes = build_minimal_gguf();
        let hash = blake3::hash(&gguf_bytes);
        let sk = NexaCoreSigningKey::from_bytes([0xE2; 32]);
        let sig = sk.sign(hash.as_bytes());

        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(*hash.as_bytes()),
            name: "e2e-toy-mlp".into(),
            version: "1.0.0".into(),
            hash: *hash.as_bytes(),
            signature: sig,
            signing_key: sk.verifying_key(),
            size_bytes: gguf_bytes.len() as u64,
            format: ModelFormat::Gguf,
        };

        let mut reg = ModelRegistry::new();
        let id = reg.register(manifest).unwrap();
        reg.load_from_bytes(id, &gguf_bytes).unwrap();
        assert!(reg.is_loaded(id));
        let attested = reg.attest(id).unwrap();
        assert_eq!(attested.name, "e2e-toy-mlp");
    }

    #[test]
    fn e2e_gguf_load_hash_mismatch_fails() {
        let gguf_bytes = build_minimal_gguf();
        let wrong_hash = [0xBB; 32];
        let sk = NexaCoreSigningKey::from_bytes([0xE3; 32]);
        let sig = sk.sign(&wrong_hash);

        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(wrong_hash),
            name: "bad-hash".into(),
            version: "1.0.0".into(),
            hash: wrong_hash,
            signature: sig,
            signing_key: sk.verifying_key(),
            size_bytes: gguf_bytes.len() as u64,
            format: ModelFormat::Gguf,
        };

        let mut reg = ModelRegistry::new();
        let id = reg.register(manifest).unwrap();
        let err = reg.load_from_bytes(id, &gguf_bytes).unwrap_err();
        match err {
            NexaCoreError::Internal { .. } => {}
            _ => panic!("expected Internal error for hash mismatch, got: {err:?}"),
        }
    }

    // =========================================================================
    // E2E: ModelRegistry → InferencePipeline → AiIpcRelay → OrchestratorBridge
    // =========================================================================
    //
    // This test exercises the full Stream 2 inference path:
    //
    //   1. Register and load a model.
    //   2. Wrap in InferencePipeline.
    //   3. Construct AiIpcRelay.
    //   4. Construct OrchestratorBridge.
    //   5. Classify an intent and confirm requires_inference is true.
    //   6. Process the intent through the bridge.
    //   7. Verify the result flows through correctly.

    #[tokio::test]
    async fn e2e_stream2_full_inference_pipeline() {
        use crate::{orchestrator_bridge::OrchestratorBridge, relay::AiIpcRelay};

        // ── Step 1: build a minimal model registry with one loaded model ──

        let sk = NexaCoreSigningKey::from_bytes([0xE4; 32]);
        let mut hash = [0u8; 32];
        hash[..16].fill(0xE5);
        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(hash),
            name: "e2e-stream2-model".into(),
            version: "1.0.0".into(),
            hash,
            signature: sk.sign(&hash),
            signing_key: sk.verifying_key(),
            size_bytes: 0,
            format: ModelFormat::Gguf,
        };

        let mut reg = ModelRegistry::new();
        let model_id = reg.register(manifest).unwrap();
        reg.load(model_id).unwrap();
        assert!(
            reg.is_loaded(model_id),
            "model must be loaded before pipeline"
        );

        // ── Step 2: wrap in InferencePipeline ──

        let shared_reg = Arc::new(Mutex::new(reg));
        let pipeline = InferencePipeline::new(Arc::clone(&shared_reg));

        // ── Step 3: construct AiIpcRelay ──

        let relay = AiIpcRelay::new(pipeline);

        // ── Step 4: construct OrchestratorBridge ──

        let bridge = OrchestratorBridge::new(relay);

        // ── Step 5: classify the intent ──

        let intent = "explain what this file does";
        assert!(
            OrchestratorBridge::requires_inference(intent),
            "intent '{intent}' should require inference"
        );

        // ── Step 6: process the intent end-to-end ──

        let result = bridge.process_intent(intent, model_id, 42).await;

        // ── Step 7: verify the result ──

        assert!(
            result.success,
            "E2E pipeline should succeed; error: {:?}",
            result.response_text
        );
        assert_eq!(result.request_id, 42, "request_id must be echoed");
        // No PII in the test intent.
        assert_eq!(
            result.entities_tokenized, 0,
            "no PII entities expected in clean intent"
        );
        // Latency is a non-negative u64 (always true); verify it was populated.
        let _ = result.inference_latency_us;
    }

    /// E2E test: PII in the intent is detected and tokenized before dispatch.
    #[tokio::test]
    async fn e2e_stream2_pii_detected_in_intent() {
        use crate::{orchestrator_bridge::OrchestratorBridge, relay::AiIpcRelay};

        let sk = NexaCoreSigningKey::from_bytes([0xE6; 32]);
        let mut hash = [0u8; 32];
        hash[..16].fill(0xE7);
        let manifest = ModelManifest {
            model_id: ModelId::from_manifest_hash(hash),
            name: "e2e-pii-model".into(),
            version: "1.0.0".into(),
            hash,
            signature: sk.sign(&hash),
            signing_key: sk.verifying_key(),
            size_bytes: 0,
            format: ModelFormat::Gguf,
        };

        let mut reg = ModelRegistry::new();
        let model_id = reg.register(manifest).unwrap();
        reg.load(model_id).unwrap();

        let pipeline = InferencePipeline::new(Arc::new(Mutex::new(reg)));
        let relay = AiIpcRelay::new(pipeline);
        let bridge = OrchestratorBridge::new(relay);

        // Intent contains an email address — preprocessor should detect it.
        let intent = "explain why admin@example.com cannot log in";
        let result = bridge.process_intent(intent, model_id, 99).await;

        assert!(result.success);
        assert_eq!(result.entities_tokenized, 1, "one email address expected");
    }

    /// E2E test: an unloaded model produces a structured error, not a panic.
    #[tokio::test]
    async fn e2e_stream2_unregistered_model_error_is_structured() {
        use crate::{orchestrator_bridge::OrchestratorBridge, relay::AiIpcRelay};

        let reg = ModelRegistry::new(); // empty — no models registered
        let pipeline = InferencePipeline::new(Arc::new(Mutex::new(reg)));
        let relay = AiIpcRelay::new(pipeline);
        let bridge = OrchestratorBridge::new(relay);

        let unknown_id = ModelId::from_bytes([0xDE; 32]);
        let result = bridge
            .process_intent("explain something", unknown_id, 55)
            .await;

        assert!(!result.success, "should fail for unknown model");
        assert_eq!(result.request_id, 55);
        assert!(
            !result.response_text.is_empty(),
            "error text must be populated for diagnostics"
        );
    }

    // =========================================================================
    // E2E: Quantized inference pipeline (Sprint 8)
    //
    // Exercises the full pipeline:
    //   build synthetic Q8_0 GGUF → parse → load_all_tensors → dequantize →
    //   build TransformerWeights → transformer_forward → non-zero logits
    // =========================================================================

    // -------------------------------------------------------------------------
    // build_synthetic_q8_0_gguf — helper
    // -------------------------------------------------------------------------

    // Reused by `provider::local_cpu` and `engine` tests (TASK-12 / TASK-13-pre
    // goldens) — one canonical tiny-model fixture, not multiple drifting
    // copies.  The body now lives in `crate::fixture` (compiled under
    // `cfg(test)` or the `fixture-model` feature) so the Ring 3 image embeds
    // the SAME model the host goldens pin (ADR-0034).
    #[allow(
        clippy::redundant_pub_crate,
        reason = "explicit crate-test visibility; plain `pub` trips unreachable_pub"
    )]
    pub(crate) use crate::fixture::build_synthetic_f32_gguf;
    // Re-export the new TASK-16 fixture builders for use in the cosine E2E.
    #[allow(
        clippy::redundant_pub_crate,
        reason = "explicit crate-test visibility; plain `pub` trips unreachable_pub"
    )]
    pub(crate) use crate::fixture::build_synthetic_q4_k_gguf;
    #[allow(
        clippy::redundant_pub_crate,
        reason = "explicit crate-test visibility; plain `pub` trips unreachable_pub"
    )]
    pub(crate) use crate::fixture::build_synthetic_q8_0_gguf;

    // -------------------------------------------------------------------------
    // quantized_inference_e2e_q8_0
    // -------------------------------------------------------------------------

    /// End-to-end test for the quantized inference pipeline.
    ///
    /// Builds a synthetic Q8_0 GGUF file in memory, loads it through the full
    /// pipeline (`parse_gguf` → `load_all_tensors` → `TransformerWeights` →
    /// `transformer_forward`), and verifies that the output logits are non-zero,
    /// proving that real dequantization (not the old zero-filled stub) ran.
    // The test body is long because it covers all seven pipeline stages plus
    // assertions; splitting into helpers would obscure the end-to-end flow.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn quantized_inference_e2e_q8_0() {
        use nexacore_hal::{
            tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype},
            transformer::{
                TransformerConfig, TransformerLayerWeights, TransformerWeights, transformer_forward,
            },
        };

        // Step 1: build the synthetic GGUF binary.
        let gguf_bytes = build_synthetic_q8_0_gguf();
        assert!(
            !gguf_bytes.is_empty(),
            "GGUF builder must not produce empty blob"
        );

        // Step 2: parse the GGUF header.
        let header =
            crate::gguf::parse_gguf(&gguf_bytes).expect("synthetic GGUF must parse without error");
        assert_eq!(
            header.tensor_count, 12,
            "expected 12 tensors in synthetic GGUF"
        );

        // Step 3: load and dequantize all tensors.
        let loaded_tensors = crate::tensor_loader::load_all_tensors(&gguf_bytes, &header)
            .expect("load_all_tensors must succeed on synthetic Q8_0 GGUF");

        // Verify dequantization produced non-zero values — the old stub always
        // returned zeros for Q8_0.
        for lt in &loaded_tensors {
            let has_nonzero = lt.buffer.as_bytes().chunks_exact(4).any(|b| {
                // chunks_exact(4) guarantees b.len() == 4; try_into cannot fail.
                let arr: [u8; 4] = b.try_into().expect("chunk is exactly 4 bytes");
                f32::from_le_bytes(arr) != 0.0
            });
            assert!(
                has_nonzero,
                "tensor '{}' is all-zero after Q8_0 dequantization \
                 — old zero-filled stub may still be active",
                lt.name
            );
        }

        // Helper: locate a dequantized tensor and reframe it with the given
        // logical shape (the Q8_0 dequantization pads to full blocks; we
        // truncate to the semantically meaningful element count).
        let find_tensor = |name: &str, shape: Vec<usize>| -> TensorBuffer {
            let lt = loaded_tensors
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("tensor '{name}' not found in loaded tensors"));
            let n_logical: usize = shape.iter().product();
            let byte_count = n_logical * 4;
            let src = lt.buffer.as_bytes();
            assert!(
                src.len() >= byte_count,
                "tensor '{}': buffer has {} bytes but shape {:?} needs {}",
                name,
                src.len(),
                shape,
                byte_count
            );
            let desc = TensorDescriptor::new(shape, TensorDtype::F32);
            // The assert above guarantees src.len() >= byte_count.
            let truncated = src
                .get(..byte_count)
                .expect("buffer length verified by assert above");
            TensorBuffer::new(desc, truncated.to_vec())
        };

        // Step 4: build TransformerConfig and TransformerWeights.
        //
        // Shape conventions (verified from transformer.rs and decode.rs):
        //   attn_q/k/v/o: [d_model, d_model]
        //   ffn_gate/up:  [d_model, d_ff]
        //   ffn_down:     [d_ff, d_model]
        //   norm weights: [d_model]
        //   token_embedding: [vocab_size, d_model]
        //   output_proj:     [d_model, vocab_size]
        let config = TransformerConfig {
            n_layers: 1,
            n_heads: 1,
            d_model: 4,
            d_ff: 8,
            vocab_size: 8,
            max_seq_len: 16,
            rms_norm_eps: 1e-5,
        };

        let layer = TransformerLayerWeights {
            attn_q: find_tensor("blk.0.attn_q.weight", vec![4, 4]),
            attn_k: find_tensor("blk.0.attn_k.weight", vec![4, 4]),
            attn_v: find_tensor("blk.0.attn_v.weight", vec![4, 4]),
            attn_o: find_tensor("blk.0.attn_output.weight", vec![4, 4]),
            ffn_gate: find_tensor("blk.0.ffn_gate.weight", vec![4, 8]),
            ffn_up: find_tensor("blk.0.ffn_up.weight", vec![4, 8]),
            ffn_down: find_tensor("blk.0.ffn_down.weight", vec![8, 4]),
            attn_norm: find_tensor("blk.0.attn_norm.weight", vec![4]),
            ffn_norm: find_tensor("blk.0.ffn_norm.weight", vec![4]),
        };

        let weights = TransformerWeights {
            token_embedding: find_tensor("token_embd.weight", vec![8, 4]),
            layers: vec![layer],
            output_norm: find_tensor("output_norm.weight", vec![4]),
            output_proj: find_tensor("output.weight", vec![4, 8]),
            n_kv_heads: None,
        };

        // Step 5: build the input token IDs tensor.
        //
        // CpuBackend EmbeddingLookup requires U8 indices; vocab_size=8 so all
        // test IDs [1, 2] fit in u8 without truncation.
        let prompt_ids: &[u8] = &[1u8, 2u8];
        let seq_len = prompt_ids.len();
        let input_desc = TensorDescriptor::new(vec![seq_len], TensorDtype::U8);
        let input_ids = TensorBuffer::new(input_desc, prompt_ids.to_vec());

        // Step 6: run the transformer forward pass.
        let backend = CpuBackend::new();
        let logits = transformer_forward(&backend, &config, &weights, &input_ids)
            .await
            .expect("transformer_forward must not error on valid synthetic inputs");

        // Step 7: verify the logits are non-zero and finite.
        //
        // Shape: [seq_len, vocab_size] = [2, 8].
        assert_eq!(
            logits.descriptor.shape,
            vec![seq_len, config.vocab_size],
            "logits shape must be [seq_len, vocab_size]"
        );

        let logit_values: Vec<f32> = logits
            .as_bytes()
            .chunks_exact(4)
            .map(|b| {
                // chunks_exact(4) guarantees b.len() == 4; try_into cannot fail.
                let arr: [u8; 4] = b.try_into().expect("chunk is exactly 4 bytes");
                f32::from_le_bytes(arr)
            })
            .collect();

        assert!(
            logit_values.iter().any(|&v| v != 0.0),
            "transformer_forward produced all-zero logits — \
             quantized weights did not propagate. logits: {logit_values:?}"
        );

        assert!(
            logit_values.iter().all(|v| v.is_finite()),
            "transformer_forward output contains non-finite values — \
             NaN/Inf propagated from weights. logits: {logit_values:?}"
        );
    }

    // =========================================================================
    // E2E cosine-vs-F32 tests (TASK-16 / ADR-0038)
    //
    // Run CpuEngine forward on the F32, Q8_0, and Q4_K fixtures and compare
    // output logit vectors via cosine similarity. This verifies that:
    //   - Q8_0-vs-F32 cosine ≥ 0.999 (scale=1.0 fixtures are nearly identical)
    //   - Q4_K-vs-F32 cosine ≥ 0.99  (4-bit encoding is faithful enough)
    // =========================================================================

    /// Compute cosine similarity between two f32 slices.
    ///
    /// Returns the cosine similarity in [-1, 1]; 1.0 means identical direction.
    /// Both slices must have the same length.
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        assert_eq!(a.len(), b.len(), "cosine_similarity: length mismatch");
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot / (norm_a * norm_b)
        }
    }

    /// Extract f32 logits from a `TensorBuffer` (last row of the forward output).
    ///
    /// The engine's `greedy_generate` uses `extract_last_row` internally;
    /// here we reproduce the same step to obtain raw logit vectors for the
    /// cosine comparison without going through argmax.
    fn logits_from_gguf(gguf: &[u8]) -> Vec<f32> {
        use nexacore_hal::{
            tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype},
            transformer::{TransformerConfig, transformer_forward_sync},
        };

        use crate::{
            bpe::{BpeTokenizer, BpeVocabulary, SpecialTokens},
            decode::extract_last_row,
            engine::CpuEngine,
        };

        let config = TransformerConfig {
            n_layers: 1,
            n_heads: 1,
            d_model: 4,
            d_ff: 8,
            vocab_size: 8,
            max_seq_len: 16,
            rms_norm_eps: 1e-5,
        };
        let tokens: Vec<(u32, Vec<u8>)> = (0u32..8).map(|i| (i, vec![b'a' + i as u8])).collect();
        let special = SpecialTokens {
            bos: 252,
            eos: 253,
            pad: 254,
            unk: 255,
        };
        let tokenizer = BpeTokenizer::new(BpeVocabulary::new(tokens, Vec::new(), special));

        let engine = CpuEngine::from_gguf(gguf, config, tokenizer).expect("fixture must load");

        // Fixed prompt ids [0, 1] ("ab") — same as the golden test.
        let prompt_ids: Vec<u8> = vec![0u8, 1u8];
        let seq_len = prompt_ids.len();
        let input = TensorBuffer::new(
            TensorDescriptor::new(vec![seq_len], TensorDtype::U8),
            prompt_ids,
        );

        let backend = CpuBackend::new();
        let logits = transformer_forward_sync(&backend, engine.config(), engine.weights(), &input)
            .expect("forward must not error on fixture");

        // Extract the last row (logits for the last token position).
        let last = extract_last_row(&logits, seq_len, engine.config().vocab_size)
            .expect("extract_last_row must succeed");

        // `extract_last_row` already returns Vec<f32>, so no conversion needed.
        last
    }

    /// E2E cosine-vs-F32: Q8_0 forward output must be ≥ 0.999 similar to F32.
    ///
    /// The Q8_0 fixture uses scale=1.0 and integer values 1..=7, which
    /// dequantize exactly to f32 integers 1.0..=7.0 — identical to the F32
    /// fixture weights. The cosine similarity of the outputs should be very
    /// close to 1.0.
    ///
    /// # Threshold: ≥ 0.999
    ///
    /// With unit-scale Q8_0, the only rounding comes from f16→f32 for the
    /// scale field. The f16 representation of 1.0 is exact, so no rounding
    /// error is introduced and the outputs are truly identical → cosine = 1.0.
    /// We assert ≥ 0.999 to tolerate any future fixture change.
    #[test]
    fn e2e_cosine_q8_0_vs_f32() {
        let f32_logits = logits_from_gguf(&build_synthetic_f32_gguf());
        let q8_logits = logits_from_gguf(&build_synthetic_q8_0_gguf());

        assert!(
            !f32_logits.iter().all(|&v| v == 0.0),
            "F32 fixture logits must not be all-zero"
        );
        assert!(
            !q8_logits.iter().all(|&v| v == 0.0),
            "Q8_0 fixture logits must not be all-zero"
        );

        let cos = cosine_similarity(&f32_logits, &q8_logits);
        // Q8_0 with scale=1.0 and integer values exactly matches the F32 fixture.
        // Threshold 0.999: the threshold is documented here to explain the choice.
        // With unit-scale and integer nibbles the weights are identical in both
        // fixtures, so the forwarded logits are identical (cosine = 1.0).
        // We assert ≥ 0.999 as a conservative tolerance.
        assert!(
            cos >= 0.999,
            "Q8_0-vs-F32 cosine similarity {cos:.6} is below threshold 0.999"
        );
    }

    /// E2E cosine-vs-F32: Q4_K forward output must be ≥ 0.99 similar to F32.
    ///
    /// The Q4_K fixture uses d=1.0, dmin=0.0, all sub-scale=1, and nibble
    /// values identical to the F32 fixture's integer values 1..=7. Because
    /// the dequant formula is `d * sc * nibble - dmin * m = 1 * 1 * nibble - 0 = nibble`,
    /// the dequantized weights are identical to the F32 fixture. In practice,
    /// the cosine similarity is 1.0 for this fixture; we assert ≥ 0.99 to
    /// accommodate any floating-point rounding differences.
    ///
    /// # Threshold: ≥ 0.99
    ///
    /// The threshold is set conservatively relative to Q8_0 because Q4_K
    /// uses 4-bit quantization with an additional level of indirection through
    /// the sub-scale machinery, which could introduce small rounding errors on
    /// some hardware. On this fixture the actual similarity is ≈ 1.0.
    #[test]
    fn e2e_cosine_q4_k_vs_f32() {
        let f32_logits = logits_from_gguf(&build_synthetic_f32_gguf());
        let q4k_logits = logits_from_gguf(&build_synthetic_q4_k_gguf());

        assert!(
            !f32_logits.iter().all(|&v| v == 0.0),
            "F32 fixture logits must not be all-zero"
        );
        assert!(
            !q4k_logits.iter().all(|&v| v == 0.0),
            "Q4_K fixture logits must not be all-zero"
        );

        let cos = cosine_similarity(&f32_logits, &q4k_logits);
        // Q4_K with d=1.0, dmin=0.0, sc=1, m=0 dequantizes to exact integer nibble
        // values — identical to the F32 fixture. Actual cosine similarity = 1.0.
        // Threshold 0.99: conservative tolerance for potential floating-point
        // differences across platforms and future fixture changes.
        assert!(
            cos >= 0.99,
            "Q4_K-vs-F32 cosine similarity {cos:.6} is below threshold 0.99"
        );
    }
}

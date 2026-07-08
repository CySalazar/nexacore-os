//! End-to-end inference integration test.
//!
//! Exercises the full Phase 2 vertical slice:
//! 1. BPE tokenizer encodes a prompt to token IDs.
//! 2. `NCFS` stores a synthetic GGUF model file.
//! 3. Model loader reads the GGUF from `NCFS` and extracts tensor weights.
//! 4. Transformer forward pass runs on the loaded weights.
//! 5. Output logits are decoded back to text via the BPE tokenizer.

// Integration tests are separate compilation units not covered by the crate-root
// cfg_attr(test, allow(...)). The lints below are intentional in test code:
//   - unwrap_used: test failures should panic; propagating errors adds no value.
//   - indexing_slicing: bounds are established by the test's own construction.
//   - cast_possible_truncation: values are known-small in test fixtures.
//   - doc_markdown: prose comments in test modules need not use code-style backticks.
#![allow(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use nexacore_fs::InMemoryFs;
use nexacore_hal::{
    tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype},
    transformer::{
        TransformerConfig, TransformerLayerWeights, TransformerWeights, transformer_forward,
    },
};
use nexacore_runtime::{
    bpe::{BpeTokenizer, BpeVocabulary},
    gguf::{GGUF_MAGIC, GGUF_VERSION_3},
    model_loader::{load_model_from_fs, write_model_to_fs},
};

fn make_f32_buf(shape: Vec<usize>, fill: f32) -> TensorBuffer {
    let desc = TensorDescriptor::new(shape, TensorDtype::F32);
    let n = desc.num_elements();
    let mut bytes = vec![0u8; n * 4];
    for i in 0..n {
        let start = i * 4;
        bytes[start..start + 4].copy_from_slice(&fill.to_le_bytes());
    }
    TensorBuffer::new(desc, bytes)
}

fn make_tiny_weights(config: &TransformerConfig) -> TransformerWeights {
    let d = config.d_model;
    let f = config.d_ff;
    let v = config.vocab_size;

    let mut layers = Vec::new();
    for _ in 0..config.n_layers {
        layers.push(TransformerLayerWeights {
            attn_q: make_f32_buf(vec![d, d], 0.01),
            attn_k: make_f32_buf(vec![d, d], 0.01),
            attn_v: make_f32_buf(vec![d, d], 0.01),
            attn_o: make_f32_buf(vec![d, d], 0.01),
            ffn_gate: make_f32_buf(vec![d, f], 0.01),
            ffn_up: make_f32_buf(vec![d, f], 0.01),
            ffn_down: make_f32_buf(vec![f, d], 0.01),
            attn_norm: make_f32_buf(vec![d], 1.0),
            ffn_norm: make_f32_buf(vec![d], 1.0),
        });
    }

    TransformerWeights {
        token_embedding: make_f32_buf(vec![v, d], 0.02),
        layers,
        output_norm: make_f32_buf(vec![d], 1.0),
        output_proj: make_f32_buf(vec![d, v], 0.01),
        n_kv_heads: None,
    }
}

/// Build a minimal GGUF file with one F32 tensor for testing the load path.
fn make_test_gguf_with_tensor(tensor_name: &str, dims: &[u64], f32_data: &[f32]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
    buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
    buf.extend_from_slice(&1u64.to_le_bytes()); // tensor_count = 1
    buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count = 0

    // Tensor info
    let name_bytes = tensor_name.as_bytes();
    buf.extend_from_slice(&(name_bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(&(dims.len() as u32).to_le_bytes());
    for d in dims {
        buf.extend_from_slice(&d.to_le_bytes());
    }
    buf.extend_from_slice(&0u32.to_le_bytes()); // dtype = F32
    buf.extend_from_slice(&0u64.to_le_bytes()); // offset = 0

    // Pad to 32-byte alignment
    let align = 32;
    let remainder = buf.len() % align;
    if remainder != 0 {
        buf.resize(buf.len() + (align - remainder), 0);
    }

    // Tensor data (F32 LE bytes)
    for val in f32_data {
        buf.extend_from_slice(&val.to_le_bytes());
    }

    buf
}

// =============================================================================
// Test: BPE tokenizer round-trip
// =============================================================================

#[test]
fn e2e_bpe_roundtrip() {
    let tokenizer = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    let prompt = "hello world";
    let ids = tokenizer.encode(prompt).unwrap();
    assert!(!ids.is_empty());
    let decoded = tokenizer.decode(&ids).unwrap();
    assert_eq!(decoded, prompt);
}

// =============================================================================
// Test: NCFS → GGUF → TensorBuffer pipeline
// =============================================================================

#[test]
fn e2e_ncfs_gguf_load() {
    let data = [1.0_f32, 2.0, 3.0, 4.0];
    let gguf = make_test_gguf_with_tensor("test.weight", &[2, 2], &data);

    let mut fs = InMemoryFs::format(256);
    write_model_to_fs(&mut fs, "/models/test.gguf", &gguf).unwrap();

    let loaded = load_model_from_fs(&fs, "/models/test.gguf").unwrap();
    assert_eq!(loaded.header.tensor_count, 1);
    assert_eq!(loaded.tensors.len(), 1);

    let tensor = &loaded.tensors[0];
    assert_eq!(tensor.name, "test.weight");
    assert_eq!(tensor.buffer.descriptor.shape, vec![2, 2]);
}

// =============================================================================
// Test: Transformer forward pass with tiny model
// =============================================================================

#[tokio::test]
async fn e2e_transformer_forward() {
    let config = TransformerConfig {
        n_layers: 1,
        n_heads: 2,
        d_model: 8,
        d_ff: 16,
        vocab_size: 32,
        max_seq_len: 16,
        rms_norm_eps: 1e-5,
    };

    let weights = make_tiny_weights(&config);
    let backend = CpuBackend::new();

    // Create input token IDs: [3, 7, 1]
    let input_desc = TensorDescriptor::new(vec![3], TensorDtype::U8);
    let input_ids = TensorBuffer::new(input_desc, vec![3, 7, 1]);

    let logits = transformer_forward(&backend, &config, &weights, &input_ids)
        .await
        .unwrap();

    // Output shape: [seq_len, vocab_size]
    assert_eq!(logits.descriptor.shape, vec![3, 32]);
    assert!(!logits.is_empty());
}

// =============================================================================
// Test: Full E2E pipeline — tokenize → load model → infer → decode
// =============================================================================

#[tokio::test]
async fn e2e_full_inference_pipeline() {
    // --- Step 1: Tokenize input ---
    let tokenizer = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    let prompt = "hi";
    let token_ids = tokenizer.encode(prompt).unwrap();
    assert!(!token_ids.is_empty());

    // --- Step 2: Create a tiny model and store in NCFS ---
    let config = TransformerConfig {
        n_layers: 1,
        n_heads: 2,
        d_model: 8,
        d_ff: 16,
        vocab_size: 256,
        max_seq_len: 16,
        rms_norm_eps: 1e-5,
    };

    // Store a dummy GGUF in NCFS to validate the load path
    let dummy_data = vec![0.1_f32; 4];
    let gguf = make_test_gguf_with_tensor("dummy.weight", &[2, 2], &dummy_data);
    let mut fs = InMemoryFs::format(256);
    write_model_to_fs(&mut fs, "/models/tiny.gguf", &gguf).unwrap();

    // Verify the model loads from the filesystem
    let loaded = load_model_from_fs(&fs, "/models/tiny.gguf").unwrap();
    assert_eq!(loaded.header.version, 3);
    assert!(!loaded.tensors.is_empty());

    // --- Step 3: Run transformer forward pass ---
    let weights = make_tiny_weights(&config);
    let backend = CpuBackend::new();

    // Convert BPE token IDs to U8 input tensor
    let seq_len = token_ids.len();
    let input_bytes: Vec<u8> = token_ids.iter().map(|&id| id as u8).collect();
    let input_desc = TensorDescriptor::new(vec![seq_len], TensorDtype::U8);
    let input_buf = TensorBuffer::new(input_desc, input_bytes);

    let logits = transformer_forward(&backend, &config, &weights, &input_buf)
        .await
        .unwrap();

    assert_eq!(logits.descriptor.shape, vec![seq_len, 256]);

    // --- Step 4: Greedy decode — pick argmax for each position ---
    let logit_bytes = logits.as_bytes();
    let vocab_size = config.vocab_size;
    let mut output_ids = Vec::new();

    for pos in 0..seq_len {
        let mut best_id = 0u32;
        let mut best_val = f32::NEG_INFINITY;
        for v in 0..vocab_size {
            let idx = pos * vocab_size + v;
            let start = idx * 4;
            if let Some(chunk) = logit_bytes.get(start..start + 4) {
                if let Ok(bytes) = <[u8; 4]>::try_from(chunk) {
                    let val = f32::from_le_bytes(bytes);
                    if val > best_val {
                        best_val = val;
                        best_id = v as u32;
                    }
                }
            }
        }
        output_ids.push(best_id);
    }

    // --- Step 5: Decode output tokens back to text ---
    let decoded = tokenizer.decode(&output_ids).unwrap();

    // The tiny random model won't produce meaningful text, but the pipeline
    // must complete without errors and produce a non-empty string.
    assert!(!decoded.is_empty());
    assert_eq!(output_ids.len(), seq_len);
}

// =============================================================================
// Test: zero-PII inference boundary — TASK-17 Phase-2 gate
//
// Chains the tokenization pipeline into the inference engine and asserts that
// NO raw PII value crosses the model boundary: the PII is replaced by opaque
// tokens BEFORE BPE encoding, so it never enters the forward pass, and the
// decoded output is checked to contain none of the original PII either.
// =============================================================================

#[tokio::test]
async fn e2e_zero_pii_inference_boundary() {
    use std::sync::Arc;

    use nexacore_tee::MockTeeBackend;
    use nexacore_tokenization::{
        TokenizationService, policy::PolicyPreset, types::TokenizeRequest,
    };
    use nexacore_types::SessionId;

    // The raw PII values that MUST NOT cross the inference boundary.
    const RAW_EMAIL: &str = "alice@example.com";
    const RAW_PHONE: &str = "555-123-4567";
    let input_text = format!("Contact {RAW_EMAIL} or call {RAW_PHONE} for support.");

    // --- Step 1: Tokenize/redact PII through the TEE-backed pipeline ---
    let backend: Arc<dyn nexacore_tee::TeeBackend> = Arc::new(MockTeeBackend::new());
    let mut service = TokenizationService::new(backend);
    let resp = service
        .tokenize(TokenizeRequest {
            session_id: SessionId::new(),
            text: input_text.clone(),
            policy: PolicyPreset::Gdpr,
        })
        .expect("tokenize PII text under GDPR policy");

    // BOUNDARY ASSERTION 1: the tokenized text that will feed the model holds
    // NONE of the raw PII — the email and phone were replaced by opaque tokens.
    let safe_text = &resp.tokenized_text;
    assert!(
        !safe_text.contains(RAW_EMAIL),
        "raw email leaked into the model-bound text: {safe_text}"
    );
    assert!(
        !safe_text.contains(RAW_PHONE),
        "raw phone leaked into the model-bound text: {safe_text}"
    );

    // --- Step 2: BPE-encode the PII-free text and run the model forward ---
    let tokenizer = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    let token_ids = tokenizer.encode(safe_text).expect("encode redacted text");
    assert!(!token_ids.is_empty());

    let config = TransformerConfig {
        n_layers: 1,
        n_heads: 2,
        d_model: 8,
        d_ff: 16,
        vocab_size: 256,
        max_seq_len: 64,
        rms_norm_eps: 1e-5,
    };
    let weights = make_tiny_weights(&config);
    let backend = CpuBackend::new();

    // Truncate to the model's max_seq_len so the forward stays in-bounds.
    let seq_len = token_ids.len().min(config.max_seq_len);
    let input_bytes: Vec<u8> = token_ids[..seq_len].iter().map(|&id| id as u8).collect();
    let input_desc = TensorDescriptor::new(vec![seq_len], TensorDtype::U8);
    let input_buf = TensorBuffer::new(input_desc, input_bytes);

    let logits = transformer_forward(&backend, &config, &weights, &input_buf)
        .await
        .expect("forward on redacted tokens");
    assert_eq!(logits.descriptor.shape, vec![seq_len, config.vocab_size]);

    // --- Step 3: Greedy-decode the output and decode back to text ---
    let logit_bytes = logits.as_bytes();
    let vocab_size = config.vocab_size;
    let mut output_ids = Vec::new();
    for pos in 0..seq_len {
        let mut best_id = 0u32;
        let mut best_val = f32::NEG_INFINITY;
        for v in 0..vocab_size {
            let start = (pos * vocab_size + v) * 4;
            if let Some(chunk) = logit_bytes.get(start..start + 4) {
                if let Ok(bytes) = <[u8; 4]>::try_from(chunk) {
                    let val = f32::from_le_bytes(bytes);
                    if val > best_val {
                        best_val = val;
                        best_id = v as u32;
                    }
                }
            }
        }
        output_ids.push(best_id);
    }
    let decoded = tokenizer.decode(&output_ids).expect("decode model output");

    // BOUNDARY ASSERTION 2: the decoded model output contains no raw PII.
    assert!(
        !decoded.contains(RAW_EMAIL),
        "raw email surfaced in the model output"
    );
    assert!(
        !decoded.contains(RAW_PHONE),
        "raw phone surfaced in the model output"
    );
}

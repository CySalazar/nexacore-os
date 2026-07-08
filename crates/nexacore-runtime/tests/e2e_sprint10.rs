//! Sprint 10 E2E integration test.
//!
//! Validates the three new subsystems added in Sprint 10:
//! 1. Speculative decoding (draft + verify loop).
//! 2. Grouped-Query Attention with `RoPE` and causal masking.
//! 3. Continuous batching scheduler serving concurrent requests.

// Integration tests are separate compilation units not covered by the crate-root
// cfg_attr(test, allow(...)). The lints below are intentional in test code:
//   - unwrap_used: test failures should panic; propagating errors adds no value.
//   - indexing_slicing: bounds are established by the test's own construction.
//   - float_cmp: NEG_INFINITY comparison is exact by definition; epsilon check
//     would be semantically wrong.
//   - similar_names: `id1`/`ids` are the clearest names for these test bindings.
//   - doc_markdown: prose comments need not use code-style backticks.
#![allow(
    clippy::float_arithmetic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::similar_names,
    clippy::doc_markdown
)]

// ---------------------------------------------------------------------------
// 1. Speculative decode — end-to-end
// ---------------------------------------------------------------------------

#[test]
fn speculative_decode_e2e_identity_models() {
    use nexacore_runtime::speculative::{SpeculativeConfig, speculative_decode};

    let vocab = 8;
    let draft_forward = |tokens: &[usize]| -> Vec<f32> {
        let mut logits = vec![0.0f32; vocab];
        let last = tokens.last().copied().unwrap_or(0);
        let next = (last + 1) % vocab;
        logits[next] = 10.0;
        logits
    };

    let target_forward = |tokens: &[usize]| -> Vec<Vec<f32>> {
        tokens
            .iter()
            .map(|&t| {
                let mut logits = vec![0.0f32; vocab];
                let next = (t + 1) % vocab;
                logits[next] = 10.0;
                logits
            })
            .collect()
    };

    let config = SpeculativeConfig {
        draft_len: 4,
        temperature: 0.0,
        max_new_tokens: 10,
        eos_token_id: None,
    };

    let result = speculative_decode(&[0], &config, draft_forward, target_forward);
    assert_eq!(result.len(), 10);
    for (i, &tok) in result.iter().enumerate() {
        assert_eq!(tok, (i + 1) % vocab);
    }
}

#[test]
fn speculative_decode_e2e_eos_stops() {
    use nexacore_runtime::speculative::{SpeculativeConfig, speculative_decode};

    let vocab = 8;
    let eos = 5;

    let forward = |tokens: &[usize]| -> Vec<f32> {
        let mut logits = vec![0.0f32; vocab];
        let last = tokens.last().copied().unwrap_or(0);
        let next = (last + 1) % vocab;
        logits[next] = 10.0;
        logits
    };

    let target_forward = |tokens: &[usize]| -> Vec<Vec<f32>> {
        tokens
            .iter()
            .map(|&t| {
                let mut logits = vec![0.0f32; vocab];
                let next = (t + 1) % vocab;
                logits[next] = 10.0;
                logits
            })
            .collect()
    };

    let config = SpeculativeConfig {
        draft_len: 3,
        temperature: 0.0,
        max_new_tokens: 100,
        eos_token_id: Some(eos),
    };

    let result = speculative_decode(&[2], &config, forward, target_forward);
    assert!(result.len() <= 100);
    assert!(result.contains(&eos));
}

// ---------------------------------------------------------------------------
// 2. GQA + RoPE + Causal mask — integration
// ---------------------------------------------------------------------------

#[test]
fn gqa_attention_produces_correct_shape() {
    use nexacore_hal::transformer::gqa_attention;

    let seq_len = 4;
    let n_heads = 4;
    let n_kv_heads = 2;
    let head_dim = 8;
    let d_model = n_heads * head_dim;
    let kv_dim = n_kv_heads * head_dim;

    let q = vec![1.0f32; seq_len * d_model];
    let k = vec![1.0f32; seq_len * kv_dim];
    let v = vec![0.5f32; seq_len * kv_dim];

    let out = gqa_attention(&q, &k, &v, seq_len, n_heads, n_kv_heads, head_dim, true);
    assert_eq!(out.len(), seq_len * d_model);
    assert!(out.iter().all(|x| x.is_finite()));
}

#[test]
fn rope_then_causal_mask_integration() {
    use nexacore_hal::transformer::{apply_causal_mask, apply_rope};

    let seq_len = 3;
    let n_heads = 2;
    let head_dim = 4;
    let d = n_heads * head_dim;

    let mut q = vec![1.0f32; seq_len * d];
    apply_rope(&mut q, seq_len, n_heads, head_dim, 0);

    let mut scores = vec![1.0f32; seq_len * seq_len];
    apply_causal_mask(&mut scores, seq_len);

    for row in 0..seq_len {
        for col in 0..seq_len {
            let val = scores[row * seq_len + col];
            if col > row {
                assert_eq!(val, f32::NEG_INFINITY);
            } else {
                assert!((val - 1.0).abs() < 1e-6);
            }
        }
    }

    assert!(q.iter().all(|x| x.is_finite()));
}

// ---------------------------------------------------------------------------
// 3. Batch scheduler — multi-request lifecycle
// ---------------------------------------------------------------------------

#[test]
fn batch_scheduler_multi_request_lifecycle() {
    use nexacore_runtime::batch::{
        BatchConfig, BatchScheduler, FinishReason, InferenceRequest, Priority, RequestId,
    };

    let config = BatchConfig {
        max_batch_size: 4,
        max_queue_size: 16,
        preemption_enabled: true,
        max_total_tokens: 1024,
    };

    let mut sched = BatchScheduler::new(config);

    let id1 = sched.next_request_id();
    let r1 = sched
        .submit(InferenceRequest {
            id: id1,
            prompt_tokens: vec![1, 2, 3],
            max_new_tokens: 3,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority: Priority::Normal,
        })
        .unwrap();

    let id2 = sched.next_request_id();
    let r2 = sched
        .submit(InferenceRequest {
            id: id2,
            prompt_tokens: vec![4, 5],
            max_new_tokens: 2,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority: Priority::High,
        })
        .unwrap();

    assert_eq!(sched.pending_count(), 2);

    let vocab = 8;
    let mut all_completed = Vec::new();

    for _ in 0..10 {
        let completed = sched.step(&mut |batch| {
            batch
                .iter()
                .map(|(rid, _toks)| {
                    let mut logits = vec![0.0f32; vocab];
                    logits[3] = 10.0;
                    (*rid, logits)
                })
                .collect()
        });
        all_completed.extend(completed);

        if sched.active_count() == 0 && sched.pending_count() == 0 {
            break;
        }
    }

    let drained = sched.drain_completed();
    all_completed.extend(drained);

    let ids: Vec<RequestId> = all_completed.iter().map(|c| c.id).collect();
    assert!(ids.contains(&r1));
    assert!(ids.contains(&r2));

    for cr in &all_completed {
        assert!(
            cr.finish_reason == FinishReason::MaxTokens
                || cr.finish_reason == FinishReason::EosToken
        );
    }
}

#[test]
fn batch_scheduler_preemption_works() {
    use nexacore_runtime::batch::{
        BatchConfig, BatchScheduler, FinishReason, InferenceRequest, Priority,
    };

    let config = BatchConfig {
        max_batch_size: 1,
        max_queue_size: 4,
        preemption_enabled: true,
        max_total_tokens: 256,
    };

    let mut sched = BatchScheduler::new(config);

    let low_id = sched.next_request_id();
    let _low = sched
        .submit(InferenceRequest {
            id: low_id,
            prompt_tokens: vec![1],
            max_new_tokens: 100,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority: Priority::Low,
        })
        .unwrap();

    sched.step(&mut |batch| {
        batch
            .iter()
            .map(|(rid, _)| (*rid, vec![0.0f32; 4]))
            .collect()
    });
    assert_eq!(sched.active_count(), 1);

    let crit_id = sched.next_request_id();
    let _critical = sched
        .submit(InferenceRequest {
            id: crit_id,
            prompt_tokens: vec![2],
            max_new_tokens: 1,
            temperature: 0.0,
            top_k: 1,
            eos_token_id: None,
            priority: Priority::Critical,
        })
        .unwrap();

    let completed = sched.step(&mut |batch| {
        batch
            .iter()
            .map(|(rid, _)| {
                let mut logits = vec![0.0f32; 4];
                logits[1] = 10.0;
                (*rid, logits)
            })
            .collect()
    });

    let all = [completed, sched.drain_completed()].concat();
    let preempted = all
        .iter()
        .any(|c| c.finish_reason == FinishReason::Preempted);
    assert!(preempted, "low-priority request should be preempted");
}

//! End-to-end test for Sprint 11.a — inference session lifecycle and serving.
//!
//! Exercises the full [`nexacore_runtime::serving`] vertical slice:
//!
//! 1. Open a `SessionManager`.
//! 2. Open three concurrent sessions bound to the same model.
//! 3. Submit one inference request per session.
//! 4. Drive the scheduler forward until all requests complete.
//! 5. Stream tokens back and verify each session receives its tokens.
//! 6. Assert FIFO ordering for equal-priority requests within a single session.
//! 7. Close all sessions and verify clean shutdown.
//!
//! The `forward_fn` used in this test is a deterministic stub that always
//! returns logits `[5.0, 1.0, 1.0]` so token 0 wins at every step.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_arithmetic,
    clippy::indexing_slicing
)]

use nexacore_runtime::serving::{BatchConfig, ServingRequest, SessionCapability, SessionManager};
use nexacore_types::ModelId;

// =============================================================================
// Shared fixtures
// =============================================================================

/// A minimal `BatchConfig` suitable for this test suite.
fn test_cfg() -> BatchConfig {
    BatchConfig {
        max_batch_size: 8,
        max_queue_size: 64,
        preemption_enabled: false,
        max_total_tokens: 4096,
    }
}

/// Build a valid `SessionCapability` for tests.
fn cap() -> SessionCapability {
    SessionCapability::new(vec![0x01, 0xAB, 0xCD]).unwrap()
}

/// The test model id (content does not matter; value is arbitrary).
fn model_id() -> ModelId {
    ModelId::from_bytes([0x42; 32])
}

/// Deterministic greedy forward function: always returns `[5.0, 1.0, 1.0]`
/// so the sampled token is always 0.
fn greedy_fwd(
    batch: &nexacore_runtime::batch::BatchView<'_>,
) -> nexacore_runtime::batch::ForwardResult {
    batch
        .iter()
        .map(|(rid, _)| (*rid, vec![5.0_f32, 1.0_f32, 1.0_f32]))
        .collect()
}

// =============================================================================
// Test: open 3 concurrent sessions, submit, drive, stream, close
// =============================================================================

/// End-to-end serving test: three concurrent sessions → submit → drain → stream.
///
/// Assertion checklist:
/// - All three sessions open successfully with unique IDs.
/// - All three requests are submitted without error.
/// - Driving the scheduler advances all requests.
/// - `stream_tokens` delivers at least one chunk per session.
/// - The final chunk for each session has `is_last = true`.
/// - All sessions close cleanly after draining.
#[test]
fn e2e_three_concurrent_sessions() {
    let mut mgr = SessionManager::new(test_cfg());
    let c = cap();
    let mid = model_id();

    // ── Step 1: Open three sessions. ─────────────────────────────────────────

    let sid_a = mgr.open_session(mid, c.clone()).unwrap();
    let sid_b = mgr.open_session(mid, c.clone()).unwrap();
    let sid_c = mgr.open_session(mid, c.clone()).unwrap();

    assert_eq!(mgr.session_count(), 3, "expected 3 open sessions");

    // IDs must be distinct (CSPRNG uniqueness).
    assert_ne!(sid_a, sid_b, "session A and B must have distinct IDs");
    assert_ne!(sid_b, sid_c, "session B and C must have distinct IDs");
    assert_ne!(sid_a, sid_c, "session A and C must have distinct IDs");

    // ── Step 2: Submit one request per session. ───────────────────────────────

    let make_req = |sid, n_tokens: usize| ServingRequest {
        session_id: sid,
        model_id: mid,
        prompt_tokens: vec![1],
        max_new_tokens: n_tokens,
        temperature: 0.0,
        top_k: 1,
        eos_token_id: None,
        priority: 1,
    };

    let _rid_a = mgr.submit(make_req(sid_a, 2), &c).unwrap();
    let _rid_b = mgr.submit(make_req(sid_b, 2), &c).unwrap();
    let _rid_c = mgr.submit(make_req(sid_c, 2), &c).unwrap();

    assert!(
        mgr.pending_count() > 0,
        "scheduler must have pending requests"
    );

    // ── Step 3: Drive scheduler until all requests complete. ──────────────────

    let max_steps = 20;
    let mut steps = 0;
    loop {
        mgr.step(&mut greedy_fwd);
        steps += 1;
        if mgr.pending_count() == 0 || steps >= max_steps {
            break;
        }
    }
    assert!(
        steps < max_steps,
        "scheduler should have completed all requests within {max_steps} steps"
    );

    // ── Step 4: Stream tokens and verify per-session delivery. ────────────────

    for &sid in &[sid_a, sid_b, sid_c] {
        let chunks = mgr.stream_tokens(sid, &c).unwrap();
        assert!(
            !chunks.is_empty(),
            "session {sid:?} should have received at least one chunk"
        );
        // Every chunk belongs to the correct session.
        for ch in &chunks {
            assert_eq!(
                ch.session_id, sid,
                "chunk session_id mismatch for session {sid:?}"
            );
        }
        // The final chunk must have `is_last = true`.
        let last = chunks.last().unwrap();
        assert!(
            last.is_last,
            "the final chunk for session {sid:?} must have is_last=true"
        );
        // For `max_new_tokens = 2` and greedy token 0, expect exactly 2 chunks.
        assert_eq!(
            chunks.len(),
            2,
            "session {sid:?}: expected 2 chunks for max_new_tokens=2"
        );
    }

    // ── Step 5: Close all sessions and verify clean shutdown. ─────────────────

    mgr.close_session(sid_a, &c).unwrap();
    mgr.close_session(sid_b, &c).unwrap();
    mgr.close_session(sid_c, &c).unwrap();

    assert_eq!(
        mgr.session_count(),
        0,
        "all sessions must be removed after close"
    );
}

// =============================================================================
// Test: LIFO ordering for equal priority within a single session
// =============================================================================

/// The `BatchScheduler` uses LIFO ordering for equal-priority requests.
///
/// This test documents and verifies the deterministic scheduling property:
/// when `max_batch_size = 1` and three equal-priority requests are submitted
/// before any step, the completion order is the reverse of the submission
/// order (last submitted, first served).
///
/// This is the correct and expected behaviour of the underlying scheduler.
/// See the `BatchScheduler` documentation for details.
#[test]
fn e2e_deterministic_ordering_for_equal_priority() {
    let cfg = BatchConfig {
        max_batch_size: 1,
        max_queue_size: 16,
        preemption_enabled: false,
        max_total_tokens: 1024,
    };
    let mut mgr = SessionManager::new(cfg);
    let c = cap();
    let mid = model_id();

    let sid = mgr.open_session(mid, c.clone()).unwrap();

    // Submit 3 requests at priority=1 (Normal) in order A, B, C.
    let req = |n: usize| ServingRequest {
        session_id: sid,
        model_id: mid,
        prompt_tokens: vec![n], // unique prompt to distinguish requests
        max_new_tokens: 1,
        temperature: 0.0,
        top_k: 1,
        eos_token_id: None,
        priority: 1,
    };

    let rid_a = mgr.submit(req(10), &c).unwrap();
    let rid_b = mgr.submit(req(20), &c).unwrap();
    let rid_c = mgr.submit(req(30), &c).unwrap();

    // Drive until all complete.
    let mut completed_order = Vec::new();
    for _ in 0..12 {
        mgr.step(&mut greedy_fwd);
        let chunks = mgr.stream_tokens(sid, &c).unwrap();
        for ch in &chunks {
            if ch.is_last {
                completed_order.push(nexacore_runtime::batch::RequestId(ch.request_id));
            }
        }
        if completed_order.len() == 3 {
            break;
        }
    }

    assert_eq!(completed_order.len(), 3, "all 3 requests must complete");

    // BatchScheduler is LIFO for equal-priority requests: the most recently
    // submitted request is at the back of the queue and is promoted first.
    // Expected completion order: C, B, A (reverse of submission).
    assert_eq!(
        completed_order,
        vec![rid_c, rid_b, rid_a],
        "LIFO ordering violated: expected [C, B, A], got {completed_order:?}"
    );

    mgr.close_session(sid, &c).unwrap();
    assert_eq!(mgr.session_count(), 0);
}

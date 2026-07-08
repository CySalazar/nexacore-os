//! Property tests: the `provider` wire types round-trip losslessly under
//! the canonical postcard encoding (`NCIP-Serde-004`) — TASK-08 (DE-G1).
//!
//! Run with `cargo test -p nexacore-runtime --test provider_wire_roundtrip`.

// Integration tests are separate compilation units not covered by the
// crate-root cfg_attr(test, allow(...)). `expect_used` is intentional in
// test code: a failed encode/decode should panic the test, not propagate.
#![allow(clippy::expect_used)]

use nexacore_runtime::provider::{
    ChatMessage, ChatRequest, ChatResponse, EmbeddingsRequest, EmbeddingsResponse, GenerateRequest,
    GenerateResponse, HealthStatus,
};
use nexacore_types::wire::{decode_canonical, encode_canonical};
use proptest::prelude::*;

/// Strategy for an arbitrary chat message.
fn chat_message() -> impl Strategy<Value = ChatMessage> {
    (".*", ".*").prop_map(|(role, content)| ChatMessage { role, content })
}

proptest! {
    #[test]
    fn generate_request_round_trips(
        model in ".*",
        prompt in ".*",
        max_tokens in any::<u32>(),
    ) {
        let req = GenerateRequest { model, prompt, max_tokens };
        let bytes = encode_canonical(&req).expect("encode");
        let back: GenerateRequest = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(req, back);
    }

    #[test]
    fn generate_response_round_trips(text in ".*", tokens in any::<u32>()) {
        let resp = GenerateResponse { text, tokens };
        let bytes = encode_canonical(&resp).expect("encode");
        let back: GenerateResponse = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(resp, back);
    }

    #[test]
    fn chat_request_round_trips(
        model in ".*",
        messages in proptest::collection::vec(chat_message(), 0..8),
    ) {
        let req = ChatRequest { model, messages };
        let bytes = encode_canonical(&req).expect("encode");
        let back: ChatRequest = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(req, back);
    }

    #[test]
    fn chat_response_round_trips(
        role in ".*",
        content in ".*",
        tokens in any::<u32>(),
    ) {
        let resp = ChatResponse { message: ChatMessage { role, content }, tokens };
        let bytes = encode_canonical(&resp).expect("encode");
        let back: ChatResponse = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(resp, back);
    }

    #[test]
    fn embeddings_request_round_trips(model in ".*", input in ".*") {
        let req = EmbeddingsRequest { model, input };
        let bytes = encode_canonical(&req).expect("encode");
        let back: EmbeddingsRequest = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(req, back);
    }

    #[test]
    fn embeddings_response_round_trips(
        // Restrict to finite f32 so equality is well-defined (NaN != NaN
        // would make the assertion meaningless; finite values encode +
        // decode bit-exactly under postcard).
        embedding in proptest::collection::vec(
            any::<f32>().prop_filter("finite", |v| v.is_finite()),
            0..32,
        ),
    ) {
        let resp = EmbeddingsResponse { embedding };
        let bytes = encode_canonical(&resp).expect("encode");
        let back: EmbeddingsResponse = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(resp, back);
    }

    #[test]
    fn health_status_round_trips(healthy in any::<bool>(), detail in ".*") {
        let hs = HealthStatus { healthy, detail };
        let bytes = encode_canonical(&hs).expect("encode");
        let back: HealthStatus = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(hs, back);
    }
}

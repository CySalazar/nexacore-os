//! Regression test against a REAL captured Ollama `/api/generate` reply.
//!
//! The fixture `ollama-generate-content-length.bin` is the byte-exact HTTP
//! response Ollama 0.x returns to a non-streamed `/api/generate` POST whose
//! body fits the Go HTTP server's write buffer: `Content-Length`-delimited
//! (larger replies switch to `Transfer-Encoding: chunked` — covered by the
//! unit tests). The bare-metal AI relay feeds exactly these bytes through
//! `response_is_complete` + `parse_response`, so this test pins the live
//! wire format end-to-end.

use nexacore_cmd_curl::{parse_response, response_is_complete};

const RAW: &[u8] = include_bytes!("fixtures/ollama-generate-content-length.bin");

#[test]
fn real_reply_is_complete() {
    assert!(response_is_complete(RAW));
    // Every strict prefix that cuts into the body must be incomplete.
    let sep = RAW
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator present");
    assert!(!response_is_complete(&RAW[..sep + 4]));
    assert!(!response_is_complete(&RAW[..RAW.len() - 1]));
}

#[test]
fn real_reply_parses_with_intact_json_body() {
    let resp = parse_response(RAW).expect("real reply must parse");
    assert_eq!(resp.status_code, 200);

    let body = core::str::from_utf8(&resp.body).expect("JSON body is UTF-8");
    // The relay's readiness check keys on these fields: a real answer has a
    // non-empty `response` and `done_reason:"stop"`. If the parser mangled
    // the body (mis-framing, stray chunk metadata), these markers vanish and
    // the relay would wrongly report the model as not-ready.
    assert!(body.starts_with('{') && body.ends_with('}'), "body is a JSON object");
    assert!(body.contains("\"response\":\""), "response field present");
    assert!(!body.contains("\"response\":\"\""), "response is non-empty");
    assert!(body.contains("\"done_reason\":\"stop\""), "done_reason is stop");
}

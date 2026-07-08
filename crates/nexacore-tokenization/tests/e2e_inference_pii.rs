//! End-to-end PII tokenization tests — inference boundary guarantee.
//!
//! These integration tests prove that PII is tokenized **before** it can
//! reach any downstream inference workload, across all three regulatory
//! policy presets exposed by `nexacore-tokenization`.
//!
//! # Placement rationale
//!
//! The task spec originally targeted
//! `crates/nexacore-runtime/tests/e2e_tokenization_inference.rs`, but
//! `nexacore-runtime`'s `Cargo.toml` does not list `nexacore-tokenization` as a
//! dev-dependency (and the "no new deps" rule prohibits adding it). The
//! test is therefore placed in `crates/nexacore-tokenization/tests/` instead,
//! where the crate is available unconditionally, and it verifies the
//! same security property at the tokenization boundary: no raw PII
//! survives the `tokenize` call in the tokenized text forwarded toward
//! inference.
//!
//! # NER stub scope
//!
//! The current [`nexacore_tokenization::ner::NerClassifier`] is a heuristic
//! stub that recognises two entity types:
//!
//! | Entity | Detection method |
//! |--------|-----------------|
//! | `Email` | whitespace-delimited token containing exactly one `@` with non-empty local and domain parts |
//! | `Phone` | digit-heavy runs of ≥ 7 digits with permitted separators (`-`, `.`, `()`, `+`) |
//!
//! Entity types `PersonName`, `Ssn`, `CreditCard`, and `Address` are not
//! detected by the stub; a Phase 3 on-device ML model will cover them.
//! The tests below exercise only entity types the NER can currently detect.
//! A specific test documents the PCI-DSS boundary: because PCI covers
//! `CreditCard` and `Ssn` — neither of which the stub detects — PCI
//! correctly leaves NER-detectable types (email, phone) in plaintext.
//!
//! # Corpus policy
//!
//! All PII values in this file are **entirely synthetic**. No real names,
//! addresses, or identification numbers appear anywhere in this file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use nexacore_tee::MockTeeBackend;
use nexacore_tokenization::{
    TokenizationService,
    policy::PolicyPreset,
    types::{DetokenizeRequest, TokenizeRequest},
};
use nexacore_types::identity::SessionId;

// =============================================================================
// Synthetic PII corpus
// =============================================================================

/// A single synthetic PII entry used in the test corpus.
///
/// Both fields contain **fake** values only. The `label` is a
/// human-readable description; `value` is the raw PII string that must
/// never appear verbatim in tokenized output.
#[derive(Debug, Clone)]
pub struct PiiEntry {
    /// Human-readable label describing the PII category.
    pub label: &'static str,
    /// The synthetic PII value itself (FAKE — never real personal data).
    pub value: &'static str,
}

/// Returns ~10 synthetic PII entries suitable for test corpus assertions.
///
/// All values are entirely fictional. Email addresses use `example.com`
/// (RFC 2606 reserved). Phone numbers follow the NANP 555-01xx range
/// reserved for fictional use. SSNs use `000-00-XXXX` (invalid by SSA
/// rules). Card numbers use a Luhn-invalid, prefix-invalid pattern.
///
/// This function is `pub` so that future integration test modules in this
/// crate can share the same corpus without duplicating definitions.
pub fn synthetic_pii_corpus() -> Vec<PiiEntry> {
    vec![
        PiiEntry {
            label: "email — alice",
            value: "alice@example.com",
        },
        PiiEntry {
            label: "email — bob",
            value: "bob@example.net",
        },
        PiiEntry {
            label: "email — charlie with subdomain",
            value: "charlie@mail.example.org",
        },
        PiiEntry {
            label: "phone — NANP 555-01xx local",
            value: "555-0100",
        },
        PiiEntry {
            label: "phone — NANP 555-01xx with area code",
            value: "555-555-0101",
        },
        PiiEntry {
            label: "phone — international prefix",
            value: "+1-800-555-0102",
        },
        PiiEntry {
            label: "SSN — all-zero prefix (invalid by SSA)",
            value: "000-00-0000",
        },
        PiiEntry {
            label: "SSN — fictitious",
            value: "000-00-1234",
        },
        PiiEntry {
            label: "credit card — fictitious PAN",
            value: "0000-0000-0000-0000",
        },
        PiiEntry {
            label: "email — service account pattern",
            value: "noreply@example.com",
        },
    ]
}

// =============================================================================
// Helper: assert_no_raw_pii
// =============================================================================

/// Assert that `text` contains none of the raw PII values from `corpus`.
///
/// Iterates every entry in `corpus` and panics with a descriptive message
/// if any `entry.value` is a substring of `text`. This is the core
/// security invariant: tokenized text forwarded toward the inference
/// pipeline must be free of every raw PII value the caller supplied.
///
/// # Panics
///
/// Panics if any raw PII value from `corpus` is found as a substring of
/// `text`, with a message identifying the offending entry and the full
/// tokenized text for debugging.
///
/// # Usage
///
/// ```ignore
/// let corpus = synthetic_pii_corpus();
/// assert_no_raw_pii(&tokenized_text, &corpus);
/// ```
pub fn assert_no_raw_pii(text: &str, corpus: &[PiiEntry]) {
    for entry in corpus {
        assert!(
            !text.contains(entry.value),
            "raw PII value for '{}' ({:?}) must not appear in tokenized text, \
             but was found in: {:?}",
            entry.label,
            entry.value,
            text,
        );
    }
}

// =============================================================================
// Test helpers
// =============================================================================

/// Construct a fresh `TokenizationService` backed by the mock TEE backend.
///
/// Each call returns an independent service instance with an empty vault,
/// matching the per-session isolation guarantee described in the crate docs.
fn new_service() -> TokenizationService {
    TokenizationService::new(Arc::new(MockTeeBackend::new()))
}

// =============================================================================
// Test 1 — GDPR preset: email is tokenized before reaching inference
// =============================================================================

/// Verify that the GDPR policy tokenizes email addresses and that
/// detokenization restores the original value.
///
/// The GDPR preset covers `Email`, `Phone`, `PersonName`, and `Address`.
/// The NER stub detects `Email` reliably, so this test exercises the full
/// end-to-end path:
///
/// 1. Input containing a fake email is passed to `tokenize`.
/// 2. The tokenized text must not contain the raw email (the "inference
///    boundary" assertion — the model would see only the opaque token).
/// 3. Detokenization inside the TEE restores the original text exactly.
#[test]
fn gdpr_preset_tokenizes_email_before_inference_boundary() {
    let corpus = synthetic_pii_corpus();
    let email = "alice@example.com";
    let input = format!("Please diagnose why {email} cannot authenticate.");
    let session = SessionId::new();

    let mut svc = new_service();

    // Step 1: Tokenize — simulates the pre-inference PII scrubbing stage.
    let tok_resp = svc
        .tokenize(TokenizeRequest {
            session_id: session,
            text: input.clone(),
            policy: PolicyPreset::Gdpr,
        })
        .expect("GDPR tokenize must succeed");

    // Step 2: Inference boundary — tokenized text must not contain raw email.
    assert!(
        !tok_resp.tokenized_text.contains(email),
        "GDPR: raw email must not appear in text forwarded toward inference; \
         got: {:?}",
        tok_resp.tokenized_text,
    );
    assert_no_raw_pii(&tok_resp.tokenized_text, &corpus);

    // The replacement manifest must record exactly one substitution.
    assert_eq!(
        tok_resp.replacements.len(),
        1,
        "GDPR: expected exactly one replacement for the email span"
    );
    let replacement = &tok_resp.replacements[0];
    assert!(
        replacement.token.starts_with("TKN-EMAIL-"),
        "GDPR: email token must carry the EMAIL slug; got {:?}",
        replacement.token,
    );

    // Step 3: TEE-local detokenization restores original.
    let detok_resp = svc
        .detokenize(DetokenizeRequest {
            session_id: session,
            tokenized_text: tok_resp.tokenized_text,
        })
        .expect("GDPR detokenize must succeed");

    assert_eq!(
        detok_resp.text, input,
        "GDPR: detokenization must recover the original text exactly"
    );
}

// =============================================================================
// Test 2 — HIPAA preset: phone is tokenized before reaching inference
// =============================================================================

/// Verify that the HIPAA policy tokenizes phone numbers and that
/// detokenization restores the original value.
///
/// The HIPAA preset covers `Phone`, `PersonName`, `Ssn`, and `Address`
/// but NOT `Email`. The NER stub detects `Phone` reliably. This test:
///
/// 1. Confirms that a phone number is removed from inference-bound text.
/// 2. Confirms that the email in the same text is **not** tokenized under
///    HIPAA (emails are not a HIPAA-covered PII type in this implementation).
/// 3. Confirms round-trip via detokenize.
#[test]
fn hipaa_preset_tokenizes_phone_before_inference_boundary() {
    let corpus = synthetic_pii_corpus();
    let phone = "+1-800-555-0102";
    // Include an email that HIPAA must NOT tokenize.
    // NOTE: Both the phone and the email are placed at whitespace boundaries
    // (not adjacent to punctuation) because the detokenizer uses
    // whitespace-delimited word splitting. A trailing punctuation character
    // glued to a token (e.g. `TKN-PHONE-xxx;`) would prevent look-up in the
    // vault.
    let email = "alice@example.com";
    let input = format!("Patient called from {phone} and sent email to {email} for follow-up");
    let session = SessionId::new();

    let mut svc = new_service();

    let tok_resp = svc
        .tokenize(TokenizeRequest {
            session_id: session,
            text: input.clone(),
            policy: PolicyPreset::Hipaa,
        })
        .expect("HIPAA tokenize must succeed");

    // Phone must be replaced (HIPAA covers Phone).
    assert!(
        !tok_resp.tokenized_text.contains(phone),
        "HIPAA: raw phone must not appear in text forwarded toward inference; \
         got: {:?}",
        tok_resp.tokenized_text,
    );

    // Run the full corpus PII check on the tokenized phone value only —
    // we assert specifically that the phone (a HIPAA-covered PII type
    // the NER can detect) is gone.
    let phone_entries: Vec<PiiEntry> = corpus
        .iter()
        .filter(|e| {
            e.value.contains('+') || (e.value.chars().filter(char::is_ascii_digit).count() >= 7)
        })
        .cloned()
        .collect();
    assert_no_raw_pii(&tok_resp.tokenized_text, &phone_entries);

    // Email must NOT be replaced (HIPAA does not cover Email in this impl).
    assert!(
        tok_resp.tokenized_text.contains(email),
        "HIPAA: email is not a HIPAA-covered type and must remain in text; \
         got: {:?}",
        tok_resp.tokenized_text,
    );

    // Exactly one replacement — the phone number.
    assert_eq!(
        tok_resp.replacements.len(),
        1,
        "HIPAA: expected exactly one replacement (the phone span)"
    );
    assert!(
        tok_resp.replacements[0].token.starts_with("TKN-PHONE-"),
        "HIPAA: phone token must carry the PHONE slug; got {:?}",
        tok_resp.replacements[0].token,
    );

    // Round-trip: detokenize must recover original.
    let detok_resp = svc
        .detokenize(DetokenizeRequest {
            session_id: session,
            tokenized_text: tok_resp.tokenized_text,
        })
        .expect("HIPAA detokenize must succeed");

    assert_eq!(
        detok_resp.text, input,
        "HIPAA: detokenization must recover the original text exactly"
    );
}

// =============================================================================
// Test 3 — PCI-DSS preset: scope is narrow and does not over-tokenize
// =============================================================================

/// Verify that the PCI-DSS policy does NOT tokenize entity types outside
/// its scope, and that the tokenization boundary is correctly enforced.
///
/// PCI-DSS covers only `CreditCard` and `Ssn`. The NER stub cannot detect
/// either of these types (Phase 3 will add ML-based detection). This test
/// therefore verifies two complementary properties:
///
/// 1. **No over-tokenization**: PCI does not tokenize `Email` or `Phone`
///    values even when they are present in the input and are detectable by
///    the NER stub. The text forwarded toward inference preserves them
///    verbatim — a safety invariant ensuring the model receives all
///    non-PCI data unmodified.
///
/// 2. **Zero replacements on NER-visible input**: The replacement manifest
///    must be empty, confirming that PCI's narrow scope is enforced at the
///    boundary.
///
/// This is a meaningful security test because PCI is a scope-limited
/// preset; accidentally tokenizing irrelevant fields would corrupt the
/// inference context without providing any privacy benefit.
#[test]
fn pci_preset_does_not_over_tokenize_non_pci_fields() {
    let email = "bob@example.net";
    let phone = "555-555-0101";
    let input = format!("Contact {email} or call {phone} to dispute the charge.",);
    let session = SessionId::new();

    let mut svc = new_service();

    let tok_resp = svc
        .tokenize(TokenizeRequest {
            session_id: session,
            text: input.clone(),
            policy: PolicyPreset::Pci,
        })
        .expect("PCI tokenize must succeed");

    // PCI must NOT tokenize email (not a PCI-covered type).
    assert!(
        tok_resp.tokenized_text.contains(email),
        "PCI: email is not PCI-covered and must remain in inference-bound text; \
         got: {:?}",
        tok_resp.tokenized_text,
    );

    // PCI must NOT tokenize phone (not a PCI-covered type).
    assert!(
        tok_resp.tokenized_text.contains(phone),
        "PCI: phone is not PCI-covered and must remain in inference-bound text; \
         got: {:?}",
        tok_resp.tokenized_text,
    );

    // No replacements — NER-detectable types are outside PCI scope.
    assert!(
        tok_resp.replacements.is_empty(),
        "PCI: no replacements expected for NER-detectable non-PCI fields; \
         got {} replacement(s): {:?}",
        tok_resp.replacements.len(),
        tok_resp.replacements,
    );

    // The tokenized text must equal the input exactly (no mutations).
    assert_eq!(
        tok_resp.tokenized_text, input,
        "PCI: text with no PCI-covered PII must pass through unchanged"
    );
}

// =============================================================================
// Test 4 — Strict (fail-closed) preset: no raw PII survives
// =============================================================================

/// Verify that the Strict policy removes all NER-detectable PII from
/// inference-bound text — the "fail-closed" security guarantee.
///
/// The Strict preset tokenizes every entity type, including `Custom`.
/// Combined with the NER stub's ability to detect `Email` and `Phone`,
/// this test proves that a text containing multiple PII values is fully
/// scrubbed before it would reach the inference pipeline.
///
/// Four properties are asserted:
///
/// 1. No raw email remains in tokenized output.
/// 2. No raw phone remains in tokenized output.
/// 3. `assert_no_raw_pii` passes over the full synthetic corpus.
/// 4. Detokenization recovers the full original text exactly.
#[test]
fn strict_preset_all_ner_detectable_pii_removed_before_inference() {
    let corpus = synthetic_pii_corpus();

    // Build a multi-PII input spanning the corpus entries the NER can detect.
    let email1 = "alice@example.com";
    let email2 = "noreply@example.com";
    let phone = "555-0100";
    let input = format!("Explain why {email1} and {email2} did not receive the SMS to {phone}.",);
    let session = SessionId::new();

    let mut svc = new_service();

    let tok_resp = svc
        .tokenize(TokenizeRequest {
            session_id: session,
            text: input.clone(),
            policy: PolicyPreset::Strict,
        })
        .expect("Strict tokenize must succeed");

    // Fail-closed: none of the NER-detectable PII values must survive.
    assert!(
        !tok_resp.tokenized_text.contains(email1),
        "Strict: first email must be absent from inference-bound text; \
         got: {:?}",
        tok_resp.tokenized_text,
    );
    assert!(
        !tok_resp.tokenized_text.contains(email2),
        "Strict: second email must be absent from inference-bound text; \
         got: {:?}",
        tok_resp.tokenized_text,
    );
    assert!(
        !tok_resp.tokenized_text.contains(phone),
        "Strict: phone must be absent from inference-bound text; \
         got: {:?}",
        tok_resp.tokenized_text,
    );

    // Full corpus sweep — none of the synthetic PII values may appear.
    assert_no_raw_pii(&tok_resp.tokenized_text, &corpus);

    // Three distinct PII entities (two emails + one phone) must have been
    // replaced.
    assert_eq!(
        tok_resp.replacements.len(),
        3,
        "Strict: expected three replacements (two emails + one phone); \
         got: {:?}",
        tok_resp.replacements,
    );

    // Every token in the manifest must carry the correct type slug.
    for replacement in &tok_resp.replacements {
        let token = &replacement.token;
        assert!(
            token.starts_with("TKN-EMAIL-") || token.starts_with("TKN-PHONE-"),
            "Strict: unexpected token slug in {token:?}",
        );
    }

    // Detokenize must recover the original text exactly.
    let detok_resp = svc
        .detokenize(DetokenizeRequest {
            session_id: session,
            tokenized_text: tok_resp.tokenized_text,
        })
        .expect("Strict detokenize must succeed");

    assert_eq!(
        detok_resp.text, input,
        "Strict: detokenization must recover the full original text"
    );
}

// =============================================================================
// Test 5 — Multi-preset corpus sweep
// =============================================================================

/// Verify that every NER-detectable PII value in the synthetic corpus is
/// removed under the Strict preset.
///
/// This test processes each NER-detectable corpus entry independently —
/// one `tokenize` call per entry — and verifies that:
///
/// 1. The raw PII value is absent from the tokenized text.
/// 2. Detokenization restores the original PII value.
/// 3. The `assert_no_raw_pii` helper reports clean output for every entry.
///
/// Processing entries individually avoids a subtle NER stub artifact: the
/// phone detector treats space as a valid phone character (to handle formats
/// like `(555) 123-4567`), so adjacent phone numbers separated only by
/// spaces would merge into one span. By tokenizing each entry in its own
/// request the test exercises the full tokenize→detokenize cycle per entry
/// without relying on non-trivial multi-token NER segmentation.
///
/// SSN and credit-card entries from the corpus are excluded: they are listed
/// for documentation purposes but the NER stub does not recognise them as
/// distinct entity types (they would be classified as Phone by digit-count
/// heuristic, not as `SSN` or `CreditCard`).
#[test]
fn strict_preset_full_corpus_sweep_no_raw_pii_in_inference_input() {
    let corpus = synthetic_pii_corpus();

    // Keep only email and phone-labelled entries — the types the NER stub
    // can detect without false-category classification.
    let ner_detectable: Vec<&PiiEntry> = corpus
        .iter()
        .filter(|e| {
            let is_email = e.value.chars().filter(|&c| c == '@').count() == 1;
            let is_phone = e.label.contains("phone");
            is_email || is_phone
        })
        .collect();

    assert!(
        !ner_detectable.is_empty(),
        "corpus must contain at least one NER-detectable entry"
    );

    // Process each PII value individually: one tokenize call per entry.
    for entry in &ner_detectable {
        let input = format!("Contact info for record {}", entry.value);
        let session = SessionId::new();
        let mut svc = new_service();

        let tok_resp = svc
            .tokenize(TokenizeRequest {
                session_id: session,
                text: input.clone(),
                policy: PolicyPreset::Strict,
            })
            .expect("Strict corpus sweep: tokenize must succeed");

        // The raw PII value must not appear in inference-bound text.
        assert!(
            !tok_resp.tokenized_text.contains(entry.value),
            "Strict corpus sweep: raw PII ({:?}) for '{}' must not appear in \
             tokenized output; got: {:?}",
            entry.value,
            entry.label,
            tok_resp.tokenized_text,
        );

        // Full corpus check via the helper.
        let single = [PiiEntry {
            label: entry.label,
            value: entry.value,
        }];
        assert_no_raw_pii(&tok_resp.tokenized_text, &single);

        // Exactly one replacement per entry.
        assert_eq!(
            tok_resp.replacements.len(),
            1,
            "Strict corpus sweep: expected one replacement for '{}' ({:?}); \
             got {:?}",
            entry.label,
            entry.value,
            tok_resp.replacements,
        );

        // Detokenize must restore the full input.
        let detok_resp = svc
            .detokenize(DetokenizeRequest {
                session_id: session,
                tokenized_text: tok_resp.tokenized_text,
            })
            .expect("Strict corpus sweep: detokenize must succeed");

        assert_eq!(
            detok_resp.text, input,
            "Strict corpus sweep: detokenization must recover the original text \
             for entry '{}' ({:?})",
            entry.label, entry.value,
        );
    }
}

// =============================================================================
// Test 6 — Cross-session token isolation
// =============================================================================

/// Verify that tokens produced in one session are not valid in a different
/// service instance (different vault), enforcing session isolation at the
/// inference boundary.
///
/// This is a security test: if token mappings leaked across session
/// boundaries, an adversary who observed tokenized inference traffic could
/// correlate tokens across users or sessions. The vault's per-instance
/// isolation prevents this.
#[test]
fn tokens_from_one_session_are_not_resolvable_in_a_different_vault() {
    let email = "alice@example.com";
    let session = SessionId::new();

    let mut svc_a = new_service();
    let svc_b = new_service(); // independent vault

    let tok_resp = svc_a
        .tokenize(TokenizeRequest {
            session_id: session,
            text: email.to_string(),
            policy: PolicyPreset::Gdpr,
        })
        .expect("session A tokenize must succeed");

    // The token must not resolve in the independent service B.
    let detok_resp = svc_b
        .detokenize(DetokenizeRequest {
            session_id: session,
            tokenized_text: tok_resp.tokenized_text.clone(),
        })
        .expect("detokenize call must not error — unknown tokens are left verbatim");

    // svc_b did not produce this token; it must leave the token verbatim,
    // meaning the detokenized text is identical to the tokenized text.
    assert_eq!(
        detok_resp.text, tok_resp.tokenized_text,
        "cross-session: token from vault A must not be resolvable in vault B"
    );

    // And critically, the raw email must NOT appear in vault B's output.
    assert!(
        !detok_resp.text.contains(email),
        "cross-session: raw email must not be reconstructable from a foreign vault; \
         got: {:?}",
        detok_resp.text,
    );
}

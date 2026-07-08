//! Tokenization pre-processing pipeline.
//!
//! Scans inference input for Personally Identifiable Information (PII) before
//! forwarding it to the model, and reverses the tokenization on the output so
//! the caller receives natural text.
//!
//! ## Phase 2 scope
//!
//! This is a **Phase 2 stub**. The detection algorithm uses simple byte-level
//! string scanning (no external regex crate, no ML-based NER). It is
//! intentionally conservative — false negatives are acceptable in Phase 2
//! because the goal is establishing the pipeline shape, not production-quality
//! PII protection. A full NER-backed implementation (using `NerClassifier` from
//! `nexacore-tokenization`) will replace this stub in Phase 3.
//!
//! ## Detected entity classes
//!
//! | Class | Pattern | Token form |
//! |-------|---------|------------|
//! | `email_address` | `word@word.word` (at least one `@` with surrounding alphanum and a `.` in the domain part) | `[PII:email_address:XXXX]` |
//! | `phone_number` | 10 or more consecutive ASCII digits, optionally separated by spaces or hyphens | `[PII:phone_number:XXXX]` |
//!
//! ## Security note
//!
//! This module makes **no cryptographic guarantees**. PII replacement is done
//! in-process memory; a compromised runtime could observe the original values.
//! Cryptographic PII tokenization (TEE-backed `TokenVault`) is tracked in
//! `/todo.md` Phase 3.

use tracing::{debug, instrument};

// =============================================================================
// Constants
// =============================================================================

/// Minimum number of consecutive digit characters that constitute a phone
/// number. ITU-T E.164 allows up to 15 digits; we use 10 as the lower bound
/// (shortest NANP number without country code).
const MIN_PHONE_DIGITS: usize = 10;

// =============================================================================
// PreprocessedInput
// =============================================================================

/// The result of running text through the pre-processing pipeline.
///
/// Callers receive this after [`PreprocessingPipeline::preprocess`] runs.
/// The `processed_text` field is safe to forward to the model; the original
/// PII has been replaced with opaque tokens.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::preprocessing::PreprocessingPipeline;
///
/// let pp = PreprocessingPipeline::new();
/// let input = pp.preprocess("Contact alice@example.com for details.");
/// assert_eq!(input.entities_found, 1);
/// assert!(input.entity_types.contains(&"email_address".to_string()));
/// ```
#[derive(Clone, Debug)]
pub struct PreprocessedInput {
    /// Input text with PII replaced by opaque tokens.
    pub processed_text: String,
    /// Total number of PII entities detected and replaced.
    pub entities_found: usize,
    /// Deduplicated list of entity type names that were found.
    pub entity_types: Vec<String>,
}

// =============================================================================
// PreprocessingPipeline
// =============================================================================

/// Pre-processing pipeline that scans input for PII before inference.
///
/// The pipeline provides three operations:
///
/// 1. [`tokenize_pii`][Self::tokenize_pii] — replace PII spans with tokens,
///    return the sanitised text and the count of replacements made.
/// 2. [`detokenize_pii`][Self::detokenize_pii] — remove PII tokens from output
///    text (Phase 2: token removal only; re-injection requires the TEE vault).
/// 3. [`preprocess`][Self::preprocess] — full pipeline: tokenize + collect
///    entity metadata.
///
/// # Thread safety
///
/// `PreprocessingPipeline` holds no mutable state. It is `Send + Sync` and
/// may be wrapped in an `Arc` and shared across tasks without a mutex.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::preprocessing::PreprocessingPipeline;
///
/// let pp = PreprocessingPipeline::new();
/// let result = pp.preprocess("Call 1234567890 or email bob@corp.io");
/// assert_eq!(result.entities_found, 2);
/// ```
#[derive(Clone, Debug, Default)]
pub struct PreprocessingPipeline;

impl PreprocessingPipeline {
    /// Create a new preprocessing pipeline.
    ///
    /// ```rust
    /// use nexacore_runtime::preprocessing::PreprocessingPipeline;
    /// let _pp = PreprocessingPipeline::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan `input` for PII entities and replace each with an opaque token.
    ///
    /// Returns `(sanitised_text, entity_count)` where `entity_count` is the
    /// number of PII spans replaced. The order of replacement is:
    /// email addresses first, then phone numbers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::preprocessing::PreprocessingPipeline;
    ///
    /// let pp = PreprocessingPipeline::new();
    /// let (out, count) = pp.tokenize_pii("Reach me at hi@example.org");
    /// assert_eq!(count, 1);
    /// assert!(out.contains("[PII:email_address:XXXX]"));
    /// ```
    // `self` is not used in Phase 2 but is kept in the signature so that
    // Phase 3 can add instance state (TEE vault handle, policy config) without
    // a breaking API change.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn tokenize_pii(&self, input: &str) -> (String, usize) {
        let (after_email, email_count) = replace_emails(input);
        let (after_phone, phone_count) = replace_phones(&after_email);
        (after_phone, email_count + phone_count)
    }

    /// Remove PII tokens from `output` text.
    ///
    /// In Phase 2 this strips the placeholder tokens rather than re-injecting
    /// the original values (re-injection requires the TEE-backed `TokenVault`
    /// from `nexacore-tokenization`, which lands in Phase 3).
    ///
    /// ```rust
    /// use nexacore_runtime::preprocessing::PreprocessingPipeline;
    ///
    /// let pp = PreprocessingPipeline::new();
    /// let out = pp.detokenize_pii("Contact [PII:email_address:XXXX] for help.");
    /// assert!(!out.contains("[PII:email_address:XXXX]"));
    /// ```
    // `self` is not used in Phase 2 but is kept for the same reason as
    // `tokenize_pii`: Phase 3 will store per-instance vault state here.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn detokenize_pii(&self, output: &str) -> String {
        // Phase 2 stub: strip known PII tokens.
        // Phase 3 will replace each token with the value retrieved from the
        // TEE-backed TokenVault keyed on the XXXX identifier.
        output
            .replace("[PII:email_address:XXXX]", "<email>")
            .replace("[PII:phone_number:XXXX]", "<phone>")
    }

    /// Process `input` through the full pipeline: PII scan → tokenize →
    /// collect entity metadata.
    ///
    /// This is the main entry point for callers that want a single call to
    /// sanitise text before forwarding it to the inference pipeline.
    ///
    /// ```rust
    /// use nexacore_runtime::preprocessing::PreprocessingPipeline;
    ///
    /// let pp = PreprocessingPipeline::new();
    /// let result = pp.preprocess("Email me at dev@nexacore-os.org or call 12345678901");
    /// assert!(result.entities_found >= 1);
    /// assert!(!result.processed_text.contains("dev@nexacore-os.org"));
    /// ```
    // Same rationale as the other methods: `self` is kept for future state.
    #[allow(clippy::unused_self, clippy::cognitive_complexity)]
    #[instrument(skip(self))]
    #[must_use]
    pub fn preprocess(&self, input: &str) -> PreprocessedInput {
        debug!(input_len = input.len(), "preprocessing: scanning for PII");

        // Run email and phone replacements individually so we can track which
        // entity types were encountered.
        let (after_email, email_count) = replace_emails(input);
        let (after_phone, phone_count) = replace_phones(&after_email);

        let entities_found = email_count + phone_count;

        let mut entity_types: Vec<String> = Vec::new();
        if email_count > 0 {
            entity_types.push("email_address".to_string());
        }
        if phone_count > 0 {
            entity_types.push("phone_number".to_string());
        }

        debug!(
            entities_found,
            entity_types = ?entity_types,
            "preprocessing: scan complete"
        );

        PreprocessedInput {
            processed_text: after_phone,
            entities_found,
            entity_types,
        }
    }
}

// =============================================================================
// Internal helpers — PII detection / replacement
// =============================================================================

/// Replace email addresses in `input` with `[PII:email_address:XXXX]`.
///
/// Detection heuristic: a token is treated as an email if it contains exactly
/// one `@` character, has at least one non-`@` character on each side, and the
/// part after `@` contains at least one `.` followed by at least one character.
///
/// This deliberately avoids pulling in the `regex` crate (no new dependency)
/// and favours correctness-of-intent over completeness — false negatives are
/// acceptable in Phase 2.
fn replace_emails(input: &str) -> (String, usize) {
    let mut result = String::with_capacity(input.len());
    let mut count = 0usize;

    // Tokenise on whitespace boundaries; reassemble with the same spacing.
    // We preserve the surrounding punctuation by scanning the word for a
    // clean email span.
    let mut first = true;
    for word in input.split_inclusive(char::is_whitespace) {
        if !first {
            // split_inclusive keeps the whitespace attached to the preceding
            // token, so we do not add a separator here.
        }
        first = false;

        if let Some(replaced) = try_replace_email_in_word(word) {
            result.push_str(&replaced);
            count += 1;
        } else {
            result.push_str(word);
        }
    }

    (result, count)
}

/// If `word` (potentially surrounded by punctuation) contains an email span,
/// replace that span and return the modified string. Returns `None` if no
/// email is found.
fn try_replace_email_in_word(word: &str) -> Option<String> {
    // Locate the `@` sign.
    let at_pos = word.find('@')?;

    // There must be at least one non-`@` character before the `@`.
    if at_pos == 0 {
        return None;
    }

    // Walk backward from `at_pos` to find the start of the local part.
    // `map_or` is used instead of `map(..).unwrap_or(..)` to satisfy clippy.
    let local_start = word[..at_pos]
        .rfind(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_')
        .map_or(0, |p| p + 1); // character after the boundary (0 if none)

    // Walk forward from `at_pos + 1` to find the end of the domain part.
    let domain_part_start = at_pos + 1;
    if domain_part_start >= word.len() {
        return None;
    }

    let domain_end = word[domain_part_start..]
        .find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_')
        .map_or(word.len(), |p| domain_part_start + p);

    let domain = &word[domain_part_start..domain_end];

    // Domain must contain at least one dot followed by at least one char.
    let dot_in_domain = domain.rfind('.');
    match dot_in_domain {
        Some(dot_pos) if dot_pos + 1 < domain.len() => {}
        _ => return None,
    }

    // Build the replacement string.
    let mut out = String::with_capacity(word.len());
    out.push_str(&word[..local_start]);
    out.push_str("[PII:email_address:XXXX]");
    out.push_str(&word[domain_end..]);

    Some(out)
}

/// Replace phone numbers (10+ consecutive ASCII digits) in `input` with
/// `[PII:phone_number:XXXX]`.
///
/// The scanner accumulates digit characters (and common separators: spaces,
/// hyphens, parentheses, dots) and flushes a replacement when a run of
/// digits reaches `MIN_PHONE_DIGITS`.
fn replace_phones(input: &str) -> (String, usize) {
    let mut result = String::with_capacity(input.len());
    let mut count = 0usize;

    // State machine: track a candidate digit run.
    let mut digit_buf = String::new();
    let mut raw_buf = String::new(); // the exact chars (digits + separators) seen
    let mut digit_count = 0usize;

    let flush_no_match =
        |result: &mut String, raw: &mut String, digits: &mut String, dc: &mut usize| {
            result.push_str(raw);
            raw.clear();
            digits.clear();
            *dc = 0;
        };

    for ch in input.chars() {
        if ch.is_ascii_digit() {
            digit_buf.push(ch);
            raw_buf.push(ch);
            digit_count += 1;
        } else if matches!(ch, ' ' | '-' | '(' | ')' | '.' | '+')
            && digit_count > 0
            && !digit_buf.is_empty()
        {
            // Allow separator characters within a candidate phone span.
            raw_buf.push(ch);
        } else {
            // Non-digit, non-separator character: decide whether we matched.
            if digit_count >= MIN_PHONE_DIGITS {
                result.push_str("[PII:phone_number:XXXX]");
                count += 1;
            } else {
                flush_no_match(&mut result, &mut raw_buf, &mut digit_buf, &mut digit_count);
            }
            raw_buf.clear();
            digit_buf.clear();
            digit_count = 0;
            result.push(ch);
        }
    }

    // Flush any trailing candidate.
    if digit_count >= MIN_PHONE_DIGITS {
        result.push_str("[PII:phone_number:XXXX]");
        count += 1;
    } else if !raw_buf.is_empty() {
        result.push_str(&raw_buf);
    }

    (result, count)
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Email detection
    // -------------------------------------------------------------------------

    #[test]
    fn detect_simple_email() {
        let pp = PreprocessingPipeline::new();
        let (out, count) = pp.tokenize_pii("Send to alice@example.com please");
        assert_eq!(count, 1);
        assert!(out.contains("[PII:email_address:XXXX]"));
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn detect_email_at_start_of_string() {
        let pp = PreprocessingPipeline::new();
        let (out, count) = pp.tokenize_pii("bob@corp.io is the contact");
        assert_eq!(count, 1);
        assert!(out.contains("[PII:email_address:XXXX]"));
    }

    #[test]
    fn detect_email_with_dots_in_local_part() {
        let pp = PreprocessingPipeline::new();
        let (out, count) = pp.tokenize_pii("first.last@subdomain.example.org");
        assert_eq!(count, 1);
        assert!(out.contains("[PII:email_address:XXXX]"));
    }

    #[test]
    fn no_email_in_plain_text() {
        let pp = PreprocessingPipeline::new();
        let (out, count) = pp.tokenize_pii("hello world, no PII here");
        assert_eq!(count, 0);
        assert_eq!(out, "hello world, no PII here");
    }

    // -------------------------------------------------------------------------
    // Phone detection
    // -------------------------------------------------------------------------

    #[test]
    fn detect_ten_digit_phone() {
        let pp = PreprocessingPipeline::new();
        let (out, count) = pp.tokenize_pii("Call 1234567890 now");
        assert_eq!(count, 1);
        assert!(out.contains("[PII:phone_number:XXXX]"));
        assert!(!out.contains("1234567890"));
    }

    #[test]
    fn nine_digits_not_a_phone() {
        let pp = PreprocessingPipeline::new();
        let (_, count) = pp.tokenize_pii("Code 123456789 is valid");
        assert_eq!(count, 0);
    }

    #[test]
    fn eleven_digit_phone_detected() {
        let pp = PreprocessingPipeline::new();
        let (out, count) = pp.tokenize_pii("International: 12345678901");
        assert_eq!(count, 1);
        assert!(out.contains("[PII:phone_number:XXXX]"));
    }

    // -------------------------------------------------------------------------
    // Detokenize
    // -------------------------------------------------------------------------

    #[test]
    fn detokenize_strips_email_token() {
        let pp = PreprocessingPipeline::new();
        let out = pp.detokenize_pii("Contact [PII:email_address:XXXX] for info.");
        assert!(!out.contains("[PII:email_address:XXXX]"));
        assert!(out.contains("<email>"));
    }

    #[test]
    fn detokenize_strips_phone_token() {
        let pp = PreprocessingPipeline::new();
        let out = pp.detokenize_pii("Call [PII:phone_number:XXXX] tomorrow.");
        assert!(!out.contains("[PII:phone_number:XXXX]"));
        assert!(out.contains("<phone>"));
    }

    #[test]
    fn detokenize_noop_on_clean_text() {
        let pp = PreprocessingPipeline::new();
        let text = "No PII in this response.";
        let out = pp.detokenize_pii(text);
        assert_eq!(out, text);
    }

    // -------------------------------------------------------------------------
    // preprocess — full pipeline
    // -------------------------------------------------------------------------

    #[test]
    fn preprocess_detects_email_and_phone() {
        let pp = PreprocessingPipeline::new();
        let result = pp.preprocess("Email dev@nexacore-os.org or call 12345678901");
        assert_eq!(result.entities_found, 2);
        assert!(result.entity_types.contains(&"email_address".to_string()));
        assert!(result.entity_types.contains(&"phone_number".to_string()));
    }

    #[test]
    fn preprocess_clean_input_has_zero_entities() {
        let pp = PreprocessingPipeline::new();
        let result = pp.preprocess("This is a normal query about the weather.");
        assert_eq!(result.entities_found, 0);
        assert!(result.entity_types.is_empty());
    }

    #[test]
    fn preprocess_preserves_non_pii_text() {
        let pp = PreprocessingPipeline::new();
        let result = pp.preprocess("Explain what a kernel is");
        assert!(result.processed_text.contains("Explain what a kernel is"));
    }

    #[test]
    fn preprocess_removes_email_from_processed_text() {
        let pp = PreprocessingPipeline::new();
        let result = pp.preprocess("Contact admin@server.net for access");
        assert!(!result.processed_text.contains("admin@server.net"));
        assert!(result.processed_text.contains("[PII:email_address:XXXX]"));
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn empty_input_is_handled() {
        let pp = PreprocessingPipeline::new();
        let result = pp.preprocess("");
        assert_eq!(result.entities_found, 0);
        assert_eq!(result.processed_text, "");
    }

    #[test]
    fn input_with_only_at_sign_not_matched() {
        let pp = PreprocessingPipeline::new();
        let (_, count) = pp.tokenize_pii("@ is a symbol");
        assert_eq!(count, 0);
    }

    #[test]
    fn entity_types_list_is_deduplicated_by_type() {
        // Two emails → entity_types should contain "email_address" once.
        let pp = PreprocessingPipeline::new();
        let result = pp.preprocess("a@b.com and c@d.org are contacts");
        assert_eq!(
            result
                .entity_types
                .iter()
                .filter(|t| *t == "email_address")
                .count(),
            1,
            "email_address should appear once in entity_types even if two emails found"
        );
    }
}

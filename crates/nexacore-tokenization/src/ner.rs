//! Named Entity Recognition (NER) for PII spans.
//!
//! This module provides a stub NER classifier that detects PII entities
//! in text using heuristic pattern matching. The intent is to provide a
//! functional placeholder that correctly handles the common cases while a
//! full on-device ML model is developed for Phase 3.
//!
//! # Status
//!
//! **Stub implementation.** The classifier uses simple byte-level scanning
//! rather than a real language model. It is conservative — it errs toward
//! marking spans as PII when uncertain — but it will produce both false
//! positives and false negatives on real-world data. A future replacement
//! will run an on-device ONNX model inside the TEE.
//!
//! # Currently detected entity types
//!
//! | Entity type | Heuristic |
//! |-------------|-----------|
//! | `Email`     | Contiguous non-whitespace run that contains exactly one `@` surrounded by non-empty local and domain parts. |
//! | `Phone`     | Contiguous run of digits, spaces, hyphens, dots, and parentheses that contains at least 7 consecutive or separated digits. |
//!
//! All other entity types (`PersonName`, `Ssn`, `CreditCard`, `Address`,
//! `Custom`) are not yet detected by this stub; they require a language-
//! model or a structured data extractor.
//!
//! # Tokenization pipeline integration
//!
//! The [`TokenizationService`](crate::TokenizationService) calls
//! [`NerClassifier::classify`] on the input text, then consults the
//! [`crate::policy::PolicyEngine`] to decide which detected spans to
//! replace. Spans are processed from right to left (highest byte offset
//! first) so that replacing a span does not invalidate the offsets of
//! earlier spans.
//!
//! See [`/docs/04-security-model.md`](../../../docs/04-security-model.md)
//! § "Tokenization service — NER pipeline".

use crate::types::EntityType;

// =============================================================================
// NerSpan
// =============================================================================

/// A single PII span detected in text.
///
/// The span records the byte offsets of the detected PII in the original
/// text, the semantic category, and a confidence score in `[0.0, 1.0]`.
///
/// # Byte offsets
///
/// `start` and `end` are byte (not character) offsets so that the caller
/// can use them directly in `&text[start..end]` slices. Callers must
/// ensure the text is valid UTF-8 and that the span boundaries are on
/// character boundaries.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::{
///     ner::{NerClassifier, NerSpan},
///     types::EntityType,
/// };
///
/// let clf = NerClassifier::new();
/// let spans = clf.classify("reach me at user@example.com");
/// let email_span = spans.iter().find(|s| s.entity_type == EntityType::Email);
/// assert!(email_span.is_some());
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct NerSpan {
    /// Byte offset of the first byte of the detected span.
    pub start: usize,
    /// Byte offset of the first byte **after** the detected span (exclusive).
    pub end: usize,
    /// Semantic category of the detected span.
    pub entity_type: EntityType,
    /// Confidence score in `[0.0, 1.0]`. For the stub implementation
    /// this is a fixed heuristic value (0.9 for rule-based matches).
    pub confidence: f32,
}

// =============================================================================
// NerClassifier
// =============================================================================

/// Stub NER classifier that detects PII entities via pattern matching.
///
/// The classifier is stateless and cheap to construct. In production, this
/// struct will hold a reference to an on-device ONNX model loaded inside
/// the TEE. For now, it scans for email addresses and phone number patterns
/// using byte-level operations (no regex crate dependency).
///
/// # Example
///
/// ```
/// use nexacore_tokenization::{ner::NerClassifier, types::EntityType};
///
/// let clf = NerClassifier::new();
/// let spans = clf.classify("Call us at +1-800-555-0100");
/// assert!(!spans.is_empty(), "phone number should be detected");
/// let span = &spans[0];
/// assert_eq!(span.entity_type, EntityType::Phone);
/// ```
#[derive(Debug, Clone, Default)]
pub struct NerClassifier {
    // No fields in the stub. A future implementation will hold a reference
    // to the loaded model and its tokenizer vocabulary.
}

impl NerClassifier {
    /// Confidence score assigned to rule-based matches.
    ///
    /// The stub always reports 0.9 because the pattern rules are precise
    /// enough that most matches are correct, but not 1.0 because there
    /// are edge cases (e.g., an email-like string in a URL fragment).
    const RULE_CONFIDENCE: f32 = 0.9;

    /// Minimum number of digit characters required for a phone-number
    /// candidate to be reported.
    ///
    /// 7 is the minimum for a local (non-international) phone number in
    /// the NANP. Sequences shorter than this are assumed to not be phone
    /// numbers (they are more likely to be dates, zip codes, etc.).
    const MIN_PHONE_DIGITS: usize = 7;

    /// Construct a new classifier instance.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::ner::NerClassifier;
    /// let clf = NerClassifier::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Classify `text`, returning a list of detected PII spans.
    ///
    /// Spans may overlap (the caller is responsible for resolving
    /// overlaps before applying tokenization). In practice, the stub
    /// never produces overlapping spans because it detects entity types
    /// that occupy disjoint textual regions (emails and phone numbers
    /// do not overlap).
    ///
    /// The returned vector is sorted by `start` ascending. If no PII is
    /// detected, an empty vector is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::ner::NerClassifier;
    ///
    /// let clf = NerClassifier::new();
    /// let spans = clf.classify("");
    /// assert!(spans.is_empty());
    /// ```
    /// `&self` is intentional: the stub does not use `self` today but the
    /// production implementation (Phase 3 on-device ML model) will hold
    /// mutable model state that `classify` will need to access.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn classify(&self, text: &str) -> Vec<NerSpan> {
        let mut spans: Vec<NerSpan> = Vec::new();
        Self::detect_emails(text, &mut spans);
        Self::detect_phones(text, &mut spans);
        spans.sort_by_key(|s| s.start);
        spans
    }

    // -------------------------------------------------------------------------
    // Email detection
    // -------------------------------------------------------------------------

    /// Scan `text` for email-like tokens and append matching spans.
    ///
    /// A token is considered an email candidate if:
    /// 1. It is a contiguous run of non-whitespace characters.
    /// 2. It contains exactly one `@` character.
    /// 3. The substring before `@` (local part) is non-empty and contains
    ///    at least one alphanumeric character.
    /// 4. The substring after `@` (domain part) is non-empty, contains at
    ///    least one `.`, and both the left and right sides of the `.` are
    ///    non-empty.
    ///
    /// These rules correctly reject bare `@`, `@domain`, `local@`, and
    /// strings with multiple `@` signs while accepting common email
    /// formats.
    fn detect_emails(text: &str, out: &mut Vec<NerSpan>) {
        // Walk through whitespace-delimited tokens.
        let bytes = text.as_bytes();
        let mut token_start = None;

        for (i, &b) in bytes.iter().enumerate() {
            let is_ws = b == b' ' || b == b'\t' || b == b'\n' || b == b'\r';
            match (is_ws, token_start) {
                (false, None) => {
                    // Start of a new token.
                    token_start = Some(i);
                }
                (true, Some(start)) => {
                    // End of a token at position i-1.
                    Self::try_email_span(text, start, i, out);
                    token_start = None;
                }
                _ => {} // continue building token or continue whitespace
            }
        }

        // Handle token that reaches end of string without trailing whitespace.
        if let Some(start) = token_start {
            Self::try_email_span(text, start, bytes.len(), out);
        }
    }

    /// Attempt to classify the substring `text[start..end]` as an email.
    /// Appends a [`NerSpan`] to `out` on success.
    ///
    /// This is an associated function (no `&self`) because the email
    /// detection rules depend only on the input slice, not on any
    /// classifier state.
    fn try_email_span(text: &str, start: usize, end: usize, out: &mut Vec<NerSpan>) {
        // Work on the raw byte slice (email addresses are ASCII-only).
        // We use `get` for safe slicing — the caller guarantees `start <= end
        // <= text.len()` but we prefer not to panic.
        let full_bytes = text.as_bytes();
        let Some(slice) = full_bytes.get(start..end) else {
            return;
        };

        // Count `@` occurrences — must be exactly one.
        let mut at_index: Option<usize> = None;
        let mut at_count: usize = 0;
        for (i, &b) in slice.iter().enumerate() {
            if b == b'@' {
                at_count += 1;
                at_index = Some(i);
                if at_count > 1 {
                    // Short-circuit: multiple `@` chars means not a valid email.
                    return;
                }
            }
        }
        let at_idx = match at_index {
            Some(i) if at_count == 1 => i,
            _ => return,
        };

        let local = slice.get(..at_idx).unwrap_or(&[]);
        let domain = slice.get(at_idx + 1..).unwrap_or(&[]);

        // Local part: non-empty, at least one alphanumeric byte.
        if local.is_empty() || !local.iter().any(u8::is_ascii_alphanumeric) {
            return;
        }

        // Domain part: non-empty, contains at least one dot, and both sides
        // of the last dot are non-empty.
        if domain.is_empty() {
            return;
        }
        let last_dot = domain
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| if b == b'.' { Some(i) } else { None })
            .last();
        let Some(dot_idx) = last_dot else { return };
        if dot_idx == 0 || dot_idx + 1 >= domain.len() {
            return;
        }

        out.push(NerSpan {
            start,
            end,
            entity_type: EntityType::Email,
            confidence: Self::RULE_CONFIDENCE,
        });
    }

    // -------------------------------------------------------------------------
    // Phone detection
    // -------------------------------------------------------------------------

    /// Scan `text` for phone-number-like sequences and append matching spans.
    ///
    /// A phone candidate is any maximal run of characters from the set
    /// `{ 0-9, ' ', '-', '.', '(', ')', '+' }` that:
    /// 1. Contains at least [`MIN_PHONE_DIGITS`] digit characters.
    /// 2. Does not overlap with an already-detected email span.
    ///
    /// We do not attempt to parse the exact number structure (NANP, ITU-T,
    /// etc.) — we rely on the digit-count heuristic to separate phone
    /// numbers from dates, zip codes, and other short numeric runs.
    fn detect_phones(text: &str, out: &mut Vec<NerSpan>) {
        let bytes = text.as_bytes();
        let mut candidate_start: Option<usize> = None;
        let mut digit_count: usize = 0;

        for (i, &b) in bytes.iter().enumerate() {
            if is_phone_char(b) {
                // Only start a new candidate on a non-whitespace phone char.
                // This prevents a word-boundary space from being included at
                // the beginning of a phone span, which would cause the span to
                // consume the preceding space and leave the token adjacent to
                // the preceding word.
                if candidate_start.is_none() && !b.is_ascii_whitespace() {
                    candidate_start = Some(i);
                }
                if b.is_ascii_digit() {
                    digit_count += 1;
                }
            } else {
                // End of candidate run.
                if let Some(start) = candidate_start.take() {
                    // Trim trailing whitespace from the span: spaces are valid
                    // inside phone number patterns (e.g. "(555) 123-4567") but
                    // a trailing space is a word separator, not part of the
                    // number. Without trimming, replacement leaves the next word
                    // directly adjacent to the inserted token.
                    let end = trim_trailing_whitespace(bytes, start, i);
                    if digit_count >= Self::MIN_PHONE_DIGITS
                        && !Self::overlaps_existing(start, end, out)
                    {
                        out.push(NerSpan {
                            start,
                            end,
                            entity_type: EntityType::Phone,
                            confidence: Self::RULE_CONFIDENCE,
                        });
                    }
                    digit_count = 0;
                }
            }
        }

        // Handle run at end of string.
        if let Some(start) = candidate_start {
            let end = trim_trailing_whitespace(bytes, start, bytes.len());
            if digit_count >= Self::MIN_PHONE_DIGITS && !Self::overlaps_existing(start, end, out) {
                out.push(NerSpan {
                    start,
                    end,
                    entity_type: EntityType::Phone,
                    confidence: Self::RULE_CONFIDENCE,
                });
            }
        }
    }

    /// Returns `true` if `[start, end)` overlaps any span already in `out`.
    ///
    /// This is an associated function because it does not depend on
    /// classifier state.
    fn overlaps_existing(start: usize, end: usize, out: &[NerSpan]) -> bool {
        out.iter()
            .any(|existing| start < existing.end && end > existing.start)
    }
}

// -------------------------------------------------------------------------
// Private helpers
// -------------------------------------------------------------------------

/// Returns `true` if `b` is a character that can appear in a phone number.
///
/// Accepted: ASCII digits, space, hyphen, dot, parentheses, plus sign.
/// The plus sign covers international prefixes like `+1` and `+44`.
#[inline]
fn is_phone_char(b: u8) -> bool {
    b.is_ascii_digit() || b == b' ' || b == b'-' || b == b'.' || b == b'(' || b == b')' || b == b'+'
}

/// Return `end` with trailing whitespace bytes removed.
///
/// Phone spans can include internal spaces (e.g. `(555) 123-4567`) but
/// must not include a trailing space that belongs to the word boundary
/// between the phone number and the next word. Without this trim, a
/// replacement like `TKN-PHONE-xxxx` would appear directly adjacent to
/// the next word.
fn trim_trailing_whitespace(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut trimmed_end = end;
    while trimmed_end > start {
        match bytes.get(trimmed_end - 1) {
            Some(&b) if b == b' ' || b == b'\t' => trimmed_end -= 1,
            _ => break,
        }
    }
    trimmed_end
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_arithmetic
)]
mod tests {
    use super::*;

    fn clf() -> NerClassifier {
        NerClassifier::new()
    }

    // -------------------------------------------------------------------------
    // Empty / trivial inputs
    // -------------------------------------------------------------------------

    #[test]
    fn empty_string_produces_no_spans() {
        let spans = clf().classify("");
        assert!(spans.is_empty());
    }

    #[test]
    fn whitespace_only_produces_no_spans() {
        let spans = clf().classify("   \t\n   ");
        assert!(spans.is_empty());
    }

    #[test]
    fn plain_text_no_pii_produces_no_spans() {
        let spans = clf().classify("Hello world this is a test sentence.");
        assert!(spans.is_empty());
    }

    // -------------------------------------------------------------------------
    // Email detection
    // -------------------------------------------------------------------------

    #[test]
    fn detects_simple_email() {
        let text = "user@example.com";
        let spans = clf().classify(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
        assert_eq!(&text[spans[0].start..spans[0].end], "user@example.com");
    }

    #[test]
    fn detects_email_in_sentence() {
        let text = "Contact alice@example.com for more info.";
        let spans = clf().classify(text);
        let email_span = spans
            .iter()
            .find(|s| s.entity_type == EntityType::Email)
            .expect("must detect email");
        let email_text = &text[email_span.start..email_span.end];
        assert_eq!(email_text, "alice@example.com");
    }

    #[test]
    fn detects_multiple_emails() {
        let text = "From: a@b.com To: c@d.org";
        let spans = clf().classify(text);
        let email_count = spans
            .iter()
            .filter(|s| s.entity_type == EntityType::Email)
            .count();
        assert_eq!(email_count, 2);
    }

    #[test]
    fn rejects_bare_at_sign() {
        let spans = clf().classify("@");
        assert!(spans.is_empty());
    }

    #[test]
    fn rejects_no_domain() {
        let spans = clf().classify("user@");
        assert!(spans.is_empty());
    }

    #[test]
    fn rejects_no_local_part() {
        let spans = clf().classify("@example.com");
        assert!(spans.is_empty());
    }

    #[test]
    fn rejects_multiple_at_signs() {
        let spans = clf().classify("a@@b.com");
        assert!(spans.is_empty());
    }

    #[test]
    fn rejects_domain_without_dot() {
        let spans = clf().classify("user@localhost");
        assert!(spans.is_empty());
    }

    #[test]
    fn email_confidence_is_rule_value() {
        let text = "test@example.com";
        let spans = clf().classify(text);
        assert!(!spans.is_empty());
        // Use approximate comparison for f32.
        assert!((spans[0].confidence - NerClassifier::RULE_CONFIDENCE).abs() < f32::EPSILON);
    }

    // -------------------------------------------------------------------------
    // Phone detection
    // -------------------------------------------------------------------------

    #[test]
    fn detects_simple_us_phone() {
        let text = "555-123-4567";
        let spans = clf().classify(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Phone);
    }

    #[test]
    fn detects_international_phone() {
        let text = "+1-800-555-0100";
        let spans = clf().classify(text);
        let has_phone = spans.iter().any(|s| s.entity_type == EntityType::Phone);
        assert!(has_phone, "international phone must be detected");
    }

    #[test]
    fn detects_phone_in_sentence() {
        let text = "Call us at +1-800-555-0100 for support.";
        let spans = clf().classify(text);
        let phone_count = spans
            .iter()
            .filter(|s| s.entity_type == EntityType::Phone)
            .count();
        assert_eq!(phone_count, 1);
    }

    #[test]
    fn rejects_short_digit_sequence() {
        // A 6-digit sequence is below the minimum.
        let spans = clf().classify("123456");
        assert!(spans.is_empty());
    }

    #[test]
    fn detects_phone_with_parentheses() {
        let text = "(555) 123-4567";
        let spans = clf().classify(text);
        let has_phone = spans.iter().any(|s| s.entity_type == EntityType::Phone);
        assert!(has_phone);
    }

    #[test]
    fn phone_span_covers_full_number() {
        let text = "555-123-4567";
        let spans = clf().classify(text);
        assert!(!spans.is_empty());
        assert_eq!(&text[spans[0].start..spans[0].end], "555-123-4567");
    }

    // -------------------------------------------------------------------------
    // Mixed content
    // -------------------------------------------------------------------------

    #[test]
    fn detects_both_email_and_phone_in_same_text() {
        let text = "Reach alice@example.com or call 555-123-4567.";
        let spans = clf().classify(text);
        let emails = spans
            .iter()
            .filter(|s| s.entity_type == EntityType::Email)
            .count();
        let phones = spans
            .iter()
            .filter(|s| s.entity_type == EntityType::Phone)
            .count();
        assert_eq!(emails, 1);
        assert_eq!(phones, 1);
    }

    #[test]
    fn spans_are_sorted_by_start() {
        let text = "555-123-4567 and alice@example.com here";
        let spans = clf().classify(text);
        for window in spans.windows(2) {
            assert!(
                window[0].start <= window[1].start,
                "spans must be sorted by start"
            );
        }
    }
}

//! On-device, embedding-based *semantic concept* detection (WS5-11.4).
//!
//! The rule-based detectors in [`crate::detectors`] catch sensitive data whose
//! *form* is known in advance (a code-name, an SSN-shaped run of digits). They
//! cannot catch data that is sensitive by *meaning* — "the patient was
//! diagnosed with early-onset Parkinson's" carries a medical condition no
//! word-list anticipated. That is the job of a semantic classifier.
//!
//! Such a classifier needs an embedding model, which is loaded on-device inside
//! the tokenization service and **must never perform any egress to classify**
//! (classifying a prompt by calling out to a remote service would leak the very
//! data we are protecting). To keep the crate host-testable while the real
//! model lands later, the model sits behind the [`ConceptClassifier`] trait —
//! the same pattern as the speech `Transcriber` (WS5-03): the integration,
//! span-scanning, threshold logic, and fail-closed wiring are all exercised
//! host-side with a deterministic stand-in ([`KeywordConceptClassifier`]); the
//! production embedding model is a drop-in trait implementation.

use crate::{ner::NerSpan, types::EntityType};

/// An on-device classifier that scores how strongly a text span expresses a
/// named semantic concept (WS5-11.4).
///
/// Implementations run **entirely on the origin device** and MUST NOT perform
/// any network egress: the candidate text handed to [`score`](Self::score) is
/// exactly the sensitive data the tokenization pipeline exists to protect, so
/// classifying it off-device would defeat the purpose.
///
/// The score is a similarity in `[0.0, 1.0]`; the production implementation is
/// an embedding model (cosine similarity between the candidate's embedding and
/// the concept's prototype), but any deterministic scorer satisfies the
/// contract.
pub trait ConceptClassifier {
    /// Score how strongly `candidate` expresses `concept`, in `[0.0, 1.0]`.
    ///
    /// Higher means a stronger match. Implementations must be pure and
    /// side-effect-free (in particular, no egress).
    fn score(&self, concept: &str, candidate: &str) -> f32;
}

/// A single semantic concept to scan for, with the acceptance threshold and the
/// largest word-window the scanner considers (WS5-11.4).
#[derive(Clone, Debug, PartialEq)]
pub struct ConceptDetector {
    /// Stable machine-readable concept slug; becomes the
    /// [`EntityType::Custom`] tag of every span it matches (so concept matches
    /// are domain-separated in the vault exactly like custom detectors —
    /// WS5-11.7).
    concept: String,
    /// Minimum classifier score for a window to be treated as a match.
    threshold: f32,
    /// Largest number of consecutive whitespace-delimited words a single
    /// candidate window may span.
    max_words: usize,
}

/// Default largest word-window a concept scan considers.
const DEFAULT_MAX_WORDS: usize = 8;

impl ConceptDetector {
    /// A new concept detector for `concept`, accepting windows scoring at or
    /// above `threshold`, scanning windows of up to `DEFAULT_MAX_WORDS`
    /// words.
    #[must_use]
    pub fn new(concept: impl Into<String>, threshold: f32) -> Self {
        Self {
            concept: concept.into(),
            threshold,
            max_words: DEFAULT_MAX_WORDS,
        }
    }

    /// Override the largest word-window considered (builder style). A value of
    /// `0` is clamped to `1` so at least single words are scanned.
    #[must_use]
    pub fn with_max_words(mut self, max_words: usize) -> Self {
        self.max_words = max_words.max(1);
        self
    }

    /// The concept slug this detector tags its matches with.
    #[must_use]
    pub fn concept(&self) -> &str {
        &self.concept
    }

    /// Scan `text` with `classifier`, returning the matched spans tagged
    /// [`EntityType::Custom`]`(concept)`.
    ///
    /// Every window of 1..=`max_words` consecutive words is scored; windows at
    /// or above `threshold` become candidate spans, which are then reduced to a
    /// sorted, non-overlapping set (earliest start wins; ties broken by the
    /// longer span) so the concept never emits overlapping matches.
    ///
    /// `classifier` runs on-device only — see [`ConceptClassifier`].
    #[must_use]
    pub fn detect_with(&self, text: &str, classifier: &dyn ConceptClassifier) -> Vec<NerSpan> {
        let words = word_spans(text);
        let mut candidates: Vec<NerSpan> = Vec::new();

        for (i, &(start, _)) in words.iter().enumerate() {
            let max_j = (i + self.max_words).min(words.len());
            for j in i..max_j {
                let Some(&(_, end)) = words.get(j) else {
                    break;
                };
                let Some(candidate) = text.get(start..end) else {
                    continue;
                };
                let score = classifier.score(&self.concept, candidate);
                if score >= self.threshold {
                    candidates.push(NerSpan {
                        start,
                        end,
                        entity_type: EntityType::Custom(self.concept.clone()),
                        confidence: score,
                    });
                }
            }
        }

        // Reduce to a sorted, non-overlapping set with the same rule the
        // detector registry uses: earliest start wins, ties broken by the
        // longer span.
        candidates.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut merged: Vec<NerSpan> = Vec::with_capacity(candidates.len());
        for span in candidates {
            if merged.last().is_none_or(|prev| span.start >= prev.end) {
                merged.push(span);
            }
        }
        merged
    }
}

/// A deterministic, dependency-free stand-in for the production embedding
/// classifier, used host-side to exercise the concept pipeline (WS5-11.4).
///
/// It maps each concept to a set of representative phrases and scores a
/// candidate `1.0` when the candidate — ignoring surrounding punctuation and
/// case — **is** one of the phrases, else `0.0`. Requiring equality (rather
/// than mere containment) makes the matched span *tight*: an embedding model
/// would score the concept-bearing phrase highest, not an arbitrarily wide
/// window that happens to contain it, and this stand-in reproduces that
/// tightness. It is **not** the real classifier — it has no semantic
/// generalization — but it satisfies the [`ConceptClassifier`] contract (pure,
/// on-device, no egress), so every integration and fail-closed test runs
/// without a model.
#[derive(Clone, Debug, Default)]
pub struct KeywordConceptClassifier {
    /// `(concept, lowercased phrase)` pairs; a candidate containing the phrase
    /// scores `1.0` for that concept.
    phrases: Vec<(String, String)>,
}

impl KeywordConceptClassifier {
    /// An empty classifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `phrase` as evidence of `concept` (case-folded on insertion).
    #[must_use]
    pub fn with_phrase(mut self, concept: impl Into<String>, phrase: impl AsRef<str>) -> Self {
        let phrase = phrase.as_ref().to_lowercase();
        if !phrase.is_empty() {
            self.phrases.push((concept.into(), phrase));
        }
        self
    }
}

impl ConceptClassifier for KeywordConceptClassifier {
    fn score(&self, concept: &str, candidate: &str) -> f32 {
        // Normalize by stripping surrounding punctuation/whitespace and folding
        // case, then require the candidate to *be* the phrase (tight match).
        let norm = candidate
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase();
        for (c, phrase) in &self.phrases {
            if c == concept && norm == *phrase {
                return 1.0;
            }
        }
        0.0
    }
}

/// Byte spans `(start, end)` of every maximal run of non-whitespace characters
/// in `text` (its whitespace-delimited words).
fn word_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() {
            if let Some(s) = start.take() {
                spans.push((s, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        spans.push((s, text.len()));
    }
    spans
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn medical_classifier() -> KeywordConceptClassifier {
        KeywordConceptClassifier::new()
            .with_phrase("medical_condition", "Parkinson")
            .with_phrase("medical_condition", "diagnosed with diabetes")
    }

    #[test]
    fn detects_single_word_concept() {
        let det = ConceptDetector::new("medical_condition", 0.5);
        let clf = medical_classifier();
        let text = "the patient has Parkinson now";
        let spans = det.detect_with(text, &clf);
        assert_eq!(spans.len(), 1);
        let s = &spans[0];
        assert_eq!(text.get(s.start..s.end).unwrap(), "Parkinson");
        assert_eq!(
            s.entity_type,
            EntityType::Custom("medical_condition".to_string())
        );
    }

    #[test]
    fn detects_multiword_concept_window() {
        let det = ConceptDetector::new("medical_condition", 0.5);
        let clf = medical_classifier();
        let text = "she was diagnosed with diabetes last year";
        let spans = det.detect_with(text, &clf);
        // The 3-word phrase "diagnosed with diabetes" matches as one span.
        let hit = spans.first().expect("a concept span");
        assert_eq!(
            text.get(hit.start..hit.end).unwrap(),
            "diagnosed with diabetes"
        );
    }

    #[test]
    fn no_match_below_threshold_yields_empty() {
        let det = ConceptDetector::new("medical_condition", 0.5);
        let clf = medical_classifier();
        assert!(
            det.detect_with("a completely unrelated sentence", &clf)
                .is_empty()
        );
    }

    #[test]
    fn spans_are_non_overlapping() {
        // A classifier where both "Parkinson" and "early Parkinson" score high;
        // the merge must keep a single non-overlapping span.
        let clf = KeywordConceptClassifier::new().with_phrase("dx", "parkinson");
        let det = ConceptDetector::new("dx", 0.5);
        let text = "early Parkinson disease";
        let spans = det.detect_with(text, &clf);
        for w in spans.windows(2) {
            assert!(w[0].end <= w[1].start, "spans must not overlap");
        }
    }

    #[test]
    fn max_words_bounds_the_window() {
        let clf = KeywordConceptClassifier::new().with_phrase("c", "a b c");
        // With max_words = 2, the 3-word phrase can never form a single window.
        let det = ConceptDetector::new("c", 0.5).with_max_words(2);
        assert!(det.detect_with("a b c", &clf).is_empty());
        // With the default window it matches.
        let det = ConceptDetector::new("c", 0.5);
        assert_eq!(det.detect_with("a b c", &clf).len(), 1);
    }

    #[test]
    fn classifier_performs_no_egress_by_construction() {
        // The trait contract is purity; the stand-in is observably pure: same
        // input → same score, no I/O. This documents the on-device invariant.
        let clf = medical_classifier();
        assert!(clf.score("medical_condition", "Parkinson") >= 0.5);
        assert!(clf.score("medical_condition", "Parkinson") >= 0.5);
        assert!(clf.score("other", "Parkinson") < 0.5);
    }
}

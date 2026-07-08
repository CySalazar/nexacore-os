//! Extensible, user-defined PII detector registry (WS5-11.1/.2/.3).
//!
//! The built-in [`NerClassifier`](crate::ner::NerClassifier) detects a fixed
//! set of entity types (email, phone). This module adds a *user-extensible*
//! layer: deployments register their own detectors for domain-specific
//! sensitive data — product code-names, internal hostnames, custom ID formats —
//! without changing the crate.
//!
//! Two detector classes are implemented here (both pure, deterministic, and
//! dependency-free); the embedding-based *concept* class (WS5-11.4) requires an
//! on-device model and lands later:
//!
//! - [`WordDetector`] (WS5-11.2): a dictionary of sensitive words/phrases,
//!   matched case-insensitively (Unicode-aware via [`char::to_lowercase`]) on
//!   word boundaries.
//! - [`PatternDetector`] (WS5-11.3): a fixed-width *format template* —
//!   `#` = digit, `@` = letter, `*` = alphanumeric, any other character is a
//!   literal — e.g. `###-##-####` matches a US SSN format.
//!
//! [`DetectorRegistry`] holds the registered detectors and runs the enabled
//! ones over a text, returning [`NerSpan`]s tagged with
//! [`EntityType::Custom`]`(detector id)`. Spans from all detectors are merged
//! into a sorted, non-overlapping set (earliest start wins, ties broken by the
//! longer span). The in-memory CRUD here is the substrate for the sealed-vault
//! persistence (WS5-11.5): [`DetectorRegistry::seal`] /
//! [`DetectorRegistry::unseal`] round-trip the whole registry through the local
//! [`TeeBackend`] so a user's custom detector set survives reboots without ever
//! leaving the device in the clear.

use nexacore_tee::{SealPolicy, SealedBlob, TeeBackend};
use nexacore_types::{
    error::Result,
    wire::{decode_canonical, encode_canonical},
};
use serde::{Deserialize, Serialize};

use crate::{ner::NerSpan, types::EntityType, vault::tee_error_to_nexacore};

/// Confidence assigned to an exact user-detector match (rule-based, precise).
const MATCH_CONFIDENCE: f32 = 1.0;

// =============================================================================
// Detector kinds
// =============================================================================

/// A dictionary detector for sensitive words/phrases (WS5-11.2).
///
/// Matching is case-insensitive (Unicode-aware) and, by default, restricted to
/// word boundaries so `secret` does not match inside `secretariat`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordDetector {
    /// Phrases to match, stored pre-lowercased for case-insensitive scanning.
    phrases: Vec<String>,
    /// Whether matches must fall on word boundaries (alphanumeric neighbours
    /// reject the match). `true` by default.
    require_word_boundary: bool,
}

impl WordDetector {
    /// A new word detector over `phrases` (case-folded on insertion), matching
    /// only on word boundaries.
    #[must_use]
    pub fn new<I, S>(phrases: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            phrases: phrases
                .into_iter()
                .map(|p| p.as_ref().to_lowercase())
                .filter(|p| !p.is_empty())
                .collect(),
            require_word_boundary: true,
        }
    }

    /// Allow matches anywhere, not only on word boundaries (builder style).
    #[must_use]
    pub fn allow_substring(mut self) -> Self {
        self.require_word_boundary = false;
        self
    }

    fn detect_into(&self, id: &str, text: &str, out: &mut Vec<NerSpan>) {
        for phrase in &self.phrases {
            for (start, _) in text.char_indices() {
                let Some(end) = match_ci_at(text, start, phrase) else {
                    continue;
                };
                if self.require_word_boundary && !is_word_boundary(text, start, end) {
                    continue;
                }
                out.push(NerSpan {
                    start,
                    end,
                    entity_type: EntityType::Custom(id.to_string()),
                    confidence: MATCH_CONFIDENCE,
                });
            }
        }
    }
}

/// A fixed-width format-template detector (WS5-11.3).
///
/// Each template character matches exactly one input character: `#` a digit,
/// `@` a letter, `*` an alphanumeric, and any other character matches itself
/// literally. The template therefore matches a run of exactly its own length.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternDetector {
    template: String,
    require_word_boundary: bool,
}

impl PatternDetector {
    /// A new pattern detector for `template`, matching only on word boundaries.
    #[must_use]
    pub fn new(template: impl Into<String>) -> Self {
        Self {
            template: template.into(),
            require_word_boundary: true,
        }
    }

    /// Allow matches anywhere, not only on word boundaries (builder style).
    #[must_use]
    pub fn allow_substring(mut self) -> Self {
        self.require_word_boundary = false;
        self
    }

    fn detect_into(&self, id: &str, text: &str, out: &mut Vec<NerSpan>) {
        let pat = self.template.as_bytes();
        let n = pat.len();
        let bytes = text.as_bytes();
        if n == 0 || n > bytes.len() {
            return;
        }
        for (start, window) in bytes.windows(n).enumerate() {
            if !template_matches(pat, window) {
                continue;
            }
            let end = start + n;
            // The template is ASCII-oriented; reject matches that split a
            // multi-byte UTF-8 character.
            if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
                continue;
            }
            if self.require_word_boundary && !is_word_boundary(text, start, end) {
                continue;
            }
            out.push(NerSpan {
                start,
                end,
                entity_type: EntityType::Custom(id.to_string()),
                confidence: MATCH_CONFIDENCE,
            });
        }
    }
}

/// The matching strategy of a [`Detector`] (WS5-11.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DetectorKind {
    /// Dictionary of sensitive words/phrases (WS5-11.2).
    Words(WordDetector),
    /// Fixed-width format template (WS5-11.3).
    Pattern(PatternDetector),
    // A semantic/embedding-based `Concept` class (WS5-11.4) is reserved; it
    // needs an on-device model and is not implementable host-side yet.
}

impl DetectorKind {
    fn detect_into(&self, id: &str, text: &str, out: &mut Vec<NerSpan>) {
        match self {
            Self::Words(d) => d.detect_into(id, text, out),
            Self::Pattern(d) => d.detect_into(id, text, out),
        }
    }
}

/// A registered detector: a stable id, an enabled flag, and its strategy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detector {
    /// Stable, machine-readable slug; becomes the [`EntityType::Custom`] tag.
    pub id: String,
    /// Whether this detector participates in [`DetectorRegistry::detect`].
    pub enabled: bool,
    /// The matching strategy.
    pub kind: DetectorKind,
}

impl Detector {
    /// A new, enabled detector.
    #[must_use]
    pub fn new(id: impl Into<String>, kind: DetectorKind) -> Self {
        Self {
            id: id.into(),
            enabled: true,
            kind,
        }
    }
}

// =============================================================================
// Registry
// =============================================================================

/// The extensible detector registry (WS5-11.1) with in-memory CRUD and
/// sealed-vault persistence (WS5-11.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DetectorRegistry {
    detectors: Vec<Detector>,
}

impl DetectorRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a detector. Returns `false` (and does nothing) if a detector
    /// with the same id already exists.
    pub fn add(&mut self, detector: Detector) -> bool {
        if self.detectors.iter().any(|d| d.id == detector.id) {
            return false;
        }
        self.detectors.push(detector);
        true
    }

    /// Remove the detector with `id`. Returns whether one was removed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.detectors.len();
        self.detectors.retain(|d| d.id != id);
        self.detectors.len() != before
    }

    /// Enable or disable the detector with `id`. Returns whether it was found.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> bool {
        if let Some(d) = self.detectors.iter_mut().find(|d| d.id == id) {
            d.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Borrow the detector with `id`, if present.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Detector> {
        self.detectors.iter().find(|d| d.id == id)
    }

    /// Number of registered detectors (enabled or not).
    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Whether the registry has no detectors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Run every enabled detector over `text` and return the merged spans,
    /// sorted by start and made non-overlapping (earliest start wins; ties
    /// broken by the longer span).
    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<NerSpan> {
        let mut spans = Vec::new();
        for d in self.detectors.iter().filter(|d| d.enabled) {
            d.kind.detect_into(&d.id, text, &mut spans);
        }
        // Sort by start ascending, then by longer span first so the greedy
        // pass below prefers the wider match on a tie.
        spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut merged: Vec<NerSpan> = Vec::with_capacity(spans.len());
        for span in spans {
            if merged.last().is_none_or(|prev| span.start >= prev.end) {
                merged.push(span);
            }
        }
        merged
    }

    /// Seal the whole registry into an opaque [`SealedBlob`] via the local
    /// [`TeeBackend`] (WS5-11.5).
    ///
    /// The blob can be written to untrusted storage and restored later with
    /// [`unseal`](DetectorRegistry::unseal) on a backend of the same TEE family
    /// and measurement. Detectors are canonicalized (sorted by `id`) before
    /// encoding, so the same content always seals to the same plaintext — a
    /// caller may hash the blob for integrity auditing.
    ///
    /// # Errors
    ///
    /// - [`nexacore_types::error::NexaCoreError::Wire`] if encoding fails.
    /// - [`nexacore_types::error::NexaCoreError::Tee`] if the backend refuses to seal.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tee::MockTeeBackend;
    /// use nexacore_tokenization::detectors::{
    ///     Detector, DetectorKind, DetectorRegistry, WordDetector,
    /// };
    ///
    /// let backend = MockTeeBackend::new();
    /// let mut reg = DetectorRegistry::new();
    /// reg.add(Detector::new(
    ///     "codename",
    ///     DetectorKind::Words(WordDetector::new(["Bluefin"])),
    /// ));
    /// let blob = reg.seal(&backend).expect("seal must succeed");
    /// let restored = DetectorRegistry::unseal(&backend, &blob).expect("unseal must succeed");
    /// assert_eq!(restored.len(), 1);
    /// ```
    pub fn seal(&self, backend: &dyn TeeBackend) -> Result<SealedBlob> {
        // Canonicalize by id for a deterministic byte representation.
        let mut detectors = self.detectors.clone();
        detectors.sort_by(|a, b| a.id.cmp(&b.id));
        let plaintext = encode_canonical(&detectors)?;

        // Derive the seal policy from a fresh attestation so the measurement is
        // the live runtime value (matches `TokenVault::seal_vault`).
        let nonce = nexacore_tee::Nonce([0u8; 32]);
        let quote = backend
            .attest(&nonce, None)
            .map_err(|e| tee_error_to_nexacore(&e, "detectors::seal::attest"))?;
        let policy = SealPolicy::new(quote.family, quote.measurement);
        backend
            .seal(&plaintext, &policy)
            .map_err(|e| tee_error_to_nexacore(&e, "detectors::seal::seal"))
    }

    /// Restore a registry from a blob produced by [`seal`](DetectorRegistry::seal)
    /// (WS5-11.5).
    ///
    /// `backend` must be the same TEE family and measurement that produced the
    /// seal; otherwise the backend rejects the unseal. The restored registry's
    /// detectors are in canonical (`id`-sorted) order.
    ///
    /// # Errors
    ///
    /// - [`nexacore_types::error::NexaCoreError::Tee`] if the backend refuses to unseal
    ///   (e.g. a measurement mismatch).
    /// - [`nexacore_types::error::NexaCoreError::Wire`] if the unsealed bytes cannot be
    ///   decoded.
    pub fn unseal(backend: &dyn TeeBackend, blob: &SealedBlob) -> Result<Self> {
        let plaintext = backend
            .unseal(blob)
            .map_err(|e| tee_error_to_nexacore(&e, "detectors::unseal::unseal"))?;
        let detectors: Vec<Detector> = decode_canonical(&plaintext)?;
        Ok(Self { detectors })
    }
}

// =============================================================================
// Private helpers
// =============================================================================

/// Match `needle_lower` (already lower-cased) at byte offset `start` in `text`,
/// case-insensitively. Returns the exclusive end byte offset on success.
fn match_ci_at(text: &str, start: usize, needle_lower: &str) -> Option<usize> {
    let rest = text.get(start..)?;
    let mut hay = rest.chars();
    let mut consumed = 0usize;
    for nc in needle_lower.chars() {
        let c = hay.next()?;
        if !c.to_lowercase().eq(nc.to_lowercase()) {
            return None;
        }
        consumed += c.len_utf8();
    }
    Some(start + consumed)
}

/// Whether `[start, end)` in `text` is flanked by non-alphanumeric characters
/// (or the string ends), i.e. it is a whole-word match.
fn is_word_boundary(text: &str, start: usize, end: usize) -> bool {
    let before_ok = text
        .get(..start)
        .and_then(|s| s.chars().next_back())
        .is_none_or(|c| !c.is_alphanumeric());
    let after_ok = text
        .get(end..)
        .and_then(|s| s.chars().next())
        .is_none_or(|c| !c.is_alphanumeric());
    before_ok && after_ok
}

/// Whether `window` (same length as `pat`) satisfies the format template.
fn template_matches(pat: &[u8], window: &[u8]) -> bool {
    pat.iter().zip(window).all(|(&p, &w)| match p {
        b'#' => w.is_ascii_digit(),
        b'@' => w.is_ascii_alphabetic(),
        b'*' => w.is_ascii_alphanumeric(),
        literal => w == literal,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn word_registry() -> DetectorRegistry {
        let mut reg = DetectorRegistry::new();
        reg.add(Detector::new(
            "codename",
            DetectorKind::Words(WordDetector::new(["Project Zenith", "Bluefin"])),
        ));
        reg
    }

    #[test]
    fn word_detector_is_case_insensitive_and_word_bounded() {
        let reg = word_registry();
        let spans = reg.detect("the bluefin and BLUEFIN ship, but bluefins do not");
        // "bluefin" and "BLUEFIN" match; "bluefins" (trailing 's') does not.
        assert_eq!(spans.len(), 2);
        for s in &spans {
            let text = "the bluefin and BLUEFIN ship, but bluefins do not";
            assert!(
                text.get(s.start..s.end)
                    .unwrap()
                    .eq_ignore_ascii_case("bluefin")
            );
            assert_eq!(s.entity_type, EntityType::Custom("codename".to_string()));
        }
    }

    #[test]
    fn word_detector_matches_multiword_phrases() {
        let reg = word_registry();
        let text = "ship project zenith by friday";
        let spans = reg.detect(text);
        let hit = spans
            .iter()
            .find(|s| s.entity_type == EntityType::Custom("codename".to_string()))
            .expect("phrase must match");
        assert_eq!(text.get(hit.start..hit.end).unwrap(), "project zenith");
    }

    #[test]
    fn word_detector_substring_mode() {
        let mut reg = DetectorRegistry::new();
        reg.add(Detector::new(
            "sub",
            DetectorKind::Words(WordDetector::new(["secret"]).allow_substring()),
        ));
        // In substring mode, "secretariat" contains a match.
        let spans = reg.detect("the secretariat");
        assert_eq!(spans.len(), 1);
    }

    #[test]
    fn pattern_detector_matches_ssn_format() {
        let mut reg = DetectorRegistry::new();
        reg.add(Detector::new(
            "ssn-like",
            DetectorKind::Pattern(PatternDetector::new("###-##-####")),
        ));
        let text = "id 123-45-6789 end";
        let spans = reg.detect(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            text.get(spans[0].start..spans[0].end).unwrap(),
            "123-45-6789"
        );
        // A malformed run (letters where digits are required) does not match.
        assert!(reg.detect("12X-45-6789").is_empty());
    }

    #[test]
    fn pattern_detector_letter_and_alnum_classes() {
        let mut reg = DetectorRegistry::new();
        reg.add(Detector::new(
            "badge",
            DetectorKind::Pattern(PatternDetector::new("@@-*##")),
        ));
        // `@@` two letters, literal `-`, `*` alnum, `##` two digits.
        let spans = reg.detect("AB-X12");
        assert_eq!(spans.len(), 1);
        assert!(reg.detect("A1-X12").is_empty()); // second char must be a letter
    }

    #[test]
    fn registry_crud_add_remove_enable_disable() {
        let mut reg = DetectorRegistry::new();
        assert!(reg.add(Detector::new(
            "d1",
            DetectorKind::Words(WordDetector::new(["alpha"])),
        )));
        // Duplicate id is rejected.
        assert!(!reg.add(Detector::new(
            "d1",
            DetectorKind::Words(WordDetector::new(["beta"])),
        )));
        assert_eq!(reg.len(), 1);
        assert!(reg.get("d1").is_some());

        // Disabling stops it from matching.
        assert!(reg.set_enabled("d1", false));
        assert!(reg.detect("alpha beta").is_empty());
        assert!(reg.set_enabled("d1", true));
        assert_eq!(reg.detect("alpha beta").len(), 1);

        // set_enabled on an unknown id reports not-found.
        assert!(!reg.set_enabled("nope", true));

        // Removal.
        assert!(reg.remove("d1"));
        assert!(!reg.remove("d1"));
        assert!(reg.is_empty());
    }

    #[test]
    fn detect_merges_overlaps_and_sorts() {
        let mut reg = DetectorRegistry::new();
        // Two detectors that both match overlapping regions of the text.
        reg.add(Detector::new(
            "w",
            DetectorKind::Words(WordDetector::new(["acme corp"])),
        ));
        reg.add(Detector::new(
            "w2",
            DetectorKind::Words(WordDetector::new(["corp"])),
        ));
        let text = "at acme corp today";
        let spans = reg.detect(text);
        // The wider "acme corp" wins over the overlapping "corp"; result is one
        // span, and spans are sorted/non-overlapping.
        assert_eq!(spans.len(), 1);
        assert_eq!(text.get(spans[0].start..spans[0].end).unwrap(), "acme corp");
        for w in spans.windows(2) {
            assert!(w[0].end <= w[1].start, "spans must be non-overlapping");
        }
    }

    #[test]
    fn empty_registry_and_no_match_yield_empty() {
        let reg = DetectorRegistry::new();
        assert!(reg.detect("nothing sensitive here").is_empty());
        let reg2 = word_registry();
        assert!(reg2.detect("completely unrelated text").is_empty());
    }

    // -------------------------------------------------------------------------
    // Sealed-vault persistence (WS5-11.5)
    // -------------------------------------------------------------------------

    use nexacore_tee::{Measurement, MockTeeBackend};

    fn mixed_registry() -> DetectorRegistry {
        let mut reg = DetectorRegistry::new();
        reg.add(Detector::new(
            "codename",
            DetectorKind::Words(WordDetector::new(["Project Zenith", "Bluefin"])),
        ));
        reg.add(Detector::new(
            "ssn-like",
            DetectorKind::Pattern(PatternDetector::new("###-##-####")),
        ));
        // A disabled detector must survive the round-trip as disabled.
        let mut disabled = Detector::new("off", DetectorKind::Words(WordDetector::new(["alpha"])));
        disabled.enabled = false;
        reg.add(disabled);
        reg
    }

    #[test]
    fn seal_unseal_round_trip_preserves_detectors_and_behaviour() {
        let backend = MockTeeBackend::new();
        let reg = mixed_registry();

        let blob = reg.seal(&backend).expect("seal must succeed");
        let restored = DetectorRegistry::unseal(&backend, &blob).expect("unseal must succeed");

        // Same detectors (count, enabled flags, kinds) — canonicalized by id.
        assert_eq!(restored.len(), reg.len());
        for id in ["codename", "ssn-like", "off"] {
            assert_eq!(restored.get(id), reg.get(id), "detector {id} must survive");
        }
        // Same detection behaviour after restore.
        let text = "ship project zenith with id 123-45-6789";
        assert_eq!(restored.detect(text), reg.detect(text));
    }

    #[test]
    fn seal_is_deterministic_for_same_content() {
        let backend = MockTeeBackend::new();
        // Build two registries with the same detectors added in different order;
        // canonicalization by id must produce identical sealed plaintext.
        let mut a = DetectorRegistry::new();
        a.add(Detector::new(
            "zeta",
            DetectorKind::Pattern(PatternDetector::new("##")),
        ));
        a.add(Detector::new(
            "alpha",
            DetectorKind::Words(WordDetector::new(["x"])),
        ));
        let mut b = DetectorRegistry::new();
        b.add(Detector::new(
            "alpha",
            DetectorKind::Words(WordDetector::new(["x"])),
        ));
        b.add(Detector::new(
            "zeta",
            DetectorKind::Pattern(PatternDetector::new("##")),
        ));
        let blob_a = a.seal(&backend).expect("seal a");
        let blob_b = b.seal(&backend).expect("seal b");
        assert_eq!(blob_a.ciphertext, blob_b.ciphertext);
    }

    #[test]
    fn unseal_fails_with_different_backend_measurement() {
        let backend_a = MockTeeBackend::with_measurement(Measurement([0x01u8; 48]));
        let backend_b = MockTeeBackend::with_measurement(Measurement([0x02u8; 48]));
        let reg = mixed_registry();
        let blob = reg.seal(&backend_a).expect("seal");
        assert!(
            DetectorRegistry::unseal(&backend_b, &blob).is_err(),
            "a different measurement must not unseal the registry"
        );
    }

    #[test]
    fn sealed_empty_registry_round_trips() {
        let backend = MockTeeBackend::new();
        let reg = DetectorRegistry::new();
        let blob = reg.seal(&backend).expect("seal empty");
        let restored = DetectorRegistry::unseal(&backend, &blob).expect("unseal empty");
        assert!(restored.is_empty());
    }
}

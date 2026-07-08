//! Compact local language identification (WS5-12.2).
//!
//! A small, dependency-free language identifier used to route text to the
//! right NER language pack (WS5-12.4) before any model runs. It uses the
//! classic Cavnar-Trenkle character-trigram approach: each language is
//! described by the rank order of its most frequent character trigrams, and an
//! input's trigram profile is scored against each language by an out-of-place
//! distance. The distance is turned into a `0..=1000` per-mille confidence
//! (fixed-point, no floats), and a guess is accepted only if it clears that
//! language's **confidence threshold** —
//! otherwise the identifier returns `None` (fail-closed, feeding the
//! language-not-covered policy WS5-12.7).
//!
//! Fully local and deterministic — no network, no model. Profiles are built
//! from representative sample text supplied by the language pack (WS5-12.1).

use std::collections::HashMap;

/// A character trigram (three consecutive characters of normalised text).
type Trigram = (char, char, char);

/// A ranked character-trigram profile of some text.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    /// Trigrams in descending frequency order (index = rank, 0 = most frequent).
    ordered: Vec<Trigram>,
    /// Trigram → rank, for O(1) lookup during scoring.
    ranks: HashMap<Trigram, usize>,
}

impl Profile {
    /// Build a profile from `text`, keeping the `top_n` most frequent trigrams.
    #[must_use]
    pub fn build(text: &str, top_n: usize) -> Self {
        let mut counts: HashMap<Trigram, u32> = HashMap::new();
        for tri in trigrams(&normalize(text)) {
            *counts.entry(tri).or_insert(0) += 1;
        }
        // Rank by count descending; break ties by the trigram itself so the
        // ranking is deterministic.
        let mut ranked: Vec<(Trigram, u32)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        ranked.truncate(top_n);

        let ordered: Vec<Trigram> = ranked.into_iter().map(|(t, _)| t).collect();
        let ranks = ordered.iter().enumerate().map(|(i, &t)| (t, i)).collect();
        Self { ordered, ranks }
    }

    /// The number of trigrams in the profile.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    /// Whether the profile is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    /// The Cavnar-Trenkle out-of-place distance from `self` (a text profile) to
    /// `reference` (a language profile): the sum over `self`'s trigrams of the
    /// rank difference, with a full-length penalty for a trigram absent from the
    /// reference. Lower is a closer match.
    #[must_use]
    pub fn distance(&self, reference: &Self) -> usize {
        let penalty = reference.ordered.len().max(1);
        self.ordered
            .iter()
            .enumerate()
            .map(|(rank, tri)| match reference.ranks.get(tri) {
                Some(&r) => rank.abs_diff(r),
                None => penalty,
            })
            .sum()
    }
}

/// Lowercase `text` and collapse every non-letter run to a single space
/// (trimmed), so trigrams capture word-boundary context.
fn normalize(text: &str) -> String {
    let mut out = String::new();
    let mut prev_space = true; // suppress a leading space
    for c in text.chars().flat_map(char::to_lowercase) {
        if c.is_alphabetic() {
            out.push(c);
            prev_space = false;
        } else if !prev_space {
            out.push(' ');
            prev_space = true;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Every 3-character sliding window of `normalised`.
fn trigrams(normalised: &str) -> Vec<Trigram> {
    let chars: Vec<char> = normalised.chars().collect();
    chars
        .windows(3)
        .filter_map(|w| match w {
            [a, b, c] => Some((*a, *b, *c)),
            _ => None,
        })
        .collect()
}

/// One registered language: its profile and acceptance threshold (per-mille).
#[derive(Debug, Clone)]
struct LangEntry {
    name: String,
    profile: Profile,
    min_confidence: u32,
}

/// An accepted language guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LangGuess {
    /// The identified language name.
    pub lang: String,
    /// Confidence in per-mille (`0..=1000`, higher is better) — fixed-point so
    /// the identifier stays float-free.
    pub confidence_milli: u32,
    /// The raw out-of-place distance (lower is a closer match).
    pub distance: usize,
}

/// Turn an out-of-place `distance` into a `0..=1000` confidence given the
/// worst-case `max_distance` (fixed-point, no floats).
#[allow(clippy::integer_division, reason = "fixed-point per-mille confidence")]
fn confidence_milli(distance: usize, max_distance: usize) -> u32 {
    let scaled = distance.saturating_mul(1000) / max_distance.max(1);
    u32::try_from(1000usize.saturating_sub(scaled)).unwrap_or(0)
}

/// A compact multi-language identifier (WS5-12.2).
#[derive(Debug, Clone)]
pub struct LanguageIdentifier {
    langs: Vec<LangEntry>,
    top_n: usize,
}

impl LanguageIdentifier {
    /// A new identifier keeping the `top_n` trigrams per profile.
    ///
    /// `top_n` is floored at 1.
    #[must_use]
    pub fn new(top_n: usize) -> Self {
        Self {
            langs: Vec::new(),
            top_n: top_n.max(1),
        }
    }

    /// Register a language from representative `sample` text, accepting a guess
    /// only when its confidence reaches `min_confidence_milli` (per-mille,
    /// clamped to `0..=1000`).
    pub fn add_language(&mut self, name: &str, sample: &str, min_confidence_milli: u32) {
        self.langs.push(LangEntry {
            name: name.to_string(),
            profile: Profile::build(sample, self.top_n),
            min_confidence: min_confidence_milli.min(1000),
        });
    }

    /// The number of registered languages.
    #[must_use]
    pub fn language_count(&self) -> usize {
        self.langs.len()
    }

    /// Identify the language of `text`, or `None` if the best match does not
    /// clear its confidence threshold (fail-closed).
    #[must_use]
    pub fn identify(&self, text: &str) -> Option<LangGuess> {
        let profile = Profile::build(text, self.top_n);
        if profile.is_empty() {
            return None;
        }
        // Worst-case distance: every kept trigram missing at full penalty.
        let max_distance = (self.top_n * self.top_n).max(1);

        let mut best: Option<(&LangEntry, usize, u32)> = None;
        for lang in &self.langs {
            let distance = profile.distance(&lang.profile);
            let confidence = confidence_milli(distance, max_distance);
            if best.is_none_or(|(_, d, _)| distance < d) {
                best = Some((lang, distance, confidence));
            }
        }

        best.and_then(|(lang, distance, confidence)| {
            (confidence >= lang.min_confidence).then(|| LangGuess {
                lang: lang.name.clone(),
                confidence_milli: confidence,
                distance,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EN: &str = "the quick brown fox jumps over the lazy dog and the cat sat \
        on the mat while the children were playing in the garden after school";
    const IT: &str = "il gatto nero salta sopra il cane pigro mentre il sole splende \
        nel cielo azzurro della città e i bambini giocano nel giardino della casa";

    fn identifier() -> LanguageIdentifier {
        let mut id = LanguageIdentifier::new(120);
        id.add_language("en", EN, 300);
        id.add_language("it", IT, 300);
        id
    }

    #[test]
    fn normalises_and_extracts_trigrams() {
        assert_eq!(normalize("Hi, THERE!"), "hi there");
        assert_eq!(trigrams("abcd"), expected_trigrams());
    }

    fn expected_trigrams() -> Vec<Trigram> {
        vec![('a', 'b', 'c'), ('b', 'c', 'd')]
    }

    #[test]
    fn profile_ranks_by_frequency() {
        // "aaa aaa" → the trigram ('a','a','a') dominates.
        let p = Profile::build("aaaa aaaa", 10);
        assert!(!p.is_empty());
        assert_eq!(p.ordered.first(), Some(&('a', 'a', 'a')));
    }

    #[test]
    fn identifies_english_and_italian() {
        let id = identifier();
        let en = id
            .identify("the dog and the fox were in the garden")
            .unwrap();
        assert_eq!(en.lang, "en");
        let it = id.identify("il sole splende sopra il gatto nero").unwrap();
        assert_eq!(it.lang, "it");
    }

    #[test]
    fn a_closer_match_has_a_lower_distance_than_the_other_language() {
        let id = identifier();
        let text = "the children were playing in the garden";
        let p = Profile::build(text, 120);
        let en = &id.langs[0];
        let it = &id.langs[1];
        assert!(p.distance(&en.profile) < p.distance(&it.profile));
    }

    #[test]
    fn threshold_rejects_low_confidence_matches() {
        // Same corpora, but require near-perfect confidence.
        let mut id = LanguageIdentifier::new(120);
        id.add_language("en", EN, 990);
        id.add_language("it", IT, 990);
        // A normal sentence never reaches 0.99 confidence → rejected.
        assert_eq!(id.identify("the dog and the fox"), None);
    }

    #[test]
    fn empty_or_unregistered_input_returns_none() {
        let id = identifier();
        assert_eq!(id.identify(""), None); // no trigrams
        let empty = LanguageIdentifier::new(50);
        assert_eq!(empty.identify("hello world there"), None); // no languages
    }
}

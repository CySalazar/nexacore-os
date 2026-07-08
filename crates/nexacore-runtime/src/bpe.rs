//! Byte-level BPE tokenizer for LLM text ↔ token ID conversion.
//!
//! This module provides a byte-level Byte Pair Encoding (BPE) tokenizer
//! compatible with GPT-2 / TinyLlama-style vocabularies. The algorithm
//! operates entirely on raw UTF-8 bytes: every input character is first
//! represented as one or more single-byte tokens; merge rules are then applied
//! iteratively in priority order until no further merges are possible.
//!
//! ## Design rationale
//!
//! - **No external tokenizer crate**: `tiktoken`, `tokenizers`, and similar
//!   crates carry heavy transitive dependency trees and, in some cases, require
//!   Python-generated vocabulary files at runtime. The NexaCore OS runtime must be
//!   self-contained with a minimal, auditable dependency surface.
//! - **Byte-level**: operating at the byte level guarantees that every possible
//!   UTF-8 string round-trips through encode → decode without data loss,
//!   provided the vocabulary contains all 256 single-byte tokens (the standard
//!   assumption for byte-BPE models such as GPT-2).
//! - **Priority-ordered merges**: merge rules are stored as an ordered `Vec`.
//!   The index of a rule in the vec is its priority; lower index = higher
//!   priority = applied first. This matches the GPT-2 `merges.txt` convention.
//!
//! ## Phase 2 scope
//!
//! The encode algorithm is O(n × m) where n is the token count and m is the
//! number of merge rules. This is correct but not production-fast; a future
//! stream may replace it with a priority-queue implementation.

// `hashbrown::HashMap` is the implementation that backs
// `std::collections::HashMap`; using it directly keeps the tokenizer
// `no_std + alloc`-compatible with identical behaviour and API
// (TASK-13-pre / ADR-0034 §3).
// Alloc types: re-exported by std's prelude on host builds, pulled from
// `alloc` when building without std.
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use hashbrown::HashMap;
use nexacore_types::Result;

// Unicode replacement character bytes (U+FFFD = 0xEF 0xBF 0xBD).
// Placed at module scope to avoid the `items_after_statements` clippy lint.
const REPLACEMENT_CHAR: &[u8] = "\u{FFFD}".as_bytes();

// =============================================================================
// SpecialTokens
// =============================================================================

/// Special token identifiers used by the tokenizer at sequence boundaries.
///
/// These IDs are reserved and are excluded from normal text content during
/// decoding. The values must not collide with any regular vocabulary entry.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::bpe::SpecialTokens;
///
/// let st = SpecialTokens {
///     bos: 1,
///     eos: 2,
///     pad: 3,
///     unk: 0,
/// };
/// assert_eq!(st.bos, 1);
/// ```
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialTokens {
    /// Token ID that marks the beginning of a sequence.
    pub bos: u32,
    /// Token ID that marks the end of a sequence.
    pub eos: u32,
    /// Token ID used for sequence padding.
    pub pad: u32,
    /// Token ID emitted when an input byte sequence is not in the vocabulary.
    pub unk: u32,
}

// =============================================================================
// MergeRule
// =============================================================================

/// A single BPE merge rule: combine the pair `(left, right)` into `merged`.
///
/// `priority` reflects the rule's position in the original `merges.txt` file
/// (lower value = earlier rule = higher priority). Lower-priority rules are
/// applied only after all higher-priority rules have been exhausted.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::bpe::MergeRule;
///
/// let rule = MergeRule {
///     left: b"h".to_vec(),
///     right: b"e".to_vec(),
///     merged: b"he".to_vec(),
///     priority: 0,
/// };
/// assert_eq!(rule.merged, b"he");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeRule {
    /// Left token bytes in the pair being merged.
    pub left: Vec<u8>,
    /// Right token bytes in the pair being merged.
    pub right: Vec<u8>,
    /// Byte sequence that results from merging `left` and `right`.
    pub merged: Vec<u8>,
    /// Position of this rule in the priority ordering (0 = highest priority).
    pub priority: u32,
}

// =============================================================================
// BpeVocabulary
// =============================================================================

/// Byte-level BPE vocabulary: bidirectional mapping between token byte
/// sequences and token IDs, plus the ordered merge table.
///
/// Construct with [`BpeVocabulary::new`] from raw token lists and merge rules,
/// or use [`BpeVocabulary::minimal_test_vocab`] for an in-process test fixture.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::bpe::{BpeVocabulary, SpecialTokens};
///
/// let vocab = BpeVocabulary::minimal_test_vocab();
/// assert!(vocab.vocab_size >= 260);
/// // All 256 single-byte tokens must be present.
/// assert_eq!(vocab.token_id(&[b'A']), Some(b'A' as u32));
/// ```
pub struct BpeVocabulary {
    /// Forward map: token byte sequence → token ID.
    token_to_id: HashMap<Vec<u8>, u32>,
    /// Reverse map: token ID → token byte sequence.
    id_to_token: HashMap<u32, Vec<u8>>,
    /// Ordered merge rules: index 0 has highest priority.
    /// Each entry is `(left_bytes, right_bytes)`.
    merges: Vec<(Vec<u8>, Vec<u8>)>,
    /// Special token IDs for BOS / EOS / PAD / UNK.
    pub special_tokens: SpecialTokens,
    /// Total number of entries in the vocabulary (regular + special).
    pub vocab_size: u32,
}

impl BpeVocabulary {
    /// Build a vocabulary from an explicit token list and merge table.
    ///
    /// `tokens` is a list of `(token_id, token_bytes)` pairs. Duplicate IDs
    /// are overwritten in insertion order; callers are responsible for
    /// providing a consistent, non-overlapping list.
    ///
    /// `merges` is ordered by priority: index 0 is the highest-priority merge
    /// and will be applied first during encoding.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::{BpeVocabulary, SpecialTokens};
    ///
    /// let tokens: Vec<(u32, Vec<u8>)> = (0u32..=255).map(|b| (b, vec![b as u8])).collect();
    /// let merges = vec![(b"h".to_vec(), b"i".to_vec())];
    /// let special = SpecialTokens {
    ///     bos: 256,
    ///     eos: 257,
    ///     pad: 258,
    ///     unk: 259,
    /// };
    /// let vocab = BpeVocabulary::new(tokens, merges, special);
    /// assert!(vocab.vocab_size >= 256);
    /// ```
    #[must_use]
    pub fn new(
        tokens: Vec<(u32, Vec<u8>)>,
        merges: Vec<(Vec<u8>, Vec<u8>)>,
        special_tokens: SpecialTokens,
    ) -> Self {
        // Vocabulary size may not exceed u32::MAX in practice; a vocabulary
        // this large would be unusable. Saturate at u32::MAX rather than panic.
        let vocab_size = u32::try_from(tokens.len()).unwrap_or(u32::MAX);

        let mut token_to_id = HashMap::with_capacity(tokens.len());
        let mut id_to_token = HashMap::with_capacity(tokens.len());

        for (id, bytes) in tokens {
            token_to_id.insert(bytes.clone(), id);
            id_to_token.insert(id, bytes);
        }

        Self {
            token_to_id,
            id_to_token,
            merges,
            special_tokens,
            vocab_size,
        }
    }

    /// Construct a minimal vocabulary suitable for unit testing.
    ///
    /// The vocabulary contains:
    /// - 256 single-byte tokens (IDs 0–255, one per byte value).
    /// - Special tokens: BOS=256, EOS=257, PAD=258, UNK=259.
    /// - A small set of merge rules for common ASCII pairs:
    ///   `h`+`e`→`he` (ID 260), `l`+`l`→`ll` (ID 261),
    ///   `he`+`ll`→`hell` (ID 262), `o`+` `→`o ` (ID 263),
    ///   `t`+`h`→`th` (ID 264), `th`+`e`→`the` (ID 265).
    ///
    /// The merge rules are ordered so that lower-index rules are applied first
    /// (they have lower priority numbers), matching GPT-2 convention.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::BpeVocabulary;
    ///
    /// let vocab = BpeVocabulary::minimal_test_vocab();
    /// assert!(vocab.vocab_size >= 260);
    /// assert_eq!(vocab.token_id(b"he"), Some(260));
    /// ```
    #[must_use]
    pub fn minimal_test_vocab() -> Self {
        // Single-byte tokens: ID = byte value for easy round-trip.
        // The cast from u32 to u8 is safe because the range is 0..=255.
        #[allow(clippy::cast_possible_truncation)]
        let mut tokens: Vec<(u32, Vec<u8>)> = (0u32..=255).map(|b| (b, vec![b as u8])).collect();

        // Special tokens.
        tokens.push((256, b"<|bos|>".to_vec()));
        tokens.push((257, b"<|eos|>".to_vec()));
        tokens.push((258, b"<|pad|>".to_vec()));
        tokens.push((259, b"<|unk|>".to_vec()));

        // Merged tokens: their byte representations are added to the vocab so
        // that encode() can map them back to IDs after merging.
        tokens.push((260, b"he".to_vec()));
        tokens.push((261, b"ll".to_vec()));
        tokens.push((262, b"hell".to_vec()));
        tokens.push((263, b"o ".to_vec()));
        tokens.push((264, b"th".to_vec()));
        tokens.push((265, b"the".to_vec()));

        // Merges ordered by priority (index 0 is applied first).
        let merges: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"h".to_vec(), b"e".to_vec()),   // 0: h+e → he   (ID 260)
            (b"l".to_vec(), b"l".to_vec()),   // 1: l+l → ll   (ID 261)
            (b"he".to_vec(), b"ll".to_vec()), // 2: he+ll → hell (ID 262)
            (b"o".to_vec(), b" ".to_vec()),   // 3: o+  → o    (ID 263)
            (b"t".to_vec(), b"h".to_vec()),   // 4: t+h → th   (ID 264)
            (b"th".to_vec(), b"e".to_vec()),  // 5: th+e → the  (ID 265)
        ];

        let special_tokens = SpecialTokens {
            bos: 256,
            eos: 257,
            pad: 258,
            unk: 259,
        };

        Self::new(tokens, merges, special_tokens)
    }

    /// Look up the token ID for a given byte sequence.
    ///
    /// Returns `None` if the byte sequence is not in the vocabulary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::BpeVocabulary;
    ///
    /// let vocab = BpeVocabulary::minimal_test_vocab();
    /// assert_eq!(vocab.token_id(b"he"), Some(260));
    /// assert_eq!(vocab.token_id(b"xyz_unknown_token"), None);
    /// ```
    #[must_use]
    pub fn token_id(&self, token: &[u8]) -> Option<u32> {
        self.token_to_id.get(token).copied()
    }

    /// Look up the byte sequence for a given token ID.
    ///
    /// Returns `None` if the ID is not in the vocabulary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::BpeVocabulary;
    ///
    /// let vocab = BpeVocabulary::minimal_test_vocab();
    /// assert_eq!(vocab.token_bytes(65), Some(b"A".as_slice())); // ASCII 'A'
    /// assert_eq!(vocab.token_bytes(99_999), None);
    /// ```
    #[must_use]
    pub fn token_bytes(&self, id: u32) -> Option<&[u8]> {
        self.id_to_token.get(&id).map(Vec::as_slice)
    }

    /// Build a lookup index from `(left_bytes, right_bytes)` pair to the
    /// priority index of the merge rule in `self.merges`.
    ///
    /// Computing this once per encode call avoids an O(m) linear scan for
    /// every pair checked during the merge loop.
    fn build_merge_index(&self) -> HashMap<(&[u8], &[u8]), usize> {
        self.merges
            .iter()
            .enumerate()
            .map(|(priority, (left, right))| ((left.as_slice(), right.as_slice()), priority))
            .collect()
    }
}

// =============================================================================
// BpeTokenizer
// =============================================================================

/// Byte-level BPE tokenizer: encodes text to token IDs and decodes back.
///
/// The tokenizer is stateless after construction and is `Send + Sync`.
/// It can be wrapped in an `Arc` and shared across threads or async tasks
/// without any additional synchronisation.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
///
/// let tokenizer = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
/// let ids = tokenizer.encode("hello").unwrap();
/// let text = tokenizer.decode(&ids).unwrap();
/// assert_eq!(text, "hello");
/// ```
pub struct BpeTokenizer {
    vocab: BpeVocabulary,
}

impl BpeTokenizer {
    /// Create a tokenizer backed by the given vocabulary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
    ///
    /// let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    /// assert!(t.vocab_size() >= 260);
    /// ```
    #[must_use]
    pub fn new(vocab: BpeVocabulary) -> Self {
        Self { vocab }
    }

    /// Encode `text` into a sequence of token IDs.
    ///
    /// The algorithm:
    /// 1. Convert the text to its UTF-8 byte representation.
    /// 2. Initialise a token list where every byte is a separate token.
    /// 3. Iteratively apply the highest-priority merge rule that matches any
    ///    adjacent pair in the current token list.
    /// 4. Repeat until no more merge rules apply.
    /// 5. Convert the final token byte sequences to IDs using the vocabulary.
    ///    Token sequences absent from the vocabulary produce `unk`.
    ///
    /// Returns an empty `Vec` for an empty input string.
    ///
    /// # Errors
    ///
    /// Currently infallible (always returns `Ok`). The `Result` wrapper is
    /// present so the signature can accommodate vocabulary-based validation
    /// errors in future without breaking callers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
    ///
    /// let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    /// // "hello": h+e → he, l+l → ll, he+ll → hell; 'o' remains.
    /// let ids = t.encode("hello").unwrap();
    /// assert!(!ids.is_empty());
    /// ```
    // The return type is Result<Vec<u32>> rather than Vec<u32> deliberately:
    // future vocabulary-based validation (e.g. verifying all tokens are in-vocab)
    // can be added without a breaking API change. The lint suppression is
    // intentional and documented here.
    #[allow(clippy::unnecessary_wraps)]
    pub fn encode(&self, text: &str) -> Result<Vec<u32>> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        // Step 1: initialise as individual bytes.
        let mut tokens: Vec<Vec<u8>> = text.as_bytes().iter().map(|b| vec![*b]).collect();

        // Build a fast pair-to-priority lookup for this encode call.
        let merge_index = self.vocab.build_merge_index();

        // Step 2–4: iteratively apply the best (lowest priority index) merge.
        loop {
            // Scan all adjacent pairs to find the one with the best (lowest)
            // priority index that exists in the merge table.
            let mut best_priority = usize::MAX;
            let mut best_pos: Option<usize> = None;

            // Use get() on both sides to satisfy clippy::indexing_slicing.
            // The pair (i, i+1) is always valid here because the loop range
            // is 0..tokens.len().saturating_sub(1).
            for i in 0..tokens.len().saturating_sub(1) {
                if let (Some(left), Some(right)) = (tokens.get(i), tokens.get(i + 1)) {
                    let pair = (left.as_slice(), right.as_slice());
                    if let Some(&priority) = merge_index.get(&pair) {
                        if priority < best_priority {
                            best_priority = priority;
                            best_pos = Some(i);
                        }
                    }
                }
            }

            match best_pos {
                None => break, // No more applicable merges.
                Some(pos) => {
                    // Merge tokens[pos] and tokens[pos+1] in-place.
                    // remove(pos+1) is always valid: pos was set from an index
                    // within 0..tokens.len()-1, so pos+1 < tokens.len().
                    let right = tokens.remove(pos + 1);
                    // After the remove, pos is still a valid index.
                    if let Some(token) = tokens.get_mut(pos) {
                        token.extend_from_slice(&right);
                    }
                }
            }
        }

        // Step 5: convert token byte sequences to IDs.
        let unk_id = self.vocab.special_tokens.unk;
        let ids = tokens
            .iter()
            .map(|t| self.vocab.token_id(t).unwrap_or(unk_id))
            .collect();

        Ok(ids)
    }

    /// Encode `text` and prepend BOS / append EOS token IDs.
    ///
    /// This is the typical entry point for feeding text into an autoregressive
    /// language model, which expects BOS at the start of the prompt.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Self::encode`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
    ///
    /// let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    /// let ids = t.encode_with_special("hi").unwrap();
    /// assert_eq!(ids.first(), Some(&256)); // BOS
    /// assert_eq!(ids.last(), Some(&257)); // EOS
    /// ```
    pub fn encode_with_special(&self, text: &str) -> Result<Vec<u32>> {
        let mut ids = vec![self.vocab.special_tokens.bos];
        ids.extend(self.encode(text)?);
        ids.push(self.vocab.special_tokens.eos);
        Ok(ids)
    }

    /// Decode a sequence of token IDs back to a UTF-8 string.
    ///
    /// Special tokens (BOS, EOS, PAD) are silently skipped. Unknown IDs
    /// (not present in the vocabulary and not a special token) produce the
    /// Unicode replacement character U+FFFD (`"\u{FFFD}"`).
    ///
    /// If the concatenated bytes do not form valid UTF-8 — which can happen
    /// with pathological token sequences — [`String::from_utf8_lossy`] replaces
    /// invalid byte sequences with U+FFFD. This is the safe, lossless
    /// fallback mandated by the Security > Stability > Performance ordering.
    ///
    /// # Errors
    ///
    /// Currently infallible (always returns `Ok`). The `Result` wrapper matches
    /// the symmetric `encode` signature and allows future callers to use `?`
    /// without API changes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
    ///
    /// let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    /// // BOS + 'h' + 'i' + EOS → "hi" (specials stripped)
    /// let text = t.decode(&[256, 104, 105, 257]).unwrap();
    /// assert_eq!(text, "hi");
    /// ```
    // See encode() for the rationale behind the Result wrapper.
    #[allow(clippy::unnecessary_wraps)]
    pub fn decode(&self, ids: &[u32]) -> Result<String> {
        let special = &self.vocab.special_tokens;
        let mut bytes: Vec<u8> = Vec::new();

        for &id in ids {
            // Skip structural special tokens; they carry no text content.
            if id == special.bos || id == special.eos || id == special.pad {
                continue;
            }

            match self.vocab.token_bytes(id) {
                Some(token_bytes) => bytes.extend_from_slice(token_bytes),
                // Unknown ID: emit the Unicode replacement character so callers
                // receive a well-formed string rather than an error.
                None => bytes.extend_from_slice(REPLACEMENT_CHAR),
            }
        }

        // from_utf8_lossy handles the edge case where merged token bytes straddle
        // a UTF-8 boundary (should not happen with a correct vocab, but safe fallback).
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Return the total vocabulary size (regular + special tokens).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
    ///
    /// let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    /// assert!(t.vocab_size() >= 260);
    /// ```
    #[must_use]
    pub fn vocab_size(&self) -> u32 {
        self.vocab.vocab_size
    }

    /// Borrow the special-token IDs (BOS/EOS/PAD/UNK).
    ///
    /// Added for TASK-12: the `LocalCpuProvider` needs the EOS id to
    /// terminate greedy generation early.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_runtime::bpe::{BpeTokenizer, BpeVocabulary};
    ///
    /// let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
    /// assert_eq!(t.special_tokens().eos, 257);
    /// ```
    #[must_use]
    pub fn special_tokens(&self) -> &SpecialTokens {
        &self.vocab.special_tokens
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build the canonical test vocabulary used by most tests:
    /// - 256 single-byte tokens (IDs 0–255).
    /// - BOS=256, EOS=257, PAD=258, UNK=259.
    /// - Merges (in priority order):
    ///   h+e → he (260), l+l → ll (261), he+ll → hell (262), o+ → o  (263).
    fn test_vocab() -> BpeVocabulary {
        #[allow(clippy::cast_possible_truncation)]
        let mut tokens: Vec<(u32, Vec<u8>)> = (0u32..=255).map(|b| (b, vec![b as u8])).collect();

        tokens.push((256, b"<|bos|>".to_vec()));
        tokens.push((257, b"<|eos|>".to_vec()));
        tokens.push((258, b"<|pad|>".to_vec()));
        tokens.push((259, b"<|unk|>".to_vec()));
        tokens.push((260, b"he".to_vec()));
        tokens.push((261, b"ll".to_vec()));
        tokens.push((262, b"hell".to_vec()));
        tokens.push((263, b"o ".to_vec())); // 'o' followed by space

        let merges: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"h".to_vec(), b"e".to_vec()),
            (b"l".to_vec(), b"l".to_vec()),
            (b"he".to_vec(), b"ll".to_vec()),
            (b"o".to_vec(), b" ".to_vec()),
        ];

        let special_tokens = SpecialTokens {
            bos: 256,
            eos: 257,
            pad: 258,
            unk: 259,
        };

        BpeVocabulary::new(tokens, merges, special_tokens)
    }

    // ── BpeVocabulary ─────────────────────────────────────────────────────────

    #[test]
    fn vocab_token_id_single_byte() {
        let vocab = test_vocab();
        // Every byte value 0–255 is a valid token with ID == byte value.
        assert_eq!(vocab.token_id(&[0u8]), Some(0));
        assert_eq!(vocab.token_id(&[65u8]), Some(65)); // 'A'
        assert_eq!(vocab.token_id(&[255u8]), Some(255));
    }

    #[test]
    fn vocab_token_id_merged_token() {
        let vocab = test_vocab();
        assert_eq!(vocab.token_id(b"he"), Some(260));
        assert_eq!(vocab.token_id(b"ll"), Some(261));
        assert_eq!(vocab.token_id(b"hell"), Some(262));
    }

    #[test]
    fn vocab_token_id_unknown_returns_none() {
        let vocab = test_vocab();
        assert_eq!(vocab.token_id(b"xyz_not_in_vocab"), None);
    }

    #[test]
    fn vocab_token_bytes_roundtrip() {
        let vocab = test_vocab();
        for b in 0u32..=255 {
            let bytes = vocab.token_bytes(b).unwrap();
            assert_eq!(bytes, &[b as u8]);
        }
    }

    #[test]
    fn vocab_token_bytes_unknown_id_returns_none() {
        let vocab = test_vocab();
        assert_eq!(vocab.token_bytes(99_999), None);
    }

    // ── BpeTokenizer::encode ──────────────────────────────────────────────────

    #[test]
    fn encode_empty_string_returns_empty() {
        let t = BpeTokenizer::new(test_vocab());
        let ids = t.encode("").unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn encode_single_bytes_no_merges() {
        // 'x', 'y', 'z' have no merge rules in test_vocab.
        let t = BpeTokenizer::new(test_vocab());
        let ids = t.encode("xyz").unwrap();
        // Each byte becomes its own token with ID == byte value.
        assert_eq!(ids, vec![b'x' as u32, b'y' as u32, b'z' as u32]);
    }

    #[test]
    fn encode_applies_merges_in_priority_order() {
        let t = BpeTokenizer::new(test_vocab());
        // "hello": h(104)+e(101) → he(260), l(108)+l(108) → ll(261),
        //          he(260)+ll(261) → hell(262), o(111) remains.
        let ids = t.encode("hello").unwrap();
        assert_eq!(ids, vec![262, b'o' as u32]);
    }

    #[test]
    fn encode_partial_merge_only_applies_matching_rules() {
        let t = BpeTokenizer::new(test_vocab());
        // "he" only: h+e → he(260), nothing more.
        let ids = t.encode("he").unwrap();
        assert_eq!(ids, vec![260]);
    }

    #[test]
    fn encode_merge_with_space() {
        let t = BpeTokenizer::new(test_vocab());
        // "o ": o(111)+ (32) → o (263).
        let ids = t.encode("o ").unwrap();
        assert_eq!(ids, vec![263]);
    }

    // ── BpeTokenizer::encode_with_special ─────────────────────────────────────

    #[test]
    fn encode_with_special_prepends_bos_appends_eos() {
        let t = BpeTokenizer::new(test_vocab());
        let ids = t.encode_with_special("hi").unwrap();
        assert_eq!(ids.first(), Some(&256)); // BOS
        assert_eq!(ids.last(), Some(&257)); // EOS
    }

    #[test]
    fn encode_with_special_empty_text_has_only_bos_eos() {
        let t = BpeTokenizer::new(test_vocab());
        let ids = t.encode_with_special("").unwrap();
        assert_eq!(ids, vec![256, 257]);
    }

    // ── BpeTokenizer::decode ──────────────────────────────────────────────────

    #[test]
    fn decode_skips_bos_eos_pad() {
        let t = BpeTokenizer::new(test_vocab());
        // BOS(256), 'h'(104), 'i'(105), EOS(257)
        let text = t.decode(&[256, 104, 105, 257]).unwrap();
        assert_eq!(text, "hi");
    }

    #[test]
    fn decode_skips_pad_token() {
        let t = BpeTokenizer::new(test_vocab());
        // PAD(258), 'a'(97)
        let text = t.decode(&[258, 97]).unwrap();
        assert_eq!(text, "a");
    }

    #[test]
    fn decode_unknown_id_produces_replacement_character() {
        let t = BpeTokenizer::new(test_vocab());
        let text = t.decode(&[99_999]).unwrap();
        assert_eq!(text, "\u{FFFD}");
    }

    #[test]
    fn decode_empty_slice_returns_empty_string() {
        let t = BpeTokenizer::new(test_vocab());
        let text = t.decode(&[]).unwrap();
        assert_eq!(text, "");
    }

    // ── Encode → decode round-trips ───────────────────────────────────────────

    #[test]
    fn roundtrip_hello() {
        let t = BpeTokenizer::new(test_vocab());
        let text = "hello";
        let ids = t.encode(text).unwrap();
        let decoded = t.decode(&ids).unwrap();
        assert_eq!(decoded, text);
    }

    #[test]
    fn roundtrip_with_special_tokens() {
        let t = BpeTokenizer::new(test_vocab());
        let text = "hello world";
        let ids = t.encode_with_special(text).unwrap();
        // decode must skip BOS/EOS and recover the original string.
        let decoded = t.decode(&ids).unwrap();
        assert_eq!(decoded, text);
    }

    #[test]
    fn roundtrip_unicode() {
        // Use the minimal_test_vocab which covers all 256 byte values.
        let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
        let text = "café";
        let ids = t.encode(text).unwrap();
        let decoded = t.decode(&ids).unwrap();
        assert_eq!(decoded, text);
    }

    #[test]
    fn roundtrip_minimal_vocab_arbitrary_ascii() {
        let t = BpeTokenizer::new(BpeVocabulary::minimal_test_vocab());
        let text = "the quick brown fox";
        let ids = t.encode(text).unwrap();
        let decoded = t.decode(&ids).unwrap();
        assert_eq!(decoded, text);
    }

    // ── vocab_size ────────────────────────────────────────────────────────────

    #[test]
    fn vocab_size_test_vocab() {
        let t = BpeTokenizer::new(test_vocab());
        // 256 bytes + 4 special + 4 merged = 264
        assert_eq!(t.vocab_size(), 264);
    }

    #[test]
    fn vocab_size_minimal_test_vocab() {
        let vocab = BpeVocabulary::minimal_test_vocab();
        // 256 + 4 specials + 6 merged = 266
        assert!(vocab.vocab_size >= 260);
    }

    // ── MergeRule struct ──────────────────────────────────────────────────────

    #[test]
    fn merge_rule_fields_accessible() {
        let rule = MergeRule {
            left: b"a".to_vec(),
            right: b"b".to_vec(),
            merged: b"ab".to_vec(),
            priority: 0,
        };
        assert_eq!(rule.left, b"a");
        assert_eq!(rule.right, b"b");
        assert_eq!(rule.merged, b"ab");
        assert_eq!(rule.priority, 0);
    }

    // ── SpecialTokens struct ──────────────────────────────────────────────────

    #[test]
    fn special_tokens_fields_accessible() {
        let st = SpecialTokens {
            bos: 1,
            eos: 2,
            pad: 3,
            unk: 0,
        };
        assert_eq!(st.bos, 1);
        assert_eq!(st.eos, 2);
        assert_eq!(st.pad, 3);
        assert_eq!(st.unk, 0);
    }
}

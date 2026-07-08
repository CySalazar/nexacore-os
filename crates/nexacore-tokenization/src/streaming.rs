//! Incremental (streaming) detokenization with cross-chunk boundary buffering
//! (WS5-11.9).
//!
//! Model responses arrive incrementally — e.g. token-by-token over the
//! `ai_stream` syscall (WS5-03) — and an opaque token may be split across two
//! chunks (`…TKN-EMA` | `IL-1a2b3c4d…`). A naive per-chunk detokenization pass
//! would fail to resolve such a straddling token and leak a partial token to
//! the caller.
//!
//! [`StreamingDetokenizer`] solves this with a one-word boundary buffer: it
//! emits the detokenized text for every word that is provably complete (one
//! followed by whitespace) and holds back the trailing, possibly-incomplete
//! word until a later chunk — or [`StreamingDetokenizer::finish`] — proves it
//! complete. Resolution is delegated to a caller-supplied closure so this
//! module stays decoupled from the vault (and trivially testable); the
//! [`crate::TokenizationService`] wires it to the on-device vault so
//! detokenization happens only on the origin device.

/// A stateful detokenizer for a token stream delivered in arbitrary chunks
/// (WS5-11.9).
///
/// Feed chunks with [`push`](Self::push); each call returns the detokenized
/// text that is safe to emit so far. Call [`finish`](Self::finish) once the
/// stream ends to flush the final buffered word.
#[derive(Debug, Default)]
pub struct StreamingDetokenizer {
    /// The trailing run of text not yet known to end on a word boundary, held
    /// back because it might be the prefix of a token continued in the next
    /// chunk.
    pending: String,
}

impl StreamingDetokenizer {
    /// A new detokenizer with an empty boundary buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next `chunk`, returning the detokenized text safe to emit now.
    ///
    /// `resolve` maps a candidate token word to its plaintext, or returns
    /// `None` to leave the word unchanged (it is not a known token). The final
    /// incomplete word of the accumulated buffer is retained for the next call.
    pub fn push<F>(&mut self, chunk: &str, resolve: F) -> String
    where
        F: Fn(&str) -> Option<String>,
    {
        self.pending.push_str(chunk);

        // Byte offset just past the last whitespace char in the buffer. Text up
        // to there is complete (every word is whitespace-terminated); the
        // remainder is a possibly-incomplete trailing word.
        let mut boundary = 0usize;
        let mut found = false;
        for (i, c) in self.pending.char_indices() {
            if c.is_whitespace() {
                boundary = i + c.len_utf8();
                found = true;
            }
        }
        if !found {
            // The whole buffer is a single incomplete word — hold everything.
            return String::new();
        }

        let tail = self.pending.split_off(boundary);
        let head = core::mem::replace(&mut self.pending, tail);
        resolve_words(&head, &resolve)
    }

    /// Flush the final buffered word once the stream has ended (WS5-11.9).
    ///
    /// Consumes the detokenizer and resolves the trailing word (which has no
    /// terminating whitespace), so a token that ends the stream is resolved.
    #[must_use]
    pub fn finish<F>(mut self, resolve: F) -> String
    where
        F: Fn(&str) -> Option<String>,
    {
        let last = core::mem::take(&mut self.pending);
        resolve_words(&last, &resolve)
    }
}

/// Resolve every whitespace-delimited word in `text`, preserving the exact
/// whitespace between words. Words for which `resolve` returns `None` are kept
/// verbatim.
fn resolve_words<F>(text: &str, resolve: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    for c in text.chars() {
        if c.is_whitespace() {
            if !word.is_empty() {
                match resolve(&word) {
                    Some(plain) => out.push_str(&plain),
                    None => out.push_str(&word),
                }
                word.clear();
            }
            out.push(c);
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        match resolve(&word) {
            Some(plain) => out.push_str(&plain),
            None => out.push_str(&word),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// A resolver mapping a couple of fixed tokens to plaintext.
    fn resolver() -> impl Fn(&str) -> Option<String> {
        let mut map = HashMap::new();
        map.insert(
            "TKN-EMAIL-1a2b3c4d".to_string(),
            "alice@example.com".to_string(),
        );
        map.insert("TKN-NAME-9f9f9f9f".to_string(), "Alice".to_string());
        move |w: &str| map.get(w).cloned()
    }

    #[test]
    fn resolves_token_split_across_chunks() {
        let resolve = resolver();
        let mut sd = StreamingDetokenizer::new();
        let mut out = String::new();
        // The token is split between the two chunks.
        out.push_str(&sd.push("hi TKN-EMA", &resolve));
        out.push_str(&sd.push("IL-1a2b3c4d there", &resolve));
        out.push_str(&sd.finish(&resolve));
        assert_eq!(out, "hi alice@example.com there");
    }

    #[test]
    fn preserves_whitespace_and_resolves_clean_token() {
        let resolve = resolver();
        let mut sd = StreamingDetokenizer::new();
        let mut out = String::new();
        // A whitespace-delimited token is resolved; the double space before it
        // and the trailing space + newline after it are preserved exactly.
        out.push_str(&sd.push("dear  TKN-NAME-9f9f9f9f \n", &resolve));
        out.push_str(&sd.finish(&resolve));
        assert_eq!(out, "dear  Alice \n");
    }

    #[test]
    fn punctuation_attached_token_is_not_resolved() {
        // Tokens are whitespace-delimited by construction; a trailing comma
        // makes the word distinct from the token, so it is left verbatim.
        let resolve = resolver();
        let mut sd = StreamingDetokenizer::new();
        let mut out = String::new();
        out.push_str(&sd.push("hi TKN-NAME-9f9f9f9f, bye", &resolve));
        out.push_str(&sd.finish(&resolve));
        assert_eq!(out, "hi TKN-NAME-9f9f9f9f, bye");
    }

    #[test]
    fn token_at_end_of_stream_is_flushed_by_finish() {
        let resolve = resolver();
        let mut sd = StreamingDetokenizer::new();
        let mut out = String::new();
        // No trailing whitespace: push holds the token, finish resolves it.
        out.push_str(&sd.push("reply to TKN-EMAIL-1a2b3c4d", &resolve));
        assert!(
            !out.contains("alice@example.com"),
            "the final word must be held until finish: {out}"
        );
        out.push_str(&sd.finish(&resolve));
        assert_eq!(out, "reply to alice@example.com");
    }

    #[test]
    fn whole_token_in_one_chunk() {
        let resolve = resolver();
        let mut sd = StreamingDetokenizer::new();
        let mut out = String::new();
        out.push_str(&sd.push("TKN-NAME-9f9f9f9f said hi\n", &resolve));
        out.push_str(&sd.finish(&resolve));
        assert_eq!(out, "Alice said hi\n");
    }

    #[test]
    fn single_char_chunks_reassemble_correctly() {
        let resolve = resolver();
        let mut sd = StreamingDetokenizer::new();
        let mut out = String::new();
        for ch in "x TKN-NAME-9f9f9f9f y".chars() {
            out.push_str(&sd.push(&ch.to_string(), &resolve));
        }
        out.push_str(&sd.finish(&resolve));
        assert_eq!(out, "x Alice y");
    }

    #[test]
    fn empty_and_whitespace_chunks_are_safe() {
        let resolve = resolver();
        let mut sd = StreamingDetokenizer::new();
        let mut out = String::new();
        out.push_str(&sd.push("", &resolve));
        out.push_str(&sd.push("   ", &resolve));
        out.push_str(&sd.finish(&resolve));
        assert_eq!(out, "   ");
    }
}

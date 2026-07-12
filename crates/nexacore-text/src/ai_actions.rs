//! AI-native actions on the current selection (WS8-08.8).
//!
//! The editor's AI actions — rewrite, summarize, translate, explain, generate,
//! fix — applied to the current text selection, provider-agnostic and
//! local-first, mirroring the WS16-03 contextual-actions pattern.
//!
//! Because `nexacore-text` stays dependency-free, the provider seam is defined
//! *locally* as the [`SelectionAiProvider`] trait: the production implementation
//! (wired elsewhere, e.g. behind the WS16-03 `ai_stream`) is injected by the
//! caller, while host tests use a lightweight double. [`apply_to_selection`]
//! validates the selection range against the text (fail-closed: empty or
//! out-of-range selections return a typed [`AiActionError`], never a panic or an
//! index), invokes the provider, and returns the [`Replacement`] text plus the
//! byte range it applies to. It never edits the buffer itself — the caller
//! splices the replacement into the [`crate::buffer::PieceTable`].

use alloc::string::String;

/// An AI action applicable to a text selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextAiAction {
    /// Rephrase the selection while preserving its meaning.
    Rewrite,
    /// Condense the selection into a shorter summary.
    Summarize,
    /// Translate the selection into another language.
    Translate,
    /// Explain what the selection means or does.
    Explain,
    /// Generate new text from the selection treated as a prompt.
    Generate,
    /// Fix grammar, spelling, or (for code) obvious mistakes in the selection.
    Fix,
}

/// Why an AI action could not produce a replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiActionError {
    /// The selection was empty, so there is nothing to act on.
    EmptySelection,
    /// The selection range was out of bounds or not on UTF-8 char boundaries.
    OutOfRange,
    /// No provider was available to service the request.
    ProviderUnavailable(String),
    /// The provider declined the request (e.g. a safety or policy refusal).
    Rejected(String),
}

/// A computed replacement: the new `text` and the byte `range` it applies to.
///
/// The range is a `[start, end)` slice of the original document text, so the
/// caller can splice `text` in over exactly that range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The replacement text the provider returned.
    pub text: String,
    /// The `[start, end)` byte range in the original text this replaces.
    pub range: (usize, usize),
}

/// A provider that applies an [`TextAiAction`] to a selection string.
///
/// This is the local, dependency-free seam. The real implementation is injected
/// by higher layers (which own the model / streaming plumbing); host tests pass
/// a double.
pub trait SelectionAiProvider {
    /// Apply `action` to `selection`, returning the replacement text.
    ///
    /// # Errors
    /// Returns [`AiActionError::ProviderUnavailable`] if the provider cannot
    /// service the request, or [`AiActionError::Rejected`] if it declines it.
    fn apply(&self, action: TextAiAction, selection: &str) -> Result<String, AiActionError>;
}

/// Validate `selection` against `text`, apply `action` via `provider`, and
/// return the [`Replacement`] to splice in.
///
/// This computes the replacement only; it does not mutate any buffer. The
/// `selection` is a `[start, end)` byte range into `text`.
///
/// # Errors
/// - [`AiActionError::OutOfRange`] if `start > end`, `end` exceeds `text`, or
///   either endpoint is not a UTF-8 character boundary.
/// - [`AiActionError::EmptySelection`] if the range is valid but empty.
/// - Any error the `provider` returns.
pub fn apply_to_selection<P: SelectionAiProvider + ?Sized>(
    provider: &P,
    action: TextAiAction,
    text: &str,
    selection: (usize, usize),
) -> Result<Replacement, AiActionError> {
    let (start, end) = selection;
    // Fail closed on any malformed range before touching the provider.
    if start > end || end > text.len() {
        return Err(AiActionError::OutOfRange);
    }
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return Err(AiActionError::OutOfRange);
    }
    let slice = text.get(start..end).ok_or(AiActionError::OutOfRange)?;
    if slice.is_empty() {
        return Err(AiActionError::EmptySelection);
    }
    let replacement = provider.apply(action, slice)?;
    Ok(Replacement {
        text: replacement,
        range: (start, end),
    })
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::ToString};

    use super::*;

    /// A double that echoes the action name and selection back.
    struct EchoProvider;

    impl SelectionAiProvider for EchoProvider {
        fn apply(&self, action: TextAiAction, selection: &str) -> Result<String, AiActionError> {
            Ok(format!("{action:?}({selection})"))
        }
    }

    /// A double that always reports the provider is unavailable.
    struct DownProvider;

    impl SelectionAiProvider for DownProvider {
        fn apply(&self, _action: TextAiAction, _selection: &str) -> Result<String, AiActionError> {
            Err(AiActionError::ProviderUnavailable("offline".to_string()))
        }
    }

    /// A double that declines any request.
    struct PickyProvider;

    impl SelectionAiProvider for PickyProvider {
        fn apply(&self, _action: TextAiAction, _selection: &str) -> Result<String, AiActionError> {
            Err(AiActionError::Rejected("policy".to_string()))
        }
    }

    #[test]
    fn happy_path_returns_replacement_and_range() {
        let text = "hello world";
        let out = apply_to_selection(&EchoProvider, TextAiAction::Rewrite, text, (0, 5)).unwrap();
        assert_eq!(out.text, "Rewrite(hello)");
        assert_eq!(out.range, (0, 5));
    }

    #[test]
    fn each_action_variant_reaches_the_provider() {
        let text = "abc";
        for action in [
            TextAiAction::Rewrite,
            TextAiAction::Summarize,
            TextAiAction::Translate,
            TextAiAction::Explain,
            TextAiAction::Generate,
            TextAiAction::Fix,
        ] {
            let out = apply_to_selection(&EchoProvider, action, text, (0, 3)).unwrap();
            assert_eq!(out.text, format!("{action:?}(abc)"));
        }
    }

    #[test]
    fn empty_selection_is_rejected() {
        let text = "hello";
        let err = apply_to_selection(&EchoProvider, TextAiAction::Fix, text, (2, 2)).unwrap_err();
        assert_eq!(err, AiActionError::EmptySelection);
    }

    #[test]
    fn out_of_range_end_is_rejected() {
        let text = "hello";
        let err = apply_to_selection(&EchoProvider, TextAiAction::Fix, text, (0, 99)).unwrap_err();
        assert_eq!(err, AiActionError::OutOfRange);
    }

    #[test]
    fn inverted_range_is_rejected() {
        let text = "hello";
        let err = apply_to_selection(&EchoProvider, TextAiAction::Fix, text, (4, 1)).unwrap_err();
        assert_eq!(err, AiActionError::OutOfRange);
    }

    #[test]
    fn non_char_boundary_is_rejected() {
        // "café" — 'é' is two bytes (3..5), so offset 4 splits it.
        let text = "café";
        assert_eq!(text.len(), 5);
        let err = apply_to_selection(&EchoProvider, TextAiAction::Fix, text, (0, 4)).unwrap_err();
        assert_eq!(err, AiActionError::OutOfRange);
        // A boundary-aligned multi-byte selection is fine.
        let ok = apply_to_selection(&EchoProvider, TextAiAction::Fix, text, (0, 5)).unwrap();
        assert_eq!(ok.text, "Fix(café)");
        assert_eq!(ok.range, (0, 5));
    }

    #[test]
    fn provider_unavailable_propagates() {
        let text = "hello";
        let err =
            apply_to_selection(&DownProvider, TextAiAction::Summarize, text, (0, 5)).unwrap_err();
        assert_eq!(
            err,
            AiActionError::ProviderUnavailable("offline".to_string())
        );
    }

    #[test]
    fn provider_rejection_propagates() {
        let text = "hello";
        let err =
            apply_to_selection(&PickyProvider, TextAiAction::Translate, text, (0, 5)).unwrap_err();
        assert_eq!(err, AiActionError::Rejected("policy".to_string()));
    }

    #[test]
    fn works_through_a_trait_object() {
        let text = "hello world";
        let provider: &dyn SelectionAiProvider = &EchoProvider;
        let out = apply_to_selection(provider, TextAiAction::Explain, text, (6, 11)).unwrap();
        assert_eq!(out.text, "Explain(world)");
        assert_eq!(out.range, (6, 11));
    }
}

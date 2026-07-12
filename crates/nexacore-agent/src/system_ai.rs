//! System-wide AI surface: dictation, screen description, smart suggestions
//! (WS16-06).
//!
//! This module brings the `ai_transcribe` / vision capabilities into everyday
//! UX through three host-testable orchestration pieces, each effecting the
//! outside world only through a trait *seam* so the logic is unit-tested
//! without a real model or desktop:
//!
//! * **Dictation** ([`DictationSession`]) — a system-wide speech-to-text
//!   session driven by a [`TranscribeSeam`](crate::system_ai::TranscribeSeam) (the `ai_transcribe` bridge,
//!   WS5-03), inserting the result at the caret of the focused field
//!   ([`FocusedField`](crate::system_ai::FocusedField)), toggled by a global hotkey ([`DictationHotkey`](crate::system_ai::DictationHotkey)).
//! * **Screen description** ([`ScreenDescriber`]) — builds an accessibility
//!   description request for the focused element from the a11y tree (WS7-16)
//!   and renders it through a [`SceneDescribeSeam`](crate::system_ai::SceneDescribeSeam).
//! * **Smart suggestions** ([`SuggestionEngine`]) — proactive, **Inform-mode**
//!   (never self-acting) contextual suggestions, surfaced under a
//!   non-intrusive [`PresentationPolicy`](crate::system_ai::PresentationPolicy) that never steals focus and is
//!   rate-limited.
//!
//! The real `ai_transcribe`, the vision model, and the live desktop wiring are
//! behind the seams and exercised on the rig (WS16-06.8).

use core::fmt;

use crate::guidance::autonomy::AutonomyLevel;

/// Failure modes for the system AI surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemAiError {
    /// The transcription backend failed or returned nothing usable.
    Transcribe(&'static str),
    /// The scene-description backend failed.
    Describe(&'static str),
    /// The operation is invalid in the current state.
    InvalidState(&'static str),
}

impl fmt::Display for SystemAiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transcribe(s) => write!(f, "transcribe error: {s}"),
            Self::Describe(s) => write!(f, "describe error: {s}"),
            Self::InvalidState(s) => write!(f, "invalid state: {s}"),
        }
    }
}

impl std::error::Error for SystemAiError {}

// ===========================================================================
// Dictation (WS16-06.1, .2, .3)
// ===========================================================================

/// Bridge to `ai_transcribe` (WS5-03): turn a captured audio buffer into text.
pub trait TranscribeSeam: Send + Sync {
    /// Transcribe `audio` (raw PCM) to text.
    ///
    /// # Errors
    ///
    /// Returns [`SystemAiError::Transcribe`] if the backend cannot transcribe.
    fn transcribe(&self, audio: &[u8]) -> Result<String, SystemAiError>;
}

/// State of a system-wide dictation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DictationState {
    /// Not capturing.
    Idle,
    /// Capturing audio.
    Listening,
}

/// A text input field with a caret, the target of dictated text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FocusedField {
    /// Current field contents.
    pub content: String,
    /// Caret byte offset within `content` (clamped to a char boundary on use).
    pub caret: usize,
}

impl FocusedField {
    /// Insert `text` at the caret, advancing the caret past it. The caret is
    /// clamped to the field length and snapped down to a char boundary so the
    /// insertion never splits a UTF-8 sequence.
    pub fn insert_at_caret(&mut self, text: &str) {
        let mut at = self.caret.min(self.content.len());
        while at > 0 && !self.content.is_char_boundary(at) {
            at -= 1;
        }
        self.content.insert_str(at, text);
        self.caret = at + text.len();
    }
}

/// A system-wide dictation session.
pub struct DictationSession<T: TranscribeSeam> {
    backend: T,
    state: DictationState,
    buffer: Vec<u8>,
}

impl<T: TranscribeSeam> DictationSession<T> {
    /// Create an idle session over a transcription backend.
    pub fn new(backend: T) -> Self {
        Self {
            backend,
            state: DictationState::Idle,
            buffer: Vec::new(),
        }
    }

    /// Current session state.
    #[must_use]
    pub fn state(&self) -> DictationState {
        self.state
    }

    /// Toggle dictation on/off (the hotkey action). Returns the new state.
    /// Turning off discards any partially-captured audio that was not finished.
    pub fn toggle(&mut self) -> DictationState {
        self.state = match self.state {
            DictationState::Idle => DictationState::Listening,
            DictationState::Listening => {
                self.buffer.clear();
                DictationState::Idle
            }
        };
        self.state
    }

    /// Append captured audio while listening.
    ///
    /// # Errors
    ///
    /// Returns [`SystemAiError::InvalidState`] if not currently listening.
    pub fn feed_audio(&mut self, chunk: &[u8]) -> Result<(), SystemAiError> {
        if self.state != DictationState::Listening {
            return Err(SystemAiError::InvalidState(
                "dictation::feed_audio::not_listening",
            ));
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Finish listening: transcribe the captured audio, insert it at the
    /// focused field's caret, return to [`DictationState::Idle`], and return the
    /// inserted text.
    ///
    /// # Errors
    ///
    /// Returns [`SystemAiError::InvalidState`] if not listening, or
    /// [`SystemAiError::Transcribe`] if the backend fails (the session still
    /// returns to idle and the buffer is cleared).
    pub fn finish_into(&mut self, field: &mut FocusedField) -> Result<String, SystemAiError> {
        if self.state != DictationState::Listening {
            return Err(SystemAiError::InvalidState(
                "dictation::finish::not_listening",
            ));
        }
        let result = self.backend.transcribe(&self.buffer);
        self.buffer.clear();
        self.state = DictationState::Idle;
        let text = result?;
        field.insert_at_caret(&text);
        Ok(text)
    }
}

/// A global hotkey binding (modifier bitmask + key code) toggling dictation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DictationHotkey {
    /// Modifier bitmask (platform-defined; matched verbatim).
    pub modifiers: u8,
    /// Key code.
    pub key: u32,
}

impl DictationHotkey {
    /// Whether an incoming `(modifiers, key)` event matches this binding.
    #[must_use]
    pub fn matches(self, modifiers: u8, key: u32) -> bool {
        self.modifiers == modifiers && self.key == key
    }
}

// ===========================================================================
// Screen description (WS16-06.4, .5)
// ===========================================================================

/// The focused UI element, projected from the a11y tree (WS7-16).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FocusedElement {
    /// Accessibility role (e.g. "button", "textbox").
    pub role: String,
    /// Accessible label / name.
    pub label: String,
    /// Current value / text content, if any.
    pub value: String,
}

/// A request to describe a region of the screen for accessibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenDescribeRequest {
    /// The focused element to describe.
    pub element: FocusedElement,
    /// Whether to include the surrounding context, not just the element.
    pub include_context: bool,
}

/// Bridge to the vision/description model.
pub trait SceneDescribeSeam: Send + Sync {
    /// Produce a natural-language description for `request`.
    ///
    /// # Errors
    ///
    /// Returns [`SystemAiError::Describe`] if the backend cannot describe.
    fn describe(&self, request: &ScreenDescribeRequest) -> Result<String, SystemAiError>;
}

/// Builds description requests and renders them through a [`SceneDescribeSeam`].
pub struct ScreenDescriber<S: SceneDescribeSeam> {
    backend: S,
}

impl<S: SceneDescribeSeam> ScreenDescriber<S> {
    /// Create a describer over a backend.
    pub fn new(backend: S) -> Self {
        Self { backend }
    }

    /// Describe the focused element. When the element already carries a label
    /// and value, a concise local description is returned without invoking the
    /// model (cheap, deterministic, offline); otherwise the model seam is used.
    ///
    /// # Errors
    ///
    /// Returns [`SystemAiError::Describe`] if the model backend fails.
    pub fn describe_focused(&self, element: &FocusedElement) -> Result<String, SystemAiError> {
        if !element.label.is_empty() && !element.role.is_empty() {
            let mut out = format!("{}: {}", element.role, element.label);
            if !element.value.is_empty() {
                out.push_str(", ");
                out.push_str(&element.value);
            }
            return Ok(out);
        }
        let request = ScreenDescribeRequest {
            element: element.clone(),
            include_context: true,
        };
        self.backend.describe(&request)
    }
}

// ===========================================================================
// Smart suggestions (WS16-06.6, .7)
// ===========================================================================

/// A proactive contextual suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// Stable identifier (for dedup / dismissal).
    pub id: String,
    /// User-facing text.
    pub text: String,
    /// Relevance score; higher surfaces first.
    pub relevance: u32,
}

/// Context the suggestion engine reasons over.
#[derive(Debug, Clone, Default)]
pub struct SuggestionContext {
    /// The foreground application id.
    pub app: String,
    /// Ids the user has already dismissed (never re-surfaced).
    pub dismissed: Vec<String>,
}

/// Non-intrusive presentation policy: bounds how suggestions reach the user so
/// they never steal focus or spam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationPolicy {
    /// Maximum suggestions visible at once.
    pub max_visible: usize,
    /// Minimum milliseconds between surfacing events.
    pub min_interval_ms: u64,
}

impl Default for PresentationPolicy {
    fn default() -> Self {
        // Conservative defaults: at most two chips, at most one surfacing per
        // 30 s — proactive but never noisy.
        Self {
            max_visible: 2,
            min_interval_ms: 30_000,
        }
    }
}

/// Generates and presents proactive suggestions at [`AutonomyLevel::Inform`].
#[derive(Debug, Clone)]
pub struct SuggestionEngine {
    policy: PresentationPolicy,
}

impl SuggestionEngine {
    /// Create an engine with the given presentation policy.
    #[must_use]
    pub fn new(policy: PresentationPolicy) -> Self {
        Self { policy }
    }

    /// The autonomy level at which suggestions operate: always
    /// [`AutonomyLevel::Inform`] — the engine presents, it never acts.
    #[must_use]
    pub fn autonomy_level() -> AutonomyLevel {
        AutonomyLevel::Inform
    }

    /// Rank candidate suggestions: drop dismissed ones, sort by descending
    /// relevance (ties by id for determinism).
    #[must_use]
    pub fn rank(mut candidates: Vec<Suggestion>, ctx: &SuggestionContext) -> Vec<Suggestion> {
        candidates.retain(|s| !ctx.dismissed.contains(&s.id));
        candidates.sort_by(|a, b| b.relevance.cmp(&a.relevance).then_with(|| a.id.cmp(&b.id)));
        candidates
    }

    /// Decide what to surface now under the non-intrusive policy.
    ///
    /// Returns `None` (surface nothing) when the rate limit has not elapsed
    /// since `last_surfaced_ms`; otherwise returns up to `max_visible` ranked,
    /// non-dismissed suggestions. Surfacing never steals focus — the caller
    /// renders the returned set as passive chips.
    #[must_use]
    pub fn surface(
        &self,
        candidates: Vec<Suggestion>,
        ctx: &SuggestionContext,
        now_ms: u64,
        last_surfaced_ms: Option<u64>,
    ) -> Option<Vec<Suggestion>> {
        if let Some(last) = last_surfaced_ms {
            if now_ms.saturating_sub(last) < self.policy.min_interval_ms {
                return None;
            }
        }
        let mut ranked = Self::rank(candidates, ctx);
        ranked.truncate(self.policy.max_visible);
        if ranked.is_empty() {
            None
        } else {
            Some(ranked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoTranscribe;
    impl TranscribeSeam for EchoTranscribe {
        fn transcribe(&self, audio: &[u8]) -> Result<String, SystemAiError> {
            if audio.is_empty() {
                return Err(SystemAiError::Transcribe("empty"));
            }
            Ok(format!("words({})", audio.len()))
        }
    }

    #[test]
    fn dictation_toggles_and_inserts_at_caret() {
        let mut session = DictationSession::new(EchoTranscribe);
        assert_eq!(session.state(), DictationState::Idle);
        // Cannot feed while idle.
        assert!(session.feed_audio(&[1, 2]).is_err());
        // Toggle on, capture, finish into a field.
        assert_eq!(session.toggle(), DictationState::Listening);
        session.feed_audio(&[0u8; 5]).expect("feed");
        let mut field = FocusedField {
            content: "ab".to_owned(),
            caret: 1,
        };
        let text = session.finish_into(&mut field).expect("finish");
        assert_eq!(text, "words(5)");
        assert_eq!(field.content, "awords(5)b");
        assert_eq!(session.state(), DictationState::Idle);
    }

    #[test]
    fn dictation_insert_respects_char_boundary() {
        let mut field = FocusedField {
            content: "é".to_owned(), // 2 bytes
            caret: 1,                // mid-char → snapped to 0
        };
        field.insert_at_caret("X");
        assert_eq!(field.content, "Xé");
    }

    #[test]
    fn hotkey_matches_exact_binding() {
        let hk = DictationHotkey {
            modifiers: 0b101,
            key: 0x44,
        };
        assert!(hk.matches(0b101, 0x44));
        assert!(!hk.matches(0b100, 0x44));
        assert!(!hk.matches(0b101, 0x45));
    }

    struct StubDescribe;
    impl SceneDescribeSeam for StubDescribe {
        fn describe(&self, _r: &ScreenDescribeRequest) -> Result<String, SystemAiError> {
            Ok("model description".to_owned())
        }
    }

    #[test]
    fn describe_uses_local_text_when_labelled() {
        let d = ScreenDescriber::new(StubDescribe);
        let el = FocusedElement {
            role: "button".to_owned(),
            label: "Send".to_owned(),
            value: String::new(),
        };
        assert_eq!(d.describe_focused(&el).expect("desc"), "button: Send");
        let el2 = FocusedElement {
            role: "textbox".to_owned(),
            label: "Subject".to_owned(),
            value: "Hello".to_owned(),
        };
        assert_eq!(
            d.describe_focused(&el2).expect("desc"),
            "textbox: Subject, Hello"
        );
    }

    #[test]
    fn describe_falls_back_to_model_when_unlabelled() {
        let d = ScreenDescriber::new(StubDescribe);
        let el = FocusedElement::default(); // no role/label
        assert_eq!(d.describe_focused(&el).expect("desc"), "model description");
    }

    fn sugg(id: &str, rel: u32) -> Suggestion {
        Suggestion {
            id: id.to_owned(),
            text: format!("do {id}"),
            relevance: rel,
        }
    }

    #[test]
    fn suggestions_rank_and_drop_dismissed() {
        assert_eq!(SuggestionEngine::autonomy_level(), AutonomyLevel::Inform);
        let ctx = SuggestionContext {
            app: "editor".to_owned(),
            dismissed: vec!["b".to_owned()],
        };
        let ranked = SuggestionEngine::rank(vec![sugg("a", 5), sugg("b", 9), sugg("c", 7)], &ctx);
        // 'b' dismissed; remaining sorted by relevance desc → c(7), a(5).
        assert_eq!(
            ranked.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["c", "a"]
        );
    }

    #[test]
    fn surface_respects_rate_limit_and_max_visible() {
        let eng = SuggestionEngine::new(PresentationPolicy {
            max_visible: 2,
            min_interval_ms: 1000,
        });
        let ctx = SuggestionContext::default();
        let cands = vec![sugg("a", 1), sugg("b", 2), sugg("c", 3)];
        // First surfacing at t=0 → top 2 (c, b).
        let shown = eng.surface(cands.clone(), &ctx, 0, None).expect("shown");
        assert_eq!(
            shown.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["c", "b"]
        );
        // 500ms later, under the 1000ms limit → nothing surfaced.
        assert!(eng.surface(cands.clone(), &ctx, 500, Some(0)).is_none());
        // 1200ms later → surfaces again.
        assert!(eng.surface(cands, &ctx, 1200, Some(0)).is_some());
    }

    #[test]
    fn surface_empty_when_all_dismissed() {
        let eng = SuggestionEngine::new(PresentationPolicy::default());
        let ctx = SuggestionContext {
            app: "x".to_owned(),
            dismissed: vec!["a".to_owned()],
        };
        assert!(
            eng.surface(vec![sugg("a", 9)], &ctx, 100_000, None)
                .is_none()
        );
    }
}

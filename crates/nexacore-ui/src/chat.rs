//! Conversation-state model for the NexaCore Helper chat app (ADR-0046, TASK-24,
//! DE-D5).
//!
//! This module is **host-testable** (`no_std + alloc`) and contains no rendering
//! primitives; the app owns window layout and calls [`ChatState::render_lines`]
//! to obtain display-ready strings.
//!
//! ## Design overview
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`ChatRole`] | Discriminates user vs. assistant turns. |
//! | [`ChatMessage`] | One immutable (or in-progress) conversation turn. |
//! | [`ChatState`] | Bounded-history conversation buffer with streaming support. |
//!
//! ## Streaming seam
//!
//! `AiInvoke(80)` returns the whole answer synchronously; the chat reveals it
//! progressively via [`ChatState::append_chunk`] across frames.  When a real
//! token-streaming relay lands, the same `append_chunk` seam is ready to
//! consume incremental tokens without an API change.
//!
//! ## Per-message backend badge
//!
//! [`ChatState::finish_assistant`] stamps each completed assistant turn with the
//! [`crate::status_bar::BackendState`] that was live at the moment the answer
//! arrived.  Two turns served by different backends therefore carry different
//! badges — the failover acceptance criterion from ADR-0046 §D4.
//!
//! ## Bounds and safety
//!
//! - A single message's text is capped at [`MAX_MESSAGE_BYTES`] bytes.  Any
//!   input that would push the message beyond this cap is **silently truncated**
//!   at the cap boundary (see [`ChatState::push_user`] and
//!   [`ChatState::append_chunk`]).  This prevents a hostile or unexpectedly
//!   large response from blowing the heap.
//! - History depth is bounded by `max_messages` (set at construction).  When
//!   the buffer is full, the **oldest** turn is evicted before the new one is
//!   appended.
//!
//! ## Quick start
//!
//! ```
//! use nexacore_ui::{
//!     chat::{ChatRole, ChatState},
//!     status_bar::BackendState,
//! };
//!
//! let mut state = ChatState::new();
//! state.push_user("Hello!");
//! state.begin_assistant();
//! state.append_chunk("Hi there!");
//! state.finish_assistant(BackendState::Gpu, 37);
//!
//! assert_eq!(state.len(), 2);
//! assert_eq!(state.messages()[0].role, ChatRole::User);
//! assert_eq!(state.messages()[1].badge, Some(BackendState::Gpu));
//! ```

use alloc::{string::String, vec::Vec};

use crate::status_bar::BackendState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum size in bytes of a single message's text.
///
/// Inputs that would push a message past this boundary are truncated at the
/// last UTF-8 character boundary at or below the cap.  This is a defensive
/// heap bound — it is not a protocol limit.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024; // 8 KiB

/// Default maximum number of turns retained in [`ChatState`].
///
/// When `len() == max_messages` and a new turn is pushed, the oldest turn is
/// dropped.
const DEFAULT_MAX_MESSAGES: usize = 64;

// ---------------------------------------------------------------------------
// ChatRole
// ---------------------------------------------------------------------------

/// Who authored a chat turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatRole {
    /// The human user.
    User,
    /// The AI assistant.
    Assistant,
}

// ---------------------------------------------------------------------------
// ChatMessage
// ---------------------------------------------------------------------------

/// One message in the conversation.
///
/// Assistant turns are stamped with a [`BackendState`] badge and a round-trip
/// latency once [`ChatState::finish_assistant`] is called.  Until then —
/// and for all user turns — `badge` and `latency_ms` are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    /// Who authored this turn.
    pub role: ChatRole,
    /// Full text of the message (capped at [`MAX_MESSAGE_BYTES`]).
    pub text: String,
    /// Backend that served this turn (assistant turns only); `None` until
    /// [`ChatState::finish_assistant`] is called, and always `None` for user
    /// turns.
    pub badge: Option<BackendState>,
    /// Round-trip latency in milliseconds (assistant turns only); `None` until
    /// [`ChatState::finish_assistant`] is called, and always `None` for user
    /// turns.
    pub latency_ms: Option<u32>,
}

impl ChatMessage {
    /// Constructs a new, finished user message.
    fn user(text: &str) -> Self {
        Self {
            role: ChatRole::User,
            text: truncate_to_cap(text),
            badge: None,
            latency_ms: None,
        }
    }

    /// Constructs a new, empty in-progress assistant message.
    fn assistant_open() -> Self {
        Self {
            role: ChatRole::Assistant,
            text: String::new(),
            badge: None,
            latency_ms: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ChatState
// ---------------------------------------------------------------------------

/// In-memory conversation state with bounded history and streaming support.
///
/// History is capped at `max_messages` turns.  When the buffer is full and a
/// new turn is appended, the **oldest** turn is evicted so the newest turns are
/// always retained.
///
/// ## Streaming
///
/// An assistant turn is opened with [`ChatState::begin_assistant`], filled
/// incrementally via [`ChatState::append_chunk`], and closed with
/// [`ChatState::finish_assistant`].  The open turn is always the last element
/// in `messages`.
///
/// ## Defensive bounds
///
/// - Per-message text is capped at [`MAX_MESSAGE_BYTES`].
/// - History depth is capped at `max_messages`.
pub struct ChatState {
    /// Conversation history, oldest first.
    messages: Vec<ChatMessage>,
    /// Maximum number of turns to retain.
    max_messages: usize,
    /// Whether the last message is an open (in-progress) assistant turn.
    ///
    /// Tracked separately so `begin_assistant`/`append_chunk`/
    /// `finish_assistant` can guard against mis-sequenced calls without
    /// scanning the vec.
    assistant_open: bool,
}

impl ChatState {
    /// Creates a new [`ChatState`] with the default history cap
    /// (`DEFAULT_MAX_MESSAGES` = 64 turns).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::ChatState;
    ///
    /// let state = ChatState::new();
    /// assert!(state.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_MESSAGES)
    }

    /// Creates a new [`ChatState`] with an explicit history cap.
    ///
    /// `max_messages` is clamped to at least `1` internally so the state is
    /// always able to hold at least one turn.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::ChatState;
    ///
    /// let state = ChatState::with_capacity(4);
    /// assert!(state.is_empty());
    /// ```
    #[must_use]
    pub fn with_capacity(max_messages: usize) -> Self {
        Self {
            messages: Vec::new(),
            max_messages: max_messages.max(1),
            assistant_open: false,
        }
    }

    /// Returns a slice of all retained messages, oldest first.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::ChatState;
    ///
    /// let mut state = ChatState::new();
    /// state.push_user("hi");
    /// assert_eq!(state.messages().len(), 1);
    /// ```
    #[must_use]
    #[inline]
    pub fn messages(&self) -> &[ChatMessage] {
        &self.messages
    }

    /// Returns the number of retained turns.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::ChatState;
    ///
    /// let mut state = ChatState::new();
    /// assert_eq!(state.len(), 0);
    /// state.push_user("hello");
    /// assert_eq!(state.len(), 1);
    /// ```
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Returns `true` if there are no retained turns.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::ChatState;
    ///
    /// let state = ChatState::new();
    /// assert!(state.is_empty());
    /// ```
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Appends a completed user turn.
    ///
    /// If the buffer is at capacity, the oldest turn is evicted first.
    /// The text is truncated at [`MAX_MESSAGE_BYTES`] if necessary.
    ///
    /// Any open assistant turn is **not** automatically closed; callers must
    /// ensure sequencing is correct (user turn follows a finished assistant
    /// turn).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::{ChatRole, ChatState};
    ///
    /// let mut state = ChatState::new();
    /// state.push_user("hello");
    /// assert_eq!(state.messages()[0].role, ChatRole::User);
    /// assert_eq!(state.messages()[0].text, "hello");
    /// ```
    pub fn push_user(&mut self, text: &str) {
        self.evict_if_full();
        self.messages.push(ChatMessage::user(text));
        // A new user turn means no assistant turn is open.
        self.assistant_open = false;
    }

    /// Opens an empty assistant turn that [`ChatState::append_chunk`] will
    /// fill incrementally (streaming seam).
    ///
    /// If the buffer is at capacity, the oldest turn is evicted first.  If an
    /// assistant turn is already open (defensive case — e.g. a double call),
    /// this is a no-op: the existing open turn is reused.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::{ChatRole, ChatState};
    ///
    /// let mut state = ChatState::new();
    /// state.begin_assistant();
    /// assert_eq!(state.len(), 1);
    /// assert_eq!(state.messages()[0].role, ChatRole::Assistant);
    /// assert_eq!(state.messages()[0].text, "");
    /// ```
    pub fn begin_assistant(&mut self) {
        // Defensive guard: do not open a second assistant turn if one is
        // already open.
        if self.assistant_open {
            return;
        }
        self.evict_if_full();
        self.messages.push(ChatMessage::assistant_open());
        self.assistant_open = true;
    }

    /// Appends `chunk` to the text of the open assistant turn.
    ///
    /// If no assistant turn is currently open (defensive: e.g. called before
    /// [`ChatState::begin_assistant`]), one is opened implicitly.
    ///
    /// The total message text is capped at [`MAX_MESSAGE_BYTES`]: once the cap
    /// is reached, further chunks are silently ignored.  This prevents a
    /// hostile or unexpectedly large response from growing the heap without
    /// bound.
    ///
    /// # Panics
    ///
    /// Does not panic.  The internal `Option::unwrap` is preceded by an
    /// unconditional `begin_assistant` call that ensures `messages` is
    /// non-empty; the `last_mut` therefore always returns `Some`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::ChatState;
    ///
    /// let mut state = ChatState::new();
    /// state.begin_assistant();
    /// state.append_chunk("Hel");
    /// state.append_chunk("lo");
    /// assert_eq!(state.messages()[0].text, "Hello");
    /// ```
    pub fn append_chunk(&mut self, chunk: &str) {
        // Ensure there is an open assistant turn to write into.
        if !self.assistant_open {
            self.begin_assistant();
        }

        // The open turn is always the last message.
        // `self.messages` is non-empty because `begin_assistant` guarantees it.
        // We use an if-let rather than expect() to satisfy clippy::expect_used.
        if let Some(msg) = self.messages.last_mut() {
            let remaining = MAX_MESSAGE_BYTES.saturating_sub(msg.text.len());
            if remaining == 0 {
                // Cap already reached — discard the chunk silently.
                return;
            }

            // Truncate `chunk` to at most `remaining` bytes, snapping to the
            // last valid UTF-8 character boundary at or below the limit.
            let take = chunk.len().min(remaining);
            let safe_len = floor_char_boundary(chunk, take);
            msg.text.push_str(&chunk[..safe_len]);
        }
    }

    /// Stamps the open assistant turn with its backend badge and latency, then
    /// closes it.
    ///
    /// If no assistant turn is open, this is a no-op (defensive).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::{chat::ChatState, status_bar::BackendState};
    ///
    /// let mut state = ChatState::new();
    /// state.begin_assistant();
    /// state.append_chunk("answer");
    /// state.finish_assistant(BackendState::Gpu, 42);
    ///
    /// let msg = &state.messages()[0];
    /// assert_eq!(msg.badge, Some(BackendState::Gpu));
    /// assert_eq!(msg.latency_ms, Some(42));
    /// ```
    pub fn finish_assistant(&mut self, badge: BackendState, latency_ms: u32) {
        if !self.assistant_open {
            // Defensive: no open turn to stamp.
            return;
        }
        // The open turn is the last message.
        if let Some(msg) = self.messages.last_mut() {
            msg.badge = Some(badge);
            msg.latency_ms = Some(latency_ms);
        }
        self.assistant_open = false;
    }

    /// Formats the conversation as display lines (most recent last), wrapped
    /// to `cols` columns.
    /// Returns at most `max_lines` lines from the tail (the most recent lines).
    ///
    /// ## Line format
    ///
    /// | Turn | Lines |
    /// |------|-------|
    /// | User | `"> "` + text, wrapped; continuation lines indented to align |
    /// | Assistant | a standalone `"[GPU NNms]"` / `"[CPU NNms]"` / `"[..]"` header line, then the reply wrapped to the full width with a small hanging indent |
    ///
    /// Putting the badge on its own header line (rather than repeating it as a
    /// per-line prefix) keeps a long reply readable as a paragraph — on a
    /// narrow window a repeated `"[GPU] "` prefix degenerates into a
    /// one-word-per-line column.
    ///
    /// Wrapping is by **character count** (via `.chars().count()`), so it is
    /// UTF-8-aware.  `cols == 0` is treated as `cols == 1` to avoid division
    /// by zero or infinite loops.  `max_lines == 0` returns an empty vec.
    ///
    /// This function is **pure** (no side effects) and designed for unit
    /// testing.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::{chat::ChatState, status_bar::BackendState};
    ///
    /// let mut state = ChatState::new();
    /// state.push_user("hi");
    /// state.begin_assistant();
    /// state.append_chunk("Hello!");
    /// state.finish_assistant(BackendState::Gpu, 10);
    ///
    /// let lines = state.render_lines(80, 100);
    /// assert!(!lines.is_empty());
    /// ```
    #[must_use]
    pub fn render_lines(&self, cols: usize, max_lines: usize) -> Vec<String> {
        if max_lines == 0 {
            return Vec::new();
        }

        // Guard against cols == 0: treat as 1 to avoid divide-by-zero or
        // infinite loops in the word-wrap logic.
        let effective_cols = cols.max(1);

        let mut all_lines: Vec<String> = Vec::new();

        for msg in &self.messages {
            match msg.role {
                ChatRole::User => {
                    // "> " on the first line; a matching-width indent aligns any
                    // wrapped continuation lines under the text rather than
                    // repeating the marker.
                    wrap_message(&msg.text, "> ", "  ", effective_cols, &mut all_lines);
                }
                ChatRole::Assistant => {
                    // The backend badge (+latency) is a standalone header line;
                    // the reply then wraps to the full width with a small
                    // hanging indent, so it reads as a paragraph instead of
                    // repeating "[GPU] " on every wrapped line.
                    all_lines.push(assistant_header(msg));
                    if !msg.text.is_empty() {
                        wrap_message(&msg.text, "  ", "  ", effective_cols, &mut all_lines);
                    }
                }
            }
        }

        // Return at most `max_lines` lines from the tail.
        if all_lines.len() <= max_lines {
            all_lines
        } else {
            let start = all_lines.len() - max_lines;
            // `start < all_lines.len()` is guaranteed by the branch above.
            // The slice is therefore always in-bounds.
            all_lines
                .get(start..)
                .map(<[String]>::to_vec)
                .unwrap_or_default()
        }
    }

    // -----------------------------------------------------------------------
    // Private methods
    // -----------------------------------------------------------------------

    /// Evicts the oldest message if the buffer is at capacity.
    ///
    /// Uses `Vec::remove(0)` which is O(n), acceptable for the small bounded
    /// histories used in the chat UI (max 64 messages by default).
    fn evict_if_full(&mut self) {
        if self.messages.len() >= self.max_messages {
            self.messages.remove(0);
            // If the evicted message was an open assistant turn (edge case:
            // cap == 1), reset the open flag.
            // In practice this cannot happen with well-sequenced calls
            // (user turn → begin_assistant → finish), but we reset for safety.
            // We cannot check whether the removed message was the open one
            // after the removal, so we use a conservative heuristic: if the
            // cap is 1, any open turn was just removed.
            if self.max_messages == 1 {
                self.assistant_open = false;
            }
        }
    }
}

impl Default for ChatState {
    /// Equivalent to [`ChatState::new`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_ui::chat::ChatState;
    ///
    /// let state = ChatState::default();
    /// assert!(state.is_empty());
    /// ```
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Private free functions
// ---------------------------------------------------------------------------

/// Returns a new [`String`] containing at most [`MAX_MESSAGE_BYTES`] bytes of
/// `s`, snapping to a valid UTF-8 character boundary.
fn truncate_to_cap(s: &str) -> String {
    let len = floor_char_boundary(s, MAX_MESSAGE_BYTES);
    s[..len].into()
}

/// Returns the standalone header line for an assistant turn: the backend
/// badge, plus round-trip latency once the turn is finished.
///
/// | State | Header |
/// |-------|--------|
/// | `Gpu`, finished | `"[GPU 42ms]"` |
/// | `CpuDegraded`, finished | `"[CPU 42ms]"` |
/// | `Unknown` / in-progress | `"[..]"` |
fn assistant_header(msg: &ChatMessage) -> String {
    let badge_tag = match msg.badge {
        Some(BackendState::Gpu) => "GPU",
        Some(BackendState::CpuDegraded) => "CPU",
        Some(BackendState::Unknown) | None => "..",
    };
    msg.latency_ms.map_or_else(
        || alloc::format!("[{badge_tag}]"),
        |ms| alloc::format!("[{badge_tag} {ms}ms]"),
    )
}

/// Wraps `text` into display lines, appending them to `out`.
///
/// The first logical line of the message is prefixed by `first_prefix`;
/// subsequent (wrapped) lines are prefixed by `cont_prefix`.  The combined
/// width of prefix + content is kept within `cols` characters (measured by
/// `chars().count()`).
///
/// Empty text produces a single line containing only the first prefix (so
/// an in-progress assistant turn is visible as an empty message bubble).
fn wrap_message(
    text: &str,
    first_prefix: &str,
    cont_prefix: &str,
    cols: usize,
    out: &mut Vec<String>,
) {
    // Determine the character budget available for actual content after
    // the prefix.  If the prefix itself is wider than cols, we still
    // allow at least 1 character of content so we always make progress.
    let first_budget = cols.saturating_sub(first_prefix.chars().count()).max(1);
    let cont_budget = cols.saturating_sub(cont_prefix.chars().count()).max(1);

    if text.is_empty() {
        // Emit an empty-content line (e.g. open assistant turn).
        out.push(String::from(first_prefix));
        return;
    }

    let chars: Vec<char> = text.chars().collect();
    let mut pos = 0;
    let mut is_first = true;

    while pos < chars.len() {
        let (prefix, budget) = if is_first {
            (first_prefix, first_budget)
        } else {
            (cont_prefix, cont_budget)
        };

        let hard_end = (pos + budget).min(chars.len());
        // Prefer a word boundary: if the hard cut would land inside a token,
        // back up to the last space within this line's window. A single token
        // longer than `budget` still hard-splits, so we always make progress.
        let mut end = hard_end;
        let splits_token =
            hard_end < chars.len() && chars.get(hard_end).is_some_and(|c| !c.is_whitespace());
        if splits_token {
            if let Some(space_idx) = (pos..hard_end)
                .rev()
                .find(|&i| chars.get(i).is_some_and(|c| c.is_whitespace()))
            {
                if space_idx > pos {
                    end = space_idx;
                }
            }
        }

        // `pos <= end <= chars.len()` is guaranteed by the bounds above.
        let slice: String = chars
            .get(pos..end)
            .map(|sl| sl.iter().collect())
            .unwrap_or_default();
        out.push(alloc::format!("{prefix}{slice}"));

        // Advance past the emitted slice and any spaces at the break point, so
        // the next wrapped line does not start with leading whitespace.
        pos = end;
        while pos < chars.len() && chars.get(pos).is_some_and(|c| c.is_whitespace()) {
            pos += 1;
        }
        is_first = false;
    }
}

/// Returns the largest byte index `<= max_bytes` that is a valid UTF-8
/// character boundary in `s`.
///
/// If `max_bytes >= s.len()`, returns `s.len()`.  If `max_bytes == 0`,
/// returns `0`.  This is needed because we truncate byte slices and must
/// not split a multi-byte codepoint.
fn floor_char_boundary(s: &str, max_bytes: usize) -> usize {
    if max_bytes >= s.len() {
        return s.len();
    }
    // Walk backwards from max_bytes to find a valid UTF-8 start byte.
    // UTF-8 continuation bytes have the form 0b10xxxxxx (i.e. (b & 0xC0) == 0x80).
    let bytes = s.as_bytes();
    let mut idx = max_bytes;
    // `idx` starts at `max_bytes < s.len()`, so `bytes.get(idx)` is always
    // within bounds during the loop.
    while idx > 0 && bytes.get(idx).is_some_and(|b| (b & 0xC0) == 0x80) {
        idx -= 1;
    }
    idx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_bar::BackendState;

    // -----------------------------------------------------------------------
    // Conversation state
    // -----------------------------------------------------------------------

    /// `push_user("hi")` then streaming assistant turn → 2 messages with
    /// correct roles, text, badge, and latency.
    #[test]
    fn conversation_state_basic() {
        let mut state = ChatState::new();
        state.push_user("hi");
        state.begin_assistant();
        state.append_chunk("4");
        state.finish_assistant(BackendState::Gpu, 42);

        assert_eq!(state.len(), 2, "exactly 2 messages");

        let user = &state.messages()[0];
        assert_eq!(user.role, ChatRole::User);
        assert_eq!(user.text, "hi");
        assert_eq!(user.badge, None);
        assert_eq!(user.latency_ms, None);

        let asst = &state.messages()[1];
        assert_eq!(asst.role, ChatRole::Assistant);
        assert_eq!(asst.text, "4");
        assert_eq!(asst.badge, Some(BackendState::Gpu));
        assert_eq!(asst.latency_ms, Some(42));
    }

    // -----------------------------------------------------------------------
    // Incremental chunks (streaming)
    // -----------------------------------------------------------------------

    /// Chunks are concatenated in order; finishing stamps the badge.
    #[test]
    fn incremental_chunks_concatenated() {
        let mut state = ChatState::new();
        state.begin_assistant();
        state.append_chunk("Hel");
        state.append_chunk("lo");

        // Text must be concatenated before finish.
        assert_eq!(state.messages()[0].text, "Hello");
        assert_eq!(state.messages()[0].badge, None, "badge not yet stamped");

        state.finish_assistant(BackendState::CpuDegraded, 99);
        assert_eq!(state.messages()[0].badge, Some(BackendState::CpuDegraded));
        assert_eq!(state.messages()[0].latency_ms, Some(99));
    }

    // -----------------------------------------------------------------------
    // Per-message badge across backends (KEY acceptance test)
    // -----------------------------------------------------------------------

    /// Turn 1 finishes with `Gpu`; turn 2 finishes with `CpuDegraded`.
    /// Each message must retain its own badge independently.
    #[test]
    fn per_message_badge_across_backends() {
        let mut state = ChatState::new();

        // Turn 1: user asks, assistant answers via GPU.
        state.push_user("question one");
        state.begin_assistant();
        state.append_chunk("answer one");
        state.finish_assistant(BackendState::Gpu, 10);

        // Turn 2: user asks again; backend has failed over to CPU.
        state.push_user("question two");
        state.begin_assistant();
        state.append_chunk("answer two");
        state.finish_assistant(BackendState::CpuDegraded, 200);

        assert_eq!(state.len(), 4, "two user + two assistant turns");

        let msg0 = &state.messages()[1]; // first assistant turn
        assert_eq!(msg0.role, ChatRole::Assistant);
        assert_eq!(
            msg0.badge,
            Some(BackendState::Gpu),
            "first assistant turn must carry Gpu badge"
        );

        let msg1 = &state.messages()[3]; // second assistant turn
        assert_eq!(msg1.role, ChatRole::Assistant);
        assert_eq!(
            msg1.badge,
            Some(BackendState::CpuDegraded),
            "second assistant turn must carry CpuDegraded badge"
        );
    }

    // -----------------------------------------------------------------------
    // Bounded history
    // -----------------------------------------------------------------------

    /// With cap=4, pushing >4 turns keeps only the 4 newest (oldest evicted).
    #[test]
    fn bounded_history_evicts_oldest() {
        let mut state = ChatState::with_capacity(4);

        // Push 6 user turns.
        for i in 0u8..6 {
            state.push_user(alloc::format!("msg{i}").as_str());
        }

        assert!(
            state.len() <= 4,
            "len must not exceed cap ({})",
            state.len()
        );

        // The newest messages should be retained (msg2..msg5).
        let texts: Vec<&str> = state.messages().iter().map(|m| m.text.as_str()).collect();
        assert!(texts.contains(&"msg5"), "newest message must be retained");
        assert!(
            !texts.contains(&"msg0"),
            "oldest message must have been evicted"
        );
    }

    // -----------------------------------------------------------------------
    // render_lines
    // -----------------------------------------------------------------------

    /// `render_lines` returns non-empty output after a couple of turns.
    #[test]
    fn render_lines_non_empty() {
        let mut state = ChatState::new();
        state.push_user("hi");
        state.begin_assistant();
        state.append_chunk("hello");
        state.finish_assistant(BackendState::Gpu, 5);

        let lines = state.render_lines(80, 100);
        assert!(
            !lines.is_empty(),
            "render_lines must produce at least one line"
        );
    }

    /// `render_lines(0, 10)` must not panic (cols==0 treated as 1).
    #[test]
    fn render_lines_cols_zero_no_panic() {
        let mut state = ChatState::new();
        state.push_user("test");
        // Must not panic.
        let _ = state.render_lines(0, 10);
    }

    /// The assistant line prefix reflects the GPU badge after a `Gpu` finish.
    #[test]
    fn render_lines_badge_reflected_in_prefix() {
        let mut state = ChatState::new();
        state.begin_assistant();
        state.append_chunk("response");
        state.finish_assistant(BackendState::Gpu, 42);

        let lines = state.render_lines(80, 100);
        let combined = lines.join("\n");
        assert!(
            combined.contains("[GPU"),
            "rendered output must contain '[GPU' for Gpu badge; got: {combined:?}"
        );
    }

    /// `render_lines` respects `max_lines`: returns the tail only.
    #[test]
    fn render_lines_respects_max_lines() {
        let mut state = ChatState::new();
        // Push 10 user messages → 10 lines minimum.
        for i in 0..10u8 {
            state.push_user(alloc::format!("msg{i}").as_str());
        }

        let lines = state.render_lines(80, 3);
        assert_eq!(lines.len(), 3, "must return exactly max_lines lines");
    }

    /// `render_lines` returns empty vec when `max_lines` == 0.
    #[test]
    fn render_lines_max_lines_zero() {
        let mut state = ChatState::new();
        state.push_user("hi");
        let lines = state.render_lines(80, 0);
        assert!(lines.is_empty());
    }

    // -----------------------------------------------------------------------
    // append_chunk text cap
    // -----------------------------------------------------------------------

    /// Appending a chunk longer than `MAX_MESSAGE_BYTES` is truncated; no panic.
    #[test]
    fn append_chunk_cap_truncates_no_panic() {
        let mut state = ChatState::new();
        state.begin_assistant();

        // A single chunk larger than the cap.
        let huge = "A".repeat(MAX_MESSAGE_BYTES + 1000);
        state.append_chunk(&huge); // must not panic

        assert!(
            state.messages()[0].text.len() <= MAX_MESSAGE_BYTES,
            "text must not exceed MAX_MESSAGE_BYTES after large chunk"
        );
    }

    /// Once the cap is reached, further `append_chunk` calls are silently
    /// ignored (no unbounded growth).
    #[test]
    fn append_chunk_cap_no_growth_after_full() {
        let mut state = ChatState::new();
        state.begin_assistant();

        // Fill to exactly the cap.
        let fill = "B".repeat(MAX_MESSAGE_BYTES);
        state.append_chunk(&fill);
        assert_eq!(state.messages()[0].text.len(), MAX_MESSAGE_BYTES);

        // More chunks should be ignored.
        state.append_chunk("extra");
        assert_eq!(
            state.messages()[0].text.len(),
            MAX_MESSAGE_BYTES,
            "length must not grow past cap"
        );
    }

    // -----------------------------------------------------------------------
    // Defensive edge cases
    // -----------------------------------------------------------------------

    /// `begin_assistant` twice is a no-op the second time.
    #[test]
    fn begin_assistant_double_is_noop() {
        let mut state = ChatState::new();
        state.begin_assistant();
        state.append_chunk("first");
        state.begin_assistant(); // defensive second call — must not open a new turn
        state.append_chunk(" second");

        // Should still be a single assistant message.
        assert_eq!(state.len(), 1);
        assert_eq!(state.messages()[0].text, "first second");
    }

    /// `finish_assistant` with no open turn is a no-op.
    #[test]
    fn finish_assistant_no_open_is_noop() {
        let mut state = ChatState::new();
        // No open turn — must not panic.
        state.finish_assistant(BackendState::Gpu, 1);
        assert!(state.is_empty());
    }

    /// `append_chunk` with no open turn implicitly opens one.
    #[test]
    fn append_chunk_opens_turn_if_none() {
        let mut state = ChatState::new();
        // No begin_assistant — defensive implicit open.
        state.append_chunk("implicit");
        assert_eq!(state.len(), 1);
        assert_eq!(state.messages()[0].text, "implicit");
    }

    // -----------------------------------------------------------------------
    // floor_char_boundary
    // -----------------------------------------------------------------------

    /// `floor_char_boundary` snaps to a valid UTF-8 boundary.
    #[test]
    fn floor_char_boundary_multibyte() {
        // "é" is 2 bytes (0xC3 0xA9).  Requesting index 1 should snap to 0.
        let s = "éàü";
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(
            floor_char_boundary(s, 1),
            0,
            "mid-codepoint should snap back"
        );
        assert_eq!(floor_char_boundary(s, 2), 2, "exact boundary is fine");
        assert_eq!(
            floor_char_boundary(s, 100),
            s.len(),
            "beyond end returns len"
        );
    }

    // -----------------------------------------------------------------------
    // CpuDegraded badge in render
    // -----------------------------------------------------------------------

    /// `render_lines` shows "[CPU" for a `CpuDegraded` turn.
    #[test]
    fn render_lines_cpu_badge() {
        let mut state = ChatState::new();
        state.begin_assistant();
        state.append_chunk("cpu answer");
        state.finish_assistant(BackendState::CpuDegraded, 300);

        let lines = state.render_lines(80, 100);
        let combined = lines.join("\n");
        assert!(
            combined.contains("[CPU"),
            "rendered output must contain '[CPU' for CpuDegraded; got: {combined:?}"
        );
    }

    /// `render_lines` shows "[.." for an `Unknown` badge.
    #[test]
    fn render_lines_unknown_badge() {
        let mut state = ChatState::new();
        state.begin_assistant();
        state.append_chunk("unknown answer");
        state.finish_assistant(BackendState::Unknown, 0);

        let lines = state.render_lines(80, 100);
        let combined = lines.join("\n");
        assert!(
            combined.contains("[.."),
            "rendered output must contain '[..' for Unknown; got: {combined:?}"
        );
    }

    /// `render_lines` includes latency in the first line of an assistant turn.
    #[test]
    fn render_lines_latency_in_first_line() {
        let mut state = ChatState::new();
        state.begin_assistant();
        state.append_chunk("answer");
        state.finish_assistant(BackendState::Gpu, 42);

        let lines = state.render_lines(80, 100);
        // The first (and only) line should contain "42ms".
        assert!(
            lines[0].contains("42ms"),
            "first assistant line must include latency; got: {:?}",
            lines[0]
        );
    }

    /// User lines are prefixed with `"> "`.
    #[test]
    fn render_lines_user_prefix() {
        let mut state = ChatState::new();
        state.push_user("hello");

        let lines = state.render_lines(80, 100);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("> "),
            "user line must start with '> '; got: {:?}",
            lines[0]
        );
    }

    /// Wrapping breaks on spaces (not mid-word) when a boundary fits the
    /// budget, and continuation lines are indented rather than re-prefixed.
    #[test]
    fn render_lines_wraps_on_word_boundaries() {
        let mut state = ChatState::new();
        state.push_user("alpha bravo charlie");

        // cols=10, prefix "> " → 8-char budget: each word fits on its own line.
        let lines = state.render_lines(10, 100);
        assert_eq!(
            lines,
            alloc::vec![
                String::from("> alpha"),
                String::from("  bravo"),
                String::from("  charlie"),
            ],
            "words must stay intact and continuations indent; got: {lines:?}"
        );
    }

    /// A single token longer than the budget still hard-splits so wrapping
    /// always makes progress (no infinite loop, no dropped text).
    #[test]
    fn render_lines_long_token_hard_splits() {
        let mut state = ChatState::new();
        state.push_user("abcdefghij"); // 10 chars, no spaces

        // cols=6, prefix "> " → 4-char budget for the first line.
        let lines = state.render_lines(6, 100);
        // Reassembling the content (minus prefixes/indents) yields the token.
        let joined: String = lines
            .iter()
            .map(|l| l.trim_start_matches(['>', ' ']))
            .collect();
        assert_eq!(joined, "abcdefghij", "no text lost; got: {lines:?}");
        assert!(lines.len() > 1, "must wrap across lines; got: {lines:?}");
    }
}

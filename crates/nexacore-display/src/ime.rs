//! Input Method Editor (IME) framework + a basic Pinyin engine (WS7-07.5/.6).
//!
//! An IME sits between the keymap ([`crate::keymap`], which turns keycodes into
//! characters) and the application. Instead of every character going straight
//! to the focused widget, the IME **composes**: it accumulates raw input into a
//! *preedit* string, offers a list of *candidates*, and only emits text when the
//! user *commits* a candidate. This is what makes it possible to type languages
//! with far more graphemes than keys — Chinese, Japanese, Korean.
//!
//! [`ImeEngine`] is the framework interface (WS7-07.5): `feed` a character,
//! read the visible [`ImeState`] (preedit + candidates + highlight), and
//! `commit`/`select`/`cancel`. [`PinyinIme`] is a minimal engine (WS7-07.6):
//! lowercase letters accumulate a pinyin syllable, a conversion table maps it to
//! Hanzi candidates, and a digit key or space commits one. Pure state,
//! `no_std + alloc` — host-testable, no display or IPC dependency.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

/// The visible state an IME presents to the UI while composing.
///
/// The UI draws the `preedit` (usually underlined, in place) and, when
/// `candidates` is non-empty, a candidate list with `selected` highlighted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImeState {
    preedit: String,
    candidates: Vec<String>,
    selected: usize,
}

impl ImeState {
    /// The in-progress composition (raw input, e.g. the pinyin letters typed).
    #[must_use]
    pub fn preedit(&self) -> &str {
        &self.preedit
    }

    /// The candidate strings for the current preedit (may be empty).
    #[must_use]
    pub fn candidates(&self) -> &[String] {
        &self.candidates
    }

    /// Index of the highlighted candidate. Only meaningful when
    /// [`ImeState::candidates`] is non-empty; clamped to a valid index whenever
    /// the candidate list changes.
    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// `true` when there is no active composition (no preedit, no candidates).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.preedit.is_empty() && self.candidates.is_empty()
    }

    /// The currently highlighted candidate, if any.
    #[must_use]
    pub fn selected_candidate(&self) -> Option<&str> {
        self.candidates.get(self.selected).map(String::as_str)
    }
}

/// Outcome of feeding one character to an [`ImeEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImeResponse {
    /// The character was consumed and composition is still in progress; the UI
    /// should redraw from [`ImeEngine::state`].
    Updating,
    /// A string was committed (a candidate was selected). The composition is
    /// cleared; the app should insert the returned text.
    Commit(String),
    /// The IME did not consume the character (no active composition and the key
    /// is not an IME trigger); the app should handle it as a normal key.
    Passthrough(char),
}

/// An input method engine: consumes characters, maintains a preedit and
/// candidate list, and commits text on selection (WS7-07.5).
pub trait ImeEngine {
    /// Feed one character. See [`ImeResponse`] for the outcomes.
    fn feed(&mut self, c: char) -> ImeResponse;

    /// The current visible composition state.
    fn state(&self) -> &ImeState;

    /// Commit the candidate at `index` (0-based). Returns the committed string
    /// and clears the composition, or `None` if `index` is out of range (the
    /// composition is left untouched).
    fn select(&mut self, index: usize) -> Option<String>;

    /// Commit the currently highlighted candidate, if any.
    fn commit_selected(&mut self) -> Option<String> {
        let idx = self.state().selected();
        self.select(idx)
    }

    /// Remove the last character from the preedit, recomputing candidates.
    /// Returns [`ImeResponse::Passthrough`] of a backspace when there is no
    /// composition to edit (so the app deletes a real character instead).
    fn backspace(&mut self) -> ImeResponse;

    /// Abandon the current composition without committing anything.
    fn cancel(&mut self);
}

/// A minimal Pinyin input method (WS7-07.6).
///
/// Lowercase ASCII letters accumulate a pinyin syllable into the preedit; a
/// conversion table maps the syllable to an ordered list of Hanzi candidates.
/// A digit `1`..=`9` commits the candidate at that 1-based position; space
/// commits the highlighted candidate. Any other key with an empty preedit
/// passes through unchanged.
pub struct PinyinIme {
    table: BTreeMap<String, Vec<String>>,
    state: ImeState,
}

impl PinyinIme {
    /// Construct an engine with an empty conversion table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: BTreeMap::new(),
            state: ImeState::default(),
        }
    }

    /// Register a `pinyin → hanzi` mapping. Multiple calls for the same syllable
    /// append candidates in insertion order (most common first, by convention).
    pub fn add_word(&mut self, pinyin: &str, hanzi: &str) {
        self.table
            .entry(pinyin.to_string())
            .or_default()
            .push(hanzi.to_string());
    }

    /// Convenience constructor seeding a tiny demo table (ni/hao/…), used by the
    /// WS7-07.7 desktop demo and the unit tests.
    #[must_use]
    pub fn with_demo_table() -> Self {
        let mut ime = Self::new();
        // A few syllables with more than one candidate to exercise selection.
        ime.add_word("ni", "你"); // you
        ime.add_word("ni", "尼");
        ime.add_word("ni", "泥");
        ime.add_word("hao", "好"); // good
        ime.add_word("hao", "号");
        ime.add_word("zhong", "中"); // middle
        ime.add_word("wen", "文"); // language/script
        ime
    }

    /// Recompute the candidate list for the current preedit and clamp the
    /// highlight into range.
    fn refresh_candidates(&mut self) {
        self.state.candidates = self
            .table
            .get(&self.state.preedit)
            .cloned()
            .unwrap_or_default();
        if self.state.selected >= self.state.candidates.len() {
            self.state.selected = 0;
        }
    }

    fn clear(&mut self) {
        self.state = ImeState::default();
    }
}

impl Default for PinyinIme {
    fn default() -> Self {
        Self::new()
    }
}

impl ImeEngine for PinyinIme {
    fn feed(&mut self, c: char) -> ImeResponse {
        // Lowercase ASCII letters extend the pinyin syllable.
        if c.is_ascii_lowercase() {
            self.state.preedit.push(c);
            self.refresh_candidates();
            return ImeResponse::Updating;
        }

        // With no active composition, nothing else is an IME action.
        if self.state.preedit.is_empty() {
            return ImeResponse::Passthrough(c);
        }

        // Digit 1..=9 selects the candidate at that 1-based position.
        if let Some(d) = c.to_digit(10) {
            if (1..=9).contains(&d) {
                let idx = (d - 1) as usize;
                if let Some(committed) = self.select(idx) {
                    return ImeResponse::Commit(committed);
                }
                // Digit out of candidate range: ignore, keep composing.
                return ImeResponse::Updating;
            }
        }

        // Space commits the highlighted candidate.
        if c == ' ' {
            if let Some(committed) = self.commit_selected() {
                return ImeResponse::Commit(committed);
            }
            // No candidate for this preedit: drop the failed composition and let
            // the space through as a normal key.
            self.clear();
            return ImeResponse::Passthrough(' ');
        }

        // Any other key while composing is ignored (kept for the UI to decide).
        ImeResponse::Updating
    }

    fn state(&self) -> &ImeState {
        &self.state
    }

    fn select(&mut self, index: usize) -> Option<String> {
        let committed = self.state.candidates.get(index).cloned()?;
        self.clear();
        Some(committed)
    }

    fn backspace(&mut self) -> ImeResponse {
        if self.state.preedit.pop().is_none() {
            return ImeResponse::Passthrough('\u{8}'); // no composition to edit
        }
        if self.state.preedit.is_empty() {
            self.clear();
        } else {
            self.refresh_candidates();
        }
        ImeResponse::Updating
    }

    fn cancel(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_engine_is_empty() {
        let ime = PinyinIme::new();
        assert!(ime.state().is_empty());
        assert_eq!(ime.state().preedit(), "");
        assert!(ime.state().candidates().is_empty());
    }

    #[test]
    fn letters_accumulate_preedit_and_surface_candidates() {
        let mut ime = PinyinIme::with_demo_table();
        assert_eq!(ime.feed('n'), ImeResponse::Updating);
        assert_eq!(ime.state().preedit(), "n");
        assert!(ime.state().candidates().is_empty(), "no word 'n' yet");
        assert_eq!(ime.feed('i'), ImeResponse::Updating);
        assert_eq!(ime.state().preedit(), "ni");
        assert_eq!(ime.state().candidates(), ["你", "尼", "泥"]);
        assert_eq!(ime.state().selected(), 0);
        assert_eq!(ime.state().selected_candidate(), Some("你"));
    }

    #[test]
    fn digit_key_commits_that_candidate() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('n');
        ime.feed('i');
        // '3' -> 1-based third candidate -> "泥".
        assert_eq!(ime.feed('3'), ImeResponse::Commit("泥".to_string()));
        assert!(ime.state().is_empty(), "composition cleared after commit");
    }

    #[test]
    fn space_commits_highlighted_candidate() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('h');
        ime.feed('a');
        ime.feed('o');
        assert_eq!(ime.state().candidates(), ["好", "号"]);
        assert_eq!(ime.feed(' '), ImeResponse::Commit("好".to_string()));
        assert!(ime.state().is_empty());
    }

    #[test]
    fn digit_out_of_range_keeps_composing() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('h');
        ime.feed('a');
        ime.feed('o'); // 2 candidates
        assert_eq!(ime.feed('5'), ImeResponse::Updating);
        assert_eq!(ime.state().preedit(), "hao", "still composing");
    }

    #[test]
    fn passthrough_when_not_composing() {
        let mut ime = PinyinIme::with_demo_table();
        assert_eq!(ime.feed('!'), ImeResponse::Passthrough('!'));
        assert_eq!(ime.feed(' '), ImeResponse::Passthrough(' '));
        assert!(ime.state().is_empty());
    }

    #[test]
    fn space_on_unknown_syllable_passes_through_and_clears() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('x');
        ime.feed('q'); // no such syllable → no candidates
        assert!(ime.state().candidates().is_empty());
        assert_eq!(ime.feed(' '), ImeResponse::Passthrough(' '));
        assert!(ime.state().is_empty(), "failed composition dropped");
    }

    #[test]
    fn backspace_edits_then_passes_through_when_empty() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('n');
        ime.feed('i');
        assert_eq!(ime.state().candidates(), ["你", "尼", "泥"]);
        assert_eq!(ime.backspace(), ImeResponse::Updating);
        assert_eq!(ime.state().preedit(), "n");
        assert!(ime.state().candidates().is_empty());
        assert_eq!(ime.backspace(), ImeResponse::Updating); // removes 'n'
        assert!(ime.state().is_empty());
        // Nothing left to edit → the backspace passes through to the app.
        assert_eq!(ime.backspace(), ImeResponse::Passthrough('\u{8}'));
    }

    #[test]
    fn select_out_of_range_is_none_and_keeps_state() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('n');
        ime.feed('i');
        assert_eq!(ime.select(99), None);
        assert_eq!(ime.state().preedit(), "ni", "composition untouched");
    }

    #[test]
    fn cancel_abandons_composition() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('n');
        ime.feed('i');
        ime.cancel();
        assert!(ime.state().is_empty());
    }

    #[test]
    fn commit_selected_uses_the_highlight() {
        let mut ime = PinyinIme::with_demo_table();
        ime.feed('z');
        ime.feed('h');
        ime.feed('o');
        ime.feed('n');
        ime.feed('g');
        assert_eq!(ime.state().candidates(), ["中"]);
        assert_eq!(ime.commit_selected(), Some("中".to_string()));
        assert!(ime.state().is_empty());
    }
}

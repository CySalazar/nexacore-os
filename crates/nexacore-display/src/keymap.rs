//! Keyboard layout tables and scancode → character mapping (WS7-07.1/.2/.3).
//!
//! An input keycode (the stable display keycode produced by the HID layer) is
//! translated to a character through the **active layout table**. A layout is
//! declared in a small XKB-like text format — one `keycode base [shift] [altgr]`
//! line per key — parsed into a [`LayoutTable`] (WS7-07.1). [`Keymap`] resolves a
//! `(keycode, modifiers)` pair to a character through the active table
//! (WS7-07.2) and switches between loaded layouts at runtime, e.g. IT ⇄ DE
//! (WS7-07.3).
//!
//! Dead keys / compose sequences (WS7-07.4) build on this. `no_std + alloc`.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

/// The characters a single key produces at each shift level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutKey {
    /// Unmodified character.
    pub base: char,
    /// Character with Shift held (`None` if the key has no shifted form).
    pub shift: Option<char>,
    /// Character with `AltGr` (level-3) held (`None` if unused).
    pub altgr: Option<char>,
}

/// Active modifier state for a key resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mods {
    /// Shift held.
    pub shift: bool,
    /// `AltGr` (right Alt / level-3) held.
    pub altgr: bool,
    /// Caps Lock engaged (affects letters only).
    pub caps: bool,
}

/// A parsed keyboard layout: a name and a keycode → [`LayoutKey`] map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutTable {
    /// The layout name (e.g. `"it"`, `"de"`).
    pub name: String,
    keys: BTreeMap<u8, LayoutKey>,
}

impl LayoutTable {
    /// Parse a layout from the XKB-like text format.
    ///
    /// Each non-empty, non-`#` line is `keycode base [shift] [altgr]`, where
    /// `keycode` is decimal and the character fields are a single character or
    /// `-` for "none". A malformed line is skipped.
    ///
    /// ```text
    /// # us letters
    /// 4 a A
    /// # italian: `AltGr` on 'e' gives the euro sign
    /// 8 e E €
    /// ```
    #[must_use]
    pub fn parse(name: &str, text: &str) -> Self {
        let mut keys = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.split_whitespace();
            let Some(code) = f.next().and_then(|c| c.parse::<u8>().ok()) else {
                continue;
            };
            let Some(base) = f.next().and_then(single_char) else {
                continue;
            };
            let shift = f.next().and_then(single_char);
            let altgr = f.next().and_then(single_char);
            keys.insert(code, LayoutKey { base, shift, altgr });
        }
        Self {
            name: name.to_string(),
            keys,
        }
    }

    /// The number of keys in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the table has no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Resolve `keycode` under `mods` to a character.
    ///
    /// `AltGr` selects the level-3 character; otherwise the shift level is chosen
    /// by Shift XOR (Caps Lock, for letters only). Returns `None` if the key is
    /// not in the table or the requested level has no character.
    #[must_use]
    pub fn resolve(&self, keycode: u8, mods: Mods) -> Option<char> {
        let key = self.keys.get(&keycode)?;
        if mods.altgr {
            return key.altgr;
        }
        let caps_effect = mods.caps && key.base.is_alphabetic();
        if mods.shift ^ caps_effect {
            key.shift
        } else {
            Some(key.base)
        }
    }
}

/// Parse a single-character field: one `char`, or `None` for the `-` sentinel.
fn single_char(field: &str) -> Option<char> {
    if field == "-" {
        return None;
    }
    let mut chars = field.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None; // more than one char → malformed
    }
    Some(c)
}

/// A keymap holding one or more layouts with a switchable active one
/// (WS7-07.3).
#[derive(Debug, Clone, Default)]
pub struct Keymap {
    layouts: Vec<LayoutTable>,
    active: usize,
}

impl Keymap {
    /// An empty keymap with no layouts.
    #[must_use]
    pub fn new() -> Self {
        Self {
            layouts: Vec::new(),
            active: 0,
        }
    }

    /// Add a layout. The first layout added becomes active.
    pub fn add_layout(&mut self, table: LayoutTable) {
        self.layouts.push(table);
    }

    /// The active layout's name, if any layout is loaded.
    #[must_use]
    pub fn active_name(&self) -> Option<&str> {
        self.layouts.get(self.active).map(|l| l.name.as_str())
    }

    /// The number of loaded layouts.
    #[must_use]
    pub fn layout_count(&self) -> usize {
        self.layouts.len()
    }

    /// Switch the active layout by name; returns `true` if a layout with that
    /// name was found.
    pub fn switch_to(&mut self, name: &str) -> bool {
        if let Some(idx) = self.layouts.iter().position(|l| l.name == name) {
            self.active = idx;
            true
        } else {
            false
        }
    }

    /// Cycle to the next loaded layout (wrapping), returning the new active
    /// name. A common global hot-key action (WS7-07.3).
    pub fn cycle(&mut self) -> Option<&str> {
        if self.layouts.is_empty() {
            return None;
        }
        self.active = (self.active + 1) % self.layouts.len();
        self.active_name()
    }

    /// Resolve `keycode` under `mods` through the active layout.
    #[must_use]
    pub fn resolve(&self, keycode: u8, mods: Mods) -> Option<char> {
        self.layouts.get(self.active)?.resolve(keycode, mods)
    }
}

// =============================================================================
// Dead keys and compose sequences (WS7-07.4)
// =============================================================================

/// A key fed to the [`Composer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// An ordinary character.
    Char(char),
    /// A dead key carrying an accent (e.g. acute `´`): it produces no character
    /// on its own but combines with the next character.
    Dead(char),
    /// The Compose (`Multi_key`) key: begins a compose sequence.
    Compose,
}

/// The result of feeding a [`Key`] to the [`Composer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeOutput {
    /// A dead key or a partial compose sequence is pending; emit nothing yet.
    Pending,
    /// Emit these characters (usually one; two when a dead key did not combine).
    Emit(Vec<char>),
}

/// Dead-key and compose-sequence resolution (WS7-07.4).
///
/// A dead key arms a pending accent that combines with the next character
/// (`´` then `e` → `é`); a non-combining follow-up emits the accent then the
/// character. The Compose key begins a sequence accumulated until it matches a
/// registered sequence (`Compose a e` → `æ`) or can no longer be a prefix of
/// one (then the buffer is emitted literally).
#[derive(Debug, Clone, Default)]
pub struct Composer {
    dead: BTreeMap<(char, char), char>,
    compose: BTreeMap<Vec<char>, char>,
    pending_dead: Option<char>,
    compose_buf: Vec<char>,
    composing: bool,
}

impl Composer {
    /// An empty composer with no combinations.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a dead-key combination: `accent` + `base` → `result`.
    pub fn add_dead(&mut self, accent: char, base: char, result: char) {
        self.dead.insert((accent, base), result);
    }

    /// Register a compose sequence (the keys typed after Compose) → `result`.
    pub fn add_compose(&mut self, sequence: &[char], result: char) {
        self.compose.insert(sequence.to_vec(), result);
    }

    /// Feed one key, returning what (if anything) to emit.
    pub fn feed(&mut self, key: Key) -> ComposeOutput {
        match key {
            Key::Dead(accent) => self.feed_dead(accent),
            Key::Compose => {
                // (Re)start a compose sequence; flush any pending dead accent.
                let mut out = Vec::new();
                if let Some(prev) = self.pending_dead.take() {
                    out.push(prev);
                }
                self.composing = true;
                self.compose_buf.clear();
                if out.is_empty() {
                    ComposeOutput::Pending
                } else {
                    ComposeOutput::Emit(out)
                }
            }
            Key::Char(c) => self.feed_char(c),
        }
    }

    fn feed_dead(&mut self, accent: char) -> ComposeOutput {
        // A second dead key emits the first accent literally, then arms the new.
        let flushed = self.pending_dead.replace(accent);
        flushed.map_or(ComposeOutput::Pending, |prev| {
            ComposeOutput::Emit(alloc::vec![prev])
        })
    }

    fn feed_char(&mut self, c: char) -> ComposeOutput {
        if let Some(accent) = self.pending_dead.take() {
            return match self.dead.get(&(accent, c)) {
                Some(&combined) => ComposeOutput::Emit(alloc::vec![combined]),
                None => ComposeOutput::Emit(alloc::vec![accent, c]),
            };
        }
        if self.composing {
            self.compose_buf.push(c);
            if let Some(&result) = self.compose.get(&self.compose_buf) {
                self.reset_compose();
                return ComposeOutput::Emit(alloc::vec![result]);
            }
            if self.is_compose_prefix() {
                return ComposeOutput::Pending;
            }
            // Dead end: emit what was accumulated literally.
            let buf = core::mem::take(&mut self.compose_buf);
            self.composing = false;
            return ComposeOutput::Emit(buf);
        }
        ComposeOutput::Emit(alloc::vec![c])
    }

    /// Whether the current buffer is a strict prefix of some longer sequence.
    fn is_compose_prefix(&self) -> bool {
        self.compose
            .keys()
            .any(|k| k.len() > self.compose_buf.len() && k.starts_with(&self.compose_buf))
    }

    fn reset_compose(&mut self) {
        self.composing = false;
        self.compose_buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn us() -> LayoutTable {
        // keycode 4 = 'a', 8 = 'e' (with € on AltGr), 30 = '1'/'!'.
        LayoutTable::parse("us", "# comment\n4 a A\n8 e E €\n30 1 !\n")
    }

    fn de() -> LayoutTable {
        // A tiny German layout: keycode 8 = 'e', and 28 = 'z' (QWERTZ swap demo).
        LayoutTable::parse("de", "8 e E\n28 z Z\n")
    }

    #[test]
    fn parses_layout_skipping_comments_and_malformed() {
        let table = us();
        assert_eq!(table.name, "us");
        assert_eq!(table.len(), 3);
        // Malformed lines (bad keycode, empty) are skipped.
        let bad = LayoutTable::parse("x", "notanum a\n4 ab A\n\n5 x X\n");
        assert_eq!(bad.len(), 1); // only "5 x X" is well-formed
    }

    #[test]
    fn resolves_base_shift_and_altgr() {
        let table = us();
        let none = Mods::default();
        assert_eq!(table.resolve(4, none), Some('a'));
        assert_eq!(
            table.resolve(
                4,
                Mods {
                    shift: true,
                    ..none
                }
            ),
            Some('A')
        );
        assert_eq!(
            table.resolve(
                8,
                Mods {
                    altgr: true,
                    ..none
                }
            ),
            Some('€')
        );
        assert_eq!(table.resolve(30, none), Some('1'));
        assert_eq!(
            table.resolve(
                30,
                Mods {
                    shift: true,
                    ..none
                }
            ),
            Some('!')
        );
        // Unknown keycode → None.
        assert_eq!(table.resolve(99, none), None);
    }

    #[test]
    fn caps_lock_affects_only_letters() {
        let table = us();
        let caps = Mods {
            caps: true,
            ..Mods::default()
        };
        // Letter: Caps Lock uppercases.
        assert_eq!(table.resolve(4, caps), Some('A'));
        // Caps + Shift on a letter cancels back to lowercase.
        assert_eq!(
            table.resolve(
                4,
                Mods {
                    caps: true,
                    shift: true,
                    ..Mods::default()
                }
            ),
            Some('a')
        );
        // Digit key: Caps Lock has no effect (stays base, not the shifted '!').
        assert_eq!(table.resolve(30, caps), Some('1'));
    }

    #[test]
    fn keymap_switches_and_cycles_layouts() {
        let mut km = Keymap::new();
        km.add_layout(us());
        km.add_layout(de());
        assert_eq!(km.active_name(), Some("us"));
        assert_eq!(km.layout_count(), 2);

        // Under US, keycode 28 is unmapped; under DE it is 'z'.
        assert_eq!(km.resolve(28, Mods::default()), None);
        assert!(km.switch_to("de"));
        assert_eq!(km.active_name(), Some("de"));
        assert_eq!(km.resolve(28, Mods::default()), Some('z'));

        // Switching to an unknown layout leaves the active one unchanged.
        assert!(!km.switch_to("fr"));
        assert_eq!(km.active_name(), Some("de"));

        // Cycle wraps back to US.
        assert_eq!(km.cycle(), Some("us"));
    }

    #[test]
    fn empty_keymap_resolves_to_none() {
        let km = Keymap::new();
        assert_eq!(km.resolve(4, Mods::default()), None);
        assert_eq!(km.active_name(), None);
    }

    // --- Dead keys & compose (WS7-07.4) -------------------------------------

    fn composer() -> Composer {
        let mut c = Composer::new();
        c.add_dead('´', 'e', 'é');
        c.add_dead('´', 'a', 'á');
        c.add_compose(&['a', 'e'], 'æ');
        c.add_compose(&['o', 'o', 'o'], '∞'); // a 3-char sequence
        c
    }

    #[test]
    fn dead_key_combines_with_next_char() {
        let mut c = composer();
        assert_eq!(c.feed(Key::Dead('´')), ComposeOutput::Pending);
        assert_eq!(
            c.feed(Key::Char('e')),
            ComposeOutput::Emit(alloc::vec!['é'])
        );
        // A plain char after that is emitted normally.
        assert_eq!(
            c.feed(Key::Char('x')),
            ComposeOutput::Emit(alloc::vec!['x'])
        );
    }

    #[test]
    fn dead_key_without_combination_emits_both() {
        let mut c = composer();
        c.feed(Key::Dead('´'));
        // '´' does not combine with 's' → emit accent then the char.
        assert_eq!(
            c.feed(Key::Char('s')),
            ComposeOutput::Emit(alloc::vec!['´', 's'])
        );
    }

    #[test]
    fn compose_sequence_matches() {
        let mut c = composer();
        assert_eq!(c.feed(Key::Compose), ComposeOutput::Pending);
        assert_eq!(c.feed(Key::Char('a')), ComposeOutput::Pending); // prefix of "ae"
        assert_eq!(
            c.feed(Key::Char('e')),
            ComposeOutput::Emit(alloc::vec!['æ'])
        );
        // Sequence is over; the next Compose starts fresh.
        assert_eq!(c.feed(Key::Compose), ComposeOutput::Pending);
        assert_eq!(c.feed(Key::Char('o')), ComposeOutput::Pending);
        assert_eq!(c.feed(Key::Char('o')), ComposeOutput::Pending);
        assert_eq!(
            c.feed(Key::Char('o')),
            ComposeOutput::Emit(alloc::vec!['∞'])
        );
    }

    #[test]
    fn compose_dead_end_emits_buffer_literally() {
        let mut c = composer();
        c.feed(Key::Compose);
        c.feed(Key::Char('a')); // prefix of "ae"
        // 'x' cannot continue any sequence → emit the accumulated buffer.
        assert_eq!(
            c.feed(Key::Char('x')),
            ComposeOutput::Emit(alloc::vec!['a', 'x'])
        );
    }
}

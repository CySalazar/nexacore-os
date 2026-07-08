//! System-wide customizable keyboard shortcuts (WS17-04).
//!
//! A [`ShortcutRegistry`] maps **rebindable actions** (global or per-app) to
//! key [`Chord`]s, supports multi-step chords (e.g. `Ctrl+K Ctrl+S`), detects
//! binding conflicts, ships `macOS`/`Windows` presets, persists overrides as
//! plain strings (so the WS17-01 typed config store holds them like any other
//! `Str` value), and exposes a settings-panel view.
//!
//! The matching is pure data: input is delivered as [`KeyStroke`]s to a
//! [`ChordMatcher`] which resolves a completed chord to an action. Every effect
//! (intercepting input, dispatching the action) lives outside this crate, so
//! the whole registry is host-testable.
//!
//! ## Persistence (WS17-04.8)
//!
//! A [`Chord`] round-trips through a canonical string — `"Ctrl+Shift+A"`,
//! `"Ctrl+K Ctrl+S"` — via [`Chord::to_canonical`] / [`Chord::parse`]. The
//! registry yields its user overrides as `(config-key, chord-string)` pairs
//! ([`ShortcutRegistry::export_overrides`]) and re-applies them
//! ([`ShortcutRegistry::apply_overrides`]); the caller stores those strings in
//! the `nexacore-config` store under the `shortcuts.*` namespace.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write as _;

// =============================================================================
// Keys, modifiers, strokes, chords
// =============================================================================

/// The modifier keys held during a keystroke.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four fields are the canonical keyboard modifier set (Ctrl/Alt/Shift/Meta); named bools read clearer than a bitflag here"
)]
pub struct Modifiers {
    /// Control.
    pub ctrl: bool,
    /// Alt / Option.
    pub alt: bool,
    /// Shift.
    pub shift: bool,
    /// Meta / Command / Super.
    pub meta: bool,
}

impl Modifiers {
    /// No modifiers held.
    pub const NONE: Self = Self {
        ctrl: false,
        alt: false,
        shift: false,
        meta: false,
    };

    /// Only Control.
    #[must_use]
    pub const fn ctrl() -> Self {
        Self {
            ctrl: true,
            ..Self::NONE
        }
    }

    /// Only Meta (Command / Super).
    #[must_use]
    pub const fn meta() -> Self {
        Self {
            meta: true,
            ..Self::NONE
        }
    }

    /// Add Shift to this modifier set (builder style).
    #[must_use]
    pub const fn with_shift(mut self) -> Self {
        self.shift = true;
        self
    }

    /// Add Alt to this modifier set (builder style).
    #[must_use]
    pub const fn with_alt(mut self) -> Self {
        self.alt = true;
        self
    }

    /// Whether no modifier is held.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !(self.ctrl || self.alt || self.shift || self.meta)
    }
}

/// A single key (the non-modifier part of a keystroke).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Key {
    /// A character key, stored lower-cased so `A` and `a` bind identically.
    Char(char),
    /// Return / Enter.
    Enter,
    /// Tab.
    Tab,
    /// Space bar.
    Space,
    /// Escape.
    Escape,
    /// Backspace.
    Backspace,
    /// Delete (forward delete).
    Delete,
    /// Up arrow.
    Up,
    /// Down arrow.
    Down,
    /// Left arrow.
    Left,
    /// Right arrow.
    Right,
    /// Home.
    Home,
    /// End.
    End,
    /// A function key `F1..=F24`.
    Function(u8),
}

impl Key {
    /// A character key, normalized to lower case.
    #[must_use]
    pub fn char(c: char) -> Self {
        // `to_lowercase` may yield several chars (e.g. 'İ'); take the first, or
        // fall back to the original for the (rare) multi-char case.
        Self::Char(c.to_lowercase().next().unwrap_or(c))
    }
}

/// One press: a [`Key`] plus the [`Modifiers`] held with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyStroke {
    /// Modifiers held.
    pub mods: Modifiers,
    /// The key pressed.
    pub key: Key,
}

impl KeyStroke {
    /// A keystroke from `mods` + `key`.
    #[must_use]
    pub const fn new(mods: Modifiers, key: Key) -> Self {
        Self { mods, key }
    }
}

/// A chord: one or more [`KeyStroke`]s pressed in sequence. A length-1 chord is
/// an ordinary single-key shortcut; longer chords are multi-step (WS17-04.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Chord(Vec<KeyStroke>);

impl Chord {
    /// A chord from a sequence of strokes (empty is rejected at parse time).
    #[must_use]
    pub fn new(strokes: Vec<KeyStroke>) -> Self {
        Self(strokes)
    }

    /// A single-stroke chord.
    #[must_use]
    pub fn single(stroke: KeyStroke) -> Self {
        Self(alloc::vec![stroke])
    }

    /// The strokes of this chord.
    #[must_use]
    pub fn strokes(&self) -> &[KeyStroke] {
        &self.0
    }

    /// Number of steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the chord has no strokes (only constructible internally).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `self` is a strict prefix of `other` (used by the matcher to
    /// keep waiting for a longer multi-step chord).
    #[must_use]
    pub fn is_strict_prefix_of(&self, other: &Self) -> bool {
        self.0.len() < other.0.len() && other.0.starts_with(&self.0)
    }

    /// Render the chord as its canonical string (WS17-04.8), e.g.
    /// `"Ctrl+K Ctrl+S"`.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        let mut out = String::new();
        for (i, s) in self.0.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            write_stroke(&mut out, s);
        }
        out
    }

    /// Parse a canonical chord string (WS17-04.8). Strokes are space-separated;
    /// within a stroke, `+`-separated tokens are modifiers then exactly one
    /// key.
    ///
    /// # Errors
    /// Returns [`ShortcutError::Parse`] on an empty or malformed string.
    pub fn parse(s: &str) -> Result<Self, ShortcutError> {
        let mut strokes = Vec::new();
        for token in s.split_whitespace() {
            strokes.push(parse_stroke(token)?);
        }
        if strokes.is_empty() {
            return Err(ShortcutError::Parse);
        }
        Ok(Self(strokes))
    }
}

// =============================================================================
// Actions, scope, registry
// =============================================================================

/// Stable identifier of a rebindable action (e.g. `"edit.copy"`).
pub type ActionId = String;

/// Where an action and its binding apply (WS17-04.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// System-wide: active in every app unless an app-scoped binding shadows it.
    Global,
    /// Active only while the named app is focused.
    App(String),
}

/// A registered action's metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionInfo {
    /// Where the action applies.
    pub scope: Scope,
    /// Human-readable description for the settings panel.
    pub description: String,
}

/// One row of the settings-panel shortcut view (WS17-04.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortcutEntry {
    /// The action id.
    pub id: ActionId,
    /// Where it applies.
    pub scope: Scope,
    /// Human-readable description.
    pub description: String,
    /// The bound chord as a canonical string, or `None` if unbound.
    pub chord: Option<String>,
}

/// A binding conflict: a `(scope, chord)` claimed by more than one action
/// (WS17-04.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// The contested scope.
    pub scope: Scope,
    /// The contested chord (canonical string).
    pub chord: String,
    /// The actions claiming it (sorted).
    pub actions: Vec<ActionId>,
}

/// The system-wide shortcut registry (WS17-04.1/.2/.3/.4).
#[derive(Clone, Debug, Default)]
pub struct ShortcutRegistry {
    /// Registered actions, keyed by id.
    actions: BTreeMap<ActionId, ActionInfo>,
    /// The live binding for each action (immediate-effect: lookups read this).
    bindings: BTreeMap<ActionId, Chord>,
}

impl ShortcutRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a rebindable action (WS17-04.1). Overwrites an existing action
    /// with the same id (its binding, if any, is preserved).
    pub fn register(
        &mut self,
        id: impl Into<ActionId>,
        scope: Scope,
        description: impl Into<String>,
    ) {
        let id = id.into();
        self.actions.insert(
            id,
            ActionInfo {
                scope,
                description: description.into(),
            },
        );
    }

    /// Number of registered actions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether no action is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Bind (or rebind) `id` to `chord` with immediate effect (WS17-04.2/.3).
    /// The new binding is live for the very next [`resolve`](Self::resolve).
    ///
    /// # Errors
    /// [`ShortcutError::UnknownAction`] if `id` was never registered.
    pub fn bind(&mut self, id: &str, chord: Chord) -> Result<(), ShortcutError> {
        if !self.actions.contains_key(id) {
            return Err(ShortcutError::UnknownAction);
        }
        self.bindings.insert(id.to_string(), chord);
        Ok(())
    }

    /// Remove `id`'s binding (leaving the action registered but unbound).
    pub fn unbind(&mut self, id: &str) -> bool {
        self.bindings.remove(id).is_some()
    }

    /// The chord currently bound to `id`, if any.
    #[must_use]
    pub fn binding(&self, id: &str) -> Option<&Chord> {
        self.bindings.get(id)
    }

    /// The metadata of `id`, if registered.
    #[must_use]
    pub fn action(&self, id: &str) -> Option<&ActionInfo> {
        self.actions.get(id)
    }

    /// Resolve a completed `chord` to an action while `active_app` is focused
    /// (WS17-04.2). An app-scoped binding for `active_app` shadows a `Global`
    /// one on the same chord; otherwise the global binding applies.
    #[must_use]
    pub fn resolve(&self, active_app: Option<&str>, chord: &Chord) -> Option<&ActionId> {
        let mut global: Option<&ActionId> = None;
        for (id, bound) in &self.bindings {
            if bound != chord {
                continue;
            }
            match self.actions.get(id).map(|a| &a.scope) {
                Some(Scope::App(app)) if Some(app.as_str()) == active_app => return Some(id),
                Some(Scope::Global) => global = global.or(Some(id)),
                _ => {}
            }
        }
        global
    }

    /// All binding conflicts (WS17-04.4): every `(scope, chord)` claimed by two
    /// or more actions. Empty when the keymap is unambiguous.
    #[must_use]
    pub fn conflicts(&self) -> Vec<Conflict> {
        // Group action ids by (scope, canonical-chord).
        let mut groups: BTreeMap<(Scope, String), Vec<ActionId>> = BTreeMap::new();
        for (id, chord) in &self.bindings {
            if let Some(info) = self.actions.get(id) {
                groups
                    .entry((info.scope.clone(), chord.to_canonical()))
                    .or_default()
                    .push(id.clone());
            }
        }
        groups
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .map(|((scope, chord), mut actions)| {
                actions.sort();
                Conflict {
                    scope,
                    chord,
                    actions,
                }
            })
            .collect()
    }

    /// Whether assigning `chord` to `id` would collide with another action in
    /// the same scope (used by the settings panel before committing a rebind).
    #[must_use]
    pub fn would_conflict(&self, id: &str, chord: &Chord) -> Option<ActionId> {
        let scope = self.actions.get(id).map(|a| &a.scope)?;
        for (other_id, bound) in &self.bindings {
            if other_id == id || bound != chord {
                continue;
            }
            if self.actions.get(other_id).map(|a| &a.scope) == Some(scope) {
                return Some(other_id.clone());
            }
        }
        None
    }

    /// Attempt a rebind from the settings panel (WS17-04.9): parse `chord_str`,
    /// reject it on conflict, otherwise apply it immediately.
    ///
    /// # Errors
    /// - [`ShortcutError::UnknownAction`] if `id` is not registered.
    /// - [`ShortcutError::Parse`] if `chord_str` is malformed.
    /// - [`ShortcutError::Conflict`] if another action in the same scope already
    ///   owns the chord (no change is made).
    pub fn try_rebind(&mut self, id: &str, chord_str: &str) -> Result<(), ShortcutError> {
        if !self.actions.contains_key(id) {
            return Err(ShortcutError::UnknownAction);
        }
        let chord = Chord::parse(chord_str)?;
        if self.would_conflict(id, &chord).is_some() {
            return Err(ShortcutError::Conflict);
        }
        self.bindings.insert(id.to_string(), chord);
        Ok(())
    }

    /// The settings-panel view: one [`ShortcutEntry`] per action, sorted by id
    /// (WS17-04.9).
    #[must_use]
    pub fn entries(&self) -> Vec<ShortcutEntry> {
        self.actions
            .iter()
            .map(|(id, info)| ShortcutEntry {
                id: id.clone(),
                scope: info.scope.clone(),
                description: info.description.clone(),
                chord: self.bindings.get(id).map(Chord::to_canonical),
            })
            .collect()
    }

    /// Export the user overrides as `(config-key, chord-string)` pairs for the
    /// `nexacore-config` store (WS17-04.8). The key is `shortcuts.<action-id>`.
    #[must_use]
    pub fn export_overrides(&self) -> Vec<(String, String)> {
        self.bindings
            .iter()
            .map(|(id, chord)| {
                let mut key = String::from("shortcuts.");
                key.push_str(id);
                (key, chord.to_canonical())
            })
            .collect()
    }

    /// Re-apply overrides loaded from the config store (WS17-04.8). Each pair is
    /// a `shortcuts.<action-id>` key and a canonical chord string; unparseable
    /// values and unknown actions are skipped, and the number applied returned.
    pub fn apply_overrides<I, K, V>(&mut self, overrides: I) -> usize
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut applied = 0;
        for (key, value) in overrides {
            let Some(id) = key.as_ref().strip_prefix("shortcuts.") else {
                continue;
            };
            if !self.actions.contains_key(id) {
                continue;
            }
            if let Ok(chord) = Chord::parse(value.as_ref()) {
                self.bindings.insert(id.to_string(), chord);
                applied += 1;
            }
        }
        applied
    }
}

// =============================================================================
// Multi-step chord matcher (WS17-04.5)
// =============================================================================

/// The outcome of feeding a [`KeyStroke`] to a [`ChordMatcher`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchResult {
    /// A chord completed and resolved to this action.
    Fired(ActionId),
    /// The strokes so far are a prefix of a longer bound chord; keep waiting.
    Pending,
    /// No bound chord matches; the buffer was reset.
    NoMatch,
}

/// A stateful matcher that turns a stream of [`KeyStroke`]s into fired actions,
/// supporting multi-step chords (WS17-04.5).
pub struct ChordMatcher<'a> {
    /// The registry consulted for bindings.
    registry: &'a ShortcutRegistry,
    /// The currently focused app (for scope resolution).
    active_app: Option<String>,
    /// Strokes accumulated for the in-progress chord.
    pending: Vec<KeyStroke>,
}

impl<'a> ChordMatcher<'a> {
    /// A matcher over `registry` for the given focused app.
    #[must_use]
    pub fn new(registry: &'a ShortcutRegistry, active_app: Option<String>) -> Self {
        Self {
            registry,
            active_app,
            pending: Vec::new(),
        }
    }

    /// The in-progress (unfired) strokes.
    #[must_use]
    pub fn pending(&self) -> &[KeyStroke] {
        &self.pending
    }

    /// Feed the next keystroke (WS17-04.5).
    ///
    /// A completed chord fires only when it is not also a strict prefix of a
    /// longer bound chord (so `Ctrl+K Ctrl+S` is reachable even if `Ctrl+K` is
    /// itself bound — the longer chord wins; use [`flush`](Self::flush) to fire
    /// the shorter one on a timeout). A stroke that matches nothing resets the
    /// buffer, then retries as the start of a fresh chord.
    pub fn feed(&mut self, stroke: KeyStroke) -> MatchResult {
        self.pending.push(stroke);
        let cand = Chord::new(self.pending.clone());

        let exact = self
            .registry
            .resolve(self.active_app.as_deref(), &cand)
            .cloned();
        let is_prefix = self.is_prefix_of_some_binding(&cand);

        if is_prefix {
            // A longer chord is still reachable: keep buffering (even if `cand`
            // also exactly matches — the longer chord takes precedence).
            return MatchResult::Pending;
        }
        if let Some(id) = exact {
            self.pending.clear();
            return MatchResult::Fired(id);
        }
        // No match. Reset; if we had buffered more than this stroke, retry the
        // single stroke as a fresh chord start.
        let retry = self.pending.len() > 1;
        self.pending.clear();
        if retry {
            return self.feed(stroke);
        }
        MatchResult::NoMatch
    }

    /// Fire the buffered chord if it exactly matches a binding (e.g. on a
    /// chord-timeout), then clear the buffer. Returns the fired action, if any.
    pub fn flush(&mut self) -> Option<ActionId> {
        if self.pending.is_empty() {
            return None;
        }
        let cand = Chord::new(core::mem::take(&mut self.pending));
        self.registry
            .resolve(self.active_app.as_deref(), &cand)
            .cloned()
    }

    /// Whether `cand` is a strict prefix of any bound chord.
    fn is_prefix_of_some_binding(&self, cand: &Chord) -> bool {
        self.registry
            .bindings
            .values()
            .any(|bound| cand.is_strict_prefix_of(bound))
    }
}

// =============================================================================
// Presets (WS17-04.6 / .7)
// =============================================================================

/// The standard editing actions every preset binds, with descriptions.
const STANDARD_ACTIONS: &[(&str, &str)] = &[
    ("edit.copy", "Copy"),
    ("edit.cut", "Cut"),
    ("edit.paste", "Paste"),
    ("edit.undo", "Undo"),
    ("edit.redo", "Redo"),
    ("edit.select_all", "Select all"),
    ("file.new", "New"),
    ("file.save", "Save"),
    ("file.find", "Find"),
    ("app.quit", "Quit application"),
    ("window.close", "Close window"),
    ("app.switch", "Switch application"),
];

/// A predefined binding scheme (WS17-04.6/.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// `macOS`-like: Command (Meta) for editing; `Cmd+Q` quits, `Cmd+Tab`
    /// switches apps.
    MacOs,
    /// Windows-like: Control for editing; `Alt+F4` closes, `Alt+Tab` switches.
    Windows,
}

impl Preset {
    /// Build a registry pre-populated with the standard actions bound per this
    /// preset (all `Global` scope).
    #[must_use]
    pub fn registry(self) -> ShortcutRegistry {
        let mut reg = ShortcutRegistry::new();
        for (id, desc) in STANDARD_ACTIONS {
            reg.register(*id, Scope::Global, *desc);
        }
        // The primary editing modifier differs between the two worlds.
        let primary = match self {
            Self::MacOs => Modifiers::meta(),
            Self::Windows => Modifiers::ctrl(),
        };
        let bind = |reg: &mut ShortcutRegistry, id: &str, mods: Modifiers, key: Key| {
            // Registered just above, so the bind cannot fail.
            let _ = reg.bind(id, Chord::single(KeyStroke::new(mods, key)));
        };
        bind(&mut reg, "edit.copy", primary, Key::char('c'));
        bind(&mut reg, "edit.cut", primary, Key::char('x'));
        bind(&mut reg, "edit.paste", primary, Key::char('v'));
        bind(&mut reg, "edit.undo", primary, Key::char('z'));
        bind(&mut reg, "edit.select_all", primary, Key::char('a'));
        bind(&mut reg, "file.new", primary, Key::char('n'));
        bind(&mut reg, "file.save", primary, Key::char('s'));
        bind(&mut reg, "file.find", primary, Key::char('f'));
        match self {
            Self::MacOs => {
                // Redo is Cmd+Shift+Z; quit Cmd+Q; close Cmd+W; switch Cmd+Tab.
                bind(&mut reg, "edit.redo", primary.with_shift(), Key::char('z'));
                bind(&mut reg, "app.quit", primary, Key::char('q'));
                bind(&mut reg, "window.close", primary, Key::char('w'));
                bind(&mut reg, "app.switch", primary, Key::Tab);
            }
            Self::Windows => {
                // Redo is Ctrl+Y; close Alt+F4; switch Alt+Tab. (No Ctrl+Q quit
                // convention on Windows — map quit to Alt+F4's window close.)
                bind(&mut reg, "edit.redo", primary, Key::char('y'));
                bind(
                    &mut reg,
                    "app.quit",
                    Modifiers::NONE.with_alt(),
                    Key::Function(4),
                );
                bind(
                    &mut reg,
                    "window.close",
                    Modifiers::NONE.with_alt(),
                    Key::Function(4),
                );
                bind(&mut reg, "app.switch", Modifiers::NONE.with_alt(), Key::Tab);
            }
        }
        reg
    }
}

// =============================================================================
// Errors + string encoding
// =============================================================================

/// An error from the shortcut subsystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortcutError {
    /// The action id is not registered.
    UnknownAction,
    /// A chord string could not be parsed.
    Parse,
    /// The requested binding conflicts with another action in the same scope.
    Conflict,
}

/// Append the canonical rendering of one stroke to `out`.
fn write_stroke(out: &mut String, s: &KeyStroke) {
    if s.mods.ctrl {
        out.push_str("Ctrl+");
    }
    if s.mods.alt {
        out.push_str("Alt+");
    }
    if s.mods.shift {
        out.push_str("Shift+");
    }
    if s.mods.meta {
        out.push_str("Meta+");
    }
    write_key(out, s.key);
}

/// Append the canonical rendering of a key to `out`.
fn write_key(out: &mut String, key: Key) {
    match key {
        Key::Char(c) => {
            for up in c.to_uppercase() {
                out.push(up);
            }
        }
        Key::Enter => out.push_str("Enter"),
        Key::Tab => out.push_str("Tab"),
        Key::Space => out.push_str("Space"),
        Key::Escape => out.push_str("Escape"),
        Key::Backspace => out.push_str("Backspace"),
        Key::Delete => out.push_str("Delete"),
        Key::Up => out.push_str("Up"),
        Key::Down => out.push_str("Down"),
        Key::Left => out.push_str("Left"),
        Key::Right => out.push_str("Right"),
        Key::Home => out.push_str("Home"),
        Key::End => out.push_str("End"),
        Key::Function(n) => {
            let _ = write!(out, "F{n}");
        }
    }
}

/// Parse one `+`-separated stroke token (`"Ctrl+Shift+A"`).
fn parse_stroke(token: &str) -> Result<KeyStroke, ShortcutError> {
    let mut mods = Modifiers::NONE;
    let mut key: Option<Key> = None;
    for part in token.split('+') {
        if part.is_empty() {
            return Err(ShortcutError::Parse);
        }
        match part {
            "Ctrl" | "Control" => mods.ctrl = true,
            "Alt" | "Option" => mods.alt = true,
            "Shift" => mods.shift = true,
            "Meta" | "Cmd" | "Command" | "Super" => mods.meta = true,
            other => {
                if key.is_some() {
                    return Err(ShortcutError::Parse); // two non-modifier keys
                }
                key = Some(parse_key(other)?);
            }
        }
    }
    key.map(|key| KeyStroke { mods, key })
        .ok_or(ShortcutError::Parse)
}

/// Parse a single key token.
fn parse_key(token: &str) -> Result<Key, ShortcutError> {
    let named = match token {
        "Enter" | "Return" => Some(Key::Enter),
        "Tab" => Some(Key::Tab),
        "Space" => Some(Key::Space),
        "Escape" | "Esc" => Some(Key::Escape),
        "Backspace" => Some(Key::Backspace),
        "Delete" | "Del" => Some(Key::Delete),
        "Up" => Some(Key::Up),
        "Down" => Some(Key::Down),
        "Left" => Some(Key::Left),
        "Right" => Some(Key::Right),
        "Home" => Some(Key::Home),
        "End" => Some(Key::End),
        _ => None,
    };
    if let Some(k) = named {
        return Ok(k);
    }
    // Function key `F1..=F24`.
    if let Some(num) = token.strip_prefix('F') {
        if let Ok(n) = num.parse::<u8>() {
            if (1..=24).contains(&n) {
                return Ok(Key::Function(n));
            }
        }
    }
    // A single character.
    let mut chars = token.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => Ok(Key::char(c)),
        _ => Err(ShortcutError::Parse),
    }
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

    fn ctrl(c: char) -> Chord {
        Chord::single(KeyStroke::new(Modifiers::ctrl(), Key::char(c)))
    }

    fn registry_with(id: &str, scope: Scope, chord: Chord) -> ShortcutRegistry {
        let mut r = ShortcutRegistry::new();
        r.register(id, scope, "desc");
        r.bind(id, chord).unwrap();
        r
    }

    // -- WS17-04.1/.2: registry + lookup --------------------------------------

    #[test]
    fn register_bind_and_resolve() {
        let r = registry_with("edit.copy", Scope::Global, ctrl('c'));
        assert_eq!(r.len(), 1);
        assert_eq!(r.resolve(None, &ctrl('c')), Some(&"edit.copy".to_string()));
        assert_eq!(r.resolve(None, &ctrl('v')), None);
    }

    #[test]
    fn bind_unknown_action_errors() {
        let mut r = ShortcutRegistry::new();
        assert_eq!(r.bind("nope", ctrl('c')), Err(ShortcutError::UnknownAction));
    }

    #[test]
    fn case_insensitive_key_binding() {
        // 'C' and 'c' must bind to the same stroke.
        let r = registry_with("edit.copy", Scope::Global, ctrl('C'));
        assert_eq!(r.resolve(None, &ctrl('c')), Some(&"edit.copy".to_string()));
    }

    // -- WS17-04.3: rebinding with immediate effect ---------------------------

    #[test]
    fn rebinding_takes_effect_immediately() {
        let mut r = registry_with("edit.copy", Scope::Global, ctrl('c'));
        r.bind("edit.copy", ctrl('y')).unwrap();
        assert_eq!(r.resolve(None, &ctrl('c')), None);
        assert_eq!(r.resolve(None, &ctrl('y')), Some(&"edit.copy".to_string()));
    }

    // -- WS17-04: per-app scope shadows global --------------------------------

    #[test]
    fn app_scope_shadows_global_on_same_chord() {
        let mut r = ShortcutRegistry::new();
        r.register("global.copy", Scope::Global, "g");
        r.register("term.copy", Scope::App("terminal".into()), "t");
        r.bind("global.copy", ctrl('c')).unwrap();
        r.bind("term.copy", ctrl('c')).unwrap();
        // In the terminal, the app binding wins; elsewhere the global one.
        assert_eq!(
            r.resolve(Some("terminal"), &ctrl('c')),
            Some(&"term.copy".to_string())
        );
        assert_eq!(
            r.resolve(Some("editor"), &ctrl('c')),
            Some(&"global.copy".to_string())
        );
        assert_eq!(
            r.resolve(None, &ctrl('c')),
            Some(&"global.copy".to_string())
        );
    }

    // -- WS17-04.4: conflict detection ----------------------------------------

    #[test]
    fn conflicts_in_same_scope_are_detected() {
        let mut r = ShortcutRegistry::new();
        r.register("a", Scope::Global, "a");
        r.register("b", Scope::Global, "b");
        r.bind("a", ctrl('c')).unwrap();
        r.bind("b", ctrl('c')).unwrap();
        let conflicts = r.conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].actions, ["a", "b"]);
        assert_eq!(conflicts[0].chord, "Ctrl+C");
    }

    #[test]
    fn global_and_app_on_same_chord_do_not_conflict() {
        let mut r = ShortcutRegistry::new();
        r.register("g", Scope::Global, "g");
        r.register("t", Scope::App("term".into()), "t");
        r.bind("g", ctrl('c')).unwrap();
        r.bind("t", ctrl('c')).unwrap();
        // Different scopes: app shadows global, not a conflict.
        assert!(r.conflicts().is_empty());
    }

    #[test]
    fn would_conflict_and_try_rebind_reject_collision() {
        let mut r = ShortcutRegistry::new();
        r.register("a", Scope::Global, "a");
        r.register("b", Scope::Global, "b");
        r.bind("a", ctrl('c')).unwrap();
        // Rebinding b onto Ctrl+C collides with a.
        assert_eq!(r.try_rebind("b", "Ctrl+C"), Err(ShortcutError::Conflict));
        // b stays unbound (no silent change).
        assert!(r.binding("b").is_none());
        // A free chord succeeds.
        assert_eq!(r.try_rebind("b", "Ctrl+B"), Ok(()));
        assert_eq!(r.binding("b").unwrap().to_canonical(), "Ctrl+B");
    }

    // -- WS17-04.5: multi-step chords -----------------------------------------

    #[test]
    fn multi_step_chord_fires_only_after_full_sequence() {
        let mut r = ShortcutRegistry::new();
        r.register("file.save_all", Scope::Global, "Save all");
        // Ctrl+K Ctrl+S
        let chord = Chord::parse("Ctrl+K Ctrl+S").unwrap();
        r.bind("file.save_all", chord).unwrap();

        let mut m = ChordMatcher::new(&r, None);
        let k = KeyStroke::new(Modifiers::ctrl(), Key::char('k'));
        let s = KeyStroke::new(Modifiers::ctrl(), Key::char('s'));
        // First stroke: prefix of the bound chord → pending.
        assert_eq!(m.feed(k), MatchResult::Pending);
        // Second stroke completes it → fired.
        assert_eq!(m.feed(s), MatchResult::Fired("file.save_all".to_string()));
        // Buffer reset after firing.
        assert!(m.pending().is_empty());
    }

    #[test]
    fn single_key_shortcut_fires_immediately() {
        let r = registry_with("edit.copy", Scope::Global, ctrl('c'));
        let mut m = ChordMatcher::new(&r, None);
        let c = KeyStroke::new(Modifiers::ctrl(), Key::char('c'));
        assert_eq!(m.feed(c), MatchResult::Fired("edit.copy".to_string()));
    }

    #[test]
    fn unmatched_stroke_resets_and_retries() {
        // Ctrl+K is a prefix of Ctrl+K Ctrl+S; pressing Ctrl+K then Ctrl+C
        // (no Ctrl+K Ctrl+C binding, but Ctrl+C is bound) should fire Ctrl+C.
        let mut r = ShortcutRegistry::new();
        r.register("save_all", Scope::Global, "s");
        r.register("copy", Scope::Global, "c");
        r.bind("save_all", Chord::parse("Ctrl+K Ctrl+S").unwrap())
            .unwrap();
        r.bind("copy", ctrl('c')).unwrap();
        let mut m = ChordMatcher::new(&r, None);
        assert_eq!(
            m.feed(KeyStroke::new(Modifiers::ctrl(), Key::char('k'))),
            MatchResult::Pending
        );
        assert_eq!(
            m.feed(KeyStroke::new(Modifiers::ctrl(), Key::char('c'))),
            MatchResult::Fired("copy".to_string())
        );
    }

    // -- WS17-04.6/.7: presets ------------------------------------------------

    #[test]
    fn macos_preset_uses_meta_for_copy() {
        let r = Preset::MacOs.registry();
        assert_eq!(r.binding("edit.copy").unwrap().to_canonical(), "Meta+C");
        assert_eq!(r.binding("app.quit").unwrap().to_canonical(), "Meta+Q");
        // No conflicts in the shipped preset.
        assert!(
            r.conflicts().is_empty(),
            "preset conflicts: {:?}",
            r.conflicts()
        );
    }

    #[test]
    fn windows_preset_uses_ctrl_for_copy() {
        let r = Preset::Windows.registry();
        assert_eq!(r.binding("edit.copy").unwrap().to_canonical(), "Ctrl+C");
        assert_eq!(r.binding("app.switch").unwrap().to_canonical(), "Alt+Tab");
        assert_eq!(r.binding("edit.redo").unwrap().to_canonical(), "Ctrl+Y");
        // window.close and app.quit both map to Alt+F4 → that IS a deliberate
        // same-scope collision; assert it is reported (honest accounting).
        let conflicts = r.conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].chord, "Alt+F4");
    }

    // -- WS17-04.8: persistence round-trip ------------------------------------

    #[test]
    fn overrides_round_trip_through_config_strings() {
        let mut r = ShortcutRegistry::new();
        r.register("edit.copy", Scope::Global, "Copy");
        r.register("file.save_all", Scope::Global, "Save all");
        r.bind("edit.copy", ctrl('c')).unwrap();
        r.bind("file.save_all", Chord::parse("Ctrl+K Ctrl+S").unwrap())
            .unwrap();

        let exported = r.export_overrides();
        assert!(exported.contains(&("shortcuts.edit.copy".to_string(), "Ctrl+C".to_string())));

        // A fresh registry with the same actions re-applies the saved strings.
        let mut restored = ShortcutRegistry::new();
        restored.register("edit.copy", Scope::Global, "Copy");
        restored.register("file.save_all", Scope::Global, "Save all");
        let applied = restored.apply_overrides(exported);
        assert_eq!(applied, 2);
        assert_eq!(
            restored.binding("file.save_all").unwrap().to_canonical(),
            "Ctrl+K Ctrl+S"
        );
    }

    #[test]
    fn apply_overrides_skips_unknown_and_malformed() {
        let mut r = ShortcutRegistry::new();
        r.register("edit.copy", Scope::Global, "Copy");
        let applied = r.apply_overrides([
            ("shortcuts.edit.copy", "Ctrl+C"), // ok
            ("shortcuts.unknown", "Ctrl+X"),   // unknown action → skip
            ("shortcuts.edit.copy", "Ctrl++"), // malformed → skip
            ("not.a.shortcut", "Ctrl+Z"),      // wrong namespace → skip
        ]);
        assert_eq!(applied, 1);
        assert_eq!(r.binding("edit.copy").unwrap().to_canonical(), "Ctrl+C");
    }

    // -- WS17-04.9: settings-panel view ---------------------------------------

    #[test]
    fn entries_describe_each_action_sorted() {
        let r = Preset::Windows.registry();
        let entries = r.entries();
        assert_eq!(entries.len(), STANDARD_ACTIONS.len());
        // Sorted by id.
        for w in entries.windows(2) {
            assert!(w[0].id <= w[1].id);
        }
        let copy = entries.iter().find(|e| e.id == "edit.copy").unwrap();
        assert_eq!(copy.description, "Copy");
        assert_eq!(copy.chord.as_deref(), Some("Ctrl+C"));
    }

    // -- canonical string parsing edge cases ----------------------------------

    #[test]
    fn chord_string_round_trips() {
        // Inputs use the canonical modifier order (Ctrl, Alt, Shift, Meta).
        for s in [
            "Ctrl+C",
            "Shift+Meta+Z",
            "Ctrl+K Ctrl+S",
            "Alt+F4",
            "Ctrl+Up",
        ] {
            let chord = Chord::parse(s).unwrap();
            assert_eq!(chord.to_canonical(), s, "round-trip failed for {s}");
        }
    }

    #[test]
    fn malformed_chord_strings_rejected() {
        for s in ["", "   ", "Ctrl+", "+C", "Ctrl+A+B", "F99"] {
            assert!(Chord::parse(s).is_err(), "should reject {s:?}");
        }
    }
}

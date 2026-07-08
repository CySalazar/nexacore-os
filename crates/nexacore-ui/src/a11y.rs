//! Accessibility layer (WS7-16): a11y tree, focus/keyboard navigation, a
//! screen-reader announcer, a high-contrast theme, and global text scaling.
//!
//! Built on top of the existing toolkit — [`crate::widget::Widget`],
//! [`crate::theme::Theme`], [`crate::shortcuts`], and
//! [`crate::notification`] — as a non-invasive layer:
//!
//! | WS7-16 sub-task | This module |
//! |-----------------|-------------|
//! | `.1`/`.2` a11y tree + role/state/name | [`crate::a11y::A11yTree`] / [`crate::a11y::A11yNode`] / [`crate::a11y::Role`] |
//! | `.3` focus tracking + change events | [`crate::a11y::FocusManager`] / [`crate::a11y::FocusChange`] |
//! | `.4` TTS engine seam | [`crate::a11y::TtsEngine`] (the real synth is library-gated) |
//! | `.5` screen reader announces focus | [`crate::a11y::ScreenReader`] / [`crate::a11y::announce`] |
//! | `.6` high-contrast theme + contrast | [`crate::a11y::high_contrast_theme`] / [`crate::a11y::contrast_ratio_permille`] |
//! | `.7` global text scaling (150%) | [`crate::a11y::TextScale`] |
//! | `.8` full keyboard navigation | [`crate::a11y::FocusManager::handle_key`] (Tab / Shift+Tab) |
//! | `.9` announcements via the notification daemon | [`crate::a11y::announcement_request`] |
//!
//! The only effect — speaking text — sits behind the [`crate::a11y::TtsEngine`] trait, so the
//! whole layer (tree, focus order, announcement phrasing, contrast math) is pure
//! and host-testable.

// Integer division is intrinsic to the permille text-scale and the integer
// luminance/contrast proxy (no floats for `no_std`); each site rounds explicitly.
#![allow(clippy::integer_division)]

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    notification::{Notification, NotificationRequest, Priority},
    shortcuts::{Key, KeyStroke},
    theme::Theme,
    widget::{Widget, WidgetId},
};

// =============================================================================
// Roles + nodes (WS7-16.1 / .2)
// =============================================================================

/// The semantic role a screen reader announces for a widget (WS7-16.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Static, non-interactive text.
    Label,
    /// A push button.
    Button,
    /// An editable text field.
    TextInput,
    /// A list of items.
    List,
    /// A non-semantic grouping container.
    Group,
}

impl Role {
    /// The spoken role name a screen reader prefixes the announcement with.
    #[must_use]
    pub const fn spoken(self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::Button => "button",
            Self::TextInput => "text field",
            Self::List => "list",
            Self::Group => "group",
        }
    }

    /// Whether a widget of this role can hold keyboard focus by default.
    #[must_use]
    pub const fn is_focusable(self) -> bool {
        matches!(self, Self::Button | Self::TextInput | Self::List)
    }
}

/// One node of the accessibility tree exposing a widget's role, name, and state
/// (WS7-16.1 / .2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct A11yNode {
    /// Tree-stable id assigned during construction (DFS pre-order).
    pub a11y_id: u32,
    /// The underlying toolkit widget id, when the widget carries one.
    pub widget_id: Option<WidgetId>,
    /// Semantic role (WS7-16.2).
    pub role: Role,
    /// Accessible name (the label/text/first item).
    pub name: String,
    /// Accessible value, when distinct from the name (e.g. a field's contents).
    pub value: Option<String>,
    /// Whether the node can receive focus.
    pub focusable: bool,
    /// Whether the node is currently disabled (not announced as actionable).
    pub disabled: bool,
    /// Child nodes, in visual order.
    pub children: Vec<A11yNode>,
}

// =============================================================================
// A11y tree (WS7-16.1)
// =============================================================================

/// The accessibility tree built from a [`Widget`] hierarchy (WS7-16.1).
///
/// Holds the root node plus a flattened focus order (the `a11y_id`s of the
/// focusable nodes in DFS pre-order), which drives Tab navigation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct A11yTree {
    root: A11yNode,
    focus_order: Vec<u32>,
}

impl A11yTree {
    /// Build the a11y tree (and its focus order) from a widget hierarchy.
    #[must_use]
    pub fn from_widget(widget: &Widget) -> Self {
        let mut next_id = 0u32;
        let root = build_node(widget, &mut next_id);
        let mut focus_order = Vec::new();
        collect_focus_order(&root, &mut focus_order);
        Self { root, focus_order }
    }

    /// The root node.
    #[must_use]
    pub const fn root(&self) -> &A11yNode {
        &self.root
    }

    /// The `a11y_id`s of the focusable nodes, in Tab order (WS7-16.8).
    #[must_use]
    pub fn focus_order(&self) -> &[u32] {
        &self.focus_order
    }

    /// Total number of nodes in the tree.
    #[must_use]
    pub fn node_count(&self) -> usize {
        count_nodes(&self.root)
    }

    /// Find a node by its `a11y_id`.
    #[must_use]
    pub fn node(&self, a11y_id: u32) -> Option<&A11yNode> {
        find_node(&self.root, a11y_id)
    }
}

fn build_node(widget: &Widget, next_id: &mut u32) -> A11yNode {
    let id = *next_id;
    *next_id += 1;
    let (role, widget_id, name, value, children) = match widget {
        Widget::Label { text, .. } => (Role::Label, None, text.clone(), None, Vec::new()),
        Widget::Button { id: wid, text, .. } => {
            (Role::Button, Some(*wid), text.clone(), None, Vec::new())
        }
        Widget::TextInput { id: wid, text, .. } => (
            Role::TextInput,
            Some(*wid),
            String::new(),
            Some(text.clone()),
            Vec::new(),
        ),
        Widget::List { items, .. } => {
            let name = format!("{} items", items.len());
            (Role::List, None, name, None, Vec::new())
        }
        Widget::Container { children, .. } => {
            let kids = children.iter().map(|c| build_node(c, next_id)).collect();
            (Role::Group, None, String::new(), None, kids)
        }
    };
    A11yNode {
        a11y_id: id,
        widget_id,
        focusable: role.is_focusable(),
        disabled: false,
        role,
        name,
        value,
        children,
    }
}

fn collect_focus_order(node: &A11yNode, out: &mut Vec<u32>) {
    if node.focusable && !node.disabled {
        out.push(node.a11y_id);
    }
    for child in &node.children {
        collect_focus_order(child, out);
    }
}

fn count_nodes(node: &A11yNode) -> usize {
    1 + node.children.iter().map(count_nodes).sum::<usize>()
}

fn find_node(node: &A11yNode, a11y_id: u32) -> Option<&A11yNode> {
    if node.a11y_id == a11y_id {
        return Some(node);
    }
    node.children.iter().find_map(|c| find_node(c, a11y_id))
}

// =============================================================================
// Focus + keyboard navigation (WS7-16.3 / .8)
// =============================================================================

/// A focus transition from one node to another (WS7-16.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FocusChange {
    /// The previously focused node, if any.
    pub from: Option<u32>,
    /// The newly focused node.
    pub to: u32,
}

/// Tracks the focused node and moves focus through the Tab order (WS7-16.3 / .8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FocusManager {
    order: Vec<u32>,
    current: Option<usize>,
}

impl FocusManager {
    /// Create a focus manager over a Tab order (typically [`A11yTree::focus_order`]).
    #[must_use]
    pub fn new(order: Vec<u32>) -> Self {
        Self {
            order,
            current: None,
        }
    }

    /// The currently focused `a11y_id`, if any.
    #[must_use]
    pub fn current(&self) -> Option<u32> {
        self.current.and_then(|i| self.order.get(i).copied())
    }

    /// Whether there is anything focusable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Move focus to the next focusable node (wraps), returning the transition.
    pub fn focus_next(&mut self) -> Option<FocusChange> {
        if self.order.is_empty() {
            return None;
        }
        let from = self.current();
        let next = match self.current {
            Some(i) => (i + 1) % self.order.len(),
            None => 0,
        };
        self.current = Some(next);
        self.current().map(|to| FocusChange { from, to })
    }

    /// Move focus to the previous focusable node (wraps).
    pub fn focus_prev(&mut self) -> Option<FocusChange> {
        if self.order.is_empty() {
            return None;
        }
        let from = self.current();
        let prev = match self.current {
            Some(0) | None => self.order.len() - 1,
            Some(i) => i - 1,
        };
        self.current = Some(prev);
        self.current().map(|to| FocusChange { from, to })
    }

    /// Focus a specific node by `a11y_id`, if it is in the Tab order.
    pub fn focus(&mut self, a11y_id: u32) -> Option<FocusChange> {
        let idx = self.order.iter().position(|&id| id == a11y_id)?;
        let from = self.current();
        self.current = Some(idx);
        Some(FocusChange { from, to: a11y_id })
    }

    /// Translate a keystroke into a focus move: Tab → next, Shift+Tab → prev
    /// (WS7-16.8). Returns `None` for keys that do not affect focus.
    pub fn handle_key(&mut self, stroke: &KeyStroke) -> Option<FocusChange> {
        if stroke.key != Key::Tab {
            return None;
        }
        if stroke.mods.shift {
            self.focus_prev()
        } else {
            self.focus_next()
        }
    }
}

// =============================================================================
// Screen reader (WS7-16.4 / .5)
// =============================================================================

/// The text a screen reader speaks for `node` (WS7-16.5).
///
/// Phrasing: `"<role>, <name>[, <value>][, dimmed]"`, e.g. `"button, Save"` or
/// `"text field, Email, you@host"`.
#[must_use]
pub fn announce(node: &A11yNode) -> String {
    let mut out = node.role.spoken().to_string();
    if !node.name.is_empty() {
        out.push_str(", ");
        out.push_str(&node.name);
    }
    if let Some(value) = &node.value {
        if !value.is_empty() {
            out.push_str(", ");
            out.push_str(value);
        }
    }
    if node.disabled {
        out.push_str(", dimmed");
    }
    out
}

/// The synthesizer seam (WS7-16.4): the real TTS engine is library-gated; tests
/// use a recording double.
pub trait TtsEngine {
    /// Speak `text` (or enqueue it).
    fn speak(&mut self, text: &str);
}

/// Announces the focused widget through a [`TtsEngine`] (WS7-16.5).
#[derive(Debug)]
pub struct ScreenReader<T: TtsEngine> {
    tts: T,
    enabled: bool,
}

impl<T: TtsEngine> ScreenReader<T> {
    /// Create a screen reader (enabled) over a TTS engine.
    pub fn new(tts: T) -> Self {
        Self { tts, enabled: true }
    }

    /// Enable or disable spoken output.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether spoken output is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Announce the node a [`FocusChange`] moved to, looking it up in `tree`.
    ///
    /// Returns the spoken text (also passed to the engine) so callers can route
    /// it elsewhere (e.g. the notification daemon, WS7-16.9). A disabled reader
    /// returns `None` and speaks nothing.
    pub fn announce_focus(&mut self, tree: &A11yTree, change: &FocusChange) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let node = tree.node(change.to)?;
        let text = announce(node);
        self.tts.speak(&text);
        Some(text)
    }

    /// Borrow the underlying engine (e.g. to inspect a test double).
    pub const fn engine(&self) -> &T {
        &self.tts
    }
}

// =============================================================================
// Contrast + high-contrast theme (WS7-16.6)
// =============================================================================

/// Perceptual luminance of an ARGB color, 0 (black) … 255 (white).
///
/// An integer Rec. 709 weighting of the sRGB channels. This is a *proxy* for
/// the WCAG gamma-linear relative luminance — monotonic and good enough to rank
/// contrast for the high-contrast palette without pulling in floating-point
/// `pow` (the crate is `no_std`). The alpha channel is ignored.
#[must_use]
pub fn luminance(argb: u32) -> u32 {
    let r = (argb >> 16) & 0xFF;
    let g = (argb >> 8) & 0xFF;
    let b = argb & 0xFF;
    (2126 * r + 7152 * g + 722 * b) / 10000
}

/// Contrast ratio between `fg` and `bg`, in permille (`21000` ≈ the 21:1 max).
///
/// Uses [`luminance`] and the WCAG ratio shape `(Lmax + k) / (Lmin + k)` with an
/// integer offset (`k = 13`, i.e. `0.05 × 255`). Like [`luminance`] it is a
/// perceptual proxy, not gamma-exact, and is used to *rank*/threshold contrast.
#[must_use]
pub fn contrast_ratio_permille(fg: u32, bg: u32) -> u32 {
    const K: u32 = 13;
    let a = luminance(fg) + K;
    let b = luminance(bg) + K;
    let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
    hi * 1000 / lo
}

/// Whether `fg` on `bg` meets the WCAG-AA-style normal-text threshold (≈4.5:1),
/// per the [`contrast_ratio_permille`] proxy.
#[must_use]
pub fn meets_aa(fg: u32, bg: u32) -> bool {
    contrast_ratio_permille(fg, bg) >= 4500
}

/// A maximal-contrast theme: pure-white text/borders on a near-black canvas with
/// a high-visibility accent (WS7-16.6).
///
/// Derived to maximise the [`contrast_ratio_permille`] of text-on-background; the
/// default text scale is bumped so the high-contrast mode is also larger.
#[must_use]
pub fn high_contrast_theme() -> Theme {
    Theme {
        bg_canvas: 0xFF00_0000,  // pure black
        bg_surface: 0xFF10_1010, // near-black surface
        text: 0xFFFF_FFFF,       // pure white (21:1 on black)
        accent: 0xFFFF_FF00,     // high-visibility yellow
        success: 0xFF00_FF00,    // saturated green
        border: 0xFFFF_FFFF,     // white borders
        text_scale: 2,           // larger by default
        padding: 8,
        spacing: 8,
        radius: 0, // square, crisp edges for maximal contrast
        // No drop shadow: soft penumbrae reduce edge contrast (transparent
        // colour makes shadow_alpha_at return 0).
        elevation: nexacore_display::effects::Shadow {
            offset_y: 0,
            blur: 0,
            spread: 0,
            color: 0x0000_0000,
        },
    }
}

// =============================================================================
// Global text scaling (WS7-16.7)
// =============================================================================

/// A global text-scale factor in permille (`1000` = 100%, `1500` = 150%).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextScale(pub u32);

/// Smallest text scale (50%).
pub const MIN_TEXT_SCALE: u32 = 500;
/// Largest text scale (300%).
pub const MAX_TEXT_SCALE: u32 = 3000;

impl Default for TextScale {
    fn default() -> Self {
        Self(1000)
    }
}

impl TextScale {
    /// Construct a clamped text scale (permille).
    #[must_use]
    pub fn new(permille: u32) -> Self {
        Self(permille.clamp(MIN_TEXT_SCALE, MAX_TEXT_SCALE))
    }

    /// 150% — the accessibility default the task calls out (WS7-16.7).
    #[must_use]
    pub const fn large() -> Self {
        Self(1500)
    }

    /// Apply the scale to a base pixel size (rounded to nearest).
    #[must_use]
    pub fn apply(self, base_px: u32) -> u32 {
        (base_px * self.0 + 500) / 1000
    }

    /// The scale as a whole percentage.
    #[must_use]
    pub const fn percent(self) -> u32 {
        self.0 / 10
    }
}

// =============================================================================
// Notification integration (WS7-16.9)
// =============================================================================

/// App id used for accessibility announcements posted to the notification
/// daemon (WS7-16.9).
pub const A11Y_APP_ID: &str = "a11y";

/// Build a low-priority notification request carrying a screen-reader
/// announcement, so a11y output also surfaces through the WS7-10 daemon
/// (WS7-16.9).
#[must_use]
pub fn announcement_request(id: u64, message: impl Into<String>) -> NotificationRequest {
    NotificationRequest::Post(Notification {
        id,
        app: A11Y_APP_ID.to_string(),
        title: "Accessibility".to_string(),
        body: message.into(),
        priority: Priority::Low,
        actions: Vec::new(),
    })
}

// A boxed TTS engine is a convenient erased form for callers wiring a chosen
// backend at runtime.
/// A heap-erased [`TtsEngine`] for runtime backend selection.
pub type BoxedTts = Box<dyn TtsEngine>;

#[cfg(test)]
mod tests {
    use nexacore_display::geometry::Rect;

    use super::*;
    use crate::layout::Direction;

    fn rect() -> Rect {
        Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        }
    }

    /// A small dialog: a label, two buttons, and a text field inside a container.
    fn dialog() -> Widget {
        Widget::Container {
            direction: Direction::Vertical,
            rect: rect(),
            children: alloc::vec![
                Widget::Label {
                    text: "Sign in".into(),
                    rect: rect(),
                },
                Widget::TextInput {
                    id: WidgetId(1),
                    text: "you@host".into(),
                    cursor: 0,
                    rect: rect(),
                },
                Widget::Button {
                    id: WidgetId(2),
                    text: "OK".into(),
                    rect: rect(),
                },
                Widget::Button {
                    id: WidgetId(3),
                    text: "Cancel".into(),
                    rect: rect(),
                },
            ],
        }
    }

    /// A recording TTS double.
    #[derive(Default)]
    struct RecordingTts {
        spoken: Vec<String>,
    }
    impl TtsEngine for RecordingTts {
        fn speak(&mut self, text: &str) {
            self.spoken.push(text.to_string());
        }
    }

    // ── .1/.2 tree + roles ────────────────────────────────────────────────

    #[test]
    fn tree_exposes_roles_and_names() {
        let tree = A11yTree::from_widget(&dialog());
        // root (group) + label + input + 2 buttons = 5 nodes.
        assert_eq!(tree.node_count(), 5);
        assert_eq!(tree.root().role, Role::Group);
        let input = tree.node(2).unwrap(); // DFS: 0=group,1=label,2=input
        assert_eq!(input.role, Role::TextInput);
        assert_eq!(input.value.as_deref(), Some("you@host"));
    }

    // ── .8 focus order is DFS over focusables ─────────────────────────────

    #[test]
    fn focus_order_lists_only_focusables_in_order() {
        let tree = A11yTree::from_widget(&dialog());
        // focusable: input(2), OK(3), Cancel(4) — label and group are not.
        assert_eq!(tree.focus_order(), &[2, 3, 4]);
    }

    // ── .3/.8 focus navigation wraps ──────────────────────────────────────

    #[test]
    fn tab_navigation_cycles_with_wrap() {
        let tree = A11yTree::from_widget(&dialog());
        let mut focus = FocusManager::new(tree.focus_order().to_vec());
        assert_eq!(focus.current(), None);
        assert_eq!(focus.focus_next().unwrap().to, 2);
        assert_eq!(focus.focus_next().unwrap().to, 3);
        assert_eq!(focus.focus_next().unwrap().to, 4);
        // wraps back to the first.
        assert_eq!(focus.focus_next().unwrap().to, 2);
        // shift+tab goes back, wrapping to the last.
        let change = focus.focus_prev().unwrap();
        assert_eq!((change.from, change.to), (Some(2), 4));
    }

    #[test]
    fn handle_key_maps_tab_and_shift_tab() {
        let tree = A11yTree::from_widget(&dialog());
        let mut focus = FocusManager::new(tree.focus_order().to_vec());
        let tab = KeyStroke {
            mods: crate::shortcuts::Modifiers::default(),
            key: Key::Tab,
        };
        assert_eq!(focus.handle_key(&tab).unwrap().to, 2);
        let shift_tab = KeyStroke {
            mods: crate::shortcuts::Modifiers {
                shift: true,
                ..Default::default()
            },
            key: Key::Tab,
        };
        // shift+tab from index 0 wraps to the last focusable.
        assert_eq!(focus.handle_key(&shift_tab).unwrap().to, 4);
        // a non-Tab key is ignored.
        let enter = KeyStroke {
            mods: crate::shortcuts::Modifiers::default(),
            key: Key::Enter,
        };
        assert!(focus.handle_key(&enter).is_none());
    }

    // ── .5 announcement phrasing + screen reader ──────────────────────────

    #[test]
    fn announce_phrases_role_name_value() {
        let tree = A11yTree::from_widget(&dialog());
        assert_eq!(announce(tree.node(3).unwrap()), "button, OK");
        assert_eq!(announce(tree.node(2).unwrap()), "text field, you@host");
    }

    #[test]
    fn screen_reader_speaks_focused_node() {
        let tree = A11yTree::from_widget(&dialog());
        let mut focus = FocusManager::new(tree.focus_order().to_vec());
        let mut reader = ScreenReader::new(RecordingTts::default());
        let change = focus.focus_next().unwrap(); // → input (2)
        let spoken = reader.announce_focus(&tree, &change).unwrap();
        assert_eq!(spoken, "text field, you@host");
        assert_eq!(reader.engine().spoken, alloc::vec!["text field, you@host"]);
    }

    #[test]
    fn disabled_reader_is_silent() {
        let tree = A11yTree::from_widget(&dialog());
        let mut reader = ScreenReader::new(RecordingTts::default());
        reader.set_enabled(false);
        let change = FocusChange { from: None, to: 3 };
        assert!(reader.announce_focus(&tree, &change).is_none());
        assert!(reader.engine().spoken.is_empty());
    }

    // ── .6 contrast + high-contrast theme ─────────────────────────────────

    #[test]
    fn contrast_white_on_black_is_maximal() {
        let r = contrast_ratio_permille(0xFFFF_FFFF, 0xFF00_0000);
        assert!(r >= 20000, "white-on-black should be ~21:1, got {r}");
        assert!(meets_aa(0xFFFF_FFFF, 0xFF00_0000));
    }

    #[test]
    fn contrast_same_color_is_unity() {
        assert_eq!(contrast_ratio_permille(0xFF80_8080, 0xFF80_8080), 1000);
        assert!(!meets_aa(0xFF80_8080, 0xFF80_8080));
    }

    #[test]
    fn high_contrast_theme_text_meets_aa() {
        let t = high_contrast_theme();
        assert!(meets_aa(t.text, t.bg_canvas));
        assert!(t.text_scale >= 2);
    }

    // ── .7 text scaling ───────────────────────────────────────────────────

    #[test]
    fn text_scale_applies_and_clamps() {
        assert_eq!(TextScale::large().percent(), 150);
        assert_eq!(TextScale::large().apply(16), 24); // 16 * 1.5
        assert_eq!(TextScale::default().apply(16), 16);
        assert_eq!(TextScale::new(99_999).0, MAX_TEXT_SCALE);
        assert_eq!(TextScale::new(1).0, MIN_TEXT_SCALE);
    }

    // ── .9 notification integration ───────────────────────────────────────

    #[test]
    fn announcement_request_is_low_priority() {
        let req = announcement_request(7, "button, Save");
        match req {
            NotificationRequest::Post(n) => {
                assert_eq!(n.app, A11Y_APP_ID);
                assert_eq!(n.body, "button, Save");
                assert_eq!(n.priority, Priority::Low);
            }
            _ => panic!("expected a Post request"),
        }
    }
}

//! Multi-tab interaction model (WS8-08.2).
//!
//! A pure interaction-state model of the editor's open documents — no rendering.
//! A [`TabSet`] holds the ordered open [`Tab`]s plus the active-tab index, and
//! exposes only state transitions (open / close / activate / next / prev /
//! mark-dirty), mirroring the interaction-state views in `nexacore-ui`. Every
//! transition is fail-closed: out-of-range input returns `None`/`false` and
//! never panics or indexes, and the active index is re-clamped after each close
//! so it can never dangle past the end of the list.

use alloc::{string::String, vec::Vec};

/// A stable, opaque identifier for an open [`Tab`].
///
/// Ids are allocated monotonically by the owning [`TabSet`] and stay valid for
/// the lifetime of the tab, so callers can hold an id across reorders and closes
/// without it ever aliasing a different tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TabId(u64);

impl TabId {
    /// The underlying numeric value (useful for logging / stable keys).
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

/// One open document tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tab {
    /// Stable identifier, unique within its [`TabSet`].
    id: TabId,
    /// Display title (typically the file name, or an "untitled" placeholder).
    title: String,
    /// Backing file path, or `None` for a never-saved document.
    path: Option<String>,
    /// Whether the document has unsaved edits.
    dirty: bool,
}

impl Tab {
    /// This tab's stable id.
    #[must_use]
    pub fn id(&self) -> TabId {
        self.id
    }

    /// This tab's display title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// This tab's backing file path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Whether this tab has unsaved edits.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// The ordered set of open tabs plus the active-tab index.
///
/// The active index always points at a valid tab whenever the set is non-empty;
/// it is re-clamped on every [`TabSet::close`]/[`TabSet::close_index`]. When the
/// set is empty the active index is meaningless and [`TabSet::active`] returns
/// `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TabSet {
    tabs: Vec<Tab>,
    active: usize,
    next_id: u64,
}

impl TabSet {
    /// An empty tab set with no active tab.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of open tabs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tabs.len()
    }

    /// Whether no tabs are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tabs.is_empty()
    }

    /// All open tabs in order.
    #[must_use]
    pub fn tabs(&self) -> &[Tab] {
        &self.tabs
    }

    /// The tab at position `index`, if in range.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Tab> {
        self.tabs.get(index)
    }

    /// The active tab, or `None` when the set is empty.
    #[must_use]
    pub fn active(&self) -> Option<&Tab> {
        self.tabs.get(self.active)
    }

    /// The active tab's index, or `None` when the set is empty.
    #[must_use]
    pub fn active_index(&self) -> Option<usize> {
        if self.tabs.is_empty() {
            None
        } else {
            Some(self.active)
        }
    }

    /// The position of the tab with `id`, if present.
    #[must_use]
    pub fn index_of(&self, id: TabId) -> Option<usize> {
        self.tabs.iter().position(|t| t.id == id)
    }

    /// The tab with `id`, if present.
    #[must_use]
    pub fn by_id(&self, id: TabId) -> Option<&Tab> {
        self.tabs.iter().find(|t| t.id == id)
    }

    /// Open a new tab with `title` and optional `path`, append it, make it the
    /// active tab, and return its freshly allocated id.
    pub fn open(&mut self, title: &str, path: Option<&str>) -> TabId {
        let id = TabId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        self.tabs.push(Tab {
            id,
            title: String::from(title),
            path: path.map(String::from),
            dirty: false,
        });
        // The newly pushed tab is the last element, so `len - 1` is in range.
        self.active = self.tabs.len().saturating_sub(1);
        id
    }

    /// Close the tab at `index`, re-clamping the active index so it never
    /// dangles. Returns `true` if a tab was removed, `false` if `index` was out
    /// of range (in which case nothing changes).
    pub fn close_index(&mut self, index: usize) -> bool {
        if index >= self.tabs.len() {
            return false;
        }
        self.tabs.remove(index);
        // Re-clamp the active index around the hole left by the removed tab.
        if self.tabs.is_empty() {
            self.active = 0;
        } else if index < self.active {
            // A tab before the active one shifted everything down by one.
            self.active = self.active.saturating_sub(1);
        } else if self.active >= self.tabs.len() {
            // The active tab (or one after it) was removed at the end; clamp to
            // the new last tab.
            self.active = self.tabs.len().saturating_sub(1);
        }
        true
    }

    /// Close the tab with `id`. Returns `true` if a tab was removed, `false` if
    /// no tab had that id.
    pub fn close(&mut self, id: TabId) -> bool {
        self.index_of(id)
            .is_some_and(|index| self.close_index(index))
    }

    /// Make the tab at `index` active. Returns `true` on success, or `false`
    /// (leaving the active tab unchanged) if `index` is out of range.
    pub fn activate(&mut self, index: usize) -> bool {
        if index < self.tabs.len() {
            self.active = index;
            true
        } else {
            false
        }
    }

    /// Activate the next tab, wrapping from the last back to the first. Returns
    /// the new active index, or `None` when the set is empty.
    #[allow(
        clippy::should_implement_trait,
        reason = "editor tab-cycling API; `next`/`prev` are the natural names and \
                  this is not an iterator"
    )]
    pub fn next(&mut self) -> Option<usize> {
        let len = self.tabs.len();
        if len == 0 {
            return None;
        }
        self.active = if self.active + 1 >= len {
            0
        } else {
            self.active + 1
        };
        Some(self.active)
    }

    /// Activate the previous tab, wrapping from the first back to the last.
    /// Returns the new active index, or `None` when the set is empty.
    pub fn prev(&mut self) -> Option<usize> {
        let len = self.tabs.len();
        if len == 0 {
            return None;
        }
        self.active = if self.active == 0 {
            len.saturating_sub(1)
        } else {
            self.active - 1
        };
        Some(self.active)
    }

    /// Mark the tab with `id` as having unsaved edits. Returns `true` if the tab
    /// exists, `false` otherwise.
    pub fn mark_dirty(&mut self, id: TabId) -> bool {
        Self::set_dirty(self.tabs.iter_mut().find(|t| t.id == id), true)
    }

    /// Mark the tab with `id` as saved (no unsaved edits). Returns `true` if the
    /// tab exists, `false` otherwise.
    pub fn mark_clean(&mut self, id: TabId) -> bool {
        Self::set_dirty(self.tabs.iter_mut().find(|t| t.id == id), false)
    }

    /// Apply a dirty flag to an optionally found tab, reporting whether one was
    /// found.
    fn set_dirty(tab: Option<&mut Tab>, dirty: bool) -> bool {
        match tab {
            Some(t) => {
                t.dirty = dirty;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty_with_no_active() {
        let set = TabSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.active(), None);
        assert_eq!(set.active_index(), None);
        assert!(set.tabs().is_empty());
    }

    #[test]
    fn open_appends_and_activates() {
        let mut set = TabSet::new();
        let a = set.open("a.txt", Some("/tmp/a.txt"));
        let b = set.open("b.txt", None);
        assert_eq!(set.len(), 2);
        // The most recently opened tab is active.
        assert_eq!(set.active_index(), Some(1));
        assert_eq!(set.active().map(Tab::id), Some(b));
        // Ids are distinct and stable.
        assert_ne!(a, b);
        assert_eq!(set.by_id(a).map(Tab::title), Some("a.txt"));
        assert_eq!(set.by_id(a).and_then(Tab::path), Some("/tmp/a.txt"));
        assert_eq!(set.by_id(b).and_then(Tab::path), None);
    }

    #[test]
    fn activate_is_bounds_checked() {
        let mut set = TabSet::new();
        set.open("a", None);
        set.open("b", None);
        set.open("c", None);
        assert!(set.activate(0));
        assert_eq!(set.active_index(), Some(0));
        // Out of range is a no-op returning false.
        assert!(!set.activate(3));
        assert_eq!(set.active_index(), Some(0));
    }

    #[test]
    fn next_and_prev_wrap() {
        let mut set = TabSet::new();
        set.open("a", None);
        set.open("b", None);
        set.open("c", None);
        set.activate(2);
        assert_eq!(set.next(), Some(0)); // wraps past the end
        assert_eq!(set.next(), Some(1));
        assert_eq!(set.prev(), Some(0));
        assert_eq!(set.prev(), Some(2)); // wraps past the start
    }

    #[test]
    fn next_prev_on_empty_return_none() {
        let mut set = TabSet::new();
        assert_eq!(set.next(), None);
        assert_eq!(set.prev(), None);
    }

    #[test]
    fn close_before_active_shifts_active_down() {
        let mut set = TabSet::new();
        let a = set.open("a", None);
        set.open("b", None);
        let c = set.open("c", None);
        set.activate(2); // active = c
        assert!(set.close(a)); // remove index 0
        // c is still active, now at index 1.
        assert_eq!(set.len(), 2);
        assert_eq!(set.active().map(Tab::id), Some(c));
        assert_eq!(set.active_index(), Some(1));
    }

    #[test]
    fn close_active_reclamps_to_valid_neighbour() {
        let mut set = TabSet::new();
        set.open("a", None);
        set.open("b", None);
        let c = set.open("c", None);
        set.activate(2); // active = last (c)
        assert!(set.close(c)); // removing the last active tab
        // Active clamps to the new last tab (index 1).
        assert_eq!(set.active_index(), Some(1));
        assert_eq!(set.active().map(Tab::title), Some("b"));
    }

    #[test]
    fn close_after_active_leaves_active_untouched() {
        let mut set = TabSet::new();
        set.open("a", None);
        let b = set.open("b", None);
        set.open("c", None);
        set.activate(0); // active = a
        assert!(set.close(b)); // remove index 1 (after active)
        assert_eq!(set.active_index(), Some(0));
        assert_eq!(set.active().map(Tab::title), Some("a"));
    }

    #[test]
    fn close_last_remaining_tab_empties_the_set() {
        let mut set = TabSet::new();
        let a = set.open("only", None);
        assert!(set.close(a));
        assert!(set.is_empty());
        assert_eq!(set.active(), None);
        assert_eq!(set.active_index(), None);
    }

    #[test]
    fn close_out_of_range_is_fail_closed() {
        let mut set = TabSet::new();
        set.open("a", None);
        assert!(!set.close_index(9)); // out of range
        assert!(!set.close(TabId(999))); // unknown id
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn mark_dirty_and_clean_toggle_the_flag() {
        let mut set = TabSet::new();
        let a = set.open("a", None);
        assert!(!set.by_id(a).is_some_and(Tab::is_dirty));
        assert!(set.mark_dirty(a));
        assert!(set.by_id(a).is_some_and(Tab::is_dirty));
        assert!(set.mark_clean(a));
        assert!(!set.by_id(a).is_some_and(Tab::is_dirty));
        // Unknown ids fail closed.
        assert!(!set.mark_dirty(TabId(999)));
        assert!(!set.mark_clean(TabId(999)));
    }

    #[test]
    fn ids_do_not_alias_after_close_and_reopen() {
        let mut set = TabSet::new();
        let a = set.open("a", None);
        assert!(set.close(a));
        let b = set.open("b", None);
        // The reopened tab gets a fresh id; the stale id no longer resolves.
        assert_ne!(a, b);
        assert_eq!(set.by_id(a), None);
        assert_eq!(set.by_id(b).map(Tab::title), Some("b"));
        assert_eq!(a.value(), 0);
        assert_eq!(b.value(), 1);
    }
}

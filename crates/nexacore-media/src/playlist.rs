//! The playlist model: add / remove / reorder / seek (WS8-02.9).
//!
//! Pure state, fully host-testable.  Entries are the canonical list; a separate
//! `order` permutation defines playback order so shuffle can be toggled without
//! disturbing the displayed list.  Shuffle is **deterministic**: the caller
//! supplies the seed (this crate performs no `Date`/random access, per its
//! `no_std` contract), so a given seed always yields the same order — which is
//! what makes it testable.

use alloc::{string::String, vec::Vec};

/// One playlist item, identified by its media URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaylistEntry {
    /// Source URI / path of the media.
    pub uri: String,
}

impl PlaylistEntry {
    /// Construct an entry from anything string-like.
    pub fn new(uri: impl Into<String>) -> Self {
        Self { uri: uri.into() }
    }
}

/// How playback continues at the end of an item / list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RepeatMode {
    /// Stop when the list ends.
    #[default]
    Off,
    /// Repeat the current item indefinitely.
    One,
    /// Loop back to the start when the list ends.
    All,
}

/// An ordered list of media with a current item, repeat, and shuffle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Playlist {
    entries: Vec<PlaylistEntry>,
    /// Playback order: `order[k]` is the entry index played k-th.
    order: Vec<usize>,
    /// The currently selected entry index (into `entries`).
    current: Option<usize>,
    repeat: RepeatMode,
    shuffle_seed: Option<u64>,
}

impl Default for Playlist {
    fn default() -> Self {
        Self::new()
    }
}

impl Playlist {
    /// An empty playlist.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            order: Vec::new(),
            current: None,
            repeat: RepeatMode::Off,
            shuffle_seed: None,
        }
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries in display order.
    #[must_use]
    pub fn entries(&self) -> &[PlaylistEntry] {
        &self.entries
    }

    /// The active repeat mode.
    #[must_use]
    pub const fn repeat(&self) -> RepeatMode {
        self.repeat
    }

    /// `true` if shuffle is enabled.
    #[must_use]
    pub const fn is_shuffled(&self) -> bool {
        self.shuffle_seed.is_some()
    }

    /// Append an entry; selects it if the list was empty.
    pub fn push(&mut self, uri: impl Into<String>) {
        self.entries.push(PlaylistEntry::new(uri));
        if self.current.is_none() {
            self.current = Some(0);
        }
        self.rebuild_order();
    }

    /// Insert an entry at `index` (clamped to the end).
    pub fn insert(&mut self, index: usize, uri: impl Into<String>) {
        let index = index.min(self.entries.len());
        self.entries.insert(index, PlaylistEntry::new(uri));
        // Keep the same item selected by shifting the index if we inserted at
        // or before it.
        if let Some(cur) = self.current {
            if index <= cur {
                self.current = Some(cur.saturating_add(1));
            }
        } else {
            self.current = Some(index);
        }
        self.rebuild_order();
    }

    /// Remove the entry at `index`, returning it.  Keeps a sensible selection.
    pub fn remove(&mut self, index: usize) -> Option<PlaylistEntry> {
        if index >= self.entries.len() {
            return None;
        }
        let removed = self.entries.remove(index);
        self.current = match self.current {
            _ if self.entries.is_empty() => None,
            Some(cur) if cur == index => Some(cur.min(self.entries.len().saturating_sub(1))),
            Some(cur) if cur > index => Some(cur.saturating_sub(1)),
            other => other,
        };
        self.rebuild_order();
        Some(removed)
    }

    /// Move the entry at `from` to `to` (both clamped); preserves the selection.
    pub fn move_item(&mut self, from: usize, to: usize) {
        if from >= self.entries.len() || self.entries.is_empty() {
            return;
        }
        let to = to.min(self.entries.len().saturating_sub(1));
        if from == to {
            return;
        }
        let selected_uri = self.current.and_then(|c| self.entries.get(c)).cloned();
        let entry = self.entries.remove(from);
        self.entries.insert(to, entry);
        // Re-find the previously selected entry by identity.
        if let Some(sel) = selected_uri {
            self.current = self.entries.iter().position(|e| *e == sel);
        }
        self.rebuild_order();
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.current = None;
    }

    /// The currently selected entry.
    #[must_use]
    pub fn current(&self) -> Option<&PlaylistEntry> {
        self.entries.get(self.current?)
    }

    /// The currently selected entry index (into [`entries`](Playlist::entries)).
    #[must_use]
    pub const fn current_index(&self) -> Option<usize> {
        self.current
    }

    /// Select the entry at `index` (no-op if out of range).
    pub fn seek_to(&mut self, index: usize) -> Option<&PlaylistEntry> {
        if index < self.entries.len() {
            self.current = Some(index);
            self.entries.get(index)
        } else {
            None
        }
    }

    /// Set the repeat mode.
    pub fn set_repeat(&mut self, mode: RepeatMode) {
        self.repeat = mode;
    }

    /// Enable shuffle with `seed`, or pass `None` to restore list order.  The
    /// current selection is preserved.
    pub fn set_shuffle(&mut self, seed: Option<u64>) {
        self.shuffle_seed = seed;
        self.rebuild_order();
    }

    /// Advance to the next item as automatic playback would (honours repeat).
    ///
    /// `RepeatMode::One` re-selects the same item; `All` wraps; `Off` returns
    /// `None` and leaves the selection unchanged at the end of the list.
    pub fn advance(&mut self) -> Option<&PlaylistEntry> {
        if self.repeat == RepeatMode::One {
            return self.current();
        }
        self.step(1, self.repeat == RepeatMode::All)
    }

    /// Manually skip to the next item (wraps only under `RepeatMode::All`).
    pub fn skip_next(&mut self) -> Option<&PlaylistEntry> {
        self.step(1, self.repeat == RepeatMode::All)
    }

    /// Manually skip to the previous item (wraps only under `RepeatMode::All`).
    pub fn skip_previous(&mut self) -> Option<&PlaylistEntry> {
        self.step(-1, self.repeat == RepeatMode::All)
    }

    /// Move `delta` positions through the playback `order`, optionally wrapping.
    fn step(&mut self, delta: isize, wrap: bool) -> Option<&PlaylistEntry> {
        if self.entries.is_empty() {
            return None;
        }
        let cur_entry = self.current?;
        let cursor = self.order.iter().position(|&e| e == cur_entry)?;
        let len = self.order.len();
        let next_cursor = if wrap {
            // Wrap with modular arithmetic over `len`.
            let len_i = isize::try_from(len).ok()?;
            let raw = isize::try_from(cursor).ok()?.checked_add(delta)?;
            usize::try_from(raw.rem_euclid(len_i)).ok()?
        } else {
            let raw = isize::try_from(cursor).ok()?.checked_add(delta)?;
            if raw < 0 || usize::try_from(raw).ok()? >= len {
                return None;
            }
            usize::try_from(raw).ok()?
        };
        let entry_index = *self.order.get(next_cursor)?;
        self.current = Some(entry_index);
        self.entries.get(entry_index)
    }

    /// Rebuild the playback `order` after a structural or shuffle change.
    fn rebuild_order(&mut self) {
        let len = self.entries.len();
        self.order = self
            .shuffle_seed
            .map_or_else(|| (0..len).collect(), |seed| shuffled_order(len, seed));
        // Clamp the selection to remain valid.
        if let Some(cur) = self.current {
            if cur >= len {
                self.current = if len == 0 {
                    None
                } else {
                    Some(len.saturating_sub(1))
                };
            }
        }
    }
}

/// Deterministic Fisher-Yates permutation of `0..len`, seeded by `seed`.
fn shuffled_order(len: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    let mut state = seed;
    let mut i = len;
    while i > 1 {
        i -= 1;
        state = lcg_next(state);
        let modulus = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
        let j = usize::try_from(state % modulus).unwrap_or(0);
        order.swap(i, j);
    }
    order
}

/// One step of a 64-bit linear congruential generator (PCG/MMIX constants).
fn lcg_next(state: u64) -> u64 {
    state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
}

//! App launcher + global search index with fuzzy ranking (WS7-14).
//!
//! The launcher reads installed-app metadata (WS7-14.1), builds a search index
//! over apps, files, and settings (WS7-14.2), and ranks matches with a
//! subsequence fuzzy scorer that rewards word-boundary and consecutive-character
//! hits (WS7-14.3). [`SearchIndex::palette_candidates`] is the hand-off point to
//! the AI command palette (WS16-02, WS7-14.5). Drawing the launcher and the dock
//! are downstream UI (WS7-14.4/.6/.7).

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Installed-app metadata (a parsed app manifest — WS7-14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    /// Reverse-DNS application id (e.g. `org.nexacore.editor`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Executable / launch target.
    pub exec: String,
    /// Icon name (may be empty).
    pub icon: String,
    /// Search keywords.
    pub keywords: Vec<String>,
}

/// Parse a `.desktop`-style app manifest (`Key=Value` lines).
///
/// Requires `Id`, `Name`, and `Exec`; `Keywords` is a `;`-separated list.
/// Returns `None` if a required key is missing.
#[must_use]
pub fn parse_app_manifest(text: &str) -> Option<AppEntry> {
    let mut id = None;
    let mut name = None;
    let mut exec = None;
    let mut icon = String::new();
    let mut keywords = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        match key.trim() {
            "Id" => id = Some(value.trim().to_string()),
            "Name" => name = Some(value.trim().to_string()),
            "Exec" => exec = Some(value.trim().to_string()),
            "Icon" => icon = value.trim().to_string(),
            "Keywords" => {
                keywords = value
                    .split(';')
                    .map(str::trim)
                    .filter(|k| !k.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
            _ => {}
        }
    }
    Some(AppEntry {
        id: id?,
        name: name?,
        exec: exec?,
        icon,
        keywords,
    })
}

/// The kind of thing a search entry refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// An installed application.
    App,
    /// A file.
    File,
    /// A settings item.
    Setting,
}

/// One indexed, searchable item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchEntry {
    /// Stable identifier (app id, file path, setting key).
    pub id: String,
    /// What this entry refers to.
    pub kind: EntryKind,
    /// The primary display title (matched against).
    pub title: String,
    /// Secondary text (not matched, shown under the title).
    pub subtitle: String,
    /// Extra match keywords.
    pub keywords: Vec<String>,
}

/// A ranked search hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// The matched entry's id.
    pub id: String,
    /// The matched entry's kind.
    pub kind: EntryKind,
    /// The matched entry's title.
    pub title: String,
    /// Match score (higher is a better match).
    pub score: i32,
}

/// The global search index (WS7-14.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchIndex {
    /// The indexed entries.
    pub entries: Vec<SearchEntry>,
}

impl SearchIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn add(&mut self, entry: SearchEntry) {
        self.entries.push(entry);
    }

    /// Index an installed app.
    pub fn add_app(&mut self, app: &AppEntry) {
        self.add(SearchEntry {
            id: app.id.clone(),
            kind: EntryKind::App,
            title: app.name.clone(),
            subtitle: app.exec.clone(),
            keywords: app.keywords.clone(),
        });
    }

    /// Rank the indexed entries against `query`, best first, capped at `limit`.
    ///
    /// An entry's score is the best fuzzy score of the query over its title and
    /// keywords; ties break toward the shorter title. An empty query returns
    /// every entry in insertion order (score 0).
    #[must_use]
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchResult> {
        let mut hits: Vec<SearchResult> = Vec::new();
        for entry in &self.entries {
            let score = if query.is_empty() {
                Some(0)
            } else {
                let mut best = fuzzy_score(query, &entry.title);
                for kw in &entry.keywords {
                    best = better(best, fuzzy_score(query, kw));
                }
                best
            };
            if let Some(score) = score {
                hits.push(SearchResult {
                    id: entry.id.clone(),
                    kind: entry.kind,
                    title: entry.title.clone(),
                    score,
                });
            }
        }
        hits.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.title.len().cmp(&b.title.len()))
                .then_with(|| a.title.cmp(&b.title))
        });
        hits.truncate(limit);
        hits
    }

    /// The search results reshaped as `(title, id)` candidates for the AI
    /// command palette (WS16-02) — the WS7-14.5 integration point.
    #[must_use]
    pub fn palette_candidates(&self, query: &str, limit: usize) -> Vec<(String, String)> {
        self.search(query, limit)
            .into_iter()
            .map(|r| (r.title, r.id))
            .collect()
    }
}

/// Keep the higher of two optional scores.
fn better(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) => Some(x),
        (None, b) => b,
    }
}

/// Whether `c` is a word-boundary separator.
fn is_boundary(c: char) -> bool {
    c == ' ' || c == '-' || c == '_' || c == '.' || c == '/'
}

const BASE_BONUS: i32 = 2;
const CONSECUTIVE_BONUS: i32 = 5;
const BOUNDARY_BONUS: i32 = 8;

/// Greedy subsequence fuzzy score of `query` within `text` (case-insensitive).
///
/// Returns `None` if `query` is not a subsequence of `text`. A higher score is a
/// better match: each matched character scores [`BASE_BONUS`], consecutive
/// matches add [`CONSECUTIVE_BONUS`], and a match at a word boundary adds
/// [`BOUNDARY_BONUS`]; a small penalty grows with the candidate length so that,
/// among equal matches, shorter titles rank higher.
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "length penalty is a coarse tie-breaker"
)]
pub fn fuzzy_score(query: &str, text: &str) -> Option<i32> {
    let q: Vec<char> = query.chars().map(|c| c.to_ascii_lowercase()).collect();
    if q.is_empty() {
        return Some(0);
    }
    let t: Vec<char> = text.chars().collect();
    let mut qi = 0usize;
    let mut score = 0i32;
    let mut prev_match: Option<usize> = None;
    for (ti, &raw) in t.iter().enumerate() {
        let Some(&qc) = q.get(qi) else {
            break; // whole query matched — stop scanning
        };
        if raw.to_ascii_lowercase() == qc {
            score += BASE_BONUS;
            if ti > 0 && prev_match == Some(ti - 1) {
                score += CONSECUTIVE_BONUS;
            }
            let at_boundary = ti == 0 || t.get(ti - 1).copied().is_some_and(is_boundary);
            if at_boundary {
                score += BOUNDARY_BONUS;
            }
            prev_match = Some(ti);
            qi += 1;
        }
    }
    if qi == q.len() {
        // Prefer shorter candidates on otherwise-equal matches.
        Some(score - i32::try_from(t.len() / 4).unwrap_or(0))
    } else {
        None
    }
}

/// A request to launch an application, produced by the launcher UI (WS7-14.4).
///
/// The launcher yields the selected app's id; resolving it to an executable and
/// actually starting it is downstream (the app-source / session), and is the
/// hand-off the AI command palette consumes as `OpenApp` (WS16-02.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    /// The application id to launch.
    pub app_id: String,
}

/// The interactive launcher view (WS7-14.4): a query box, the ranked results for
/// that query, and a selection cursor over them.
///
/// This is interaction *state*, not drawing — the compositor renders it. Typing
/// (or [`set_query`](Self::set_query)) re-runs the search over a
/// [`SearchIndex`] and resets the cursor to the top hit; the arrow keys move the
/// cursor; [`launch`](Self::launch) turns the selected hit into a
/// [`LaunchRequest`] when it is an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherView {
    query: String,
    results: Vec<SearchResult>,
    selected: usize,
    limit: usize,
}

impl LauncherView {
    /// A new, empty launcher that shows at most `limit` results.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            query: String::new(),
            results: Vec::new(),
            selected: 0,
            limit,
        }
    }

    /// The current query text.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The ranked results for the current query.
    #[must_use]
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// The index of the currently selected result.
    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// The currently selected result, if any.
    #[must_use]
    pub fn selected(&self) -> Option<&SearchResult> {
        self.results.get(self.selected)
    }

    fn refresh(&mut self, index: &SearchIndex) {
        self.results = index.search(&self.query, self.limit);
        self.selected = 0;
    }

    /// Replace the query and re-run the search, selecting the top hit.
    pub fn set_query(&mut self, index: &SearchIndex, query: impl Into<String>) {
        self.query = query.into();
        self.refresh(index);
    }

    /// Append a typed character to the query and re-run the search.
    pub fn push_char(&mut self, index: &SearchIndex, ch: char) {
        self.query.push(ch);
        self.refresh(index);
    }

    /// Delete the last character of the query and re-run the search. Returns
    /// whether a character was removed.
    pub fn backspace(&mut self, index: &SearchIndex) -> bool {
        if self.query.pop().is_some() {
            self.refresh(index);
            true
        } else {
            false
        }
    }

    /// Move the selection cursor down one result (clamped to the last result).
    pub fn move_down(&mut self) {
        let last = self.results.len().saturating_sub(1);
        if self.selected < last {
            self.selected += 1;
        }
    }

    /// Move the selection cursor up one result (clamped to the first result).
    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// The launch request for the selected result, or `None` if nothing is
    /// selected or the selection is not a launchable app (WS7-14.4).
    #[must_use]
    pub fn launch(&self) -> Option<LaunchRequest> {
        let result = self.selected()?;
        (result.kind == EntryKind::App).then(|| LaunchRequest {
            app_id: result.id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EDITOR_MANIFEST: &str = "\
# Text editor
Id=org.nexacore.editor
Name=Text Editor
Exec=/apps/editor
Icon=editor
Keywords=text;edit;code;write
";

    fn index() -> SearchIndex {
        let mut idx = SearchIndex::new();
        idx.add_app(&parse_app_manifest(EDITOR_MANIFEST).unwrap());
        idx.add_app(&AppEntry {
            id: "org.nexacore.terminal".to_string(),
            name: "Terminal".to_string(),
            exec: "/apps/terminal".to_string(),
            icon: String::new(),
            keywords: alloc::vec!["shell".to_string(), "console".to_string()],
        });
        idx.add(SearchEntry {
            id: "audio.output.volume".to_string(),
            kind: EntryKind::Setting,
            title: "Output volume".to_string(),
            subtitle: "Audio".to_string(),
            keywords: alloc::vec!["sound".to_string()],
        });
        idx
    }

    #[test]
    fn manifest_parses_required_and_keyword_fields() {
        let app = parse_app_manifest(EDITOR_MANIFEST).unwrap();
        assert_eq!(app.id, "org.nexacore.editor");
        assert_eq!(app.name, "Text Editor");
        assert_eq!(app.keywords, ["text", "edit", "code", "write"]);
        // Missing Exec → None.
        assert!(parse_app_manifest("Id=x\nName=y").is_none());
    }

    #[test]
    fn fuzzy_requires_subsequence() {
        assert!(fuzzy_score("edt", "Text Editor").is_some());
        assert!(fuzzy_score("zzz", "Text Editor").is_none());
        // Word-boundary + consecutive match scores higher than a scattered one.
        let boundary = fuzzy_score("term", "Terminal").unwrap();
        let scattered = fuzzy_score("tml", "Terminal").unwrap();
        assert!(boundary > scattered, "{boundary} !> {scattered}");
    }

    #[test]
    fn search_ranks_the_best_app_first() {
        let idx = index();
        let results = idx.search("term", 10);
        assert_eq!(results.first().unwrap().id, "org.nexacore.terminal");

        // A keyword match still surfaces the entry.
        let sound = idx.search("sound", 10);
        assert_eq!(sound.first().unwrap().id, "audio.output.volume");

        // Non-matching query yields nothing.
        assert!(idx.search("qqqq", 10).is_empty());
    }

    #[test]
    fn empty_query_returns_all_and_limit_caps() {
        let idx = index();
        assert_eq!(idx.search("", 10).len(), 3);
        assert_eq!(idx.search("", 2).len(), 2);
    }

    #[test]
    fn palette_candidates_expose_title_and_id() {
        let idx = index();
        let cands = idx.palette_candidates("editor", 5);
        assert_eq!(cands.first().unwrap().1, "org.nexacore.editor");
    }

    #[test]
    fn typing_narrows_results_and_selects_the_top_hit() {
        let idx = index();
        let mut view = LauncherView::new(10);
        for ch in "term".chars() {
            view.push_char(&idx, ch);
        }
        assert_eq!(view.query(), "term");
        assert_eq!(
            view.selected().map(|r| r.id.as_str()),
            Some("org.nexacore.terminal")
        );
    }

    #[test]
    fn backspace_widens_the_result_set() {
        let idx = index();
        let mut view = LauncherView::new(10);
        view.set_query(&idx, "terminal");
        let narrow = view.results().len();
        // Delete down to "t" — more entries match the shorter query.
        for _ in 0..7 {
            assert!(view.backspace(&idx));
        }
        assert_eq!(view.query(), "t");
        assert!(view.results().len() >= narrow);
        // Backspacing an empty query returns false.
        view.set_query(&idx, "");
        assert!(!view.backspace(&idx));
    }

    #[test]
    fn arrow_navigation_is_clamped() {
        let idx = index();
        let mut view = LauncherView::new(10);
        view.set_query(&idx, ""); // all entries, selection at 0
        assert_eq!(view.selected_index(), 0);
        view.move_up(); // already at top → stays
        assert_eq!(view.selected_index(), 0);
        view.move_down();
        assert_eq!(view.selected_index(), 1);
        // Drive past the end → clamps to the last result.
        for _ in 0..10 {
            view.move_down();
        }
        assert_eq!(view.selected_index(), view.results().len() - 1);
    }

    #[test]
    fn launch_yields_an_app_id_only_for_apps() {
        let idx = index();
        let mut view = LauncherView::new(10);
        view.set_query(&idx, "terminal");
        assert_eq!(
            view.launch(),
            Some(LaunchRequest {
                app_id: "org.nexacore.terminal".to_string()
            })
        );
        // A settings result is not launchable as an app.
        view.set_query(&idx, "volume");
        assert_eq!(view.selected().map(|r| r.kind), Some(EntryKind::Setting));
        assert_eq!(view.launch(), None);
    }

    #[test]
    fn launch_is_none_when_there_are_no_results() {
        let idx = index();
        let mut view = LauncherView::new(10);
        view.set_query(&idx, "qqqq");
        assert!(view.results().is_empty());
        assert_eq!(view.selected(), None);
        assert_eq!(view.launch(), None);
    }
}

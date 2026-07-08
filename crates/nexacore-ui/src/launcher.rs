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
}

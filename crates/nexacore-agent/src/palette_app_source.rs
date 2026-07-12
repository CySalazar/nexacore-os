//! Wiring the launcher as the palette's app-source (WS16-02.2).
//!
//! The command palette parses "open <something>" into an
//! [`Intent::OpenApp`](crate::palette::Intent::OpenApp) whose `app` field is the
//! raw phrase the user typed ("text editor"), not an installed application. This
//! module resolves that phrase against the set of installed apps the launcher
//! knows about (WS7-14), turning it into a concrete [`ResolvedApp`] with a stable
//! id — or `None` when no app matches, so the palette never fabricates a launch
//! target.
//!
//! The two crates stay decoupled: the launcher (`nexacore-ui`, `no_std`) exposes
//! its apps as `(name, id)` pairs (from its `AppEntry`/`palette_candidates`
//! surface), and the integration layer feeds those into a [`ListAppSource`]
//! here. Neither crate depends on the other — the hand-off is plain data.

use std::{string::String, vec::Vec};

use crate::palette::Intent;

/// An installed application the palette can launch (WS16-02.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApp {
    /// The stable application id (e.g. `org.nexacore.terminal`).
    pub id: String,
    /// The display name.
    pub name: String,
}

/// A source of launchable applications for the palette (WS16-02.2).
///
/// The production source is the launcher's search index (WS7-14); this trait
/// keeps the palette decoupled from `nexacore-ui`.
pub trait AppSource {
    /// Resolve a user phrase (e.g. "text editor") to a single best-matching app.
    fn resolve_app(&self, query: &str) -> Option<ResolvedApp>;

    /// The ranked launchable-app candidates for `query`, best first.
    fn app_candidates(&self, query: &str, limit: usize) -> Vec<ResolvedApp>;
}

/// A list-backed [`AppSource`] fed from the launcher's `(name, id)` app list.
#[derive(Debug, Clone, Default)]
pub struct ListAppSource {
    apps: Vec<ResolvedApp>,
}

impl ListAppSource {
    /// Build a source from `(name, id)` pairs (as the launcher exposes them).
    #[must_use]
    pub fn from_pairs(pairs: &[(String, String)]) -> Self {
        let apps = pairs
            .iter()
            .map(|(name, id)| ResolvedApp {
                id: id.clone(),
                name: name.clone(),
            })
            .collect();
        Self { apps }
    }

    /// The match score of `app` against the lowercase `query`, or `None` for no
    /// match. Exact name beats prefix beats substring.
    fn score(app: &ResolvedApp, query: &str) -> Option<u8> {
        let name = app.name.to_ascii_lowercase();
        if name == query {
            Some(3)
        } else if name.starts_with(query) {
            Some(2)
        } else if name.contains(query) {
            Some(1)
        } else {
            None
        }
    }
}

impl AppSource for ListAppSource {
    fn resolve_app(&self, query: &str) -> Option<ResolvedApp> {
        let query = query.trim().to_ascii_lowercase();
        if query.is_empty() {
            return None;
        }
        self.apps
            .iter()
            .filter_map(|app| Self::score(app, &query).map(|score| (score, app)))
            // Highest score wins; ties keep the earliest app (stable).
            .max_by_key(|(score, _)| *score)
            .map(|(_, app)| app.clone())
    }

    fn app_candidates(&self, query: &str, limit: usize) -> Vec<ResolvedApp> {
        let query = query.trim().to_ascii_lowercase();
        if query.is_empty() {
            return Vec::new();
        }
        let mut scored: Vec<(u8, &ResolvedApp)> = self
            .apps
            .iter()
            .filter_map(|app| Self::score(app, &query).map(|score| (score, app)))
            .collect();
        // Best score first; stable within a score.
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored
            .into_iter()
            .take(limit)
            .map(|(_, app)| app.clone())
            .collect()
    }
}

/// Resolve an [`Intent::OpenApp`] against an [`AppSource`] (WS16-02.2).
///
/// Returns the concrete [`ResolvedApp`] to launch, or `None` when the intent is
/// not an open-app request or no installed app matches the phrase.
#[must_use]
pub fn resolve_open_app<S: AppSource + ?Sized>(intent: &Intent, source: &S) -> Option<ResolvedApp> {
    match intent {
        Intent::OpenApp { app } => source.resolve_app(app),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> ListAppSource {
        ListAppSource::from_pairs(&[
            ("Text Editor".to_string(), "org.nexacore.editor".to_string()),
            ("Terminal".to_string(), "org.nexacore.terminal".to_string()),
            (
                "Terminal Themes".to_string(),
                "org.nexacore.terminal.themes".to_string(),
            ),
        ])
    }

    #[test]
    fn an_exact_name_resolves_to_its_id() {
        let resolved = source().resolve_app("Terminal");
        assert_eq!(
            resolved.map(|a| a.id),
            Some("org.nexacore.terminal".to_string())
        );
    }

    #[test]
    fn resolution_is_case_insensitive_and_prefers_exact_over_prefix() {
        // "terminal" exactly matches "Terminal" (score 3) over the "Terminal
        // Themes" prefix match (score 2).
        let resolved = source().resolve_app("terminal");
        assert_eq!(
            resolved.map(|a| a.id),
            Some("org.nexacore.terminal".to_string())
        );
    }

    #[test]
    fn a_substring_resolves_when_there_is_no_better_match() {
        let resolved = source().resolve_app("editor");
        assert_eq!(
            resolved.map(|a| a.id),
            Some("org.nexacore.editor".to_string())
        );
    }

    #[test]
    fn an_unknown_app_resolves_to_none() {
        assert_eq!(source().resolve_app("spreadsheet"), None);
        assert_eq!(source().resolve_app("   "), None);
    }

    #[test]
    fn candidates_are_ranked_and_limited() {
        let cands = source().app_candidates("terminal", 10);
        // Both "Terminal" (exact) and "Terminal Themes" (prefix) match; exact first.
        assert_eq!(cands.len(), 2);
        assert_eq!(
            cands.first().map(|a| a.id.as_str()),
            Some("org.nexacore.terminal")
        );
        // Limit is honored.
        assert_eq!(source().app_candidates("terminal", 1).len(), 1);
    }

    #[test]
    fn resolve_open_app_bridges_the_palette_intent() {
        let open = Intent::OpenApp {
            app: "text editor".to_string(),
        };
        assert_eq!(
            resolve_open_app(&open, &source()).map(|a| a.id),
            Some("org.nexacore.editor".to_string())
        );
        // A non-open intent yields nothing.
        let other = Intent::SearchContent {
            query: "x".to_string(),
        };
        assert_eq!(resolve_open_app(&other, &source()), None);
        // An open-app intent for an unknown app yields nothing (no fabricated id).
        let ghost = Intent::OpenApp {
            app: "ghostapp".to_string(),
        };
        assert_eq!(resolve_open_app(&ghost, &source()), None);
    }
}

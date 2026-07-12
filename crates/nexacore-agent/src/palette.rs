//! System-wide natural-language command palette (WS16-02).
//!
//! A global palette (opened by [`PALETTE_HOTKEY`](crate::palette::PALETTE_HOTKEY)) takes a natural-language
//! prompt and turns it into one or more executable [`PlannedAction`](crate::palette::PlannedAction)s: launch an
//! app, change a setting, search content semantically, run an automation, or
//! query the system. It fuses launcher + search + agent into a single "describe
//! anything" surface.
//!
//! ## Layering
//!
//! - **Parsing** ([`IntentParser`](crate::palette::IntentParser), WS16-02.3) is a seam: the production parser
//!   is the AI runtime (WS5-03); [`RuleBasedParser`](crate::palette::RuleBasedParser) is the deterministic,
//!   local-first fallback that classifies common English/Italian phrasings and
//!   splits compound prompts (WS16-02.9).
//! - **Planning** ([`CommandPalette::plan`](crate::palette::CommandPalette::plan)) maps each [`Intent`](crate::palette::Intent) to a
//!   [`PlannedAction`](crate::palette::PlannedAction) with a category and risk (WS16-02.4–.8).
//! - **Gating** ([`CommandPalette::submit`](crate::palette::CommandPalette::submit)) runs risky actions past a
//!   capability check and attaches the four mandatory Impact-Dashboard axes
//!   (WS16-02.10), reusing [`crate::guidance::impact`].
//!
//! Wiring the launcher app-source (WS16-02.2) and the concrete execution
//! backends (config store, semantic search, workflow engine) is downstream; this
//! module is the device-independent, fully host-testable core.

use crate::guidance::impact::{ImpactDimension, ImpactScore};

/// The dedicated system hotkey that opens the palette (WS16-02.1).
pub const PALETTE_HOTKEY: &str = "Super+Space";

/// A parsed user intent (WS16-02.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// Launch an application (WS16-02.4).
    OpenApp {
        /// The application name or identifier.
        app: String,
    },
    /// Change a system setting (WS16-02.5).
    ChangeSetting {
        /// The setting to change (e.g. `dark mode`, `volume`).
        key: String,
        /// The requested value (e.g. `on`, `off`, `down`).
        value: String,
    },
    /// Search files/notes/content semantically (WS16-02.6).
    SearchContent {
        /// The search query.
        query: String,
    },
    /// Run an agentic automation/workflow (WS16-02.7).
    RunAutomation {
        /// The automation name or description.
        name: String,
    },
    /// Query system state / diagnostics (WS16-02.8).
    QuerySystem {
        /// The topic being asked about.
        topic: String,
    },
    /// The prompt could not be classified.
    Unknown {
        /// The original (trimmed) text.
        text: String,
    },
}

/// Parses a natural-language prompt into one or more [`Intent`]s.
///
/// The production implementation is the AI runtime (WS5-03); [`RuleBasedParser`]
/// is the deterministic fallback.
pub trait IntentParser {
    /// Parse `prompt` into intents (one per action in a compound prompt).
    fn parse(&self, prompt: &str) -> Vec<Intent>;
}

/// Substrings that separate multiple actions in one prompt (English + Italian).
const CONNECTIVES: [&str; 8] = [";", ",", " and ", " then ", " & ", " e ", " poi ", " ed "];

/// Split a compound prompt into individual action segments.
fn segment(prompt: &str) -> Vec<&str> {
    let mut segments = vec![prompt];
    for delim in CONNECTIVES {
        let mut next = Vec::new();
        for seg in segments {
            let mut rest = seg;
            while let Some(pos) = rest.find(delim) {
                if let Some(head) = rest.get(..pos) {
                    next.push(head);
                }
                rest = rest.get(pos + delim.len()..).unwrap_or("");
            }
            next.push(rest);
        }
        segments = next;
    }
    segments
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Case-insensitively strip any of `prefixes` from `seg`, returning the trimmed
/// remainder (in original case) on the first match.
fn strip_verb<'a>(seg: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    let lower = seg.to_ascii_lowercase();
    for &p in prefixes {
        if lower.starts_with(p) {
            return seg.get(p.len()..).map(str::trim);
        }
    }
    None
}

const OPEN_VERBS: [&str; 6] = ["open ", "launch ", "start ", "apri ", "avvia ", "lancia "];
const SEARCH_VERBS: [&str; 8] = [
    "search for ",
    "search ",
    "find ",
    "look for ",
    "show me ",
    "cerca ",
    "trova ",
    "mostra ",
];
const AUTOMATION_VERBS: [&str; 4] = [
    "run automation ",
    "automate ",
    "esegui automazione ",
    "automatizza ",
];
const SETTING_VERBS: [&str; 10] = [
    "set ",
    "enable ",
    "disable ",
    "turn on ",
    "turn off ",
    "switch to ",
    "imposta ",
    "attiva ",
    "disattiva ",
    "metti ",
];
const QUERY_VERBS: [&str; 8] = [
    "what ",
    "how ",
    "why ",
    "status ",
    "show status",
    "tell me ",
    "qual ",
    "stato ",
];

/// A deterministic, local-first [`IntentParser`] fallback.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleBasedParser;

impl RuleBasedParser {
    /// Classify a single (already-segmented) phrase.
    fn classify(seg: &str) -> Intent {
        let lower = seg.to_ascii_lowercase();
        // Volume up/down is a common setting phrasing worth special-casing.
        if lower.contains("volume") {
            let value =
                if lower.contains("down") || lower.contains("lower") || lower.contains("abbassa") {
                    "down"
                } else if lower.contains("up") || lower.contains("raise") || lower.contains("alza")
                {
                    "up"
                } else {
                    "set"
                };
            return Intent::ChangeSetting {
                key: "volume".to_string(),
                value: value.to_string(),
            };
        }
        if let Some(rest) = strip_verb(seg, &AUTOMATION_VERBS) {
            return Intent::RunAutomation {
                name: rest.to_owned(),
            };
        }
        if let Some(rest) = strip_verb(seg, &OPEN_VERBS) {
            return Intent::OpenApp {
                app: rest.to_owned(),
            };
        }
        if let Some(rest) = strip_verb(seg, &SEARCH_VERBS) {
            return Intent::SearchContent {
                query: rest.to_owned(),
            };
        }
        if let Some(rest) = strip_verb(seg, &SETTING_VERBS) {
            return setting_from(rest);
        }
        if strip_verb(seg, &QUERY_VERBS).is_some() || lower.ends_with('?') {
            return Intent::QuerySystem {
                topic: seg.trim_end_matches('?').trim().to_string(),
            };
        }
        Intent::Unknown {
            text: seg.to_string(),
        }
    }
}

/// Derive a [`Intent::ChangeSetting`] from the text after a setting verb,
/// extracting a coarse on/off value.
fn setting_from(rest: &str) -> Intent {
    let lower = rest.to_ascii_lowercase();
    // Strip a leading "the "/"il "/"lo "/"la " noise word.
    let key_raw = rest
        .strip_prefix("the ")
        .or_else(|| rest.strip_prefix("il "))
        .or_else(|| rest.strip_prefix("lo "))
        .or_else(|| rest.strip_prefix("la "))
        .unwrap_or(rest);
    // Off cues flip the value; everything else defaults to "on".
    let value =
        if lower.contains(" off") || lower.contains("disable") || lower.contains("disattiva") {
            "off"
        } else {
            "on"
        };
    // Drop a trailing " in X"/" to X"/" a X" phrase from the key for readability.
    let key = key_raw
        .split(" in ")
        .next()
        .unwrap_or(key_raw)
        .split(" to ")
        .next()
        .unwrap_or(key_raw)
        .trim()
        .to_string();
    Intent::ChangeSetting {
        key,
        value: value.to_string(),
    }
}

impl IntentParser for RuleBasedParser {
    fn parse(&self, prompt: &str) -> Vec<Intent> {
        segment(prompt).into_iter().map(Self::classify).collect()
    }
}

/// The category of a planned action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCategory {
    /// Launch an application.
    LaunchApp,
    /// Change a system setting.
    ChangeSetting,
    /// Search content.
    Search,
    /// Run an automation.
    Automation,
    /// Query system state.
    Query,
    /// Unrecognised.
    Unrecognised,
}

/// The risk tier of a planned action, gating whether a capability is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// Read-only / launch-only: no capability required.
    Safe,
    /// Mutates system state: capability-gated (WS16-02.10).
    Elevated,
}

/// A capability a palette action may require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteCapability {
    /// Permission to change settings.
    Settings,
    /// Permission to run automations.
    Automation,
}

/// The capability-gate seam (WS16-02.10).
pub trait PaletteCapabilities {
    /// Whether the caller holds `cap`.
    fn holds(&self, cap: PaletteCapability) -> bool;
}

/// A concrete action planned from an [`Intent`] (WS16-02.4–.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    /// The originating intent.
    pub intent: Intent,
    /// The action category.
    pub category: ActionCategory,
    /// A plain-language description of what will happen.
    pub description: String,
    /// The action's risk tier.
    pub risk: RiskLevel,
    /// The capability required to run it (`None` for [`RiskLevel::Safe`]).
    pub required_capability: Option<PaletteCapability>,
}

impl PlannedAction {
    /// The four mandatory Impact-Dashboard axes for a risky action, in canonical
    /// order (WS16-02.10). Safe actions score all-zero.
    #[must_use]
    pub fn impact_axes(&self) -> Vec<ImpactScore> {
        let (privacy, trust, cost, time) = match self.category {
            ActionCategory::ChangeSetting => (10, 40, 5, 10),
            ActionCategory::Automation => (30, 60, 25, 40),
            _ => (0, 0, 0, 0),
        };
        vec![
            ImpactScore::new(ImpactDimension::Privacy, privacy),
            ImpactScore::new(ImpactDimension::Trust, trust),
            ImpactScore::new(ImpactDimension::Cost, cost),
            ImpactScore::new(ImpactDimension::Time, time),
        ]
    }
}

/// Map an intent to its planned action.
fn plan_intent(intent: Intent) -> PlannedAction {
    let (category, risk, cap, description) = match &intent {
        Intent::OpenApp { app } => (
            ActionCategory::LaunchApp,
            RiskLevel::Safe,
            None,
            format!("Launch application: {app}"),
        ),
        Intent::SearchContent { query } => (
            ActionCategory::Search,
            RiskLevel::Safe,
            None,
            format!("Search content for: {query}"),
        ),
        Intent::QuerySystem { topic } => (
            ActionCategory::Query,
            RiskLevel::Safe,
            None,
            format!("Report system state: {topic}"),
        ),
        Intent::ChangeSetting { key, value } => (
            ActionCategory::ChangeSetting,
            RiskLevel::Elevated,
            Some(PaletteCapability::Settings),
            format!("Set {key} = {value}"),
        ),
        Intent::RunAutomation { name } => (
            ActionCategory::Automation,
            RiskLevel::Elevated,
            Some(PaletteCapability::Automation),
            format!("Run automation: {name}"),
        ),
        Intent::Unknown { text } => (
            ActionCategory::Unrecognised,
            RiskLevel::Safe,
            None,
            format!("No matching action for: {text}"),
        ),
    };
    PlannedAction {
        intent,
        category,
        description,
        risk,
        required_capability: cap,
    }
}

/// Why a planned action was not authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedAction {
    /// The action that was denied.
    pub action: PlannedAction,
    /// The capability the caller lacked.
    pub missing_capability: PaletteCapability,
}

/// The result of submitting a prompt: the authorized plan and any denials.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PaletteOutcome {
    /// Actions cleared to run, in prompt order.
    pub authorized: Vec<PlannedAction>,
    /// Risky actions blocked for want of a capability (WS16-02.10).
    pub denied: Vec<DeniedAction>,
}

/// The command palette: a parser plus planning and capability gating.
#[derive(Debug, Clone, Default)]
pub struct CommandPalette<P: IntentParser> {
    parser: P,
}

impl<P: IntentParser> CommandPalette<P> {
    /// A palette using `parser`.
    pub fn new(parser: P) -> Self {
        Self { parser }
    }

    /// Parse and plan `prompt` into actions (multi-action, WS16-02.9), without
    /// gating.
    #[must_use]
    pub fn plan(&self, prompt: &str) -> Vec<PlannedAction> {
        self.parser
            .parse(prompt)
            .into_iter()
            .map(plan_intent)
            .collect()
    }

    /// Plan `prompt`, then gate: an [`RiskLevel::Elevated`] action runs only if
    /// `caps` grants its capability (deny-by-default). Safe actions always pass.
    #[must_use]
    pub fn submit(&self, prompt: &str, caps: &impl PaletteCapabilities) -> PaletteOutcome {
        let mut outcome = PaletteOutcome::default();
        for action in self.plan(prompt) {
            match (action.risk, action.required_capability) {
                (RiskLevel::Elevated, Some(cap)) if !caps.holds(cap) => {
                    outcome.denied.push(DeniedAction {
                        action,
                        missing_capability: cap,
                    });
                }
                _ => outcome.authorized.push(action),
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capability set granting an explicit list.
    struct Grant(Vec<PaletteCapability>);
    impl PaletteCapabilities for Grant {
        fn holds(&self, cap: PaletteCapability) -> bool {
            self.0.contains(&cap)
        }
    }

    fn palette() -> CommandPalette<RuleBasedParser> {
        CommandPalette::new(RuleBasedParser)
    }

    #[test]
    fn classifies_the_five_intent_kinds() {
        let p = RuleBasedParser;
        assert_eq!(
            p.parse("open Firefox"),
            vec![Intent::OpenApp {
                app: "Firefox".into()
            }]
        );
        assert_eq!(
            p.parse("find notes about rust"),
            vec![Intent::SearchContent {
                query: "notes about rust".into()
            }]
        );
        assert_eq!(
            p.parse("run automation nightly-backup"),
            vec![Intent::RunAutomation {
                name: "nightly-backup".into()
            }]
        );
        assert!(matches!(
            p.parse("what is the cpu temperature").as_slice(),
            [Intent::QuerySystem { .. }]
        ));
    }

    #[test]
    fn decomposes_a_compound_prompt() {
        // The plan's canonical example: dark mode + volume, in one prompt.
        let intents = RuleBasedParser.parse("enable dark mode and lower the volume");
        assert_eq!(intents.len(), 2);
        assert!(matches!(&intents[0], Intent::ChangeSetting { key, value }
            if key.contains("dark") && value == "on"));
        assert_eq!(
            intents[1],
            Intent::ChangeSetting {
                key: "volume".into(),
                value: "down".into()
            }
        );
    }

    #[test]
    fn decomposes_italian_compound_prompt() {
        // The WS16-02 verification prompt, in Italian.
        let intents = RuleBasedParser.parse("metti il sistema in dark mode e abbassa il volume");
        assert_eq!(intents.len(), 2);
        assert!(matches!(&intents[0], Intent::ChangeSetting { .. }));
        assert_eq!(
            intents[1],
            Intent::ChangeSetting {
                key: "volume".into(),
                value: "down".into()
            }
        );
    }

    #[test]
    fn safe_actions_pass_and_risky_actions_gate() {
        let pal = palette();
        // No capabilities: the setting change is denied, the search passes.
        let out = pal.submit("find my notes and enable dark mode", &Grant(vec![]));
        assert_eq!(out.authorized.len(), 1);
        assert_eq!(out.authorized[0].category, ActionCategory::Search);
        assert_eq!(out.denied.len(), 1);
        assert_eq!(
            out.denied[0].missing_capability,
            PaletteCapability::Settings
        );

        // With the Settings capability, both pass.
        let out = pal.submit(
            "find my notes and enable dark mode",
            &Grant(vec![PaletteCapability::Settings]),
        );
        assert_eq!(out.authorized.len(), 2);
        assert!(out.denied.is_empty());
    }

    #[test]
    fn risky_actions_expose_four_impact_axes() {
        let actions = palette().plan("run automation cleanup");
        let axes = actions[0].impact_axes();
        assert_eq!(axes.len(), 4);
        assert_eq!(axes[0].dimension, ImpactDimension::Privacy);
        // Automation carries non-trivial trust/time impact.
        assert!(axes.iter().any(|a| a.score > 0));
        // A safe action scores all-zero.
        let safe = palette().plan("open Terminal");
        assert!(safe[0].impact_axes().iter().all(|a| a.score == 0));
    }

    #[test]
    fn unknown_prompt_is_not_actioned() {
        let actions = palette().plan("xyzzy plugh");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].category, ActionCategory::Unrecognised);
    }
}

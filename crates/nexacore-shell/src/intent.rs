//! Intent classification — lightweight agent integration for the shell.
//!
//! This module provides a keyword-based heuristic that mirrors the NCIP-022
//! Orchestrator's routing logic. Given a raw command or natural-language
//! string, [`crate::intent::classify_intent`] returns the most appropriate [`crate::intent::IntentClass`],
//! which the REPL uses to:
//!
//! - Display an agent label prefix when `NEXACORE_AGENT=1` is set.
//! - Emit a warning when `NEXACORE_MODE=high-risk` and the intent is sensitive.
//! - Record the classification in the per-session [`crate::audit::AuditLog`].
//!
//! ## Classification algorithm
//!
//! 1. Lower-case the input once.
//! 2. Count keyword matches for each category (see `GUIDANCE_KEYWORDS`,
//!    `ADMIN_KEYWORDS`, `SECURITY_KEYWORDS`, `TASK_KEYWORDS`).
//! 3. The category with the highest count wins.
//! 4. If two or more categories are tied at the top (and count > 0), the
//!    result is `IntentClass::Composite`.
//! 5. If no keyword matches at all, the default is `IntentClass::Task`.

use alloc::string::String;

// ── Keyword tables ─────────────────────────────────────────────────────────────

/// Keywords that indicate a guidance / explanation intent.
const GUIDANCE_KEYWORDS: &[&str] = &[
    "explain",
    "help",
    "how to",
    "what is",
    "tutorial",
    "guide",
    "teach",
    "learn",
    "understand",
];

/// Keywords that indicate a system-administration intent.
const ADMIN_KEYWORDS: &[&str] = &[
    "install",
    "configure",
    "mount",
    "unmount",
    "update",
    "upgrade",
    "service",
    "daemon",
    "driver",
    "restart",
    "reboot",
    "shutdown",
    "package",
];

/// Keywords that indicate a security-related intent.
const SECURITY_KEYWORDS: &[&str] = &[
    "audit",
    "security",
    "threat",
    "vulnerability",
    "permission",
    "access control",
    "encrypt",
    "decrypt",
    "certificate",
    "password",
    "authentication",
];

/// Keywords that indicate a concrete task / automation intent.
const TASK_KEYWORDS: &[&str] = &[
    "search",
    "find",
    "create",
    "write",
    "organize",
    "rename",
    "download",
    "upload",
    "summarize",
    "translate",
    "schedule",
    "remind",
    "monitor",
    "compare",
    "analyze",
];

// ── IntentClass ────────────────────────────────────────────────────────────────

/// The classified intent of a shell input string.
///
/// Each variant corresponds to one of the five NCIP-022 agent roles. The
/// [`Composite`](IntentClass::Composite) variant is emitted when the input
/// simultaneously matches two or more top-level categories with equal score,
/// indicating that the Orchestrator should be consulted rather than routing to
/// a single specialised agent.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::intent::{IntentClass, classify_intent};
///
/// assert_eq!(
///     classify_intent("help me understand paging"),
///     IntentClass::Guidance
/// );
/// assert_eq!(
///     classify_intent("install firefox"),
///     IntentClass::Administration
/// );
/// assert_eq!(
///     classify_intent("audit system permissions"),
///     IntentClass::Security
/// );
/// assert_eq!(classify_intent("find all rust files"), IntentClass::Task);
/// assert_eq!(
///     classify_intent("install and audit the firewall"),
///     IntentClass::Composite
/// );
/// assert_eq!(classify_intent("hello world"), IntentClass::Task); // default
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentClass {
    /// The input asks for explanations, tutorials, or conceptual guidance.
    Guidance,
    /// The input involves system administration (install, configure, reboot, …).
    Administration,
    /// The input concerns security topics (audit, encrypt, permissions, …).
    Security,
    /// The input requests a concrete, bounded task (find, create, rename, …).
    Task,
    /// Two or more categories tied; the Orchestrator should handle routing.
    Composite,
}

// ── classify_intent ───────────────────────────────────────────────────────────

/// Classify the intent of `content` into one of the five [`IntentClass`] variants.
///
/// The function is case-insensitive: `content` is lower-cased once before any
/// keyword comparison. Multi-word keywords (e.g. `"how to"`, `"access control"`)
/// are matched as substrings of the lower-cased input.
///
/// # Algorithm
///
/// Each of the four keyword tables is scanned; a running match count is
/// accumulated per category. The category with the highest count wins. A tie
/// among the leading categories (count > 0) yields `IntentClass::Composite`.
/// Zero total matches defaults to `IntentClass::Task`.
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::intent::{IntentClass, classify_intent};
///
/// // Guidance wins via "explain" and "how to".
/// assert_eq!(
///     classify_intent("explain how to set up a firewall"),
///     IntentClass::Guidance,
/// );
///
/// // No keywords → default Task.
/// assert_eq!(classify_intent(""), IntentClass::Task);
/// ```
pub fn classify_intent(content: &str) -> IntentClass {
    let lower: String = content.to_lowercase();

    let guidance_score = count_matches(&lower, GUIDANCE_KEYWORDS);
    let admin_score = count_matches(&lower, ADMIN_KEYWORDS);
    let security_score = count_matches(&lower, SECURITY_KEYWORDS);
    let task_score = count_matches(&lower, TASK_KEYWORDS);

    let max_score = guidance_score
        .max(admin_score)
        .max(security_score)
        .max(task_score);

    // Zero matches → default Task.
    if max_score == 0 {
        return IntentClass::Task;
    }

    // Count how many categories share the top score.
    let tied_count = [guidance_score, admin_score, security_score, task_score]
        .iter()
        .filter(|&&s| s == max_score)
        .count();

    if tied_count >= 2 {
        return IntentClass::Composite;
    }

    // Exactly one category holds the top score.
    if guidance_score == max_score {
        IntentClass::Guidance
    } else if admin_score == max_score {
        IntentClass::Administration
    } else if security_score == max_score {
        IntentClass::Security
    } else {
        IntentClass::Task
    }
}

// ── agent_label ───────────────────────────────────────────────────────────────

/// Return the display label bracket for the given [`IntentClass`].
///
/// These labels are prepended to shell output when `NEXACORE_AGENT=1` is set in
/// the shell environment, giving the user visibility into which agent is
/// handling the request.
///
/// | Variant | Label |
/// |---------|-------|
/// | `Guidance` | `"[GUIDANCE]"` |
/// | `Administration` | `"[ADMIN]"` |
/// | `Security` | `"[SECURITY]"` |
/// | `Task` | `"[TASK]"` |
/// | `Composite` | `"[COMPOSITE]"` |
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::intent::{IntentClass, agent_label};
///
/// assert_eq!(agent_label(IntentClass::Guidance), "[GUIDANCE]");
/// assert_eq!(agent_label(IntentClass::Administration), "[ADMIN]");
/// assert_eq!(agent_label(IntentClass::Security), "[SECURITY]");
/// assert_eq!(agent_label(IntentClass::Task), "[TASK]");
/// assert_eq!(agent_label(IntentClass::Composite), "[COMPOSITE]");
/// ```
pub fn agent_label(class: IntentClass) -> &'static str {
    match class {
        IntentClass::Guidance => "[GUIDANCE]",
        IntentClass::Administration => "[ADMIN]",
        IntentClass::Security => "[SECURITY]",
        IntentClass::Task => "[TASK]",
        IntentClass::Composite => "[COMPOSITE]",
    }
}

// ── agent_short_id ────────────────────────────────────────────────────────────

/// Return the short agent identifier string for the given [`IntentClass`].
///
/// Short IDs are used in audit log entries and internal routing metadata.
/// They are stable identifiers; do not change them without a version bump.
///
/// | Variant | Short ID |
/// |---------|----------|
/// | `Guidance` | `"guid"` |
/// | `Administration` | `"sadm"` |
/// | `Security` | `"secp"` |
/// | `Task` | `"task"` |
/// | `Composite` | `"orch"` |
///
/// # Examples
///
/// ```rust
/// use nexacore_shell::intent::{IntentClass, agent_short_id};
///
/// assert_eq!(agent_short_id(IntentClass::Guidance), "guid");
/// assert_eq!(agent_short_id(IntentClass::Administration), "sadm");
/// assert_eq!(agent_short_id(IntentClass::Security), "secp");
/// assert_eq!(agent_short_id(IntentClass::Task), "task");
/// assert_eq!(agent_short_id(IntentClass::Composite), "orch");
/// ```
pub fn agent_short_id(class: IntentClass) -> &'static str {
    match class {
        IntentClass::Guidance => "guid",
        IntentClass::Administration => "sadm",
        IntentClass::Security => "secp",
        IntentClass::Task => "task",
        IntentClass::Composite => "orch",
    }
}

// ── count_matches (private helper) ────────────────────────────────────────────

/// Count how many keywords from `table` appear as substrings of `lower_input`.
///
/// `lower_input` must already be lower-cased by the caller; this avoids
/// repeated lower-casing when multiple tables are checked for the same input.
fn count_matches(lower_input: &str, table: &[&str]) -> usize {
    table.iter().filter(|kw| lower_input.contains(**kw)).count()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_guidance() {
        assert_eq!(
            classify_intent("help me understand paging"),
            IntentClass::Guidance
        );
    }

    #[test]
    fn test_classify_administration() {
        assert_eq!(
            classify_intent("install firefox"),
            IntentClass::Administration
        );
    }

    #[test]
    fn test_classify_security() {
        assert_eq!(
            classify_intent("audit system permissions"),
            IntentClass::Security
        );
    }

    #[test]
    fn test_classify_task() {
        assert_eq!(classify_intent("find all rust files"), IntentClass::Task);
    }

    #[test]
    fn test_classify_composite() {
        // "install" → Administration; "audit" → Security: tie → Composite.
        assert_eq!(
            classify_intent("install and audit the firewall"),
            IntentClass::Composite
        );
    }

    #[test]
    fn test_classify_default_is_task() {
        assert_eq!(classify_intent("hello world"), IntentClass::Task);
    }

    #[test]
    fn test_agent_label_all_variants() {
        assert_eq!(agent_label(IntentClass::Guidance), "[GUIDANCE]");
        assert_eq!(agent_label(IntentClass::Administration), "[ADMIN]");
        assert_eq!(agent_label(IntentClass::Security), "[SECURITY]");
        assert_eq!(agent_label(IntentClass::Task), "[TASK]");
        assert_eq!(agent_label(IntentClass::Composite), "[COMPOSITE]");
    }

    #[test]
    fn test_agent_short_id_all_variants() {
        assert_eq!(agent_short_id(IntentClass::Guidance), "guid");
        assert_eq!(agent_short_id(IntentClass::Administration), "sadm");
        assert_eq!(agent_short_id(IntentClass::Security), "secp");
        assert_eq!(agent_short_id(IntentClass::Task), "task");
        assert_eq!(agent_short_id(IntentClass::Composite), "orch");
    }

    #[test]
    fn test_case_insensitive() {
        // "HELP" should match "help" keyword → Guidance.
        assert_eq!(classify_intent("HELP me"), IntentClass::Guidance);
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(classify_intent(""), IntentClass::Task);
    }

    #[test]
    fn test_classify_multiple_guidance_keywords() {
        // "explain" + "how to" + "learn" → Guidance (score 3 vs others ≤ 1).
        assert_eq!(
            classify_intent("explain how to learn about kernels"),
            IntentClass::Guidance
        );
    }

    #[test]
    fn test_classify_security_wins_over_task() {
        // "find" (Task) vs "vulnerability" + "security" (Security score 2).
        assert_eq!(
            classify_intent("find a security vulnerability"),
            IntentClass::Security
        );
    }

    #[test]
    fn test_classify_composite_three_way_tie() {
        // "help" (Guidance=1) "install" (Admin=1) "audit" (Security=1): tie → Composite.
        assert_eq!(
            classify_intent("help install and audit"),
            IntentClass::Composite
        );
    }
}

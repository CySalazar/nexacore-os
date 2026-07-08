//! NCIP-007 §1 — Trigger sources for the Guidance Agent.
//!
//! Three sources determine when the Guidance Agent activates:
//! - **Failure-driven**: the system encountered an error or anomaly.
//! - **Explicit-invoke**: the user directly requests assistance.
//! - **Watch-always-on**: background monitoring detects a noteworthy event.
//!
//! See NCIP-Agent-Arch-022 §S4 and NCIP-007 §1.

use serde::{Deserialize, Serialize};

/// The origin of a guidance trigger event (NCIP-007 §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriggerSource {
    /// An operation failed or the system is in an error state.
    FailureDriven,
    /// The user explicitly invoked the Guidance Agent (question, tutorial request).
    ExplicitInvoke,
    /// Background watch detected a noteworthy system event.
    WatchAlwaysOn,
}

impl TriggerSource {
    /// Returns a short human-readable label for this source.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FailureDriven => "failure-driven",
            Self::ExplicitInvoke => "explicit-invoke",
            Self::WatchAlwaysOn => "watch-always-on",
        }
    }
}

/// A single guidance trigger event carrying its source and context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriggerEvent {
    /// Where this trigger originated.
    pub source: TriggerSource,
    /// Contextual description of what triggered the event.
    pub context: String,
    /// Unix timestamp (seconds) when the trigger was created.
    pub timestamp: u64,
}

impl TriggerEvent {
    /// Construct a new trigger event.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::triggers::{TriggerEvent, TriggerSource};
    ///
    /// let event = TriggerEvent::new(TriggerSource::ExplicitInvoke, "User asked for help", 0);
    /// assert_eq!(event.source, TriggerSource::ExplicitInvoke);
    /// ```
    #[must_use]
    pub fn new(source: TriggerSource, context: impl Into<String>, timestamp: u64) -> Self {
        Self {
            source,
            context: context.into(),
            timestamp,
        }
    }
}

/// Evaluates whether a given trigger event should cause the Guidance Agent to act.
///
/// The evaluation rules follow NCIP-007 §1:
/// - `ExplicitInvoke` always fires.
/// - `FailureDriven` fires when the context is non-empty.
/// - `WatchAlwaysOn` fires when the context is non-empty.
#[derive(Debug, Default)]
pub struct TriggerEvaluator;

impl TriggerEvaluator {
    /// Create a new evaluator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Determine whether a trigger event should cause the Guidance Agent to activate.
    ///
    /// Returns `true` if the agent should handle this event.
    ///
    /// # Examples
    ///
    /// ```
    /// use nexacore_agent::guidance::triggers::{TriggerEvaluator, TriggerEvent, TriggerSource};
    ///
    /// let evaluator = TriggerEvaluator::new();
    /// let event = TriggerEvent::new(TriggerSource::ExplicitInvoke, "Help me", 0);
    /// assert!(evaluator.should_fire(&event));
    /// ```
    // The `&self` receiver is intentional: future evaluator variants may carry
    // configuration (e.g., topic filters for WatchAlwaysOn) that affects firing.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn should_fire(&self, event: &TriggerEvent) -> bool {
        match event.source {
            // Explicit invocations always fire regardless of context content.
            TriggerSource::ExplicitInvoke => true,
            // Failure-driven and watch triggers require a non-empty context.
            TriggerSource::FailureDriven | TriggerSource::WatchAlwaysOn => {
                !event.context.is_empty()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> u64 {
        0
    }

    #[test]
    fn explicit_invoke_always_fires() {
        let ev = TriggerEvent::new(TriggerSource::ExplicitInvoke, "", ts());
        assert!(TriggerEvaluator::new().should_fire(&ev));
    }

    #[test]
    fn explicit_invoke_fires_with_context() {
        let ev = TriggerEvent::new(TriggerSource::ExplicitInvoke, "What is X?", ts());
        assert!(TriggerEvaluator::new().should_fire(&ev));
    }

    #[test]
    fn failure_driven_fires_with_nonempty_context() {
        let ev = TriggerEvent::new(TriggerSource::FailureDriven, "disk full", ts());
        assert!(TriggerEvaluator::new().should_fire(&ev));
    }

    #[test]
    fn failure_driven_does_not_fire_when_context_empty() {
        let ev = TriggerEvent::new(TriggerSource::FailureDriven, "", ts());
        assert!(!TriggerEvaluator::new().should_fire(&ev));
    }

    #[test]
    fn watch_fires_with_nonempty_context() {
        let ev = TriggerEvent::new(TriggerSource::WatchAlwaysOn, "CPU spike 95%", ts());
        assert!(TriggerEvaluator::new().should_fire(&ev));
    }

    #[test]
    fn watch_does_not_fire_when_context_empty() {
        let ev = TriggerEvent::new(TriggerSource::WatchAlwaysOn, "", ts());
        assert!(!TriggerEvaluator::new().should_fire(&ev));
    }

    #[test]
    fn trigger_source_labels_are_unique() {
        let labels = [
            TriggerSource::FailureDriven.label(),
            TriggerSource::ExplicitInvoke.label(),
            TriggerSource::WatchAlwaysOn.label(),
        ];
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }
}

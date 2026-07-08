//! Per-step capability + Impact gating (WS16-04.9).
//!
//! Every workflow step is gated two ways before its effect runs:
//!
//! 1. **Capability** — [`GatedExecutor`] wraps any [`ActionExecutor`] and refuses
//!    (fail-closed) an action the [`ActionCapabilityGate`] does not authorize, so
//!    the inner executor's effect is never reached.
//! 2. **Impact** — [`assess_impact`] scores an action on the four mandatory
//!    Impact Dashboard axes (Privacy / Trust / Cost / Time), the same axes the
//!    NexaCore Helper surfaces (NCIP-Helper-007 §S6), so the UI can show the
//!    user what a workflow will cost before they enable it.

use crate::{engine::ActionExecutor, model::Action};

/// The four mandatory Impact Dashboard axes for a workflow action (WS16-04.9),
/// each scored 0 (none) … 100 (maximum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepImpact {
    /// Risk to user privacy (data leaving the device).
    pub privacy: u8,
    /// Effect on user trust (destructive / irreversible actions).
    pub trust: u8,
    /// Monetary/compute cost (paid services, egress).
    pub cost: u8,
    /// Time the action is expected to take.
    pub time: u8,
}

impl StepImpact {
    /// The highest score across the four axes (the headline risk).
    #[must_use]
    pub const fn max_axis(self) -> u8 {
        let a = if self.privacy > self.trust {
            self.privacy
        } else {
            self.trust
        };
        let b = if self.cost > self.time {
            self.cost
        } else {
            self.time
        };
        if a > b { a } else { b }
    }
}

/// Score an action on the four mandatory Impact axes (WS16-04.9).
///
/// A coarse, deterministic heuristic (no model needed): destructive file actions
/// score high Trust, network requests score high Privacy and Cost (data leaves
/// the device), local classification scores low across the board.
#[must_use]
pub fn assess_impact(action: &Action) -> StepImpact {
    match action {
        Action::ClassifyFile { .. } => StepImpact {
            privacy: 0,
            trust: 0,
            cost: 0,
            time: 25,
        },
        Action::LaunchApp { .. } => StepImpact {
            privacy: 0,
            trust: 25,
            cost: 0,
            time: 25,
        },
        Action::CopyFile { .. } => StepImpact {
            privacy: 0,
            trust: 25,
            cost: 0,
            time: 50, // duplicates data — takes longer than a move/launch
        },
        Action::MoveFile { .. } => StepImpact {
            privacy: 0,
            trust: 50,
            cost: 0,
            time: 25,
        },
        Action::DeleteFile { .. } => StepImpact {
            privacy: 0,
            trust: 100, // destructive / irreversible
            cost: 0,
            time: 25,
        },
        Action::NetworkRequest { .. } => StepImpact {
            privacy: 75, // data egresses the device
            trust: 25,
            cost: 75, // paid/cloud egress
            time: 50,
        },
    }
}

/// Authorizes (or refuses) workflow actions (WS16-04.9).
///
/// The production implementation verifies a capability token against the action;
/// tests use a rule-based double. Mirrors `nexacore_monitor::ActionCapability`
/// and the Helper's capability gate.
pub trait ActionCapabilityGate {
    /// Returns `true` if the holder is authorized to perform `action`.
    fn authorize(&self, action: &Action) -> bool;
}

/// Wraps an [`ActionExecutor`] so every action passes the capability gate before
/// its effect runs — fail-closed (WS16-04.9).
pub struct GatedExecutor<'a, E, G> {
    inner: &'a mut E,
    gate: &'a G,
}

impl<'a, E, G> GatedExecutor<'a, E, G> {
    /// Gate `inner` behind `gate`.
    pub fn new(inner: &'a mut E, gate: &'a G) -> Self {
        Self { inner, gate }
    }
}

impl<E: ActionExecutor, G: ActionCapabilityGate> ActionExecutor for GatedExecutor<'_, E, G> {
    fn execute(&mut self, action: &Action) -> Result<String, String> {
        if !self.gate.authorize(action) {
            // Fail-closed: the inner effect is never attempted.
            return Err(format!(
                "capability denied for action: {}",
                action_kind(action)
            ));
        }
        self.inner.execute(action)
    }
}

/// A short kind label for an action (for gate-denial messages).
fn action_kind(action: &Action) -> &'static str {
    match action {
        Action::LaunchApp { .. } => "launch-app",
        Action::ClassifyFile { .. } => "classify-file",
        Action::MoveFile { .. } => "move-file",
        Action::CopyFile { .. } => "copy-file",
        Action::DeleteFile { .. } => "delete-file",
        Action::NetworkRequest { .. } => "network-request",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    struct AllowExceptDelete;
    impl ActionCapabilityGate for AllowExceptDelete {
        fn authorize(&self, action: &Action) -> bool {
            !matches!(action, Action::DeleteFile { .. })
        }
    }

    #[derive(Default)]
    struct Recorder {
        ran: Vec<Action>,
    }
    impl ActionExecutor for Recorder {
        fn execute(&mut self, action: &Action) -> Result<String, String> {
            self.ran.push(action.clone());
            Ok("done".to_string())
        }
    }

    #[test]
    fn impact_flags_delete_as_high_trust_and_network_as_high_privacy() {
        let del = assess_impact(&Action::DeleteFile { path: "/x".into() });
        assert_eq!(del.trust, 100);
        assert_eq!(del.max_axis(), 100);
        let net = assess_impact(&Action::NetworkRequest {
            url: "https://x".into(),
            method: "POST".into(),
        });
        assert!(net.privacy >= 75 && net.cost >= 75);
        let classify = assess_impact(&Action::ClassifyFile { path: "/x".into() });
        assert_eq!(classify.max_axis(), 25);
    }

    #[test]
    fn gate_blocks_unauthorized_action_fail_closed() {
        let mut inner = Recorder::default();
        let gate = AllowExceptDelete;
        let mut gated = GatedExecutor::new(&mut inner, &gate);
        let err = gated
            .execute(&Action::DeleteFile { path: "/x".into() })
            .unwrap_err();
        assert!(err.contains("capability denied"));
        // Fail-closed: the inner effect never ran.
        assert!(inner.ran.is_empty());
    }

    #[test]
    fn gate_allows_authorized_action() {
        let mut inner = Recorder::default();
        let gate = AllowExceptDelete;
        let mut gated = GatedExecutor::new(&mut inner, &gate);
        gated
            .execute(&Action::ClassifyFile { path: "/x".into() })
            .expect("authorized");
        assert_eq!(inner.ran.len(), 1);
    }
}

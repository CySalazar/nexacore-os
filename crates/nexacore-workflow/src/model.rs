//! The declarative workflow model (WS16-04.1).
//!
//! A [`Workflow`] is `trigger → steps`, where each [`Step`] carries one
//! [`Action`]. The model is the *declaration* of an automation; running it is
//! the execution engine (WS16-04.2). It derives `serde` so a workflow can be
//! authored as config-as-code (WS16-04.8) or generated from natural language
//! (WS16-04.7), and [`Workflow::canonical_bytes`] gives a deterministic
//! encoding for storage and comparison.

use serde::{Deserialize, Serialize};

/// What causes a [`Workflow`] to run (WS16-04.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trigger {
    /// Run only when explicitly invoked by the user.
    Manual,
    /// Run when a file appears in `directory` (a file watch).
    FileCreated {
        /// The watched directory.
        directory: String,
    },
    /// Run on a named system event (e.g. `network.online`, `power.low`).
    SystemEvent {
        /// The event identifier.
        event: String,
    },
    /// Run on a fixed schedule, every `every_seconds` seconds.
    Schedule {
        /// The interval in seconds (must be non-zero).
        every_seconds: u64,
    },
}

/// A single action a step performs (WS16-04.4/.5/.6).
///
/// Network actions are capability-bound at execution time (WS16-04.6/.9); the
/// model just records the intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Launch an application with arguments (WS16-04.4).
    LaunchApp {
        /// The application identifier.
        app: String,
        /// Command-line arguments.
        args: Vec<String>,
    },
    /// Classify a file (e.g. by content/type) without moving it (WS16-04.5).
    ClassifyFile {
        /// The file to classify.
        path: String,
    },
    /// Move a file from `from` to `to` (WS16-04.5).
    MoveFile {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
    },
    /// Copy a file from `from` to `to` (WS16-04.5).
    CopyFile {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
    },
    /// Delete a file (WS16-04.5).
    DeleteFile {
        /// The file to delete.
        path: String,
    },
    /// Make a capability-bound network request (WS16-04.6).
    NetworkRequest {
        /// The target URL.
        url: String,
        /// The HTTP method (e.g. `GET`, `POST`).
        method: String,
    },
}

impl Action {
    /// Whether every required field of the action is non-empty.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match self {
            Self::LaunchApp { app, .. } => !app.is_empty(),
            Self::ClassifyFile { path } | Self::DeleteFile { path } => !path.is_empty(),
            Self::MoveFile { from, to } | Self::CopyFile { from, to } => {
                !from.is_empty() && !to.is_empty()
            }
            Self::NetworkRequest { url, method } => !url.is_empty() && !method.is_empty(),
        }
    }
}

/// One step of a workflow: a human-readable description plus the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// A short description of what this step does.
    pub description: String,
    /// The action performed.
    pub action: Action,
}

impl Step {
    /// Create a step.
    #[must_use]
    pub fn new(description: impl Into<String>, action: Action) -> Self {
        Self {
            description: description.into(),
            action,
        }
    }
}

/// Why a [`Workflow`] is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkflowError {
    /// The workflow name is empty.
    #[error("workflow name is empty")]
    EmptyName,
    /// The workflow has no steps.
    #[error("workflow has no steps")]
    NoSteps,
    /// A `Schedule` trigger had a zero interval.
    #[error("schedule trigger interval is zero")]
    ZeroSchedule,
    /// The step at `index` has an empty required field.
    #[error("step {index} is malformed (an empty required field)")]
    MalformedStep {
        /// The index of the offending step.
        index: usize,
    },
    /// Canonical encoding of the workflow failed.
    #[error("workflow canonical encoding failed")]
    Encode,
    /// Canonical decoding of a stored workflow failed (WS16-04.8).
    #[error("workflow canonical decoding failed")]
    Decode,
}

/// A declarative automation: a trigger and the steps it runs (WS16-04.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workflow {
    /// A human-readable name (unique per user, by convention).
    pub name: String,
    /// What causes the workflow to run.
    pub trigger: Trigger,
    /// The ordered steps to run.
    pub steps: Vec<Step>,
    /// Whether the workflow is currently enabled.
    pub enabled: bool,
}

impl Workflow {
    /// A new enabled workflow.
    #[must_use]
    pub fn new(name: impl Into<String>, trigger: Trigger, steps: Vec<Step>) -> Self {
        Self {
            name: name.into(),
            trigger,
            steps,
            enabled: true,
        }
    }

    /// Validate the workflow's structure.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowError::EmptyName`] for an empty name,
    /// [`WorkflowError::NoSteps`] if there are no steps,
    /// [`WorkflowError::ZeroSchedule`] for a zero-interval schedule trigger, or
    /// [`WorkflowError::MalformedStep`] for the first step with an empty
    /// required field.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if self.name.is_empty() {
            return Err(WorkflowError::EmptyName);
        }
        if matches!(self.trigger, Trigger::Schedule { every_seconds: 0 }) {
            return Err(WorkflowError::ZeroSchedule);
        }
        if self.steps.is_empty() {
            return Err(WorkflowError::NoSteps);
        }
        for (index, step) in self.steps.iter().enumerate() {
            if !step.action.is_well_formed() {
                return Err(WorkflowError::MalformedStep { index });
            }
        }
        Ok(())
    }

    /// A deterministic encoding of the workflow (for storage / comparison),
    /// via the workspace canonical encoder.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowError::Encode`] if canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WorkflowError> {
        nexacore_types::wire::encode_canonical(self).map_err(|_| WorkflowError::Encode)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn inbox_workflow() -> Workflow {
        Workflow::new(
            "tidy-inbox",
            Trigger::FileCreated {
                directory: "/Inbox".to_owned(),
            },
            vec![
                Step::new(
                    "classify the new file",
                    Action::ClassifyFile {
                        path: "/Inbox/*".to_owned(),
                    },
                ),
                Step::new(
                    "move it to Documents",
                    Action::MoveFile {
                        from: "/Inbox/*".to_owned(),
                        to: "/Documents/".to_owned(),
                    },
                ),
            ],
        )
    }

    #[test]
    fn a_well_formed_workflow_validates() {
        let wf = inbox_workflow();
        assert_eq!(wf.validate(), Ok(()));
        assert!(wf.enabled);
        assert_eq!(wf.steps.len(), 2);
    }

    #[test]
    fn empty_name_is_rejected() {
        let mut wf = inbox_workflow();
        wf.name = String::new();
        assert_eq!(wf.validate(), Err(WorkflowError::EmptyName));
    }

    #[test]
    fn no_steps_is_rejected() {
        let wf = Workflow::new("noop", Trigger::Manual, Vec::new());
        assert_eq!(wf.validate(), Err(WorkflowError::NoSteps));
    }

    #[test]
    fn zero_interval_schedule_is_rejected() {
        let wf = Workflow::new(
            "tick",
            Trigger::Schedule { every_seconds: 0 },
            vec![Step::new(
                "ping",
                Action::LaunchApp {
                    app: "pinger".to_owned(),
                    args: Vec::new(),
                },
            )],
        );
        assert_eq!(wf.validate(), Err(WorkflowError::ZeroSchedule));
    }

    #[test]
    fn malformed_step_is_rejected_with_its_index() {
        let wf = Workflow::new(
            "bad",
            Trigger::Manual,
            vec![
                Step::new(
                    "ok",
                    Action::DeleteFile {
                        path: "/tmp/x".to_owned(),
                    },
                ),
                Step::new(
                    "empty path",
                    Action::DeleteFile {
                        path: String::new(),
                    },
                ),
            ],
        );
        assert_eq!(
            wf.validate(),
            Err(WorkflowError::MalformedStep { index: 1 })
        );
    }

    #[test]
    fn action_well_formedness_covers_every_variant() {
        assert!(
            Action::LaunchApp {
                app: "a".to_owned(),
                args: Vec::new()
            }
            .is_well_formed()
        );
        assert!(
            !Action::LaunchApp {
                app: String::new(),
                args: Vec::new()
            }
            .is_well_formed()
        );
        assert!(
            Action::CopyFile {
                from: "a".to_owned(),
                to: "b".to_owned()
            }
            .is_well_formed()
        );
        assert!(
            !Action::CopyFile {
                from: "a".to_owned(),
                to: String::new()
            }
            .is_well_formed()
        );
        assert!(
            Action::NetworkRequest {
                url: "https://x".to_owned(),
                method: "GET".to_owned()
            }
            .is_well_formed()
        );
        assert!(
            !Action::NetworkRequest {
                url: String::new(),
                method: "GET".to_owned()
            }
            .is_well_formed()
        );
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let wf = inbox_workflow();
        let bytes = wf.canonical_bytes().expect("encode");
        let decoded: Workflow = nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, wf);
        assert_eq!(decoded.validate(), Ok(()));
    }
}

//! Local-first workflow execution engine (WS16-04.2) with per-step action
//! logging (WS16-04.10).
//!
//! [`WorkflowEngine::run`] validates a [`Workflow`] and
//! runs its steps in order, delegating each [`Action`] to an [`ActionExecutor`].
//! The side effects (launching apps, moving files, network requests) live behind
//! that trait, so the engine is fully testable with a mock and the concrete
//! executors (WS16-04.4/.5/.6) — and the capability/Impact gate (WS16-04.9) —
//! plug in without changing the engine. Every step's outcome is recorded in an
//! [`ExecutionReport`], which is the executed-action log (WS16-04.10).

use crate::model::{Action, Workflow, WorkflowError};

/// Performs the side effect of a single [`Action`].
///
/// `execute` returns `Ok(detail)` with a human-readable note on success, or
/// `Err(reason)` describing why the action failed. Concrete implementations
/// (app/file/network executors, the capability gate) live in later sub-tasks.
pub trait ActionExecutor {
    /// Perform `action`, returning a success detail or a failure reason.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the action could not be performed.
    fn execute(&mut self, action: &Action) -> Result<String, String>;
}

/// The result of running one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepResult {
    /// The action succeeded, with a human-readable detail.
    Ok(String),
    /// The action failed, with a reason.
    Failed(String),
    /// The step was not attempted (a prior step failed under fail-fast).
    Skipped,
}

/// The recorded outcome of one workflow step (WS16-04.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcome {
    /// The step's description.
    pub description: String,
    /// The action that was (or would have been) performed.
    pub action: Action,
    /// What happened.
    pub result: StepResult,
}

/// The log of a workflow run: every step's outcome (WS16-04.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// The workflow name.
    pub workflow: String,
    /// Per-step outcomes, in execution order.
    pub outcomes: Vec<StepOutcome>,
    /// Whether every step succeeded.
    pub completed: bool,
}

impl ExecutionReport {
    /// The first failed step, if any.
    #[must_use]
    pub fn first_failure(&self) -> Option<&StepOutcome> {
        self.outcomes
            .iter()
            .find(|o| matches!(o.result, StepResult::Failed(_)))
    }

    /// The number of steps that succeeded.
    #[must_use]
    pub fn succeeded(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.result, StepResult::Ok(_)))
            .count()
    }
}

/// The local-first workflow execution engine (WS16-04.2).
#[derive(Debug, Clone, Copy)]
pub struct WorkflowEngine {
    /// If `true` (the default), a failed step skips the rest of the workflow;
    /// if `false`, remaining steps still run.
    pub fail_fast: bool,
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self { fail_fast: true }
    }
}

impl WorkflowEngine {
    /// An engine with the default (fail-fast) policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An engine with an explicit fail-fast policy.
    #[must_use]
    pub const fn with_fail_fast(fail_fast: bool) -> Self {
        Self { fail_fast }
    }

    /// Validate and run `workflow`, delegating each action to `executor` and
    /// recording every step's outcome.
    ///
    /// # Errors
    ///
    /// Returns the [`WorkflowError`] from [`Workflow::validate`](crate::model::Workflow::validate)
    /// if the workflow is malformed; a malformed workflow is never run.
    pub fn run<E: ActionExecutor>(
        self,
        workflow: &Workflow,
        executor: &mut E,
    ) -> Result<ExecutionReport, WorkflowError> {
        workflow.validate()?;
        let mut outcomes = Vec::with_capacity(workflow.steps.len());
        let mut failed = false;
        for step in &workflow.steps {
            let result = if failed && self.fail_fast {
                StepResult::Skipped
            } else {
                match executor.execute(&step.action) {
                    Ok(detail) => StepResult::Ok(detail),
                    Err(reason) => {
                        failed = true;
                        StepResult::Failed(reason)
                    }
                }
            };
            outcomes.push(StepOutcome {
                description: step.description.clone(),
                action: step.action.clone(),
                result,
            });
        }
        Ok(ExecutionReport {
            workflow: workflow.name.clone(),
            outcomes,
            completed: !failed,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use crate::model::{Step, Trigger};

    /// Records every action it is asked to execute, and optionally fails on the
    /// action at a chosen call index.
    struct Recorder {
        seen: Vec<Action>,
        fail_on: Option<usize>,
    }

    impl Recorder {
        fn new(fail_on: Option<usize>) -> Self {
            Self {
                seen: Vec::new(),
                fail_on,
            }
        }
    }

    impl ActionExecutor for Recorder {
        fn execute(&mut self, action: &Action) -> Result<String, String> {
            let index = self.seen.len();
            self.seen.push(action.clone());
            if Some(index) == self.fail_on {
                Err(format!("boom at step {index}"))
            } else {
                Ok(format!("did step {index}"))
            }
        }
    }

    fn three_step_workflow() -> Workflow {
        Workflow::new(
            "demo",
            Trigger::Manual,
            vec![
                Step::new(
                    "a",
                    Action::ClassifyFile {
                        path: "/x".to_owned(),
                    },
                ),
                Step::new(
                    "b",
                    Action::DeleteFile {
                        path: "/y".to_owned(),
                    },
                ),
                Step::new(
                    "c",
                    Action::LaunchApp {
                        app: "z".to_owned(),
                        args: Vec::new(),
                    },
                ),
            ],
        )
    }

    #[test]
    fn runs_all_steps_and_logs_each_action() {
        let wf = three_step_workflow();
        let mut exec = Recorder::new(None);
        let report = WorkflowEngine::new().run(&wf, &mut exec).expect("runs");
        assert!(report.completed);
        assert_eq!(report.succeeded(), 3);
        assert_eq!(report.outcomes.len(), 3);
        // The log records each action in order (WS16-04.10).
        assert_eq!(exec.seen.len(), 3);
        assert_eq!(report.outcomes[0].action, wf.steps[0].action);
        assert_eq!(
            report.outcomes[2].result,
            StepResult::Ok("did step 2".to_owned())
        );
    }

    #[test]
    fn fail_fast_skips_remaining_steps_after_a_failure() {
        let wf = three_step_workflow();
        let mut exec = Recorder::new(Some(1)); // fail on the second step
        let report = WorkflowEngine::new().run(&wf, &mut exec).expect("runs");
        assert!(!report.completed);
        assert_eq!(
            report.outcomes[0].result,
            StepResult::Ok("did step 0".to_owned())
        );
        assert!(matches!(report.outcomes[1].result, StepResult::Failed(_)));
        assert_eq!(report.outcomes[2].result, StepResult::Skipped);
        // Only the first two steps were actually attempted.
        assert_eq!(exec.seen.len(), 2);
        assert_eq!(
            report.first_failure().map(|o| o.description.as_str()),
            Some("b")
        );
    }

    #[test]
    fn without_fail_fast_remaining_steps_still_run() {
        let wf = three_step_workflow();
        let mut exec = Recorder::new(Some(1));
        let report = WorkflowEngine::with_fail_fast(false)
            .run(&wf, &mut exec)
            .expect("runs");
        assert!(!report.completed);
        // Every step was attempted despite the failure.
        assert_eq!(exec.seen.len(), 3);
        assert_eq!(report.succeeded(), 2);
        assert!(matches!(report.outcomes[1].result, StepResult::Failed(_)));
        assert_eq!(
            report.outcomes[2].result,
            StepResult::Ok("did step 2".to_owned())
        );
    }

    #[test]
    fn a_malformed_workflow_is_never_run() {
        let wf = Workflow::new("empty", Trigger::Manual, Vec::new());
        let mut exec = Recorder::new(None);
        assert_eq!(
            WorkflowEngine::new().run(&wf, &mut exec),
            Err(WorkflowError::NoSteps)
        );
        // The executor was never invoked.
        assert!(exec.seen.is_empty());
    }
}

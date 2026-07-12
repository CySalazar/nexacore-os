//! Integrating the Helper's 30-second undo with executed workflows (WS16-04.11).
//!
//! When a workflow runs (WS16-04.2) it produces an
//! [`ExecutionReport`](nexacore_workflow::engine::ExecutionReport) — the per-step
//! log of what actually happened. This module turns that log into an undo entry
//! for the Helper's 30-second window ([`crate::guidance::undo`], WS16-01.7), so a
//! user who let an automation run can reverse it just like any other autonomous
//! action.
//!
//! Undoing a workflow means **applying the inverse of each executed step in
//! reverse order**: a `MoveFile{a→b}` is undone by `MoveFile{b→a}`, a
//! `CopyFile{a→b}` by deleting the copy at `b`. `DeleteFile`, `LaunchApp`, and
//! `NetworkRequest` have no mechanical inverse, so a workflow containing an
//! executed one of those is recorded as **not reversible** (`reversible: false`).
//! `ClassifyFile` is read-only — a no-op to undo — so it never blocks
//! reversibility. Only steps that actually ran ([`StepResult::Ok`](nexacore_workflow::engine::StepResult::Ok)) are
//! inverted; failed and skipped steps left no effect to reverse.
//!
//! The inverse is itself a [`Workflow`](nexacore_workflow::model::Workflow) whose canonical bytes become the opaque
//! pre-action snapshot the Helper's window carries; replaying it reverses the
//! original run.

use nexacore_workflow::{
    engine::{ExecutionReport, StepResult},
    model::{Action, Step, Trigger, Workflow},
};

use crate::guidance::undo::{UndoEntry, UndoWindow};

/// Whether an executed action can be mechanically reversed within the window.
///
/// `MoveFile`/`CopyFile` have an inverse; `ClassifyFile` is read-only (a no-op to
/// undo); `DeleteFile`/`LaunchApp`/`NetworkRequest` are irreversible.
#[must_use]
pub fn is_reversible(action: &Action) -> bool {
    matches!(
        action,
        Action::MoveFile { .. } | Action::CopyFile { .. } | Action::ClassifyFile { .. }
    )
}

/// The concrete inverse of a single executed action, or `None` when the action
/// has no reversing step (either irreversible, or a read-only no-op).
#[must_use]
pub fn inverse_action(action: &Action) -> Option<Action> {
    match action {
        Action::MoveFile { from, to } => Some(Action::MoveFile {
            from: to.clone(),
            to: from.clone(),
        }),
        Action::CopyFile { to, .. } => Some(Action::DeleteFile { path: to.clone() }),
        // ClassifyFile is a read-only no-op; Delete/Launch/Network are irreversible.
        _ => None,
    }
}

/// Build the inverse [`Workflow`] that undoes `report`, or `None` if the run left
/// nothing to reverse (WS16-04.11).
///
/// Successfully-executed steps are inverted in reverse order. A report with no
/// reversing steps (nothing ran, or every executed step was a read-only no-op)
/// yields `None`.
#[must_use]
pub fn inverse_workflow(report: &ExecutionReport) -> Option<Workflow> {
    let mut steps: Vec<Step> = report
        .outcomes
        .iter()
        .filter(|outcome| matches!(outcome.result, StepResult::Ok(_)))
        .filter_map(|outcome| {
            inverse_action(&outcome.action)
                .map(|action| Step::new(format!("undo: {}", outcome.description), action))
        })
        .collect();
    steps.reverse();

    if steps.is_empty() {
        return None;
    }
    Some(Workflow::new(
        format!("undo:{}", report.workflow),
        Trigger::Manual,
        steps,
    ))
}

/// A workflow run packaged for the Helper's 30-second undo window (WS16-04.11).
#[derive(Debug, Clone)]
pub struct WorkflowUndoPlan {
    /// The undo-window entry describing the run.
    pub entry: UndoEntry,
    /// The inverse workflow that reverses the run, if it is reversible.
    pub inverse: Option<Workflow>,
    /// The opaque snapshot bytes (the inverse's canonical encoding) the window
    /// carries; empty when there is nothing to reverse.
    pub snapshot: Vec<u8>,
}

/// Package an executed workflow's `report` as a [`WorkflowUndoPlan`]
/// (WS16-04.11).
///
/// `reversible` on the entry is `true` only when *every* executed step can be
/// reversed — a single irreversible executed step (a delete, an app launch, a
/// network call) marks the whole run non-reversible, even though the reversible
/// steps' inverses are still computed.
#[must_use]
pub fn plan_workflow_undo(
    report: &ExecutionReport,
    action_id: u64,
    timestamp: u64,
) -> WorkflowUndoPlan {
    let all_reversible = report
        .outcomes
        .iter()
        .filter(|outcome| matches!(outcome.result, StepResult::Ok(_)))
        .all(|outcome| is_reversible(&outcome.action));

    let inverse = inverse_workflow(report);
    let snapshot = inverse
        .as_ref()
        .and_then(|workflow| workflow.canonical_bytes().ok())
        .unwrap_or_default();

    let entry = UndoEntry::new(
        action_id,
        format!("ran workflow '{}'", report.workflow),
        timestamp,
        all_reversible,
    );

    WorkflowUndoPlan {
        entry,
        inverse,
        snapshot,
    }
}

/// Record an executed workflow into the Helper's undo window (WS16-04.11).
///
/// Returns `true` if the run was fully reversible. The inverse workflow's
/// canonical bytes are stored as the entry's pre-action snapshot, so the Helper
/// can replay them to undo the run within the 30-second window.
pub fn record_workflow_undo(
    window: &mut UndoWindow,
    report: &ExecutionReport,
    action_id: u64,
    timestamp: u64,
) -> bool {
    let plan = plan_workflow_undo(report, action_id, timestamp);
    let reversible = plan.entry.reversible;
    window.record_with_snapshot(plan.entry, plan.snapshot);
    reversible
}

#[cfg(test)]
mod tests {
    use nexacore_workflow::engine::{StepOutcome, StepResult};

    use super::*;

    fn ok(description: &str, action: Action) -> StepOutcome {
        StepOutcome {
            description: description.to_owned(),
            action,
            result: StepResult::Ok("done".to_owned()),
        }
    }

    fn report(outcomes: Vec<StepOutcome>) -> ExecutionReport {
        let completed = outcomes
            .iter()
            .all(|o| matches!(o.result, StepResult::Ok(_)));
        ExecutionReport {
            workflow: "tidy-inbox".to_owned(),
            outcomes,
            completed,
        }
    }

    fn move_file(from: &str, to: &str) -> Action {
        Action::MoveFile {
            from: from.to_owned(),
            to: to.to_owned(),
        }
    }

    #[test]
    fn move_inverts_to_the_swapped_move() {
        assert_eq!(
            inverse_action(&move_file("/a", "/b")),
            Some(move_file("/b", "/a"))
        );
    }

    #[test]
    fn copy_inverts_to_deleting_the_copy() {
        let copy = Action::CopyFile {
            from: "/a".to_owned(),
            to: "/b".to_owned(),
        };
        assert_eq!(
            inverse_action(&copy),
            Some(Action::DeleteFile {
                path: "/b".to_owned()
            })
        );
    }

    #[test]
    fn irreversible_and_noop_actions_have_no_inverse() {
        assert_eq!(
            inverse_action(&Action::DeleteFile {
                path: "/x".to_owned()
            }),
            None
        );
        assert_eq!(
            inverse_action(&Action::ClassifyFile {
                path: "/x".to_owned()
            }),
            None
        );
        assert!(!is_reversible(&Action::DeleteFile {
            path: "/x".to_owned()
        }));
        assert!(is_reversible(&Action::ClassifyFile {
            path: "/x".to_owned()
        }));
    }

    #[test]
    fn inverse_workflow_reverses_executed_steps_in_reverse_order() {
        let rep = report(vec![
            ok("move a", move_file("/a", "/b")),
            ok(
                "copy c",
                Action::CopyFile {
                    from: "/c".to_owned(),
                    to: "/d".to_owned(),
                },
            ),
        ]);
        let inverse = inverse_workflow(&rep);
        assert!(inverse.is_some());
        let Some(inverse) = inverse else { return };
        // Reverse order: undo the copy (delete /d) first, then undo the move.
        assert_eq!(inverse.steps.len(), 2);
        assert_eq!(
            inverse.steps.first().map(|s| &s.action),
            Some(&Action::DeleteFile {
                path: "/d".to_owned()
            })
        );
        assert_eq!(
            inverse.steps.last().map(|s| &s.action),
            Some(&move_file("/b", "/a"))
        );
        assert_eq!(inverse.validate(), Ok(()));
    }

    #[test]
    fn only_successfully_executed_steps_are_inverted() {
        let rep = report(vec![
            ok("moved", move_file("/a", "/b")),
            StepOutcome {
                description: "failed move".to_owned(),
                action: move_file("/c", "/d"),
                result: StepResult::Failed("nope".to_owned()),
            },
            StepOutcome {
                description: "skipped".to_owned(),
                action: move_file("/e", "/f"),
                result: StepResult::Skipped,
            },
        ]);
        let inverse = inverse_workflow(&rep);
        assert!(inverse.is_some());
        let Some(inverse) = inverse else { return };
        // Only the one Ok step is inverted.
        assert_eq!(inverse.steps.len(), 1);
    }

    #[test]
    fn an_executed_delete_marks_the_run_not_reversible() {
        let rep = report(vec![
            ok("moved", move_file("/a", "/b")),
            ok(
                "deleted",
                Action::DeleteFile {
                    path: "/b".to_owned(),
                },
            ),
        ]);
        let plan = plan_workflow_undo(&rep, 1, 100);
        // The delete cannot be reversed → the whole run is not reversible…
        assert!(!plan.entry.reversible);
        // …but the reversible move's inverse is still computed.
        assert!(plan.inverse.is_some());
    }

    #[test]
    fn a_fully_reversible_run_is_marked_reversible_and_snapshotted() {
        let rep = report(vec![ok("moved", move_file("/a", "/b"))]);
        let plan = plan_workflow_undo(&rep, 7, 100);
        assert!(plan.entry.reversible);
        assert!(!plan.snapshot.is_empty()); // inverse canonical bytes are carried
    }

    #[test]
    fn recording_into_the_window_registers_the_undo_entry() {
        let rep = report(vec![ok("moved", move_file("/a", "/b"))]);
        let mut window = UndoWindow::new();
        let reversible = record_workflow_undo(&mut window, &rep, 42, 100);
        assert!(reversible);
        assert_eq!(window.len(), 1);
        assert!(window.can_undo(42));
    }
}

//! Trigger evaluation (WS16-04.3).
//!
//! A [`Trigger`] declares *when* a workflow should run; a [`TriggerEvent`] is a
//! concrete occurrence the runtime observes (a file appeared, a system event
//! fired, a schedule tick elapsed, the user invoked it). [`trigger_fires`]
//! decides whether an event satisfies a trigger — pure logic, host-testable; the
//! actual file-watch / event-bus / timer wiring is the runtime's job and feeds
//! these events in.

use crate::model::Trigger;

/// A concrete occurrence evaluated against a [`Trigger`] (WS16-04.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerEvent {
    /// The user explicitly invoked the workflow.
    Manual,
    /// A file appeared at `path` (delivered by a directory watch).
    FileCreated {
        /// The full path of the newly-created file.
        path: String,
    },
    /// A named system event fired (e.g. `network.online`).
    SystemEvent {
        /// The event identifier.
        event: String,
    },
    /// A scheduler tick reporting how many seconds have elapsed since the
    /// workflow last ran (or since it was armed).
    ScheduleTick {
        /// Seconds elapsed since the last run.
        elapsed_seconds: u64,
    },
}

/// Returns `true` if `event` satisfies `trigger` (WS16-04.3).
///
/// - `Manual` fires only on [`TriggerEvent::Manual`].
/// - `FileCreated { directory }` fires when a [`TriggerEvent::FileCreated`]
///   path is directly inside `directory`.
/// - `SystemEvent { event }` fires on an exact event-id match.
/// - `Schedule { every_seconds }` fires when a [`TriggerEvent::ScheduleTick`]'s
///   elapsed time has reached the interval (a zero interval never fires —
///   it is rejected by [`Workflow::validate`](crate::model::Workflow::validate)).
#[must_use]
pub fn trigger_fires(trigger: &Trigger, event: &TriggerEvent) -> bool {
    match (trigger, event) {
        (Trigger::Manual, TriggerEvent::Manual) => true,
        (Trigger::FileCreated { directory }, TriggerEvent::FileCreated { path }) => {
            path_is_directly_in(path, directory)
        }
        (Trigger::SystemEvent { event: want }, TriggerEvent::SystemEvent { event: got }) => {
            want == got
        }
        (Trigger::Schedule { every_seconds }, TriggerEvent::ScheduleTick { elapsed_seconds }) => {
            *every_seconds > 0 && elapsed_seconds >= every_seconds
        }
        _ => false,
    }
}

/// Whether `path` names a file directly inside `directory` (one path segment
/// below it), tolerating a trailing slash on the directory.
fn path_is_directly_in(path: &str, directory: &str) -> bool {
    let dir = directory.strip_suffix('/').unwrap_or(directory);
    let Some(rest) = path.strip_prefix(dir) else {
        return false;
    };
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    // Directly inside: non-empty and no further path separator.
    !rest.is_empty() && !rest.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_only_fires_on_manual() {
        assert!(trigger_fires(&Trigger::Manual, &TriggerEvent::Manual));
        assert!(!trigger_fires(
            &Trigger::Manual,
            &TriggerEvent::SystemEvent { event: "x".into() }
        ));
    }

    #[test]
    fn file_created_matches_files_in_directory() {
        let t = Trigger::FileCreated {
            directory: "/Inbox".into(),
        };
        assert!(trigger_fires(
            &t,
            &TriggerEvent::FileCreated {
                path: "/Inbox/report.pdf".into()
            }
        ));
        // Trailing slash on the directory is tolerated.
        let t2 = Trigger::FileCreated {
            directory: "/Inbox/".into(),
        };
        assert!(trigger_fires(
            &t2,
            &TriggerEvent::FileCreated {
                path: "/Inbox/a.txt".into()
            }
        ));
        // A nested subdirectory is NOT "directly in".
        assert!(!trigger_fires(
            &t,
            &TriggerEvent::FileCreated {
                path: "/Inbox/sub/a.txt".into()
            }
        ));
        // A different directory does not match.
        assert!(!trigger_fires(
            &t,
            &TriggerEvent::FileCreated {
                path: "/Other/a.txt".into()
            }
        ));
    }

    #[test]
    fn system_event_matches_exact_id() {
        let t = Trigger::SystemEvent {
            event: "network.online".into(),
        };
        assert!(trigger_fires(
            &t,
            &TriggerEvent::SystemEvent {
                event: "network.online".into()
            }
        ));
        assert!(!trigger_fires(
            &t,
            &TriggerEvent::SystemEvent {
                event: "network.offline".into()
            }
        ));
    }

    #[test]
    fn schedule_fires_when_interval_elapsed() {
        let t = Trigger::Schedule { every_seconds: 60 };
        assert!(!trigger_fires(
            &t,
            &TriggerEvent::ScheduleTick {
                elapsed_seconds: 59
            }
        ));
        assert!(trigger_fires(
            &t,
            &TriggerEvent::ScheduleTick {
                elapsed_seconds: 60
            }
        ));
        assert!(trigger_fires(
            &t,
            &TriggerEvent::ScheduleTick {
                elapsed_seconds: 120
            }
        ));
    }

    #[test]
    fn mismatched_trigger_event_pairs_do_not_fire() {
        assert!(!trigger_fires(
            &Trigger::Manual,
            &TriggerEvent::ScheduleTick { elapsed_seconds: 9 }
        ));
    }
}

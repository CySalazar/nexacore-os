//! Integration tests for the container lifecycle state machine.
//!
//! These tests exercise the state machine end-to-end through the
//! public API of [`nexacore_container::lifecycle`] and the engine stub.
//! They are the spiritual counterpart to the in-crate unit tests but
//! live in `tests/` so that they only see the public surface — any
//! change that breaks the public state-machine API breaks these
//! tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    // Same workspace-bug carve-out as `src/lib.rs`. Drop when the
    // upstream clippy lint stops false-positiving on the workspace
    // `clippy.toml` `=` banner.
    clippy::literal_string_with_formatting_args
)]

use nexacore_container::lifecycle::{ContainerLifecycleState, TransitionError};

/// Walk a representative happy-path lifecycle:
/// Pending → Provisioning → Running → Suspended → Snapshotted →
///   (restored) Running → Suspended → Terminating → Terminated.
#[test]
fn full_happy_path_lifecycle_walk() {
    let mut state = ContainerLifecycleState::Pending;
    for next in [
        ContainerLifecycleState::Provisioning,
        ContainerLifecycleState::Running,
        ContainerLifecycleState::Suspended,
        ContainerLifecycleState::Snapshotted,
        ContainerLifecycleState::Running,
        ContainerLifecycleState::Suspended,
        ContainerLifecycleState::Terminating,
        ContainerLifecycleState::Terminated,
    ] {
        state = state
            .try_transition(next)
            .unwrap_or_else(|e| panic!("expected {state:?} → {next:?} to be allowed: {e:?}"));
        assert_eq!(state, next);
    }
    assert!(state.is_terminal());
}

/// Pending can short-circuit straight to Terminating if the spec is
/// rejected after the container has been registered but before
/// provisioning starts. Per NCIP-Container-006 § 5.
#[test]
fn pending_can_short_circuit_to_terminating() {
    let s = ContainerLifecycleState::Pending
        .try_transition(ContainerLifecycleState::Terminating)
        .expect("pending → terminating");
    let t = s
        .try_transition(ContainerLifecycleState::Terminated)
        .expect("terminating → terminated");
    assert_eq!(t, ContainerLifecycleState::Terminated);
}

/// A container in Provisioning can be aborted directly to
/// Terminating (e.g., image fetch failed after the lifecycle entry was
/// created).
#[test]
fn provisioning_can_abort_to_terminating() {
    let s = ContainerLifecycleState::Provisioning
        .try_transition(ContainerLifecycleState::Terminating)
        .expect("provisioning → terminating");
    assert_eq!(s, ContainerLifecycleState::Terminating);
}

/// Negative case: cannot skip Provisioning.
#[test]
fn cannot_skip_provisioning() {
    assert!(matches!(
        ContainerLifecycleState::Pending.try_transition(ContainerLifecycleState::Running),
        Err(TransitionError::Invalid { .. })
    ));
}

/// Negative case: Terminated is a hard sink — no state can be reached
/// from it.
#[test]
fn terminated_blocks_every_outgoing_transition() {
    for next in [
        ContainerLifecycleState::Pending,
        ContainerLifecycleState::Provisioning,
        ContainerLifecycleState::Running,
        ContainerLifecycleState::Suspended,
        ContainerLifecycleState::Snapshotted,
        ContainerLifecycleState::Terminating,
    ] {
        let err = ContainerLifecycleState::Terminated
            .try_transition(next)
            .expect_err("terminal");
        assert!(matches!(err, TransitionError::Invalid { .. }));
    }
}

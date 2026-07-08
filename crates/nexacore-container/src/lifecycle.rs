//! Container lifecycle state machine.
//!
//! See `NCIP-Container-006` § 5 ("Lifecycle states"). The state machine
//! has seven states arranged in a directed graph (not a strict linear
//! progression):
//!
//! ```text
//! Pending → Provisioning → Running ⇄ Suspended → Snapshotted
//!                            ↓          ↓                ↓
//!                       Terminating  Terminating    Terminating
//!                            ↓          ↓                ↓
//!                        Terminated ← Terminated ← Terminated
//! ```
//!
//! The machine is enforced by [`ContainerLifecycleState::try_transition`],
//! which returns [`TransitionError`] for any invalid edge. The engine's
//! `provision` / `run` / `suspend` / `resume` / `snapshot` / `terminate`
//! methods route their state changes through this function so that
//! state-machine soundness is checked in one place.

/// All possible lifecycle states for an `NexaCoreContainer`.
///
/// The discriminants are explicit and stable so the type can be sent
/// across the management REST API and audit logs without
/// representation drift. Reordering or renaming variants is a
/// breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ContainerLifecycleState {
    /// Just created. `nexacore-container run` accepted the spec but image
    /// cache lookup / capability validation has not yet started.
    Pending = 0,
    /// Image is staged on disk and capabilities are validated; the
    /// hypervisor is preparing the VM.
    Provisioning = 1,
    /// The guest is executing user code.
    Running = 2,
    /// The VM is paused (`VMPAUSE` on TDX, equivalent on SEV-SNP /
    /// KVM); memory remains in place; no CPU is consumed.
    Suspended = 3,
    /// Full state captured to disk (memory + disk + vCPU state),
    /// sealed under the host's `SealPolicy { tee_family,
    /// current_measurement }` per `nexacore_tee::SealedBlob`.
    Snapshotted = 4,
    /// Resources are being released. Best-effort cleanup is performed
    /// regardless of any earlier error.
    Terminating = 5,
    /// Terminal state. Audit log retains the lifecycle history; the
    /// snapshot may be retained or discarded per host policy.
    Terminated = 6,
}

impl ContainerLifecycleState {
    /// Returns `true` for terminal states from which no transition is
    /// permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminated)
    }

    /// Returns `true` for states where the guest's vCPUs are
    /// actively scheduled.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Validate a proposed transition `self → next`. Returns
    /// `Ok(next)` if the edge is permitted by `NCIP-Container-006`
    /// § 5, [`TransitionError`] otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::Invalid`] if no edge from `self` to
    /// `next` exists in the state diagram.
    pub const fn try_transition(self, next: Self) -> Result<Self, TransitionError> {
        // The match below is the canonical transition table from
        // `NCIP-Container-006` § 5. We deliberately group edges by
        // **destination** so the table reads "what states can reach
        // `next`": this is what an auditor checking the NCIP looks
        // for, and the grouping mirrors the engine's per-method
        // surface (`run` reaches `Running`, `suspend` reaches
        // `Suspended`, `terminate` reaches `Terminating`, etc.).
        //
        // Adding or removing an edge is a normative change requiring
        // an amendment to NCIP-Container-006 § 5.
        let ok = matches!(
            (self, next),
            (Self::Pending, Self::Provisioning)
                | (
                    Self::Provisioning | Self::Suspended | Self::Snapshotted,
                    Self::Running,
                )
                | (Self::Running, Self::Suspended)
                | (Self::Suspended, Self::Snapshotted)
                | (
                    Self::Pending
                        | Self::Provisioning
                        | Self::Running
                        | Self::Suspended
                        | Self::Snapshotted,
                    Self::Terminating,
                )
                | (Self::Terminating, Self::Terminated)
        );
        if ok {
            Ok(next)
        } else {
            Err(TransitionError::Invalid {
                from: self,
                to: next,
            })
        }
    }

    /// Render the state name as a static slug suitable for tracing /
    /// audit logs. The returned string is `&'static str` and never
    /// contains runtime data.
    #[must_use]
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Provisioning => "provisioning",
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Snapshotted => "snapshotted",
            Self::Terminating => "terminating",
            Self::Terminated => "terminated",
        }
    }
}

/// State-machine transition error.
///
/// Implements `From<TransitionError> for ContainerError` via the
/// `#[from]` attribute on
/// [`ContainerError::Lifecycle`](crate::ContainerError::Lifecycle), so
/// engine methods can use `?` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// The requested transition is not in the state diagram.
    #[error("invalid transition {from:?} → {to:?}")]
    Invalid {
        /// Current state at the time of the call.
        from: ContainerLifecycleState,
        /// Requested next state.
        to: ContainerLifecycleState,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pending_to_provisioning_allowed() {
        assert_eq!(
            ContainerLifecycleState::Pending.try_transition(ContainerLifecycleState::Provisioning),
            Ok(ContainerLifecycleState::Provisioning)
        );
    }

    #[test]
    fn provisioning_to_running_allowed() {
        assert_eq!(
            ContainerLifecycleState::Provisioning.try_transition(ContainerLifecycleState::Running),
            Ok(ContainerLifecycleState::Running)
        );
    }

    #[test]
    fn running_to_suspended_and_back_allowed() {
        let s = ContainerLifecycleState::Running
            .try_transition(ContainerLifecycleState::Suspended)
            .expect("running → suspended");
        assert_eq!(s, ContainerLifecycleState::Suspended);
        let r = s
            .try_transition(ContainerLifecycleState::Running)
            .expect("suspended → running");
        assert_eq!(r, ContainerLifecycleState::Running);
    }

    #[test]
    fn suspended_to_snapshotted_allowed() {
        assert_eq!(
            ContainerLifecycleState::Suspended.try_transition(ContainerLifecycleState::Snapshotted),
            Ok(ContainerLifecycleState::Snapshotted)
        );
    }

    #[test]
    fn snapshotted_resume_to_running_allowed() {
        assert_eq!(
            ContainerLifecycleState::Snapshotted.try_transition(ContainerLifecycleState::Running),
            Ok(ContainerLifecycleState::Running)
        );
    }

    #[test]
    fn terminating_only_to_terminated() {
        assert_eq!(
            ContainerLifecycleState::Terminating
                .try_transition(ContainerLifecycleState::Terminated),
            Ok(ContainerLifecycleState::Terminated)
        );
        let err = ContainerLifecycleState::Terminating
            .try_transition(ContainerLifecycleState::Running)
            .expect_err("must reject");
        assert!(matches!(err, TransitionError::Invalid { .. }));
    }

    #[test]
    fn terminated_is_terminal_and_blocks_all_transitions() {
        assert!(ContainerLifecycleState::Terminated.is_terminal());
        for s in [
            ContainerLifecycleState::Pending,
            ContainerLifecycleState::Provisioning,
            ContainerLifecycleState::Running,
            ContainerLifecycleState::Suspended,
            ContainerLifecycleState::Snapshotted,
            ContainerLifecycleState::Terminating,
            ContainerLifecycleState::Terminated,
        ] {
            let err = ContainerLifecycleState::Terminated
                .try_transition(s)
                .expect_err("terminal");
            assert!(matches!(err, TransitionError::Invalid { .. }));
        }
    }

    #[test]
    fn pending_cannot_jump_to_running_directly() {
        // Must go via Provisioning per NCIP-Container-006 § 5.
        let err = ContainerLifecycleState::Pending
            .try_transition(ContainerLifecycleState::Running)
            .expect_err("must reject");
        assert!(matches!(err, TransitionError::Invalid { .. }));
    }

    #[test]
    fn running_cannot_snapshot_directly() {
        // Must Suspended → Snapshotted per NCIP-Container-006 § 5.
        let err = ContainerLifecycleState::Running
            .try_transition(ContainerLifecycleState::Snapshotted)
            .expect_err("must reject");
        assert!(matches!(err, TransitionError::Invalid { .. }));
    }

    #[test]
    fn snapshotted_cannot_directly_suspend() {
        // Snapshotted is restored to Running (or terminated); resuming
        // a stored snapshot brings it back to Running first.
        let err = ContainerLifecycleState::Snapshotted
            .try_transition(ContainerLifecycleState::Suspended)
            .expect_err("must reject");
        assert!(matches!(err, TransitionError::Invalid { .. }));
    }

    #[test]
    fn is_active_only_for_running() {
        assert!(ContainerLifecycleState::Running.is_active());
        for s in [
            ContainerLifecycleState::Pending,
            ContainerLifecycleState::Provisioning,
            ContainerLifecycleState::Suspended,
            ContainerLifecycleState::Snapshotted,
            ContainerLifecycleState::Terminating,
            ContainerLifecycleState::Terminated,
        ] {
            assert!(!s.is_active(), "{s:?} should not be active");
        }
    }

    #[test]
    fn as_slug_is_static_and_kebab_case() {
        // The slug is `&'static str`; it ends up in audit logs and
        // tracing fields. We assert it is non-empty for every state.
        for s in [
            ContainerLifecycleState::Pending,
            ContainerLifecycleState::Provisioning,
            ContainerLifecycleState::Running,
            ContainerLifecycleState::Suspended,
            ContainerLifecycleState::Snapshotted,
            ContainerLifecycleState::Terminating,
            ContainerLifecycleState::Terminated,
        ] {
            assert!(!s.as_slug().is_empty());
            assert!(
                s.as_slug().chars().all(|c| c.is_ascii_lowercase()),
                "slug must be lowercase: {}",
                s.as_slug()
            );
        }
    }
}

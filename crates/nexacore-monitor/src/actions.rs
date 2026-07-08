//! Capability-gated process actions: kill and renice (WS8-05.5/.6).
//!
//! Mutating another process is privileged, so every action is checked against
//! an [`ActionCapability`] **before** any kernel effect is attempted: if the
//! capability does not authorize the action for the target pid, the action is
//! refused and the [`ProcessController`] is never touched. On hardware the
//! capability seam wraps a real `CapabilityToken` and the controller wraps the
//! kill/renice syscalls; host tests use in-memory doubles, so the gate logic is
//! verified without the kernel.

/// A privileged action against a target process (WS8-05.5/.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAction {
    /// Terminate the process.
    Kill,
    /// Change the process's scheduling niceness.
    Renice {
        /// Requested niceness (`-20`..=`19`, Linux convention).
        nice: i8,
    },
}

/// The capability gate: decides whether a caller may perform `action` on `pid`
/// (WS8-05.5/.6).
///
/// The production impl checks a held `CapabilityToken`; host tests use a fixed
/// allow/deny double.
pub trait ActionCapability {
    /// Whether the caller is authorized to perform `action` on `pid`.
    fn allows(&self, action: ProcessAction, pid: u64) -> bool;
}

/// The kernel effect seam: performs the actual kill/renice (WS8-05.5/.6).
pub trait ProcessController {
    /// Terminate `pid`.
    ///
    /// # Errors
    /// Returns [`ControlError::Kernel`] / [`ControlError::NotFound`] on failure.
    fn kill(&mut self, pid: u64) -> Result<(), ControlError>;

    /// Set `pid`'s niceness to `nice`.
    ///
    /// # Errors
    /// Returns [`ControlError::Kernel`] / [`ControlError::NotFound`] on failure.
    fn renice(&mut self, pid: u64, nice: i8) -> Result<(), ControlError>;
}

/// Why a process action failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// The capability did not authorize the action (gate refusal — no effect
    /// was attempted).
    Denied,
    /// The requested niceness was outside the valid `-20`..=`19` range.
    InvalidNice,
    /// The target process does not exist.
    NotFound,
    /// The kernel effect failed; carries a static reason.
    Kernel(&'static str),
}

/// Lowest valid niceness (highest priority), Linux convention.
pub const NICE_MIN: i8 = -20;
/// Highest valid niceness (lowest priority), Linux convention.
pub const NICE_MAX: i8 = 19;

/// Drives capability-gated kill/renice against a [`ProcessController`]
/// (WS8-05.5/.6).
pub struct ProcessActions<C: ProcessController, A: ActionCapability> {
    /// The kernel effect seam.
    controller: C,
    /// The capability gate.
    capability: A,
}

impl<C: ProcessController, A: ActionCapability> ProcessActions<C, A> {
    /// A new action driver over `controller`, gated by `capability`.
    pub const fn new(controller: C, capability: A) -> Self {
        Self {
            controller,
            capability,
        }
    }

    /// Kill `pid`, gated by the capability (WS8-05.5).
    ///
    /// # Errors
    /// - [`ControlError::Denied`] if the capability refuses (no effect tried).
    /// - the controller's error otherwise.
    pub fn kill(&mut self, pid: u64) -> Result<(), ControlError> {
        if !self.capability.allows(ProcessAction::Kill, pid) {
            return Err(ControlError::Denied);
        }
        self.controller.kill(pid)
    }

    /// Renice `pid` to `nice`, gated by the capability (WS8-05.6).
    ///
    /// # Errors
    /// - [`ControlError::InvalidNice`] if `nice` is out of range.
    /// - [`ControlError::Denied`] if the capability refuses (no effect tried).
    /// - the controller's error otherwise.
    pub fn renice(&mut self, pid: u64, nice: i8) -> Result<(), ControlError> {
        if !(NICE_MIN..=NICE_MAX).contains(&nice) {
            return Err(ControlError::InvalidNice);
        }
        if !self.capability.allows(ProcessAction::Renice { nice }, pid) {
            return Err(ControlError::Denied);
        }
        self.controller.renice(pid, nice)
    }

    /// Borrow the underlying controller (e.g. to inspect recorded effects).
    pub const fn controller(&self) -> &C {
        &self.controller
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// Records the effects it is asked to perform.
    #[derive(Default)]
    struct RecordingController {
        killed: Vec<u64>,
        reniced: Vec<(u64, i8)>,
    }
    impl ProcessController for RecordingController {
        fn kill(&mut self, pid: u64) -> Result<(), ControlError> {
            self.killed.push(pid);
            Ok(())
        }
        fn renice(&mut self, pid: u64, nice: i8) -> Result<(), ControlError> {
            self.reniced.push((pid, nice));
            Ok(())
        }
    }

    /// Allows or denies every action uniformly.
    struct FixedCap(bool);
    impl ActionCapability for FixedCap {
        fn allows(&self, _action: ProcessAction, _pid: u64) -> bool {
            self.0
        }
    }

    #[test]
    fn authorized_kill_reaches_the_controller() {
        let mut a = ProcessActions::new(RecordingController::default(), FixedCap(true));
        assert_eq!(a.kill(42), Ok(()));
        assert_eq!(a.controller().killed, [42]);
    }

    #[test]
    fn denied_kill_is_refused_without_effect() {
        let mut a = ProcessActions::new(RecordingController::default(), FixedCap(false));
        assert_eq!(a.kill(42), Err(ControlError::Denied));
        // The controller must NOT have been invoked.
        assert!(a.controller().killed.is_empty());
    }

    #[test]
    fn authorized_renice_reaches_the_controller() {
        let mut a = ProcessActions::new(RecordingController::default(), FixedCap(true));
        assert_eq!(a.renice(7, -5), Ok(()));
        assert_eq!(a.controller().reniced, [(7, -5)]);
    }

    #[test]
    fn denied_renice_is_refused_without_effect() {
        let mut a = ProcessActions::new(RecordingController::default(), FixedCap(false));
        assert_eq!(a.renice(7, 5), Err(ControlError::Denied));
        assert!(a.controller().reniced.is_empty());
    }

    #[test]
    fn out_of_range_nice_is_rejected_before_the_gate() {
        // Even with an allowing capability, an invalid niceness is rejected and
        // never reaches the controller.
        let mut a = ProcessActions::new(RecordingController::default(), FixedCap(true));
        assert_eq!(a.renice(7, 100), Err(ControlError::InvalidNice));
        assert_eq!(a.renice(7, -100), Err(ControlError::InvalidNice));
        assert!(a.controller().reniced.is_empty());
        // The boundary values are valid.
        assert_eq!(a.renice(7, NICE_MIN), Ok(()));
        assert_eq!(a.renice(7, NICE_MAX), Ok(()));
    }

    #[test]
    fn capability_can_discriminate_by_action_and_pid() {
        /// Allows kill of pid 1 only; denies everything else.
        struct OnlyKillOne;
        impl ActionCapability for OnlyKillOne {
            fn allows(&self, action: ProcessAction, pid: u64) -> bool {
                matches!(action, ProcessAction::Kill) && pid == 1
            }
        }
        let mut a = ProcessActions::new(RecordingController::default(), OnlyKillOne);
        assert_eq!(a.kill(1), Ok(()));
        assert_eq!(a.kill(2), Err(ControlError::Denied));
        assert_eq!(a.renice(1, 0), Err(ControlError::Denied));
        assert_eq!(a.controller().killed, [1]);
    }
}

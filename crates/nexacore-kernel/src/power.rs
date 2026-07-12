//! Device power-management suspend/resume callback framework (WS12-06.4).
//!
//! System suspend (S3-class) and resume are *ordered* device operations: every
//! driver that holds live hardware state must quiesce it before the platform
//! powers down, and restore it on the way back up. Linux models this with the
//! `dev_pm_ops` `.suspend`/`.resume` callbacks driven over the device tree; this
//! module is the `core + alloc` analogue.
//!
//! The design is a small three-part model, host-testable without any live
//! hardware:
//!
//! 1. **Callback** — the [`PowerCallback`] (a.k.a. [`SuspendResume`]) trait a
//!    driver implements: [`suspend`](PowerCallback::suspend) quiesces the device,
//!    [`resume`](PowerCallback::resume) restores it.
//! 2. **Registry** — [`PowerManager`] keeps the registered devices in a
//!    deterministic **registration order**, which fixes the suspend order (and
//!    thus the reverse resume order).
//! 3. **Orchestrator** — [`PowerManager::suspend_all`] calls `suspend()` on every
//!    device in order; [`PowerManager::resume_all`] calls `resume()` in **reverse**
//!    order (device-PM semantics: last suspended is first resumed). A `suspend()`
//!    failure mid-way **rolls back** — the already-suspended prefix is resumed and
//!    the system is left in the resumed state — and the failing device is
//!    reported. Double-suspend and resume-without-suspend are guarded.
//!
//! The effect boundary is the trait itself: the bare-metal kernel registers real
//! drivers; host tests register recording doubles.

use alloc::{boxed::Box, vec::Vec};

/// Error from a device power-management transition (WS12-06.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmError {
    /// A device callback rejected the transition — the value a
    /// [`PowerCallback`] returns to signal its own hardware fault.
    DeviceFault,
    /// [`PowerManager::suspend_all`] was called while already suspended.
    AlreadySuspended,
    /// [`PowerManager::resume_all`] was called while not suspended.
    NotSuspended,
    /// A device's `suspend()` failed during [`PowerManager::suspend_all`]; the
    /// already-suspended prefix was rolled back (resumed) and the system left
    /// resumed. Carries the registration index of the device that failed.
    SuspendFailed {
        /// Registration index of the device whose `suspend()` failed.
        index: usize,
    },
    /// A device's `resume()` failed during [`PowerManager::resume_all`]. Carries
    /// the registration index of the device that failed.
    ResumeFailed {
        /// Registration index of the device whose `resume()` failed.
        index: usize,
    },
}

/// A driver's power-management callback (WS12-06.4).
///
/// Implemented by any device that holds live hardware state across a system
/// suspend. Registered with a [`PowerManager`], which drives
/// [`suspend`](Self::suspend) / [`resume`](Self::resume) in the correct order.
pub trait PowerCallback {
    /// Quiesce the device ahead of platform power-down.
    ///
    /// # Errors
    ///
    /// Returns [`PmError`] (typically [`PmError::DeviceFault`]) if the device
    /// cannot be suspended; the orchestrator then rolls back.
    fn suspend(&mut self) -> Result<(), PmError>;

    /// Restore the device after platform power-up.
    ///
    /// # Errors
    ///
    /// Returns [`PmError`] if the device cannot be resumed.
    fn resume(&mut self) -> Result<(), PmError>;
}

/// Ordered registry and orchestrator of device power-management callbacks
/// (WS12-06.4).
pub struct PowerManager {
    /// Registered devices, in registration order (fixes suspend order).
    devices: Vec<Box<dyn PowerCallback>>,
    /// Whether the whole set is currently suspended.
    suspended: bool,
}

impl PowerManager {
    /// An empty manager with no registered devices (system resumed).
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            suspended: false,
        }
    }

    /// Register a device, returning its registration index.
    ///
    /// The index fixes this device's position in the suspend order (and thus
    /// the reverse resume order). Registration is only permitted while resumed.
    ///
    /// # Errors
    ///
    /// Returns [`PmError::AlreadySuspended`] if the system is currently
    /// suspended (registering into a suspended set would leave the new device in
    /// an inconsistent, un-suspended state).
    pub fn register(&mut self, device: Box<dyn PowerCallback>) -> Result<usize, PmError> {
        if self.suspended {
            return Err(PmError::AlreadySuspended);
        }
        let index = self.devices.len();
        self.devices.push(device);
        Ok(index)
    }

    /// Whether the set is currently suspended.
    #[must_use]
    pub const fn is_suspended(&self) -> bool {
        self.suspended
    }

    /// Number of registered devices.
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether no devices are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Suspend every registered device in registration order (WS12-06.4).
    ///
    /// On the first device whose `suspend()` fails, the already-suspended prefix
    /// is rolled back — resumed in reverse order — so the system is left fully
    /// resumed, and the failing device's index is reported.
    ///
    /// # Errors
    ///
    /// - [`PmError::AlreadySuspended`] if the set is already suspended (no-op).
    /// - [`PmError::SuspendFailed`] if a device's `suspend()` fails; the prefix
    ///   is rolled back and the system left resumed.
    pub fn suspend_all(&mut self) -> Result<(), PmError> {
        if self.suspended {
            return Err(PmError::AlreadySuspended);
        }
        let mut failed_at = None;
        for (index, device) in self.devices.iter_mut().enumerate() {
            if device.suspend().is_err() {
                failed_at = Some(index);
                break;
            }
        }
        if let Some(index) = failed_at {
            // Roll back the already-suspended prefix [0, index) in reverse.
            for device in self.devices.iter_mut().take(index).rev() {
                let _ = device.resume();
            }
            // System is left resumed.
            return Err(PmError::SuspendFailed { index });
        }
        self.suspended = true;
        Ok(())
    }

    /// Resume every registered device in **reverse** registration order
    /// (WS12-06.4): the last device suspended is the first resumed.
    ///
    /// # Errors
    ///
    /// - [`PmError::NotSuspended`] if the set is not currently suspended (no-op).
    /// - [`PmError::ResumeFailed`] if a device's `resume()` fails; the remaining
    ///   devices are still resumed and the set is left in the resumed state.
    pub fn resume_all(&mut self) -> Result<(), PmError> {
        if !self.suspended {
            return Err(PmError::NotSuspended);
        }
        let last = self.devices.len().saturating_sub(1);
        let mut outcome = Ok(());
        for (offset, device) in self.devices.iter_mut().rev().enumerate() {
            if device.resume().is_err() && outcome.is_ok() {
                // Record the first failure but keep resuming the rest so no
                // device is left stranded in the suspended state. `offset` counts
                // from the last device (reverse order); map it back to the
                // registration index.
                outcome = Err(PmError::ResumeFailed {
                    index: last - offset,
                });
            }
        }
        self.suspended = false;
        outcome
    }
}

impl Default for PowerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;

    use super::*;

    /// A power-management operation recorded by a [`RecordingDevice`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Suspend,
        Resume,
    }

    /// Shared, ordered log of `(device id, op)` across all doubles.
    type Log = Rc<RefCell<Vec<(u32, Op)>>>;

    /// A recording host double: logs every suspend/resume call in global order,
    /// optionally failing its `suspend()` to exercise rollback.
    struct RecordingDevice {
        id: u32,
        log: Log,
        fail_suspend: bool,
    }

    impl RecordingDevice {
        fn device(id: u32, log: &Log) -> Box<dyn PowerCallback> {
            Box::new(Self {
                id,
                log: Rc::clone(log),
                fail_suspend: false,
            })
        }

        fn failing(id: u32, log: &Log) -> Box<dyn PowerCallback> {
            Box::new(Self {
                id,
                log: Rc::clone(log),
                fail_suspend: true,
            })
        }
    }

    impl PowerCallback for RecordingDevice {
        fn suspend(&mut self) -> Result<(), PmError> {
            self.log.borrow_mut().push((self.id, Op::Suspend));
            if self.fail_suspend {
                Err(PmError::DeviceFault)
            } else {
                Ok(())
            }
        }

        fn resume(&mut self) -> Result<(), PmError> {
            self.log.borrow_mut().push((self.id, Op::Resume));
            Ok(())
        }
    }

    fn new_log() -> Log {
        Rc::new(RefCell::new(Vec::new()))
    }

    #[test]
    fn suspend_calls_all_in_registration_order() {
        let log = new_log();
        let mut pm = PowerManager::new();
        pm.register(RecordingDevice::device(1, &log)).unwrap();
        pm.register(RecordingDevice::device(2, &log)).unwrap();
        pm.register(RecordingDevice::device(3, &log)).unwrap();

        pm.suspend_all().unwrap();

        assert_eq!(
            *log.borrow(),
            vec![(1, Op::Suspend), (2, Op::Suspend), (3, Op::Suspend)]
        );
        assert!(pm.is_suspended());
    }

    #[test]
    fn resume_calls_all_in_reverse_order() {
        let log = new_log();
        let mut pm = PowerManager::new();
        pm.register(RecordingDevice::device(1, &log)).unwrap();
        pm.register(RecordingDevice::device(2, &log)).unwrap();
        pm.register(RecordingDevice::device(3, &log)).unwrap();

        pm.suspend_all().unwrap();
        log.borrow_mut().clear();
        pm.resume_all().unwrap();

        assert_eq!(
            *log.borrow(),
            vec![(3, Op::Resume), (2, Op::Resume), (1, Op::Resume)]
        );
        assert!(!pm.is_suspended());
    }

    #[test]
    fn failing_suspend_rolls_back_the_prefix_and_leaves_system_resumed() {
        let log = new_log();
        let mut pm = PowerManager::new();
        pm.register(RecordingDevice::device(1, &log)).unwrap(); // index 0, ok
        pm.register(RecordingDevice::device(2, &log)).unwrap(); // index 1, ok
        pm.register(RecordingDevice::failing(3, &log)).unwrap(); // index 2, fails
        pm.register(RecordingDevice::device(4, &log)).unwrap(); // index 3, never reached

        let result = pm.suspend_all();

        assert_eq!(result, Err(PmError::SuspendFailed { index: 2 }));
        // 1,2 suspend; 3 attempts and fails; prefix [1,2] resumed in reverse.
        // Device 4 is never touched.
        assert_eq!(
            *log.borrow(),
            vec![
                (1, Op::Suspend),
                (2, Op::Suspend),
                (3, Op::Suspend),
                (2, Op::Resume),
                (1, Op::Resume),
            ]
        );
        // System left resumed after rollback.
        assert!(!pm.is_suspended());
    }

    #[test]
    fn double_suspend_is_guarded() {
        let log = new_log();
        let mut pm = PowerManager::new();
        pm.register(RecordingDevice::device(1, &log)).unwrap();

        pm.suspend_all().unwrap();
        log.borrow_mut().clear();

        // Second suspend is rejected and issues no further device calls.
        assert_eq!(pm.suspend_all(), Err(PmError::AlreadySuspended));
        assert!(log.borrow().is_empty());
        assert!(pm.is_suspended());
    }

    #[test]
    fn resume_without_suspend_is_guarded() {
        let log = new_log();
        let mut pm = PowerManager::new();
        pm.register(RecordingDevice::device(1, &log)).unwrap();

        assert_eq!(pm.resume_all(), Err(PmError::NotSuspended));
        assert!(log.borrow().is_empty());
        assert!(!pm.is_suspended());
    }

    #[test]
    fn suspend_resume_round_trip_can_repeat() {
        let log = new_log();
        let mut pm = PowerManager::new();
        pm.register(RecordingDevice::device(1, &log)).unwrap();
        pm.register(RecordingDevice::device(2, &log)).unwrap();

        pm.suspend_all().unwrap();
        pm.resume_all().unwrap();
        // A second cycle works because state returned to resumed.
        pm.suspend_all().unwrap();
        assert!(pm.is_suspended());
        pm.resume_all().unwrap();
        assert!(!pm.is_suspended());
    }

    #[test]
    fn register_while_suspended_is_rejected() {
        let log = new_log();
        let mut pm = PowerManager::new();
        pm.register(RecordingDevice::device(1, &log)).unwrap();
        pm.suspend_all().unwrap();

        assert_eq!(
            pm.register(RecordingDevice::device(2, &log)).map(|_| ()),
            Err(PmError::AlreadySuspended)
        );
        assert_eq!(pm.len(), 1);
    }
}

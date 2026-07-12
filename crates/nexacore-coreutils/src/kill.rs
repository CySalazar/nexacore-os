//! `kill` — send a signal to a pid, capability-gated (WS8-10.8).
//!
//! Signalling another process is privileged, so — mirroring the monitor's
//! `ProcessActions` (WS8-05.5) — every send is checked against a
//! [`KillCapability`] **before** any effect is attempted: if the capability does
//! not authorize the target pid, the send is refused with [`KillError::Denied`]
//! and the [`SignalController`] is never touched. On hardware the capability
//! wraps a real token and the controller wraps the kill syscall; host tests use
//! in-memory doubles, so the gate is verified without the kernel.
//!
//! ## Signals
//!
//! [`Signal::parse`] accepts a signal by number (`9`, `-9`) or by name with or
//! without the `SIG` prefix and an optional leading `-` (`TERM`, `-TERM`,
//! `SIGKILL`, `-KILL`). An unrecognised signal is fail-closed:
//! [`KillError::UnknownSignal`]. With no signal argument, `kill` sends the
//! default [`Signal::TERM`].

use crate::CoreError;

/// A POSIX-style signal, identified by its number and canonical name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal {
    /// The signal number (e.g. `9` for `KILL`).
    number: u8,
    /// The canonical short name without the `SIG` prefix (e.g. `KILL`).
    name: &'static str,
}

impl Signal {
    /// `SIGHUP` (1) — hangup.
    pub const HUP: Self = Self {
        number: 1,
        name: "HUP",
    };
    /// `SIGINT` (2) — interrupt.
    pub const INT: Self = Self {
        number: 2,
        name: "INT",
    };
    /// `SIGQUIT` (3) — quit.
    pub const QUIT: Self = Self {
        number: 3,
        name: "QUIT",
    };
    /// `SIGKILL` (9) — non-catchable termination.
    pub const KILL: Self = Self {
        number: 9,
        name: "KILL",
    };
    /// `SIGTERM` (15) — the default, catchable termination.
    pub const TERM: Self = Self {
        number: 15,
        name: "TERM",
    };
    /// `SIGSTOP` (19) — non-catchable stop.
    pub const STOP: Self = Self {
        number: 19,
        name: "STOP",
    };
    /// `SIGCONT` (18) — continue if stopped.
    pub const CONT: Self = Self {
        number: 18,
        name: "CONT",
    };
    /// `SIGUSR1` (10) — user-defined signal 1.
    pub const USR1: Self = Self {
        number: 10,
        name: "USR1",
    };
    /// `SIGUSR2` (12) — user-defined signal 2.
    pub const USR2: Self = Self {
        number: 12,
        name: "USR2",
    };

    /// Every signal this module recognises, in ascending number order.
    const KNOWN: [Self; 9] = [
        Self::HUP,
        Self::INT,
        Self::QUIT,
        Self::KILL,
        Self::USR1,
        Self::USR2,
        Self::TERM,
        Self::CONT,
        Self::STOP,
    ];

    /// This signal's number.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.number
    }

    /// This signal's canonical short name (no `SIG` prefix).
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Parse a signal token: a number (`9`, `-9`) or a name (`TERM`, `-TERM`,
    /// `SIGKILL`, `-SIGKILL`), case-insensitively.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidArgument`] if the token names no known signal.
    pub fn parse(token: &str) -> Result<Self, CoreError> {
        // Strip an optional leading `-` (as in `kill -9` / `kill -TERM`).
        let body = token.strip_prefix('-').unwrap_or(token);
        if body.is_empty() {
            return Err(CoreError::InvalidArgument);
        }
        // A purely numeric body is a signal number.
        if body.chars().all(|c| c.is_ascii_digit()) {
            let number = parse_u8(body)?;
            return Self::from_number(number).ok_or(CoreError::InvalidArgument);
        }
        // Otherwise a name, with an optional `SIG` prefix, case-insensitive.
        let upper = body.to_ascii_uppercase();
        let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
        Self::KNOWN
            .into_iter()
            .find(|s| s.name == bare)
            .ok_or(CoreError::InvalidArgument)
    }

    /// The known signal with the given number, if any.
    #[must_use]
    pub fn from_number(number: u8) -> Option<Self> {
        Self::KNOWN.into_iter().find(|s| s.number == number)
    }
}

/// Parse a decimal `u8` without the `/` operator or `.unwrap()`.
fn parse_u8(digits: &str) -> Result<u8, CoreError> {
    let mut value: u32 = 0;
    for ch in digits.chars() {
        let d = ch.to_digit(10).ok_or(CoreError::InvalidNumber)?;
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(d))
            .ok_or(CoreError::InvalidNumber)?;
        if value > u32::from(u8::MAX) {
            return Err(CoreError::InvalidNumber);
        }
    }
    u8::try_from(value).map_err(|_| CoreError::InvalidNumber)
}

/// Why a `kill` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillError {
    /// The capability refused the target (gate refusal — no effect attempted).
    Denied,
    /// The target process does not exist.
    NotFound,
    /// The signal token named no known signal.
    UnknownSignal,
    /// The kernel effect failed; carries a static reason.
    Kernel(&'static str),
}

impl core::fmt::Display for KillError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Denied => f.write_str("operation not permitted"),
            Self::NotFound => f.write_str("no such process"),
            Self::UnknownSignal => f.write_str("invalid signal specification"),
            Self::Kernel(reason) => write!(f, "kill failed: {reason}"),
        }
    }
}

/// The capability gate: decides whether the caller may signal `pid`.
///
/// The production impl checks a held capability token; host tests use a fixed
/// allow/deny double.
pub trait KillCapability {
    /// Whether the caller is authorized to signal `pid`.
    fn allows(&self, pid: u64) -> bool;
}

/// The kernel effect seam: actually delivers a signal.
pub trait SignalController {
    /// Deliver `signal` to `pid`.
    ///
    /// # Errors
    /// [`KillError::NotFound`] if `pid` does not exist, [`KillError::Kernel`] on
    /// any other kernel failure.
    fn send(&mut self, pid: u64, signal: Signal) -> Result<(), KillError>;
}

/// Drives capability-gated signal delivery against a [`SignalController`].
pub struct Kill<C: SignalController, A: KillCapability> {
    /// The kernel effect seam.
    controller: C,
    /// The capability gate.
    capability: A,
}

impl<C: SignalController, A: KillCapability> Kill<C, A> {
    /// A new `kill` driver over `controller`, gated by `capability`.
    pub const fn new(controller: C, capability: A) -> Self {
        Self {
            controller,
            capability,
        }
    }

    /// Send `signal` to `pid`, gated by the capability.
    ///
    /// The capability is checked **first**: on refusal the controller is never
    /// invoked.
    ///
    /// # Errors
    /// - [`KillError::Denied`] if the capability refuses (no effect attempted).
    /// - the controller's error otherwise.
    pub fn send(&mut self, pid: u64, signal: Signal) -> Result<(), KillError> {
        if !self.capability.allows(pid) {
            return Err(KillError::Denied);
        }
        self.controller.send(pid, signal)
    }

    /// Parse `signal_token` then send it to `pid`, gated by the capability.
    ///
    /// # Errors
    /// - [`KillError::UnknownSignal`] if the token is not a known signal.
    /// - otherwise as [`send`](Self::send).
    pub fn send_named(&mut self, pid: u64, signal_token: &str) -> Result<(), KillError> {
        let signal = Signal::parse(signal_token).map_err(|_| KillError::UnknownSignal)?;
        self.send(pid, signal)
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

    /// Records the signals it is asked to deliver; can fail a chosen pid.
    #[derive(Default)]
    struct RecordingController {
        sent: Vec<(u64, u8)>,
    }
    impl SignalController for RecordingController {
        fn send(&mut self, pid: u64, signal: Signal) -> Result<(), KillError> {
            if pid == 0 {
                return Err(KillError::NotFound);
            }
            self.sent.push((pid, signal.number()));
            Ok(())
        }
    }

    /// Allows every pid.
    struct AllowAll;
    impl KillCapability for AllowAll {
        fn allows(&self, _pid: u64) -> bool {
            true
        }
    }

    /// Denies every pid.
    struct DenyAll;
    impl KillCapability for DenyAll {
        fn allows(&self, _pid: u64) -> bool {
            false
        }
    }

    #[test]
    fn parse_by_number_with_and_without_dash() {
        assert_eq!(Signal::parse("9"), Ok(Signal::KILL));
        assert_eq!(Signal::parse("-9"), Ok(Signal::KILL));
        assert_eq!(Signal::parse("15"), Ok(Signal::TERM));
    }

    #[test]
    fn parse_by_name_variants() {
        assert_eq!(Signal::parse("TERM"), Ok(Signal::TERM));
        assert_eq!(Signal::parse("-TERM"), Ok(Signal::TERM));
        assert_eq!(Signal::parse("sigkill"), Ok(Signal::KILL));
        assert_eq!(Signal::parse("-SIGKILL"), Ok(Signal::KILL));
        assert_eq!(Signal::parse("cont"), Ok(Signal::CONT));
    }

    #[test]
    fn parse_rejects_unknown_and_empty() {
        assert_eq!(Signal::parse("BOGUS"), Err(CoreError::InvalidArgument));
        assert_eq!(Signal::parse("99"), Err(CoreError::InvalidArgument));
        assert_eq!(Signal::parse("-"), Err(CoreError::InvalidArgument));
        assert_eq!(Signal::parse("999"), Err(CoreError::InvalidNumber));
    }

    #[test]
    fn allowed_kill_reaches_controller() {
        let mut kill = Kill::new(RecordingController::default(), AllowAll);
        assert_eq!(kill.send(42, Signal::TERM), Ok(()));
        assert_eq!(kill.controller().sent, [(42, 15)]);
    }

    #[test]
    fn denied_kill_never_touches_controller() {
        let mut kill = Kill::new(RecordingController::default(), DenyAll);
        assert_eq!(kill.send(42, Signal::KILL), Err(KillError::Denied));
        // The controller recorded nothing: the effect was never attempted.
        assert!(kill.controller().sent.is_empty());
    }

    #[test]
    fn send_named_parses_then_gates() {
        let mut kill = Kill::new(RecordingController::default(), AllowAll);
        assert_eq!(kill.send_named(7, "-9"), Ok(()));
        assert_eq!(kill.controller().sent, [(7, 9)]);
        assert_eq!(kill.send_named(7, "NOPE"), Err(KillError::UnknownSignal));
    }

    #[test]
    fn unknown_signal_is_checked_before_capability() {
        // Even with a deny-all capability, an unknown signal reports the signal
        // error (parsing happens first in send_named).
        let mut kill = Kill::new(RecordingController::default(), DenyAll);
        assert_eq!(kill.send_named(1, "NOPE"), Err(KillError::UnknownSignal));
    }

    #[test]
    fn controller_error_propagates() {
        let mut kill = Kill::new(RecordingController::default(), AllowAll);
        assert_eq!(kill.send(0, Signal::TERM), Err(KillError::NotFound));
    }

    #[test]
    fn from_number_maps_known_signals() {
        assert_eq!(Signal::from_number(9), Some(Signal::KILL));
        assert_eq!(Signal::from_number(15), Some(Signal::TERM));
        assert_eq!(Signal::from_number(200), None);
    }

    #[test]
    fn error_display_is_human_readable() {
        use alloc::format;
        assert_eq!(format!("{}", KillError::Denied), "operation not permitted");
        assert_eq!(format!("{}", KillError::NotFound), "no such process");
    }
}

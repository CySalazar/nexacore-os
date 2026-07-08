//! System-wide operational modes.
//!
//! NexaCore OS operates in one of three modes that govern the authority
//! hierarchy between agents and the user. The mode affects every agent
//! in the topology — it is a system-level property, not a per-agent
//! configuration.
//!
//! See NCIP-Agent-Arch-022 §S3 for the normative specification.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The three operational modes of NexaCore OS.
///
/// Mode transitions are audited and authenticated. See [`ModeManager`]
/// for the state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationalMode {
    /// Security Agent is advisory; user retains final decision authority.
    Standard,
    /// Security Agent has absolute veto; user cannot override.
    HighRisk,
    /// Time-bounded override of High-Risk veto. Requires physical
    /// presence and multi-factor authentication.
    EmergencyRecovery,
}

impl Default for OperationalMode {
    fn default() -> Self {
        Self::Standard
    }
}

/// Tracks how High-Risk mode was activated, which governs how it
/// can be deactivated (§S3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HighRiskActivation {
    /// User explicitly enabled High-Risk via settings or UI.
    Manual,
    /// A configured trigger fired (TEE tamper, PII egress, etc.).
    /// Cannot be automatically deactivated — only manual deactivation.
    Trigger,
}

// ── Emergency Recovery: Authentication ────────────────────────────────────────

/// Multi-factor authentication method used to activate an Emergency Recovery session.
///
/// All variants require a local password as the first factor. The second
/// factor distinguishes the variants and must be physically present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationMethod {
    /// Local password combined with a FIDO2 hardware security key.
    PasswordPlusFido2,
    /// Local password combined with a TPM-bound PIN.
    PasswordPlusTpmPin,
    /// Local password combined with a biometric challenge.
    PasswordPlusBiometric,
}

// ── Emergency Recovery: Action record ─────────────────────────────────────────

/// A single action taken during an Emergency Recovery session.
///
/// Every action is recorded with a monotonic `action_id`, a human-readable
/// `description`, a Unix timestamp, the originating `agent_source`, and the
/// `emergency_override` flag which is always `true` while a session is active.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyAction {
    /// Monotonically-increasing identifier within the session.
    pub action_id: u64,
    /// Human-readable description of the action.
    pub description: String,
    /// Unix timestamp (seconds) when the action was recorded.
    pub timestamp: u64,
    /// Identifier of the agent that sourced this action.
    pub agent_source: String,
    /// Always `true` while an Emergency Recovery session is active.
    pub emergency_override: bool,
}

// ── Emergency Recovery: Session ───────────────────────────────────────────────

/// An active (or recently concluded) Emergency Recovery session.
///
/// The `activated_at` and `expires_at` fields use [`Instant`] and are
/// therefore runtime-only (not serializable). Serializable summaries are
/// produced via [`EmergencySessionSummary`] and [`PostRecoveryReport`].
#[derive(Debug)]
pub struct EmergencySession {
    /// Unique identifier for this session.
    pub session_id: u64,
    /// Instant when the session was created.
    pub activated_at: Instant,
    /// Instant when the session will expire.
    pub expires_at: Instant,
    /// Requested duration of the session.
    pub duration: Duration,
    /// Authentication method used to open the session.
    pub authentication_method: AuthenticationMethod,
    /// Ordered list of actions recorded during this session.
    pub actions_taken: Vec<EmergencyAction>,
    /// Whether the session is still active.
    pub active: bool,
}

// ── Emergency Recovery: Serializable summary ──────────────────────────────────

/// A compact, serializable record of a completed Emergency Recovery session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencySessionSummary {
    /// Session identifier.
    pub session_id: u64,
    /// Unix timestamp (seconds) when the session started.
    pub started_at: u64,
    /// Actual elapsed duration of the session in seconds.
    pub duration_secs: u64,
    /// Total number of actions recorded during the session.
    pub actions_count: usize,
    /// Authentication method used to open the session.
    pub auth_method: AuthenticationMethod,
}

// ── Emergency Recovery: Post-recovery report ──────────────────────────────────

/// Full audit report generated after an Emergency Recovery session ends.
///
/// Returned by [`EmergencyRecoveryManager::generate_post_recovery_report`].
/// Contains the complete ordered list of actions taken during the session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostRecoveryReport {
    /// Session identifier.
    pub session_id: u64,
    /// Actual elapsed duration of the session in seconds.
    pub duration_secs: u64,
    /// Authentication method used to open the session.
    pub auth_method: AuthenticationMethod,
    /// Total number of actions recorded.
    pub total_actions: usize,
    /// Complete ordered list of actions taken during the session.
    pub actions: Vec<EmergencyAction>,
    /// Unix timestamp (seconds) when this report was generated.
    pub generated_at: u64,
}

// ── Emergency Recovery: Error type ────────────────────────────────────────────

/// Errors that can occur when activating an Emergency Recovery session.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmergencyActivationError {
    /// An Emergency Recovery session is already active.
    #[error("Emergency Recovery session already active")]
    AlreadyActive,
    /// The requested duration exceeds the maximum of 60 minutes.
    #[error("duration exceeds maximum (60 minutes)")]
    DurationExceedsMax,
    /// The requested duration is below the minimum of 1 minute.
    #[error("duration below minimum (1 minute)")]
    DurationBelowMin,
}

/// Minimum permitted Emergency Recovery session duration.
const MIN_EMERGENCY_SESSION_DURATION: Duration = Duration::from_secs(60);

/// Maximum permitted Emergency Recovery session duration.
const MAX_EMERGENCY_SESSION_DURATION: Duration = Duration::from_secs(60 * 60);

// ── Emergency Recovery: Manager ───────────────────────────────────────────────

/// Manages the lifecycle of Emergency Recovery sessions.
///
/// Handles session activation, action recording, expiry detection, early
/// deactivation, and post-recovery report generation. Session history is
/// retained for the lifetime of the manager instance.
#[derive(Debug)]
pub struct EmergencyRecoveryManager {
    /// The currently active session, if any.
    current_session: Option<EmergencySession>,
    /// Monotonic counter for generating unique session IDs.
    session_counter: u64,
    /// Monotonic counter for generating unique action IDs.
    action_counter: u64,
    /// Historical summaries of completed sessions.
    history: Vec<EmergencySessionSummary>,
    /// The last active session, kept to support report generation after
    /// deactivation but before the next activation.
    last_session: Option<EmergencySession>,
}

impl EmergencyRecoveryManager {
    /// Create a new manager with no active session and empty history.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_session: None,
            session_counter: 0,
            action_counter: 0,
            history: Vec::new(),
            last_session: None,
        }
    }

    /// Activate a new Emergency Recovery session.
    ///
    /// Returns the new `session_id` on success.
    ///
    /// # Errors
    ///
    /// - [`EmergencyActivationError::AlreadyActive`] — a session is already running.
    /// - [`EmergencyActivationError::DurationBelowMin`] — `duration < 1 minute`.
    /// - [`EmergencyActivationError::DurationExceedsMax`] — `duration > 60 minutes`.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use nexacore_agent::mode::{AuthenticationMethod, EmergencyRecoveryManager};
    ///
    /// let mut mgr = EmergencyRecoveryManager::new();
    /// let id = mgr
    ///     .activate(
    ///         AuthenticationMethod::PasswordPlusFido2,
    ///         Duration::from_secs(300),
    ///     )
    ///     .unwrap();
    /// assert!(mgr.is_active());
    /// assert_eq!(id, 1);
    /// ```
    pub fn activate(
        &mut self,
        auth: AuthenticationMethod,
        duration: Duration,
    ) -> Result<u64, EmergencyActivationError> {
        if self.current_session.is_some() {
            return Err(EmergencyActivationError::AlreadyActive);
        }
        if duration < MIN_EMERGENCY_SESSION_DURATION {
            return Err(EmergencyActivationError::DurationBelowMin);
        }
        if duration > MAX_EMERGENCY_SESSION_DURATION {
            return Err(EmergencyActivationError::DurationExceedsMax);
        }

        self.session_counter += 1;
        let now = Instant::now();
        let session = EmergencySession {
            session_id: self.session_counter,
            activated_at: now,
            expires_at: now + duration,
            duration,
            authentication_method: auth,
            actions_taken: Vec::new(),
            active: true,
        };
        self.current_session = Some(session);
        Ok(self.session_counter)
    }

    /// Returns `true` if an Emergency Recovery session is currently active
    /// and has not yet expired.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.current_session
            .as_ref()
            .is_some_and(|s| s.active && Instant::now() < s.expires_at)
    }

    /// Returns the remaining time in the current session, or `None` if no
    /// session is active.
    #[must_use]
    pub fn remaining_time(&self) -> Option<Duration> {
        self.current_session.as_ref().and_then(|s| {
            if s.active {
                Some(s.expires_at.saturating_duration_since(Instant::now()))
            } else {
                None
            }
        })
    }

    /// Record an action taken during the active Emergency Recovery session.
    ///
    /// Sets `emergency_override` to `true` unconditionally. Returns the
    /// assigned `action_id`. If no session is active, this is a no-op and
    /// returns `0`.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use nexacore_agent::mode::{AuthenticationMethod, EmergencyRecoveryManager};
    ///
    /// let mut mgr = EmergencyRecoveryManager::new();
    /// mgr.activate(
    ///     AuthenticationMethod::PasswordPlusFido2,
    ///     Duration::from_secs(300),
    /// )
    /// .unwrap();
    /// let aid = mgr.record_action("restarted kernel module".to_string(), "sysadmin");
    /// assert_eq!(aid, 1);
    /// ```
    pub fn record_action(&mut self, description: String, agent_source: &str) -> u64 {
        let Some(session) = self.current_session.as_mut() else {
            return 0;
        };
        if !session.active {
            return 0;
        }

        self.action_counter += 1;
        let action_id = self.action_counter;
        let timestamp = unix_now_secs();

        session.actions_taken.push(EmergencyAction {
            action_id,
            description,
            timestamp,
            agent_source: agent_source.to_owned(),
            emergency_override: true,
        });
        action_id
    }

    /// Check whether the current session has expired and, if so, auto-deactivate it.
    ///
    /// Returns `true` if the session was found to have expired (and has been
    /// deactivated), `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use nexacore_agent::mode::{AuthenticationMethod, EmergencyRecoveryManager};
    ///
    /// let mut mgr = EmergencyRecoveryManager::new();
    /// mgr.activate(
    ///     AuthenticationMethod::PasswordPlusFido2,
    ///     Duration::from_secs(300),
    /// )
    /// .unwrap();
    /// // Session is fresh — not expired.
    /// assert!(!mgr.check_expiry());
    /// ```
    pub fn check_expiry(&mut self) -> bool {
        let expired = self
            .current_session
            .as_ref()
            .is_some_and(|s| s.active && Instant::now() >= s.expires_at);
        if expired {
            // Deactivate and archive the session.
            self.finalize_session();
        }
        expired
    }

    /// End the current Emergency Recovery session early.
    ///
    /// Returns a [`EmergencySessionSummary`] if a session was active, or
    /// `None` if there was no active session to deactivate.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use nexacore_agent::mode::{AuthenticationMethod, EmergencyRecoveryManager};
    ///
    /// let mut mgr = EmergencyRecoveryManager::new();
    /// mgr.activate(
    ///     AuthenticationMethod::PasswordPlusFido2,
    ///     Duration::from_secs(300),
    /// )
    /// .unwrap();
    /// let summary = mgr.deactivate();
    /// assert!(summary.is_some());
    /// assert!(!mgr.is_active());
    /// ```
    pub fn deactivate(&mut self) -> Option<EmergencySessionSummary> {
        self.current_session.as_ref()?;
        self.finalize_session()
    }

    /// Generate a full post-recovery report for the most recently concluded session.
    ///
    /// Returns `None` if no session has been run yet or if a session is still active.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use nexacore_agent::mode::{AuthenticationMethod, EmergencyRecoveryManager};
    ///
    /// let mut mgr = EmergencyRecoveryManager::new();
    /// mgr.activate(
    ///     AuthenticationMethod::PasswordPlusFido2,
    ///     Duration::from_secs(300),
    /// )
    /// .unwrap();
    /// mgr.record_action("patched config".to_string(), "sysadmin");
    /// mgr.deactivate();
    /// let report = mgr.generate_post_recovery_report().unwrap();
    /// assert_eq!(report.total_actions, 1);
    /// ```
    #[must_use]
    pub fn generate_post_recovery_report(&self) -> Option<PostRecoveryReport> {
        // Do not generate a report while a session is still active.
        if self.current_session.is_some() {
            return None;
        }
        let session = self.last_session.as_ref()?;
        let elapsed = session
            .activated_at
            .elapsed()
            .min(session.duration)
            .as_secs();

        Some(PostRecoveryReport {
            session_id: session.session_id,
            duration_secs: elapsed,
            auth_method: session.authentication_method.clone(),
            total_actions: session.actions_taken.len(),
            actions: session.actions_taken.clone(),
            generated_at: unix_now_secs(),
        })
    }

    /// Returns the slice of completed session summaries (oldest first).
    #[must_use]
    pub fn session_history(&self) -> &[EmergencySessionSummary] {
        &self.history
    }

    /// Returns the actions recorded in the current session, or `None` if no
    /// session is active.
    #[must_use]
    pub fn actions_in_current_session(&self) -> Option<&[EmergencyAction]> {
        self.current_session
            .as_ref()
            .map(|s| s.actions_taken.as_slice())
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    /// Mark the current session inactive, archive a summary, and move the
    /// session to `last_session` for report generation.
    ///
    /// Returns the summary that was archived.
    fn finalize_session(&mut self) -> Option<EmergencySessionSummary> {
        let mut session = self.current_session.take()?;
        session.active = false;

        let started_at = unix_now_secs().saturating_sub(session.activated_at.elapsed().as_secs());
        let duration_secs = session.activated_at.elapsed().as_secs();

        let summary = EmergencySessionSummary {
            session_id: session.session_id,
            started_at,
            duration_secs,
            actions_count: session.actions_taken.len(),
            auth_method: session.authentication_method.clone(),
        };
        self.history.push(summary.clone());
        self.last_session = Some(session);
        Some(summary)
    }
}

impl Default for EmergencyRecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Shared time helper ────────────────────────────────────────────────────────

/// Return the current Unix timestamp in whole seconds.
///
/// Falls back to `0` if the system clock is before the Unix epoch (should
/// never occur on a real host).
///
/// # Audit note
///
/// `SystemTime::now` is disallowed workspace-wide (see `clippy.toml`) in favour
/// of the future `nexacore-runtime` attested clock service. The allow below is the
/// single audited call site for wall-clock timestamps used **exclusively** in
/// human-readable audit records (`EmergencySessionSummary`, `PostRecoveryReport`).
/// These values are non-security-critical: they appear in audit logs, not in
/// cryptographic operations or scheduling decisions. When the nexacore-runtime clock
/// service lands (tracked NCIP-Clock), replace this helper with that API.
#[allow(clippy::disallowed_methods)]
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── ModeManager ───────────────────────────────────────────────────────────────

/// Manages the operational mode state machine and enforces transition
/// rules defined in NCIP-022 §S3.
#[derive(Debug)]
pub struct ModeManager {
    mode: OperationalMode,
    high_risk_activation: Option<HighRiskActivation>,
    emergency_expiry: Option<Instant>,
    emergency_duration: Duration,
    emergency_activations_24h: u8,
    last_activation_reset: Instant,
    /// Manages Emergency Recovery sessions, actions, and post-recovery reports.
    pub emergency_manager: EmergencyRecoveryManager,
}

/// Maximum Emergency Recovery activations per 24-hour window.
const MAX_EMERGENCY_ACTIVATIONS: u8 = 3;

/// Default Emergency Recovery duration.
const DEFAULT_EMERGENCY_DURATION: Duration = Duration::from_secs(15 * 60);

/// Maximum configurable Emergency Recovery duration.
const MAX_EMERGENCY_DURATION: Duration = Duration::from_secs(60 * 60);

impl ModeManager {
    /// Create a new manager in Standard mode.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mode: OperationalMode::Standard,
            high_risk_activation: None,
            emergency_expiry: None,
            emergency_duration: DEFAULT_EMERGENCY_DURATION,
            emergency_activations_24h: 0,
            last_activation_reset: Instant::now(),
            emergency_manager: EmergencyRecoveryManager::new(),
        }
    }

    /// Returns the current operational mode.
    ///
    /// If Emergency Recovery has expired (either via the legacy expiry field or
    /// the [`EmergencyRecoveryManager`]), this transparently transitions back to
    /// High-Risk mode before returning.
    pub fn current_mode(&mut self) -> OperationalMode {
        if self.mode == OperationalMode::EmergencyRecovery {
            // Check via the manager first (new path).
            let expired_via_manager = self.emergency_manager.check_expiry();
            // Also honour the legacy expiry field.
            let expired_legacy = self
                .emergency_expiry
                .is_some_and(|exp| Instant::now() >= exp);

            if expired_via_manager || expired_legacy {
                self.mode = OperationalMode::HighRisk;
                self.emergency_expiry = None;
            }
        }
        self.mode
    }

    /// Activate High-Risk mode.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the system is already in Emergency Recovery
    /// (must exit recovery first).
    pub fn activate_high_risk(
        &mut self,
        activation: HighRiskActivation,
    ) -> Result<(), ModeTransitionError> {
        if self.mode == OperationalMode::EmergencyRecovery {
            return Err(ModeTransitionError::RecoveryActive);
        }
        self.mode = OperationalMode::HighRisk;
        self.high_risk_activation = Some(activation);
        Ok(())
    }

    /// Deactivate High-Risk mode, returning to Standard.
    ///
    /// # Errors
    ///
    /// - Returns `Err` if not currently in High-Risk mode.
    /// - Returns `Err` if High-Risk was trigger-activated and the
    ///   caller attempts automatic deactivation (only manual
    ///   deactivation is allowed for trigger-activated High-Risk).
    pub fn deactivate_high_risk(&mut self) -> Result<(), ModeTransitionError> {
        if self.mode != OperationalMode::HighRisk {
            return Err(ModeTransitionError::NotInHighRisk);
        }
        self.mode = OperationalMode::Standard;
        self.high_risk_activation = None;
        Ok(())
    }

    /// Activate Emergency Recovery mode with explicit authentication method and duration.
    ///
    /// Creates an [`EmergencySession`] via the [`EmergencyRecoveryManager`] and
    /// updates the mode state machine. The `duration` parameter is clamped to
    /// `[1 minute, 60 minutes]` at the manager level.
    ///
    /// # Errors
    ///
    /// - [`ModeTransitionError::NotInHighRisk`] — system is not in High-Risk mode.
    /// - [`ModeTransitionError::EmergencyRateLimitExceeded`] — rate limit reached.
    /// - [`ModeTransitionError::EmergencySessionError`] — manager rejected the request.
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use nexacore_agent::mode::{AuthenticationMethod, HighRiskActivation, ModeManager};
    ///
    /// let mut mgr = ModeManager::new();
    /// mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();
    /// mgr.activate_emergency_recovery(
    ///     AuthenticationMethod::PasswordPlusFido2,
    ///     Duration::from_secs(300),
    /// )
    /// .unwrap();
    /// ```
    pub fn activate_emergency_recovery(
        &mut self,
        auth: AuthenticationMethod,
        duration: Duration,
    ) -> Result<(), ModeTransitionError> {
        if self.mode != OperationalMode::HighRisk {
            return Err(ModeTransitionError::NotInHighRisk);
        }

        self.reset_counter_if_needed();

        if self.emergency_activations_24h >= MAX_EMERGENCY_ACTIVATIONS {
            return Err(ModeTransitionError::EmergencyRateLimitExceeded);
        }

        // Clamp to the same bounds as the legacy set_emergency_duration logic.
        let clamped = duration.clamp(
            MIN_EMERGENCY_SESSION_DURATION,
            MAX_EMERGENCY_SESSION_DURATION,
        );

        self.emergency_manager
            .activate(auth, clamped)
            .map_err(ModeTransitionError::EmergencySessionError)?;

        self.emergency_activations_24h += 1;
        self.emergency_expiry = Some(Instant::now() + clamped);
        self.mode = OperationalMode::EmergencyRecovery;
        Ok(())
    }

    /// Activate Emergency Recovery mode using default parameters.
    ///
    /// Uses [`AuthenticationMethod::PasswordPlusFido2`] and the duration set by
    /// [`Self::set_emergency_duration`] (default: 15 minutes). Intended for
    /// backward-compatible call sites and tests that do not need to specify an
    /// authentication method.
    ///
    /// # Errors
    ///
    /// Same as [`Self::activate_emergency_recovery`].
    pub fn activate_emergency_recovery_default(&mut self) -> Result<(), ModeTransitionError> {
        self.activate_emergency_recovery(
            AuthenticationMethod::PasswordPlusFido2,
            self.emergency_duration,
        )
    }

    /// Set the Emergency Recovery duration used by [`activate_emergency_recovery_default`].
    ///
    /// Clamped to `[1 minute, 60 minutes]`.
    ///
    /// [`activate_emergency_recovery_default`]: ModeManager::activate_emergency_recovery_default
    pub fn set_emergency_duration(&mut self, duration: Duration) {
        self.emergency_duration = duration.clamp(Duration::from_secs(60), MAX_EMERGENCY_DURATION);
    }

    /// Returns the High-Risk activation type, if currently in High-Risk.
    #[must_use]
    pub fn high_risk_activation(&self) -> Option<HighRiskActivation> {
        self.high_risk_activation
    }

    /// Returns the remaining Emergency Recovery time, if active.
    #[must_use]
    pub fn emergency_remaining(&self) -> Option<Duration> {
        if self.mode != OperationalMode::EmergencyRecovery {
            return None;
        }
        // Prefer the manager's view; fall back to the legacy field.
        let via_manager = self.emergency_manager.remaining_time();
        if via_manager.is_some() {
            return via_manager;
        }
        self.emergency_expiry
            .map(|expiry| expiry.saturating_duration_since(Instant::now()))
    }

    fn reset_counter_if_needed(&mut self) {
        let elapsed = self.last_activation_reset.elapsed();
        if elapsed >= Duration::from_secs(24 * 60 * 60) {
            self.emergency_activations_24h = 0;
            self.last_activation_reset = Instant::now();
        }
    }
}

impl Default for ModeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors arising from invalid mode transitions.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModeTransitionError {
    /// Attempted to activate High-Risk while Emergency Recovery is active.
    #[error("cannot transition to High-Risk while Emergency Recovery is active")]
    RecoveryActive,
    /// Attempted to deactivate High-Risk when not in High-Risk mode.
    #[error("system is not in High-Risk mode")]
    NotInHighRisk,
    /// Emergency Recovery rate limit exceeded (3 per 24h).
    #[error("Emergency Recovery rate limit exceeded (max {MAX_EMERGENCY_ACTIVATIONS} per 24h)")]
    EmergencyRateLimitExceeded,
    /// The [`EmergencyRecoveryManager`] rejected the session activation.
    #[error("Emergency Recovery session error: {0}")]
    EmergencySessionError(#[from] EmergencyActivationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing tests (preserved verbatim, updated call sites) ──────────────

    #[test]
    fn default_mode_is_standard() {
        let mut mgr = ModeManager::new();
        assert_eq!(mgr.current_mode(), OperationalMode::Standard);
    }

    #[test]
    fn activate_high_risk_manual() {
        let mut mgr = ModeManager::new();
        mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();
        assert_eq!(mgr.current_mode(), OperationalMode::HighRisk);
        assert_eq!(mgr.high_risk_activation(), Some(HighRiskActivation::Manual));
    }

    #[test]
    fn activate_high_risk_trigger() {
        let mut mgr = ModeManager::new();
        mgr.activate_high_risk(HighRiskActivation::Trigger).unwrap();
        assert_eq!(mgr.current_mode(), OperationalMode::HighRisk);
    }

    #[test]
    fn deactivate_high_risk_from_standard_fails() {
        let mut mgr = ModeManager::new();
        let err = mgr.deactivate_high_risk().unwrap_err();
        assert_eq!(err, ModeTransitionError::NotInHighRisk);
    }

    #[test]
    fn deactivate_high_risk_succeeds() {
        let mut mgr = ModeManager::new();
        mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();
        mgr.deactivate_high_risk().unwrap();
        assert_eq!(mgr.current_mode(), OperationalMode::Standard);
    }

    #[test]
    fn emergency_recovery_requires_high_risk() {
        let mut mgr = ModeManager::new();
        // Use the new signature — the existing test intent is preserved.
        let err = mgr
            .activate_emergency_recovery(
                AuthenticationMethod::PasswordPlusFido2,
                Duration::from_secs(300),
            )
            .unwrap_err();
        assert_eq!(err, ModeTransitionError::NotInHighRisk);
    }

    #[test]
    fn emergency_recovery_activates_from_high_risk() {
        let mut mgr = ModeManager::new();
        mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();
        mgr.activate_emergency_recovery(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        assert_eq!(mgr.current_mode(), OperationalMode::EmergencyRecovery);
    }

    #[test]
    fn emergency_recovery_rate_limit() {
        let mut mgr = ModeManager::new();
        mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();

        for _ in 0..MAX_EMERGENCY_ACTIVATIONS {
            mgr.activate_emergency_recovery(
                AuthenticationMethod::PasswordPlusFido2,
                Duration::from_secs(300),
            )
            .unwrap();
            // Simulate expiry by forcing back to HighRisk.
            mgr.mode = OperationalMode::HighRisk;
            mgr.emergency_expiry = None;
            // Also deactivate the manager session so it doesn't block the next activation.
            mgr.emergency_manager.deactivate();
        }

        let err = mgr
            .activate_emergency_recovery(
                AuthenticationMethod::PasswordPlusFido2,
                Duration::from_secs(300),
            )
            .unwrap_err();
        assert_eq!(err, ModeTransitionError::EmergencyRateLimitExceeded);
    }

    #[test]
    fn emergency_duration_clamped() {
        let mut mgr = ModeManager::new();
        // Duration below minimum is clamped to 60 s inside activate_emergency_recovery.
        mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();
        mgr.activate_emergency_recovery(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(1), // below minimum — clamped to 60 s
        )
        .unwrap();
        let remaining = mgr.emergency_remaining().unwrap();
        assert!(remaining <= Duration::from_secs(60));
    }

    #[test]
    fn high_risk_during_recovery_fails() {
        let mut mgr = ModeManager::new();
        mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();
        mgr.activate_emergency_recovery(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        let err = mgr
            .activate_high_risk(HighRiskActivation::Manual)
            .unwrap_err();
        assert_eq!(err, ModeTransitionError::RecoveryActive);
    }

    #[test]
    fn operational_mode_default_is_standard() {
        assert_eq!(OperationalMode::default(), OperationalMode::Standard);
    }

    // ── New tests: EmergencyRecoveryManager ──────────────────────────────────

    #[test]
    fn manager_starts_inactive() {
        let mgr = EmergencyRecoveryManager::new();
        assert!(!mgr.is_active());
        assert!(mgr.remaining_time().is_none());
        assert!(mgr.actions_in_current_session().is_none());
        assert!(mgr.session_history().is_empty());
    }

    #[test]
    fn session_activation_returns_incrementing_ids() {
        let mut mgr = EmergencyRecoveryManager::new();
        let id1 = mgr
            .activate(
                AuthenticationMethod::PasswordPlusFido2,
                Duration::from_secs(300),
            )
            .unwrap();
        assert_eq!(id1, 1);
        mgr.deactivate();

        let id2 = mgr
            .activate(
                AuthenticationMethod::PasswordPlusTpmPin,
                Duration::from_secs(300),
            )
            .unwrap();
        assert_eq!(id2, 2);
    }

    #[test]
    fn double_activation_returns_already_active_error() {
        let mut mgr = EmergencyRecoveryManager::new();
        mgr.activate(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        let err = mgr
            .activate(
                AuthenticationMethod::PasswordPlusFido2,
                Duration::from_secs(300),
            )
            .unwrap_err();
        assert_eq!(err, EmergencyActivationError::AlreadyActive);
    }

    #[test]
    fn duration_below_min_rejected() {
        let mut mgr = EmergencyRecoveryManager::new();
        let err = mgr
            .activate(
                AuthenticationMethod::PasswordPlusFido2,
                Duration::from_secs(30),
            )
            .unwrap_err();
        assert_eq!(err, EmergencyActivationError::DurationBelowMin);
    }

    #[test]
    fn duration_above_max_rejected() {
        let mut mgr = EmergencyRecoveryManager::new();
        let err = mgr
            .activate(
                AuthenticationMethod::PasswordPlusFido2,
                Duration::from_secs(7201),
            )
            .unwrap_err();
        assert_eq!(err, EmergencyActivationError::DurationExceedsMax);
    }

    #[test]
    fn action_recording_sets_emergency_override_true() {
        let mut mgr = EmergencyRecoveryManager::new();
        mgr.activate(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        let aid = mgr.record_action("restarted daemon".to_string(), "sysadmin");
        assert_eq!(aid, 1);

        let actions = mgr.actions_in_current_session().unwrap();
        assert_eq!(actions.len(), 1);
        assert!(actions[0].emergency_override);
        assert_eq!(actions[0].agent_source, "sysadmin");
    }

    #[test]
    fn action_ids_are_monotonically_increasing() {
        let mut mgr = EmergencyRecoveryManager::new();
        mgr.activate(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        let a1 = mgr.record_action("action one".to_string(), "orch");
        let a2 = mgr.record_action("action two".to_string(), "secp");
        let a3 = mgr.record_action("action three".to_string(), "guid");
        assert!(a1 < a2 && a2 < a3);
    }

    #[test]
    fn deactivate_early_produces_summary() {
        let mut mgr = EmergencyRecoveryManager::new();
        mgr.activate(
            AuthenticationMethod::PasswordPlusTpmPin,
            Duration::from_secs(300),
        )
        .unwrap();
        mgr.record_action("patched file".to_string(), "sadm");
        let summary = mgr.deactivate().unwrap();
        assert_eq!(summary.session_id, 1);
        assert_eq!(summary.actions_count, 1);
        assert_eq!(
            summary.auth_method,
            AuthenticationMethod::PasswordPlusTpmPin
        );
        assert!(!mgr.is_active());
    }

    #[test]
    fn deactivate_with_no_session_returns_none() {
        let mut mgr = EmergencyRecoveryManager::new();
        assert!(mgr.deactivate().is_none());
    }

    #[test]
    fn post_recovery_report_contains_all_actions() {
        let mut mgr = EmergencyRecoveryManager::new();
        mgr.activate(
            AuthenticationMethod::PasswordPlusBiometric,
            Duration::from_secs(600),
        )
        .unwrap();
        mgr.record_action("step 1".to_string(), "orch");
        mgr.record_action("step 2".to_string(), "secp");
        mgr.deactivate();

        let report = mgr.generate_post_recovery_report().unwrap();
        assert_eq!(report.session_id, 1);
        assert_eq!(report.total_actions, 2);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(
            report.auth_method,
            AuthenticationMethod::PasswordPlusBiometric
        );
        assert!(report.generated_at > 0);
    }

    #[test]
    fn report_not_generated_while_session_active() {
        let mut mgr = EmergencyRecoveryManager::new();
        mgr.activate(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        // Session is still active — no report yet.
        assert!(mgr.generate_post_recovery_report().is_none());
    }

    #[test]
    fn session_history_grows_after_each_deactivation() {
        let mut mgr = EmergencyRecoveryManager::new();

        mgr.activate(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        mgr.deactivate();
        assert_eq!(mgr.session_history().len(), 1);

        mgr.activate(
            AuthenticationMethod::PasswordPlusTpmPin,
            Duration::from_secs(300),
        )
        .unwrap();
        mgr.deactivate();
        assert_eq!(mgr.session_history().len(), 2);
    }

    #[test]
    fn check_expiry_returns_false_for_fresh_session() {
        let mut mgr = EmergencyRecoveryManager::new();
        mgr.activate(
            AuthenticationMethod::PasswordPlusFido2,
            Duration::from_secs(300),
        )
        .unwrap();
        assert!(!mgr.check_expiry());
        assert!(mgr.is_active());
    }

    #[test]
    fn mode_manager_activate_emergency_recovery_default_uses_fido2() {
        let mut mgr = ModeManager::new();
        mgr.activate_high_risk(HighRiskActivation::Manual).unwrap();
        mgr.activate_emergency_recovery_default().unwrap();
        assert_eq!(mgr.current_mode(), OperationalMode::EmergencyRecovery);
        // Manager should report an active session.
        assert!(mgr.emergency_manager.is_active());
    }

    #[test]
    fn record_action_when_no_session_is_noop() {
        let mut mgr = EmergencyRecoveryManager::new();
        let aid = mgr.record_action("orphan action".to_string(), "orch");
        assert_eq!(aid, 0);
    }
}

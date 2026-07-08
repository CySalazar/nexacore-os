//! Backend health tracking with anti-flap hysteresis — TASK-10 (DE-G3 + DE-G5).
//!
//! Three pieces, smallest first:
//!
//! 1. [`HealthTracker`] — a pure, clock-free state machine: one per
//!    backend, fed boolean observations (request outcomes and periodic
//!    probe results), transitioning between [`BackendHealthState::Healthy`]
//!    and [`BackendHealthState::Unhealthy`] per the counter thresholds in
//!    [`HealthPolicy`].
//! 2. [`HealthRegistry`] — the shared, thread-safe view the
//!    [`super::BackendRouter`] consults on every request. Routing reads
//!    are a lock-free [`AtomicBool`] load; state updates take a short
//!    [`parking_lot::Mutex`] over the tracker.
//! 3. [`BackendStatusSink`] — where health *transitions* go: the registry
//!    emits one [`BackendStatusEvent`] per flip (never per observation),
//!    which TASK-21's status bar consumes over IPC.
//!
//! ## Hysteresis (anti-flapping)
//!
//! Transitions are **asymmetric** by design (ADR-0031):
//!
//! - `Healthy → Unhealthy` after [`HealthPolicy::fail_threshold`]
//!   *consecutive* failures (default **1**: the first connectivity
//!   failure already cost a user-visible timeout — mark the backend down
//!   immediately so the next request goes straight to the fallback).
//! - `Unhealthy → Healthy` after [`HealthPolicy::recover_threshold`]
//!   *consecutive* successes (default **3**: a backend that flaps
//!   up/down must prove itself stable before traffic returns to it).
//!
//! An intermittent backend (ok, fail, ok, fail, …) therefore never
//! re-accumulates `recover_threshold` consecutive successes and stays
//! `Unhealthy` — requests keep flowing to the stable fallback with no
//! flip-flopping, which is exactly the acceptance criterion.
//!
//! Determinism: no clocks, no randomness — state depends only on the
//! observation sequence, so every test is reproducible.

use core::sync::atomic::{AtomicBool, Ordering};

use nexacore_types::ai::{BackendKind, BackendStatusEvent};
use parking_lot::Mutex;

// =============================================================================
// HealthPolicy
// =============================================================================

/// Hysteresis thresholds for backend health transitions.
///
/// See the module docs for the rationale behind the asymmetric defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthPolicy {
    /// Consecutive failures that flip a `Healthy` backend to `Unhealthy`.
    /// Must be ≥ 1.
    pub fail_threshold: u32,
    /// Consecutive successes that flip an `Unhealthy` backend back to
    /// `Healthy`. Must be ≥ 1.
    pub recover_threshold: u32,
}

impl Default for HealthPolicy {
    /// Fail fast (1 failure), recover deliberately (3 successes).
    fn default() -> Self {
        Self {
            fail_threshold: 1,
            recover_threshold: 3,
        }
    }
}

impl HealthPolicy {
    /// Clamp both thresholds to ≥ 1. A threshold of 0 would make a state
    /// unreachable-from or instantly-left, neither of which is a
    /// meaningful policy; clamping at construction keeps the tracker's
    /// invariants simple.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            fail_threshold: self.fail_threshold.max(1),
            recover_threshold: self.recover_threshold.max(1),
        }
    }
}

// =============================================================================
// BackendHealthState / HealthTracker
// =============================================================================

/// The two health states a backend can be in, as seen by the router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendHealthState {
    /// The backend is believed able to serve requests; the router tries
    /// it in normal policy order.
    Healthy,
    /// The backend is believed down; the router demotes it to last
    /// resort until it recovers.
    Unhealthy,
}

/// Pure hysteresis state machine for one backend. No clock, no I/O —
/// feed it observations, read back transitions.
#[derive(Clone, Debug)]
pub struct HealthTracker {
    policy: HealthPolicy,
    state: BackendHealthState,
    consecutive_failures: u32,
    consecutive_successes: u32,
}

impl HealthTracker {
    /// A tracker starting `Healthy` (optimistic: the router should try
    /// the preferred backend at least once before writing it off).
    #[must_use]
    pub fn new(policy: HealthPolicy) -> Self {
        Self {
            policy: policy.clamped(),
            state: BackendHealthState::Healthy,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> BackendHealthState {
        self.state
    }

    /// Feed one observation (`true` = the backend responded / probe
    /// succeeded; `false` = connectivity-class failure). Returns the new
    /// state **iff this observation caused a transition**, `None`
    /// otherwise.
    pub fn observe(&mut self, ok: bool) -> Option<BackendHealthState> {
        if ok {
            self.consecutive_failures = 0;
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
            if self.state == BackendHealthState::Unhealthy
                && self.consecutive_successes >= self.policy.recover_threshold
            {
                self.state = BackendHealthState::Healthy;
                return Some(self.state);
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            if self.state == BackendHealthState::Healthy
                && self.consecutive_failures >= self.policy.fail_threshold
            {
                self.state = BackendHealthState::Unhealthy;
                return Some(self.state);
            }
        }
        None
    }
}

// =============================================================================
// BackendStatusSink
// =============================================================================

/// Where backend health *transitions* are delivered.
///
/// The registry calls [`BackendStatusSink::emit`] exactly once per state
/// flip (never per observation or per request). Implementations must be
/// cheap and non-blocking — they run inline on the request path.
///
/// The shipped implementations are [`TracingStatusSink`] (logs the
/// transition; the default) and [`BufferStatusSink`] (collects events
/// in memory; for tests and for TASK-21's IPC bridge to drain).
pub trait BackendStatusSink: Send + Sync {
    /// Deliver one health-transition event.
    fn emit(&self, event: BackendStatusEvent);
}

/// `Arc<S>` forwards to `S`, so a caller can keep a handle to a sink it
/// has handed to the [`HealthRegistry`] (which boxes its sink) — e.g. a
/// test reading back a [`BufferStatusSink`], or the TASK-21 bridge
/// draining one.
impl<S: BackendStatusSink + ?Sized> BackendStatusSink for std::sync::Arc<S> {
    fn emit(&self, event: BackendStatusEvent) {
        S::emit(self, event);
    }
}

/// A [`BackendStatusSink`] that logs each transition via `tracing`.
///
/// The default sink: until the IPC event bridge lands (TASK-21), health
/// transitions are at least observable in the runtime's structured log.
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingStatusSink;

impl BackendStatusSink for TracingStatusSink {
    fn emit(&self, event: BackendStatusEvent) {
        if event.healthy {
            tracing::info!(backend = event.backend.label(), "backend recovered");
        } else {
            tracing::warn!(backend = event.backend.label(), "backend unhealthy");
        }
    }
}

/// A [`BackendStatusSink`] that buffers events in memory, in emission
/// order. Used by tests to assert transition sequences, and usable by
/// the TASK-21 IPC bridge as a drain point.
#[derive(Debug, Default)]
pub struct BufferStatusSink {
    events: Mutex<Vec<BackendStatusEvent>>,
}

impl BufferStatusSink {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the events emitted so far, in order.
    #[must_use]
    pub fn events(&self) -> Vec<BackendStatusEvent> {
        self.events.lock().clone()
    }

    /// Remove and return all buffered events, leaving the buffer empty.
    pub fn drain(&self) -> Vec<BackendStatusEvent> {
        core::mem::take(&mut *self.events.lock())
    }
}

impl BackendStatusSink for BufferStatusSink {
    fn emit(&self, event: BackendStatusEvent) {
        self.events.lock().push(event);
    }
}

// =============================================================================
// HealthRegistry
// =============================================================================

/// Per-backend health entry: the lock-free flag the router reads on
/// every request, plus the mutex-guarded tracker behind it.
#[derive(Debug)]
struct Entry {
    /// Fast-path mirror of `tracker.state()` for routing decisions.
    healthy: AtomicBool,
    /// Whether the backend serves with explicitly reduced performance
    /// (TASK-12, plan §9 honesty contract). Set once at registration
    /// via [`HealthRegistry::set_degraded`]; carried on every emitted
    /// [`BackendStatusEvent`].
    degraded: AtomicBool,
    tracker: Mutex<HealthTracker>,
}

impl Entry {
    fn new(policy: HealthPolicy) -> Self {
        Self {
            healthy: AtomicBool::new(true),
            degraded: AtomicBool::new(false),
            tracker: Mutex::new(HealthTracker::new(policy)),
        }
    }
}

/// Shared health state for both backends + the transition event sink.
///
/// Owned by the [`super::BackendRouter`]; observations come from two
/// sources feeding the same trackers (ADR-0031):
///
/// - **per-request outcomes** — a retriable provider error is failure
///   evidence, a success is recovery evidence;
/// - **periodic probes** ([`super::BackendRouter::probe_health_once`])
///   — the `health()` result of each registered provider. While a
///   backend is demoted the router stops sending it requests, so the
///   probe is the *only* recovery path — exactly the DE-G3 "health-check
///   periodico" role.
pub struct HealthRegistry {
    remote_gpu: Entry,
    local_cpu: Entry,
    sink: Box<dyn BackendStatusSink>,
}

impl core::fmt::Debug for HealthRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HealthRegistry")
            .field("remote_gpu", &self.remote_gpu)
            .field("local_cpu", &self.local_cpu)
            .finish_non_exhaustive()
    }
}

impl HealthRegistry {
    /// A registry with both backends starting `Healthy`, using `policy`
    /// for both trackers and delivering transitions to `sink`.
    #[must_use]
    pub fn new(policy: HealthPolicy, sink: Box<dyn BackendStatusSink>) -> Self {
        Self {
            remote_gpu: Entry::new(policy),
            local_cpu: Entry::new(policy),
            sink,
        }
    }

    fn entry(&self, kind: BackendKind) -> &Entry {
        match kind {
            BackendKind::RemoteGpu => &self.remote_gpu,
            BackendKind::LocalCpu => &self.local_cpu,
        }
    }

    /// Lock-free health read for routing decisions.
    #[must_use]
    pub fn is_healthy(&self, kind: BackendKind) -> bool {
        self.entry(kind).healthy.load(Ordering::Acquire)
    }

    /// Whether `kind` is flagged degraded (TASK-12, plan §9).
    #[must_use]
    pub fn is_degraded(&self, kind: BackendKind) -> bool {
        self.entry(kind).degraded.load(Ordering::Acquire)
    }

    /// Flag `kind` as serving with reduced performance. Set at backend
    /// registration (the flag is a static property of the provider, not
    /// a health observation); every subsequent [`BackendStatusEvent`]
    /// carries it.
    pub fn set_degraded(&self, kind: BackendKind, degraded: bool) {
        self.entry(kind).degraded.store(degraded, Ordering::Release);
    }

    /// Feed one observation for `kind` (`true` = success). On a state
    /// transition, updates the routing flag and emits exactly one
    /// [`BackendStatusEvent`] through the sink.
    pub fn observe(&self, kind: BackendKind, ok: bool) {
        let entry = self.entry(kind);
        // Hold the tracker lock across flag-store + emit so concurrent
        // observers OF THE SAME BACKEND cannot interleave two transitions
        // out of order (events must reflect that tracker's actual state
        // sequence; different backends have independent locks and their
        // events carry the backend id, so cross-backend ordering is
        // irrelevant).
        let mut tracker = entry.tracker.lock();
        if let Some(new_state) = tracker.observe(ok) {
            let healthy = new_state == BackendHealthState::Healthy;
            entry.healthy.store(healthy, Ordering::Release);
            self.sink.emit(BackendStatusEvent {
                backend: kind,
                healthy,
                degraded: entry.degraded.load(Ordering::Acquire),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- HealthTracker (pure state machine) -----------------------------

    #[test]
    fn default_policy_fails_fast_recovers_deliberately() {
        let p = HealthPolicy::default();
        assert_eq!(p.fail_threshold, 1);
        assert_eq!(p.recover_threshold, 3);
    }

    #[test]
    fn zero_thresholds_are_clamped_to_one() {
        let p = HealthPolicy {
            fail_threshold: 0,
            recover_threshold: 0,
        }
        .clamped();
        assert_eq!(p.fail_threshold, 1);
        assert_eq!(p.recover_threshold, 1);
    }

    #[test]
    fn first_failure_flips_to_unhealthy_with_default_policy() {
        let mut t = HealthTracker::new(HealthPolicy::default());
        assert_eq!(t.state(), BackendHealthState::Healthy);
        assert_eq!(t.observe(false), Some(BackendHealthState::Unhealthy));
        // Further failures do not re-emit a transition.
        assert_eq!(t.observe(false), None);
        assert_eq!(t.state(), BackendHealthState::Unhealthy);
    }

    #[test]
    fn recovery_requires_consecutive_successes() {
        let mut t = HealthTracker::new(HealthPolicy::default());
        t.observe(false); // -> Unhealthy
        assert_eq!(t.observe(true), None); // 1 of 3
        assert_eq!(t.observe(true), None); // 2 of 3
        assert_eq!(t.observe(true), Some(BackendHealthState::Healthy)); // 3 of 3
        assert_eq!(t.state(), BackendHealthState::Healthy);
    }

    #[test]
    fn intermittent_health_never_recovers_no_flip_flop() {
        // ok, fail, ok, fail, … — the consecutive-success counter resets
        // on every failure, so the tracker stays Unhealthy after the
        // first failure: exactly one transition total.
        let mut t = HealthTracker::new(HealthPolicy::default());
        let mut transitions = 0;
        for i in 0..20 {
            if t.observe(i % 2 == 0).is_some() {
                transitions += 1;
            }
        }
        // i=0 ok (no-op), i=1 fail -> Unhealthy; never 3 consecutive oks.
        assert_eq!(transitions, 1);
        assert_eq!(t.state(), BackendHealthState::Unhealthy);
    }

    #[test]
    fn higher_fail_threshold_tolerates_blips() {
        let mut t = HealthTracker::new(HealthPolicy {
            fail_threshold: 3,
            recover_threshold: 1,
        });
        assert_eq!(t.observe(false), None);
        assert_eq!(t.observe(false), None);
        // A success resets the failure streak.
        assert_eq!(t.observe(true), None);
        assert_eq!(t.state(), BackendHealthState::Healthy);
        // Three consecutive failures now flip it.
        t.observe(false);
        t.observe(false);
        assert_eq!(t.observe(false), Some(BackendHealthState::Unhealthy));
    }

    // ---- HealthRegistry (shared view + events) --------------------------

    #[test]
    fn registry_starts_healthy_and_emits_only_on_transitions() {
        let sink = std::sync::Arc::new(BufferStatusSink::new());
        let registry = HealthRegistry::new(HealthPolicy::default(), Box::new(sink.clone()));

        assert!(registry.is_healthy(BackendKind::RemoteGpu));
        assert!(registry.is_healthy(BackendKind::LocalCpu));

        registry.observe(BackendKind::RemoteGpu, true); // no transition
        registry.observe(BackendKind::RemoteGpu, false); // -> Unhealthy
        registry.observe(BackendKind::RemoteGpu, false); // still Unhealthy

        assert!(!registry.is_healthy(BackendKind::RemoteGpu));
        assert!(registry.is_healthy(BackendKind::LocalCpu), "independent");
        assert_eq!(
            sink.events(),
            vec![BackendStatusEvent {
                backend: BackendKind::RemoteGpu,
                healthy: false,
                degraded: false,
            }]
        );

        // Recovery emits the second (and only second) event.
        for _ in 0..3 {
            registry.observe(BackendKind::RemoteGpu, true);
        }
        assert!(registry.is_healthy(BackendKind::RemoteGpu));
        assert_eq!(sink.events().len(), 2);
        assert_eq!(
            sink.events()[1],
            BackendStatusEvent {
                backend: BackendKind::RemoteGpu,
                healthy: true,
                degraded: false,
            }
        );
    }

    #[test]
    fn buffer_sink_drain_empties_the_buffer() {
        let sink = BufferStatusSink::new();
        sink.emit(BackendStatusEvent {
            backend: BackendKind::LocalCpu,
            healthy: false,
            degraded: true,
        });
        assert_eq!(sink.drain().len(), 1);
        assert!(sink.events().is_empty());
    }
}

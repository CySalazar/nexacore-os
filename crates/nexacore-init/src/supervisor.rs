//! The PID 1 supervisor loop and its host seam (WS12-01.2, .5–.9).
//!
//! [`Supervisor`] owns the validated set of [`ServiceManifest`]s, their
//! topological start order, and the per-service runtime state. It drives every
//! process/clock effect through the [`ServiceHost`] trait, so the control logic
//! — ordered start, health checks, restart-with-backoff, socket activation,
//! capability injection, ordered shutdown — is pure and host-testable.

use alloc::{collections::BTreeMap, vec::Vec};
use core::fmt;

use crate::{
    GraphError, ManifestError, ServiceName,
    graph::DependencyGraph,
    manifest::{Capability, ServiceManifest, SocketSpec},
};

/// An opaque process identifier handed back by the host on spawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub u64);

/// Whether a spawned process is still alive, as reported by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
    /// The process is still running.
    Alive,
    /// The process has exited; `success` is its success flag (zero exit status).
    Exited {
        /// `true` on a successful (zero) exit status.
        success: bool,
    },
}

/// The result of a periodic health probe (WS12-01.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// The service reported healthy.
    Healthy,
    /// The service reported unhealthy and should be recycled.
    Unhealthy,
}

/// A signal delivered to the supervisor (WS12-01.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Graceful termination request (SIGTERM-class): ordered shutdown.
    Terminate,
    /// Interrupt request (SIGINT-class): ordered shutdown.
    Interrupt,
    /// A child changed state (SIGCHLD-class): reap and reconcile.
    ChildExited,
}

/// The request the supervisor hands the host to spawn a service.
///
/// It carries the injected [`capabilities`](Self::capabilities) (WS12-01.8) and
/// the optional socket (WS12-01.7) so the host can wire both at spawn time.
#[derive(Debug)]
pub struct SpawnRequest<'a> {
    /// The service being spawned.
    pub name: &'a ServiceName,
    /// The executable to run.
    pub exec: &'a str,
    /// Command-line arguments.
    pub args: &'a [alloc::string::String],
    /// Capabilities to inject into the new process.
    pub capabilities: &'a [Capability],
    /// The socket to pass for socket-activated services, if any.
    pub socket: Option<&'a SocketSpec>,
}

/// Error returned by the host when an effect fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpawnError(pub alloc::string::String);

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spawn failed: {}", self.0)
    }
}

/// The seam through which the supervisor performs all process/clock effects.
///
/// The production implementation is backed by `nexacore-usys` syscalls; tests
/// use an in-memory mock. Keeping every effect here makes [`Supervisor`] pure
/// logic.
pub trait ServiceHost {
    /// Returns a monotonic clock reading in milliseconds.
    fn now_ms(&self) -> u64;

    /// Spawns a service, returning its [`Pid`].
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError`] if the process could not be created.
    fn spawn(&mut self, request: &SpawnRequest<'_>) -> Result<Pid, SpawnError>;

    /// Forcibly stops a running process.
    fn kill(&mut self, pid: Pid);

    /// Cheaply reports whether a process is still alive (polled every tick).
    fn liveness(&mut self, pid: Pid) -> Liveness;

    /// Runs the (possibly expensive) health probe for a process (polled only
    /// when the service's health-check interval has elapsed).
    fn health(&mut self, pid: Pid) -> Health;

    /// Creates the listening socket for a socket-activated service.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError`] if the socket could not be created.
    fn create_socket(&mut self, name: &ServiceName, spec: &SocketSpec) -> Result<(), SpawnError>;
}

/// The lifecycle status of a supervised service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunStatus {
    /// Declared but not yet started.
    Pending,
    /// Socket created; awaiting the first connection before spawning.
    SocketArmed,
    /// Currently running.
    Running,
    /// Crashed; waiting for the backoff delay before restarting.
    Backoff,
    /// Intentionally stopped (shutdown).
    Stopped,
    /// Exited and not restarted (policy said so).
    Failed,
}

#[derive(Clone, Copy, Debug)]
struct ServiceRuntime {
    status: RunStatus,
    pid: Option<Pid>,
    restart_count: u32,
    restart_at_ms: u64,
    last_health_ms: u64,
}

impl Default for ServiceRuntime {
    fn default() -> Self {
        Self {
            status: RunStatus::Pending,
            pid: None,
            restart_count: 0,
            restart_at_ms: 0,
            last_health_ms: 0,
        }
    }
}

/// An observable action taken by the supervisor during a tick (the action log,
/// useful for journald-class logging and for tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TickEvent {
    /// A service was (re)spawned and is now running.
    Started(ServiceName),
    /// A socket was created for a socket-activated service.
    SocketArmed(ServiceName),
    /// A service process exited.
    Exited {
        /// The service that exited.
        service: ServiceName,
        /// Its success flag.
        success: bool,
    },
    /// A health probe reported the service unhealthy.
    Unhealthy(ServiceName),
    /// A restart was scheduled after a crash/unhealthy event.
    RestartScheduled {
        /// The service to be restarted.
        service: ServiceName,
        /// The earliest monotonic time (ms) the restart may happen.
        at_ms: u64,
    },
    /// A previously crashed service was restarted.
    Restarted(ServiceName),
    /// A service exited and the policy declined to restart it.
    GaveUp(ServiceName),
    /// A service was stopped during shutdown.
    Stopped(ServiceName),
    /// A (re)spawn failed at the host.
    SpawnFailed {
        /// The service whose spawn failed.
        service: ServiceName,
        /// The host error message.
        error: alloc::string::String,
    },
}

/// Error returned when constructing a [`Supervisor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisorError {
    /// A manifest failed validation.
    Manifest(ServiceName, ManifestError),
    /// The dependency graph was invalid (duplicate/unknown/cyclic).
    Graph(GraphError),
    /// A service failed to spawn during initial bring-up.
    Spawn(ServiceName, SpawnError),
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(s, e) => write!(f, "manifest {s} invalid: {e}"),
            Self::Graph(e) => write!(f, "dependency graph invalid: {e}"),
            Self::Spawn(s, e) => write!(f, "service {s} failed to start: {e}"),
        }
    }
}

/// The PID 1 supervisor (WS12-01.2).
pub struct Supervisor<H: ServiceHost> {
    manifests: BTreeMap<ServiceName, ServiceManifest>,
    order: Vec<ServiceName>,
    runtimes: BTreeMap<ServiceName, ServiceRuntime>,
    host: H,
}

impl<H: ServiceHost> Supervisor<H> {
    /// Builds a supervisor from a set of manifests, validating each manifest and
    /// computing the topological start order.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::Manifest`] on an invalid manifest, or
    /// [`SupervisorError::Graph`] if the dependency graph is duplicate, dangling
    /// or cyclic.
    pub fn new<I>(manifests: I, host: H) -> Result<Self, SupervisorError>
    where
        I: IntoIterator<Item = ServiceManifest>,
    {
        let manifests: Vec<ServiceManifest> = manifests.into_iter().collect();
        for m in &manifests {
            m.validate()
                .map_err(|e| SupervisorError::Manifest(m.name.clone(), e))?;
        }
        let graph = DependencyGraph::from_manifests(&manifests).map_err(SupervisorError::Graph)?;
        let order = graph.topological_order().map_err(SupervisorError::Graph)?;

        let mut map = BTreeMap::new();
        let mut runtimes = BTreeMap::new();
        for m in manifests {
            runtimes.insert(m.name.clone(), ServiceRuntime::default());
            map.insert(m.name.clone(), m);
        }
        Ok(Self {
            manifests: map,
            order,
            runtimes,
            host,
        })
    }

    /// The topological start order (its reverse is the shutdown order).
    #[must_use]
    pub fn start_order(&self) -> &[ServiceName] {
        &self.order
    }

    /// The current lifecycle status of a service, if known.
    #[must_use]
    pub fn status(&self, name: &ServiceName) -> Option<RunStatus> {
        self.runtimes.get(name).map(|r| r.status)
    }

    /// The number of times a service has been restarted.
    #[must_use]
    pub fn restart_count(&self, name: &ServiceName) -> u32 {
        self.runtimes.get(name).map_or(0, |r| r.restart_count)
    }

    /// The current pid of a service, if running.
    #[must_use]
    pub fn pid(&self, name: &ServiceName) -> Option<Pid> {
        self.runtimes.get(name).and_then(|r| r.pid)
    }

    /// A read-only handle to the host (for inspection in tests/diagnostics).
    #[must_use]
    pub fn host(&self) -> &H {
        &self.host
    }

    /// A mutable handle to the host (for scripting effects in tests).
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Starts every service in dependency order, arming socket-activated ones
    /// instead of spawning them (WS12-01.4 / .7).
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::Spawn`] if a non-socket service fails its
    /// initial spawn (fail-fast at bring-up).
    pub fn start_all(&mut self) -> Result<Vec<TickEvent>, SupervisorError> {
        let mut events = Vec::new();
        let order = self.order.clone();
        for name in &order {
            let socket = self.manifests.get(name).and_then(|m| m.socket.clone());
            if let Some(spec) = socket {
                self.host
                    .create_socket(name, &spec)
                    .map_err(|e| SupervisorError::Spawn(name.clone(), e))?;
                if let Some(rt) = self.runtimes.get_mut(name) {
                    rt.status = RunStatus::SocketArmed;
                }
                events.push(TickEvent::SocketArmed(name.clone()));
            } else {
                self.spawn_service(name)
                    .map_err(|e| SupervisorError::Spawn(name.clone(), e))?;
                events.push(TickEvent::Started(name.clone()));
            }
        }
        Ok(events)
    }

    /// Spawns a socket-armed service in response to an inbound connection
    /// (WS12-01.7). No-op unless the service is currently socket-armed.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError`] if the lazy spawn fails.
    pub fn notify_socket_connection(
        &mut self,
        name: &ServiceName,
    ) -> Result<Option<TickEvent>, SpawnError> {
        if self.runtimes.get(name).map(|r| r.status) != Some(RunStatus::SocketArmed) {
            return Ok(None);
        }
        self.spawn_service(name)?;
        Ok(Some(TickEvent::Started(name.clone())))
    }

    /// Advances the supervisor by one step: polls liveness/health of running
    /// services, schedules restarts for crashed/unhealthy ones (WS12-01.5/.6),
    /// and restarts any whose backoff has elapsed. Returns the action log.
    pub fn tick(&mut self) -> Vec<TickEvent> {
        let now = self.host.now_ms();
        let mut events = Vec::new();
        let order = self.order.clone();
        for name in &order {
            self.poll_one(name, now, &mut events);
        }
        for name in &order {
            self.maybe_restart(name, now, &mut events);
        }
        events
    }

    /// Handles a delivered signal (WS12-01.9): termination/interrupt trigger an
    /// ordered shutdown; a child-exit signal reaps and reconciles via [`tick`](Self::tick).
    pub fn handle_signal(&mut self, signal: Signal) -> Vec<TickEvent> {
        match signal {
            Signal::Terminate | Signal::Interrupt => self.shutdown(),
            Signal::ChildExited => self.tick(),
        }
    }

    /// Stops every running/armed service in reverse dependency order
    /// (WS12-01.9). Returns the action log.
    pub fn shutdown(&mut self) -> Vec<TickEvent> {
        let mut events = Vec::new();
        let order = self.order.clone();
        for name in order.iter().rev() {
            let Some(rt) = self.runtimes.get_mut(name) else {
                continue;
            };
            match rt.status {
                RunStatus::Running => {
                    if let Some(pid) = rt.pid {
                        self.host.kill(pid);
                    }
                    rt.pid = None;
                    rt.status = RunStatus::Stopped;
                    events.push(TickEvent::Stopped(name.clone()));
                }
                RunStatus::SocketArmed | RunStatus::Backoff | RunStatus::Pending => {
                    rt.status = RunStatus::Stopped;
                    events.push(TickEvent::Stopped(name.clone()));
                }
                RunStatus::Stopped | RunStatus::Failed => {}
            }
        }
        events
    }

    // --- internals ---------------------------------------------------------

    fn spawn_service(&mut self, name: &ServiceName) -> Result<(), SpawnError> {
        // Clone the (small) spawn inputs so the immutable manifest borrow does
        // not overlap the mutable host/runtime borrows below.
        let Some(m) = self.manifests.get(name) else {
            return Ok(());
        };
        let exec = m.exec.clone();
        let args = m.args.clone();
        let caps = m.capabilities.clone();
        let socket = m.socket.clone();

        let request = SpawnRequest {
            name,
            exec: &exec,
            args: &args,
            capabilities: &caps,
            socket: socket.as_ref(),
        };
        let pid = self.host.spawn(&request)?;
        let now = self.host.now_ms();
        if let Some(rt) = self.runtimes.get_mut(name) {
            rt.pid = Some(pid);
            rt.status = RunStatus::Running;
            rt.last_health_ms = now;
        }
        Ok(())
    }

    fn poll_one(&mut self, name: &ServiceName, now: u64, events: &mut Vec<TickEvent>) {
        let Some(rt) = self.runtimes.get(name) else {
            return;
        };
        if rt.status != RunStatus::Running {
            return;
        }
        let Some(pid) = rt.pid else { return };
        let last_health_ms = rt.last_health_ms;
        let health_interval = self
            .manifests
            .get(name)
            .and_then(|m| m.health)
            .map(|h| h.interval_ms);

        match self.host.liveness(pid) {
            Liveness::Exited { success } => self.handle_termination(name, success, now, events),
            Liveness::Alive => {
                if let Some(interval) = health_interval {
                    if now.saturating_sub(last_health_ms) >= interval {
                        if let Some(rt) = self.runtimes.get_mut(name) {
                            rt.last_health_ms = now;
                        }
                        if self.host.health(pid) == Health::Unhealthy {
                            events.push(TickEvent::Unhealthy(name.clone()));
                            self.host.kill(pid);
                            self.handle_termination(name, false, now, events);
                        }
                    }
                }
            }
        }
    }

    fn handle_termination(
        &mut self,
        name: &ServiceName,
        success: bool,
        now: u64,
        events: &mut Vec<TickEvent>,
    ) {
        events.push(TickEvent::Exited {
            service: name.clone(),
            success,
        });
        let policy = self.manifests.get(name).map(|m| m.restart);
        let backoff = self.manifests.get(name).map(|m| m.backoff);
        let restart = policy.is_some_and(|p| p.should_restart(success));

        let Some(rt) = self.runtimes.get_mut(name) else {
            return;
        };
        rt.pid = None;
        if restart {
            rt.restart_count = rt.restart_count.saturating_add(1);
            let delay = backoff.map_or(0, |b| b.delay_ms(rt.restart_count));
            rt.restart_at_ms = now.saturating_add(delay);
            rt.status = RunStatus::Backoff;
            events.push(TickEvent::RestartScheduled {
                service: name.clone(),
                at_ms: rt.restart_at_ms,
            });
        } else {
            rt.status = RunStatus::Failed;
            events.push(TickEvent::GaveUp(name.clone()));
        }
    }

    fn maybe_restart(&mut self, name: &ServiceName, now: u64, events: &mut Vec<TickEvent>) {
        let due = self
            .runtimes
            .get(name)
            .is_some_and(|r| r.status == RunStatus::Backoff && now >= r.restart_at_ms);
        if !due {
            return;
        }
        match self.spawn_service(name) {
            Ok(()) => events.push(TickEvent::Restarted(name.clone())),
            Err(e) => {
                // Treat a failed restart as another crash: keep backing off.
                if let Some(backoff) = self.manifests.get(name).map(|m| m.backoff) {
                    if let Some(rt) = self.runtimes.get_mut(name) {
                        rt.restart_count = rt.restart_count.saturating_add(1);
                        rt.restart_at_ms = now.saturating_add(backoff.delay_ms(rt.restart_count));
                        rt.status = RunStatus::Backoff;
                    }
                }
                events.push(TickEvent::SpawnFailed {
                    service: name.clone(),
                    error: e.0,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    use super::*;
    use crate::manifest::{Backoff, HealthCheck, RestartPolicy};

    /// Records what each spawned service was given, and scripts liveness/health.
    #[derive(Default)]
    struct MockHost {
        now: u64,
        next_pid: u64,
        spawns: Vec<(ServiceName, Vec<String>, bool)>, // (name, capability names, has_socket)
        kills: Vec<Pid>,
        sockets: Vec<ServiceName>,
        live: BTreeMap<Pid, Liveness>,
        health: BTreeMap<Pid, Health>,
        last_pid: BTreeMap<ServiceName, Pid>,
    }

    impl MockHost {
        fn advance(&mut self, ms: u64) {
            self.now += ms;
        }
        fn pid_of(&self, name: &str) -> Pid {
            *self.last_pid.get(&ServiceName::new(name).unwrap()).unwrap()
        }
        fn set_exited(&mut self, pid: Pid, success: bool) {
            self.live.insert(pid, Liveness::Exited { success });
        }
        fn set_unhealthy(&mut self, pid: Pid) {
            self.health.insert(pid, Health::Unhealthy);
        }
        fn caps_injected(&self, name: &str) -> Vec<String> {
            self.spawns
                .iter()
                .find(|(n, _, _)| n.as_str() == name)
                .map(|(_, c, _)| c.clone())
                .unwrap_or_default()
        }
    }

    impl ServiceHost for MockHost {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn spawn(&mut self, request: &SpawnRequest<'_>) -> Result<Pid, SpawnError> {
            self.next_pid += 1;
            let pid = Pid(self.next_pid);
            let caps = request
                .capabilities
                .iter()
                .map(|c| c.name().to_string())
                .collect();
            self.spawns
                .push((request.name.clone(), caps, request.socket.is_some()));
            self.live.insert(pid, Liveness::Alive);
            self.health.insert(pid, Health::Healthy);
            self.last_pid.insert(request.name.clone(), pid);
            Ok(pid)
        }
        fn kill(&mut self, pid: Pid) {
            self.kills.push(pid);
        }
        fn liveness(&mut self, pid: Pid) -> Liveness {
            self.live.get(&pid).copied().unwrap_or(Liveness::Alive)
        }
        fn health(&mut self, pid: Pid) -> Health {
            self.health.get(&pid).copied().unwrap_or(Health::Healthy)
        }
        fn create_socket(
            &mut self,
            name: &ServiceName,
            _spec: &SocketSpec,
        ) -> Result<(), SpawnError> {
            self.sockets.push(name.clone());
            Ok(())
        }
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    fn manifest(n: &str, deps: &[&str]) -> ServiceManifest {
        ServiceManifest::new(n, "/bin/x")
            .unwrap()
            .requires(deps.iter().copied())
            .unwrap()
    }

    #[test]
    fn starts_services_in_dependency_order() {
        // log <- net <- ui
        let manifests = vec![
            manifest("ui", &["net"]),
            manifest("net", &["log"]),
            manifest("log", &[]),
        ];
        let mut sup = Supervisor::new(manifests, MockHost::default()).unwrap();
        let events = sup.start_all().unwrap();
        let started: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                TickEvent::Started(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(started, vec!["log", "net", "ui"]);
        assert_eq!(sup.status(&name("net")), Some(RunStatus::Running));
    }

    #[test]
    fn injects_per_service_capabilities() {
        let net = ServiceManifest::new("net", "/bin/net")
            .unwrap()
            .with_capabilities(["net.bind", "net.raw"]);
        let mut sup = Supervisor::new(vec![net], MockHost::default()).unwrap();
        sup.start_all().unwrap();
        assert_eq!(
            sup.host().caps_injected("net"),
            vec!["net.bind".to_string(), "net.raw".to_string()]
        );
    }

    #[test]
    fn socket_activated_service_starts_lazily() {
        let api = ServiceManifest::new("api", "/bin/api")
            .unwrap()
            .with_socket(SocketSpec::listen("tcp:0.0.0.0:80"));
        let mut sup = Supervisor::new(vec![api], MockHost::default()).unwrap();
        sup.start_all().unwrap();
        assert_eq!(sup.status(&name("api")), Some(RunStatus::SocketArmed));
        assert!(sup.host().spawns.is_empty()); // not spawned yet
        assert_eq!(sup.host().sockets, vec![name("api")]);

        let ev = sup.notify_socket_connection(&name("api")).unwrap();
        assert_eq!(ev, Some(TickEvent::Started(name("api"))));
        assert_eq!(sup.status(&name("api")), Some(RunStatus::Running));
        assert_eq!(sup.host().spawns.len(), 1);
    }

    #[test]
    fn unhealthy_service_is_recycled() {
        let svc = ServiceManifest::new("svc", "/bin/svc")
            .unwrap()
            .with_health(HealthCheck::every_ms(1000))
            .with_restart(RestartPolicy::Always);
        let mut sup = Supervisor::new(vec![svc], MockHost::default()).unwrap();
        sup.start_all().unwrap();
        let pid = sup.host().pid_of("svc");
        sup.host_mut().set_unhealthy(pid);
        sup.host_mut().advance(1000); // health interval elapsed

        let events = sup.tick();
        assert!(events.contains(&TickEvent::Unhealthy(name("svc"))));
        assert!(sup.host().kills.contains(&pid));
        assert_eq!(sup.status(&name("svc")), Some(RunStatus::Backoff));
    }

    #[test]
    fn never_policy_does_not_restart() {
        let svc = ServiceManifest::new("svc", "/bin/svc")
            .unwrap()
            .with_restart(RestartPolicy::Never);
        let mut sup = Supervisor::new(vec![svc], MockHost::default()).unwrap();
        sup.start_all().unwrap();
        let pid = sup.host().pid_of("svc");
        sup.host_mut().set_exited(pid, false);
        let events = sup.tick();
        assert!(events.contains(&TickEvent::GaveUp(name("svc"))));
        assert_eq!(sup.status(&name("svc")), Some(RunStatus::Failed));
    }

    #[test]
    fn ordered_shutdown_is_reverse_dependency_order() {
        let manifests = vec![
            manifest("ui", &["net"]),
            manifest("net", &["log"]),
            manifest("log", &[]),
        ];
        let mut sup = Supervisor::new(manifests, MockHost::default()).unwrap();
        sup.start_all().unwrap();
        let events = sup.handle_signal(Signal::Terminate);
        let stopped: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                TickEvent::Stopped(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(stopped, vec!["ui", "net", "log"]); // reverse of start order
        assert_eq!(sup.status(&name("log")), Some(RunStatus::Stopped));
    }

    /// WS12-01.11 — killing `nexacore-net` triggers a supervised restart.
    #[test]
    fn supervised_restart_after_crash_with_backoff() {
        let net = ServiceManifest::new("nexacore-net", "/bin/nexacore-net")
            .unwrap()
            .with_restart(RestartPolicy::OnFailure)
            .with_backoff(Backoff {
                base_ms: 100,
                max_ms: 1000,
                factor: 2,
            });
        let mut sup = Supervisor::new(vec![net], MockHost::default()).unwrap();
        sup.start_all().unwrap();
        let first_pid = sup.host().pid_of("nexacore-net");

        // The process is killed / crashes (non-zero exit).
        sup.host_mut().set_exited(first_pid, false);
        let events = sup.tick();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TickEvent::RestartScheduled { .. }))
        );
        assert_eq!(sup.status(&name("nexacore-net")), Some(RunStatus::Backoff));
        assert_eq!(sup.restart_count(&name("nexacore-net")), 1);

        // Before the backoff elapses, nothing restarts.
        sup.host_mut().advance(50);
        assert!(sup.tick().is_empty());
        assert_eq!(sup.status(&name("nexacore-net")), Some(RunStatus::Backoff));

        // After the 100ms backoff, the supervisor restarts it with a fresh pid.
        sup.host_mut().advance(60); // now 110ms since crash
        let events = sup.tick();
        assert!(events.contains(&TickEvent::Restarted(name("nexacore-net"))));
        assert_eq!(sup.status(&name("nexacore-net")), Some(RunStatus::Running));
        let second_pid = sup.host().pid_of("nexacore-net");
        assert_ne!(first_pid, second_pid);
    }

    #[test]
    fn successful_exit_under_onfailure_is_not_restarted() {
        let svc = ServiceManifest::new("oneshot", "/bin/oneshot")
            .unwrap()
            .with_restart(RestartPolicy::OnFailure);
        let mut sup = Supervisor::new(vec![svc], MockHost::default()).unwrap();
        sup.start_all().unwrap();
        let pid = sup.host().pid_of("oneshot");
        sup.host_mut().set_exited(pid, true); // clean exit
        let events = sup.tick();
        assert!(events.contains(&TickEvent::GaveUp(name("oneshot"))));
        assert_eq!(sup.status(&name("oneshot")), Some(RunStatus::Failed));
    }

    #[test]
    fn construction_rejects_cyclic_dependencies() {
        let manifests = vec![manifest("a", &["b"]), manifest("b", &["a"])];
        match Supervisor::new(manifests, MockHost::default()) {
            Err(SupervisorError::Graph(GraphError::Cycle(_))) => {}
            _ => panic!("expected cyclic-dependency error"),
        }
    }
}

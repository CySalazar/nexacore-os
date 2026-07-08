//! Service unit manifest format (WS12-01.1).
//!
//! A [`ServiceManifest`] is the declarative description of one supervised
//! service: what to run, what it depends on, how to restart it, how to check
//! its health, whether it is socket-activated, and which capabilities the
//! supervisor injects into it at spawn time.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::{NameError, ServiceName, names_from};

/// What the supervisor does when a service process exits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Never restart the service once it has exited.
    Never,
    /// Restart only on unsuccessful exit (non-zero) or an unhealthy check.
    #[default]
    OnFailure,
    /// Restart on any exit, successful or not.
    Always,
}

impl RestartPolicy {
    /// Returns `true` if a process that exited with the given success flag
    /// should be restarted under this policy.
    #[must_use]
    pub fn should_restart(self, exited_successfully: bool) -> bool {
        match self {
            Self::Never => false,
            Self::Always => true,
            Self::OnFailure => !exited_successfully,
        }
    }
}

/// Exponential backoff schedule for restarts.
///
/// The delay before the *n*-th restart (with `n >= 1`) is
/// `min(max_ms, base_ms * factor^(n-1))`, computed with saturating integer
/// arithmetic so it can never overflow or panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// Delay before the first restart, in milliseconds.
    pub base_ms: u64,
    /// Upper bound on the delay, in milliseconds.
    pub max_ms: u64,
    /// Multiplicative growth factor between successive restarts (`>= 1`).
    pub factor: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        // 100ms, doubling, capped at 30s — a sane default for crash loops.
        Self {
            base_ms: 100,
            max_ms: 30_000,
            factor: 2,
        }
    }
}

impl Backoff {
    /// Returns the delay before the `restart_count`-th restart.
    ///
    /// `restart_count` is the 1-based index of the restart about to happen
    /// (the first restart after a crash is `1`). A `restart_count` of `0`
    /// yields `0` (no delay).
    #[must_use]
    pub fn delay_ms(&self, restart_count: u32) -> u64 {
        if restart_count == 0 {
            return 0;
        }
        let mut delay = self.base_ms;
        let mut step = 1;
        while step < restart_count {
            delay = delay.saturating_mul(self.factor);
            if delay >= self.max_ms {
                return self.max_ms;
            }
            step += 1;
        }
        delay.min(self.max_ms)
    }
}

/// Periodic liveness probe for a service (WS12-01.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthCheck {
    /// How often the supervisor polls the service's health, in milliseconds.
    pub interval_ms: u64,
}

impl HealthCheck {
    /// Creates a health check with the given interval.
    #[must_use]
    pub fn every_ms(interval_ms: u64) -> Self {
        Self { interval_ms }
    }
}

/// A capability injected into a service at spawn time (WS12-01.8).
///
/// The string is an opaque capability name (e.g. `net.bind`, `fs.read:/etc`)
/// interpreted by the production host against `nexacore-capability`; the
/// supervisor only carries and forwards it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Capability(pub String);

impl Capability {
    /// Creates a capability from a name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the capability name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}

/// Socket-activation specification (WS12-01.7).
///
/// When present, the supervisor creates the listening socket up front but
/// defers spawning the service until the first inbound connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketSpec {
    /// An opaque listen address (e.g. `tcp:0.0.0.0:80`, `unix:/run/foo.sock`),
    /// interpreted by the host.
    pub listen: String,
}

impl SocketSpec {
    /// Creates a socket spec for the given listen address.
    #[must_use]
    pub fn listen(addr: impl Into<String>) -> Self {
        Self {
            listen: addr.into(),
        }
    }
}

/// A declarative service unit manifest (WS12-01.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceManifest {
    /// The service's unique name.
    pub name: ServiceName,
    /// The executable path or command the service runs.
    pub exec: String,
    /// Command-line arguments passed to `exec`.
    pub args: Vec<String>,
    /// Services that must be *running* before this one starts (hard order).
    pub requires: Vec<ServiceName>,
    /// Restart policy applied when the process exits.
    pub restart: RestartPolicy,
    /// Backoff schedule between restarts.
    pub backoff: Backoff,
    /// Optional periodic health check.
    pub health: Option<HealthCheck>,
    /// Optional socket activation; when set, the service is started lazily.
    pub socket: Option<SocketSpec>,
    /// Capabilities injected into the service at spawn time.
    pub capabilities: Vec<Capability>,
}

impl ServiceManifest {
    /// Starts building a manifest for a service with the given name and exec.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] if `name` is not a valid [`ServiceName`].
    pub fn new(name: impl Into<String>, exec: impl Into<String>) -> Result<Self, NameError> {
        Ok(Self {
            name: ServiceName::new(name)?,
            exec: exec.into(),
            args: Vec::new(),
            requires: Vec::new(),
            restart: RestartPolicy::default(),
            backoff: Backoff::default(),
            health: None,
            socket: None,
            capabilities: Vec::new(),
        })
    }

    /// Sets the command-line arguments.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Declares the services this one requires to be running first.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] if any dependency name is invalid.
    pub fn requires<I, S>(mut self, deps: I) -> Result<Self, NameError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.requires = names_from(deps)?;
        Ok(self)
    }

    /// Sets the restart policy.
    #[must_use]
    pub fn with_restart(mut self, policy: RestartPolicy) -> Self {
        self.restart = policy;
        self
    }

    /// Sets the backoff schedule.
    #[must_use]
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Sets the periodic health check.
    #[must_use]
    pub fn with_health(mut self, health: HealthCheck) -> Self {
        self.health = Some(health);
        self
    }

    /// Marks the service as socket-activated by the given socket.
    #[must_use]
    pub fn with_socket(mut self, socket: SocketSpec) -> Self {
        self.socket = Some(socket);
        self
    }

    /// Sets the capabilities injected at spawn time.
    #[must_use]
    pub fn with_capabilities<I, S>(mut self, caps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.capabilities = caps.into_iter().map(Capability::new).collect();
        self
    }

    /// Validates the manifest's self-consistency.
    ///
    /// # Errors
    ///
    /// - [`ManifestError::EmptyExec`] if `exec` is empty.
    /// - [`ManifestError::SelfDependency`] if the service requires itself.
    /// - [`ManifestError::DuplicateDependency`] if a dependency is listed twice.
    /// - [`ManifestError::InvalidBackoff`] if `factor == 0` or `max_ms < base_ms`.
    /// - [`ManifestError::InvalidHealthInterval`] if a health check interval is 0.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.exec.is_empty() {
            return Err(ManifestError::EmptyExec);
        }
        for (i, dep) in self.requires.iter().enumerate() {
            if *dep == self.name {
                return Err(ManifestError::SelfDependency);
            }
            if self.requires.iter().skip(i + 1).any(|d| d == dep) {
                return Err(ManifestError::DuplicateDependency);
            }
        }
        if self.backoff.factor == 0 || self.backoff.max_ms < self.backoff.base_ms {
            return Err(ManifestError::InvalidBackoff);
        }
        if let Some(h) = self.health {
            if h.interval_ms == 0 {
                return Err(ManifestError::InvalidHealthInterval);
            }
        }
        Ok(())
    }
}

/// Error returned when a [`ServiceManifest`] fails validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// The `exec` field was empty.
    EmptyExec,
    /// The service listed itself as a dependency.
    SelfDependency,
    /// A dependency appeared more than once.
    DuplicateDependency,
    /// `factor == 0` or `max_ms < base_ms`.
    InvalidBackoff,
    /// A health-check interval was zero.
    InvalidHealthInterval,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExec => f.write_str("service manifest has an empty exec"),
            Self::SelfDependency => f.write_str("service requires itself"),
            Self::DuplicateDependency => f.write_str("service lists a dependency twice"),
            Self::InvalidBackoff => f.write_str("invalid backoff (factor 0 or max < base)"),
            Self::InvalidHealthInterval => f.write_str("health-check interval is zero"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn restart_policy_decisions() {
        assert!(!RestartPolicy::Never.should_restart(false));
        assert!(RestartPolicy::Always.should_restart(true));
        assert!(RestartPolicy::OnFailure.should_restart(false));
        assert!(!RestartPolicy::OnFailure.should_restart(true));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let b = Backoff {
            base_ms: 100,
            max_ms: 1000,
            factor: 2,
        };
        assert_eq!(b.delay_ms(0), 0);
        assert_eq!(b.delay_ms(1), 100);
        assert_eq!(b.delay_ms(2), 200);
        assert_eq!(b.delay_ms(3), 400);
        assert_eq!(b.delay_ms(4), 800);
        assert_eq!(b.delay_ms(5), 1000); // capped
        assert_eq!(b.delay_ms(100), 1000); // saturating, no overflow
    }

    #[test]
    fn manifest_builder_and_validate() {
        let m = ServiceManifest::new("nexacore-net", "/bin/nexacore-net")
            .unwrap()
            .with_args(["--config", "/etc/net.toml"])
            .requires(["nexacore-log"])
            .unwrap()
            .with_restart(RestartPolicy::Always)
            .with_health(HealthCheck::every_ms(1000))
            .with_capabilities(["net.bind", "net.raw"]);
        assert!(m.validate().is_ok());
        assert_eq!(
            m.args,
            vec![String::from("--config"), String::from("/etc/net.toml")]
        );
        assert_eq!(m.capabilities.len(), 2);
    }

    #[test]
    fn validate_rejects_bad_manifests() {
        let mut m = ServiceManifest::new("svc", "/bin/svc").unwrap();
        m.exec = String::new();
        assert_eq!(m.validate(), Err(ManifestError::EmptyExec));

        let m = ServiceManifest::new("svc", "/bin/svc")
            .unwrap()
            .requires(["svc"])
            .unwrap();
        assert_eq!(m.validate(), Err(ManifestError::SelfDependency));

        let m = ServiceManifest::new("svc", "/bin/svc")
            .unwrap()
            .requires(["a", "a"])
            .unwrap();
        assert_eq!(m.validate(), Err(ManifestError::DuplicateDependency));

        let m = ServiceManifest::new("svc", "/bin/svc")
            .unwrap()
            .with_backoff(Backoff {
                base_ms: 100,
                max_ms: 10,
                factor: 2,
            });
        assert_eq!(m.validate(), Err(ManifestError::InvalidBackoff));

        let m = ServiceManifest::new("svc", "/bin/svc")
            .unwrap()
            .with_health(HealthCheck::every_ms(0));
        assert_eq!(m.validate(), Err(ManifestError::InvalidHealthInterval));
    }
}

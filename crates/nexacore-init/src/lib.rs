//! `nexacore-init` — the NexaCore OS init / service manager (WS12-01).
//!
//! A PID 1 supervisor in the spirit of systemd / launchd, but typed and
//! capability-first:
//!
//! - **Service unit manifest** ([`ServiceManifest`]): exec, dependencies,
//!   restart policy + backoff, periodic health check, socket activation, and
//!   the set of capabilities injected into the service. (WS12-01.1)
//! - **PID 1 supervisor loop** ([`Supervisor`]): starts, polls, restarts and
//!   stops services, driving all process/clock effects through the
//!   [`ServiceHost`] seam. (WS12-01.2)
//! - **Dependency graph** ([`DependencyGraph`]) and **topological start order**
//!   ([`DependencyGraph::topological_order`]). (WS12-01.3 / .4)
//! - **Periodic health checks** with unhealthy-service recovery. (WS12-01.5)
//! - **Restart-on-crash with exponential backoff**, policy-aware
//!   ([`RestartPolicy`] / [`Backoff`]). (WS12-01.6)
//! - **Socket activation**: socket-armed services are spawned lazily on the
//!   first connection. (WS12-01.7)
//! - **Per-service capability injection** at spawn time. (WS12-01.8)
//! - **Signal handling and ordered shutdown** in reverse dependency order.
//!   (WS12-01.9)
//!
//! All effects (spawning, killing, polling liveness, the monotonic clock,
//! socket creation) live behind the [`ServiceHost`] trait, so the supervisor is
//! pure logic and fully host-testable. The production host is backed by
//! `nexacore-usys` syscalls; a `MockHost` is provided under `cfg(test)`.
//!
//! `no_std + alloc`, zero production dependencies — it builds for the host and
//! for `x86_64-unknown-none`.

#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-init")]
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::integer_division
    )
)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt;

pub mod graph;
pub mod manifest;
pub mod supervisor;

pub use graph::{DependencyGraph, GraphError};
pub use manifest::{
    Backoff, Capability, HealthCheck, ManifestError, RestartPolicy, ServiceManifest, SocketSpec,
};
pub use supervisor::{
    Health, Pid, RunStatus, ServiceHost, Signal, SpawnError, SpawnRequest, Supervisor,
    SupervisorError,
};

// ---------------------------------------------------------------------------
// ServiceName — a validated service identifier
// ---------------------------------------------------------------------------

/// A validated service name (e.g. `nexacore-net`).
///
/// Names are non-empty, at most [`ServiceName::MAX_LEN`] bytes, and contain only
/// lowercase ASCII letters, digits, `-`, `_` and `.`. Keeping the alphabet
/// narrow lets names double as stable identifiers in logs, sockets and audit.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceName(String);

impl ServiceName {
    /// Maximum length of a service name, in bytes.
    pub const MAX_LEN: usize = 64;

    /// Creates a validated [`ServiceName`], or returns [`NameError`].
    ///
    /// # Errors
    ///
    /// Returns [`NameError::Empty`] for an empty string, [`NameError::TooLong`]
    /// past [`Self::MAX_LEN`], or [`NameError::InvalidChar`] for any byte
    /// outside `[a-z0-9._-]`.
    pub fn new(raw: impl Into<String>) -> Result<Self, NameError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(NameError::Empty);
        }
        if raw.len() > Self::MAX_LEN {
            return Err(NameError::TooLong);
        }
        for ch in raw.chars() {
            if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')) {
                return Err(NameError::InvalidChar(ch));
            }
        }
        Ok(Self(raw))
    }

    /// Returns the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceName({:?})", self.0)
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error returned when constructing a [`ServiceName`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    /// The name was empty.
    Empty,
    /// The name exceeded [`ServiceName::MAX_LEN`] bytes.
    TooLong,
    /// The name contained a byte outside `[a-z0-9._-]`.
    InvalidChar(char),
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("service name is empty"),
            Self::TooLong => f.write_str("service name is too long"),
            Self::InvalidChar(ch) => write!(f, "service name contains invalid character {ch:?}"),
        }
    }
}

/// Convenience: collect a list of [`ServiceName`]s from string-like items.
///
/// # Errors
///
/// Propagates the first [`NameError`] encountered.
pub(crate) fn names_from<I, S>(items: I) -> Result<Vec<ServiceName>, NameError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    items.into_iter().map(ServiceName::new).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names_are_accepted() {
        assert_eq!(
            ServiceName::new("nexacore-net").unwrap().as_str(),
            "nexacore-net"
        );
        assert!(ServiceName::new("a.b_c-1").is_ok());
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert_eq!(ServiceName::new(""), Err(NameError::Empty));
        assert_eq!(ServiceName::new("Net"), Err(NameError::InvalidChar('N')));
        assert_eq!(ServiceName::new("a b"), Err(NameError::InvalidChar(' ')));
        let long = "a".repeat(ServiceName::MAX_LEN + 1);
        assert_eq!(ServiceName::new(long), Err(NameError::TooLong));
    }
}

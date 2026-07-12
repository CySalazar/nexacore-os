//! `whoami` / `id` — the current principal over an injected identity (WS8-10.9).
//!
//! Pure `no_std` logic has no ambient notion of "who am I": there is no syscall
//! to a kernel here. The current principal is therefore an injected
//! [`Identity`] value, obtained through the [`IdentitySource`] seam — the same
//! shape as [`FileSystem`](crate::fs::FileSystem): a trait plus a deterministic
//! host double ([`StaticIdentity`]).
//!
//! ## Capability identity, not Unix uid/gid
//!
//! NexaCore is capability-based, so identity is a [`Principal`] (a named actor
//! with an abstract numeric id standing in for a uid) carrying a set of
//! [`Role`]s (abstract groups, standing in for supplementary gids). There is no
//! separate primary-group concept and no `gid`: authority comes from the
//! principal's roles and the capability tokens it holds, not from a uid:gid
//! pair.
//!
//! - [`whoami`] renders just the principal name.
//! - [`id_line`] renders `principal=<id>(<name>) roles=<id>(<name>),…`, the
//!   capability analogue of `id`'s `uid=…(…) groups=…` line.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// A named actor with an abstract numeric id.
///
/// The `id` is a stand-in for a Unix uid: an opaque, stable handle to the
/// principal. It is not an ambient-authority number — it only names the actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The abstract principal id (uid analogue).
    pub id: u64,
    /// The human-readable principal name.
    pub name: String,
}

impl Principal {
    /// Construct a principal from an id and name.
    #[must_use]
    pub fn new(id: u64, name: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
        }
    }

    /// Render as `id(name)`, the way `id` prints a uid or gid.
    #[must_use]
    pub fn labelled(&self) -> String {
        format!("{}({})", self.id, self.name)
    }
}

/// An abstract group/role the current principal belongs to (gid analogue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    /// The abstract role id.
    pub id: u64,
    /// The human-readable role name.
    pub name: String,
}

impl Role {
    /// Construct a role from an id and name.
    #[must_use]
    pub fn new(id: u64, name: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
        }
    }

    /// Render as `id(name)`.
    #[must_use]
    pub fn labelled(&self) -> String {
        format!("{}({})", self.id, self.name)
    }
}

/// The identity of the current actor: a principal plus its roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The current principal.
    pub principal: Principal,
    /// The roles (abstract groups) the principal carries.
    pub roles: Vec<Role>,
}

impl Identity {
    /// Construct an identity from a principal and its roles.
    #[must_use]
    pub fn new(principal: Principal, roles: Vec<Role>) -> Self {
        Self { principal, roles }
    }
}

/// The seam that yields the current [`Identity`].
///
/// On hardware this bridges to the kernel's principal registry; host tests use
/// [`StaticIdentity`]. Keeping identity behind a trait means no utility ever
/// reaches for ambient state.
pub trait IdentitySource {
    /// The identity of the current actor.
    fn current(&self) -> Identity;
}

/// A fixed-identity host double for [`IdentitySource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticIdentity {
    /// The identity this source always reports.
    identity: Identity,
}

impl StaticIdentity {
    /// Wrap a fixed [`Identity`].
    #[must_use]
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }
}

impl IdentitySource for StaticIdentity {
    fn current(&self) -> Identity {
        self.identity.clone()
    }
}

/// `whoami`: the current principal's name.
#[must_use]
pub fn whoami(identity: &Identity) -> String {
    identity.principal.name.clone()
}

/// `whoami` over a source seam.
#[must_use]
pub fn whoami_from<S: IdentitySource>(source: &S) -> String {
    whoami(&source.current())
}

/// `id`: a one-line summary of the principal and its roles.
///
/// The form is `principal=<id>(<name>) roles=<id>(<name>),…`. When the principal
/// has no roles the `roles=` field is emitted empty, so the shape is stable for
/// parsing.
#[must_use]
pub fn id_line(identity: &Identity) -> String {
    let roles = identity
        .roles
        .iter()
        .map(Role::labelled)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "principal={} roles={}",
        identity.principal.labelled(),
        roles
    )
}

/// `id` over a source seam.
#[must_use]
pub fn id_from<S: IdentitySource>(source: &S) -> String {
    id_line(&source.current())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn identity() -> Identity {
        Identity::new(
            Principal::new(1000, "alice"),
            vec![Role::new(10, "staff"), Role::new(20, "dev")],
        )
    }

    #[test]
    fn whoami_is_principal_name() {
        assert_eq!(whoami(&identity()), "alice");
    }

    #[test]
    fn id_line_lists_principal_and_roles() {
        assert_eq!(
            id_line(&identity()),
            "principal=1000(alice) roles=10(staff),20(dev)"
        );
    }

    #[test]
    fn id_line_with_no_roles_has_empty_field() {
        let solo = Identity::new(Principal::new(0, "root"), Vec::new());
        assert_eq!(id_line(&solo), "principal=0(root) roles=");
    }

    #[test]
    fn source_seam_round_trips() {
        let source = StaticIdentity::new(identity());
        assert_eq!(whoami_from(&source), "alice");
        assert_eq!(
            id_from(&source),
            "principal=1000(alice) roles=10(staff),20(dev)"
        );
    }

    #[test]
    fn principal_and_role_labels() {
        assert_eq!(Principal::new(5, "svc").labelled(), "5(svc)");
        assert_eq!(Role::new(7, "audit").labelled(), "7(audit)");
    }
}

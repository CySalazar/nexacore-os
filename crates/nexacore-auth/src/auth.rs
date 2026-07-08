//! PAM-class pluggable authentication stack (WS12-05.4).
//!
//! Authentication runs an ordered stack of [`AuthModule`]s, each tagged with a
//! PAM-style [`Control`] flag that governs how its result affects the overall
//! outcome. The bundled [`PasswordModule`] checks a presented password against
//! the [`crate::store::UserStore`] via the [`crate::hash`] seam; other modules
//! (TEE-bound token, one-time-password, …) plug in the same way.

use alloc::{boxed::Box, vec::Vec};

use crate::{
    hash::{PasswordHasher, verify},
    store::UserStore,
};

/// The result a single [`AuthModule`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleResult {
    /// The module authenticated the request.
    Success,
    /// The module rejected the request.
    Failure,
    /// The module does not apply and abstains.
    Skip,
}

/// The credentials presented for an authentication attempt.
pub struct AuthRequest<'a> {
    /// The login name.
    pub username: &'a str,
    /// The presented secret.
    pub password: &'a [u8],
}

/// A pluggable, stackable authentication check.
pub trait AuthModule {
    /// A short, stable module name for diagnostics.
    fn name(&self) -> &str;

    /// Evaluate the request against the user store.
    fn authenticate(&self, request: &AuthRequest<'_>, store: &UserStore) -> ModuleResult;
}

/// PAM-style control flag governing how a module's result shapes the stack
/// outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Must succeed for the stack to authenticate; a failure is recorded but the
    /// remaining modules still run (so failures don't reveal which module).
    Required,
    /// Like [`Control::Required`], but a failure aborts the stack immediately.
    Requisite,
    /// A success (with no prior required failure) authenticates immediately; a
    /// failure is ignored.
    Sufficient,
    /// Advisory: neither authenticates nor denies on its own.
    Optional,
}

/// The overall outcome of running an [`AuthStack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The stack authenticated the request.
    Authenticated,
    /// The stack denied the request.
    Denied,
}

/// An ordered stack of `(control, module)` entries evaluated PAM-style.
#[derive(Default)]
pub struct AuthStack {
    entries: Vec<(Control, Box<dyn AuthModule>)>,
}

impl AuthStack {
    /// An empty stack (which denies everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a module with its control flag.
    pub fn push(&mut self, control: Control, module: Box<dyn AuthModule>) -> &mut Self {
        self.entries.push((control, module));
        self
    }

    /// The number of modules in the stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the stack has no modules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Run the stack against `request`.
    ///
    /// Semantics: a [`Control::Requisite`] failure denies immediately; a
    /// [`Control::Sufficient`] success (with no prior required/requisite
    /// failure) authenticates immediately; [`Control::Required`] modules must
    /// all pass; [`Control::Optional`] modules never decide the outcome. The
    /// stack authenticates iff at least one required/requisite module passed and
    /// none failed.
    #[must_use]
    pub fn authenticate(&self, request: &AuthRequest<'_>, store: &UserStore) -> AuthOutcome {
        let mut binding_failed = false;
        let mut binding_success = false;
        for (control, module) in &self.entries {
            let result = module.authenticate(request, store);
            match control {
                Control::Required => match result {
                    ModuleResult::Success => binding_success = true,
                    ModuleResult::Failure => binding_failed = true,
                    ModuleResult::Skip => {}
                },
                Control::Requisite => match result {
                    ModuleResult::Success => binding_success = true,
                    ModuleResult::Failure => return AuthOutcome::Denied,
                    ModuleResult::Skip => {}
                },
                Control::Sufficient => {
                    if result == ModuleResult::Success && !binding_failed {
                        return AuthOutcome::Authenticated;
                    }
                }
                Control::Optional => {}
            }
        }
        if binding_success && !binding_failed {
            AuthOutcome::Authenticated
        } else {
            AuthOutcome::Denied
        }
    }
}

/// A fixed salt used only to make the absent-user code path perform an
/// equivalent hash, so authentication time does not reveal account existence.
const DECOY_SALT: &[u8] = b"nexacore-auth-decoy-salt-v1";

/// A password-checking [`AuthModule`]: verifies the presented password against
/// the user's stored credential.
pub struct PasswordModule<H: PasswordHasher> {
    hasher: H,
}

impl<H: PasswordHasher> PasswordModule<H> {
    /// A module verifying passwords with `hasher`.
    pub fn new(hasher: H) -> Self {
        Self { hasher }
    }
}

impl<H: PasswordHasher> AuthModule for PasswordModule<H> {
    fn name(&self) -> &'static str {
        "password"
    }

    fn authenticate(&self, request: &AuthRequest<'_>, store: &UserStore) -> ModuleResult {
        // An unknown user fails (rather than skips) so it cannot be enumerated
        // and cannot satisfy a `required` slot. To also defeat *timing*
        // enumeration, an absent user still incurs an equivalent hashing cost
        // (a decoy hash) so the response time does not reveal whether the
        // account exists.
        store.get_by_name(request.username).map_or_else(
            || {
                // `black_box` stops the optimiser from eliding the decoy hash,
                // preserving the constant-time property.
                let decoy = self.hasher.hash(request.password, DECOY_SALT);
                core::hint::black_box(&decoy);
                ModuleResult::Failure
            },
            |user| {
                if verify(&self.hasher, &user.credential, request.password) {
                    ModuleResult::Success
                } else {
                    ModuleResult::Failure
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash::Blake3Hasher,
        store::{Privileges, UserStore, create_account},
    };

    fn store_with_alice() -> UserStore {
        let mut store = UserStore::new();
        create_account(
            &mut store,
            &Blake3Hasher::new(2),
            "alice",
            b"hunter2",
            b"salt",
            Privileges::user(),
            0,
        )
        .unwrap();
        store
    }

    fn password_stack(control: Control) -> AuthStack {
        let mut stack = AuthStack::new();
        stack.push(control, Box::new(PasswordModule::new(Blake3Hasher::new(2))));
        stack
    }

    #[test]
    fn required_password_authenticates_and_denies() {
        let store = store_with_alice();
        let stack = password_stack(Control::Required);
        assert_eq!(
            stack.authenticate(
                &AuthRequest {
                    username: "alice",
                    password: b"hunter2"
                },
                &store
            ),
            AuthOutcome::Authenticated
        );
        assert_eq!(
            stack.authenticate(
                &AuthRequest {
                    username: "alice",
                    password: b"wrong"
                },
                &store
            ),
            AuthOutcome::Denied
        );
        // Unknown user is denied (and indistinguishable from a bad password).
        assert_eq!(
            stack.authenticate(
                &AuthRequest {
                    username: "mallory",
                    password: b"hunter2"
                },
                &store
            ),
            AuthOutcome::Denied
        );
    }

    #[test]
    fn empty_stack_denies() {
        let store = store_with_alice();
        assert_eq!(
            AuthStack::new().authenticate(
                &AuthRequest {
                    username: "alice",
                    password: b"hunter2"
                },
                &store
            ),
            AuthOutcome::Denied
        );
    }

    #[test]
    fn requisite_failure_aborts_before_a_later_sufficient() {
        // A module that always succeeds, to prove the requisite short-circuits.
        struct AlwaysOk;
        impl AuthModule for AlwaysOk {
            fn name(&self) -> &'static str {
                "always-ok"
            }
            fn authenticate(&self, _r: &AuthRequest<'_>, _s: &UserStore) -> ModuleResult {
                ModuleResult::Success
            }
        }
        let store = store_with_alice();
        let mut stack = AuthStack::new();
        stack.push(
            Control::Requisite,
            Box::new(PasswordModule::new(Blake3Hasher::new(2))),
        );
        stack.push(Control::Sufficient, Box::new(AlwaysOk));
        // Wrong password → requisite fails → the later sufficient never runs.
        assert_eq!(
            stack.authenticate(
                &AuthRequest {
                    username: "alice",
                    password: b"wrong"
                },
                &store
            ),
            AuthOutcome::Denied
        );
        // Right password → requisite passes, then sufficient authenticates.
        assert_eq!(
            stack.authenticate(
                &AuthRequest {
                    username: "alice",
                    password: b"hunter2"
                },
                &store
            ),
            AuthOutcome::Authenticated
        );
    }

    #[test]
    fn optional_alone_does_not_authenticate() {
        let store = store_with_alice();
        let stack = password_stack(Control::Optional);
        // Even with the correct password, an optional-only stack has no binding
        // success, so it denies.
        assert_eq!(
            stack.authenticate(
                &AuthRequest {
                    username: "alice",
                    password: b"hunter2"
                },
                &store
            ),
            AuthOutcome::Denied
        );
    }
}

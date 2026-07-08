//! Session manager: greeter, lock screen, idle-lock, fast switching (WS7-15).
//!
//! A pure state machine for the desktop session lifecycle. It presents a greeter
//! (user list + credential form, WS7-15.2), starts/stops sessions (WS7-15.1),
//! locks and unlocks them behind authentication (WS7-15.4), auto-locks on idle
//! (WS7-15.5), fast-switches between concurrently logged-in users (WS7-15.6),
//! and logs out back to the greeter (WS7-15.7). Credential checks go through the
//! [`Authenticator`] seam — the real backend is `nexacore-auth` (WS12-05,
//! WS7-15.3); drawing the greeter/lock UI is downstream.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Credential-verification seam. The production implementation is the
/// `nexacore-auth` password module (WS12-05); tests supply a stub.
pub trait Authenticator {
    /// Whether `secret` authenticates `user`.
    fn authenticate(&self, user: &str, secret: &[u8]) -> bool;
}

/// Why a session operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Authentication was rejected.
    AuthFailed,
    /// No session is currently active.
    NoActiveSession,
    /// No session exists for the requested user.
    NoSuchSession,
}

/// A logged-in user's session.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Session {
    user: String,
    locked: bool,
    idle_ms: u64,
}

/// What the shell should currently display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionView {
    /// The greeter (no active session).
    Greeter,
    /// The active session for a user.
    Active(String),
    /// The lock screen for a user's active session.
    Locked(String),
}

/// The session manager (WS7-15).
#[derive(Debug, Clone)]
pub struct SessionManager {
    users: Vec<String>,
    sessions: Vec<Session>,
    active: Option<usize>,
    idle_timeout_ms: u64,
}

impl SessionManager {
    /// A manager for the greeter's `users`, auto-locking after `idle_timeout_ms`
    /// of inactivity (0 disables idle-lock).
    #[must_use]
    pub fn new(users: &[&str], idle_timeout_ms: u64) -> Self {
        Self {
            users: users.iter().map(|u| (*u).to_string()).collect(),
            sessions: Vec::new(),
            active: None,
            idle_timeout_ms,
        }
    }

    /// The greeter's selectable user list (WS7-15.2).
    #[must_use]
    pub fn greeter_users(&self) -> &[String] {
        &self.users
    }

    /// What the shell should display.
    #[must_use]
    pub fn view(&self) -> SessionView {
        match self.active.and_then(|i| self.sessions.get(i)) {
            None => SessionView::Greeter,
            Some(s) if s.locked => SessionView::Locked(s.user.clone()),
            Some(s) => SessionView::Active(s.user.clone()),
        }
    }

    fn session_index(&self, user: &str) -> Option<usize> {
        self.sessions.iter().position(|s| s.user == user)
    }

    /// Authenticate `user` from the greeter and make their session active,
    /// starting one if needed (WS7-15.1/.3). An already-running session is
    /// unlocked and switched to (fast user switching, WS7-15.6).
    ///
    /// # Errors
    /// [`SessionError::AuthFailed`] if the credential is rejected.
    pub fn login(
        &mut self,
        user: &str,
        secret: &[u8],
        auth: &impl Authenticator,
    ) -> Result<(), SessionError> {
        if !auth.authenticate(user, secret) {
            return Err(SessionError::AuthFailed);
        }
        let idx = if let Some(i) = self.session_index(user) {
            if let Some(s) = self.sessions.get_mut(i) {
                s.locked = false;
                s.idle_ms = 0;
            }
            i
        } else {
            self.sessions.push(Session {
                user: user.to_string(),
                locked: false,
                idle_ms: 0,
            });
            self.sessions.len() - 1
        };
        self.active = Some(idx);
        Ok(())
    }

    /// Lock the active session (WS7-15.4).
    ///
    /// # Errors
    /// [`SessionError::NoActiveSession`] if nothing is active.
    pub fn lock(&mut self) -> Result<(), SessionError> {
        let i = self.active.ok_or(SessionError::NoActiveSession)?;
        if let Some(s) = self.sessions.get_mut(i) {
            s.locked = true;
        }
        Ok(())
    }

    /// Unlock the active session with the user's credential (WS7-15.4).
    ///
    /// # Errors
    /// [`SessionError::NoActiveSession`] if nothing is active, or
    /// [`SessionError::AuthFailed`] if the credential is rejected.
    pub fn unlock(&mut self, secret: &[u8], auth: &impl Authenticator) -> Result<(), SessionError> {
        let i = self.active.ok_or(SessionError::NoActiveSession)?;
        let user = self
            .sessions
            .get(i)
            .map(|s| s.user.clone())
            .ok_or(SessionError::NoActiveSession)?;
        if !auth.authenticate(&user, secret) {
            return Err(SessionError::AuthFailed);
        }
        if let Some(s) = self.sessions.get_mut(i) {
            s.locked = false;
            s.idle_ms = 0;
        }
        Ok(())
    }

    /// Advance the idle clock of the active session by `delta_ms`; auto-locks it
    /// once the idle timeout is reached (WS7-15.5). Returns whether it locked.
    pub fn tick_idle(&mut self, delta_ms: u64) -> bool {
        if self.idle_timeout_ms == 0 {
            return false;
        }
        let Some(i) = self.active else { return false };
        if let Some(s) = self.sessions.get_mut(i) {
            if s.locked {
                return false;
            }
            s.idle_ms = s.idle_ms.saturating_add(delta_ms);
            if s.idle_ms >= self.idle_timeout_ms {
                s.locked = true;
                return true;
            }
        }
        false
    }

    /// Register user activity, resetting the active session's idle clock.
    pub fn activity(&mut self) {
        if let Some(s) = self.active.and_then(|i| self.sessions.get_mut(i)) {
            s.idle_ms = 0;
        }
    }

    /// Fast-switch the active session to an already-running `user` (WS7-15.6).
    /// A locked target keeps its lock (the caller shows the lock screen).
    ///
    /// # Errors
    /// [`SessionError::NoSuchSession`] if `user` has no running session.
    pub fn switch_to(&mut self, user: &str) -> Result<(), SessionError> {
        let i = self
            .session_index(user)
            .ok_or(SessionError::NoSuchSession)?;
        self.active = Some(i);
        Ok(())
    }

    /// Log out the active session and return to the greeter (WS7-15.7).
    ///
    /// # Errors
    /// [`SessionError::NoActiveSession`] if nothing is active.
    pub fn logout(&mut self) -> Result<(), SessionError> {
        let i = self.active.ok_or(SessionError::NoActiveSession)?;
        if i < self.sessions.len() {
            self.sessions.remove(i);
        }
        self.active = None;
        Ok(())
    }

    /// The users with a currently running session (for fast-switch menus).
    #[must_use]
    pub fn running_users(&self) -> Vec<&str> {
        self.sessions.iter().map(|s| s.user.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts `secret == b"pw:" ++ user`.
    struct StubAuth;
    impl Authenticator for StubAuth {
        fn authenticate(&self, user: &str, secret: &[u8]) -> bool {
            let mut expected = alloc::vec![b'p', b'w', b':'];
            expected.extend_from_slice(user.as_bytes());
            secret == expected.as_slice()
        }
    }

    fn pw(user: &str) -> Vec<u8> {
        let mut v = alloc::vec![b'p', b'w', b':'];
        v.extend_from_slice(user.as_bytes());
        v
    }

    #[test]
    fn login_requires_valid_credentials() {
        let mut sm = SessionManager::new(&["alice", "bob"], 0);
        assert_eq!(sm.view(), SessionView::Greeter);
        assert_eq!(sm.greeter_users(), ["alice", "bob"]);
        assert_eq!(
            sm.login("alice", b"wrong", &StubAuth),
            Err(SessionError::AuthFailed)
        );
        assert_eq!(sm.view(), SessionView::Greeter);
        sm.login("alice", &pw("alice"), &StubAuth).unwrap();
        assert_eq!(sm.view(), SessionView::Active("alice".to_string()));
    }

    #[test]
    fn lock_and_unlock() {
        let mut sm = SessionManager::new(&["alice"], 0);
        sm.login("alice", &pw("alice"), &StubAuth).unwrap();
        sm.lock().unwrap();
        assert_eq!(sm.view(), SessionView::Locked("alice".to_string()));
        assert_eq!(
            sm.unlock(b"wrong", &StubAuth),
            Err(SessionError::AuthFailed)
        );
        assert_eq!(sm.view(), SessionView::Locked("alice".to_string()));
        sm.unlock(&pw("alice"), &StubAuth).unwrap();
        assert_eq!(sm.view(), SessionView::Active("alice".to_string()));
    }

    #[test]
    fn idle_timeout_auto_locks() {
        let mut sm = SessionManager::new(&["alice"], 1000);
        sm.login("alice", &pw("alice"), &StubAuth).unwrap();
        assert!(!sm.tick_idle(500));
        assert_eq!(sm.view(), SessionView::Active("alice".to_string()));
        assert!(sm.tick_idle(500)); // reaches 1000 → locks
        assert_eq!(sm.view(), SessionView::Locked("alice".to_string()));
        // Activity before the threshold resets the clock.
        let mut sm2 = SessionManager::new(&["alice"], 1000);
        sm2.login("alice", &pw("alice"), &StubAuth).unwrap();
        sm2.tick_idle(900);
        sm2.activity();
        assert!(!sm2.tick_idle(500));
    }

    #[test]
    fn fast_switch_and_logout() {
        let mut sm = SessionManager::new(&["alice", "bob"], 0);
        sm.login("alice", &pw("alice"), &StubAuth).unwrap();
        sm.lock().unwrap(); // alice stays running but locked
        sm.login("bob", &pw("bob"), &StubAuth).unwrap();
        assert_eq!(sm.view(), SessionView::Active("bob".to_string()));
        assert_eq!(sm.running_users(), ["alice", "bob"]);

        // Switch back to alice: her session is still locked.
        sm.switch_to("alice").unwrap();
        assert_eq!(sm.view(), SessionView::Locked("alice".to_string()));
        assert_eq!(sm.switch_to("carol"), Err(SessionError::NoSuchSession));

        // Logout returns to greeter and drops the session.
        sm.unlock(&pw("alice"), &StubAuth).unwrap();
        sm.logout().unwrap();
        assert_eq!(sm.view(), SessionView::Greeter);
        assert_eq!(sm.running_users(), ["bob"]);
    }
}

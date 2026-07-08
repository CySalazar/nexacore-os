//! User-store schema, per-user privileges, home-key derivation, and account
//! creation (WS12-05.1/.5/.6/.7).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    AuthError,
    hash::{Credential, PasswordHasher, make_credential},
};

/// A user identifier.
pub type Uid = u32;

/// The first uid handed to a regular user; `0..FIRST_USER_UID` is reserved for
/// root and system accounts.
pub const FIRST_USER_UID: Uid = 1000;

/// The maximum length of a login name.
pub const MAX_USERNAME_LEN: usize = 32;

/// Whether `username` is a valid login name.
///
/// A name must be 1..=[`MAX_USERNAME_LEN`] bytes, drawn from `[a-z0-9_-]`, and
/// begin with a lowercase letter or underscore. This is deliberately strict: it
/// rejects `.`, `..`, path separators, NUL, control bytes, non-ASCII, and
/// uppercase, so the name can never traverse or escape the derived
/// `/home/<username>` path, nor collide by case (WS12-05 hardening).
#[must_use]
pub fn is_valid_username(username: &str) -> bool {
    let bytes = username.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_USERNAME_LEN {
        return false;
    }
    let first_ok = matches!(bytes.first(), Some(&b) if b.is_ascii_lowercase() || b == b'_');
    first_ok
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Per-user privileges: an admin flag — the per-user root capability — plus a
/// set of named fine-grained capabilities (WS12-05.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Privileges {
    admin: bool,
    capabilities: BTreeSet<String>,
}

impl Privileges {
    /// Unprivileged (no admin, no capabilities).
    #[must_use]
    pub fn user() -> Self {
        Self::default()
    }

    /// An administrator (the per-user root capability).
    #[must_use]
    pub fn admin() -> Self {
        Self {
            admin: true,
            capabilities: BTreeSet::new(),
        }
    }

    /// Whether the user holds the root capability.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.admin
    }

    /// Grant a named capability.
    pub fn grant(&mut self, capability: &str) {
        self.capabilities.insert(capability.to_string());
    }

    /// Revoke a named capability, returning whether it was held.
    pub fn revoke(&mut self, capability: &str) -> bool {
        self.capabilities.remove(capability)
    }

    /// Whether the user may perform `capability`: an admin may do anything;
    /// others need the specific grant.
    #[must_use]
    pub fn can(&self, capability: &str) -> bool {
        self.admin || self.capabilities.contains(capability)
    }
}

/// A user account record (the store schema).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// The user's numeric identifier.
    pub uid: Uid,
    /// The login name (unique, no path separator).
    pub username: String,
    /// The password credential.
    pub credential: Credential,
    /// The home directory path (`/home/<username>`).
    pub home: String,
    /// The user's privileges.
    pub privileges: Privileges,
    /// Creation timestamp (ns since epoch; `0` if no clock).
    pub created_ns: u64,
}

/// The user store: uid → record, with a name index.
#[derive(Debug, Clone, Default)]
pub struct UserStore {
    by_uid: BTreeMap<Uid, UserRecord>,
    by_name: BTreeMap<String, Uid>,
}

impl UserStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of registered users.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_uid.len()
    }

    /// Whether the store has no users.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_uid.is_empty()
    }

    /// The record for `uid`, if present.
    #[must_use]
    pub fn get(&self, uid: Uid) -> Option<&UserRecord> {
        self.by_uid.get(&uid)
    }

    /// The record for `username`, if present.
    #[must_use]
    pub fn get_by_name(&self, username: &str) -> Option<&UserRecord> {
        self.by_name
            .get(username)
            .and_then(|uid| self.by_uid.get(uid))
    }

    /// Whether a user with `username` exists.
    #[must_use]
    pub fn contains_name(&self, username: &str) -> bool {
        self.by_name.contains_key(username)
    }

    /// Iterate the records in ascending uid order.
    pub fn iter(&self) -> impl Iterator<Item = &UserRecord> {
        self.by_uid.values()
    }

    /// The lowest free uid at or above [`FIRST_USER_UID`].
    #[must_use]
    pub fn next_uid(&self) -> Uid {
        use core::cmp::Ordering;
        let mut candidate = FIRST_USER_UID;
        for &uid in self.by_uid.keys() {
            match uid.cmp(&candidate) {
                Ordering::Equal => candidate = candidate.saturating_add(1),
                Ordering::Greater => break,
                Ordering::Less => {}
            }
        }
        candidate
    }

    /// Insert `record`, failing if its uid or username is already taken.
    ///
    /// # Errors
    /// [`AuthError::UidTaken`] or [`AuthError::UsernameTaken`] on a collision.
    pub fn insert(&mut self, record: UserRecord) -> Result<(), AuthError> {
        if self.by_uid.contains_key(&record.uid) {
            return Err(AuthError::UidTaken);
        }
        if self.by_name.contains_key(&record.username) {
            return Err(AuthError::UsernameTaken);
        }
        self.by_name.insert(record.username.clone(), record.uid);
        self.by_uid.insert(record.uid, record);
        Ok(())
    }

    /// Remove the user `uid`, returning the record if it existed.
    pub fn remove(&mut self, uid: Uid) -> Option<UserRecord> {
        let record = self.by_uid.remove(&uid)?;
        self.by_name.remove(&record.username);
        Some(record)
    }
}

/// Derive a per-user home encryption key from the user's secret material.
///
/// Uses BLAKE3 key-derivation-mode with a fixed context, bound to the uid and a
/// per-user salt, so two users (or two installs) never share a home key even
/// with the same secret. The `user_secret` is the volume/KEK material the FDE
/// layer (`nexacore_fs::v3::fde`) recovers — this crate only derives the
/// per-user subkey; it never persists the secret.
#[must_use]
pub fn derive_home_key(user_secret: &[u8], uid: Uid, salt: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("NexaCore-home-key-v1");
    hasher.update(&uid.to_le_bytes());
    hasher.update(salt);
    hasher.update(user_secret);
    *hasher.finalize().as_bytes()
}

/// Create a new account: validate the name, hash the password, assign the next
/// uid, set the home to `/home/<username>`, and insert the record.
///
/// # Errors
/// [`AuthError::InvalidUsername`] if `username` is empty or contains `/`;
/// [`AuthError::UsernameTaken`] if the name is in use; other [`AuthError`]s from
/// [`UserStore::insert`].
#[allow(clippy::too_many_arguments)]
pub fn create_account<H: PasswordHasher>(
    store: &mut UserStore,
    hasher: &H,
    username: &str,
    password: &[u8],
    salt: &[u8],
    privileges: Privileges,
    created_ns: u64,
) -> Result<Uid, AuthError> {
    if !is_valid_username(username) {
        return Err(AuthError::InvalidUsername);
    }
    if store.contains_name(username) {
        return Err(AuthError::UsernameTaken);
    }
    let uid = store.next_uid();
    let mut home = String::from("/home/");
    home.push_str(username);
    // Bind the uid into the effective salt so two accounts that share a
    // caller-supplied salt (or a weak/reused one) never produce the same digest
    // for the same password — defence-in-depth against salt reuse.
    let mut effective_salt = Vec::with_capacity(salt.len() + 4);
    effective_salt.extend_from_slice(salt);
    effective_salt.extend_from_slice(&uid.to_le_bytes());
    let record = UserRecord {
        uid,
        username: username.to_string(),
        credential: make_credential(hasher, password, &effective_salt),
        home,
        privileges,
        created_ns,
    };
    store.insert(record)?;
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Blake3Hasher, verify};

    fn hasher() -> Blake3Hasher {
        Blake3Hasher::new(2)
    }

    #[test]
    fn create_account_assigns_uid_home_and_credential() {
        let mut store = UserStore::new();
        let h = hasher();
        let uid = create_account(
            &mut store,
            &h,
            "alice",
            b"pw",
            b"salt",
            Privileges::admin(),
            42,
        )
        .unwrap();
        assert_eq!(uid, FIRST_USER_UID);
        let alice = store.get(uid).unwrap();
        assert_eq!(alice.username, "alice");
        assert_eq!(alice.home, "/home/alice");
        assert_eq!(alice.created_ns, 42);
        assert!(alice.privileges.is_admin());
        assert!(verify(&h, &alice.credential, b"pw"));
    }

    #[test]
    fn second_account_gets_next_uid_and_names_are_unique() {
        let mut store = UserStore::new();
        let h = hasher();
        let a = create_account(&mut store, &h, "a", b"x", b"s", Privileges::user(), 0).unwrap();
        let b = create_account(&mut store, &h, "b", b"y", b"s", Privileges::user(), 0).unwrap();
        assert_eq!((a, b), (1000, 1001));
        assert_eq!(store.len(), 2);
        // Duplicate name is refused.
        assert_eq!(
            create_account(&mut store, &h, "a", b"z", b"s", Privileges::user(), 0).err(),
            Some(AuthError::UsernameTaken)
        );
        // Bad names are refused.
        assert_eq!(
            create_account(&mut store, &h, "", b"z", b"s", Privileges::user(), 0).err(),
            Some(AuthError::InvalidUsername)
        );
        assert_eq!(
            create_account(&mut store, &h, "a/b", b"z", b"s", Privileges::user(), 0).err(),
            Some(AuthError::InvalidUsername)
        );
    }

    #[test]
    fn username_validation_blocks_traversal_and_injection() {
        // Path-traversal and injection attempts never reach the store.
        assert!(!is_valid_username(".."));
        assert!(!is_valid_username("."));
        assert!(!is_valid_username("../etc"));
        assert!(!is_valid_username("a\0b"));
        assert!(!is_valid_username("a b"));
        assert!(!is_valid_username("Alice")); // uppercase → case-collision risk
        assert!(!is_valid_username("1abc")); // must start with a letter/underscore
        assert!(!is_valid_username(&"a".repeat(MAX_USERNAME_LEN + 1)));
        // Well-formed names pass.
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("_svc-worker_01"));

        let mut store = UserStore::new();
        let h = hasher();
        assert_eq!(
            create_account(&mut store, &h, "..", b"x", b"s", Privileges::user(), 0).err(),
            Some(AuthError::InvalidUsername)
        );
        assert!(store.is_empty(), "no traversal name was ever inserted");
    }

    #[test]
    fn next_uid_reuses_the_lowest_gap() {
        let mut store = UserStore::new();
        let h = hasher();
        create_account(&mut store, &h, "a", b"x", b"s", Privileges::user(), 0).unwrap();
        let b = create_account(&mut store, &h, "b", b"x", b"s", Privileges::user(), 0).unwrap();
        create_account(&mut store, &h, "c", b"x", b"s", Privileges::user(), 0).unwrap();
        store.remove(b);
        // 1001 freed → the next account reuses it.
        let d = create_account(&mut store, &h, "d", b"x", b"s", Privileges::user(), 0).unwrap();
        assert_eq!(d, 1001);
        assert!(store.get_by_name("b").is_none());
    }

    #[test]
    fn privileges_gate_capabilities() {
        let mut user = Privileges::user();
        assert!(!user.can("net.bind"));
        user.grant("net.bind");
        assert!(user.can("net.bind"));
        assert!(!user.can("disk.format"));
        assert!(user.revoke("net.bind"));
        assert!(!user.can("net.bind"));
        // An admin can do anything without explicit grants.
        assert!(Privileges::admin().can("disk.format"));
    }

    #[test]
    fn same_password_and_salt_yield_distinct_digests_per_user() {
        let mut store = UserStore::new();
        let h = hasher();
        // Two users, identical password AND caller salt.
        let a = create_account(&mut store, &h, "a", b"pw", b"s", Privileges::user(), 0).unwrap();
        let b = create_account(&mut store, &h, "b", b"pw", b"s", Privileges::user(), 0).unwrap();
        let da = &store.get(a).unwrap().credential.hash;
        let db = &store.get(b).unwrap().credential.hash;
        assert_ne!(da, db, "uid-bound salt must separate identical passwords");
        // Each still verifies its own password.
        assert!(verify(&h, &store.get(a).unwrap().credential, b"pw"));
        assert!(verify(&h, &store.get(b).unwrap().credential, b"pw"));
    }

    #[test]
    fn home_key_is_per_user_and_deterministic() {
        let secret = b"volume-kek-material";
        let k1 = derive_home_key(secret, 1000, b"s");
        assert_eq!(k1, derive_home_key(secret, 1000, b"s"), "deterministic");
        // Different uid or salt → unrelated key.
        assert_ne!(k1, derive_home_key(secret, 1001, b"s"));
        assert_ne!(k1, derive_home_key(secret, 1000, b"t"));
    }
}

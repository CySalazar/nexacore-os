//! The typed configuration store: layered values, transactions, watch/notify
//! and capability-gated writes (WS17-01.2/.5/.6/.7/.8).

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::{ConfigError, Key, schema::SchemaRegistry, value::ConfigValue};

// ---------------------------------------------------------------------------
// Persistence backend (WS17-01.2)
// ---------------------------------------------------------------------------

/// Persistence backend for the **system layer** of the store (WS17-01.2).
///
/// The production backend is VFS-backed (WS3-02) so configuration survives
/// reboots; [`MemoryBackend`] is the in-memory implementation used by host
/// tests and early bring-up.
pub trait ConfigBackend {
    /// Load the persisted system value for `key`, if any.
    fn load(&self, key: &Key) -> Option<ConfigValue>;
    /// Persist `value` as the system value for `key`.
    fn store(&mut self, key: &Key, value: &ConfigValue);
    /// Remove any persisted system value for `key`.
    fn remove(&mut self, key: &Key);
}

/// In-memory [`ConfigBackend`] (host tests / pre-VFS bring-up).
#[derive(Debug, Clone, Default)]
pub struct MemoryBackend {
    map: BTreeMap<Key, ConfigValue>,
}

impl MemoryBackend {
    /// A new, empty backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConfigBackend for MemoryBackend {
    fn load(&self, key: &Key) -> Option<ConfigValue> {
        self.map.get(key).cloned()
    }
    fn store(&mut self, key: &Key, value: &ConfigValue) {
        self.map.insert(key.clone(), value.clone());
    }
    fn remove(&mut self, key: &Key) {
        self.map.remove(key);
    }
}

// ---------------------------------------------------------------------------
// Capability gate (WS17-01.8)
// ---------------------------------------------------------------------------

/// Authorizes writes to the store — writes are **default-deny** (WS17-01.8).
///
/// The caller must present an authorizer that grants the target key. The
/// production authorizer verifies an `nexacore-capability` `CapabilityToken` whose
/// `Resource` covers the key's namespace; [`AllowAll`] / [`DenyAll`] /
/// [`PrefixAuthorizer`] are provided for tests and simple policies.
pub trait WriteAuthorizer {
    /// Whether a write to `key` is authorized.
    fn authorize(&self, key: &Key) -> bool;
}

/// Authorizer that permits every write (tests / trusted system init only).
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;
impl WriteAuthorizer for AllowAll {
    fn authorize(&self, _key: &Key) -> bool {
        true
    }
}

/// Authorizer that denies every write (the conservative default).
#[derive(Debug, Clone, Copy)]
pub struct DenyAll;
impl WriteAuthorizer for DenyAll {
    fn authorize(&self, _key: &Key) -> bool {
        false
    }
}

/// Authorizer scoped to a set of namespace prefixes: a write is allowed iff the
/// key lies within one of the granted namespaces (the shape an attenuated
/// capability takes).
#[derive(Debug, Clone, Default)]
pub struct PrefixAuthorizer {
    allowed: Vec<String>,
}

impl PrefixAuthorizer {
    /// A new authorizer granting no namespaces (deny-all until granted).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Grant write access to the `prefix` namespace (and everything under it).
    #[must_use]
    pub fn grant(mut self, prefix: &str) -> Self {
        self.allowed.push(String::from(prefix));
        self
    }
}

impl WriteAuthorizer for PrefixAuthorizer {
    fn authorize(&self, key: &Key) -> bool {
        self.allowed.iter().any(|p| key.is_in_namespace(p))
    }
}

// ---------------------------------------------------------------------------
// Users + change events + watchers (WS17-01.5/.7)
// ---------------------------------------------------------------------------

/// Identifies a user for per-user override layering (WS17-01.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(pub u64);

/// A change pushed to a matching watcher when a key's value changes.
#[derive(Debug, Clone, PartialEq)]
pub struct ChangeEvent {
    /// The key that changed.
    pub key: Key,
    /// The new value.
    pub value: ConfigValue,
    /// The user whose override changed, or `None` for a system-layer change.
    pub user: Option<UserId>,
}

/// Opaque handle to a registered watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatcherId(u64);

struct Watcher {
    id: WatcherId,
    prefix: String,
    pending: Vec<ChangeEvent>,
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// The typed configuration store (WS17-01.2).
///
/// Value resolution is layered (WS17-01.7): a per-user override wins over the
/// persisted system value, which wins over the schema default. Every write is
/// schema-validated (WS17-01.4) and capability-gated (WS17-01.8); matching
/// watchers are notified (WS17-01.5).
pub struct ConfigStore<B: ConfigBackend = MemoryBackend> {
    schema: SchemaRegistry,
    system: B,
    overrides: BTreeMap<UserId, BTreeMap<Key, ConfigValue>>,
    watchers: Vec<Watcher>,
    next_watcher: u64,
}

impl<B: ConfigBackend> ConfigStore<B> {
    /// Create a store over `schema` and persistence `backend`.
    #[must_use]
    pub fn new(schema: SchemaRegistry, backend: B) -> Self {
        Self {
            schema,
            system: backend,
            overrides: BTreeMap::new(),
            watchers: Vec::new(),
            next_watcher: 0,
        }
    }

    /// Borrow the schema registry.
    #[must_use]
    pub fn schema(&self) -> &SchemaRegistry {
        &self.schema
    }

    /// Resolve the effective value for `key` as seen by `user` (WS17-01.7):
    /// user override → system value → schema default.
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnknownKey`] if no schema is registered for `key`.
    pub fn get(&self, key: &Key, user: Option<UserId>) -> Result<ConfigValue, ConfigError> {
        let schema = self.schema.get(key).ok_or(ConfigError::UnknownKey)?;
        if let Some(uid) = user {
            if let Some(v) = self.overrides.get(&uid).and_then(|m| m.get(key)) {
                return Ok(v.clone());
            }
        }
        if let Some(v) = self.system.load(key) {
            return Ok(v);
        }
        Ok(schema.default.clone())
    }

    /// Validate a single write against the schema and the authorizer without
    /// applying it. Returns the error a real write would produce.
    fn check_write(
        &self,
        key: &Key,
        value: &ConfigValue,
        auth: &dyn WriteAuthorizer,
    ) -> Result<(), ConfigError> {
        let schema = self.schema.get(key).ok_or(ConfigError::UnknownKey)?;
        schema.ty.validate(value)?;
        if auth.authorize(key) {
            Ok(())
        } else {
            Err(ConfigError::Unauthorized)
        }
    }

    /// Set the **system-layer** value for `key` (WS17-01.2). Validated and
    /// capability-gated; notifies matching watchers on success.
    ///
    /// # Errors
    ///
    /// `UnknownKey`, a validation error, or `Unauthorized` — in which case
    /// nothing is written.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "owned ConfigValue is the ergonomic write API; it is cloned into the backend + watchers"
    )]
    pub fn set(
        &mut self,
        key: &Key,
        value: ConfigValue,
        auth: &dyn WriteAuthorizer,
    ) -> Result<(), ConfigError> {
        self.check_write(key, &value, auth)?;
        self.system.store(key, &value);
        self.notify(key, &value, None);
        Ok(())
    }

    /// Set a **per-user override** for `key` (WS17-01.7). Validated and
    /// capability-gated; notifies matching watchers on success.
    ///
    /// # Errors
    ///
    /// As [`Self::set`].
    #[allow(
        clippy::needless_pass_by_value,
        reason = "owned ConfigValue is the ergonomic write API; it is cloned into the override map + watchers"
    )]
    pub fn set_user_override(
        &mut self,
        user: UserId,
        key: &Key,
        value: ConfigValue,
        auth: &dyn WriteAuthorizer,
    ) -> Result<(), ConfigError> {
        self.check_write(key, &value, auth)?;
        self.overrides
            .entry(user)
            .or_default()
            .insert(key.clone(), value.clone());
        self.notify(key, &value, Some(user));
        Ok(())
    }

    /// Apply several system-layer writes **atomically** (WS17-01.6): every
    /// write is validated and authorized first; if any fails, none are applied.
    ///
    /// # Errors
    ///
    /// The first validation/authorization error encountered. On error the
    /// store is unchanged.
    pub fn transaction(
        &mut self,
        writes: &[(Key, ConfigValue)],
        auth: &dyn WriteAuthorizer,
    ) -> Result<(), ConfigError> {
        // Phase 1: validate + authorize everything. No mutation yet.
        for (key, value) in writes {
            self.check_write(key, value, auth)?;
        }
        // Phase 2: all checks passed — apply + notify.
        for (key, value) in writes {
            self.system.store(key, value);
            self.notify(key, value, None);
        }
        Ok(())
    }

    /// Register a watcher for all keys in the `prefix` namespace (empty prefix
    /// = every key) (WS17-01.5). Returns its [`WatcherId`].
    pub fn watch(&mut self, prefix: &str) -> WatcherId {
        let id = WatcherId(self.next_watcher);
        self.next_watcher += 1;
        self.watchers.push(Watcher {
            id,
            prefix: String::from(prefix),
            pending: Vec::new(),
        });
        id
    }

    /// Drain and return the pending change events for `watcher` (WS17-01.5).
    /// Returns an empty vec for an unknown or idle watcher.
    pub fn poll(&mut self, watcher: WatcherId) -> Vec<ChangeEvent> {
        self.watchers
            .iter_mut()
            .find(|w| w.id == watcher)
            .map(|w| core::mem::take(&mut w.pending))
            .unwrap_or_default()
    }

    /// Stop and remove `watcher`.
    pub fn unwatch(&mut self, watcher: WatcherId) {
        self.watchers.retain(|w| w.id != watcher);
    }

    /// Enqueue a change event to every watcher whose namespace contains `key`.
    fn notify(&mut self, key: &Key, value: &ConfigValue, user: Option<UserId>) {
        for w in &mut self.watchers {
            if key.is_in_namespace(&w.prefix) {
                w.pending.push(ChangeEvent {
                    key: key.clone(),
                    value: value.clone(),
                    user,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use super::*;
    use crate::{
        schema::KeySchema,
        value::{ConfigValue, ValueType},
    };

    fn theme_registry() -> SchemaRegistry {
        let mut reg = SchemaRegistry::new();
        reg.register(
            Key::new("desktop.theme.mode").unwrap(),
            KeySchema::new(
                ValueType::Enum(&["light", "dark", "auto"]),
                ConfigValue::Str("auto".to_string()),
                "theme mode",
            )
            .unwrap(),
        );
        reg.register(
            Key::new("desktop.theme.density").unwrap(),
            KeySchema::new(
                ValueType::Int { min: 0, max: 2 },
                ConfigValue::Int(1),
                "ui density",
            )
            .unwrap(),
        );
        reg
    }

    fn store() -> ConfigStore<MemoryBackend> {
        ConfigStore::new(theme_registry(), MemoryBackend::new())
    }

    #[test]
    fn get_returns_schema_default_when_unset() {
        let s = store();
        let k = Key::new("desktop.theme.mode").unwrap();
        assert_eq!(
            s.get(&k, None).unwrap(),
            ConfigValue::Str("auto".to_string())
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        let s = store();
        let k = Key::new("nope.missing").unwrap();
        assert_eq!(s.get(&k, None), Err(ConfigError::UnknownKey));
    }

    #[test]
    fn set_persists_to_system_layer_and_get_reads_it() {
        let mut s = store();
        let k = Key::new("desktop.theme.mode").unwrap();
        s.set(&k, ConfigValue::Str("dark".to_string()), &AllowAll)
            .unwrap();
        assert_eq!(
            s.get(&k, None).unwrap(),
            ConfigValue::Str("dark".to_string())
        );
    }

    #[test]
    fn set_validates_against_schema() {
        let mut s = store();
        let k = Key::new("desktop.theme.density").unwrap();
        // Out of range (max 2): rejected and not written (WS17-01.4).
        assert_eq!(
            s.set(&k, ConfigValue::Int(9), &AllowAll),
            Err(ConfigError::OutOfRange)
        );
        assert_eq!(s.get(&k, None).unwrap(), ConfigValue::Int(1)); // still default
        // Wrong enum variant rejected.
        let m = Key::new("desktop.theme.mode").unwrap();
        assert_eq!(
            s.set(&m, ConfigValue::Str("blue".to_string()), &AllowAll),
            Err(ConfigError::NotAllowedValue)
        );
    }

    #[test]
    fn writes_are_default_deny_capability_gated() {
        let mut s = store();
        let k = Key::new("desktop.theme.mode").unwrap();
        // DenyAll → rejected, nothing written (WS17-01.8).
        assert_eq!(
            s.set(&k, ConfigValue::Str("dark".to_string()), &DenyAll),
            Err(ConfigError::Unauthorized)
        );
        assert_eq!(
            s.get(&k, None).unwrap(),
            ConfigValue::Str("auto".to_string())
        );
        // A prefix-scoped capability grants only its namespace.
        let cap = PrefixAuthorizer::new().grant("desktop.theme");
        assert!(
            s.set(&k, ConfigValue::Str("dark".to_string()), &cap)
                .is_ok()
        );
        let other = PrefixAuthorizer::new().grant("net");
        assert_eq!(
            s.set(&k, ConfigValue::Str("light".to_string()), &other),
            Err(ConfigError::Unauthorized)
        );
    }

    #[test]
    fn user_override_shadows_system_then_default() {
        let mut s = store();
        let k = Key::new("desktop.theme.mode").unwrap();
        let alice = UserId(1);
        // System value set; Alice has no override yet → sees system value.
        s.set(&k, ConfigValue::Str("dark".to_string()), &AllowAll)
            .unwrap();
        assert_eq!(
            s.get(&k, Some(alice)).unwrap(),
            ConfigValue::Str("dark".to_string())
        );
        // Alice overrides → sees her own value; system + other users unaffected.
        s.set_user_override(alice, &k, ConfigValue::Str("light".to_string()), &AllowAll)
            .unwrap();
        assert_eq!(
            s.get(&k, Some(alice)).unwrap(),
            ConfigValue::Str("light".to_string())
        );
        assert_eq!(
            s.get(&k, None).unwrap(),
            ConfigValue::Str("dark".to_string())
        );
        assert_eq!(
            s.get(&k, Some(UserId(2))).unwrap(),
            ConfigValue::Str("dark".to_string())
        );
    }

    #[test]
    fn watch_notify_is_prefix_scoped() {
        let mut s = store();
        let w_theme = s.watch("desktop.theme");
        let w_net = s.watch("net");
        let k = Key::new("desktop.theme.mode").unwrap();
        s.set(&k, ConfigValue::Str("dark".to_string()), &AllowAll)
            .unwrap();
        // The theme watcher sees the change; the net watcher does not.
        let evs = s.poll(w_theme);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].key, k);
        assert_eq!(evs[0].value, ConfigValue::Str("dark".to_string()));
        assert!(s.poll(w_net).is_empty());
        // Draining is idempotent — a second poll yields nothing new.
        assert!(s.poll(w_theme).is_empty());
    }

    #[test]
    fn transaction_is_atomic_all_or_nothing() {
        let mut s = store();
        let mode = Key::new("desktop.theme.mode").unwrap();
        let density = Key::new("desktop.theme.density").unwrap();
        // One write is invalid (density 9 > max 2): the whole transaction fails
        // and NEITHER key is written (WS17-01.6).
        let bad = vec![
            (mode.clone(), ConfigValue::Str("dark".to_string())),
            (density.clone(), ConfigValue::Int(9)),
        ];
        assert_eq!(s.transaction(&bad, &AllowAll), Err(ConfigError::OutOfRange));
        assert_eq!(
            s.get(&mode, None).unwrap(),
            ConfigValue::Str("auto".to_string())
        );
        assert_eq!(s.get(&density, None).unwrap(), ConfigValue::Int(1));
        // A fully-valid transaction applies both.
        let good = vec![
            (mode.clone(), ConfigValue::Str("dark".to_string())),
            (density.clone(), ConfigValue::Int(2)),
        ];
        assert!(s.transaction(&good, &AllowAll).is_ok());
        assert_eq!(
            s.get(&mode, None).unwrap(),
            ConfigValue::Str("dark".to_string())
        );
        assert_eq!(s.get(&density, None).unwrap(), ConfigValue::Int(2));
    }

    #[test]
    fn transaction_rejected_by_capability_writes_nothing() {
        let mut s = store();
        let mode = Key::new("desktop.theme.mode").unwrap();
        let writes = vec![(mode.clone(), ConfigValue::Str("dark".to_string()))];
        assert_eq!(
            s.transaction(&writes, &DenyAll),
            Err(ConfigError::Unauthorized)
        );
        assert_eq!(
            s.get(&mode, None).unwrap(),
            ConfigValue::Str("auto".to_string())
        );
    }
}

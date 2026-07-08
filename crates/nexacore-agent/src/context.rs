//! Per-agent persistent context store.
//!
//! Each agent maintains its own scoped context that persists across
//! sessions but is isolated from other agents' contexts. Context data
//! is bound to a specific user + agent pair and cannot be exfiltrated
//! across agent boundaries.
//!
//! See NCIP-Agent-Arch-022 §S1.1 and `docs/04-security-model.md` § Side channels.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::agent::AgentKind;

/// A key in the context store. Scoped to (`agent_kind`, namespace, key).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContextKey {
    /// The agent this context belongs to.
    pub agent: AgentKind,
    /// Logical namespace within the agent's context.
    pub namespace: String,
    /// Key within the namespace.
    pub key: String,
}

/// A value in the context store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextValue {
    /// Opaque value bytes.
    pub data: Vec<u8>,
    /// Unix timestamp when this value was last written.
    pub updated_at: u64,
}

/// Per-agent persistent context store.
///
/// In-memory implementation for Phase 2. A future phase will back this
/// with TEE-sealed storage via `nexacore-tokenization`.
#[derive(Debug, Default)]
pub struct ContextStore {
    entries: BTreeMap<ContextKey, ContextValue>,
}

impl ContextStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Write a value into the store.
    pub fn put(&mut self, key: ContextKey, data: Vec<u8>, timestamp: u64) {
        self.entries.insert(
            key,
            ContextValue {
                data,
                updated_at: timestamp,
            },
        );
    }

    /// Read a value from the store.
    #[must_use]
    pub fn get(&self, key: &ContextKey) -> Option<&ContextValue> {
        self.entries.get(key)
    }

    /// Delete a value from the store.
    pub fn remove(&mut self, key: &ContextKey) -> Option<ContextValue> {
        self.entries.remove(key)
    }

    /// List all keys belonging to a specific agent.
    #[must_use]
    pub fn keys_for_agent(&self, agent: AgentKind) -> Vec<&ContextKey> {
        self.entries.keys().filter(|k| k.agent == agent).collect()
    }

    /// Flush all context for a specific agent (called on agent suspend
    /// to enforce KV-cache isolation).
    pub fn flush_agent(&mut self, agent: AgentKind) {
        self.entries.retain(|k, _| k.agent != agent);
    }

    /// Returns the number of entries in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(agent: AgentKind, ns: &str, k: &str) -> ContextKey {
        ContextKey {
            agent,
            namespace: ns.into(),
            key: k.into(),
        }
    }

    #[test]
    fn put_and_get() {
        let mut store = ContextStore::new();
        let k = key(AgentKind::Guidance, "session", "history");
        store.put(k.clone(), vec![1, 2, 3], 1000);
        let v = store.get(&k).unwrap();
        assert_eq!(v.data, vec![1, 2, 3]);
        assert_eq!(v.updated_at, 1000);
    }

    #[test]
    fn get_missing_returns_none() {
        let store = ContextStore::new();
        let k = key(AgentKind::SysAdmin, "config", "missing");
        assert!(store.get(&k).is_none());
    }

    #[test]
    fn remove_returns_value() {
        let mut store = ContextStore::new();
        let k = key(AgentKind::Security, "alerts", "last");
        store.put(k.clone(), vec![42], 2000);
        let removed = store.remove(&k).unwrap();
        assert_eq!(removed.data, vec![42]);
        assert!(store.get(&k).is_none());
    }

    #[test]
    fn keys_for_agent_filters_correctly() {
        let mut store = ContextStore::new();
        store.put(key(AgentKind::Guidance, "a", "1"), vec![], 0);
        store.put(key(AgentKind::Guidance, "b", "2"), vec![], 0);
        store.put(key(AgentKind::SysAdmin, "c", "3"), vec![], 0);

        let guidance_keys = store.keys_for_agent(AgentKind::Guidance);
        assert_eq!(guidance_keys.len(), 2);

        let sysadmin_keys = store.keys_for_agent(AgentKind::SysAdmin);
        assert_eq!(sysadmin_keys.len(), 1);
    }

    #[test]
    fn flush_agent_removes_only_target() {
        let mut store = ContextStore::new();
        store.put(key(AgentKind::Guidance, "a", "1"), vec![], 0);
        store.put(key(AgentKind::SysAdmin, "b", "2"), vec![], 0);

        store.flush_agent(AgentKind::Guidance);
        assert_eq!(store.len(), 1);
        assert!(store.keys_for_agent(AgentKind::Guidance).is_empty());
        assert_eq!(store.keys_for_agent(AgentKind::SysAdmin).len(), 1);
    }

    #[test]
    fn agent_isolation() {
        let mut store = ContextStore::new();
        let k1 = key(AgentKind::Guidance, "shared_ns", "secret");
        let k2 = key(AgentKind::SysAdmin, "shared_ns", "secret");

        store.put(k1.clone(), vec![1], 0);
        store.put(k2.clone(), vec![2], 0);

        assert_eq!(store.get(&k1).unwrap().data, vec![1]);
        assert_eq!(store.get(&k2).unwrap().data, vec![2]);
    }
}

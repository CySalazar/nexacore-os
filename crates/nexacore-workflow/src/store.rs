//! Config-as-code workflow store (WS16-04.8).
//!
//! A [`WorkflowStore`] is the persisted collection of a user's workflows — the
//! "config as code" surface (WS17-02): it round-trips through the workspace
//! canonical encoder, validating every workflow on the way back in, so a
//! malformed or tampered store is rejected rather than silently loaded.

use serde::{Deserialize, Serialize};

use crate::model::{Workflow, WorkflowError};

/// A validated, serializable collection of workflows (WS16-04.8).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStore {
    workflows: Vec<Workflow>,
}

impl WorkflowStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            workflows: Vec::new(),
        }
    }

    /// Add (or replace, by name) a workflow after validating it.
    ///
    /// # Errors
    ///
    /// Propagates [`Workflow::validate`](crate::model::Workflow::validate)
    /// errors; an invalid workflow never enters the store.
    pub fn upsert(&mut self, workflow: Workflow) -> Result<(), WorkflowError> {
        workflow.validate()?;
        if let Some(existing) = self.workflows.iter_mut().find(|w| w.name == workflow.name) {
            *existing = workflow;
        } else {
            self.workflows.push(workflow);
        }
        Ok(())
    }

    /// Look up a workflow by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Workflow> {
        self.workflows.iter().find(|w| w.name == name)
    }

    /// Remove a workflow by name, returning it if present.
    pub fn remove(&mut self, name: &str) -> Option<Workflow> {
        let idx = self.workflows.iter().position(|w| w.name == name)?;
        Some(self.workflows.remove(idx))
    }

    /// All stored workflows.
    #[must_use]
    pub fn workflows(&self) -> &[Workflow] {
        &self.workflows
    }

    /// Number of stored workflows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.workflows.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.workflows.is_empty()
    }

    /// Serialize the store to canonical bytes (config-as-code persistence).
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Encode`] if canonical encoding fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WorkflowError> {
        nexacore_types::wire::encode_canonical(self).map_err(|_| WorkflowError::Encode)
    }

    /// Load a store from canonical bytes, validating every workflow.
    ///
    /// A stored workflow that fails validation (e.g. a tampered file with an
    /// empty name or a malformed step) is rejected — the load is fail-closed.
    ///
    /// # Errors
    ///
    /// - [`WorkflowError::Decode`] if the bytes do not decode.
    /// - any [`Workflow::validate`](crate::model::Workflow::validate) error from
    ///   a stored workflow.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WorkflowError> {
        let store: Self =
            nexacore_types::wire::decode_canonical(bytes).map_err(|_| WorkflowError::Decode)?;
        for workflow in &store.workflows {
            workflow.validate()?;
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::model::{Action, Step, Trigger, Workflow};

    fn sample(name: &str) -> Workflow {
        Workflow::new(
            name,
            Trigger::Manual,
            vec![Step::new(
                "classify",
                Action::ClassifyFile { path: "/a".into() },
            )],
        )
    }

    #[test]
    fn upsert_adds_then_replaces_by_name() {
        let mut store = WorkflowStore::new();
        store.upsert(sample("w")).unwrap();
        assert_eq!(store.len(), 1);
        // Same name replaces (no duplicate).
        let mut updated = sample("w");
        updated.enabled = false;
        store.upsert(updated).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.get("w").unwrap().enabled);
    }

    #[test]
    fn upsert_rejects_invalid_workflow() {
        let mut store = WorkflowStore::new();
        let bad = Workflow::new("", Trigger::Manual, vec![]);
        assert_eq!(store.upsert(bad).unwrap_err(), WorkflowError::EmptyName);
        assert!(store.is_empty());
    }

    #[test]
    fn remove_returns_workflow() {
        let mut store = WorkflowStore::new();
        store.upsert(sample("w")).unwrap();
        assert!(store.remove("w").is_some());
        assert!(store.remove("w").is_none());
    }

    #[test]
    fn round_trips_through_bytes() {
        let mut store = WorkflowStore::new();
        store.upsert(sample("a")).unwrap();
        store.upsert(sample("b")).unwrap();
        let bytes = store.to_bytes().unwrap();
        let back = WorkflowStore::from_bytes(&bytes).unwrap();
        assert_eq!(back, store);
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        assert_eq!(
            WorkflowStore::from_bytes(b"\xff\xff not canonical").unwrap_err(),
            WorkflowError::Decode
        );
    }
}

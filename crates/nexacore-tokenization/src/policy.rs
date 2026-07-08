//! Policy engine: maps regulatory presets to tokenization decisions.
//!
//! NexaCore OS supports multiple regulatory regimes. Rather than hard-coding a
//! single policy, the tokenization service accepts a [`PolicyPreset`] per
//! request and consults a [`PolicyEngine`] to decide, for each detected PII
//! entity, whether it must be tokenized.
//!
//! # Preset semantics
//!
//! | Preset | Entities always tokenized |
//! |--------|--------------------------|
//! | GDPR   | `PersonName`, `Email`, `Phone`, `Address` |
//! | HIPAA  | `PersonName`, `Ssn`, `Phone`, `Address` |
//! | PCI    | `CreditCard`, `Ssn` |
//! | Strict | every known entity type (most conservative) |
//!
//! `Custom(String)` entities are always tokenized under `Strict`; other
//! presets do not tokenize them by default (they are deployment-specific
//! and unknown to the built-in policy).
//!
//! # Example
//!
//! ```
//! use nexacore_tokenization::{
//!     policy::{PolicyEngine, PolicyPreset},
//!     types::EntityType,
//! };
//!
//! let engine = PolicyEngine::new(PolicyPreset::Gdpr);
//! assert!(engine.should_tokenize(&EntityType::Email));
//! assert!(!engine.should_tokenize(&EntityType::CreditCard));
//! ```

use serde::{Deserialize, Serialize};

use crate::types::EntityType;

// =============================================================================
// PolicyPreset
// =============================================================================

/// A regulatory preset that controls which entity types are tokenized.
///
/// Each variant corresponds to a specific regulatory regime. A
/// [`PolicyEngine`] constructed from one of these presets answers
/// per-entity-type tokenization decisions consistently with that regime.
///
/// # Example
///
/// ```
/// use nexacore_tokenization::policy::PolicyPreset;
/// let preset = PolicyPreset::Hipaa;
/// assert_eq!(format!("{preset:?}"), "Hipaa");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PolicyPreset {
    /// General Data Protection Regulation (EU 2016/679).
    ///
    /// Tokenizes: `PersonName`, `Email`, `Phone`, `Address`.
    Gdpr,
    /// Health Insurance Portability and Accountability Act (U.S.).
    ///
    /// Tokenizes: `PersonName`, `Ssn`, `Phone`, `Address`.
    Hipaa,
    /// Payment Card Industry Data Security Standard.
    ///
    /// Tokenizes: `CreditCard`, `Ssn`.
    Pci,
    /// Most-conservative preset — tokenizes every known entity type,
    /// including `Custom(…)` variants.
    Strict,
}

// =============================================================================
// PolicyEngine
// =============================================================================

/// Answers per-entity-type tokenization decisions under a fixed preset.
///
/// The engine is stateless after construction: it holds only the chosen
/// [`PolicyPreset`] and applies its rules on every call to
/// [`should_tokenize`](PolicyEngine::should_tokenize).
///
/// # Example
///
/// ```
/// use nexacore_tokenization::{
///     policy::{PolicyEngine, PolicyPreset},
///     types::EntityType,
/// };
///
/// let engine = PolicyEngine::new(PolicyPreset::Strict);
/// // Under Strict, every entity type must be tokenized.
/// assert!(engine.should_tokenize(&EntityType::PersonName));
/// assert!(engine.should_tokenize(&EntityType::CreditCard));
/// assert!(engine.should_tokenize(&EntityType::Custom("internal-id".to_string())));
/// ```
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    preset: PolicyPreset,
}

impl PolicyEngine {
    /// Construct a new `PolicyEngine` from a [`PolicyPreset`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::policy::{PolicyEngine, PolicyPreset};
    ///
    /// let engine = PolicyEngine::new(PolicyPreset::Pci);
    /// ```
    #[must_use]
    pub const fn new(preset: PolicyPreset) -> Self {
        Self { preset }
    }

    /// Returns the active [`PolicyPreset`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::policy::{PolicyEngine, PolicyPreset};
    ///
    /// let engine = PolicyEngine::new(PolicyPreset::Gdpr);
    /// assert_eq!(engine.preset(), PolicyPreset::Gdpr);
    /// ```
    #[must_use]
    pub const fn preset(&self) -> PolicyPreset {
        self.preset
    }

    /// Returns `true` if `entity_type` must be tokenized under the
    /// current preset.
    ///
    /// # Decision table
    ///
    /// | Entity type  | GDPR | HIPAA | PCI  | Strict |
    /// |--------------|------|-------|------|--------|
    /// | `PersonName` | yes  | yes   | no   | yes    |
    /// | `Email`      | yes  | no    | no   | yes    |
    /// | `Phone`      | yes  | yes   | no   | yes    |
    /// | `Ssn`        | no   | yes   | yes  | yes    |
    /// | `CreditCard` | no   | no    | yes  | yes    |
    /// | `Address`    | yes  | yes   | no   | yes    |
    /// | `Custom(…)`  | no   | no    | no   | yes    |
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_tokenization::{
    ///     policy::{PolicyEngine, PolicyPreset},
    ///     types::EntityType,
    /// };
    ///
    /// let engine = PolicyEngine::new(PolicyPreset::Pci);
    /// assert!(engine.should_tokenize(&EntityType::CreditCard));
    /// assert!(engine.should_tokenize(&EntityType::Ssn));
    /// assert!(!engine.should_tokenize(&EntityType::Email));
    /// ```
    #[must_use]
    pub fn should_tokenize(&self, entity_type: &EntityType) -> bool {
        match self.preset {
            PolicyPreset::Gdpr => matches!(
                entity_type,
                EntityType::PersonName
                    | EntityType::Email
                    | EntityType::Phone
                    | EntityType::Address
            ),
            PolicyPreset::Hipaa => matches!(
                entity_type,
                EntityType::PersonName | EntityType::Ssn | EntityType::Phone | EntityType::Address
            ),
            PolicyPreset::Pci => {
                matches!(entity_type, EntityType::CreditCard | EntityType::Ssn)
            }
            // Strict tokenizes every entity type, including Custom variants.
            PolicyPreset::Strict => true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    // -------------------------------------------------------------------------
    // GDPR preset
    // -------------------------------------------------------------------------

    #[test]
    fn gdpr_tokenizes_person_name() {
        let e = PolicyEngine::new(PolicyPreset::Gdpr);
        assert!(e.should_tokenize(&EntityType::PersonName));
    }

    #[test]
    fn gdpr_tokenizes_email() {
        let e = PolicyEngine::new(PolicyPreset::Gdpr);
        assert!(e.should_tokenize(&EntityType::Email));
    }

    #[test]
    fn gdpr_tokenizes_phone() {
        let e = PolicyEngine::new(PolicyPreset::Gdpr);
        assert!(e.should_tokenize(&EntityType::Phone));
    }

    #[test]
    fn gdpr_tokenizes_address() {
        let e = PolicyEngine::new(PolicyPreset::Gdpr);
        assert!(e.should_tokenize(&EntityType::Address));
    }

    #[test]
    fn gdpr_does_not_tokenize_ssn() {
        let e = PolicyEngine::new(PolicyPreset::Gdpr);
        assert!(!e.should_tokenize(&EntityType::Ssn));
    }

    #[test]
    fn gdpr_does_not_tokenize_credit_card() {
        let e = PolicyEngine::new(PolicyPreset::Gdpr);
        assert!(!e.should_tokenize(&EntityType::CreditCard));
    }

    #[test]
    fn gdpr_does_not_tokenize_custom() {
        let e = PolicyEngine::new(PolicyPreset::Gdpr);
        assert!(!e.should_tokenize(&EntityType::Custom("employee-id".to_string())));
    }

    // -------------------------------------------------------------------------
    // HIPAA preset
    // -------------------------------------------------------------------------

    #[test]
    fn hipaa_tokenizes_person_name() {
        let e = PolicyEngine::new(PolicyPreset::Hipaa);
        assert!(e.should_tokenize(&EntityType::PersonName));
    }

    #[test]
    fn hipaa_tokenizes_ssn() {
        let e = PolicyEngine::new(PolicyPreset::Hipaa);
        assert!(e.should_tokenize(&EntityType::Ssn));
    }

    #[test]
    fn hipaa_tokenizes_phone() {
        let e = PolicyEngine::new(PolicyPreset::Hipaa);
        assert!(e.should_tokenize(&EntityType::Phone));
    }

    #[test]
    fn hipaa_tokenizes_address() {
        let e = PolicyEngine::new(PolicyPreset::Hipaa);
        assert!(e.should_tokenize(&EntityType::Address));
    }

    #[test]
    fn hipaa_does_not_tokenize_email() {
        let e = PolicyEngine::new(PolicyPreset::Hipaa);
        assert!(!e.should_tokenize(&EntityType::Email));
    }

    #[test]
    fn hipaa_does_not_tokenize_credit_card() {
        let e = PolicyEngine::new(PolicyPreset::Hipaa);
        assert!(!e.should_tokenize(&EntityType::CreditCard));
    }

    // -------------------------------------------------------------------------
    // PCI preset
    // -------------------------------------------------------------------------

    #[test]
    fn pci_tokenizes_credit_card() {
        let e = PolicyEngine::new(PolicyPreset::Pci);
        assert!(e.should_tokenize(&EntityType::CreditCard));
    }

    #[test]
    fn pci_tokenizes_ssn() {
        let e = PolicyEngine::new(PolicyPreset::Pci);
        assert!(e.should_tokenize(&EntityType::Ssn));
    }

    #[test]
    fn pci_does_not_tokenize_person_name() {
        let e = PolicyEngine::new(PolicyPreset::Pci);
        assert!(!e.should_tokenize(&EntityType::PersonName));
    }

    #[test]
    fn pci_does_not_tokenize_email() {
        let e = PolicyEngine::new(PolicyPreset::Pci);
        assert!(!e.should_tokenize(&EntityType::Email));
    }

    #[test]
    fn pci_does_not_tokenize_phone() {
        let e = PolicyEngine::new(PolicyPreset::Pci);
        assert!(!e.should_tokenize(&EntityType::Phone));
    }

    #[test]
    fn pci_does_not_tokenize_address() {
        let e = PolicyEngine::new(PolicyPreset::Pci);
        assert!(!e.should_tokenize(&EntityType::Address));
    }

    // -------------------------------------------------------------------------
    // Strict preset
    // -------------------------------------------------------------------------

    #[test]
    fn strict_tokenizes_all_known_types() {
        let e = PolicyEngine::new(PolicyPreset::Strict);
        let all = [
            EntityType::PersonName,
            EntityType::Email,
            EntityType::Phone,
            EntityType::Ssn,
            EntityType::CreditCard,
            EntityType::Address,
            EntityType::Custom("anything".to_string()),
        ];
        for et in &all {
            assert!(e.should_tokenize(et), "Strict must tokenize {et:?}");
        }
    }

    // -------------------------------------------------------------------------
    // Accessor
    // -------------------------------------------------------------------------

    #[test]
    fn preset_accessor_returns_configured_preset() {
        let e = PolicyEngine::new(PolicyPreset::Hipaa);
        assert_eq!(e.preset(), PolicyPreset::Hipaa);
    }
}

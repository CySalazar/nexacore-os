//! Personal-cluster device trust store: pinning + trust-on-first-use (WS6-01.8).
//!
//! Once a NexaCore device joins the personal cluster its identity is *pinned*:
//! the trust store remembers the device's public-key fingerprint keyed by its
//! mesh node id. On every later contact the presented fingerprint must match the
//! pin — a different fingerprint is a [`TrustDecision::Mismatch`] (an
//! unauthorised key change, e.g. a LAN man-in-the-middle), which is rejected and
//! **does not overwrite** the stored pin.
//!
//! Fingerprints are opaque bytes here (a hash such as SHA-256 computed by the
//! vetted crypto layer); this module is the pure trust *policy* — pinning, TOFU,
//! mismatch detection and revocation — host-testable with no cryptography of its
//! own. A legitimate key rotation is applied only through an explicit
//! [`TrustStore::pin`], which represents an operator (or an authenticated
//! rotation flow) authorising the new key.

use std::{collections::BTreeMap, string::String, vec::Vec};

/// A pinned cluster device: its node id, the pinned public-key fingerprint, and
/// whether it has been revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedDevice {
    /// The device's mesh node id.
    pub node_id: String,
    /// The pinned public-key fingerprint (opaque bytes).
    pub fingerprint: Vec<u8>,
    /// Whether the device has been revoked (kept so a revoked key stays denied).
    pub revoked: bool,
}

/// The outcome of presenting a device's fingerprint to the [`TrustStore`]
/// (WS6-01.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// The device was unknown and has now been pinned and trusted (TOFU).
    PinnedFirstUse,
    /// The presented fingerprint matches the existing pin.
    AlreadyTrusted,
    /// The presented fingerprint differs from the pin — rejected, and the pin is
    /// left untouched.
    Mismatch {
        /// The pinned fingerprint.
        expected: Vec<u8>,
        /// The fingerprint that was presented.
        presented: Vec<u8>,
    },
    /// The device is present but revoked — rejected.
    Revoked,
    /// The device is unknown and trust-on-first-use is disabled — rejected.
    UnknownRejected,
}

impl TrustDecision {
    /// Whether this decision means the device is trusted for this contact.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::PinnedFirstUse | Self::AlreadyTrusted)
    }
}

/// A store of pinned cluster device identities (WS6-01.8).
///
/// `allow_tofu` controls whether an unknown device is pinned on first contact
/// (trust-on-first-use) or rejected until it is explicitly [`pin`]ned.
///
/// [`pin`]: TrustStore::pin
#[derive(Debug, Clone)]
pub struct TrustStore {
    devices: BTreeMap<String, PinnedDevice>,
    allow_tofu: bool,
}

impl TrustStore {
    /// A new, empty trust store. `allow_tofu` enables trust-on-first-use.
    #[must_use]
    pub fn new(allow_tofu: bool) -> Self {
        Self {
            devices: BTreeMap::new(),
            allow_tofu,
        }
    }

    /// Whether trust-on-first-use is enabled.
    #[must_use]
    pub fn allows_tofu(&self) -> bool {
        self.allow_tofu
    }

    /// Explicitly pin (or re-pin) `node_id` to `fingerprint`, clearing any
    /// revoked flag (WS6-01.8).
    ///
    /// This is the authorised way to record a key — including a rotation to a new
    /// key — and always overwrites any prior pin. Use [`observe`] for the runtime
    /// path, which never overwrites on mismatch.
    ///
    /// [`observe`]: TrustStore::observe
    pub fn pin(&mut self, node_id: &str, fingerprint: &[u8]) {
        self.devices.insert(
            node_id.to_string(),
            PinnedDevice {
                node_id: node_id.to_string(),
                fingerprint: fingerprint.to_vec(),
                revoked: false,
            },
        );
    }

    /// Present `node_id`'s `fingerprint` on contact and decide trust (WS6-01.8).
    ///
    /// - Unknown device: pinned and trusted if TOFU is enabled
    ///   ([`TrustDecision::PinnedFirstUse`]), else rejected
    ///   ([`TrustDecision::UnknownRejected`]).
    /// - Known device: [`TrustDecision::AlreadyTrusted`] when the fingerprint
    ///   matches, [`TrustDecision::Revoked`] when revoked, otherwise
    ///   [`TrustDecision::Mismatch`] — and the stored pin is **not** changed.
    pub fn observe(&mut self, node_id: &str, fingerprint: &[u8]) -> TrustDecision {
        match self.devices.get(node_id) {
            Some(dev) => {
                if dev.revoked {
                    TrustDecision::Revoked
                } else if dev.fingerprint == fingerprint {
                    TrustDecision::AlreadyTrusted
                } else {
                    TrustDecision::Mismatch {
                        expected: dev.fingerprint.clone(),
                        presented: fingerprint.to_vec(),
                    }
                }
            }
            None if self.allow_tofu => {
                self.pin(node_id, fingerprint);
                TrustDecision::PinnedFirstUse
            }
            None => TrustDecision::UnknownRejected,
        }
    }

    /// Whether `node_id` is currently trusted for `fingerprint`, without any side
    /// effect (WS6-01.8).
    ///
    /// A pure read: `true` only when the device is pinned, not revoked, and the
    /// fingerprint matches. Unlike [`observe`] it never pins an unknown device.
    ///
    /// [`observe`]: TrustStore::observe
    #[must_use]
    pub fn is_trusted(&self, node_id: &str, fingerprint: &[u8]) -> bool {
        self.devices
            .get(node_id)
            .is_some_and(|d| !d.revoked && d.fingerprint == fingerprint)
    }

    /// Revoke `node_id`, keeping its entry so the key stays denied. Returns
    /// `false` when the device is unknown.
    pub fn revoke(&mut self, node_id: &str) -> bool {
        if let Some(dev) = self.devices.get_mut(node_id) {
            dev.revoked = true;
            true
        } else {
            false
        }
    }

    /// Forget `node_id` entirely (allowing a fresh TOFU pin later). Returns
    /// `false` when the device is unknown.
    pub fn forget(&mut self, node_id: &str) -> bool {
        self.devices.remove(node_id).is_some()
    }

    /// The pinned fingerprint of `node_id`, if present (revoked or not).
    #[must_use]
    pub fn fingerprint_of(&self, node_id: &str) -> Option<&[u8]> {
        self.devices.get(node_id).map(|d| d.fingerprint.as_slice())
    }

    /// Whether `node_id` has an entry (revoked or not).
    #[must_use]
    pub fn contains(&self, node_id: &str) -> bool {
        self.devices.contains_key(node_id)
    }

    /// The number of pinned devices (including revoked ones).
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "node-a1b2c3";
    const FP1: &[u8] = &[1, 2, 3, 4];
    const FP2: &[u8] = &[9, 9, 9, 9];

    #[test]
    fn tofu_pins_on_first_use_then_recognizes() {
        let mut store = TrustStore::new(true);
        assert!(store.is_empty());
        assert_eq!(store.observe(NODE, FP1), TrustDecision::PinnedFirstUse);
        assert!(store.contains(NODE));
        assert_eq!(store.fingerprint_of(NODE), Some(FP1));
        // Same key next time → already trusted.
        assert_eq!(store.observe(NODE, FP1), TrustDecision::AlreadyTrusted);
    }

    #[test]
    fn mismatch_is_rejected_and_does_not_overwrite_the_pin() {
        let mut store = TrustStore::new(true);
        store.observe(NODE, FP1);
        let decision = store.observe(NODE, FP2);
        assert_eq!(
            decision,
            TrustDecision::Mismatch {
                expected: FP1.to_vec(),
                presented: FP2.to_vec(),
            }
        );
        assert!(!decision.is_trusted());
        // The pin is unchanged — the attacker's key was not recorded.
        assert_eq!(store.fingerprint_of(NODE), Some(FP1));
        assert_eq!(store.observe(NODE, FP1), TrustDecision::AlreadyTrusted);
    }

    #[test]
    fn tofu_disabled_rejects_unknown_devices() {
        let mut store = TrustStore::new(false);
        assert_eq!(store.observe(NODE, FP1), TrustDecision::UnknownRejected);
        assert!(!store.contains(NODE));
        // Only an explicit pin admits it.
        store.pin(NODE, FP1);
        assert_eq!(store.observe(NODE, FP1), TrustDecision::AlreadyTrusted);
    }

    #[test]
    fn explicit_pin_authorizes_a_key_rotation() {
        let mut store = TrustStore::new(true);
        store.observe(NODE, FP1);
        // An authorised rotation to a new key.
        store.pin(NODE, FP2);
        assert_eq!(store.fingerprint_of(NODE), Some(FP2));
        assert_eq!(store.observe(NODE, FP2), TrustDecision::AlreadyTrusted);
        // The old key is now a mismatch.
        assert!(matches!(
            store.observe(NODE, FP1),
            TrustDecision::Mismatch { .. }
        ));
    }

    #[test]
    fn revoke_blocks_a_previously_trusted_device() {
        let mut store = TrustStore::new(true);
        store.observe(NODE, FP1);
        assert!(store.revoke(NODE));
        assert_eq!(store.observe(NODE, FP1), TrustDecision::Revoked);
        assert!(!store.is_trusted(NODE, FP1));
        // The entry is retained (revoked keys stay denied).
        assert!(store.contains(NODE));
        // Revoking an unknown device reports false.
        assert!(!store.revoke("unknown"));
    }

    #[test]
    fn forget_removes_and_allows_a_fresh_pin() {
        let mut store = TrustStore::new(true);
        store.observe(NODE, FP1);
        assert!(store.forget(NODE));
        assert!(!store.contains(NODE));
        assert!(!store.forget(NODE)); // already gone
        // A fresh TOFU pin is possible again.
        assert_eq!(store.observe(NODE, FP2), TrustDecision::PinnedFirstUse);
    }

    #[test]
    fn is_trusted_is_read_only() {
        let store = TrustStore::new(true);
        // is_trusted must not pin an unknown device.
        assert!(!store.is_trusted(NODE, FP1));
        assert!(store.is_empty());
    }

    #[test]
    fn decision_trust_flag_matches_variants() {
        assert!(TrustDecision::PinnedFirstUse.is_trusted());
        assert!(TrustDecision::AlreadyTrusted.is_trusted());
        assert!(!TrustDecision::Revoked.is_trusted());
        assert!(!TrustDecision::UnknownRejected.is_trusted());
        assert!(
            !TrustDecision::Mismatch {
                expected: vec![],
                presented: vec![],
            }
            .is_trusted()
        );
    }
}

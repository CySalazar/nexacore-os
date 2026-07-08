//! OS and protocol version vocabulary.
//!
//! NexaCore OS uses two distinct version concepts:
//!
//! * [`OsVersion`] — the `SemVer` 2.0.0 version of the OS distribution
//!   (e.g., `0.1.0`, `1.0.0`). This evolves with releases.
//! * [`ProtocolVersion`] — the wire-protocol version negotiated at mesh
//!   handshake. Format `NexaCore-PROTO-vMAJOR.MINOR`. Patch is implicit (no
//!   wire-visible patch component) because mesh peers MUST be
//!   bug-for-bug compatible at the wire layer.
//!
//! Decoupling the two lets us patch the OS without forcing every peer
//! on the mesh to upgrade in lockstep, and lets the protocol evolve
//! (with negotiation) independently of OS release cadence.
//!
//! See [`/docs/09-tech-specifications.md`](../../../docs/09-tech-specifications.md)
//! § "Versioning policy".

use core::fmt;

use serde::{Deserialize, Serialize};

// =============================================================================
// OsVersion — SemVer 2.0.0 distribution version.
// =============================================================================

/// `SemVer` 2.0.0 version of the NexaCore OS distribution.
///
/// Pre-release and build metadata segments are intentionally omitted at
/// v0.1 — they will be added when the project starts producing
/// release-candidate builds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct OsVersion {
    /// `SemVer` major component. Bumped on incompatible API changes.
    pub major: u16,
    /// `SemVer` minor component. Bumped on backwards-compatible additions.
    pub minor: u16,
    /// `SemVer` patch component. Bumped on backwards-compatible bug fixes.
    pub patch: u16,
}

impl OsVersion {
    /// The current OS version (compile-time constant). Updated at every
    /// release; do not bump manually outside the release process.
    pub const CURRENT: Self = Self {
        major: 0,
        minor: 1,
        patch: 0,
    };

    /// Construct a new `OsVersion` literal.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// =============================================================================
// ProtocolVersion — mesh wire protocol identifier.
// =============================================================================

/// Mesh wire-protocol version, negotiated at handshake.
///
/// # Compatibility rule
///
/// Two peers are wire-compatible iff:
///
/// * Their `major` components are identical.
/// * The accepting peer's `minor` is greater than or equal to the
///   initiating peer's `minor`.
///
/// In other words: minor-version additions are backwards compatible
/// (older peers ignore new optional fields), but a major version bump
/// breaks compatibility. There is no `patch` component on the wire —
/// any wire-observable patch-level change MUST be a `minor` bump.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Wire major. Bumped on incompatible protocol changes.
    pub major: u16,
    /// Wire minor. Bumped on backwards-compatible additions.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Construct a new `ProtocolVersion` literal.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns `true` iff `self` (the local peer) can speak with `other`
    /// (the remote peer announcement) per the compatibility rule above.
    ///
    /// The relation is **not** symmetric in the general case: a peer
    /// running `v1.5` can talk to a peer announcing `v1.3`, but
    /// `v1.3.is_compatible_with(v1.5)` returns `false` because the
    /// older peer cannot understand new fields.
    ///
    /// Arguments are taken by value because `ProtocolVersion` is 4 bytes
    /// (two `u16`s), well below the reference-vs-value threshold —
    /// passing by value also enables call-site copy elision.
    #[must_use]
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Wire format defined in /docs/03-mesh-protocol.md.
        write!(f, "NexaCore-PROTO-v{}.{}", self.major, self.minor)
    }
}

// =============================================================================
// Well-known constants.
// =============================================================================

/// Protocol version 0.1 — the initial draft used during P0/P1 development.
///
/// Superseded by [`PROTOCOL_VERSION_V0_2`] on the `bincode → postcard`
/// wire-format cutover (see
/// [`NCIP-Serde-004`](https://github.com/CySalazar/nexacore-os/blob/main/ncips/ncip-serde-004.md)).
/// Retained as a constant so that historical references in proofs, audit
/// records, and the Tamarin model remain valid; **no peer negotiates
/// v0.1 after `NCIP-Serde-004` reaches `Active`**.
pub const PROTOCOL_VERSION_V0_1: ProtocolVersion = ProtocolVersion::new(0, 1);

/// Protocol version 0.2 — first `postcard`-encoded wire format.
///
/// Uses `postcard` 1.x as the canonical wire encoding (per
/// `NCIP-Serde-004`). All current development targets v0.2. Mesh
/// handshake (see `docs/protocol/handshake.md` § 3.2) negotiates v0.2
/// only; v0.1 is removed from the negotiation menu because the wire
/// format is incompatible.
///
/// The discriminant `serde_format = "postcard-1.0"` is the conceptual
/// label for this format; the negotiation message carries the
/// `NexaCore-PROTO-v0.2` string and an out-of-band reference to this
/// constant for the byte-format contract.
pub const PROTOCOL_VERSION_V0_2: ProtocolVersion = ProtocolVersion::new(0, 2);

/// Protocol version 1.0 — first stable release target. Reserved.
pub const PROTOCOL_VERSION_V1_0: ProtocolVersion = ProtocolVersion::new(1, 0);

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn os_version_display_is_dotted_triple() {
        let v = OsVersion::new(1, 2, 3);
        assert_eq!(format!("{v}"), "1.2.3");
    }

    #[test]
    fn os_version_ordering_is_lexicographic() {
        assert!(OsVersion::new(0, 1, 0) < OsVersion::new(0, 2, 0));
        assert!(OsVersion::new(0, 2, 0) < OsVersion::new(1, 0, 0));
        assert!(OsVersion::new(1, 0, 0) < OsVersion::new(1, 0, 1));
    }

    #[test]
    fn protocol_version_display_uses_nexacore_proto_prefix() {
        let v = ProtocolVersion::new(0, 1);
        assert_eq!(format!("{v}"), "NexaCore-PROTO-v0.1");
    }

    #[test]
    fn protocol_compat_same_major_higher_local_minor() {
        let local = ProtocolVersion::new(1, 5);
        let remote = ProtocolVersion::new(1, 3);
        assert!(local.is_compatible_with(remote));
    }

    #[test]
    fn protocol_compat_same_major_same_minor() {
        let v = ProtocolVersion::new(1, 0);
        assert!(v.is_compatible_with(v));
    }

    #[test]
    fn protocol_incompat_remote_minor_higher() {
        // The local peer cannot speak a protocol it has not been
        // taught. Compatibility is asymmetric in the minor direction.
        let local = ProtocolVersion::new(1, 3);
        let remote = ProtocolVersion::new(1, 5);
        assert!(!local.is_compatible_with(remote));
    }

    #[test]
    fn protocol_incompat_different_major() {
        let local = ProtocolVersion::new(1, 0);
        let remote = ProtocolVersion::new(2, 0);
        assert!(!local.is_compatible_with(remote));
        assert!(!remote.is_compatible_with(local));
    }

    #[test]
    fn well_known_constants_are_what_they_say() {
        assert_eq!(PROTOCOL_VERSION_V0_1, ProtocolVersion::new(0, 1));
        assert_eq!(PROTOCOL_VERSION_V0_2, ProtocolVersion::new(0, 2));
        assert_eq!(PROTOCOL_VERSION_V1_0, ProtocolVersion::new(1, 0));
    }

    #[test]
    fn v0_2_is_strictly_after_v0_1() {
        // The protocol-version ordering is lexicographic on (major,
        // minor). v0.2 must be strictly greater than v0.1 so version
        // negotiation can pick the newer one when both peers support
        // it.
        assert!(PROTOCOL_VERSION_V0_2 > PROTOCOL_VERSION_V0_1);
    }

    #[test]
    fn v0_2_is_minor_compatible_with_v0_1() {
        // Per `is_compatible_with`'s asymmetric rule: a peer on v0.2
        // CAN talk down to a peer on v0.1 (same major, local minor ≥
        // remote minor), but not the reverse. This is the property
        // the mesh handshake relies on at the version-negotiation
        // step.
        assert!(PROTOCOL_VERSION_V0_2.is_compatible_with(PROTOCOL_VERSION_V0_1));
        assert!(!PROTOCOL_VERSION_V0_1.is_compatible_with(PROTOCOL_VERSION_V0_2));
    }
}

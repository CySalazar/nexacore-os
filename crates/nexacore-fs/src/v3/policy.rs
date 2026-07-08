//! Per-volume adaptive policy object (WS3-09, NCIP-027 §S2.1).
//!
//! NexaCore runs on home, gaming, server, and enterprise machines at every
//! security level, so the filesystem must adapt to context — *without*
//! degenerating into the tunable jungle of ZFS/ext4 (`data=writeback` and
//! friends) and **without ever touching the invariant floor**.
//!
//! The design is a small [`VolumePolicy`] "envelope" whose fields only govern
//! behaviour that is safe to vary — commit cadence, extent allocation, the ZSTD
//! default, retention/TRIM, scrub cadence, cache/writeback, chaff, and the
//! unlock class. The invariant floor — mandatory integrity, per-volume
//! encryption, atomic CoW commit, capability enforcement — is **not
//! representable** in this type: there is simply no field that can weaken it, so
//! no policy (persisted or malicious) can express a floor violation. The floor
//! is reported by [`InvariantFloor`], a constant independent of the policy.
//!
//! Five named [`ProfileId`] presets cover the common contexts. A profile change
//! is an ordinary CoW commit carrying a [`PolicyChange`] audit record; runtime
//! [`SessionOverlay`]s layer over the persisted policy and are never serialised;
//! and enterprise **pinning** ([`PolicyManager`]) requires an administrative
//! capability to commit a new profile (NCIP-027 §T8).

use alloc::{string::String, vec::Vec};

use super::V3Error;

/// A named per-volume profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileId {
    /// Desktop: low-latency commits, moderate compression, write-back cache.
    Interactive,
    /// Gaming: throughput-biased, large extents, no compression stalls.
    Gaming,
    /// Server: batched commits, frequent scrub, durability-biased cache.
    Server,
    /// High-assurance: frequent scrub, chaff on, TEE-bound unlock, tight TRIM.
    HighAssurance,
    /// Archive: max compression, large extents, rare scrub, long retention.
    Archive,
}

impl ProfileId {
    fn code(self) -> u8 {
        match self {
            Self::Interactive => 0,
            Self::Gaming => 1,
            Self::Server => 2,
            Self::HighAssurance => 3,
            Self::Archive => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self, V3Error> {
        match code {
            0 => Ok(Self::Interactive),
            1 => Ok(Self::Gaming),
            2 => Ok(Self::Server),
            3 => Ok(Self::HighAssurance),
            4 => Ok(Self::Archive),
            _ => Err(V3Error::Corrupt),
        }
    }
}

/// Commit frequency / batching bias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitCadence {
    /// Commit eagerly for low latency.
    LowLatency,
    /// Batch commits for balanced throughput.
    Batched,
    /// Maximise throughput with the largest safe batches.
    Throughput,
}

/// Default extent compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionDefault {
    /// No compression.
    Off,
    /// Fast, low-ratio compression.
    Fast,
    /// Maximum-ratio compression.
    Max,
}

/// Cache write policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// Write through to the device promptly (durability-biased).
    WriteThrough,
    /// Buffer writes and flush lazily (throughput-biased).
    WriteBack,
}

/// The class of unlock the volume requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockClass {
    /// A passphrase may unlock the volume.
    Passphrase,
    /// Only a TEE/TPM-bound key may unlock the volume.
    TeeBound,
    /// Either a passphrase or a TEE-bound key may unlock.
    Either,
}

/// The per-volume policy envelope. Every field varies *behaviour only*; none can
/// express a floor violation (there is no integrity/encryption/commit/capability
/// knob).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumePolicy {
    /// The named profile this policy was derived from.
    pub profile_id: ProfileId,
    /// Commit cadence / batching.
    pub commit_cadence: CommitCadence,
    /// Default extent compression.
    pub compression: CompressionDefault,
    /// Cache write policy.
    pub cache: CachePolicy,
    /// Unlock class.
    pub unlock: UnlockClass,
    /// Generations to retain freed blocks before TRIM (see
    /// [`super::cache::RetentionTracker`]).
    pub trim_window_generations: u32,
    /// Scrub interval in hours (`0` = scrub disabled).
    pub scrub_interval_hours: u32,
    /// Prefer allocating large contiguous extents.
    pub prefer_large_extents: bool,
    /// Emit chaff writes to blur access patterns (NCIP §SC6).
    pub chaff_enabled: bool,
}

impl VolumePolicy {
    /// The preset policy for a named profile.
    #[must_use]
    pub fn preset(profile: ProfileId) -> Self {
        match profile {
            ProfileId::Interactive => Self {
                profile_id: profile,
                commit_cadence: CommitCadence::LowLatency,
                compression: CompressionDefault::Fast,
                cache: CachePolicy::WriteBack,
                unlock: UnlockClass::Either,
                trim_window_generations: 4,
                scrub_interval_hours: 168,
                prefer_large_extents: false,
                chaff_enabled: false,
            },
            ProfileId::Gaming => Self {
                profile_id: profile,
                commit_cadence: CommitCadence::Throughput,
                compression: CompressionDefault::Off,
                cache: CachePolicy::WriteBack,
                unlock: UnlockClass::Either,
                trim_window_generations: 2,
                scrub_interval_hours: 336,
                prefer_large_extents: true,
                chaff_enabled: false,
            },
            ProfileId::Server => Self {
                profile_id: profile,
                commit_cadence: CommitCadence::Batched,
                compression: CompressionDefault::Fast,
                cache: CachePolicy::WriteThrough,
                unlock: UnlockClass::TeeBound,
                trim_window_generations: 8,
                scrub_interval_hours: 24,
                prefer_large_extents: false,
                chaff_enabled: false,
            },
            ProfileId::HighAssurance => Self {
                profile_id: profile,
                commit_cadence: CommitCadence::Batched,
                compression: CompressionDefault::Fast,
                cache: CachePolicy::WriteThrough,
                unlock: UnlockClass::TeeBound,
                trim_window_generations: 16,
                scrub_interval_hours: 6,
                prefer_large_extents: false,
                chaff_enabled: true,
            },
            ProfileId::Archive => Self {
                profile_id: profile,
                commit_cadence: CommitCadence::Throughput,
                compression: CompressionDefault::Max,
                cache: CachePolicy::WriteThrough,
                unlock: UnlockClass::Either,
                trim_window_generations: 32,
                scrub_interval_hours: 720,
                prefer_large_extents: true,
                chaff_enabled: false,
            },
        }
    }

    /// The 12-byte serialisation of the policy envelope. By construction it
    /// encodes only envelope fields, so it can never represent a floor
    /// violation.
    #[must_use]
    pub fn encode(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0] = self.profile_id.code();
        out[1] = match self.commit_cadence {
            CommitCadence::LowLatency => 0,
            CommitCadence::Batched => 1,
            CommitCadence::Throughput => 2,
        };
        out[2] = match self.compression {
            CompressionDefault::Off => 0,
            CompressionDefault::Fast => 1,
            CompressionDefault::Max => 2,
        };
        out[3] = match self.cache {
            CachePolicy::WriteThrough => 0,
            CachePolicy::WriteBack => 1,
        };
        out[4] = match self.unlock {
            UnlockClass::Passphrase => 0,
            UnlockClass::TeeBound => 1,
            UnlockClass::Either => 2,
        };
        out[5] = u8::from(self.prefer_large_extents);
        out[6] = u8::from(self.chaff_enabled);
        // trim window (u16) + scrub hours (u16) little-endian.
        let trim = u16::try_from(self.trim_window_generations).unwrap_or(u16::MAX);
        let scrub = u16::try_from(self.scrub_interval_hours).unwrap_or(u16::MAX);
        out[7] = 0; // reserved / alignment
        out[8..10].copy_from_slice(&trim.to_le_bytes());
        out[10..12].copy_from_slice(&scrub.to_le_bytes());
        out
    }

    /// Parse a policy envelope from its 12-byte serialisation.
    ///
    /// # Errors
    /// [`V3Error::Corrupt`] if any discriminant is out of range.
    pub fn decode(bytes: &[u8; 12]) -> Result<Self, V3Error> {
        let commit_cadence = match bytes[1] {
            0 => CommitCadence::LowLatency,
            1 => CommitCadence::Batched,
            2 => CommitCadence::Throughput,
            _ => return Err(V3Error::Corrupt),
        };
        let compression = match bytes[2] {
            0 => CompressionDefault::Off,
            1 => CompressionDefault::Fast,
            2 => CompressionDefault::Max,
            _ => return Err(V3Error::Corrupt),
        };
        let cache = match bytes[3] {
            0 => CachePolicy::WriteThrough,
            1 => CachePolicy::WriteBack,
            _ => return Err(V3Error::Corrupt),
        };
        let unlock = match bytes[4] {
            0 => UnlockClass::Passphrase,
            1 => UnlockClass::TeeBound,
            2 => UnlockClass::Either,
            _ => return Err(V3Error::Corrupt),
        };
        let mut trim = [0u8; 2];
        trim.copy_from_slice(&bytes[8..10]);
        let mut scrub = [0u8; 2];
        scrub.copy_from_slice(&bytes[10..12]);
        Ok(Self {
            profile_id: ProfileId::from_code(bytes[0])?,
            commit_cadence,
            compression,
            cache,
            unlock,
            trim_window_generations: u32::from(u16::from_le_bytes(trim)),
            scrub_interval_hours: u32::from(u16::from_le_bytes(scrub)),
            prefer_large_extents: bytes[5] != 0,
            chaff_enabled: bytes[6] != 0,
        })
    }
}

/// The invariant floor: the guarantees no policy can weaken. Independent of any
/// [`VolumePolicy`] — a constant, so a profile change cannot alter it.
// Four bools are intentional: one per non-negotiable invariant, each named.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvariantFloor {
    /// Block integrity (Merkle) is always verified on read.
    pub integrity_mandatory: bool,
    /// Per-volume encryption at rest is always required.
    pub encryption_required: bool,
    /// Every commit is atomic copy-on-write.
    pub atomic_commit: bool,
    /// Capability checks are always enforced.
    pub capability_enforced: bool,
}

/// The one and only floor. Every field is `true` regardless of the active
/// profile.
pub const FLOOR: InvariantFloor = InvariantFloor {
    integrity_mandatory: true,
    encryption_required: true,
    atomic_commit: true,
    capability_enforced: true,
};

/// An audit record for a profile change (WS3-09.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChange {
    /// The profile before the change.
    pub from: ProfileId,
    /// The profile after the change.
    pub to: ProfileId,
    /// Identity of the requesting agent.
    pub requesting_agent: String,
    /// The NCIP-007 autonomy level under which the change was made.
    pub autonomy_level: u8,
    /// The telemetry-grounded justification for the change.
    pub justification: String,
}

/// A runtime-only overlay of policy fields (WS3-09.4).
///
/// Layered over the persisted policy and **never serialised** (there is no
/// `encode`), so it decays with the session. Only fields safe to vary at
/// runtime are overridable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionOverlay {
    /// Optional compression override for this session.
    pub compression: Option<CompressionDefault>,
    /// Optional cache-policy override for this session.
    pub cache: Option<CachePolicy>,
}

impl SessionOverlay {
    /// The effective policy: `base` with any overlay fields applied.
    #[must_use]
    pub fn effective(self, base: &VolumePolicy) -> VolumePolicy {
        let mut policy = *base;
        if let Some(compression) = self.compression {
            policy.compression = compression;
        }
        if let Some(cache) = self.cache {
            policy.cache = cache;
        }
        policy
    }
}

/// An error from policy management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// A profile commit was attempted on a pinned volume without the
    /// administrative `fs:policy` capability.
    Unauthorized,
}

/// Owns the persisted policy, the enterprise pin, and the change audit log.
#[derive(Debug, Clone)]
pub struct PolicyManager {
    policy: VolumePolicy,
    pinned: bool,
    audit: Vec<PolicyChange>,
}

impl PolicyManager {
    /// A manager over `policy`, initially unpinned with an empty audit log.
    #[must_use]
    pub fn new(policy: VolumePolicy) -> Self {
        Self {
            policy,
            pinned: false,
            audit: Vec::new(),
        }
    }

    /// The active persisted policy.
    #[must_use]
    pub fn policy(&self) -> &VolumePolicy {
        &self.policy
    }

    /// Whether the policy is pinned (enterprise lock).
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        self.pinned
    }

    /// Pin or unpin the policy. Pinning is an administrative act; `admin` must
    /// hold the `fs:policy` capability.
    ///
    /// # Errors
    /// [`PolicyError::Unauthorized`] if `admin` is false.
    pub fn set_pinned(&mut self, pinned: bool, admin: bool) -> Result<(), PolicyError> {
        if !admin {
            return Err(PolicyError::Unauthorized);
        }
        self.pinned = pinned;
        Ok(())
    }

    /// Commit a switch to `profile`, recording `change` in the audit log. On a
    /// pinned volume this requires the administrative `fs:policy` capability
    /// (`admin`); the change itself is an ordinary atomic CoW commit at the
    /// superblock layer (the caller performs the commit).
    ///
    /// # Errors
    /// [`PolicyError::Unauthorized`] if the volume is pinned and `admin` is
    /// false.
    pub fn commit_profile(
        &mut self,
        profile: ProfileId,
        change: PolicyChange,
        admin: bool,
    ) -> Result<(), PolicyError> {
        if self.pinned && !admin {
            return Err(PolicyError::Unauthorized);
        }
        self.policy = VolumePolicy::preset(profile);
        self.audit.push(change);
        Ok(())
    }

    /// The recorded profile-change audit log.
    #[must_use]
    pub fn audit(&self) -> &[PolicyChange] {
        &self.audit
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    const PROFILES: [ProfileId; 5] = [
        ProfileId::Interactive,
        ProfileId::Gaming,
        ProfileId::Server,
        ProfileId::HighAssurance,
        ProfileId::Archive,
    ];

    #[test]
    fn every_preset_round_trips_through_serialisation() {
        for profile in PROFILES {
            let policy = VolumePolicy::preset(profile);
            assert_eq!(policy.profile_id, profile);
            let decoded = VolumePolicy::decode(&policy.encode()).unwrap();
            assert_eq!(decoded, policy);
        }
    }

    #[test]
    fn decode_rejects_out_of_range_discriminants() {
        let mut bytes = VolumePolicy::preset(ProfileId::Server).encode();
        bytes[0] = 9; // bad profile id
        assert_eq!(VolumePolicy::decode(&bytes).err(), Some(V3Error::Corrupt));
        let mut bytes = VolumePolicy::preset(ProfileId::Server).encode();
        bytes[2] = 7; // bad compression
        assert_eq!(VolumePolicy::decode(&bytes).err(), Some(V3Error::Corrupt));
    }

    #[test]
    fn floor_is_constant_and_no_profile_can_change_it() {
        // The floor is a const, independent of the policy: switching to the
        // most permissive-looking profile cannot weaken any guarantee. `black_box`
        // keeps the check from being const-folded away.
        let floor = core::hint::black_box(FLOOR);
        let all_on = InvariantFloor {
            integrity_mandatory: true,
            encryption_required: true,
            atomic_commit: true,
            capability_enforced: true,
        };
        assert_eq!(floor, all_on);
        // The 12-byte envelope has no field the floor is derived from, so there
        // is no byte a hostile policy could set to disable a guarantee — every
        // profile leaves the floor identical.
        for profile in PROFILES {
            let _ = VolumePolicy::preset(profile).encode();
            assert_eq!(core::hint::black_box(FLOOR), all_on);
        }
    }

    #[test]
    fn profiles_differ_in_the_expected_envelope_fields() {
        let archive = VolumePolicy::preset(ProfileId::Archive);
        let gaming = VolumePolicy::preset(ProfileId::Gaming);
        assert_eq!(archive.compression, CompressionDefault::Max);
        assert_eq!(gaming.compression, CompressionDefault::Off);
        assert!(archive.trim_window_generations > gaming.trim_window_generations);
        assert!(VolumePolicy::preset(ProfileId::HighAssurance).chaff_enabled);
        assert_eq!(
            VolumePolicy::preset(ProfileId::HighAssurance).unlock,
            UnlockClass::TeeBound
        );
    }

    #[test]
    fn session_overlay_layers_without_touching_the_base() {
        let base = VolumePolicy::preset(ProfileId::Interactive);
        let overlay = SessionOverlay {
            compression: Some(CompressionDefault::Off),
            cache: None,
        };
        let effective = overlay.effective(&base);
        assert_eq!(effective.compression, CompressionDefault::Off);
        assert_eq!(
            effective.cache, base.cache,
            "unset overlay field keeps base"
        );
        // The base (and thus what gets persisted) is untouched; the overlay has
        // no serialisation of its own.
        assert_eq!(base.compression, CompressionDefault::Fast);
    }

    fn change() -> PolicyChange {
        PolicyChange {
            from: ProfileId::Interactive,
            to: ProfileId::Server,
            requesting_agent: "helper".to_string(),
            autonomy_level: 2,
            justification: "read/write ratio shifted to server-like".to_string(),
        }
    }

    #[test]
    fn profile_change_records_audit() {
        let mut mgr = PolicyManager::new(VolumePolicy::preset(ProfileId::Interactive));
        mgr.commit_profile(ProfileId::Server, change(), false)
            .unwrap();
        assert_eq!(mgr.policy().profile_id, ProfileId::Server);
        assert_eq!(mgr.audit().len(), 1);
        assert_eq!(mgr.audit()[0].requesting_agent, "helper");
    }

    #[test]
    fn pinning_requires_admin_to_commit() {
        let mut mgr = PolicyManager::new(VolumePolicy::preset(ProfileId::Interactive));
        // Pinning itself needs admin.
        assert_eq!(
            mgr.set_pinned(true, false).err(),
            Some(PolicyError::Unauthorized)
        );
        mgr.set_pinned(true, true).unwrap();
        assert!(mgr.is_pinned());
        // A pinned volume rejects a non-admin profile commit …
        assert_eq!(
            mgr.commit_profile(ProfileId::Gaming, change(), false).err(),
            Some(PolicyError::Unauthorized)
        );
        assert_eq!(mgr.policy().profile_id, ProfileId::Interactive, "unchanged");
        // … but accepts an admin one.
        mgr.commit_profile(ProfileId::Gaming, change(), true)
            .unwrap();
        assert_eq!(mgr.policy().profile_id, ProfileId::Gaming);
    }
}

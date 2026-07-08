//! Minimal Linux guest image manifest for the application path (WS9-03.1).
//!
//! The app path runs Linux GUI programs inside a container micro-VM. That VM
//! boots a **minimal, Stichting-signed guest image** whose PID 1 is the guest
//! agent (see [`super::agent`]) hosting a headless Wayland compositor. This
//! module is the host-side, declarative description of *what that image must
//! contain* — a build manifest the image builder consumes and the engine
//! validates before launch. It is deliberately content-addressed (every
//! artifact is named by a BLAKE3 digest) so a built image can be verified
//! against the manifest and so attestation ([`crate::attestation`]) can cover
//! the exact bits that booted.
//!
//! Building the actual rootfs is an offline, reproducible pipeline (P8.3); this
//! type is its contract and is fully host-testable (construction, validation,
//! canonical serialization round-trip).

use serde::{Deserialize, Serialize};

use super::{AppBridgeError, AppBridgeResult};

/// A content digest (BLAKE3-256) naming a guest artifact.
pub type Digest = [u8; 32];

/// A virtio device the guest image requires to be present for the app path.
///
/// Window integration is impossible without a framebuffer transport
/// ([`GuestVirtioDevice::Gpu`]) and a control channel
/// ([`GuestVirtioDevice::Vsock`]); the others are optional interop channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestVirtioDevice {
    /// `virtio-gpu` — carries the guest framebuffer the compositor samples.
    Gpu,
    /// `virtio-vsock` — carries the [`super::agent`] control protocol.
    Vsock,
    /// `virtio-snd` — carries guest audio to the host ([`super::audio`]).
    Snd,
    /// `virtio-input` — carries host input events into the guest.
    Input,
}

/// A rootfs layer named by its content digest, applied in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsLayer {
    /// Content digest of the (compressed) layer tarball.
    pub digest: Digest,
    /// Uncompressed size in bytes (used for allocation/quota planning).
    pub uncompressed_size: u64,
}

/// The declarative manifest of a minimal Linux guest image for the app path.
///
/// A manifest is *valid* iff it names a kernel and an agent, includes at least
/// the [`GuestVirtioDevice::Gpu`] and [`GuestVirtioDevice::Vsock`] devices, and
/// carries at least one rootfs layer. Validation is fail-closed: an incomplete
/// manifest cannot be launched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestImageManifest {
    /// Human-readable image tag (e.g. `nexacore/linux-app:1-stable`). Not
    /// security-relevant — the digests are the trust anchor.
    pub tag: String,
    /// BLAKE3 digest of the Stichting-signed guest kernel image.
    pub kernel_digest: Digest,
    /// Absolute path of the guest agent binary that runs as PID 1.
    pub agent_path: String,
    /// BLAKE3 digest of the guest agent binary.
    pub agent_digest: Digest,
    /// Rootfs layers, applied bottom-up.
    pub rootfs_layers: Vec<RootfsLayer>,
    /// virtio devices the image requires.
    pub required_devices: Vec<GuestVirtioDevice>,
}

impl GuestImageManifest {
    /// Whether the manifest requires `device`.
    #[must_use]
    pub fn requires(&self, device: GuestVirtioDevice) -> bool {
        self.required_devices.contains(&device)
    }

    /// Total uncompressed rootfs footprint, saturating on overflow.
    #[must_use]
    pub fn rootfs_footprint(&self) -> u64 {
        self.rootfs_layers
            .iter()
            .fold(0u64, |acc, l| acc.saturating_add(l.uncompressed_size))
    }

    /// Validate the manifest's structural invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AppBridgeError::InvalidManifest`] with a slug naming the first
    /// failed invariant: an empty tag or agent path, an all-zero kernel or
    /// agent digest (an unbuilt placeholder), a missing mandatory device, or an
    /// empty rootfs.
    pub fn validate(&self) -> AppBridgeResult<()> {
        if self.tag.is_empty() {
            return Err(AppBridgeError::InvalidManifest("empty tag"));
        }
        if self.agent_path.is_empty() || !self.agent_path.starts_with('/') {
            return Err(AppBridgeError::InvalidManifest("agent path not absolute"));
        }
        if self.kernel_digest == [0u8; 32] {
            return Err(AppBridgeError::InvalidManifest("unset kernel digest"));
        }
        if self.agent_digest == [0u8; 32] {
            return Err(AppBridgeError::InvalidManifest("unset agent digest"));
        }
        if self.rootfs_layers.is_empty() {
            return Err(AppBridgeError::InvalidManifest("no rootfs layers"));
        }
        if !self.requires(GuestVirtioDevice::Gpu) {
            return Err(AppBridgeError::InvalidManifest("missing virtio-gpu"));
        }
        if !self.requires(GuestVirtioDevice::Vsock) {
            return Err(AppBridgeError::InvalidManifest("missing virtio-vsock"));
        }
        Ok(())
    }

    /// Encode to the canonical wire form (per `NCIP-Serde-004`).
    ///
    /// # Errors
    ///
    /// Returns a [`nexacore_types::NexaCoreError`] if canonical encoding fails.
    pub fn to_wire(&self) -> nexacore_types::Result<Vec<u8>> {
        nexacore_types::wire::encode_canonical(self)
    }

    /// Decode from the canonical wire form.
    ///
    /// # Errors
    ///
    /// Returns a [`nexacore_types::NexaCoreError`] if the bytes are not a valid
    /// canonical encoding of a manifest.
    pub fn from_wire(bytes: &[u8]) -> nexacore_types::Result<Self> {
        nexacore_types::wire::decode_canonical(bytes)
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
    use super::*;

    fn valid_manifest() -> GuestImageManifest {
        GuestImageManifest {
            tag: "nexacore/linux-app:1-stable".to_string(),
            kernel_digest: [1u8; 32],
            agent_path: "/usr/bin/nexacore-guest-agent".to_string(),
            agent_digest: [2u8; 32],
            rootfs_layers: vec![RootfsLayer {
                digest: [3u8; 32],
                uncompressed_size: 64 * 1024 * 1024,
            }],
            required_devices: vec![GuestVirtioDevice::Gpu, GuestVirtioDevice::Vsock],
        }
    }

    #[test]
    fn valid_manifest_passes() {
        assert!(valid_manifest().validate().is_ok());
    }

    #[test]
    fn missing_gpu_is_rejected() {
        let mut m = valid_manifest();
        m.required_devices = vec![GuestVirtioDevice::Vsock];
        assert_eq!(
            m.validate(),
            Err(AppBridgeError::InvalidManifest("missing virtio-gpu"))
        );
    }

    #[test]
    fn unbuilt_placeholder_digest_is_rejected() {
        let mut m = valid_manifest();
        m.kernel_digest = [0u8; 32];
        assert_eq!(
            m.validate(),
            Err(AppBridgeError::InvalidManifest("unset kernel digest"))
        );
    }

    #[test]
    fn relative_agent_path_is_rejected() {
        let mut m = valid_manifest();
        m.agent_path = "usr/bin/agent".to_string();
        assert_eq!(
            m.validate(),
            Err(AppBridgeError::InvalidManifest("agent path not absolute"))
        );
    }

    #[test]
    fn footprint_sums_layers() {
        let mut m = valid_manifest();
        m.rootfs_layers.push(RootfsLayer {
            digest: [4u8; 32],
            uncompressed_size: 1000,
        });
        assert_eq!(m.rootfs_footprint(), 64 * 1024 * 1024 + 1000);
    }

    #[test]
    fn wire_round_trips() {
        let m = valid_manifest();
        let bytes = m.to_wire().expect("encode");
        let back = GuestImageManifest::from_wire(&bytes).expect("decode");
        assert_eq!(m, back);
    }
}

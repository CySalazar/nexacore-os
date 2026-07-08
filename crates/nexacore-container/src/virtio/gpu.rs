//! `virtio-gpu` host-side backend trait — bridges to the NexaCore tensor
//! HAL's GPU dispatch surface.
//!
//! See `NCIP-Container-006` § 3.

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::{ContainerError, ContainerResult};

/// GPU access mode requested by the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuAccess {
    /// Shared (multiplexed) access to any GPU available on the host.
    Shared,
    /// Exclusive access to a specific GPU. The string is the
    /// host-local GPU identifier (e.g., `0`, `1`); a follow-up NCIP
    /// formalizes the identifier shape.
    Exclusive,
}

/// virtio-gpu backend trait.
pub trait VirtioGpuBackend: Send + Sync {
    /// Provision a GPU context for a container.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Capability`] if the container's
    /// capability set does not grant `gpu:shared` or
    /// `gpu:exclusive:<id>`, [`ContainerError::Virtio`] for host-side
    /// device errors, or [`ContainerError::NotYetImplemented`] in
    /// the v0.1 scaffold.
    fn provision_context(&self, access: GpuAccess) -> ContainerResult<u64>;
}

/// v0.1 stub.
#[derive(Debug, Default)]
pub struct StubVirtioGpu;

impl VirtioGpuBackend for StubVirtioGpu {
    fn provision_context(&self, _access: GpuAccess) -> ContainerResult<u64> {
        Err(ContainerError::NotYetImplemented(
            "virtio::gpu::provision_context",
        ))
    }
}

/// Functional `virtio-gpu` backend gated on the container's GPU grant.
///
/// GPU access is not expressed in the capability `Resource` model (which covers
/// filesystem/network/IPC); the container's [`crate::profile::CapabilityProfile`]
/// decides whether GPU is granted at all, and this backend is constructed with
/// that decision. It then enforces **exclusive/shared arbitration**: an
/// exclusive context cannot coexist with any other context, and a shared
/// context cannot be opened while an exclusive one is held. Both checks fail
/// closed. The real bridge to the tensor-HAL GPU dispatch (WS5) is wired on the
/// rig; the arbitration is host-tested here.
#[derive(Debug)]
pub struct ProfileVirtioGpu {
    gpu_granted: bool,
    state: Mutex<GpuState>,
    next: AtomicU64,
}

#[derive(Debug, Default)]
struct GpuState {
    contexts: usize,
    exclusive_held: bool,
}

impl ProfileVirtioGpu {
    /// Construct a backend; `gpu_granted` comes from the container's profile.
    #[must_use]
    pub fn new(gpu_granted: bool) -> Self {
        Self {
            gpu_granted,
            state: Mutex::new(GpuState::default()),
            next: AtomicU64::new(1),
        }
    }

    /// Number of live GPU contexts.
    #[must_use]
    pub fn context_count(&self) -> usize {
        self.state.lock().contexts
    }
}

// `provision_context` holds the state guard across the arbitration match and
// the mutation; the guard is needed for that whole critical section.
#[allow(clippy::significant_drop_tightening)]
impl VirtioGpuBackend for ProfileVirtioGpu {
    fn provision_context(&self, access: GpuAccess) -> ContainerResult<u64> {
        if !self.gpu_granted {
            return Err(ContainerError::Capability("virtio::gpu::provision_context"));
        }
        let mut state = self.state.lock();
        match access {
            GpuAccess::Exclusive if state.contexts > 0 => {
                return Err(ContainerError::Virtio("virtio::gpu::exclusive_busy"));
            }
            GpuAccess::Shared if state.exclusive_held => {
                return Err(ContainerError::Virtio(
                    "virtio::gpu::shared_blocked_by_exclusive",
                ));
            }
            _ => {}
        }
        if matches!(access, GpuAccess::Exclusive) {
            state.exclusive_held = true;
        }
        state.contexts += 1;
        Ok(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn stub_provision_context_returns_not_yet_implemented() {
        let b = StubVirtioGpu;
        let err = b.provision_context(GpuAccess::Shared).expect_err("stub");
        assert!(matches!(
            err,
            ContainerError::NotYetImplemented("virtio::gpu::provision_context")
        ));
    }

    #[test]
    fn ungranted_gpu_fails_closed() {
        let gpu = ProfileVirtioGpu::new(false);
        assert!(matches!(
            gpu.provision_context(GpuAccess::Shared),
            Err(ContainerError::Capability(_))
        ));
    }

    #[test]
    fn exclusive_blocks_further_contexts() {
        let gpu = ProfileVirtioGpu::new(true);
        gpu.provision_context(GpuAccess::Exclusive)
            .expect("exclusive");
        assert_eq!(gpu.context_count(), 1);
        // No second context (shared or exclusive) while exclusive is held.
        assert!(matches!(
            gpu.provision_context(GpuAccess::Shared),
            Err(ContainerError::Virtio(_))
        ));
        assert!(matches!(
            gpu.provision_context(GpuAccess::Exclusive),
            Err(ContainerError::Virtio(_))
        ));
    }

    #[test]
    fn shared_contexts_multiplex() {
        let gpu = ProfileVirtioGpu::new(true);
        gpu.provision_context(GpuAccess::Shared).expect("first");
        gpu.provision_context(GpuAccess::Shared).expect("second");
        assert_eq!(gpu.context_count(), 2);
        // An exclusive request now conflicts with the live shared contexts.
        assert!(matches!(
            gpu.provision_context(GpuAccess::Exclusive),
            Err(ContainerError::Virtio(_))
        ));
    }
}

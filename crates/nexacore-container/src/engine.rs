//! Container engine trait — the central abstraction for the hypervisor
//! backend selected at build time (KVM / TDX / SEV-SNP).
//!
//! See `NCIP-Container-006` § 1 ("Container model") and § 10 ("Reference
//! Implementation") for the rationale and the feature-gated backend
//! selection.
//!
//! ## Why a trait
//!
//! Three hypervisor backends are in scope for v1.x:
//!
//! - **KVM** (default): plain KVM-based micro-VM on VT-x / AMD-V. No
//!   confidentiality vs. the host kernel; suitable for non-TEE hardware
//!   and for development.
//! - **Intel TDX**: confidential VM (TD) on TDX-capable Xeon. Per-VM
//!   measurement; host kernel is outside the trust boundary.
//! - **AMD SEV-SNP**: confidential VM on Milan+ EPYC. Equivalent guarantees
//!   to TDX from a trust-boundary perspective.
//!
//! All three implement the same `ContainerEngine` trait. Consumers
//! (`nexacore-shell`, the management REST API, mesh peers offloading work)
//! depend only on the trait, not on the concrete backend.
//!
//! ## v0.1 → v0.2 transition
//!
//! `KvmEngine` previously returned [`ContainerError::NotYetImplemented`]
//! for every method. As of v0.2, it maintains real in-memory container state
//! via a `parking_lot::Mutex<HashMap<ContainerId, ContainerState>>` and
//! dispatches all hypervisor calls through the
//! [`crate::hypervisor::Hypervisor`] trait, which defaults to
//! [`crate::hypervisor::MockHypervisor`] when constructed via
//! [`KvmEngine::with_mock`].

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use parking_lot::Mutex;

use crate::{
    ContainerError, ContainerResult,
    attestation::ContainerQuote,
    console::ConsoleOutput,
    hypervisor::{Hypervisor, MockHypervisor, VcpuExit, VmHandle},
    image::OciImageRef,
    lifecycle::ContainerLifecycleState,
    profile::CapabilityProfile,
};

/// Opaque, engine-assigned identifier for a single container instance.
///
/// The internal representation is a `u64` for engine-local
/// addressability; cross-host references use the mesh-level `NodeId` /
/// attested-channel identifiers, never the local `ContainerId`. Two
/// containers spawned on the same host MUST receive distinct
/// `ContainerId` values; `Default` returns the canonical
/// "uninitialized" sentinel (`0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ContainerId(pub u64);

impl ContainerId {
    /// Construct from a raw `u64`. Engine-internal use only.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Borrow the raw `u64`. Used by tracing / audit log code only.
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }
}

/// Launch-time specification for a new container.
///
/// Every field is required by `NCIP-Container-006` § 4 (CLI surface) at
/// some level — either passed explicitly by the user or derived from
/// the selected capability profile. The struct is intentionally
/// non-exhaustive to allow follow-up NCIPs to add fields (e.g.,
/// `--cpus`, `--memory`, `--snapshot-id`) without breaking the trait
/// surface.
///
/// Because the struct is `#[non_exhaustive]`, external crates must use
/// [`ContainerSpec::new`] rather than struct literal syntax.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ContainerSpec {
    /// OCI image to run (or the Wine guest image alias when invoked
    /// via `nexacore-container run-windows`).
    pub image: OciImageRef,
    /// Capability profile that determines the granted virtio scopes.
    pub profile: CapabilityProfile,
    /// Whether to require a confidential VM (TDX / SEV-SNP). If true
    /// and the host has no TEE, the engine returns
    /// [`ContainerError::Backend`] without booting the guest.
    pub tee_required: bool,
}

impl ContainerSpec {
    /// Construct a container spec.
    ///
    /// This is the canonical constructor for external crates because
    /// `ContainerSpec` is `#[non_exhaustive]` (struct literal syntax would
    /// break when new fields are added in follow-up NCIPs).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::{
    ///     engine::ContainerSpec, image::OciImageRef, profile::CapabilityProfile,
    /// };
    ///
    /// let spec = ContainerSpec::new(
    ///     OciImageRef::parse("alpine:latest").expect("parse"),
    ///     CapabilityProfile::CliTool,
    ///     false,
    /// );
    /// assert!(!spec.tee_required);
    /// ```
    #[must_use]
    pub fn new(image: OciImageRef, profile: CapabilityProfile, tee_required: bool) -> Self {
        Self {
            image,
            profile,
            tee_required,
        }
    }
}

/// Vendor-neutral container engine surface.
///
/// Implementations:
/// - `KvmEngine` (default, gated by `kvm` feature) — real state management
///   backed by the [`crate::hypervisor::Hypervisor`] abstraction; uses
///   [`crate::hypervisor::MockHypervisor`] when constructed via
///   [`KvmEngine::with_mock`] for testing.
/// - `TdxEngine` (gated by `tdx` feature) — Intel TDX confidential VM.
/// - `SevSnpEngine` (gated by `sev-snp` feature) — AMD SEV-SNP.
///
/// All methods are synchronous for v0.1 to keep the trait surface
/// trivially mockable. A follow-up NCIP introduces an `async` variant
/// for the long-running `run` and `snapshot` paths once the runtime
/// (tokio vs. smol) is chosen.
pub trait ContainerEngine: Send + Sync {
    /// Provision a container from its spec. After this call returns
    /// `Ok`, the container is in
    /// [`ContainerLifecycleState::Provisioning`].
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Image`] if the OCI image cannot be
    /// fetched / verified, [`ContainerError::Capability`] if the
    /// requested profile cannot be satisfied by the host's grant set,
    /// or [`ContainerError::Backend`] if hypervisor setup fails.
    fn provision(&self, spec: ContainerSpec) -> ContainerResult<ContainerId>;

    /// Transition a provisioned container to
    /// [`ContainerLifecycleState::Running`].
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the container is not
    /// in `Provisioning`, or [`ContainerError::Backend`] if the guest
    /// kernel fails to boot.
    fn run(&self, id: ContainerId) -> ContainerResult<()>;

    /// Pause a running container (`VMPAUSE` on TDX, equivalent on
    /// SEV-SNP / KVM). Memory remains in place; no CPU is consumed.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the container is not
    /// in `Running`.
    fn suspend(&self, id: ContainerId) -> ContainerResult<()>;

    /// Resume a suspended container.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the container is not
    /// in `Suspended`.
    fn resume(&self, id: ContainerId) -> ContainerResult<()>;

    /// Capture a container snapshot (memory + disk + vCPU state),
    /// sealed under the host TEE's current measurement. The container
    /// transitions to [`ContainerLifecycleState::Snapshotted`].
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the container is not
    /// in `Suspended` (per `NCIP-Container-006` § 5, snapshot is
    /// reached via Suspended → Snapshotted), or
    /// [`ContainerError::Attestation`] if the sealing operation
    /// fails.
    fn snapshot(&self, id: ContainerId) -> ContainerResult<()>;

    /// Terminate a container. Releases all hypervisor and virtio
    /// resources. The container transitions to
    /// [`ContainerLifecycleState::Terminated`] via `Terminating`.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if resource release fails
    /// (best-effort cleanup is performed regardless).
    fn terminate(&self, id: ContainerId) -> ContainerResult<()>;

    /// Read-only query for the current lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if `id` does not refer to
    /// a container managed by this engine.
    fn state(&self, id: ContainerId) -> ContainerResult<ContainerLifecycleState>;

    /// Generate a per-container attestation quote.
    ///
    /// The quote covers the host TEE measurement, the guest kernel
    /// hash, the OCI image digest, the granted capability set, and a
    /// verifier-supplied nonce, per `NCIP-Container-006` § 6.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Attestation`] if the host has no TEE
    /// available or the underlying [`nexacore_tee::TeeBackend::attest`]
    /// call fails.
    fn attest(&self, id: ContainerId, nonce: &[u8]) -> ContainerResult<ContainerQuote>;
}

// -----------------------------------------------------------------------------
// KVM backend — feature-gated
// -----------------------------------------------------------------------------

/// Per-container runtime state managed by [`KvmEngine`].
///
/// One `ContainerState` entry exists per container registered with the engine.
/// The entry is created by [`KvmEngine::provision`] and remains in the map
/// after termination so that callers can still query the final state via
/// [`KvmEngine::state`].
#[cfg(feature = "kvm")]
struct ContainerState {
    /// The original launch spec.
    ///
    /// Retained for future use by the attestation path — the spec's image
    /// digest and capability profile are bound into the `ContainerQuote`
    /// per `NCIP-Container-006` § 6. The `#[allow]` suppresses the
    /// `dead_code` warning until that path lands in a follow-up NCIP.
    #[allow(dead_code)]
    spec: ContainerSpec,
    /// Current lifecycle state. Updated under the engine lock.
    lifecycle: ContainerLifecycleState,
    /// Handle to the guest VM, set by `provision` and consumed by `terminate`.
    /// `None` after the VM has been destroyed.
    vm_handle: Option<VmHandle>,
    /// Accumulated guest serial output (port `0x3F8` writes).
    console: ConsoleOutput,
    /// Backing memory for the guest physical address space.
    ///
    /// This `Vec<u8>` is allocated in `provision` and registered with the
    /// hypervisor via `set_memory`. It MUST outlive the `vm_handle`: the raw
    /// pointer passed to `set_memory` points into this allocation, and the
    /// [`MockHypervisor`] (and a future real KVM backend) must not access it
    /// after `destroy_vm` is called. We hold the `Vec` here to guarantee the
    /// memory is not dropped until `ContainerState` itself is dropped (which
    /// happens only when the entry is removed from the engine map).
    _guest_mem: Vec<u8>,
}

/// KVM-backed container engine with real state management.
///
/// `KvmEngine` implements the [`ContainerEngine`] trait with actual per-
/// container lifecycle tracking. All container state is stored in an in-process
/// `parking_lot::Mutex<HashMap>`, and all hypervisor operations are dispatched
/// through the [`crate::hypervisor::Hypervisor`] trait.
///
/// For production use, supply a real KVM hypervisor implementation:
/// ```rust,ignore
/// let engine = KvmEngine::new(Box::new(KvmHypervisor::open().expect("open /dev/kvm")));
/// ```
///
/// For tests (no KVM hardware or root required), use [`KvmEngine::with_mock`]:
/// ```rust
/// use nexacore_container::{
///     engine::{ContainerEngine, ContainerSpec, KvmEngine},
///     image::OciImageRef,
///     profile::CapabilityProfile,
/// };
///
/// let engine = KvmEngine::with_mock();
/// let spec = ContainerSpec::new(
///     OciImageRef::parse("alpine:latest").expect("parse"),
///     CapabilityProfile::CliTool,
///     false,
/// );
/// let id = engine.provision(spec).expect("provision");
/// assert_eq!(
///     engine.state(id).expect("state"),
///     nexacore_container::ContainerLifecycleState::Provisioning,
/// );
/// ```
#[cfg(feature = "kvm")]
pub struct KvmEngine {
    /// The hypervisor back-end (real KVM or [`MockHypervisor`] for tests).
    hypervisor: Box<dyn Hypervisor>,
    /// All container state, keyed by [`ContainerId`]. Access requires the
    /// `parking_lot` mutex (no poison semantics — lock calls return the guard
    /// directly).
    containers: Mutex<HashMap<ContainerId, ContainerState>>,
    /// Monotonically increasing counter for generating unique `ContainerId`
    /// values. Starts at `1`; `0` is the sentinel "uninitialized" value.
    next_id: AtomicU64,
}

#[cfg(feature = "kvm")]
impl std::fmt::Debug for KvmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ContainerState` is not `Debug` (it contains `ContainerSpec` which
        // holds a `CapabilityProfile` with a `String` field). We only surface
        // the container count and the next ID counter.
        let count = self.containers.lock().len();
        f.debug_struct("KvmEngine")
            .field("container_count", &count)
            .field("next_id", &self.next_id.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// See the `ContainerEngine` impl block below for rationale on
// `significant_drop_tightening`.
#[cfg(feature = "kvm")]
#[allow(clippy::significant_drop_tightening)]
impl KvmEngine {
    /// Construct a `KvmEngine` backed by the given [`Hypervisor`] implementation.
    ///
    /// Use this constructor when you have a real KVM (or TDX/SEV-SNP) back-end.
    /// For tests, prefer [`KvmEngine::with_mock`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::{engine::KvmEngine, hypervisor::MockHypervisor};
    ///
    /// let engine = KvmEngine::new(Box::new(MockHypervisor::new()));
    /// ```
    #[must_use]
    pub fn new(hypervisor: Box<dyn Hypervisor>) -> Self {
        Self {
            hypervisor,
            containers: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Construct a `KvmEngine` backed by the in-memory [`MockHypervisor`].
    ///
    /// This is the standard entry-point for unit and integration tests. No
    /// hardware virtualisation, `/dev/kvm`, or root privileges are required.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::{
    ///     engine::{ContainerEngine, ContainerSpec, KvmEngine},
    ///     image::OciImageRef,
    ///     profile::CapabilityProfile,
    /// };
    ///
    /// let engine = KvmEngine::with_mock();
    /// let spec = ContainerSpec::new(
    ///     OciImageRef::parse("alpine:latest").expect("parse"),
    ///     CapabilityProfile::CliTool,
    ///     false,
    /// );
    /// let id = engine.provision(spec).expect("provision");
    /// engine.run(id).expect("run");
    /// let output = engine.console_output(id).expect("console");
    /// assert!(output.contains("hello"));
    /// engine.terminate(id).expect("terminate");
    /// ```
    #[must_use]
    pub fn with_mock() -> Self {
        Self::new(Box::new(MockHypervisor::new()))
    }

    /// Read the accumulated guest serial console output for a container.
    ///
    /// Returns the output as a `String`, leaving the internal buffer unchanged
    /// (non-destructive read). Non-UTF-8 bytes are replaced with `U+FFFD`.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if `id` does not refer to a known
    /// container.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::{
    ///     engine::{ContainerEngine, ContainerSpec, KvmEngine},
    ///     image::OciImageRef,
    ///     profile::CapabilityProfile,
    /// };
    ///
    /// let engine = KvmEngine::with_mock();
    /// let spec = ContainerSpec::new(
    ///     OciImageRef::parse("alpine:latest").expect("parse"),
    ///     CapabilityProfile::CliTool,
    ///     false,
    /// );
    /// let id = engine.provision(spec).expect("provision");
    /// engine.run(id).expect("run");
    /// let out = engine.console_output(id).expect("console_output");
    /// assert!(out.contains("hello"));
    /// ```
    pub fn console_output(&self, id: ContainerId) -> ContainerResult<String> {
        let containers = self.containers.lock();
        let state = containers.get(&id).ok_or(ContainerError::Backend(
            "engine::kvm::console_output::not_found",
        ))?;
        // Return the raw buffered text so the caller sees the exact bytes
        // (including the trailing newline that run_vcpu writes). We use
        // `as_bytes()` because `ConsoleOutput::buf` is a private field.
        Ok(String::from_utf8_lossy(state.console.as_bytes()).into_owned())
    }

    /// Allocate a new, unique `ContainerId`. Starts at 1; 0 is reserved.
    fn alloc_id(&self) -> ContainerId {
        ContainerId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Execute the vCPU run loop for a container, capturing console output.
    ///
    /// This method drives the mock (or real) guest until the vCPU halts or
    /// shuts down. All `IoOut` exits on port `0x3F8` are forwarded to the
    /// container's `ConsoleOutput`. The containers lock is NOT held during the
    /// run loop to avoid contention with concurrent `state()` calls; it is
    /// acquired only at the start (to read the VM handle) and at the end (to
    /// write back console bytes).
    #[allow(
        clippy::cognitive_complexity,
        reason = "guest run loop: branches mirror VM lifecycle + console I/O states"
    )]
    fn run_guest(&self, id: ContainerId) -> ContainerResult<()> {
        // Step 1: retrieve the VM handle under the lock, then release it.
        let vm_handle = {
            let containers = self.containers.lock();
            let state = containers
                .get(&id)
                .ok_or(ContainerError::Backend("engine::kvm::run_guest::not_found"))?;
            state
                .vm_handle
                .as_ref()
                .ok_or(ContainerError::Backend(
                    "engine::kvm::run_guest::no_vm_handle",
                ))?
                .clone()
        };

        let vcpu = self.hypervisor.create_vcpu(&vm_handle, 0)?;
        tracing::debug!(
            container_id = id.as_raw(),
            "engine: vCPU created, entering run loop"
        );

        // Step 2: run loop — accumulate console bytes locally.
        let mut console_bytes: Vec<u8> = Vec::new();
        loop {
            match self.hypervisor.run_vcpu(&vcpu)? {
                VcpuExit::IoOut { port: 0x3F8, data } => {
                    tracing::debug!(
                        container_id = id.as_raw(),
                        bytes = data.len(),
                        "engine: COM1 serial output"
                    );
                    console_bytes.extend_from_slice(&data);
                }
                VcpuExit::IoOut { port, .. } => {
                    // Non-serial I/O port write — ignored in v0.1.
                    tracing::debug!(container_id = id.as_raw(), port, "engine: IoOut (ignored)");
                }
                VcpuExit::MmioWrite { addr, .. } => {
                    // MMIO write — ignored in v0.1 (virtio-mmio landing later).
                    tracing::debug!(
                        container_id = id.as_raw(),
                        addr,
                        "engine: MmioWrite (ignored)"
                    );
                }
                VcpuExit::Halt | VcpuExit::Shutdown => {
                    tracing::debug!(container_id = id.as_raw(), "engine: guest halted/shutdown");
                    break;
                }
                VcpuExit::InternalError => {
                    return Err(ContainerError::Backend(
                        "engine::kvm::run_guest::internal_error",
                    ));
                }
            }
        }

        // Step 3: write captured console bytes back under the lock.
        let mut containers = self.containers.lock();
        let state = containers.get_mut(&id).ok_or(ContainerError::Backend(
            "engine::kvm::run_guest::not_found_post_run",
        ))?;
        for b in console_bytes {
            state.console.write_byte(b);
        }

        Ok(())
    }
}

// The `significant_drop_tightening` lint fires on every method that acquires
// the containers lock and then returns data borrowed from the guard (e.g.,
// `state()` returns `ContainerLifecycleState` copied from the guard, but
// clippy cannot prove the copy before the lock can be released). In all
// cases the guard IS released at the earliest possible point — either at the
// end of a block expression or when the function returns. The `#[allow]` is
// scoped to this impl block only.
#[cfg(feature = "kvm")]
#[allow(clippy::significant_drop_tightening)]
impl ContainerEngine for KvmEngine {
    /// Provision a container: create the guest VM, validate the spec, and
    /// transition the container to [`ContainerLifecycleState::Provisioning`].
    ///
    /// The provisioning sequence:
    ///
    /// 1. Validate that `tee_required` is not set (TEE not yet implemented).
    /// 2. Call `hypervisor.create_vm()` to obtain a `VmHandle`.
    /// 3. Allocate a 64 MiB memory region (`Vec<u8>`) as the guest backing store.
    /// 4. Register the memory via `hypervisor.set_memory()`.
    /// 5. Store the `ContainerState` in the engine map.
    /// 6. Return the `ContainerId`.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if `tee_required` is `true`,
    /// if `create_vm` fails, or if `set_memory` fails.
    fn provision(&self, spec: ContainerSpec) -> ContainerResult<ContainerId> {
        // 64 MiB guest physical memory region. Defined at the top of the
        // function so it comes before any statements (satisfies
        // `clippy::items_after_statement`).
        const GUEST_MEM_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

        // Guard: TEE requirement cannot be satisfied in v0.1.
        if spec.tee_required {
            return Err(ContainerError::Backend(
                "engine::kvm::provision::tee_not_available",
            ));
        }

        tracing::debug!(image = %spec.image, "engine: provisioning container");

        // Create the VM.
        let vm = self.hypervisor.create_vm()?;

        // Allocate 64 MiB of guest physical memory. The Vec is kept alive in
        // `ContainerState::_guest_mem` so its backing pointer remains stable.
        let mut mem: Vec<u8> = vec![0u8; GUEST_MEM_SIZE];
        let host_ptr: *mut u8 = mem.as_mut_ptr();

        // SAFETY: `host_ptr` points to the start of `mem`, which is a valid,
        // aligned, writable region of at least `GUEST_MEM_SIZE` bytes. `mem`
        // is moved into `ContainerState::_guest_mem` below and is never
        // dropped while the container exists (the entry survives until
        // `terminate` completes). The [`MockHypervisor`] implementation of
        // `set_memory` does not dereference `host_ptr`; a future real KVM
        // backend will pass this address to `KVM_SET_USER_MEMORY_REGION`.
        self.hypervisor
            .set_memory(&vm, 0, 0x0000_0000, GUEST_MEM_SIZE, host_ptr)?;

        let id = self.alloc_id();
        {
            let mut containers = self.containers.lock();
            containers.insert(
                id,
                ContainerState {
                    spec,
                    lifecycle: ContainerLifecycleState::Provisioning,
                    vm_handle: Some(vm),
                    console: ConsoleOutput::new(),
                    _guest_mem: mem,
                },
            );
        }

        tracing::debug!(container_id = id.as_raw(), "engine: container provisioned");
        Ok(id)
    }

    /// Transition the container to [`ContainerLifecycleState::Running`] and
    /// execute the guest until it halts.
    ///
    /// Accepted source states (per `NCIP-Container-006` § 5):
    /// `Provisioning`, `Suspended`, `Snapshotted`.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the source state is invalid,
    /// or [`ContainerError::Backend`] if the guest fails to boot.
    fn run(&self, id: ContainerId) -> ContainerResult<()> {
        // Validate and advance lifecycle state; release lock before guest execution.
        {
            let mut containers = self.containers.lock();
            let state = containers
                .get_mut(&id)
                .ok_or(ContainerError::Backend("engine::kvm::run::not_found"))?;
            state.lifecycle = state
                .lifecycle
                .try_transition(ContainerLifecycleState::Running)?;
        }

        tracing::debug!(container_id = id.as_raw(), "engine: running container");
        self.run_guest(id)?;
        tracing::debug!(container_id = id.as_raw(), "engine: container run complete");
        Ok(())
    }

    /// Pause a running container → [`ContainerLifecycleState::Suspended`].
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the container is not in
    /// `Running`.
    fn suspend(&self, id: ContainerId) -> ContainerResult<()> {
        let mut containers = self.containers.lock();
        let state = containers
            .get_mut(&id)
            .ok_or(ContainerError::Backend("engine::kvm::suspend::not_found"))?;
        state.lifecycle = state
            .lifecycle
            .try_transition(ContainerLifecycleState::Suspended)?;
        tracing::debug!(container_id = id.as_raw(), "engine: container suspended");
        Ok(())
    }

    /// Resume a suspended container → [`ContainerLifecycleState::Running`].
    ///
    /// Re-runs the guest vCPU; console output is appended to the existing buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the container is not in
    /// `Suspended`.
    fn resume(&self, id: ContainerId) -> ContainerResult<()> {
        {
            let mut containers = self.containers.lock();
            let state = containers
                .get_mut(&id)
                .ok_or(ContainerError::Backend("engine::kvm::resume::not_found"))?;
            state.lifecycle = state
                .lifecycle
                .try_transition(ContainerLifecycleState::Running)?;
        }

        tracing::debug!(container_id = id.as_raw(), "engine: resuming container");
        self.run_guest(id)?;
        Ok(())
    }

    /// Snapshot a suspended container → [`ContainerLifecycleState::Snapshotted`].
    ///
    /// v0.1 stub: transitions the state; actual memory/disk serialisation and
    /// sealing lands in a follow-up NCIP.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Lifecycle`] if the container is not in
    /// `Suspended`.
    fn snapshot(&self, id: ContainerId) -> ContainerResult<()> {
        let mut containers = self.containers.lock();
        let state = containers
            .get_mut(&id)
            .ok_or(ContainerError::Backend("engine::kvm::snapshot::not_found"))?;
        state.lifecycle = state
            .lifecycle
            .try_transition(ContainerLifecycleState::Snapshotted)?;
        tracing::debug!(
            container_id = id.as_raw(),
            "engine: container snapshotted (stub)"
        );
        Ok(())
    }

    /// Terminate a container: transition through `Terminating → Terminated`
    /// and destroy the guest VM.
    ///
    /// Best-effort cleanup: even if `destroy_vm` returns an error, the
    /// container state is advanced to `Terminated` so no further operations
    /// can be attempted on a partially-cleaned-up container.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if `id` is not found or if the
    /// lifecycle transition is invalid.
    fn terminate(&self, id: ContainerId) -> ContainerResult<()> {
        // Step 1: claim the VM handle and advance to Terminating.
        let vm_handle = {
            let mut containers = self.containers.lock();
            let state = containers
                .get_mut(&id)
                .ok_or(ContainerError::Backend("engine::kvm::terminate::not_found"))?;
            state.lifecycle = state
                .lifecycle
                .try_transition(ContainerLifecycleState::Terminating)?;
            state.vm_handle.take()
        };

        // Step 2: destroy the VM (best-effort; log but do not abort).
        if let Some(vm) = vm_handle {
            if let Err(e) = self.hypervisor.destroy_vm(vm) {
                tracing::warn!(
                    container_id = id.as_raw(),
                    error = %e,
                    "engine: destroy_vm failed (best-effort)"
                );
            }
        }

        // Step 3: advance to Terminated.
        {
            let mut containers = self.containers.lock();
            let state = containers.get_mut(&id).ok_or(ContainerError::Backend(
                "engine::kvm::terminate::not_found_post_destroy",
            ))?;
            state.lifecycle = state
                .lifecycle
                .try_transition(ContainerLifecycleState::Terminated)?;
        }

        tracing::debug!(container_id = id.as_raw(), "engine: container terminated");
        Ok(())
    }

    /// Read-only query for the current lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if `id` does not refer to a
    /// container managed by this engine.
    fn state(&self, id: ContainerId) -> ContainerResult<ContainerLifecycleState> {
        let containers = self.containers.lock();
        let state = containers
            .get(&id)
            .ok_or(ContainerError::Backend("engine::kvm::state::not_found"))?;
        Ok(state.lifecycle)
    }

    /// Attestation stub — TEE attestation is not yet implemented.
    ///
    /// Returns [`ContainerError::NotYetImplemented`] until the TDX / SEV-SNP
    /// attestation path lands in a follow-up NCIP.
    fn attest(&self, _id: ContainerId, _nonce: &[u8]) -> ContainerResult<ContainerQuote> {
        Err(ContainerError::NotYetImplemented("engine::kvm::attest"))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;
    use crate::profile::CapabilityProfile;

    fn sample_spec() -> ContainerSpec {
        ContainerSpec {
            image: OciImageRef::parse("alpine:latest").expect("parses"),
            profile: CapabilityProfile::CliTool,
            tee_required: false,
        }
    }

    #[test]
    fn container_id_round_trip() {
        let raw = 0x1234_5678_9abc_def0_u64;
        let id = ContainerId::from_raw(raw);
        assert_eq!(id.as_raw(), raw);
    }

    #[test]
    fn container_id_default_is_zero() {
        assert_eq!(ContainerId::default().as_raw(), 0);
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_provision_returns_provisioning_state() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Provisioning
        );
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_provision_two_containers_get_distinct_ids() {
        let engine = KvmEngine::with_mock();
        let id1 = engine.provision(sample_spec()).expect("id1");
        let id2 = engine.provision(sample_spec()).expect("id2");
        assert_ne!(id1.as_raw(), id2.as_raw());
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_run_transitions_to_running() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Running
        );
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_run_captures_hello_output() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        let output = engine.console_output(id).expect("console");
        assert!(output.contains("hello"), "console must contain 'hello'");
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_suspend_transitions_to_suspended() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        engine.suspend(id).expect("suspend");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Suspended
        );
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_resume_transitions_back_to_running() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        engine.suspend(id).expect("suspend");
        engine.resume(id).expect("resume");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Running
        );
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_terminate_transitions_to_terminated() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        engine.terminate(id).expect("terminate");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Terminated
        );
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_state_unknown_id_returns_error() {
        let engine = KvmEngine::with_mock();
        let bad_id = ContainerId::from_raw(999_999);
        let err = engine.state(bad_id).expect_err("must error");
        assert!(matches!(err, ContainerError::Backend(_)));
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_run_rejects_wrong_state() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        // Cannot run again from Running — must suspend first.
        let err = engine.run(id).expect_err("must reject Running→Running");
        assert!(matches!(err, ContainerError::Lifecycle(_)));
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_suspend_rejects_non_running() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        // Provisioning → Suspended is invalid.
        let err = engine.suspend(id).expect_err("must reject");
        assert!(matches!(err, ContainerError::Lifecycle(_)));
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_attest_returns_not_yet_implemented() {
        let engine = KvmEngine::with_mock();
        let err = engine
            .attest(ContainerId::from_raw(1), b"nonce")
            .expect_err("stub");
        assert!(matches!(err, ContainerError::NotYetImplemented(_)));
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_tee_required_spec_rejected() {
        let engine = KvmEngine::with_mock();
        let spec = ContainerSpec {
            image: OciImageRef::parse("alpine:latest").expect("parses"),
            profile: CapabilityProfile::CliTool,
            tee_required: true,
        };
        let err = engine.provision(spec).expect_err("tee not available");
        assert!(matches!(err, ContainerError::Backend(_)));
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_snapshot_requires_suspended() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        // Can only snapshot from Suspended; Running → Snapshotted is invalid.
        let err = engine.snapshot(id).expect_err("must reject");
        assert!(matches!(err, ContainerError::Lifecycle(_)));
    }

    #[cfg(feature = "kvm")]
    #[test]
    fn kvm_engine_snapshot_from_suspended_succeeds() {
        let engine = KvmEngine::with_mock();
        let id = engine.provision(sample_spec()).expect("provision");
        engine.run(id).expect("run");
        engine.suspend(id).expect("suspend");
        engine.snapshot(id).expect("snapshot");
        assert_eq!(
            engine.state(id).expect("state"),
            ContainerLifecycleState::Snapshotted
        );
    }
}

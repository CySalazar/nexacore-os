//! Hypervisor abstraction layer for the KVM container engine.
//!
//! This module defines the [`Hypervisor`] trait — the single seam between the
//! engine's lifecycle logic and the underlying hypervisor back-end. The trait
//! mirrors the KVM ioctl surface at a safe, typed level so that:
//!
//! 1. Unit and integration tests can run on any developer machine (including
//!    CI hosts that have no `/dev/kvm` and no root access) by substituting
//!    [`MockHypervisor`].
//! 2. A future `KvmHypervisor` implementation can wire the real ioctls
//!    (`KVM_CREATE_VM`, `KVM_SET_USER_MEMORY_REGION`, `KVM_CREATE_VCPU`,
//!    `KVM_RUN`) without touching any other part of the engine.
//! 3. TDX and SEV-SNP back-ends can provide their own implementations that
//!    intercept the same call sites and add attestation plumbing.
//!
//! ## `set_memory` raw-pointer contract
//!
//! [`Hypervisor::set_memory`] accepts a `*mut u8` host pointer because the
//! underlying `KVM_SET_USER_MEMORY_REGION` ioctl identifies a host virtual
//! address (the start of a pre-allocated memory region) to map into the
//! guest's physical address space. This is the minimal faithful representation
//! of that interface at the Rust level. All safety obligations are **on the
//! caller** (the engine's `provision` method), not on the trait implementor.
//! The doc comment and every call site carry a `// SAFETY:` annotation.
//!
//! ## Mock back-end
//!
//! [`MockHypervisor`] is an in-memory simulator of the minimal guest boot
//! sequence needed by the engine tests:
//!
//! 1. `create_vm` → returns a handle and registers the VM in internal state.
//! 2. `set_memory` → accepted and ignored (the mock does not actually address
//!    the guest's physical memory).
//! 3. `create_vcpu` → returns a handle and registers the vCPU.
//! 4. `run_vcpu` → simulates a simple guest that writes `"hello\n"` to the
//!    serial port (`0x3F8`) then halts. The sequence is:
//!    - First call  → `VcpuExit::IoOut { port: 0x3F8, data: b"hello\n" }`
//!    - Second call → `VcpuExit::Halt`
//! 5. `destroy_vm` → removes the VM from internal state and releases all
//!    associated vCPU entries.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use parking_lot::Mutex;

use crate::{ContainerError, ContainerResult};

// ---------------------------------------------------------------------------
// Opaque handles
// ---------------------------------------------------------------------------

/// Opaque handle referencing a guest VM instance inside the hypervisor.
///
/// The `u64` interior is a hypervisor-assigned identifier. Callers MUST
/// treat it as opaque: comparing handles across different [`Hypervisor`]
/// implementations is meaningless. The sentinel value `0` is reserved and
/// MUST NOT be returned by a conforming implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmHandle(pub(crate) u64);

impl VmHandle {
    /// Borrow the raw identifier. Intended for tracing and audit logs only.
    #[must_use]
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

/// Opaque handle referencing a single virtual CPU inside a guest VM.
///
/// A vCPU handle is always scoped to the VM that created it. Passing a vCPU
/// handle to methods of a different [`Hypervisor`] instance or after
/// [`Hypervisor::destroy_vm`] has been called is a caller-side bug and
/// implementations are permitted to return [`ContainerError::Backend`] in
/// that case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VcpuHandle(pub(crate) u64);

impl VcpuHandle {
    /// Borrow the raw identifier. Intended for tracing and audit logs only.
    #[must_use]
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// vCPU exit reason
// ---------------------------------------------------------------------------

/// The reason a vCPU stopped executing and returned to the host.
///
/// This is a simplified subset of the exit reasons defined by
/// `linux/kvm.h` (`KVM_EXIT_*`). The full set of KVM exits is not modelled
/// here; only the exits that the engine currently handles are represented.
/// Unknown exits map to [`VcpuExit::InternalError`] in the real backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VcpuExit {
    /// The guest executed a `HLT` instruction (or an equivalent guest-halt
    /// sequence). This is the normal termination signal for micro-VM guests
    /// that have finished their work.
    Halt,

    /// The guest performed a PIO write (`OUT` instruction).
    ///
    /// The engine's `run` loop inspects the port number: port `0x3F8` is the
    /// first serial UART (COM1), and its writes are captured into the
    /// container's [`crate::console::ConsoleOutput`].
    IoOut {
        /// x86 I/O port number.
        port: u16,
        /// The bytes written by the guest. For a 1-byte OUT the `Vec` has
        /// exactly one element; for a OUTS (string I/O) it may be longer.
        data: Vec<u8>,
    },

    /// The guest performed an MMIO write to a device-mapped address range.
    ///
    /// v0.1: not handled; reserved for future virtio-mmio backend wiring.
    MmioWrite {
        /// Guest physical address of the write.
        addr: u64,
        /// The bytes written.
        data: Vec<u8>,
    },

    /// The guest requested a system shutdown (e.g., via the ACPI power
    /// button or a `reboot` syscall inside the guest).
    Shutdown,

    /// An unrecoverable internal hypervisor error occurred. The engine MUST
    /// treat this as a terminal condition and transition the container to
    /// `Terminating`.
    InternalError,
}

// ---------------------------------------------------------------------------
// Hypervisor trait
// ---------------------------------------------------------------------------

/// Abstraction over the hypervisor back-end used by [`crate::engine::KvmEngine`].
///
/// All methods are synchronous and fallible. Errors are reported as
/// [`ContainerError`]; the [`ContainerError::Backend`] variant carries a
/// static slug identifying the failed operation so that audit logs are
/// PII-safe.
///
/// ## Thread safety
///
/// Implementations MUST be `Send + Sync` so that the engine can hold them in
/// an `Arc` and share them across async tasks or multiple threads in future
/// work.
///
/// ## Safety contract for `set_memory`
///
/// The `host_ptr` argument to [`Self::set_memory`] is a raw mutable pointer
/// to the start of a host virtual memory region. **The caller is responsible
/// for ensuring that:**
///
/// 1. `host_ptr` is non-null and valid for `size` bytes of read+write access
///    for the entire lifetime of the VM handle.
/// 2. The memory region is page-aligned (4 KiB on x86-64) and its `size` is
///    a multiple of the page size.
/// 3. The region is not concurrently mutated by any Rust-side code after this
///    call returns (the guest may write to it at any time).
///
/// Implementations that do not actually dereference the pointer (e.g.,
/// [`MockHypervisor`]) may ignore these requirements.
pub trait Hypervisor: Send + Sync {
    /// Create a new guest VM. Returns a [`VmHandle`] that identifies the VM
    /// for all subsequent operations.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if the hypervisor cannot allocate
    /// resources for a new VM (e.g., because `/dev/kvm` is unavailable or the
    /// system limit on concurrent VMs has been reached).
    fn create_vm(&self) -> ContainerResult<VmHandle>;

    /// Register a host memory region as a guest physical memory slot.
    ///
    /// `slot` is the guest memory slot index (0-based; KVM allows up to 509
    /// usable slots on x86-64). `guest_addr` is the guest physical address at
    /// which the region appears. `size` is the length in bytes. `host_ptr` is
    /// the start of the pre-allocated host memory.
    ///
    /// # Safety (caller obligation)
    ///
    /// See the [`Hypervisor`] trait-level documentation for the full contract
    /// on `host_ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if the ioctl fails (e.g., misaligned
    /// `guest_addr`, overlapping slot, or invalid `vm` handle).
    fn set_memory(
        &self,
        vm: &VmHandle,
        slot: u32,
        guest_addr: u64,
        size: usize,
        host_ptr: *mut u8,
    ) -> ContainerResult<()>;

    /// Create a virtual CPU attached to `vm`. Returns a [`VcpuHandle`]
    /// identifying the new vCPU.
    ///
    /// `id` is the logical vCPU index (0-based). For single-vCPU guests (the
    /// v0.1 norm) `id` is always `0`.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if the vCPU cannot be created (e.g.,
    /// the VM already has the maximum number of vCPUs, or `vm` is invalid).
    fn create_vcpu(&self, vm: &VmHandle, id: u32) -> ContainerResult<VcpuHandle>;

    /// Run the vCPU until it exits to the host. Returns the exit reason.
    ///
    /// This method blocks until the guest causes a VM-exit. The engine's `run`
    /// loop calls this method in a loop, handling each exit in turn, until it
    /// observes [`VcpuExit::Halt`] or [`VcpuExit::Shutdown`].
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if the `KVM_RUN` ioctl fails or if
    /// `vcpu` is not a valid handle.
    fn run_vcpu(&self, vcpu: &VcpuHandle) -> ContainerResult<VcpuExit>;

    /// Destroy a VM and release all hypervisor resources associated with it.
    ///
    /// After this call the `vm` handle is consumed and MUST NOT be used again.
    /// All vCPU handles associated with this VM become invalid. The caller is
    /// responsible for ensuring no thread is executing inside [`Self::run_vcpu`]
    /// for a vCPU of this VM when `destroy_vm` is called.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::Backend`] if resource release fails. Best-
    /// effort cleanup is performed regardless of the error.
    fn destroy_vm(&self, vm: VmHandle) -> ContainerResult<()>;
}

// ---------------------------------------------------------------------------
// MockHypervisor — in-memory simulation
// ---------------------------------------------------------------------------

/// State tracked per-VM inside the mock.
#[derive(Debug)]
struct MockVmState {
    /// vCPU entries: maps vCPU handle id → step counter.
    ///
    /// Step `0` → next `run_vcpu` emits `IoOut("hello\n" to 0x3F8)`.
    /// Step `1+` → `Halt` (idempotent after first halt).
    vcpus: HashMap<u64, usize>,
}

/// In-memory mock hypervisor for testing.
///
/// [`MockHypervisor`] simulates the minimal guest boot sequence required by
/// the engine integration tests without requiring `/dev/kvm`, root privileges,
/// or any hardware virtualisation support. It is entirely safe and runs on any
/// platform.
///
/// ## Simulated guest behaviour
///
/// When [`Hypervisor::run_vcpu`] is called on a vCPU for the first time, the
/// mock returns:
///
/// ```text
/// VcpuExit::IoOut { port: 0x3F8, data: b"hello\n".to_vec() }
/// ```
///
/// The second (and all subsequent) calls return [`VcpuExit::Halt`]. This
/// simulates a trivial guest that prints one line to the serial console and
/// then halts.
///
/// ## Example
///
/// ```rust
/// use nexacore_container::hypervisor::{Hypervisor, MockHypervisor, VcpuExit};
///
/// let hv = MockHypervisor::new();
/// let vm = hv.create_vm().expect("create_vm");
/// let vcpu = hv.create_vcpu(&vm, 0).expect("create_vcpu");
///
/// // First run: guest writes "hello\n" to serial port.
/// let exit = hv.run_vcpu(&vcpu).expect("run_vcpu");
/// assert!(matches!(exit, VcpuExit::IoOut { port: 0x3F8, .. }));
///
/// // Second run: guest halts.
/// let exit2 = hv.run_vcpu(&vcpu).expect("run_vcpu");
/// assert_eq!(exit2, VcpuExit::Halt);
///
/// hv.destroy_vm(vm).expect("destroy_vm");
/// ```
#[derive(Debug, Default)]
pub struct MockHypervisor {
    /// Counter for generating unique VM / vCPU handles.
    next_id: AtomicU64,
    /// Per-VM state tracked in the mock.
    ///
    /// `parking_lot::Mutex` is used instead of `std::sync::Mutex` per
    /// workspace policy (`clippy.toml` disallowed-methods). It does not
    /// have poison semantics, so lock calls return the guard directly.
    vms: Mutex<HashMap<u64, MockVmState>>,
}

impl MockHypervisor {
    /// Construct a new, empty mock hypervisor.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nexacore_container::hypervisor::MockHypervisor;
    /// let hv = MockHypervisor::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            vms: Mutex::new(HashMap::new()),
        }
    }

    /// Allocate a unique, non-zero `u64` handle id.
    fn alloc_id(&self) -> u64 {
        // Relaxed ordering is sufficient: we only need uniqueness, not
        // ordering relative to any other memory operation.
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

// The `significant_drop_tightening` lint fires on `set_memory`,
// `create_vcpu`, `run_vcpu`, and `destroy_vm` because the lock guard covers
// the entire method body. In each case the guard IS needed for the full
// scope (we read or mutate the map through its full extent). The `#[allow]`
// is scoped to this impl block only.
#[allow(clippy::significant_drop_tightening)]
impl Hypervisor for MockHypervisor {
    fn create_vm(&self) -> ContainerResult<VmHandle> {
        let id = self.alloc_id();
        self.vms.lock().insert(
            id,
            MockVmState {
                vcpus: HashMap::new(),
            },
        );
        tracing::debug!(vm_id = id, "mock: create_vm");
        Ok(VmHandle(id))
    }

    fn set_memory(
        &self,
        vm: &VmHandle,
        slot: u32,
        guest_addr: u64,
        size: usize,
        // The mock intentionally does not dereference this pointer.
        // A conforming caller must still satisfy the safety contract
        // documented on the trait; here we just accept and discard it.
        _host_ptr: *mut u8,
    ) -> ContainerResult<()> {
        let vms = self.vms.lock();
        if !vms.contains_key(&vm.0) {
            return Err(ContainerError::Backend(
                "mock::hypervisor::set_memory::invalid_vm",
            ));
        }
        tracing::debug!(
            vm_id = vm.0,
            slot,
            guest_addr,
            size,
            "mock: set_memory (accepted, not mapped)"
        );
        Ok(())
    }

    fn create_vcpu(&self, vm: &VmHandle, id: u32) -> ContainerResult<VcpuHandle> {
        let vcpu_handle_id = self.alloc_id();
        let mut vms = self.vms.lock();
        let vm_state = vms.get_mut(&vm.0).ok_or(ContainerError::Backend(
            "mock::hypervisor::create_vcpu::invalid_vm",
        ))?;
        // Register the vCPU with step 0 (first run_vcpu will produce IoOut).
        vm_state.vcpus.insert(vcpu_handle_id, 0);
        tracing::debug!(
            vm_id = vm.0,
            vcpu_id = vcpu_handle_id,
            logical_id = id,
            "mock: create_vcpu"
        );
        Ok(VcpuHandle(vcpu_handle_id))
    }

    fn run_vcpu(&self, vcpu: &VcpuHandle) -> ContainerResult<VcpuExit> {
        let mut vms = self.vms.lock();

        // Find the VM that owns this vCPU handle by scanning all VMs.
        // This linear scan is acceptable for a mock with a small number of VMs.
        let step = vms
            .values_mut()
            .find_map(|vm_state| vm_state.vcpus.get_mut(&vcpu.0))
            .ok_or(ContainerError::Backend(
                "mock::hypervisor::run_vcpu::invalid_vcpu",
            ))?;

        let current_step = *step;
        // Advance the step counter so the next call returns Halt.
        *step = current_step.saturating_add(1);

        let exit = if current_step == 0 {
            // First run: guest writes "hello\n" to the first serial UART (COM1,
            // port 0x3F8).
            tracing::debug!(
                vcpu_id = vcpu.0,
                "mock: run_vcpu → IoOut(0x3F8, \"hello\\n\")"
            );
            VcpuExit::IoOut {
                port: 0x3F8,
                data: b"hello\n".to_vec(),
            }
        } else {
            // Second and subsequent runs: guest has halted.
            tracing::debug!(vcpu_id = vcpu.0, "mock: run_vcpu → Halt");
            VcpuExit::Halt
        };

        Ok(exit)
    }

    fn destroy_vm(&self, vm: VmHandle) -> ContainerResult<()> {
        self.vms
            .lock()
            .remove(&vm.0)
            .ok_or(ContainerError::Backend(
                "mock::hypervisor::destroy_vm::invalid_vm",
            ))?;
        tracing::debug!(vm_id = vm.0, "mock: destroy_vm");
        Ok(())
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

    // Helper: create a VM and one vCPU in the mock.
    fn setup() -> (MockHypervisor, VmHandle, VcpuHandle) {
        let hv = MockHypervisor::new();
        let vm = hv.create_vm().expect("create_vm");
        let vcpu = hv.create_vcpu(&vm, 0).expect("create_vcpu");
        (hv, vm, vcpu)
    }

    #[test]
    fn create_vm_returns_nonzero_handle() {
        let hv = MockHypervisor::new();
        let vm = hv.create_vm().expect("create_vm");
        assert_ne!(vm.as_raw(), 0, "handle must be non-zero");
    }

    #[test]
    fn two_vms_get_distinct_handles() {
        let hv = MockHypervisor::new();
        let vm1 = hv.create_vm().expect("vm1");
        let vm2 = hv.create_vm().expect("vm2");
        assert_ne!(vm1.as_raw(), vm2.as_raw());
    }

    #[test]
    fn create_vcpu_returns_nonzero_handle() {
        let (hv, vm, _) = setup();
        let v2 = hv.create_vcpu(&vm, 1).expect("vcpu");
        assert_ne!(v2.as_raw(), 0);
    }

    #[test]
    fn set_memory_succeeds_on_valid_vm() {
        let hv = MockHypervisor::new();
        let vm = hv.create_vm().expect("vm");
        // SAFETY: the mock does not dereference host_ptr; passing a null
        // pointer is safe specifically for MockHypervisor (not for real KVM).
        let result = hv.set_memory(&vm, 0, 0x0000, 4096, std::ptr::null_mut());
        assert!(result.is_ok(), "set_memory must succeed on a valid VM");
    }

    #[test]
    fn set_memory_fails_on_invalid_vm() {
        let hv = MockHypervisor::new();
        let fake_vm = VmHandle(9999);
        // SAFETY: mock does not dereference; null is safe here.
        let err = hv
            .set_memory(&fake_vm, 0, 0x0, 4096, std::ptr::null_mut())
            .expect_err("invalid vm should fail");
        assert!(matches!(err, ContainerError::Backend(_)));
    }

    #[test]
    fn run_vcpu_first_call_is_io_out_serial() {
        let (hv, _vm, vcpu) = setup();
        let exit = hv.run_vcpu(&vcpu).expect("run_vcpu");
        match exit {
            VcpuExit::IoOut { port, ref data } => {
                assert_eq!(port, 0x3F8, "must be COM1 serial port");
                assert_eq!(data, b"hello\n");
            }
            other => panic!("expected IoOut, got {other:?}"),
        }
    }

    #[test]
    fn run_vcpu_second_call_is_halt() {
        let (hv, _vm, vcpu) = setup();
        // Consume the IoOut.
        let _ = hv.run_vcpu(&vcpu).expect("first run");
        let exit = hv.run_vcpu(&vcpu).expect("second run");
        assert_eq!(exit, VcpuExit::Halt);
    }

    #[test]
    fn run_vcpu_subsequent_calls_stay_halt() {
        let (hv, _vm, vcpu) = setup();
        let _ = hv.run_vcpu(&vcpu).expect("first");
        for _ in 0..5 {
            let e = hv.run_vcpu(&vcpu).expect("subsequent");
            assert_eq!(e, VcpuExit::Halt);
        }
    }

    #[test]
    fn run_vcpu_on_invalid_handle_returns_error() {
        let hv = MockHypervisor::new();
        let bad_vcpu = VcpuHandle(42_000);
        let err = hv.run_vcpu(&bad_vcpu).expect_err("invalid handle");
        assert!(matches!(err, ContainerError::Backend(_)));
    }

    #[test]
    fn destroy_vm_removes_vm() {
        let hv = MockHypervisor::new();
        let vm = hv.create_vm().expect("vm");
        let vm_id = vm.as_raw();
        hv.destroy_vm(vm).expect("destroy_vm");
        // After destruction the ID is gone; verify via set_memory on a ghost handle.
        let ghost = VmHandle(vm_id);
        // SAFETY: mock does not dereference; null is safe here.
        let err = hv
            .set_memory(&ghost, 0, 0x0, 4096, std::ptr::null_mut())
            .expect_err("destroyed vm");
        assert!(matches!(err, ContainerError::Backend(_)));
    }

    #[test]
    fn destroy_vm_on_invalid_handle_returns_error() {
        let hv = MockHypervisor::new();
        let fake = VmHandle(99_999);
        let err = hv.destroy_vm(fake).expect_err("invalid vm");
        assert!(matches!(err, ContainerError::Backend(_)));
    }

    #[test]
    fn vm_handle_as_raw_round_trips() {
        let h = VmHandle(42);
        assert_eq!(h.as_raw(), 42);
    }

    #[test]
    fn vcpu_handle_as_raw_round_trips() {
        let h = VcpuHandle(99);
        assert_eq!(h.as_raw(), 99);
    }
}

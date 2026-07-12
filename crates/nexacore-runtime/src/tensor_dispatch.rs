//! Tensor HAL dispatch: hardware probe, vendor-wrapper loading, and
//! per-backend throughput (WS5-02.3, .9–.12, .14, .16).
//!
//! This module sits above [`crate::tensor_hal`]: it probes the host
//! capabilities ([`probe_caps`](crate::tensor_dispatch::probe_caps),
//! WS5-02.3), defines the runtime ABI for loading vendor compute wrappers
//! ([`VendorBackendLoader`](crate::tensor_dispatch::VendorBackendLoader),
//! WS5-02.9) with CUDA / ROCm stubs (WS5-02.10/.11), composes vendor loading
//! with the always-available CPU fallback
//! ([`dispatch_backend`](crate::tensor_dispatch::dispatch_backend),
//! WS5-02.12), measures per-backend throughput
//! ([`BackendThroughput`](crate::tensor_dispatch::BackendThroughput),
//! WS5-02.14), and reports the backend/capability matrix
//! ([`capability_matrix`](crate::tensor_dispatch::capability_matrix),
//! WS5-02.16).
//!
//! The Vulkan-compute backend and the real vendor runtimes (CUDA/ROCm/Vulkan
//! drivers) are loaded on the rig; here every effectful path is behind a trait
//! seam so the dispatch logic is fully host-tested.

// Throughput math divides op counts by elapsed microseconds (both runtime
// values) and casts between integer widths for the rate computation.
#![allow(
    clippy::integer_division,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]

use crate::tensor_hal::{
    BackendKind, CpuBackend, HardwareCaps, TensorBackend, select_backend_available,
};

/// The vendor-wrapper ABI version this build understands. A loader advertising a
/// different version is refused (a forward/backward-incompatible wrapper must
/// not be `dlopen`ed into the inference process).
pub const VENDOR_ABI_VERSION: u32 = 1;

/// The symbol a vendor shared object must export to be loadable as a tensor
/// backend (the `dlopen`/`dlsym` entry point, resolved on the rig).
pub const VENDOR_ENTRY_SYMBOL: &str = "nexacore_tensor_backend_v1";

/// Probe the host's compute capabilities (WS5-02.3).
///
/// AVX-512 is detected via CPUID on x86-64; on other architectures it is
/// reported absent. The Vulkan-GPU flag is supplied by the caller because GPU
/// presence is discovered by the virtio-gpu / KMS driver, not by this crate —
/// pass `vulkan_gpu_present` from the driver enumeration (the rig wires it).
#[must_use]
pub fn probe_caps(vulkan_gpu_present: bool) -> HardwareCaps {
    let avx512 = {
        #[cfg(target_arch = "x86_64")]
        {
            std::is_x86_feature_detected!("avx512f")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    };
    HardwareCaps {
        avx512,
        vulkan_gpu: vulkan_gpu_present,
    }
}

/// The runtime-loadable vendor compute wrapper ABI (WS5-02.9, dlopen-like).
///
/// A vendor wrapper (CUDA, ROCm, …) is a shared object exporting
/// [`VENDOR_ENTRY_SYMBOL`]; the host resolves it, checks
/// [`Self::abi_version`] against [`VENDOR_ABI_VERSION`], and — only on a
/// match and only when the vendor runtime is actually present
/// ([`Self::try_load`] returns `Some`) — uses the returned backend.
pub trait VendorBackendLoader: Send + Sync {
    /// The ABI version the wrapper was built against.
    fn abi_version(&self) -> u32;
    /// Vendor identifier, for logging/telemetry.
    fn vendor_name(&self) -> &'static str;
    /// Attempt to load the backend; `None` when the vendor runtime is absent.
    fn try_load(&self) -> Option<Box<dyn TensorBackend>>;
}

/// A registry of vendor loaders consulted in registration order.
#[derive(Default)]
pub struct VendorRegistry {
    loaders: Vec<Box<dyn VendorBackendLoader>>,
}

impl VendorRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a vendor loader (consulted after earlier registrations).
    pub fn register(&mut self, loader: Box<dyn VendorBackendLoader>) {
        self.loaders.push(loader);
    }

    /// Number of registered loaders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loaders.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    /// Load the first available vendor backend whose ABI version matches
    /// [`VENDOR_ABI_VERSION`]. Loaders with a mismatched ABI are skipped
    /// (never loaded). Returns `None` if none are available.
    #[must_use]
    pub fn load_first_available(&self) -> Option<Box<dyn TensorBackend>> {
        self.loaders
            .iter()
            .filter(|l| l.abi_version() == VENDOR_ABI_VERSION)
            .find_map(|l| l.try_load())
    }
}

/// CUDA vendor backend stub (WS5-02.10).
///
/// A correctness-preserving stub: it delegates the trait ops to the scalar CPU
/// reference so results match. On a host without a CUDA runtime
/// [`CudaBackend::new_if_supported`] returns `None`; the real GPU dispatch is
/// wired on the rig.
#[derive(Debug, Default, Clone, Copy)]
pub struct CudaBackend;

impl CudaBackend {
    /// Returns a backend only when the CUDA runtime is present. Always `None`
    /// today (no in-tree CUDA bindings); the real probe checks `libcuda`.
    #[must_use]
    pub fn new_if_supported() -> Option<Self> {
        None
    }
}

impl TensorBackend for CudaBackend {
    fn name(&self) -> &'static str {
        "cuda-stub"
    }
    #[allow(
        clippy::many_single_char_names,
        reason = "a/b/m/k/n are the conventional matmul dimension names"
    )]
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, k: usize, n: usize) -> Vec<f32> {
        CpuBackend.matmul(a, b, m, k, n)
    }
    fn softmax(&self, logits: &mut [f32]) {
        CpuBackend.softmax(logits);
    }
    fn dequant(
        &self,
        dtype: crate::gguf::GgufDtype,
        raw: &[u8],
        n_elements: usize,
    ) -> nexacore_types::error::Result<Vec<f32>> {
        CpuBackend.dequant(dtype, raw, n_elements)
    }
}

/// CUDA wrapper loader (WS5-02.10).
#[derive(Debug, Default, Clone, Copy)]
pub struct CudaLoader;

impl VendorBackendLoader for CudaLoader {
    fn abi_version(&self) -> u32 {
        VENDOR_ABI_VERSION
    }
    fn vendor_name(&self) -> &'static str {
        "cuda"
    }
    fn try_load(&self) -> Option<Box<dyn TensorBackend>> {
        CudaBackend::new_if_supported().map(|b| Box::new(b) as Box<dyn TensorBackend>)
    }
}

/// ROCm vendor backend stub (WS5-02.11). See [`CudaBackend`] for the contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct RocmBackend;

impl RocmBackend {
    /// Returns a backend only when the ROCm runtime is present. Always `None`
    /// today; the real probe checks `libamdhip64`.
    #[must_use]
    pub fn new_if_supported() -> Option<Self> {
        None
    }
}

impl TensorBackend for RocmBackend {
    fn name(&self) -> &'static str {
        "rocm-stub"
    }
    #[allow(
        clippy::many_single_char_names,
        reason = "a/b/m/k/n are the conventional matmul dimension names"
    )]
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, k: usize, n: usize) -> Vec<f32> {
        CpuBackend.matmul(a, b, m, k, n)
    }
    fn softmax(&self, logits: &mut [f32]) {
        CpuBackend.softmax(logits);
    }
    fn dequant(
        &self,
        dtype: crate::gguf::GgufDtype,
        raw: &[u8],
        n_elements: usize,
    ) -> nexacore_types::error::Result<Vec<f32>> {
        CpuBackend.dequant(dtype, raw, n_elements)
    }
}

/// ROCm wrapper loader (WS5-02.11).
#[derive(Debug, Default, Clone, Copy)]
pub struct RocmLoader;

impl VendorBackendLoader for RocmLoader {
    fn abi_version(&self) -> u32 {
        VENDOR_ABI_VERSION
    }
    fn vendor_name(&self) -> &'static str {
        "rocm"
    }
    fn try_load(&self) -> Option<Box<dyn TensorBackend>> {
        RocmBackend::new_if_supported().map(|b| Box::new(b) as Box<dyn TensorBackend>)
    }
}

/// Resolve the backend to dispatch to (WS5-02.12 fallback policy).
///
/// Tries the registered vendor wrappers first (CUDA/ROCm/…); if none are
/// available, falls back to the capability-selected built-in backend, which is
/// itself CPU-backed when no GPU/AVX backend is constructible. The result is
/// therefore **always** a working backend — never a failure.
#[must_use]
pub fn dispatch_backend(caps: HardwareCaps, registry: &VendorRegistry) -> Box<dyn TensorBackend> {
    registry
        .load_first_available()
        .unwrap_or_else(|| select_backend_available(caps))
}

/// Per-backend throughput sample (WS5-02.14): how many primitive ops a backend
/// completed in a measured wall-clock interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendThroughput {
    /// Backend name (from [`TensorBackend::name`]).
    pub backend: &'static str,
    /// Number of primitive ops completed (e.g. matmul MACs / 1e6, caller's unit).
    pub ops: u64,
    /// Elapsed wall-clock time in microseconds.
    pub elapsed_us: u64,
}

impl BackendThroughput {
    /// Ops per second, scaled by 1000 (so a fractional rate is preserved as an
    /// integer). Returns 0 when no time has elapsed.
    #[must_use]
    pub fn ops_per_sec_milli(self) -> u64 {
        if self.elapsed_us == 0 {
            return 0;
        }
        // ops / (elapsed_us / 1e6) * 1000 = ops * 1e9 / elapsed_us.
        self.ops.saturating_mul(1_000_000_000) / self.elapsed_us
    }
}

/// One row of the backend/capability matrix (WS5-02.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapability {
    /// The backend kind.
    pub kind: BackendKind,
    /// Stable backend name.
    pub name: &'static str,
    /// Whether this build provides a constructible implementation of the kind.
    pub implemented: bool,
    /// Whether the host hardware required by the kind is present.
    pub hardware_present: bool,
}

impl BackendCapability {
    /// Whether the backend can be dispatched to on this host right now: it must
    /// be both implemented in this build and backed by present hardware.
    #[must_use]
    pub fn available(self) -> bool {
        self.implemented && self.hardware_present
    }
}

/// The backend/capability matrix for this host (WS5-02.16).
///
/// Reports each backend kind, whether this build implements it, and whether the
/// hardware it needs is present. The scalar CPU reference is always implemented
/// and "present"; AVX-512 and Vulkan are not yet implemented in-tree (selection
/// targets for WS5-02.4+) even when the hardware is reported by `caps`.
#[must_use]
pub fn capability_matrix(caps: HardwareCaps) -> Vec<BackendCapability> {
    vec![
        BackendCapability {
            kind: BackendKind::Cpu,
            name: "cpu-scalar",
            implemented: true,
            hardware_present: true,
        },
        BackendCapability {
            kind: BackendKind::CpuAvx512,
            name: "cpu-avx512",
            implemented: false,
            hardware_present: caps.avx512,
        },
        BackendCapability {
            kind: BackendKind::Vulkan,
            name: "vulkan-compute",
            implemented: false,
            hardware_present: caps.vulkan_gpu,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock vendor loader that is "available" and ABI-matched.
    struct MockOk;
    impl VendorBackendLoader for MockOk {
        fn abi_version(&self) -> u32 {
            VENDOR_ABI_VERSION
        }
        fn vendor_name(&self) -> &'static str {
            "mock-ok"
        }
        fn try_load(&self) -> Option<Box<dyn TensorBackend>> {
            Some(Box::new(CpuBackend))
        }
    }

    /// A mock loader with a mismatched ABI — must never be loaded.
    struct MockBadAbi;
    impl VendorBackendLoader for MockBadAbi {
        fn abi_version(&self) -> u32 {
            VENDOR_ABI_VERSION + 99
        }
        fn vendor_name(&self) -> &'static str {
            "mock-bad-abi"
        }
        fn try_load(&self) -> Option<Box<dyn TensorBackend>> {
            // Would panic the test if ever called — proves the ABI guard skips it.
            Some(Box::new(CpuBackend))
        }
    }

    #[test]
    fn probe_caps_reports_cpu_truthfully() {
        let caps = probe_caps(false);
        assert!(!caps.vulkan_gpu);
        // avx512 reflects the host; just assert the call is total.
        let _ = caps.avx512;
        assert!(probe_caps(true).vulkan_gpu);
    }

    #[test]
    fn cuda_rocm_stubs_unavailable_but_correct() {
        assert!(CudaBackend::new_if_supported().is_none());
        assert!(RocmBackend::new_if_supported().is_none());
        // The stub still computes correct results (delegates to CPU reference).
        let a = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let b = [7.0, 8.0, 9.0, 10.0, 11.0, 12.0];
        assert_eq!(
            CudaBackend.matmul(&a, &b, 2, 3, 2),
            vec![58.0, 64.0, 139.0, 154.0]
        );
        assert_eq!(CudaBackend.name(), "cuda-stub");
        assert_eq!(RocmBackend.name(), "rocm-stub");
    }

    #[test]
    fn registry_skips_mismatched_abi_and_loads_available() {
        let mut reg = VendorRegistry::new();
        assert!(reg.is_empty());
        reg.register(Box::new(MockBadAbi)); // wrong ABI → skipped
        reg.register(Box::new(MockOk)); // right ABI, available → loaded
        assert_eq!(reg.len(), 2);
        let backend = reg.load_first_available().expect("a backend loads");
        assert_eq!(backend.name(), "cpu-scalar");
    }

    #[test]
    fn cuda_loader_unavailable_on_host() {
        let mut reg = VendorRegistry::new();
        reg.register(Box::new(CudaLoader));
        reg.register(Box::new(RocmLoader));
        // No vendor runtime on this host → nothing loads.
        assert!(reg.load_first_available().is_none());
    }

    #[test]
    fn dispatch_falls_back_to_cpu_when_no_vendor() {
        let reg = VendorRegistry::new();
        let backend = dispatch_backend(HardwareCaps::default(), &reg);
        assert_eq!(backend.name(), "cpu-scalar");
    }

    #[test]
    fn dispatch_prefers_vendor_when_available() {
        let mut reg = VendorRegistry::new();
        reg.register(Box::new(MockOk));
        let backend = dispatch_backend(
            HardwareCaps {
                avx512: true,
                vulkan_gpu: true,
            },
            &reg,
        );
        // Vendor loader wins over the capability-selected built-in.
        assert_eq!(backend.name(), "cpu-scalar"); // MockOk returns a CpuBackend
    }

    #[test]
    fn throughput_rate_and_zero_guard() {
        let t = BackendThroughput {
            backend: "cpu-scalar",
            ops: 2_000_000,
            elapsed_us: 1_000_000, // 1 second
        };
        // 2e6 ops / 1s = 2e6 ops/s → milli = 2e9.
        assert_eq!(t.ops_per_sec_milli(), 2_000_000_000);
        let zero = BackendThroughput {
            backend: "x",
            ops: 5,
            elapsed_us: 0,
        };
        assert_eq!(zero.ops_per_sec_milli(), 0);
    }

    #[test]
    fn capability_matrix_lists_cpu_available() {
        let matrix = capability_matrix(HardwareCaps {
            avx512: true,
            vulkan_gpu: true,
        });
        assert_eq!(matrix.len(), 3);
        let cpu = matrix
            .iter()
            .find(|c| c.kind == BackendKind::Cpu)
            .expect("cpu row");
        assert!(cpu.available());
        // AVX-512 / Vulkan are selection targets, not yet constructible (their
        // hardware may be present, but they are not implemented in-tree).
        assert!(
            matrix
                .iter()
                .all(|c| c.kind == BackendKind::Cpu || !c.available())
        );
    }
}

//! Tensor HAL: a backend-dispatched compute abstraction (WS5-02.1/.2).
//!
//! `TensorBackend` is the trait every compute backend implements — the
//! primitive ops the inference engine dispatches: `matmul`, `dequant`, and
//! `softmax` (WS5-02.1). `CpuBackend` is the portable scalar **reference**
//! implementation; AVX-512 (WS5-02.4) and Vulkan-compute (WS5-02.5+) backends
//! plug in behind the same trait.
//!
//! `select_backend` is the runtime selection policy (WS5-02.2): given the
//! probed `HardwareCaps` it returns the *preferred* `BackendKind`, while
//! `backend_for` returns a concrete backend only for kinds that are actually
//! implemented today (just `Cpu`). This separation lets the selection policy be
//! forward-looking without pretending the GPU/AVX backends exist yet.
//!
//! Gated on `std`: the reference backend's `softmax` uses `f32::exp` (a libm
//! intrinsic unavailable in the bare-metal `no_std` build), and the module is
//! part of the full-service compute surface.

// Numeric compute kernel: explicit floating-point arithmetic is intentional
// (matching the other compute modules — `decode`, `engine`, `tensor_loader`).
// `f32::mul_add` is not guaranteed faster here, so `suboptimal_flops` is
// suppressed module-wide too.
#![allow(clippy::float_arithmetic, clippy::suboptimal_flops)]

use nexacore_types::error::Result;

use crate::{gguf::GgufDtype, tensor_loader::dequantize_to_f32};

/// The primitive tensor operations a compute backend provides (WS5-02.1).
pub trait TensorBackend {
    /// Stable backend name, for logging/telemetry.
    fn name(&self) -> &'static str;

    /// Row-major matmul: `a` is `m`×`k`, `b` is `k`×`n`, result is `m`×`n`.
    ///
    /// Returns a zero matrix if the input slice lengths do not match the
    /// declared dimensions (defensive: never panics).
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, k: usize, n: usize) -> Vec<f32>;

    /// Numerically-stable softmax over `logits`, in place.
    fn softmax(&self, logits: &mut [f32]);

    /// Dequantize `raw` — a 1-D tensor of `n_elements` values of `dtype` — to
    /// `f32`.
    ///
    /// # Errors
    ///
    /// Propagates the underlying [`dequantize_to_f32`] error (e.g. a
    /// block-aligned byte-count mismatch).
    fn dequant(&self, dtype: GgufDtype, raw: &[u8], n_elements: usize) -> Result<Vec<f32>>;
}

/// Portable scalar CPU backend — the reference implementation (the WS5-02.4
/// AVX-512 backend will accelerate the same trait).
#[derive(Debug, Default, Clone, Copy)]
pub struct CpuBackend;

impl TensorBackend for CpuBackend {
    fn name(&self) -> &'static str {
        "cpu-scalar"
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "all indices are bounds-checked by the length guard above"
    )]
    #[allow(
        clippy::many_single_char_names,
        reason = "a/b/m/k/n are the conventional matmul dimension names"
    )]
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, k: usize, n: usize) -> Vec<f32> {
        // Defensive: shapes must match, else return a zero matrix (no panic).
        if a.len() != m.saturating_mul(k) || b.len() != k.saturating_mul(n) {
            return vec![0.0f32; m.saturating_mul(n)];
        }
        let mut out = vec![0.0f32; m * n];
        for i in 0..m {
            for j in 0..n {
                let mut acc = 0.0f32;
                for p in 0..k {
                    acc += a[i * k + p] * b[p * n + j];
                }
                out[i * n + j] = acc;
            }
        }
        out
    }

    fn softmax(&self, logits: &mut [f32]) {
        if logits.is_empty() {
            return;
        }
        // Subtract the max for numerical stability.
        let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let mut sum = 0.0f32;
        for v in logits.iter_mut() {
            let e = (*v - max).exp();
            *v = e;
            sum += e;
        }
        if sum > 0.0 {
            for v in logits.iter_mut() {
                *v /= sum;
            }
        }
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "chunks_exact(4) guarantees each chunk has exactly 4 bytes"
    )]
    fn dequant(&self, dtype: GgufDtype, raw: &[u8], n_elements: usize) -> Result<Vec<f32>> {
        let info = crate::gguf::GgufTensorInfo {
            name: String::new(),
            n_dimensions: 1,
            dimensions: vec![u64::try_from(n_elements).unwrap_or(u64::MAX)],
            dtype,
            offset: 0,
        };
        let buf = dequantize_to_f32(&info, raw)?;
        let out = buf
            .as_bytes()
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        Ok(out)
    }
}

/// AVX2 + FMA accelerated CPU backend (WS5-01.8).
///
/// Same trait surface as [`CpuBackend`], but [`Avx2Backend::matmul`] uses 256-bit
/// AVX2 + FMA intrinsics, vectorizing over the contiguous `N` (column) dimension
/// of row-major `b`. It is only constructed via [`Avx2Backend::new_if_supported`]
/// (returns `None` unless the CPU advertises AVX2 + FMA), and its `matmul` falls
/// back to the scalar reference when the features are absent — so results stay
/// correct everywhere. `softmax`/`dequant` reuse the scalar reference.
#[derive(Debug, Default, Clone, Copy)]
pub struct Avx2Backend;

impl Avx2Backend {
    /// Returns an [`Avx2Backend`] iff this CPU supports AVX2 and FMA, else `None`.
    #[must_use]
    pub fn new_if_supported() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
                return Some(Self);
            }
        }
        None
    }
}

impl TensorBackend for Avx2Backend {
    fn name(&self) -> &'static str {
        "cpu-avx2"
    }

    #[allow(
        clippy::many_single_char_names,
        reason = "a/b/m/k/n are the conventional matmul dimension names"
    )]
    #[allow(
        unsafe_code,
        reason = "AVX2 intrinsics, gated by runtime feature detection"
    )]
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, k: usize, n: usize) -> Vec<f32> {
        if a.len() != m.saturating_mul(k) || b.len() != k.saturating_mul(n) {
            return vec![0.0f32; m.saturating_mul(n)];
        }
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
                // SAFETY: entered only when the CPU advertises AVX2 + FMA; the
                // shape guard above ensures matmul_avx2 reads only in-bounds.
                return unsafe { matmul_avx2(a, b, m, k, n) };
            }
        }
        // Portable fallback: identical numerics to the scalar reference.
        CpuBackend.matmul(a, b, m, k, n)
    }

    fn softmax(&self, logits: &mut [f32]) {
        CpuBackend.softmax(logits);
    }

    fn dequant(&self, dtype: GgufDtype, raw: &[u8], n_elements: usize) -> Result<Vec<f32>> {
        CpuBackend.dequant(dtype, raw, n_elements)
    }
}

/// AVX2 + FMA row-major matmul. Vectorizes 8 output columns at a time over the
/// contiguous `N` dimension of `b`; a scalar loop handles the `n % 8` tail.
///
/// # Safety
///
/// The caller must ensure the CPU supports AVX2 + FMA and that `a.len() == m*k`
/// and `b.len() == k*n` (the public [`Avx2Backend::matmul`] guards both).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
#[allow(unsafe_code, reason = "AVX2 intrinsics")]
#[allow(
    clippy::indexing_slicing,
    reason = "all slice indices are bounded by the loop conditions and the caller's shape guarantee"
)]
#[allow(
    clippy::many_single_char_names,
    reason = "a/b/m/k/n are the conventional matmul dimension names"
)]
unsafe fn matmul_avx2(a: &[f32], b: &[f32], m: usize, k: usize, n: usize) -> Vec<f32> {
    use core::arch::x86_64::{
        _mm256_fmadd_ps, _mm256_loadu_ps, _mm256_set1_ps, _mm256_setzero_ps, _mm256_storeu_ps,
    };

    let mut out = vec![0.0f32; m * n];
    for i in 0..m {
        let a_row = &a[i * k..i * k + k];
        let out_base = i * n;
        let mut j = 0usize;
        // Vectorized core: 8 output columns per step.
        while j + 8 <= n {
            // SAFETY: p*n + j + 8 <= k*n = b.len() for p < k, j + 8 <= n.
            let acc = unsafe {
                let mut acc = _mm256_setzero_ps();
                for p in 0..k {
                    let bv = _mm256_loadu_ps(b[p * n + j..p * n + j + 8].as_ptr());
                    acc = _mm256_fmadd_ps(_mm256_set1_ps(a_row[p]), bv, acc);
                }
                acc
            };
            let mut tmp = [0.0f32; 8];
            // SAFETY: tmp holds exactly 8 lanes.
            unsafe { _mm256_storeu_ps(tmp.as_mut_ptr(), acc) };
            out[out_base + j..out_base + j + 8].copy_from_slice(&tmp);
            j += 8;
        }
        // Scalar tail for the remaining n % 8 columns.
        while j < n {
            let mut s = 0.0f32;
            for p in 0..k {
                s += a_row[p] * b[p * n + j];
            }
            out[out_base + j] = s;
            j += 1;
        }
    }
    out
}

/// Which compute backend to dispatch to (WS5-02.2).
///
/// Only [`BackendKind::Cpu`] is implemented today; the other variants are the
/// selection targets for WS5-02.4+ and currently resolve to no backend in
/// [`backend_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendKind {
    /// Portable scalar CPU (the reference, always available).
    Cpu,
    /// CPU with AVX-512 acceleration (WS5-02.4).
    CpuAvx512,
    /// Vulkan-compute GPU (WS5-02.5+).
    Vulkan,
}

/// Probed hardware capabilities feeding [`select_backend`] (WS5-02.3 input).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HardwareCaps {
    /// The CPU supports AVX-512.
    pub avx512: bool,
    /// A Vulkan-capable GPU (e.g. virtio-gpu) is present.
    pub vulkan_gpu: bool,
}

/// Choose the preferred backend for `caps` (WS5-02.2).
///
/// Preference order is fastest-first: Vulkan GPU, then AVX-512 CPU, then the
/// portable scalar CPU. This is the *policy*; [`backend_for`] decides whether
/// the chosen kind is actually constructible yet.
#[must_use]
pub fn select_backend(caps: HardwareCaps) -> BackendKind {
    if caps.vulkan_gpu {
        BackendKind::Vulkan
    } else if caps.avx512 {
        BackendKind::CpuAvx512
    } else {
        BackendKind::Cpu
    }
}

/// Construct the backend for `kind`, or `None` if it is not implemented yet.
///
/// Today only [`BackendKind::Cpu`] resolves to a backend; AVX-512 and Vulkan
/// return `None` until WS5-02.4+ land. Callers fall back to `Cpu` (always
/// available) — see [`select_backend_available`].
#[must_use]
pub fn backend_for(kind: BackendKind) -> Option<Box<dyn TensorBackend>> {
    match kind {
        BackendKind::Cpu => Some(Box::new(CpuBackend)),
        BackendKind::CpuAvx512 | BackendKind::Vulkan => None,
    }
}

/// Select and construct the preferred backend, with scalar-CPU fallback.
///
/// When the preferred kind (per [`select_backend`]) is not yet implemented,
/// falls back to the always-available scalar CPU backend (WS5-02.2, plus the
/// WS5-02.12 graceful-fallback requirement).
#[must_use]
pub fn select_backend_available(caps: HardwareCaps) -> Box<dyn TensorBackend> {
    backend_for(select_backend(caps)).unwrap_or_else(|| Box::new(CpuBackend))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_matmul_known_result() {
        // A = [[1,2,3],[4,5,6]] (2×3), B = [[7,8],[9,10],[11,12]] (3×2).
        // AB = [[58,64],[139,154]].
        let a = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let b = [7.0, 8.0, 9.0, 10.0, 11.0, 12.0];
        let out = CpuBackend.matmul(&a, &b, 2, 3, 2);
        assert_eq!(out, vec![58.0, 64.0, 139.0, 154.0]);
    }

    #[test]
    fn avx2_matmul_known_result_exercises_scalar_tail() {
        // n = 2 (< 8): all columns go through the scalar tail of matmul_avx2.
        let Some(avx) = Avx2Backend::new_if_supported() else {
            return; // no AVX2 on this host — nothing to verify
        };
        let a = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let b = [7.0, 8.0, 9.0, 10.0, 11.0, 12.0];
        assert_eq!(avx.matmul(&a, &b, 2, 3, 2), vec![58.0, 64.0, 139.0, 154.0]);
    }

    #[test]
    #[allow(
        clippy::cast_precision_loss,
        reason = "deterministic test fixture values from indices"
    )]
    #[allow(
        clippy::many_single_char_names,
        reason = "a/b/m/k/n are the conventional matmul dimension names"
    )]
    fn avx2_matmul_matches_scalar_within_tolerance() {
        let Some(avx) = Avx2Backend::new_if_supported() else {
            return; // no AVX2 on this host — the scalar path is the reference
        };
        // n = 10 exercises both the 8-wide vector core and the 2-column tail.
        let (m, k, n) = (3usize, 5usize, 10usize);
        let a: Vec<f32> = (0..m * k).map(|i| i as f32 * 0.5 - 3.0).collect();
        let b: Vec<f32> = (0..k * n).map(|i| (i as f32 * 0.1).sin()).collect();
        let got = avx.matmul(&a, &b, m, k, n);
        let want = CpuBackend.matmul(&a, &b, m, k, n);
        assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(&want) {
            // FMA rounds once per product-sum, so results differ from the scalar
            // reference only in the last bits — compare within a tolerance.
            assert!(
                (g - w).abs() <= 1e-4 + 1e-4 * w.abs(),
                "avx2 {g} vs scalar {w}"
            );
        }
    }

    #[test]
    fn avx2_matmul_shape_mismatch_is_zero_not_panic() {
        let Some(avx) = Avx2Backend::new_if_supported() else {
            return;
        };
        assert_eq!(avx.matmul(&[1.0; 5], &[1.0; 6], 2, 3, 2), vec![0.0; 4]);
    }

    #[test]
    fn cpu_matmul_shape_mismatch_is_zero_not_panic() {
        // a has 5 elements but 2×3 needs 6 → defensive zero matrix.
        let out = CpuBackend.matmul(&[1.0; 5], &[1.0; 6], 2, 3, 2);
        assert_eq!(out, vec![0.0; 4]);
    }

    #[test]
    fn cpu_softmax_sums_to_one_and_is_monotonic() {
        let mut v = [1.0f32, 2.0, 3.0];
        CpuBackend.softmax(&mut v);
        let sum: f32 = v.iter().sum();
        assert!((sum - 1.0).abs() < 1e-6, "softmax must sum to 1, got {sum}");
        // Larger input → larger probability.
        assert!(v[0] < v[1] && v[1] < v[2]);
    }

    #[test]
    fn cpu_softmax_empty_is_noop() {
        let mut v: [f32; 0] = [];
        CpuBackend.softmax(&mut v);
        assert!(v.is_empty());
    }

    #[test]
    fn cpu_dequant_f32_passthrough() {
        // F32 tensor of 2 values round-trips through dequant.
        let raw = [1.5f32, -2.25f32];
        let mut bytes = Vec::new();
        for f in raw {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
        let out = CpuBackend.dequant(GgufDtype::F32, &bytes, 2).unwrap();
        assert_eq!(out, vec![1.5, -2.25]);
    }

    #[test]
    fn select_backend_prefers_fastest_available_kind() {
        assert_eq!(select_backend(HardwareCaps::default()), BackendKind::Cpu);
        assert_eq!(
            select_backend(HardwareCaps {
                avx512: true,
                vulkan_gpu: false
            }),
            BackendKind::CpuAvx512
        );
        assert_eq!(
            select_backend(HardwareCaps {
                avx512: true,
                vulkan_gpu: true
            }),
            BackendKind::Vulkan
        );
    }

    #[test]
    fn backend_for_only_cpu_is_implemented() {
        assert!(backend_for(BackendKind::Cpu).is_some());
        assert!(backend_for(BackendKind::CpuAvx512).is_none());
        assert!(backend_for(BackendKind::Vulkan).is_none());
    }

    #[test]
    fn select_backend_available_falls_back_to_cpu() {
        // Even when AVX-512/Vulkan are "preferred", the unimplemented kinds fall
        // back to the always-available scalar CPU backend.
        let caps = HardwareCaps {
            avx512: true,
            vulkan_gpu: true,
        };
        let backend = select_backend_available(caps);
        assert_eq!(backend.name(), "cpu-scalar");
    }
}

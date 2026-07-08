//! # `nexacore-hal`
//!
//! Hardware Abstraction Layer for NexaCore OS.
//!
//! Defines vendor-neutral traits for the four hardware classes that NexaCore OS
//! cares about: tensor accelerators (CPU/GPU/NPU), networking, storage, and
//! TEEs. Userspace services depend on traits in this crate; concrete
//! backends are loaded at runtime based on detected hardware.
//!
//! ## Status
//!
//! Draft v0.2 — the [`tee`] module now re-exports [`nexacore_tee`]'s trait
//! surface so consumers can write `use nexacore_hal::tee::TeeBackend;` and not
//! care that the underlying implementation lives in a sibling crate.
//! Tensor, network, and storage modules remain scaffolds; their P1+
//! implementations land per the roadmap.
//!
//! ## Design rationale
//!
//! - **Trait-based dispatch**: callers don't know whether inference runs
//!   on CPU AVX-512, NVIDIA CUDA, or an integrated NPU. The HAL hides it.
//! - **Runtime backend selection**: concrete backends (e.g., CUDA wrappers)
//!   are dynamically loaded. Missing hardware is detected gracefully.
//! - **Async by default**: I/O and inference workloads are async-first.
//! - **TEE HAL is mandatory**: a node without a working TEE HAL cannot
//!   participate in the mesh.
//!
//! ## Modules
//!
//! - [`tensor`] — Tensor HAL (compute dispatch).
//! - [`network`] — Network HAL (transport-agnostic).
//! - [`storage`] — Storage HAL (block + filesystem-friendly).
//! - [`tee`] — TEE HAL (re-exports from [`nexacore_tee`]).

// TASK-13-pre / ADR-0034: make nexacore-hal no_std-capable behind a default-on
// `std` feature.  When std is absent we still depend on `alloc` for Vec /
// String / Box.
#![cfg_attr(not(feature = "std"), no_std)]
#![doc(html_root_url = "https://docs.nexacore-os.org/nexacore-hal")]
#![deny(missing_docs)]
// Test helpers freely use indexing, float arithmetic, direct comparisons, and
// other patterns that are intentionally forbidden in production code.  Allowing
// them in the cfg(test) context is ADR-0003-compliant: it is NOT a blanket
// group-allow at crate root but a narrowly-scoped test-only exemption.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unnecessary_wraps,
        clippy::indexing_slicing,
        clippy::float_arithmetic,
        clippy::cast_precision_loss,
        clippy::suboptimal_flops,
        clippy::float_cmp,
        clippy::identity_op,
        clippy::erasing_op,
        clippy::redundant_clone,
        clippy::integer_division,
    )
)]

// Pull in heap allocation primitives when building without the standard library.
// The `alloc` crate is always available in Rust when `extern crate alloc` is
// declared; the global allocator is provided by the consumer crate (e.g. the
// bump allocator in the Ring 3 image).
#[cfg(not(feature = "std"))]
extern crate alloc;

/// Transcendental float shim — routes `sqrt`, `exp`, `sin`, `cos`, `powf`, and
/// `tanh` to `f32` inherent methods under `std` and to `libm` under `no_std`.
///
/// Call sites in [`transformer`] and [`tensor`] use `crate::math::*` so that
/// the transcendental path is a single audited point (ADR-0034).
pub mod math;

/// Tensor HAL — uniform compute dispatch across CPU/GPU/NPU.
///
/// See [`tensor`] for the full type surface: [`tensor::TensorBackend`],
/// [`tensor::CpuBackend`], [`tensor::TensorDtype`], etc.
pub mod tensor;

/// Transformer inference building blocks — composing `TensorOp` primitives.
///
/// Provides a synchronous-logic, async-surface forward pass for LLaMA-style
/// decoder-only transformers.  See [`transformer::transformer_forward`].
pub mod transformer;

/// Network HAL — transport-agnostic networking primitives.
pub mod network {
    // TODO(phase-1): `NetworkBackend` trait covering Ethernet/Wi-Fi.
}

/// Storage HAL — block storage abstractions.
pub mod storage {
    // TODO(phase-1): `BlockDevice` and friends (NVMe-first).
}

/// TEE HAL — re-exports and integration with [`nexacore_tee`].
///
/// Consumers that want the TEE trait surface should `use nexacore_hal::tee::*`
/// (or pull individual symbols). The point of this module is to give
/// every HAL consumer a single dependency (`nexacore-hal`) instead of two
/// (`nexacore-hal` plus `nexacore-tee`), which simplifies the build graph and
/// makes the workspace's HAL story coherent.
///
/// This module is only present when the `std` feature is active (TEE
/// backends require the standard library; TASK-13-pre / ADR-0034).
///
/// Future additions: a `select_tee_backend()` helper that detects the
/// available TEE family at runtime and returns a `Box<dyn TeeBackend>`.
/// That helper requires `std`; it will land behind a feature flag when
/// `nexacore-runtime` integrates it.
#[cfg(feature = "std")]
pub mod tee {
    // Re-export the full vendor-neutral surface.
    // Re-export concrete backends when their features are enabled. Each
    // re-export is gated on the same feature as the backend itself, so a
    // build that didn't enable `tdx` does not need to compile its
    // dependencies.
    #[cfg(feature = "mock")]
    pub use nexacore_tee::MockTeeBackend;
    #[cfg(feature = "sev-snp")]
    pub use nexacore_tee::sev_snp::SevSnpBackend;
    #[cfg(feature = "tdx")]
    pub use nexacore_tee::tdx::TdxBackend;
    // Backend routing: CPU-vendor detection + `select_tee_family` (WS10-02.9/.10,
    // closing WS10-01.12). Vendor-neutral, so re-exported unconditionally.
    pub use nexacore_tee::{
        BackendAvailability, CpuVendor, Measurement, Nonce, Quote, QuoteVersion, SealPolicy,
        SealedBlob, TeeBackend, TeeError, TeeErrorKind, TeeFamily, TeeSharedKey, select_tee_family,
    };
}

#[cfg(test)]
mod tests {
    /// Placeholder test asserting the crate compiles.
    #[test]
    fn placeholder() {}
}

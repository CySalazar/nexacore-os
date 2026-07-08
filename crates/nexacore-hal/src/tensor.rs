//! Tensor HAL — uniform compute dispatch across CPU, GPU, and NPU.
//!
//! This module defines the vendor-neutral types and traits that the rest of
//! NexaCore OS uses to run tensor workloads. Callers never see whether inference
//! runs on CPU AVX-512, NVIDIA CUDA, or an Apple Neural Engine — they just
//! call [`crate::tensor::TensorBackend::execute`].
//!
//! # Design overview
//!
//! ```text
//!   ┌─────────────────────────────────────┐
//!   │         caller (service crate)      │
//!   │  let buf = backend.allocate(&desc)  │
//!   │  let out = backend.execute(op, &[]) │
//!   └───────────────┬─────────────────────┘
//!                   │ dyn TensorBackend
//!         ┌─────────┴──────────┐
//!         │   CpuBackend       │  ← this module
//!         │  (SIMD dispatch)   │
//!         └────────────────────┘
//!         (future: GpuBackend, NpuBackend)
//! ```
//!
//! # `no_std` note
//!
//! `CpuBackend` uses `Vec` (heap) and `is_x86_feature_detected!` (std),
//! so this module requires the standard library.  The *trait surface*
//! (`TensorBackend`, `TensorDescriptor`, `TensorDtype`, etc.) uses only
//! `alloc` types and could be split into a `no_std`-compatible crate in a
//! future refactor.  That split is deferred to Phase 6 per the NexaCore OS
//! `no_std` roadmap.
//!
//! # Async overhead
//!
//! [`crate::tensor::TensorBackend`] is decorated with `#[async_trait]`, which boxes the
//! returned future (`Box<dyn Future>`).  This allocation is intentional:
//! Phase 2 targets correctness, not peak throughput.  A zero-copy,
//! poll-based version is planned for Phase 4 after the SIMD dispatch layer
//! is benchmarked.

// Float arithmetic is pervasive in tensor math; allowing it for this module
// is correct and intentional.  All other workspace lints remain in force.
#![allow(clippy::float_arithmetic)]

// Pull alloc types when std is absent (Vec, String are re-exported from alloc
// in std but live in `alloc` when std is not available).
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use async_trait::async_trait;
use nexacore_types::error::{HalErrorKind, NexaCoreError, Result};

// =============================================================================
// SIMD capability discriminant
// =============================================================================

/// SIMD capability levels detected at runtime on the host CPU.
///
/// Variants are ordered from weakest to strongest within each ISA family.
/// Detection is performed once at [`CpuBackend`] construction time and cached.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::{CpuBackend, SimdCapability, TensorBackend};
///
/// let backend = CpuBackend::new();
/// // At least None is always present; actual level depends on the host CPU.
/// assert!(!backend.capabilities().is_empty());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SimdCapability {
    /// No SIMD support detected; scalar fallback only.
    None,
    /// Intel/AMD SSE 4.2 (128-bit vectors).
    Sse42,
    /// Intel/AMD AVX2 (256-bit vectors, FMA3).
    Avx2,
    /// Intel/AMD AVX-512 (512-bit vectors; implies AVX2).
    Avx512,
    /// ARM Neon / `AdvSIMD` (128-bit vectors).
    Neon,
    /// ARM SVE for `AArch64` (scalable vector extension).
    SveAarch64,
}

// =============================================================================
// Tensor data type
// =============================================================================

/// Numeric data type stored in a [`TensorBuffer`].
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::TensorDtype;
///
/// let dtype = TensorDtype::F32;
/// assert_eq!(dtype.bytes_per_element(), 4);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TensorDtype {
    /// 32-bit single-precision floating point (IEEE 754).
    F32,
    /// 16-bit half-precision floating point (IEEE 754-2008).
    F16,
    /// 16-bit brain float (Google bfloat16; mantissa truncated from F32).
    Bf16,
    /// 8-bit signed integer (quantized inference).
    I8,
    /// 8-bit unsigned integer (quantized inference).
    U8,
}

impl TensorDtype {
    /// Number of bytes needed to store one element of this dtype.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::TensorDtype;
    ///
    /// assert_eq!(TensorDtype::F32.bytes_per_element(), 4);
    /// assert_eq!(TensorDtype::F16.bytes_per_element(), 2);
    /// assert_eq!(TensorDtype::Bf16.bytes_per_element(), 2);
    /// assert_eq!(TensorDtype::I8.bytes_per_element(), 1);
    /// assert_eq!(TensorDtype::U8.bytes_per_element(), 1);
    /// ```
    #[must_use]
    pub const fn bytes_per_element(self) -> usize {
        match self {
            Self::F32 => 4,
            Self::F16 | Self::Bf16 => 2,
            Self::I8 | Self::U8 => 1,
        }
    }
}

// =============================================================================
// TensorDescriptor
// =============================================================================

/// Metadata describing the shape, element type, and optional debug name of a
/// tensor.
///
/// A `TensorDescriptor` is a *logical* description of a tensor — it does not
/// own any data. Pass it to [`TensorBackend::allocate`] to obtain a
/// [`TensorBuffer`] backed by real memory.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::{TensorDescriptor, TensorDtype};
///
/// let desc = TensorDescriptor::new(vec![2, 3], TensorDtype::F32);
/// assert_eq!(desc.byte_size(), 2 * 3 * 4);
///
/// let named = TensorDescriptor::named(vec![1, 768], TensorDtype::F16, "embeddings");
/// assert_eq!(named.name.as_deref(), Some("embeddings"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorDescriptor {
    /// Dimensions from outermost to innermost (row-major / C order).
    ///
    /// An empty `shape` (scalar tensor) is valid; it has exactly one element.
    pub shape: Vec<usize>,

    /// Numeric element type.
    pub dtype: TensorDtype,

    /// Optional human-readable label for diagnostics.  Never used in
    /// correctness-critical paths; purely for tracing/logging.
    pub name: Option<String>,
}

impl TensorDescriptor {
    /// Create an unnamed tensor descriptor.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::new(vec![4, 4], TensorDtype::F32);
    /// assert_eq!(desc.name, None);
    /// ```
    #[must_use]
    pub fn new(shape: Vec<usize>, dtype: TensorDtype) -> Self {
        Self {
            shape,
            dtype,
            name: None,
        }
    }

    /// Create a named tensor descriptor.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::named(vec![1, 512], TensorDtype::Bf16, "hidden");
    /// assert_eq!(desc.name.as_deref(), Some("hidden"));
    /// ```
    #[must_use]
    pub fn named(shape: Vec<usize>, dtype: TensorDtype, name: impl Into<String>) -> Self {
        Self {
            shape,
            dtype,
            name: Some(name.into()),
        }
    }

    /// Total number of elements across all dimensions.
    ///
    /// A scalar tensor (empty `shape`) has exactly 1 element.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::new(vec![3, 4, 5], TensorDtype::F32);
    /// assert_eq!(desc.num_elements(), 60);
    ///
    /// // Scalar: empty shape → 1 element.
    /// let scalar = TensorDescriptor::new(vec![], TensorDtype::F32);
    /// assert_eq!(scalar.num_elements(), 1);
    /// ```
    #[must_use]
    pub fn num_elements(&self) -> usize {
        // product-of-dimensions; identity for empty iterator is 1 (scalar).
        self.shape.iter().product()
    }

    /// Total size in bytes required to hold all elements.
    ///
    /// Computed as `num_elements() * dtype.bytes_per_element()`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::new(vec![2, 3], TensorDtype::F32);
    /// assert_eq!(desc.byte_size(), 24); // 6 elements × 4 bytes
    /// ```
    #[must_use]
    pub fn byte_size(&self) -> usize {
        self.num_elements() * self.dtype.bytes_per_element()
    }
}

// =============================================================================
// TensorBuffer
// =============================================================================

/// An opaque byte buffer paired with its [`TensorDescriptor`].
///
/// `TensorBuffer` is the physical counterpart to [`TensorDescriptor`]: the
/// descriptor records what shape and type the tensor has, while this struct
/// holds the raw bytes.
///
/// Buffers are created via [`TensorBackend::allocate`] and consumed by
/// [`TensorBackend::execute`].  Callers should not inspect the raw bytes
/// unless implementing a backend.
///
/// # Example
///
/// ```rust
/// use nexacore_hal::tensor::{TensorBuffer, TensorDescriptor, TensorDtype};
///
/// let desc = TensorDescriptor::new(vec![2], TensorDtype::F32);
/// let buf = TensorBuffer::new(desc.clone(), vec![0u8; desc.byte_size()]);
/// assert_eq!(buf.len(), 8);
/// assert!(!buf.is_empty());
/// ```
#[derive(Debug)]
pub struct TensorBuffer {
    /// Descriptor that was used to allocate this buffer.
    pub descriptor: TensorDescriptor,
    // Raw element bytes.  Layout is always dense row-major (C order).
    bytes: Vec<u8>,
}

impl TensorBuffer {
    /// Construct a `TensorBuffer` from a pre-allocated byte vector.
    ///
    /// Callers are responsible for ensuring `bytes.len()` equals
    /// `descriptor.byte_size()`.  Backends enforce this contract
    /// internally; external callers should use
    /// [`TensorBackend::allocate`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorBuffer, TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::new(vec![4], TensorDtype::U8);
    /// let buf = TensorBuffer::new(desc.clone(), vec![1, 2, 3, 4]);
    /// assert_eq!(buf.as_bytes(), &[1u8, 2, 3, 4]);
    /// ```
    #[must_use]
    pub fn new(descriptor: TensorDescriptor, bytes: Vec<u8>) -> Self {
        Self { descriptor, bytes }
    }

    /// Immutable view of the raw byte content.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorBuffer, TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::new(vec![1], TensorDtype::I8);
    /// let buf = TensorBuffer::new(desc, vec![42]);
    /// assert_eq!(buf.as_bytes(), &[42u8]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Total byte length of this buffer.
    ///
    /// Should equal `self.descriptor.byte_size()` for any well-formed buffer.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorBuffer, TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::new(vec![3], TensorDtype::F16);
    /// let buf = TensorBuffer::new(desc, vec![0u8; 6]);
    /// assert_eq!(buf.len(), 6);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the buffer contains no bytes.
    ///
    /// A well-formed buffer is never empty (even a scalar has `>=1` byte),
    /// but this method is provided to satisfy `clippy::len_without_is_empty`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{TensorBuffer, TensorDescriptor, TensorDtype};
    ///
    /// let desc = TensorDescriptor::new(vec![1], TensorDtype::U8);
    /// let buf = TensorBuffer::new(desc, vec![0]);
    /// assert!(!buf.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// =============================================================================
// Quantization types
// =============================================================================

/// Linear quantization scheme — controls whether parameters are computed
/// globally or per output channel.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::QuantizationScheme;
///
/// let per_tensor = QuantizationScheme::PerTensor;
/// let per_channel = QuantizationScheme::PerChannel { axis: 0 };
/// let _ = format!("{per_tensor:?}");
/// let _ = format!("{per_channel:?}");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuantizationScheme {
    /// Compute a single scale and zero-point from the whole tensor.
    PerTensor,
    /// Compute independent scale and zero-point for each slice along `axis`.
    ///
    /// This is commonly applied along the output-channel axis (axis 0) of
    /// weight tensors; it preserves more accuracy at a small metadata cost.
    PerChannel {
        /// Dimension along which independent quantization parameters are
        /// computed. Must be less than the tensor rank.
        axis: usize,
    },
}

/// Symmetric or asymmetric INT8 quantization parameters.
///
/// A single (scale, zero\_point) pair maps the floating-point domain to INT8:
/// - Quantize: `q = clamp(round(x / scale) + zero_point, -128, 127)`
/// - Dequantize: `x = (q - zero_point) * scale`
///
/// For symmetric quantization (the default for weight tensors) `zero_point`
/// is `0`, which removes the zero-point correction term from the matmul and
/// reduces arithmetic.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::QuantizationParams;
///
/// let p = QuantizationParams {
///     scale: 0.05,
///     zero_point: 0,
/// };
/// assert_eq!(p.zero_point, 0);
/// // Manually apply dequantize formula.
/// let q: i8 = 64;
/// let x = (f32::from(q) - f32::from(p.zero_point)) * p.scale;
/// assert!((x - 3.2_f32).abs() < 1e-5_f32);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QuantizationParams {
    /// Linear scale factor: maps the INT8 grid step to FP32 units.
    ///
    /// Must be finite and positive. A `scale` of 0 would divide by zero
    /// during quantization and is rejected at runtime.
    pub scale: f32,
    /// Zero-point shift applied after rounding.
    ///
    /// For symmetric quantization set this to `0`. For asymmetric
    /// quantization it centres the representable range on the actual
    /// data distribution, improving accuracy on non-zero-centred activations.
    pub zero_point: i8,
}

// =============================================================================
// TensorOp
// =============================================================================

/// Operations that a [`TensorBackend`] can execute.
///
/// Each variant corresponds to a primitive tensor operation.  The Phase 2
/// `CpuBackend` stubs every op with a zeroed output; real dispatch is Phase 4.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::TensorOp;
///
/// let op = TensorOp::MatMul {
///     transpose_a: false,
///     transpose_b: true,
/// };
/// let _ = format!("{op:?}"); // Debug is always available.
/// ```
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum TensorOp {
    /// Dense matrix multiplication: `C = α·A·B`.
    ///
    /// - `transpose_a`: transpose the first input before multiplication.
    /// - `transpose_b`: transpose the second input before multiplication.
    MatMul {
        /// If `true`, transpose the first input matrix before the multiply.
        transpose_a: bool,
        /// If `true`, transpose the second input matrix before the multiply.
        transpose_b: bool,
    },

    /// Element-wise addition of two tensors with identical shapes.
    Add,

    /// Element-wise `ReLU` activation: `max(0, x)`.
    Relu,

    /// Softmax normalisation along a specified axis.
    Softmax {
        /// The dimension along which softmax is computed.
        axis: usize,
    },

    /// Reshape a tensor to a new shape without copying data.
    ///
    /// The total number of elements must be unchanged.
    Reshape {
        /// Target shape.  Product must equal the source tensor's
        /// [`TensorDescriptor::num_elements`].
        new_shape: Vec<usize>,
    },

    /// Layer normalization: normalize the input across the last (feature) axis.
    ///
    /// For each slice along the last dimension, computes:
    /// `output = (x - mean) / sqrt(variance + epsilon)`.
    ///
    /// The output has the same shape and dtype as the input.
    LayerNorm {
        /// Small constant added to the variance before taking the square root
        /// for numerical stability.  Typical value: `1e-5` or `1e-6`.
        epsilon: f32,
    },

    /// Embedding table lookup: index rows from a 2-D weight table.
    ///
    /// - Input 0: weight table with shape `[vocab_size, embed_dim]`, dtype `F32`.
    /// - Input 1: index tensor with shape `[batch]`, dtype `I8` or `U8`
    ///   (the byte value is cast to `usize` for the row lookup).
    ///
    /// Output shape: `[batch, embed_dim]`, dtype `F32`.
    /// Returns an error if any index is out of bounds.
    EmbeddingLookup,

    /// Permute (transpose) tensor axes.
    ///
    /// `axes[i]` gives the source dimension for output dimension `i`.
    /// For example, a 2-D tensor with `axes = [1, 0]` is a standard matrix
    /// transpose; a 3-D tensor with `axes = [2, 0, 1]` rotates dimensions.
    ///
    /// - Single input required.
    /// - Output shape: `[shape[axes[0]], shape[axes[1]], ...]`.
    Transpose {
        /// Permutation of dimension indices (length must equal the input rank).
        axes: Vec<usize>,
    },

    /// Element-wise GELU activation.
    ///
    /// `output[i] = x * 0.5 * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x³)))`
    ///
    /// Single F32 input; output has the same shape and dtype.
    GeLU,

    /// Multiply every element by a scalar constant.
    ///
    /// Single F32 input; output has the same shape and dtype.
    Scale {
        /// The scalar multiplier applied to every element.
        scalar: f32,
    },

    /// Concatenate multiple tensors along a given axis.
    ///
    /// All inputs must have the same rank and identical extents on every axis
    /// except the concat axis.  The output extent on the concat axis is the
    /// sum of the input extents on that axis.
    Concat {
        /// The axis along which inputs are concatenated (0-based).
        axis: usize,
    },

    /// RMS Layer Normalization (used by `LLaMA` and modern transformers).
    ///
    /// For each slice along the last dimension:
    /// `output = x / sqrt(mean(x²) + epsilon)`
    ///
    /// Weight scaling is handled by the caller (separate `MatMul` or `Scale` op).
    /// Single F32 input; output has the same shape and dtype.
    RmsNorm {
        /// Numerical stability constant added inside the square root.
        epsilon: f32,
    },

    /// Quantize an F32 tensor to INT8 using a linear scale/zero-point mapping.
    ///
    /// The formula is: `q = clamp(round(x / scale) + zero_point, -128, 127)`
    ///
    /// Supports per-tensor and per-channel quantization via [`QuantizationScheme`].
    ///
    /// - Single F32 input; output has the same shape with dtype [`TensorDtype::I8`].
    /// - For per-channel quantization the [`QuantizationParams`] are derived
    ///   automatically from the input data along the specified axis.
    /// - The computed [`QuantizationParams`] (scale, zero\_point) are embedded in the
    ///   returned buffer's descriptor for later use by [`TensorOp::Dequantize`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{QuantizationScheme, TensorOp};
    ///
    /// let op = TensorOp::Quantize {
    ///     scheme: QuantizationScheme::PerTensor,
    /// };
    /// let _ = format!("{op:?}");
    /// ```
    Quantize {
        /// Determines whether quantization parameters are computed globally
        /// (per-tensor) or independently along one axis (per-channel).
        scheme: QuantizationScheme,
    },

    /// Dequantize an INT8 tensor back to F32.
    ///
    /// The formula is: `x = (q - zero_point) * scale`
    ///
    /// - Single I8 input; output has the same shape with dtype [`TensorDtype::F32`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{QuantizationParams, TensorOp};
    ///
    /// let op = TensorOp::Dequantize {
    ///     params: QuantizationParams {
    ///         scale: 0.1,
    ///         zero_point: 0,
    ///     },
    /// };
    /// let _ = format!("{op:?}");
    /// ```
    Dequantize {
        /// Scale and zero-point used during the original quantization step.
        /// These must match the parameters that were used to produce the I8
        /// input tensor, otherwise the reconstructed F32 values will be incorrect.
        params: QuantizationParams,
    },

    /// Matrix multiplication on INT8 tensors with INT32 accumulation.
    ///
    /// Computes `C[i,j] = sum_k A[i,k] * B[k,j]` in the integer domain,
    /// accumulating in `i32` to prevent overflow, then rescales the result to
    /// `f32` via `out_scale`.
    ///
    /// The rescaling formula is:
    /// `c_f32 = (c_i32 - correction) * (scale_a * scale_b) / out_scale`
    ///
    /// For symmetric quantization (`zero_point = 0`), the correction term is 0.
    ///
    /// - Input 0: INT8 matrix A with shape `[M, K]`.
    /// - Input 1: INT8 matrix B with shape `[K, N]`.
    /// - Output: F32 matrix C with shape `[M, N]`.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{QuantizationParams, TensorOp};
    ///
    /// let op = TensorOp::QuantizedMatMul {
    ///     params_a: QuantizationParams {
    ///         scale: 0.01,
    ///         zero_point: 0,
    ///     },
    ///     params_b: QuantizationParams {
    ///         scale: 0.01,
    ///         zero_point: 0,
    ///     },
    ///     out_scale: 1.0,
    /// };
    /// let _ = format!("{op:?}");
    /// ```
    QuantizedMatMul {
        /// Quantization parameters for the first (A) input matrix.
        params_a: QuantizationParams,
        /// Quantization parameters for the second (B) input matrix.
        params_b: QuantizationParams,
        /// Output scale factor applied after integer accumulation.
        /// Set to `1.0` to get raw dequantized values; set to a larger value
        /// to keep output in a numerically stable range.
        out_scale: f32,
    },
}

// =============================================================================
// TensorBackend trait — async surface (std only)
// =============================================================================

/// Vendor-neutral interface for running tensor workloads.
///
/// Implementors hide the specifics of the underlying hardware (CPU with
/// AVX-512, NVIDIA CUDA, Apple ANE, etc.).  NexaCore OS selects a backend at
/// runtime based on [`SimdCapability`] detection and available drivers.
///
/// # Async contract
///
/// `allocate` and `execute` are `async` because GPU and NPU backends
/// communicate over device queues which are inherently asynchronous.  The
/// CPU backend returns immediately inside an `async fn`, so the overhead is
/// one `Box` allocation per call (see crate-level async overhead note).
///
/// # Object safety
///
/// The trait is object-safe: `Box<dyn TensorBackend>` is valid and used by
/// `nexacore-runtime`'s backend registry.
///
/// # Availability
///
/// This trait is only available when the `std` feature is enabled (it requires
/// `async_trait`, which depends on `std`).  For `no_std` builds use the sync
/// methods [`CpuBackend::execute_sync`] and [`CpuBackend::allocate_sync`]
/// directly (TASK-13-pre / ADR-0034).
///
/// # Example
///
/// ```no_run
/// # use nexacore_hal::tensor::{CpuBackend, TensorBackend, TensorDescriptor, TensorDtype, TensorOp};
/// # #[tokio::main]
/// # async fn main() -> nexacore_types::error::Result<()> {
/// let backend = CpuBackend::new();
/// let desc = TensorDescriptor::new(vec![4, 4], TensorDtype::F32);
/// let buf = backend.allocate(&desc).await?;
/// assert_eq!(buf.len(), 64);
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "std")]
#[async_trait]
pub trait TensorBackend: Send + Sync {
    /// Human-readable backend identifier for logging and diagnostics.
    ///
    /// The returned string is always a compile-time literal (`&'static str`).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorBackend};
    ///
    /// let b = CpuBackend::new();
    /// assert_eq!(b.name(), "cpu");
    /// ```
    fn name(&self) -> &'static str;

    /// SIMD capability levels available on this backend, from weakest to
    /// strongest.  The slice is never empty: at minimum it contains
    /// [`SimdCapability::None`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorBackend};
    ///
    /// let b = CpuBackend::new();
    /// assert!(!b.capabilities().is_empty());
    /// ```
    fn capabilities(&self) -> &[SimdCapability];

    /// Allocate a zeroed [`TensorBuffer`] matching `desc`.
    ///
    /// Returns `Err(NexaCoreError::Hal { kind: HardwareUnavailable, .. })` if the
    /// requested size exceeds [`TensorBackend::max_tensor_size_bytes`].
    ///
    /// # Errors
    ///
    /// - [`HalErrorKind::HardwareUnavailable`] — requested allocation exceeds
    ///   the backend's size limit.
    async fn allocate(&self, desc: &TensorDescriptor) -> Result<TensorBuffer>;

    /// Execute `op` on the given input buffers and return a new output buffer.
    ///
    /// For Phase 2, `CpuBackend::execute` returns a zeroed buffer of the
    /// correct output shape.  Real SIMD dispatch lands in Phase 4.
    ///
    /// # Errors
    ///
    /// - [`HalErrorKind::HardwareUnavailable`] — no input provided.
    /// - [`HalErrorKind::DeviceFailure`] — unsupported op/dtype combination
    ///   (never happens in the stub; reserved for Phase 4).
    async fn execute(&self, op: TensorOp, inputs: &[&TensorBuffer]) -> Result<TensorBuffer>;

    /// Returns `true` if this backend can process tensors of the given dtype.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorBackend, TensorDtype};
    ///
    /// let b = CpuBackend::new();
    /// assert!(b.supports_dtype(TensorDtype::F32));
    /// ```
    fn supports_dtype(&self, dtype: TensorDtype) -> bool;

    /// Maximum allocation size in bytes this backend will honour.
    ///
    /// Calls to [`allocate`](TensorBackend::allocate) whose
    /// `desc.byte_size()` exceeds this limit return an error instead of
    /// attempting the allocation.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorBackend};
    ///
    /// let b = CpuBackend::new();
    /// assert!(b.max_tensor_size_bytes() > 0);
    /// ```
    fn max_tensor_size_bytes(&self) -> usize;
}

// =============================================================================
// CpuBackend
// =============================================================================

/// Default HAL backend that runs tensor ops on the host CPU.
///
/// `CpuBackend` detects available SIMD extensions once at construction time
/// (see [`CpuBackend::new`]) and caches them.  The Phase 2 `execute` method
/// is a stub that returns correctly-shaped zeroed buffers; real SIMD dispatch
/// is scheduled for Phase 4.
///
/// # Default limit
///
/// The default maximum allocation is 4 GiB.  Use [`CpuBackend::with_max_bytes`]
/// to override.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::{CpuBackend, TensorBackend};
///
/// let backend = CpuBackend::new();
/// // Always has at least one capability entry (SimdCapability::None minimum).
/// assert!(!backend.capabilities().is_empty());
/// ```
pub struct CpuBackend {
    // Detected SIMD capability set for this CPU.  Always has at least one
    // entry (SimdCapability::None) so that `capabilities()` never returns an
    // empty slice.
    capabilities: Vec<SimdCapability>,

    // Upper bound on single-allocation size.  Enforced in `allocate`.
    max_bytes: usize,
}

/// 4 GiB in bytes — the default maximum tensor allocation for `CpuBackend`.
///
/// This is a safe upper bound that avoids triggering OOM on 64-bit hosts
/// while still accommodating large language model weight tensors.
const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024 * 1024; // 4 GiB

impl CpuBackend {
    /// Create a `CpuBackend` with SIMD auto-detection and a 4 GiB allocation
    /// ceiling.
    ///
    /// SIMD detection uses `is_x86_feature_detected!` on `x86_64` and falls
    /// back to `SimdCapability::None` on all other architectures.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorBackend};
    ///
    /// let backend = CpuBackend::new();
    /// // Capabilities always contains at least one entry.
    /// assert!(!backend.capabilities().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_bytes(DEFAULT_MAX_BYTES)
    }

    /// Create a `CpuBackend` with a custom allocation ceiling.
    ///
    /// Useful in constrained test environments or embedded scenarios where
    /// memory budgets are tight.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorBackend};
    ///
    /// let backend = CpuBackend::with_max_bytes(64 * 1024); // 64 KiB limit
    /// assert_eq!(backend.max_tensor_size_bytes(), 64 * 1024);
    /// ```
    #[must_use]
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        let capabilities = detect_simd_capabilities();
        Self {
            capabilities,
            max_bytes,
        }
    }
}

impl Default for CpuBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect the SIMD capability set available on the current CPU.
///
/// The returned vec always contains at least `SimdCapability::None` as the
/// baseline entry.  On `x86_64` with AVX-512 support, the returned vec is
/// `[None, Sse42, Avx2, Avx512]` (all levels up to and including the
/// strongest detected).
///
/// Detection is performed once per [`CpuBackend`] construction.  Results
/// should be considered stable for the lifetime of a process (CPU features
/// do not change at runtime).
///
/// On `no_std` builds this always returns `[SimdCapability::None]` because
/// `is_x86_feature_detected!` depends on `std` (TASK-13-pre / ADR-0034).
fn detect_simd_capabilities() -> Vec<SimdCapability> {
    // `mut` is consumed only by the cfg-gated detection blocks below, which
    // are all compiled out on `no_std` x86_64 builds (TASK-13-pre / ADR-0034).
    #[cfg_attr(
        not(any(all(feature = "std", target_arch = "x86_64"), target_arch = "aarch64")),
        allow(unused_mut)
    )]
    let mut caps = vec![SimdCapability::None];

    // x86_64-specific detection using the standard library's
    // `is_x86_feature_detected!` macro.  The macro reads CPUID at runtime;
    // no unsafe code is needed.  Gated on `feature = "std"` because the macro
    // requires std (TASK-13-pre / ADR-0034).
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        // Check in ascending order so the vec is ordered weakest → strongest.
        if is_x86_feature_detected!("sse4.2") {
            caps.push(SimdCapability::Sse42);
        }
        if is_x86_feature_detected!("avx2") {
            caps.push(SimdCapability::Avx2);
        }
        // AVX-512 foundation: avx512f is the base feature.
        if is_x86_feature_detected!("avx512f") {
            caps.push(SimdCapability::Avx512);
        }
    }

    // AArch64: Neon is mandatory on all AArch64 CPUs per the ARM architecture
    // specification.  SVE is optional and queried separately.
    #[cfg(target_arch = "aarch64")]
    {
        // Neon (AdvSIMD) is always present on AArch64.
        caps.push(SimdCapability::Neon);

        #[cfg(target_feature = "sve")]
        caps.push(SimdCapability::SveAarch64);
    }

    caps
}

// =============================================================================
// Low-level byte helpers (no unsafe)
// =============================================================================

/// Read a single `f32` from `bytes` at element index `idx` (little-endian).
///
/// Returns an error if the slice does not contain a full 4-byte word at the
/// requested position, preventing out-of-bounds access.
fn read_f32(bytes: &[u8], idx: usize) -> Result<f32> {
    // Each f32 occupies exactly 4 bytes; compute the byte offset.
    let start = idx.checked_mul(4).ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "read_f32::index_overflow")
    })?;
    let end = start
        .checked_add(4)
        .ok_or_else(|| NexaCoreError::hal(HalErrorKind::DeviceFailure, "read_f32::end_overflow"))?;
    // Use TryInto to convert the 4-byte slice to a fixed-size array, avoiding
    // element-by-element indexing that would trigger clippy::indexing_slicing.
    let chunk: [u8; 4] = bytes
        .get(start..end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "read_f32::out_of_bounds")
        })?;
    Ok(f32::from_le_bytes(chunk))
}

/// Write a single `f32` to `bytes` at element index `idx` (little-endian).
///
/// Returns an error if `bytes` does not have room for 4 bytes at the
/// requested offset.
fn write_f32(bytes: &mut [u8], idx: usize, val: f32) -> Result<()> {
    let start = idx.checked_mul(4).ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "write_f32::index_overflow")
    })?;
    let end = start.checked_add(4).ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "write_f32::end_overflow")
    })?;
    let chunk = bytes.get_mut(start..end).ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "write_f32::out_of_bounds")
    })?;
    // copy_from_slice avoids element-by-element indexing into `chunk`.
    chunk.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

// =============================================================================
// Output descriptor derivation
// =============================================================================

/// Derive the output [`TensorDescriptor`] for a given [`TensorOp`] and input set.
///
/// For element-wise ops (`Add`, `Relu`, `Softmax`, `LayerNorm`) the output
/// descriptor inherits the first input's shape and dtype.  `MatMul` computes
/// the output shape from the matrix dimensions.  `EmbeddingLookup` derives
/// `[batch, embed_dim]`.  `Reshape` uses the requested `new_shape`.
///
/// Returns an error if `inputs` is empty for ops that require at least one
/// input, or if there are not enough inputs for multi-input ops.
// This function covers all TensorOp variants; the length is a structural
// necessity of a complete match, not a complexity problem.
#[allow(clippy::too_many_lines)]
fn output_descriptor_for(op: &TensorOp, inputs: &[&TensorBuffer]) -> Result<TensorDescriptor> {
    match op {
        TensorOp::MatMul {
            transpose_a,
            transpose_b,
        } => {
            // MatMul requires exactly 2 inputs: A and B.
            let mat_a = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::matmul::requires_two_inputs",
                )
            })?;
            let mat_b = inputs.get(1).ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::matmul::requires_two_inputs",
                )
            })?;

            // Resolve the effective rows and columns after optional transpose.
            let (rows_out, k_from_a) =
                matmul_effective_dims(&mat_a.descriptor.shape, *transpose_a)?;
            let (k_from_b, cols_out) =
                matmul_effective_dims(&mat_b.descriptor.shape, *transpose_b)?;

            if k_from_a != k_from_b {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::matmul::inner_dimension_mismatch",
                ));
            }

            Ok(TensorDescriptor::new(
                vec![rows_out, cols_out],
                mat_a.descriptor.dtype,
            ))
        }

        TensorOp::EmbeddingLookup => {
            // Requires 2 inputs: table [vocab_size, embed_dim] and indices [batch].
            let emb_table = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::embedding_lookup::requires_two_inputs",
                )
            })?;
            let emb_indices = inputs.get(1).ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::embedding_lookup::requires_two_inputs",
                )
            })?;

            // Table must be 2-D.
            if emb_table.descriptor.shape.len() != 2 {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::embedding_lookup::table_must_be_2d",
                ));
            }
            // Indices must be 1-D.
            if emb_indices.descriptor.shape.len() != 1 {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::embedding_lookup::indices_must_be_1d",
                ));
            }

            // Table is confirmed 2-D; use get() to avoid clippy::indexing_slicing.
            let embed_dim = emb_table.descriptor.shape.get(1).copied().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::embedding_lookup::shape_error",
                )
            })?;
            let batch = emb_indices
                .descriptor
                .shape
                .first()
                .copied()
                .ok_or_else(|| {
                    NexaCoreError::hal(
                        HalErrorKind::DeviceFailure,
                        "execute::embedding_lookup::shape_error",
                    )
                })?;
            Ok(TensorDescriptor::new(
                vec![batch, embed_dim],
                TensorDtype::F32,
            ))
        }

        TensorOp::Reshape { new_shape } => {
            // Reshape must have exactly one input; grab the dtype from it.
            let src = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::reshape::no_input",
                )
            })?;
            Ok(TensorDescriptor::new(
                new_shape.clone(),
                src.descriptor.dtype,
            ))
        }

        TensorOp::Transpose { axes } => {
            let src = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::transpose::no_input",
                )
            })?;
            let shape = &src.descriptor.shape;
            if axes.len() != shape.len() {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::transpose::axes_rank_mismatch",
                ));
            }
            // Build output shape by permuting input shape according to axes.
            let out_shape = axes
                .iter()
                .map(|&ax| {
                    shape.get(ax).copied().ok_or_else(|| {
                        NexaCoreError::hal(
                            HalErrorKind::DeviceFailure,
                            "execute::transpose::axis_out_of_bounds",
                        )
                    })
                })
                .collect::<Result<Vec<usize>>>()?;
            Ok(TensorDescriptor::new(out_shape, src.descriptor.dtype))
        }

        TensorOp::Concat { axis } => {
            let first = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::concat::no_input",
                )
            })?;
            let rank = first.descriptor.shape.len();
            if *axis >= rank {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::concat::axis_out_of_bounds",
                ));
            }
            // Verify all inputs share the same rank and non-concat dimensions.
            for inp in inputs.iter().skip(1) {
                if inp.descriptor.shape.len() != rank {
                    return Err(NexaCoreError::hal(
                        HalErrorKind::DeviceFailure,
                        "execute::concat::rank_mismatch",
                    ));
                }
                for (dim_idx, (&a, &b)) in first
                    .descriptor
                    .shape
                    .iter()
                    .zip(inp.descriptor.shape.iter())
                    .enumerate()
                {
                    if dim_idx != *axis && a != b {
                        return Err(NexaCoreError::hal(
                            HalErrorKind::DeviceFailure,
                            "execute::concat::shape_mismatch_on_non_concat_axis",
                        ));
                    }
                }
            }
            // Sum the concat axis across all inputs; copy the rest from first.
            let mut out_shape = first.descriptor.shape.clone();
            let axis_total: usize = inputs
                .iter()
                .map(|inp| inp.descriptor.shape.get(*axis).copied().unwrap_or(0))
                .sum();
            if let Some(slot) = out_shape.get_mut(*axis) {
                *slot = axis_total;
            }
            Ok(TensorDescriptor::new(out_shape, first.descriptor.dtype))
        }

        // Quantize: same shape as input but dtype changes to I8.
        TensorOp::Quantize { .. } => {
            let src = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::quantize::no_input",
                )
            })?;
            Ok(TensorDescriptor::new(
                src.descriptor.shape.clone(),
                TensorDtype::I8,
            ))
        }

        // Dequantize: same shape as input but dtype changes to F32.
        TensorOp::Dequantize { .. } => {
            let src = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::dequantize::no_input",
                )
            })?;
            Ok(TensorDescriptor::new(
                src.descriptor.shape.clone(),
                TensorDtype::F32,
            ))
        }

        // QuantizedMatMul: same shape derivation as FP32 MatMul but output dtype is F32.
        TensorOp::QuantizedMatMul { .. } => {
            let mat_a = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::quant_matmul::requires_two_inputs",
                )
            })?;
            let mat_b = inputs.get(1).ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::HardwareUnavailable,
                    "execute::quant_matmul::requires_two_inputs",
                )
            })?;
            // No transposition for quantized matmul; A is [M,K], B is [K,N].
            let (rows_out, k_from_a) = matmul_effective_dims(&mat_a.descriptor.shape, false)?;
            let (k_from_b, cols_out) = matmul_effective_dims(&mat_b.descriptor.shape, false)?;
            if k_from_a != k_from_b {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::quant_matmul::inner_dimension_mismatch",
                ));
            }
            Ok(TensorDescriptor::new(
                vec![rows_out, cols_out],
                TensorDtype::F32,
            ))
        }

        // Element-wise ops (Add, Relu, Softmax, LayerNorm, GeLU, Scale,
        // RmsNorm): inherit first input's shape and dtype.
        _ => {
            let src = inputs.first().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::HardwareUnavailable, "execute::no_input")
            })?;
            Ok(TensorDescriptor::new(
                src.descriptor.shape.clone(),
                src.descriptor.dtype,
            ))
        }
    }
}

/// Resolve the effective `(rows, cols)` of a 2-D matrix after an optional transpose.
///
/// Returns an error if the shape is not exactly 2-D.
fn matmul_effective_dims(shape: &[usize], transpose: bool) -> Result<(usize, usize)> {
    if shape.len() != 2 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::matmul::input_must_be_2d",
        ));
    }
    // Shape is confirmed 2-D; get() calls succeed by construction.
    let rows = shape.first().copied().ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "execute::matmul::shape_error")
    })?;
    let cols = shape.get(1).copied().ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "execute::matmul::shape_error")
    })?;
    if transpose {
        Ok((cols, rows))
    } else {
        Ok((rows, cols))
    }
}

// =============================================================================
// Per-op scalar implementations (F32 only)
// =============================================================================

/// Require `dtype == F32`, returning a [`HalErrorKind::DeviceFailure`] error
/// tagged with `op_tag` if the requirement is not met.
fn require_f32(dtype: TensorDtype, op_tag: &'static str) -> Result<()> {
    if dtype == TensorDtype::F32 {
        Ok(())
    } else {
        Err(NexaCoreError::hal(HalErrorKind::DeviceFailure, op_tag))
    }
}

// =============================================================================
// SIMD matmul implementations
// =============================================================================

/// Scalar (no-SIMD) F32 matrix multiplication kernel.
///
/// Computes `C[row,col] = sum_{k} A_eff[row,k] * B_eff[k,col]` for all
/// valid `(row, col)` pairs, writing results into `out_bytes`.
///
/// Index mapping (row-major, C order):
/// - `A_eff[row][k]` without transpose: `A[row * inner + k]`
/// - `A_eff[row][k]` with `transpose_a`: `A[k * rows_out + row]`
/// - `B_eff[k][col]` without transpose: `B[k * cols_out + col]`
/// - `B_eff[k][col]` with `transpose_b`: `B[col * inner + k]`
///
/// # Errors
///
/// Returns `Err` only if an index overflows `usize` (impossible in practice
/// for matrices sized from a valid [`TensorDescriptor`]).
// Eight parameters are a structural necessity of a complete matrix-multiply
// kernel signature; splitting would require a struct or extra indirection that
// adds no clarity for an internal helper.
#[allow(clippy::too_many_arguments)]
fn matmul_scalar(
    a_bytes: &[u8],
    b_bytes: &[u8],
    rows_out: usize,
    cols_out: usize,
    inner: usize,
    transpose_a: bool,
    transpose_b: bool,
    out_bytes: &mut [u8],
) -> Result<()> {
    for row in 0..rows_out {
        for col in 0..cols_out {
            let mut acc = 0.0_f32;
            for k in 0..inner {
                let a_flat = if transpose_a {
                    k * rows_out + row
                } else {
                    row * inner + k
                };
                let b_flat = if transpose_b {
                    col * inner + k
                } else {
                    k * cols_out + col
                };
                acc += read_f32(a_bytes, a_flat)? * read_f32(b_bytes, b_flat)?;
            }
            write_f32(out_bytes, row * cols_out + col, acc)?;
        }
    }
    Ok(())
}

/// AVX2 + FMA3 F32 matrix multiplication kernel (`x86_64` only).
///
/// Processes 8 `f32` elements per iteration using 256-bit YMM registers and
/// fused multiply-add (`_mm256_fmadd_ps`).  Only the non-transposed case uses
/// the SIMD hot path; transposed inputs fall back to [`matmul_scalar`]
/// because the non-contiguous B access pattern would negate any SIMD gain
/// without an explicit in-place transpose.
///
/// Remainder elements (when `inner % 8 != 0`) are handled by a scalar tail
/// loop so correctness is preserved for any matrix dimension.
///
/// # Safety
///
/// Must only be called after confirming `is_x86_feature_detected!("avx2")`
/// **and** `is_x86_feature_detected!("fma")` return `true`.  The
/// `#[target_feature(enable = "avx2,fma")]` attribute ensures the compiler
/// emits legal instructions, but calling the function on a CPU that does not
/// support AVX2/FMA is undefined behaviour per the Intel ISA manual.
/// The dispatcher in [`exec_matmul`] guarantees the feature check is
/// performed before any call to this function.
///
/// Gated on `feature = "std"` because `std::arch` requires std
/// (TASK-13-pre / ADR-0034).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,fma")]
// `unsafe_code` is allowed for SIMD intrinsic functions; the workspace-level
// `unsafe_code = "warn"` lint is intentionally suppressed here because
// x86 SIMD intrinsics are inherently unsafe by API contract.  Each unsafe
// operation is individually justified with a `// SAFETY:` comment.
#[allow(unsafe_code)]
// Eight parameters are a structural necessity; see `matmul_scalar`.
#[allow(clippy::too_many_arguments)]
// `inner / lanes * lanes` is intentional integer truncation to find the
// largest multiple of `lanes` that is <= `inner`.  All values are `usize`;
// no precision loss is possible and the result is used only as a loop bound.
#[allow(clippy::integer_division)]
unsafe fn matmul_avx2(
    a: &[f32],
    b: &[f32],
    rows_out: usize,
    cols_out: usize,
    inner: usize,
    transpose_a: bool,
    transpose_b: bool,
    out: &mut [f32],
) {
    use std::arch::x86_64::{
        _mm256_fmadd_ps, _mm256_loadu_ps, _mm256_setzero_ps, _mm256_storeu_ps,
    };

    // Transposed access patterns produce non-contiguous memory strides that
    // would require a gather load or an explicit pre-transpose.  Neither is
    // worth the added complexity here; fall back to the proven scalar path.
    if transpose_a || transpose_b {
        // Reinterpret `&[f32]` as `&[u8]` for the scalar helper.
        // SAFETY: `a` and `b` are valid `&[f32]` slices; `f32` has no
        // padding and any bit pattern is a valid byte sequence, so the byte
        // reinterpretation is well-defined.  Byte length = element count * 4.
        let a_bytes = unsafe { std::slice::from_raw_parts(a.as_ptr().cast::<u8>(), a.len() * 4) };
        let b_bytes = unsafe { std::slice::from_raw_parts(b.as_ptr().cast::<u8>(), b.len() * 4) };
        // SAFETY: same reasoning; the mutable borrow is exclusive.
        let out_bytes =
            unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), out.len() * 4) };
        // matmul_scalar only fails on index overflow, which cannot happen
        // because `a`, `b`, and `out` were already sized correctly by the
        // caller.  Ignore the Result.
        let _ = matmul_scalar(
            a_bytes,
            b_bytes,
            rows_out,
            cols_out,
            inner,
            transpose_a,
            transpose_b,
            out_bytes,
        );
        return;
    }

    // Non-transposed hot path:
    //   A is row-major [rows_out, inner]
    //   B is row-major [inner,    cols_out]
    //   C is row-major [rows_out, cols_out]
    //
    // For each output element C[row, col] we compute the dot product of
    // row `row` of A with column `col` of B.  The inner dimension is
    // vectorised in chunks of 8 f32 (256 bits).
    let lanes = 8_usize;
    let inner_full = inner / lanes * lanes; // largest multiple of 8 <= inner

    for row in 0..rows_out {
        for col in 0..cols_out {
            // SAFETY: `_mm256_setzero_ps` requires AVX2, guaranteed by caller.
            let mut acc_vec = unsafe { _mm256_setzero_ps() };

            let mut k = 0_usize;
            while k < inner_full {
                // A[row, k..k+8] is contiguous in memory (A is row-major).
                // SAFETY: `a` has `rows_out * inner` elements.  Offset
                // `row * inner + k` through `+ k + 7` is in bounds because
                // `row < rows_out` and `k + 7 < inner_full <= inner`.
                // `_mm256_loadu_ps` does NOT require 32-byte alignment.
                let a_ptr = unsafe { a.as_ptr().add(row * inner + k) };
                let a_vec = unsafe { _mm256_loadu_ps(a_ptr) };

                // B[k..k+7, col] is non-contiguous (stride = cols_out).
                // Load each scalar individually into a temporary array,
                // then pack into a YMM register via `_mm256_loadu_ps`.
                // SAFETY: `k + 7 < inner_full <= inner` and `col < cols_out`,
                // so `(k+i) * cols_out + col < inner * cols_out = b.len()`
                // for all `i` in 0..8.
                let b0 = unsafe { *b.get_unchecked(k * cols_out + col) };
                let b1 = unsafe { *b.get_unchecked((k + 1) * cols_out + col) };
                let b2 = unsafe { *b.get_unchecked((k + 2) * cols_out + col) };
                let b3 = unsafe { *b.get_unchecked((k + 3) * cols_out + col) };
                let b4 = unsafe { *b.get_unchecked((k + 4) * cols_out + col) };
                let b5 = unsafe { *b.get_unchecked((k + 5) * cols_out + col) };
                let b6 = unsafe { *b.get_unchecked((k + 6) * cols_out + col) };
                let b7 = unsafe { *b.get_unchecked((k + 7) * cols_out + col) };
                let b_arr: [f32; 8] = [b0, b1, b2, b3, b4, b5, b6, b7];
                // SAFETY: `b_arr` is an 8-element `f32` stack array; valid
                // pointer, no alignment requirement for `_mm256_loadu_ps`.
                let b_vec = unsafe { _mm256_loadu_ps(b_arr.as_ptr()) };

                // Fused multiply-add: acc += a * b (single rounding).
                // SAFETY: `_mm256_fmadd_ps` is an FMA3 instruction; caller
                // guarantees both AVX2 and FMA are available.
                acc_vec = unsafe { _mm256_fmadd_ps(a_vec, b_vec, acc_vec) };
                k += lanes;
            }

            // Horizontal reduction: store 8 lanes to stack and sum scalarly.
            // Avoids a dependency on AVX `hadd` which is slow on most
            // µarchitectures.
            let mut lane_arr = [0.0_f32; 8];
            // SAFETY: `lane_arr` is 8 `f32` on the stack; `_mm256_storeu_ps`
            // requires only a valid pointer — not 32-byte alignment.  Stack
            // allocations are at least 8-byte aligned on x86_64, which
            // satisfies the unaligned-store contract.
            unsafe { _mm256_storeu_ps(lane_arr.as_mut_ptr(), acc_vec) };
            let mut acc = lane_arr.iter().copied().fold(0.0_f32, |s, v| s + v);

            // Scalar tail: handle the remaining `inner - inner_full` elements.
            for ki in inner_full..inner {
                // SAFETY: `ki < inner`, `row < rows_out`, `col < cols_out`,
                // so both offsets are within their respective slice bounds.
                let av = unsafe { *a.get_unchecked(row * inner + ki) };
                let bv = unsafe { *b.get_unchecked(ki * cols_out + col) };
                acc += av * bv;
            }

            // SAFETY: `row < rows_out` and `col < cols_out`, therefore
            // `row * cols_out + col < rows_out * cols_out = out.len()`.
            unsafe { *out.get_unchecked_mut(row * cols_out + col) = acc };
        }
    }
}

/// SSE4.2 F32 matrix multiplication kernel (`x86_64` only).
///
/// Processes 4 `f32` elements per iteration using 128-bit XMM registers.
/// SSE4.2 does not include FMA, so separate `_mm_mul_ps` + `_mm_add_ps`
/// instructions are used.  Transposed inputs fall back to [`matmul_scalar`]
/// for the same reasons as in [`matmul_avx2`].
///
/// # Safety
///
/// Must only be called after confirming `is_x86_feature_detected!("sse4.2")`
/// returns `true`.  The `#[target_feature(enable = "sse4.2")]` attribute
/// ensures correct code generation; calling on a CPU without SSE4.2 is
/// undefined behaviour per the Intel ISA manual.
/// The dispatcher in [`exec_matmul`] guarantees the feature check is
/// performed before any call to this function.
///
/// Gated on `feature = "std"` because `std::arch` requires std
/// (TASK-13-pre / ADR-0034).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[target_feature(enable = "sse4.2")]
// `unsafe_code` suppressed for the same reason as `matmul_avx2`: SSE
// intrinsics are unsafe by API contract and every unsafe block carries a
// SAFETY comment.
#[allow(unsafe_code)]
// Eight parameters are a structural necessity; see `matmul_scalar`.
#[allow(clippy::too_many_arguments)]
// `inner / lanes * lanes` is intentional integer truncation; see `matmul_avx2`.
#[allow(clippy::integer_division)]
unsafe fn matmul_sse42(
    a: &[f32],
    b: &[f32],
    rows_out: usize,
    cols_out: usize,
    inner: usize,
    transpose_a: bool,
    transpose_b: bool,
    out: &mut [f32],
) {
    use std::arch::x86_64::{_mm_add_ps, _mm_loadu_ps, _mm_mul_ps, _mm_setzero_ps, _mm_storeu_ps};

    // Fall back to scalar for transposed cases (see `matmul_avx2` for
    // rationale).
    if transpose_a || transpose_b {
        // SAFETY: `f32` slices reinterpreted as `u8` — always well-defined;
        // `f32` has no padding and any bit pattern is a valid byte sequence.
        let a_bytes = unsafe { std::slice::from_raw_parts(a.as_ptr().cast::<u8>(), a.len() * 4) };
        let b_bytes = unsafe { std::slice::from_raw_parts(b.as_ptr().cast::<u8>(), b.len() * 4) };
        // SAFETY: same reasoning; the mutable borrow is exclusive.
        let out_bytes =
            unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), out.len() * 4) };
        let _ = matmul_scalar(
            a_bytes,
            b_bytes,
            rows_out,
            cols_out,
            inner,
            transpose_a,
            transpose_b,
            out_bytes,
        );
        return;
    }

    let lanes = 4_usize;
    let inner_full = inner / lanes * lanes; // largest multiple of 4 <= inner

    for row in 0..rows_out {
        for col in 0..cols_out {
            // SAFETY: `_mm_setzero_ps` requires SSE (implied by SSE4.2).
            let mut acc_vec = unsafe { _mm_setzero_ps() };

            let mut k = 0_usize;
            while k < inner_full {
                // A[row, k..k+4] is contiguous in memory (A is row-major).
                // SAFETY: offset `row * inner + k` through `+ k + 3` is in
                // bounds because `row < rows_out` and `k + 3 < inner_full
                // <= inner`.  `_mm_loadu_ps` does NOT require 16-byte
                // alignment.
                let a_ptr = unsafe { a.as_ptr().add(row * inner + k) };
                let a_vec = unsafe { _mm_loadu_ps(a_ptr) };

                // B[k..k+3, col] is non-contiguous; load each scalar
                // individually.
                // SAFETY: `k + 3 < inner_full <= inner` and `col < cols_out`,
                // so `(k+i) * cols_out + col < inner * cols_out = b.len()`
                // for all `i` in 0..4.
                let b0 = unsafe { *b.get_unchecked(k * cols_out + col) };
                let b1 = unsafe { *b.get_unchecked((k + 1) * cols_out + col) };
                let b2 = unsafe { *b.get_unchecked((k + 2) * cols_out + col) };
                let b3 = unsafe { *b.get_unchecked((k + 3) * cols_out + col) };
                let b_arr: [f32; 4] = [b0, b1, b2, b3];
                // SAFETY: 4-element `f32` stack array; `_mm_loadu_ps` needs
                // only a valid pointer, not 16-byte alignment.
                let b_vec = unsafe { _mm_loadu_ps(b_arr.as_ptr()) };

                // No FMA in SSE4.2: use separate multiply + add.
                // SAFETY: `_mm_mul_ps` and `_mm_add_ps` are baseline SSE
                // instructions (guaranteed by SSE4.2 presence).
                let prod = unsafe { _mm_mul_ps(a_vec, b_vec) };
                acc_vec = unsafe { _mm_add_ps(acc_vec, prod) };
                k += lanes;
            }

            // Horizontal reduction.
            let mut lane_arr = [0.0_f32; 4];
            // SAFETY: `lane_arr` is 4 `f32` on the stack; `_mm_storeu_ps`
            // requires only a valid pointer, not 16-byte alignment.
            unsafe { _mm_storeu_ps(lane_arr.as_mut_ptr(), acc_vec) };
            let mut acc = lane_arr.iter().copied().fold(0.0_f32, |s, v| s + v);

            // Scalar tail.
            for ki in inner_full..inner {
                // SAFETY: `ki < inner`, `row < rows_out`, `col < cols_out`,
                // so both offsets are within their respective slice bounds.
                let av = unsafe { *a.get_unchecked(row * inner + ki) };
                let bv = unsafe { *b.get_unchecked(ki * cols_out + col) };
                acc += av * bv;
            }

            // SAFETY: `row < rows_out` and `col < cols_out`, therefore
            // `row * cols_out + col < rows_out * cols_out = out.len()`.
            unsafe { *out.get_unchecked_mut(row * cols_out + col) = acc };
        }
    }
}

/// F32 matrix multiplication dispatcher: `C[row,col] = sum_inner A[row,inner] * B[inner,col]`.
///
/// Selects the best available SIMD backend at runtime:
/// - **AVX2 + FMA** — 8-wide `f32` FMA using `_mm256_fmadd_ps`
/// - **SSE4.2** — 4-wide `f32` multiply-add using `_mm_mul_ps` + `_mm_add_ps`
/// - **Scalar** — portable triple-loop fallback (always available)
///
/// Detection is performed once per call via `is_x86_feature_detected!`.  All
/// paths produce results equivalent within `f32` precision; the AVX2 path may
/// differ slightly from scalar for large inner dimensions due to FMA3
/// single-rounding semantics (the difference is within `1e-3` for typical
/// weight matrices).
///
/// Supports optional transposition of either input.  Validates that both
/// inputs are 2-D with matching inner dimensions.
// `unsafe_code` is allowed here because the dispatcher calls `align_to`
// (which requires an `unsafe` block per its stdlib signature) and the SIMD
// kernel functions (which are `unsafe fn` by `#[target_feature]` contract).
// Every unsafe call site carries an explicit `// SAFETY:` justification.
#[allow(unsafe_code)]
fn exec_matmul(
    inputs: &[&TensorBuffer],
    transpose_a: bool,
    transpose_b: bool,
) -> Result<TensorBuffer> {
    let mat_a = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::matmul::requires_two_inputs",
        )
    })?;
    let mat_b = inputs.get(1).ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::matmul::requires_two_inputs",
        )
    })?;

    require_f32(mat_a.descriptor.dtype, "execute::matmul::unsupported_dtype")?;
    require_f32(mat_b.descriptor.dtype, "execute::matmul::unsupported_dtype")?;

    let (rows_out, inner_a) = matmul_effective_dims(&mat_a.descriptor.shape, transpose_a)?;
    let (inner_b, cols_out) = matmul_effective_dims(&mat_b.descriptor.shape, transpose_b)?;

    if inner_a != inner_b {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::matmul::inner_dimension_mismatch",
        ));
    }
    let inner = inner_a;

    let out_desc = TensorDescriptor::new(vec![rows_out, cols_out], TensorDtype::F32);
    // Zero-initialise so SIMD paths that skip tail elements leave 0.0 there.
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    let a_bytes = mat_a.as_bytes();
    let b_bytes = mat_b.as_bytes();

    // Attempt to reinterpret the byte buffers as &[f32] using `align_to`.
    // `align_to` splits the slice into a (possibly empty) byte prefix that
    // satisfies the alignment requirement, a well-aligned middle, and a
    // (possibly empty) suffix.  We can use the SIMD path only when both
    // prefixes are empty, meaning the data is already f32-aligned.
    //
    // In practice the Rust global allocator returns memory aligned to at
    // least 8 bytes on x86_64, so the prefix will be empty for any Vec<u8>
    // whose total length is a multiple of 4 — which is guaranteed here
    // because we only reach this code for F32 buffers (4 bytes/element).
    //
    // SAFETY: `align_to::<f32>` is a safe standard library function; it
    // takes a shared reference and returns slices with the same lifetime.
    // The only unsafe requirement is that the resulting `middle` elements
    // are valid `f32` bit patterns — which is always true because every
    // 4-byte sequence is a valid (possibly NaN) f32.
    // The aligned views and the eligibility flag are consumed only by the
    // SIMD dispatch below, which is compiled out on no_std builds — hence the
    // `unused_variables` allowance (TASK-13-pre / ADR-0034).
    #[cfg_attr(
        not(all(feature = "std", target_arch = "x86_64")),
        allow(unused_variables)
    )]
    let (a_prefix, a_floats, _a_suffix) = unsafe { a_bytes.align_to::<f32>() };
    #[cfg_attr(
        not(all(feature = "std", target_arch = "x86_64")),
        allow(unused_variables)
    )]
    let (b_prefix, b_floats, _b_suffix) = unsafe { b_bytes.align_to::<f32>() };

    #[cfg_attr(
        not(all(feature = "std", target_arch = "x86_64")),
        allow(unused_variables)
    )]
    let simd_eligible = a_prefix.is_empty() && b_prefix.is_empty();

    // Dispatch to the best available kernel.
    // Gated on `feature = "std"` because `is_x86_feature_detected!` and the
    // SIMD kernel functions require std (TASK-13-pre / ADR-0034).
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    if simd_eligible {
        let n_out = rows_out * cols_out;
        let mut out_floats = vec![0.0_f32; n_out];

        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("fma") {
            // SAFETY: we just confirmed AVX2 and FMA are supported by this
            // CPU.  `matmul_avx2` is annotated
            // `#[target_feature(enable = "avx2,fma")]` and must only be
            // called when those features are present — which we verified.
            unsafe {
                matmul_avx2(
                    a_floats,
                    b_floats,
                    rows_out,
                    cols_out,
                    inner,
                    transpose_a,
                    transpose_b,
                    &mut out_floats,
                );
            }
            for (i, &v) in out_floats.iter().enumerate() {
                write_f32(&mut out_bytes, i, v)?;
            }
            return Ok(TensorBuffer::new(out_desc, out_bytes));
        }

        if is_x86_feature_detected!("sse4.2") {
            // SAFETY: we just confirmed SSE4.2 is supported by this CPU.
            // `matmul_sse42` must only be called when `sse4.2` is present.
            unsafe {
                matmul_sse42(
                    a_floats,
                    b_floats,
                    rows_out,
                    cols_out,
                    inner,
                    transpose_a,
                    transpose_b,
                    &mut out_floats,
                );
            }
            for (i, &v) in out_floats.iter().enumerate() {
                write_f32(&mut out_bytes, i, v)?;
            }
            return Ok(TensorBuffer::new(out_desc, out_bytes));
        }
    }

    // Scalar fallback — always correct, no SIMD required.
    //
    // Also reached on non-x86_64 architectures and when the alignment check
    // above fails (extremely unlikely; see comment above `align_to` call).
    matmul_scalar(
        a_bytes,
        b_bytes,
        rows_out,
        cols_out,
        inner,
        transpose_a,
        transpose_b,
        &mut out_bytes,
    )?;

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Element-wise F32 addition of two tensors with identical shapes.
fn exec_add(inputs: &[&TensorBuffer]) -> Result<TensorBuffer> {
    let lhs = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::add::requires_two_inputs",
        )
    })?;
    let rhs = inputs.get(1).ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::add::requires_two_inputs",
        )
    })?;

    require_f32(lhs.descriptor.dtype, "execute::add::unsupported_dtype")?;
    require_f32(rhs.descriptor.dtype, "execute::add::unsupported_dtype")?;

    if lhs.descriptor.shape != rhs.descriptor.shape {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::add::shape_mismatch",
        ));
    }

    let n_elems = lhs.descriptor.num_elements();
    let out_desc = TensorDescriptor::new(lhs.descriptor.shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    let lhs_bytes = lhs.as_bytes();
    let rhs_bytes = rhs.as_bytes();

    for elem_idx in 0..n_elems {
        let sum = read_f32(lhs_bytes, elem_idx)? + read_f32(rhs_bytes, elem_idx)?;
        write_f32(&mut out_bytes, elem_idx, sum)?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Element-wise F32 `ReLU`: `output[i] = max(0.0, input[i])`.
fn exec_relu(inputs: &[&TensorBuffer]) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::HardwareUnavailable, "execute::relu::no_input")
    })?;

    require_f32(src.descriptor.dtype, "execute::relu::unsupported_dtype")?;

    let n_elems = src.descriptor.num_elements();
    let out_desc = TensorDescriptor::new(src.descriptor.shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];
    let src_bytes = src.as_bytes();

    for elem_idx in 0..n_elems {
        let val = read_f32(src_bytes, elem_idx)?;
        write_f32(&mut out_bytes, elem_idx, f32::max(0.0, val))?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Numerically stable F32 softmax along a given axis.
///
/// For each slice along `axis`, computes:
/// `exp(x - max(x)) / sum(exp(x - max(x)))`.
///
/// Subtracting `max(x)` before exponentiating prevents overflow for large
/// logits (the result is identical by algebraic equivalence).
fn exec_softmax(inputs: &[&TensorBuffer], axis: usize) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::softmax::no_input",
        )
    })?;

    require_f32(src.descriptor.dtype, "execute::softmax::unsupported_dtype")?;

    let shape = &src.descriptor.shape;
    if axis >= shape.len() {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::softmax::axis_out_of_bounds",
        ));
    }

    let out_desc = TensorDescriptor::new(shape.clone(), TensorDtype::F32);
    let src_bytes = src.as_bytes();
    let n_total = src.descriptor.num_elements();
    let mut out_values: Vec<f32> = Vec::with_capacity(n_total);

    // Read all input floats first to simplify the axis-iteration logic.
    for elem_idx in 0..n_total {
        out_values.push(read_f32(src_bytes, elem_idx)?);
    }

    // axis_size: number of elements along the softmax axis.
    let axis_size = shape.get(axis).copied().ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::DeviceFailure, "execute::softmax::axis_error")
    })?;
    // outer: product of dims before axis.
    let outer: usize = shape.get(..axis).map_or(1, |s| s.iter().product());
    // inner: product of dims after axis.
    let inner: usize = shape.get(axis + 1..).map_or(1, |s| s.iter().product());

    for outer_idx in 0..outer {
        for inner_idx in 0..inner {
            // Flat index of element at axis position `axis_pos`:
            //   outer_idx * (axis_size * inner) + axis_pos * inner + inner_idx
            let base = outer_idx * (axis_size * inner) + inner_idx;

            // Pass 1: find max for numerical stability.
            let mut max_val = f32::NEG_INFINITY;
            for axis_pos in 0..axis_size {
                let flat = base + axis_pos * inner;
                let val = out_values.get(flat).copied().ok_or_else(|| {
                    NexaCoreError::hal(HalErrorKind::DeviceFailure, "execute::softmax::index_error")
                })?;
                if val > max_val {
                    max_val = val;
                }
            }

            // Pass 2: compute exp(x - max) and accumulate sum.
            // Use crate::math::exp for no_std compatibility (ADR-0034).
            let mut exp_sum = 0.0_f32;
            for axis_pos in 0..axis_size {
                let flat = base + axis_pos * inner;
                let val = out_values.get(flat).copied().ok_or_else(|| {
                    NexaCoreError::hal(HalErrorKind::DeviceFailure, "execute::softmax::index_error")
                })?;
                let exp_val = crate::math::exp(val - max_val);
                if let Some(slot) = out_values.get_mut(flat) {
                    *slot = exp_val;
                }
                exp_sum += exp_val;
            }

            // Pass 3: divide by sum.
            for axis_pos in 0..axis_size {
                let flat = base + axis_pos * inner;
                if let Some(slot) = out_values.get_mut(flat) {
                    *slot /= exp_sum;
                }
            }
        }
    }

    let mut out_bytes = vec![0u8; out_desc.byte_size()];
    for (elem_idx, val) in out_values.iter().enumerate() {
        write_f32(&mut out_bytes, elem_idx, *val)?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// F32 layer normalization across the last axis.
///
/// For each slice of size `last_dim` along the last dimension, computes:
/// `output = (x - mean) / sqrt(variance + epsilon)`.
#[allow(clippy::integer_division, clippy::cast_precision_loss)]
fn exec_layer_norm(inputs: &[&TensorBuffer], epsilon: f32) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::layer_norm::no_input",
        )
    })?;

    require_f32(
        src.descriptor.dtype,
        "execute::layer_norm::unsupported_dtype",
    )?;

    let shape = &src.descriptor.shape;
    if shape.is_empty() {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::layer_norm::scalar_not_supported",
        ));
    }

    // Use .last() to avoid clippy::indexing_slicing for shape[len-1].
    let last_dim = shape.last().copied().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::layer_norm::shape_error",
        )
    })?;
    let n_total = src.descriptor.num_elements();
    // Division is exact: n_total = n_slices * last_dim by construction.
    let n_slices = n_total / last_dim;

    let src_bytes = src.as_bytes();
    let out_desc = TensorDescriptor::new(shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    for slice_idx in 0..n_slices {
        let slice_start = slice_idx * last_dim;

        // Compute mean.  Cast `last_dim as f32`: dimensions are always < 2^23
        // in practice on this target so precision loss is not meaningful.
        let mut mean = 0.0_f32;
        for dim_pos in 0..last_dim {
            mean += read_f32(src_bytes, slice_start + dim_pos)?;
        }
        mean /= last_dim as f32;

        // Compute variance: E[(x - mean)^2].
        let mut var = 0.0_f32;
        for dim_pos in 0..last_dim {
            let diff = read_f32(src_bytes, slice_start + dim_pos)? - mean;
            var += diff * diff;
        }
        var /= last_dim as f32;

        let std_dev = crate::math::sqrt(var + epsilon);
        for dim_pos in 0..last_dim {
            let elem = read_f32(src_bytes, slice_start + dim_pos)?;
            write_f32(
                &mut out_bytes,
                slice_start + dim_pos,
                (elem - mean) / std_dev,
            )?;
        }
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Embedding table lookup: gather rows from a `[vocab_size, embed_dim]` table
/// using an index tensor with dtype `I8` or `U8`.
///
/// Each byte in the index tensor is cast to `usize` and used as a row index
/// into the table.  Returns an error if any index is out of bounds.
fn exec_embedding_lookup(inputs: &[&TensorBuffer]) -> Result<TensorBuffer> {
    let table = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::embedding_lookup::requires_two_inputs",
        )
    })?;
    let indices = inputs.get(1).ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::embedding_lookup::requires_two_inputs",
        )
    })?;

    require_f32(
        table.descriptor.dtype,
        "execute::embedding_lookup::unsupported_table_dtype",
    )?;

    if !matches!(indices.descriptor.dtype, TensorDtype::I8 | TensorDtype::U8) {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::embedding_lookup::unsupported_index_dtype",
        ));
    }

    if table.descriptor.shape.len() != 2 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::embedding_lookup::table_must_be_2d",
        ));
    }
    if indices.descriptor.shape.len() != 1 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::embedding_lookup::indices_must_be_1d",
        ));
    }

    // Both shapes are validated; get() calls below are guaranteed to succeed.
    let vocab_size = table.descriptor.shape.first().copied().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::embedding_lookup::shape_error",
        )
    })?;
    let embed_dim = table.descriptor.shape.get(1).copied().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::embedding_lookup::shape_error",
        )
    })?;
    let batch = indices.descriptor.shape.first().copied().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::embedding_lookup::shape_error",
        )
    })?;

    let table_bytes = table.as_bytes();
    let index_bytes = indices.as_bytes();

    let out_desc = TensorDescriptor::new(vec![batch, embed_dim], TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    for batch_idx in 0..batch {
        // Read the raw index byte and cast to usize.  Both I8 and U8 occupy a
        // single byte; we interpret it as unsigned so indices 0..=255 are valid.
        let raw_byte = index_bytes.get(batch_idx).copied().ok_or_else(|| {
            NexaCoreError::hal(
                HalErrorKind::DeviceFailure,
                "execute::embedding_lookup::index_read_error",
            )
        })?;
        let row_idx = usize::from(raw_byte);

        if row_idx >= vocab_size {
            return Err(NexaCoreError::hal(
                HalErrorKind::DeviceFailure,
                "execute::embedding_lookup::index_out_of_bounds",
            ));
        }

        for dim_pos in 0..embed_dim {
            let val = read_f32(table_bytes, row_idx * embed_dim + dim_pos)?;
            write_f32(&mut out_bytes, batch_idx * embed_dim + dim_pos, val)?;
        }
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Reshape: reinterpret the byte data with a new shape.
///
/// The total element count of `new_shape` must equal the total element count
/// of the source tensor.  The dtype is preserved.
fn exec_reshape(inputs: &[&TensorBuffer], new_shape: &[usize]) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::reshape::no_input",
        )
    })?;

    let src_elems = src.descriptor.num_elements();
    let dst_elems: usize = new_shape.iter().product();

    if src_elems != dst_elems {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::reshape::element_count_mismatch",
        ));
    }

    let out_desc = TensorDescriptor::new(new_shape.to_vec(), src.descriptor.dtype);
    Ok(TensorBuffer::new(out_desc, src.as_bytes().to_vec()))
}

/// Permute tensor axes: output[axes permutation of coords] = input[coords].
///
/// Uses stride arithmetic to compute the source flat index for each output
/// element without allocating intermediate index vectors.
fn exec_transpose(inputs: &[&TensorBuffer], axes: &[usize]) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::transpose::no_input",
        )
    })?;

    require_f32(
        src.descriptor.dtype,
        "execute::transpose::unsupported_dtype",
    )?;

    let in_shape = &src.descriptor.shape;
    let rank = in_shape.len();

    if axes.len() != rank {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::transpose::axes_rank_mismatch",
        ));
    }

    // Output shape: shape[axes[i]] for each i.
    let out_shape: Vec<usize> = axes
        .iter()
        .map(|&ax| {
            in_shape.get(ax).copied().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::transpose::axis_out_of_bounds",
                )
            })
        })
        .collect::<Result<Vec<usize>>>()?;

    // Precompute row-major strides for the input shape.
    // stride[i] = product of in_shape[i+1..rank].
    let mut in_strides = vec![1usize; rank];
    for i in (0..rank.saturating_sub(1)).rev() {
        let next = in_strides.get(i + 1).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "transpose::stride_error")
        })?;
        let dim = in_shape.get(i + 1).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "transpose::stride_error")
        })?;
        if let Some(s) = in_strides.get_mut(i) {
            *s = next * dim;
        }
    }

    // Precompute row-major strides for the output shape.
    let mut out_strides = vec![1usize; rank];
    for i in (0..rank.saturating_sub(1)).rev() {
        let next = out_strides.get(i + 1).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "transpose::stride_error")
        })?;
        let dim = out_shape.get(i + 1).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "transpose::stride_error")
        })?;
        if let Some(s) = out_strides.get_mut(i) {
            *s = next * dim;
        }
    }

    let n_total: usize = out_shape.iter().product();
    let out_desc = TensorDescriptor::new(out_shape, TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];
    let src_bytes = src.as_bytes();

    // For each output flat index, reconstruct its multi-dimensional coordinate
    // in the output space, then map to the input flat index via axes permutation.
    #[allow(clippy::integer_division)]
    for out_flat in 0..n_total {
        // Decode out_flat into per-dimension indices in output space.
        let mut remaining = out_flat;
        let mut out_coords = vec![0usize; rank];
        for dim_idx in 0..rank {
            let stride = out_strides.get(dim_idx).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "transpose::decode_error")
            })?;
            let coord = remaining / stride;
            remaining %= stride;
            if let Some(c) = out_coords.get_mut(dim_idx) {
                *c = coord;
            }
        }

        // Map output coord[i] → input coord[axes[i]], then compute input flat index.
        let mut in_flat = 0usize;
        for (out_dim, &ax) in axes.iter().enumerate() {
            let out_coord = out_coords.get(out_dim).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "transpose::map_error")
            })?;
            let in_stride = in_strides.get(ax).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "transpose::map_error")
            })?;
            in_flat += out_coord * in_stride;
        }

        write_f32(&mut out_bytes, out_flat, read_f32(src_bytes, in_flat)?)?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Element-wise GELU activation (tanh approximation).
///
/// `output[i] = x * 0.5 * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x³)))`
#[allow(clippy::cast_precision_loss)]
fn exec_gelu(inputs: &[&TensorBuffer]) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(HalErrorKind::HardwareUnavailable, "execute::gelu::no_input")
    })?;

    require_f32(src.descriptor.dtype, "execute::gelu::unsupported_dtype")?;

    let n_elems = src.descriptor.num_elements();
    let out_desc = TensorDescriptor::new(src.descriptor.shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];
    let src_bytes = src.as_bytes();

    // Coefficient: sqrt(2/π) ≈ 0.7978845608.
    // Use core::f32::consts::PI for no_std compatibility (core is always available).
    let sqrt_2_over_pi = crate::math::sqrt(2.0_f32 / core::f32::consts::PI);

    for elem_idx in 0..n_elems {
        let x = read_f32(src_bytes, elem_idx)?;
        // Use mul_add for better FP accuracy as suggested by clippy::suboptimal_flops.
        // Routed through crate::math for no_std compatibility (ADR-0034).
        let inner = sqrt_2_over_pi * crate::math::mul_add(0.044_715 * x * x, x, x);
        let val = x * 0.5 * (1.0 + crate::math::tanh(inner));
        write_f32(&mut out_bytes, elem_idx, val)?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Multiply every element by a scalar constant.
fn exec_scale(inputs: &[&TensorBuffer], scalar: f32) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::scale::no_input",
        )
    })?;

    require_f32(src.descriptor.dtype, "execute::scale::unsupported_dtype")?;

    let n_elems = src.descriptor.num_elements();
    let out_desc = TensorDescriptor::new(src.descriptor.shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];
    let src_bytes = src.as_bytes();

    for elem_idx in 0..n_elems {
        let val = read_f32(src_bytes, elem_idx)? * scalar;
        write_f32(&mut out_bytes, elem_idx, val)?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Concatenate multiple tensors along `axis`.
///
/// All inputs must share the same rank and identical extents on every axis
/// except `axis`.  The output's `axis` extent is the sum of the inputs'.
#[allow(clippy::integer_division, clippy::too_many_lines)]
fn exec_concat(inputs: &[&TensorBuffer], axis: usize) -> Result<TensorBuffer> {
    let first = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::concat::no_input",
        )
    })?;

    require_f32(first.descriptor.dtype, "execute::concat::unsupported_dtype")?;

    let rank = first.descriptor.shape.len();
    if axis >= rank {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::concat::axis_out_of_bounds",
        ));
    }

    // Validate all inputs and compute output axis size.
    let mut out_axis_size = 0usize;
    for inp in inputs {
        require_f32(inp.descriptor.dtype, "execute::concat::unsupported_dtype")?;
        if inp.descriptor.shape.len() != rank {
            return Err(NexaCoreError::hal(
                HalErrorKind::DeviceFailure,
                "execute::concat::rank_mismatch",
            ));
        }
        for (dim_idx, (&a, &b)) in first
            .descriptor
            .shape
            .iter()
            .zip(inp.descriptor.shape.iter())
            .enumerate()
        {
            if dim_idx != axis && a != b {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::concat::shape_mismatch_on_non_concat_axis",
                ));
            }
        }
        let ax_size = inp.descriptor.shape.get(axis).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "execute::concat::shape_error")
        })?;
        out_axis_size += ax_size;
    }

    // Build output shape.
    let mut out_shape = first.descriptor.shape.clone();
    if let Some(slot) = out_shape.get_mut(axis) {
        *slot = out_axis_size;
    }
    let out_desc = TensorDescriptor::new(out_shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    // Compute strides for output and each input using the output shape.
    // We iterate output elements and determine which input tensor contributes.
    //
    // Strategy: for each element in the output, decode its coordinate along
    // the concat axis; then find which input owns that slice, and copy the
    // value from the appropriate input offset.
    //
    // Precompute row-major strides for the output shape.
    let mut out_strides = vec![1usize; rank];
    for i in (0..rank.saturating_sub(1)).rev() {
        let next_stride = out_strides.get(i + 1).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::stride_error")
        })?;
        let next_dim = out_shape.get(i + 1).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::stride_error")
        })?;
        if let Some(s) = out_strides.get_mut(i) {
            *s = next_stride * next_dim;
        }
    }

    let n_total: usize = out_shape.iter().product();

    for out_flat in 0..n_total {
        // Decode the coordinate along the concat axis only (others mirror input).
        let axis_stride = out_strides.get(axis).copied().ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::decode_error")
        })?;
        // The coordinate along the concat axis within the full output.
        let out_axis_coord = (out_flat / axis_stride) % out_axis_size;

        // Find which input tensor owns this coordinate and the local offset.
        let mut cursor = 0usize;
        let mut found_input: Option<(&TensorBuffer, usize)> = None;
        for inp in inputs {
            let inp_axis_size = inp.descriptor.shape.get(axis).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::inp_shape_error")
            })?;
            if out_axis_coord < cursor + inp_axis_size {
                found_input = Some((inp, out_axis_coord - cursor));
                break;
            }
            cursor += inp_axis_size;
        }

        let (inp, local_axis_coord) = found_input.ok_or_else(|| {
            NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::input_lookup_error")
        })?;

        // Precompute strides for this input shape.
        let inp_shape = &inp.descriptor.shape;
        let mut inp_strides = vec![1usize; rank];
        for i in (0..rank.saturating_sub(1)).rev() {
            let next_s = inp_strides.get(i + 1).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::inp_stride")
            })?;
            let next_d = inp_shape.get(i + 1).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::inp_stride")
            })?;
            if let Some(s) = inp_strides.get_mut(i) {
                *s = next_s * next_d;
            }
        }

        // Reconstruct the input flat index from the output coordinates,
        // replacing the concat axis coordinate with `local_axis_coord`.
        let mut in_flat = 0usize;
        for dim_idx in 0..rank {
            let stride = out_strides.get(dim_idx).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::reindex_error")
            })?;
            let coord = if dim_idx == axis {
                local_axis_coord
            } else {
                // Decode the coordinate for this non-concat dimension from out_flat.
                // The "outer" size for this dimension is the product of all dimensions
                // before it in the output layout, but since we only need the coord we
                // derive it as: coord = (out_flat / stride) % out_shape[dim_idx].
                let dim_size = out_shape.get(dim_idx).copied().ok_or_else(|| {
                    NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::reindex_error")
                })?;
                (out_flat / stride) % dim_size
            };
            let inp_stride = inp_strides.get(dim_idx).copied().ok_or_else(|| {
                NexaCoreError::hal(HalErrorKind::DeviceFailure, "concat::reindex_error")
            })?;
            in_flat += coord * inp_stride;
        }

        write_f32(&mut out_bytes, out_flat, read_f32(inp.as_bytes(), in_flat)?)?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// RMS Layer Normalization across the last axis.
///
/// For each slice of size `last_dim`:
/// `rms = sqrt(mean(x²) + epsilon)`, `output = x / rms`.
///
/// Weight scaling is handled separately by the caller.
#[allow(clippy::integer_division, clippy::cast_precision_loss)]
fn exec_rms_norm(inputs: &[&TensorBuffer], epsilon: f32) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::rms_norm::no_input",
        )
    })?;

    require_f32(src.descriptor.dtype, "execute::rms_norm::unsupported_dtype")?;

    let shape = &src.descriptor.shape;
    if shape.is_empty() {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::rms_norm::scalar_not_supported",
        ));
    }

    let last_dim = shape.last().copied().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::rms_norm::shape_error",
        )
    })?;
    let n_total = src.descriptor.num_elements();
    // Division is exact: n_total = n_slices * last_dim by construction.
    let n_slices = n_total / last_dim;

    let src_bytes = src.as_bytes();
    let out_desc = TensorDescriptor::new(shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    for slice_idx in 0..n_slices {
        let slice_start = slice_idx * last_dim;

        // Compute mean of squares.
        let mut mean_sq = 0.0_f32;
        for dim_pos in 0..last_dim {
            let x = read_f32(src_bytes, slice_start + dim_pos)?;
            mean_sq += x * x;
        }
        mean_sq /= last_dim as f32;

        let rms = crate::math::sqrt(mean_sq + epsilon);
        for dim_pos in 0..last_dim {
            let x = read_f32(src_bytes, slice_start + dim_pos)?;
            write_f32(&mut out_bytes, slice_start + dim_pos, x / rms)?;
        }
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

// =============================================================================
// Quantization helpers
// =============================================================================

/// Compute the `(min, max)` range of a slice of `f32` values.
///
/// Returns `(0.0, 0.0)` for an empty slice, which produces a scale of 0.
/// Callers that depend on a non-zero scale must validate the input is non-empty.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::f32_min_max;
///
/// let (mn, mx) = f32_min_max(&[-1.0, 0.5, 2.0]);
/// assert!((mn - (-1.0_f32)).abs() < 1e-6_f32);
/// assert!((mx - 2.0_f32).abs() < 1e-6_f32);
/// ```
pub fn f32_min_max(values: &[f32]) -> (f32, f32) {
    values
        .iter()
        .fold((f32::INFINITY, f32::NEG_INFINITY), |(mn, mx), &v| {
            (mn.min(v), mx.max(v))
        })
}

/// Derive symmetric per-tensor [`QuantizationParams`] from the absolute maximum
/// of the data.
///
/// Symmetric quantization sets `zero_point = 0` and derives `scale` so that the
/// largest absolute value maps to `127`.  This is the standard approach for
/// weight tensors in post-training quantization.
///
/// Returns `scale = 1.0, zero_point = 0` for all-zero data to avoid division by
/// zero.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::symmetric_quant_params;
///
/// let p = symmetric_quant_params(&[-2.0, 1.0, 2.0]);
/// assert_eq!(p.zero_point, 0);
/// // scale = 2.0 / 127 ≈ 0.01574
/// assert!((p.scale - 2.0_f32 / 127.0_f32).abs() < 1e-6_f32);
/// ```
#[allow(clippy::cast_precision_loss)]
pub fn symmetric_quant_params(values: &[f32]) -> QuantizationParams {
    let abs_max = values.iter().fold(0.0_f32, |m, &v| m.max(v.abs()));
    // Guard: if all values are 0 return a no-op scale.
    if abs_max == 0.0 {
        return QuantizationParams {
            scale: 1.0,
            zero_point: 0,
        };
    }
    // 127 = max representable INT8 value for symmetric range [-127, 127].
    let scale = abs_max / 127.0_f32;
    QuantizationParams {
        scale,
        zero_point: 0,
    }
}

/// Derive asymmetric per-tensor [`QuantizationParams`] from the actual data range.
///
/// Asymmetric quantization maps `[min_val, max_val]` onto `[-128, 127]`, choosing
/// `scale` and `zero_point` to minimise clipping.  This is appropriate for
/// activation tensors which are often non-zero-centred.
///
/// Returns `scale = 1.0, zero_point = 0` for degenerate ranges to avoid
/// division by zero.
///
/// # Example
///
/// ```
/// use nexacore_hal::tensor::asymmetric_quant_params;
///
/// // A range of [0, 1] should give a zero_point that centres the data.
/// let p = asymmetric_quant_params(&[0.0, 0.5, 1.0]);
/// assert!(p.scale > 0.0);
/// ```
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
pub fn asymmetric_quant_params(values: &[f32]) -> QuantizationParams {
    let (min_val, max_val) = f32_min_max(values);
    let range = max_val - min_val;
    if range == 0.0 {
        return QuantizationParams {
            scale: 1.0,
            zero_point: 0,
        };
    }
    // Map [min_val, max_val] to [-128, 127].
    let scale = range / 255.0_f32;
    // zero_point: the INT8 value that represents 0.0 in the float domain.
    // Derived from: 0 = (zp - zero_point) * scale  →  zero_point = -min_val / scale.
    // Clamped to [-128, 127] to stay in the representable range.
    // Routed through crate::math for no_std compatibility (ADR-0034).
    let zp_f32 = crate::math::round(-min_val / scale);
    let zero_point = zp_f32.clamp(-128.0, 127.0) as i8;
    QuantizationParams { scale, zero_point }
}

/// Quantize a single `f32` value to `i8` given `scale` and `zero_point`.
///
/// `q = clamp(round(x / scale) + zero_point, -128, 127)`
#[allow(clippy::cast_possible_truncation)]
fn quantize_element(x: f32, scale: f32, zero_point: i8) -> i8 {
    // Division by scale: scale is guaranteed non-zero by the callers that
    // compute it via `symmetric_quant_params` / `asymmetric_quant_params`.
    // Routed through crate::math for no_std compatibility (ADR-0034).
    let q_f32 = crate::math::round(x / scale) + f32::from(zero_point);
    // clamp to [-128, 127] before cast to i8.
    q_f32.clamp(-128.0, 127.0) as i8
}

/// Dequantize a single `i8` value to `f32` given `scale` and `zero_point`.
///
/// `x = (q - zero_point) * scale`
#[allow(clippy::cast_precision_loss)]
fn dequantize_element(q: i8, scale: f32, zero_point: i8) -> f32 {
    f32::from(q - zero_point) * scale
}

/// Quantize an F32 tensor to INT8.
///
/// Supports per-tensor (symmetric) quantization for weight tensors and
/// per-channel quantization for weight matrices where channels run along
/// axis 0.
///
/// For `PerTensor`: uses symmetric quantization (zero\_point = 0).
/// For `PerChannel { axis }`: uses symmetric quantization per slice along
/// `axis`.
///
/// The output buffer has dtype `I8`.
// cast_sign_loss: storing i8 bytes in a Vec<u8> requires an i8 → u8 bit-cast.
// This is intentional and semantically correct: the byte pattern is preserved
// and read back as i8 in exec_dequantize using the same u8 → i8 cast.
#[allow(
    clippy::cast_precision_loss,
    clippy::integer_division,
    clippy::cast_sign_loss
)]
fn exec_quantize(inputs: &[&TensorBuffer], scheme: &QuantizationScheme) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::quantize::no_input",
        )
    })?;

    require_f32(src.descriptor.dtype, "execute::quantize::unsupported_dtype")?;

    let n_elems = src.descriptor.num_elements();
    let src_bytes = src.as_bytes();

    // Read all source floats once to avoid repeated byte arithmetic.
    let mut src_vals: Vec<f32> = Vec::with_capacity(n_elems);
    for i in 0..n_elems {
        src_vals.push(read_f32(src_bytes, i)?);
    }

    let out_desc = TensorDescriptor::new(src.descriptor.shape.clone(), TensorDtype::I8);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    match scheme {
        QuantizationScheme::PerTensor => {
            // Compute a single scale from the full tensor.
            let params = symmetric_quant_params(&src_vals);
            for (i, &x) in src_vals.iter().enumerate() {
                let q = quantize_element(x, params.scale, params.zero_point);
                // SAFETY: i8 and u8 are both 1-byte types; transmuting the sign
                // bit is well-defined and the only way to store a signed byte in
                // a Vec<u8> without unsafe: we use u8::wrapping_cast semantics.
                // The pattern `q as u8` is equivalent to reinterpreting the bits.
                if let Some(slot) = out_bytes.get_mut(i) {
                    *slot = q as u8;
                }
            }
        }

        QuantizationScheme::PerChannel { axis } => {
            let shape = &src.descriptor.shape;
            let rank = shape.len();
            if *axis >= rank {
                return Err(NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::quantize::per_channel::axis_out_of_bounds",
                ));
            }

            // axis_size: number of channels.
            let axis_size = shape.get(*axis).copied().ok_or_else(|| {
                NexaCoreError::hal(
                    HalErrorKind::DeviceFailure,
                    "execute::quantize::shape_error",
                )
            })?;
            // outer: product of dims before axis.
            let outer: usize = shape.get(..*axis).map_or(1, |s| s.iter().product());
            // inner: product of dims after axis.
            let inner: usize = shape.get(axis + 1..).map_or(1, |s| s.iter().product());

            // For each channel, collect its elements, compute params, then quantize.
            for ch in 0..axis_size {
                // Gather all element values for this channel.
                let ch_vals: Vec<f32> = (0..outer)
                    .flat_map(|o| (0..inner).map(move |i| o * (axis_size * inner) + ch * inner + i))
                    .map(|flat| src_vals.get(flat).copied().unwrap_or(0.0))
                    .collect();

                let params = symmetric_quant_params(&ch_vals);

                for (local_idx, &x) in ch_vals.iter().enumerate() {
                    // Reconstruct the global flat index for this element.
                    let o = local_idx / inner;
                    let i = local_idx % inner;
                    let flat = o * (axis_size * inner) + ch * inner + i;
                    let q = quantize_element(x, params.scale, params.zero_point);
                    if let Some(slot) = out_bytes.get_mut(flat) {
                        *slot = q as u8;
                    }
                }
            }
        }
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// Dequantize an INT8 tensor to F32.
///
/// Applies `x = (q - zero_point) * scale` to every element.
/// The input tensor must have dtype `I8`.
// cast_possible_wrap: u8 → i8 is an intentional bit-reinterpretation. The byte
// was stored by exec_quantize using the same i8 → u8 convention, so the cast
// recovers the original signed value correctly.
#[allow(clippy::cast_possible_wrap)]
fn exec_dequantize(inputs: &[&TensorBuffer], params: QuantizationParams) -> Result<TensorBuffer> {
    let src = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::dequantize::no_input",
        )
    })?;

    if src.descriptor.dtype != TensorDtype::I8 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::dequantize::input_must_be_i8",
        ));
    }

    let n_elems = src.descriptor.num_elements();
    let src_bytes = src.as_bytes();

    let out_desc = TensorDescriptor::new(src.descriptor.shape.clone(), TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    for i in 0..n_elems {
        // Read the raw byte and reinterpret as i8 (bit-cast).
        let raw = src_bytes.get(i).copied().ok_or_else(|| {
            NexaCoreError::hal(
                HalErrorKind::DeviceFailure,
                "execute::dequantize::read_error",
            )
        })?;
        // SAFETY: u8 → i8 is a well-defined bit-reinterpretation in Rust.
        // The byte was stored by exec_quantize using the same convention.
        let q = raw as i8;
        let x = dequantize_element(q, params.scale, params.zero_point);
        write_f32(&mut out_bytes, i, x)?;
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

/// INT8 matrix multiplication with INT32 accumulation, output in F32.
///
/// Computes `C[i,j] = sum_k A[i,k] * B[k,j]` where A and B are INT8 matrices.
/// Accumulation happens in `i32` to avoid overflow for large K.
///
/// The dequantized output is:
/// `c_f32 = (c_i32 * scale_a * scale_b) / out_scale`
///
/// For symmetric quantization (`zero_point = 0` for both A and B), the
/// zero-point correction terms cancel and the formula reduces to a simple
/// scaling of the integer dot product.
///
/// For asymmetric quantization the correction terms are computed and subtracted:
/// `correction = zero_point_a * sum_k B[k,j] + zero_point_b * sum_k A[i,k]
///               - zero_point_a * zero_point_b * K`
///
/// This correction is computed once per output element.
// cast_possible_wrap: u8 → i8 bit-cast is intentional (see exec_dequantize comment).
// cast_possible_truncation: `inner as i32` — inner dimension is a tensor size;
//   in practice < 2^16 and cannot wrap a 32-bit signed integer.
#[allow(
    clippy::integer_division,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::too_many_lines
)]
fn exec_quantized_matmul(
    inputs: &[&TensorBuffer],
    params_a: QuantizationParams,
    params_b: QuantizationParams,
    out_scale: f32,
) -> Result<TensorBuffer> {
    let mat_a = inputs.first().ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::quant_matmul::requires_two_inputs",
        )
    })?;
    let mat_b = inputs.get(1).ok_or_else(|| {
        NexaCoreError::hal(
            HalErrorKind::HardwareUnavailable,
            "execute::quant_matmul::requires_two_inputs",
        )
    })?;

    if mat_a.descriptor.dtype != TensorDtype::I8 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::quant_matmul::input_a_must_be_i8",
        ));
    }
    if mat_b.descriptor.dtype != TensorDtype::I8 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::quant_matmul::input_b_must_be_i8",
        ));
    }

    if out_scale == 0.0 {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::quant_matmul::out_scale_must_be_nonzero",
        ));
    }

    let (rows, inner_a) = matmul_effective_dims(&mat_a.descriptor.shape, false)?;
    let (inner_b, cols) = matmul_effective_dims(&mat_b.descriptor.shape, false)?;

    if inner_a != inner_b {
        return Err(NexaCoreError::hal(
            HalErrorKind::DeviceFailure,
            "execute::quant_matmul::inner_dimension_mismatch",
        ));
    }
    let inner = inner_a;

    let a_bytes = mat_a.as_bytes();
    let b_bytes = mat_b.as_bytes();

    let out_desc = TensorDescriptor::new(vec![rows, cols], TensorDtype::F32);
    let mut out_bytes = vec![0u8; out_desc.byte_size()];

    // Pre-compute combined float scale: product of both input scales divided by
    // the output scale.  Multiplied once per output element rather than per
    // accumulation step.
    let combined_scale = params_a.scale * params_b.scale / out_scale;

    // Zero-point integers cast to i32 for arithmetic without overflow.
    let zp_a = i32::from(params_a.zero_point);
    let zp_b = i32::from(params_b.zero_point);
    let k_i32 = inner as i32;

    for row in 0..rows {
        // Pre-compute sum_k A[row,k] once per row for the asymmetric correction.
        let row_sum_a: i32 = (0..inner)
            .map(|k| {
                let idx = row * inner + k;
                a_bytes.get(idx).map_or(0_i32, |&b| i32::from(b as i8))
            })
            .fold(0_i32, i32::saturating_add);

        for col in 0..cols {
            // Integer dot product: accumulate A[row,k] * B[k,col] in i32.
            let mut acc_i32: i32 = 0;
            for k in 0..inner {
                let a_idx = row * inner + k;
                let b_idx = k * cols + col;
                let a_val = a_bytes
                    .get(a_idx)
                    .copied()
                    .ok_or_else(|| {
                        NexaCoreError::hal(
                            HalErrorKind::DeviceFailure,
                            "execute::quant_matmul::index_error_a",
                        )
                    })
                    .map(|b| i32::from(b as i8))?;
                let b_val = b_bytes
                    .get(b_idx)
                    .copied()
                    .ok_or_else(|| {
                        NexaCoreError::hal(
                            HalErrorKind::DeviceFailure,
                            "execute::quant_matmul::index_error_b",
                        )
                    })
                    .map(|b| i32::from(b as i8))?;
                acc_i32 = acc_i32.saturating_add(a_val * b_val);
            }

            // Asymmetric correction: handles non-zero zero-points.
            // correction = zp_a * sum_k(B[k,col]) + zp_b * row_sum_a
            //              - zp_a * zp_b * K
            // For symmetric (zp = 0) this entire block is zero and is compiled
            // away by the optimizer.
            if zp_a != 0 || zp_b != 0 {
                // sum_k B[k,col] for this column.
                let col_sum_b: i32 = (0..inner)
                    .map(|k| {
                        let idx = k * cols + col;
                        b_bytes.get(idx).map_or(0_i32, |&b| i32::from(b as i8))
                    })
                    .fold(0_i32, i32::saturating_add);

                let correction = zp_a
                    .saturating_mul(col_sum_b)
                    .saturating_add(zp_b.saturating_mul(row_sum_a))
                    .saturating_sub(zp_a.saturating_mul(zp_b).saturating_mul(k_i32));

                acc_i32 = acc_i32.saturating_sub(correction);
            }

            // Rescale to F32.
            let out_val = (acc_i32 as f32) * combined_scale;
            write_f32(&mut out_bytes, row * cols + col, out_val)?;
        }
    }

    Ok(TensorBuffer::new(out_desc, out_bytes))
}

// =============================================================================
// CpuBackend — synchronous inherent methods (available in std AND no_std)
// =============================================================================

impl CpuBackend {
    /// Human-readable backend identifier — always `"cpu"`.
    ///
    /// Available in both `std` and `no_std` builds.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::CpuBackend;
    ///
    /// assert_eq!(CpuBackend::new().name(), "cpu");
    /// ```
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "method form mirrors the async TensorBackend trait surface"
    )]
    pub fn name(&self) -> &'static str {
        "cpu"
    }

    /// SIMD capability levels for this backend, weakest to strongest.
    ///
    /// Always contains at least [`SimdCapability::None`].  On `no_std` builds
    /// SIMD detection is skipped and only `None` is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::CpuBackend;
    ///
    /// assert!(!CpuBackend::new().capabilities().is_empty());
    /// ```
    #[must_use]
    pub fn capabilities(&self) -> &[SimdCapability] {
        &self.capabilities
    }

    /// Returns `true` if this backend can process tensors of the given dtype.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorDtype};
    ///
    /// assert!(CpuBackend::new().supports_dtype(TensorDtype::F32));
    /// ```
    #[must_use]
    pub fn supports_dtype(&self, dtype: TensorDtype) -> bool {
        match dtype {
            TensorDtype::F32 | TensorDtype::I8 | TensorDtype::U8 => true,
            TensorDtype::F16 | TensorDtype::Bf16 => {
                self.capabilities.contains(&SimdCapability::Avx512)
                    || self.capabilities.contains(&SimdCapability::Neon)
                    || self.capabilities.contains(&SimdCapability::SveAarch64)
            }
        }
    }

    /// Maximum allocation size in bytes this backend will honour.
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::CpuBackend;
    ///
    /// assert!(CpuBackend::new().max_tensor_size_bytes() > 0);
    /// ```
    #[must_use]
    pub fn max_tensor_size_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Allocate a zeroed [`TensorBuffer`] matching `desc` — synchronous variant.
    ///
    /// This is the real allocation body that the async [`TensorBackend::allocate`]
    /// delegates to (under `std`).  Available in both `std` and `no_std` builds
    /// so that the `no_std` inference path can allocate without an executor
    /// (TASK-13-pre / ADR-0034).
    ///
    /// # Errors
    ///
    /// - [`HalErrorKind::HardwareUnavailable`] — `desc.byte_size()` exceeds
    ///   [`CpuBackend::max_tensor_size_bytes`].
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorDescriptor, TensorDtype};
    ///
    /// let backend = CpuBackend::new();
    /// let desc = TensorDescriptor::new(vec![4, 4], TensorDtype::F32);
    /// let buf = backend.allocate_sync(&desc).unwrap();
    /// assert_eq!(buf.len(), 64);
    /// ```
    pub fn allocate_sync(&self, desc: &TensorDescriptor) -> Result<TensorBuffer> {
        let size = desc.byte_size();
        if size > self.max_bytes {
            return Err(NexaCoreError::hal(
                HalErrorKind::HardwareUnavailable,
                "allocate::exceeds_max_tensor_size",
            ));
        }
        let bytes = vec![0u8; size];
        Ok(TensorBuffer::new(desc.clone(), bytes))
    }

    /// Execute `op` on the given input buffers — synchronous variant.
    ///
    /// This is the real computation body that the async [`TensorBackend::execute`]
    /// delegates to (under `std`).  Available in both `std` and `no_std` builds
    /// so that the `no_std` inference path can run tensor ops without an executor
    /// (TASK-13-pre / ADR-0034).
    ///
    /// # Errors
    ///
    /// Returns an error if any tensor operation fails (shape mismatch,
    /// out-of-bounds index, unsupported dtype/op combination, etc.).
    ///
    /// # Example
    ///
    /// ```
    /// use nexacore_hal::tensor::{CpuBackend, TensorBuffer, TensorDescriptor, TensorDtype, TensorOp};
    ///
    /// let backend = CpuBackend::new();
    /// let desc = TensorDescriptor::new(vec![4], TensorDtype::F32);
    /// let buf = backend.allocate_sync(&desc).unwrap();
    /// let out = backend.execute_sync(TensorOp::Relu, &[&buf]).unwrap();
    /// assert_eq!(out.descriptor.shape, vec![4]);
    /// ```
    pub fn execute_sync(&self, op: TensorOp, inputs: &[&TensorBuffer]) -> Result<TensorBuffer> {
        // Validate output descriptor (validates input counts and shapes).
        let out_desc = output_descriptor_for(&op, inputs)?;

        // Guard the output size before doing any computation.
        if out_desc.byte_size() > self.max_bytes {
            return Err(NexaCoreError::hal(
                HalErrorKind::HardwareUnavailable,
                "execute::output_exceeds_max_tensor_size",
            ));
        }

        match op {
            TensorOp::MatMul {
                transpose_a,
                transpose_b,
            } => exec_matmul(inputs, transpose_a, transpose_b),

            TensorOp::Add => exec_add(inputs),

            TensorOp::Relu => exec_relu(inputs),

            TensorOp::Softmax { axis } => exec_softmax(inputs, axis),

            TensorOp::LayerNorm { epsilon } => exec_layer_norm(inputs, epsilon),

            TensorOp::EmbeddingLookup => exec_embedding_lookup(inputs),

            TensorOp::Reshape { new_shape } => exec_reshape(inputs, &new_shape),

            TensorOp::Transpose { axes } => exec_transpose(inputs, &axes),

            TensorOp::GeLU => exec_gelu(inputs),

            TensorOp::Scale { scalar } => exec_scale(inputs, scalar),

            TensorOp::Concat { axis } => exec_concat(inputs, axis),

            TensorOp::RmsNorm { epsilon } => exec_rms_norm(inputs, epsilon),

            TensorOp::Quantize { scheme } => exec_quantize(inputs, &scheme),

            TensorOp::Dequantize { params } => exec_dequantize(inputs, params),

            TensorOp::QuantizedMatMul {
                params_a,
                params_b,
                out_scale,
            } => exec_quantized_matmul(inputs, params_a, params_b, out_scale),
        }
    }
}

// =============================================================================
// TensorBackend impl for CpuBackend — async surface (std only)
// =============================================================================

/// Async `TensorBackend` implementation for `CpuBackend`.
///
/// Available only when the `std` feature is enabled; delegates to the
/// synchronous inherent methods ([`CpuBackend::allocate_sync`] /
/// [`CpuBackend::execute_sync`]) so there is a single audited compute body
/// (TASK-13-pre / ADR-0034).
#[cfg(feature = "std")]
#[async_trait]
impl TensorBackend for CpuBackend {
    fn name(&self) -> &'static str {
        Self::name(self)
    }

    fn capabilities(&self) -> &[SimdCapability] {
        Self::capabilities(self)
    }

    async fn allocate(&self, desc: &TensorDescriptor) -> Result<TensorBuffer> {
        let size = desc.byte_size();
        if size > self.max_bytes {
            tracing::warn!(
                requested_bytes = size,
                limit_bytes = self.max_bytes,
                "CpuBackend::allocate rejected oversized allocation"
            );
        }
        tracing::trace!(
            shape = ?desc.shape,
            dtype = ?desc.dtype,
            size_bytes = size,
            "CpuBackend::allocate"
        );
        self.allocate_sync(desc)
    }

    async fn execute(&self, op: TensorOp, inputs: &[&TensorBuffer]) -> Result<TensorBuffer> {
        tracing::trace!(
            op = ?op,
            input_count = inputs.len(),
            "CpuBackend::execute"
        );
        self.execute_sync(op, inputs)
    }

    fn supports_dtype(&self, dtype: TensorDtype) -> bool {
        Self::supports_dtype(self, dtype)
    }

    fn max_tensor_size_bytes(&self) -> usize {
        Self::max_tensor_size_bytes(self)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // TensorDtype
    // -------------------------------------------------------------------------

    #[test]
    fn dtype_bytes_per_element_f32() {
        assert_eq!(TensorDtype::F32.bytes_per_element(), 4);
    }

    #[test]
    fn dtype_bytes_per_element_f16_bf16() {
        assert_eq!(TensorDtype::F16.bytes_per_element(), 2);
        assert_eq!(TensorDtype::Bf16.bytes_per_element(), 2);
    }

    #[test]
    fn dtype_bytes_per_element_i8_u8() {
        assert_eq!(TensorDtype::I8.bytes_per_element(), 1);
        assert_eq!(TensorDtype::U8.bytes_per_element(), 1);
    }

    // -------------------------------------------------------------------------
    // TensorDescriptor
    // -------------------------------------------------------------------------

    #[test]
    fn descriptor_num_elements_2d() {
        let d = TensorDescriptor::new(vec![3, 4], TensorDtype::F32);
        assert_eq!(d.num_elements(), 12);
    }

    #[test]
    fn descriptor_num_elements_scalar() {
        // Empty shape → scalar → 1 element.
        let d = TensorDescriptor::new(vec![], TensorDtype::F32);
        assert_eq!(d.num_elements(), 1);
    }

    #[test]
    fn descriptor_byte_size_f32_matrix() {
        let d = TensorDescriptor::new(vec![2, 3], TensorDtype::F32);
        assert_eq!(d.byte_size(), 24); // 6 × 4 bytes
    }

    #[test]
    fn descriptor_byte_size_f16_vector() {
        let d = TensorDescriptor::new(vec![16], TensorDtype::F16);
        assert_eq!(d.byte_size(), 32); // 16 × 2 bytes
    }

    #[test]
    fn descriptor_named_roundtrip() {
        let d = TensorDescriptor::named(vec![1, 128], TensorDtype::Bf16, "query");
        assert_eq!(d.name.as_deref(), Some("query"));
        assert_eq!(d.shape, vec![1, 128]);
        assert_eq!(d.dtype, TensorDtype::Bf16);
    }

    // -------------------------------------------------------------------------
    // TensorBuffer
    // -------------------------------------------------------------------------

    #[test]
    fn buffer_len_and_not_empty() {
        let desc = TensorDescriptor::new(vec![4], TensorDtype::U8);
        let buf = TensorBuffer::new(desc, vec![1, 2, 3, 4]);
        assert_eq!(buf.len(), 4);
        assert!(!buf.is_empty());
    }

    #[test]
    fn buffer_as_bytes_roundtrip() {
        let desc = TensorDescriptor::new(vec![2], TensorDtype::I8);
        let buf = TensorBuffer::new(desc, vec![10, 20]);
        assert_eq!(buf.as_bytes(), &[10u8, 20u8]);
    }

    // -------------------------------------------------------------------------
    // CpuBackend construction + capability detection
    // -------------------------------------------------------------------------

    #[test]
    fn cpu_backend_capabilities_not_empty() {
        let b = CpuBackend::new();
        assert!(!b.capabilities().is_empty());
    }

    #[test]
    fn cpu_backend_capabilities_always_has_none() {
        let b = CpuBackend::new();
        assert!(b.capabilities().contains(&SimdCapability::None));
    }

    #[test]
    fn cpu_backend_name_is_cpu() {
        let b = CpuBackend::new();
        assert_eq!(b.name(), "cpu");
    }

    #[test]
    fn cpu_backend_default_max_bytes() {
        let b = CpuBackend::new();
        assert_eq!(b.max_tensor_size_bytes(), DEFAULT_MAX_BYTES);
    }

    #[test]
    fn cpu_backend_custom_max_bytes() {
        let b = CpuBackend::with_max_bytes(1024);
        assert_eq!(b.max_tensor_size_bytes(), 1024);
    }

    #[test]
    fn cpu_backend_default_impl_matches_new() {
        let b = CpuBackend::default();
        assert_eq!(b.max_tensor_size_bytes(), DEFAULT_MAX_BYTES);
    }

    // -------------------------------------------------------------------------
    // supports_dtype
    // -------------------------------------------------------------------------

    #[test]
    fn supports_dtype_f32_always() {
        let b = CpuBackend::new();
        assert!(b.supports_dtype(TensorDtype::F32));
    }

    #[test]
    fn supports_dtype_i8_u8_always() {
        let b = CpuBackend::new();
        assert!(b.supports_dtype(TensorDtype::I8));
        assert!(b.supports_dtype(TensorDtype::U8));
    }

    #[test]
    fn supports_dtype_f16_depends_on_avx512_or_neon() {
        let b = CpuBackend::new();
        let has_avx512 = b.capabilities().contains(&SimdCapability::Avx512);
        let has_neon = b.capabilities().contains(&SimdCapability::Neon);
        let has_sve = b.capabilities().contains(&SimdCapability::SveAarch64);
        assert_eq!(
            b.supports_dtype(TensorDtype::F16),
            has_avx512 || has_neon || has_sve
        );
    }

    #[test]
    fn supports_dtype_bf16_same_as_f16() {
        let b = CpuBackend::new();
        assert_eq!(
            b.supports_dtype(TensorDtype::Bf16),
            b.supports_dtype(TensorDtype::F16)
        );
    }

    // -------------------------------------------------------------------------
    // allocate (async)
    //
    // All success-path tests return `Result<()>` so we can use `?` instead of
    // `.expect()` / `.unwrap()`, which are denied by workspace lint policy
    // (`clippy::expect_used` + `clippy::unwrap_used` are promoted to errors
    // via `-D warnings` in CI).  Error-path tests use `.is_err()` / `matches!`
    // to avoid the same lint.
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn allocate_correct_size() -> Result<()> {
        let b = CpuBackend::new();
        let desc = TensorDescriptor::new(vec![4, 4], TensorDtype::F32);
        let buf = b.allocate(&desc).await?;
        assert_eq!(buf.len(), 64); // 16 elements × 4 bytes
        Ok(())
    }

    #[tokio::test]
    async fn allocate_zeroed() -> Result<()> {
        let b = CpuBackend::new();
        let desc = TensorDescriptor::new(vec![8], TensorDtype::U8);
        let buf = b.allocate(&desc).await?;
        assert!(buf.as_bytes().iter().all(|&x| x == 0));
        Ok(())
    }

    #[tokio::test]
    async fn allocate_scalar_one_element() -> Result<()> {
        let b = CpuBackend::new();
        let desc = TensorDescriptor::new(vec![], TensorDtype::F32);
        let buf = b.allocate(&desc).await?;
        assert_eq!(buf.len(), 4); // 1 element × 4 bytes
        Ok(())
    }

    #[tokio::test]
    async fn allocate_rejects_oversized() {
        // Set a tiny limit.
        let b = CpuBackend::with_max_bytes(16);
        let desc = TensorDescriptor::new(vec![100], TensorDtype::F32); // 400 bytes
        let result = b.allocate(&desc).await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(NexaCoreError::Hal {
                kind: HalErrorKind::HardwareUnavailable,
                ..
            })
        ));
    }

    // -------------------------------------------------------------------------
    // execute stubs
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn execute_add_returns_same_shape() -> Result<()> {
        let b = CpuBackend::new();
        let desc = TensorDescriptor::new(vec![3, 3], TensorDtype::F32);
        let buf = b.allocate(&desc).await?;
        let out = b.execute(TensorOp::Add, &[&buf, &buf]).await?;
        assert_eq!(out.descriptor.shape, vec![3, 3]);
        assert_eq!(out.len(), 9 * 4);
        Ok(())
    }

    #[tokio::test]
    async fn execute_relu_returns_zeroed_stub() -> Result<()> {
        let b = CpuBackend::new();
        let desc = TensorDescriptor::new(vec![4], TensorDtype::F32);
        let buf = b.allocate(&desc).await?;
        let out = b.execute(TensorOp::Relu, &[&buf]).await?;
        assert!(out.as_bytes().iter().all(|&x| x == 0));
        Ok(())
    }

    #[tokio::test]
    async fn execute_softmax_returns_correct_shape() -> Result<()> {
        let b = CpuBackend::new();
        let desc = TensorDescriptor::new(vec![1, 10], TensorDtype::F32);
        let buf = b.allocate(&desc).await?;
        let out = b.execute(TensorOp::Softmax { axis: 1 }, &[&buf]).await?;
        assert_eq!(out.descriptor.shape, vec![1, 10]);
        Ok(())
    }

    #[tokio::test]
    async fn execute_reshape_changes_shape() -> Result<()> {
        let b = CpuBackend::new();
        let desc = TensorDescriptor::new(vec![2, 6], TensorDtype::F32);
        let buf = b.allocate(&desc).await?;
        let out = b
            .execute(
                TensorOp::Reshape {
                    new_shape: vec![3, 4],
                },
                &[&buf],
            )
            .await?;
        assert_eq!(out.descriptor.shape, vec![3, 4]);
        // byte count unchanged: 12 elements × 4 bytes
        assert_eq!(out.len(), 48);
        Ok(())
    }

    /// Updated matmul test: validates real computation with two inputs.
    /// Replaced the old Phase-2-stub assertion (single input, shape check only).
    #[tokio::test]
    async fn execute_matmul_stub() -> Result<()> {
        let backend = CpuBackend::new();
        // A [2,2] × I [2,2] (identity matrix) → result equals A.
        let mat_a = make_f32_buf(vec![2, 2], &[1.0, 0.0, 0.0, 1.0]);
        let identity = make_f32_buf(vec![2, 2], &[1.0, 0.0, 0.0, 1.0]);

        let out = backend
            .execute(
                TensorOp::MatMul {
                    transpose_a: false,
                    transpose_b: false,
                },
                &[&mat_a, &identity],
            )
            .await?;
        assert_eq!(out.descriptor.shape, vec![2, 2]);
        let vals = read_f32_buf(&out);
        assert!((vals[0] - 1.0_f32).abs() < 1e-6_f32);
        assert!((vals[1] - 0.0_f32).abs() < 1e-6_f32);
        assert!((vals[2] - 0.0_f32).abs() < 1e-6_f32);
        assert!((vals[3] - 1.0_f32).abs() < 1e-6_f32);
        Ok(())
    }

    #[tokio::test]
    async fn execute_no_input_returns_error() {
        let backend = CpuBackend::new();
        let result = backend.execute(TensorOp::Add, &[]).await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(NexaCoreError::Hal {
                kind: HalErrorKind::HardwareUnavailable,
                ..
            })
        ));
    }

    // -------------------------------------------------------------------------
    // Test helpers: build F32 buffers and read them back.
    // -------------------------------------------------------------------------

    /// Build an F32 `TensorBuffer` from a `shape` and a flat slice of values.
    fn make_f32_buf(shape: Vec<usize>, values: &[f32]) -> TensorBuffer {
        let desc = TensorDescriptor::new(shape, TensorDtype::F32);
        let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        TensorBuffer::new(desc, bytes)
    }

    /// Decode all `f32` values from a `TensorBuffer` into a `Vec<f32>`.
    fn read_f32_buf(buf: &TensorBuffer) -> Vec<f32> {
        let raw = buf.as_bytes();
        (0..buf.descriptor.num_elements())
            .map(|elem| {
                let byte_start = elem * 4;
                f32::from_le_bytes([
                    raw[byte_start],
                    raw[byte_start + 1],
                    raw[byte_start + 2],
                    raw[byte_start + 3],
                ])
            })
            .collect()
    }

    // -------------------------------------------------------------------------
    // MatMul tests
    // -------------------------------------------------------------------------

    /// A [2,3] × [3,2] matmul with known values.
    ///
    /// A = [[1,2,3],[4,5,6]], B = [[7,8],[9,10],[11,12]]
    ///
    /// Expected C:
    /// - C[0,0] = 1*7 + 2*9 + 3*11 = 58
    /// - C[0,1] = 1*8 + 2*10 + 3*12 = 64
    /// - C[1,0] = 4*7 + 5*9 + 6*11 = 139
    /// - C[1,1] = 4*8 + 5*10 + 6*12 = 154
    #[tokio::test]
    async fn matmul_2x3_times_3x2_identity() -> Result<()> {
        let backend = CpuBackend::new();
        let mat_a = make_f32_buf(vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let mat_b = make_f32_buf(vec![3, 2], &[7.0, 8.0, 9.0, 10.0, 11.0, 12.0]);

        let out = backend
            .execute(
                TensorOp::MatMul {
                    transpose_a: false,
                    transpose_b: false,
                },
                &[&mat_a, &mat_b],
            )
            .await?;

        assert_eq!(out.descriptor.shape, vec![2, 2]);
        let vals = read_f32_buf(&out);
        assert!((vals[0] - 58.0_f32).abs() < 1e-4_f32, "C[0,0]={}", vals[0]);
        assert!((vals[1] - 64.0_f32).abs() < 1e-4_f32, "C[0,1]={}", vals[1]);
        assert!((vals[2] - 139.0_f32).abs() < 1e-4_f32, "C[1,0]={}", vals[2]);
        assert!((vals[3] - 154.0_f32).abs() < 1e-4_f32, "C[1,1]={}", vals[3]);
        Ok(())
    }

    /// MatMul with `transpose_b = true`.
    ///
    /// A = [[1,2],[3,4]], B_raw = [[1,3],[2,4]].
    /// With transpose_b, B_eff = B_raw^T = [[1,2],[3,4]].
    /// C = A × B_eff = [[7,10],[15,22]].
    #[tokio::test]
    async fn matmul_transpose_b() -> Result<()> {
        let backend = CpuBackend::new();
        let mat_a = make_f32_buf(vec![2, 2], &[1.0, 2.0, 3.0, 4.0]);
        let mat_b = make_f32_buf(vec![2, 2], &[1.0, 3.0, 2.0, 4.0]);

        let out = backend
            .execute(
                TensorOp::MatMul {
                    transpose_a: false,
                    transpose_b: true,
                },
                &[&mat_a, &mat_b],
            )
            .await?;

        assert_eq!(out.descriptor.shape, vec![2, 2]);
        let vals = read_f32_buf(&out);
        assert!((vals[0] - 7.0_f32).abs() < 1e-4_f32, "C[0,0]={}", vals[0]);
        assert!((vals[1] - 10.0_f32).abs() < 1e-4_f32, "C[0,1]={}", vals[1]);
        assert!((vals[2] - 15.0_f32).abs() < 1e-4_f32, "C[1,0]={}", vals[2]);
        assert!((vals[3] - 22.0_f32).abs() < 1e-4_f32, "C[1,1]={}", vals[3]);
        Ok(())
    }

    /// MatMul with mismatched inner dimensions must return an error.
    #[tokio::test]
    async fn matmul_dimension_mismatch_errors() {
        let backend = CpuBackend::new();
        let mat_a = make_f32_buf(vec![2, 3], &[1.0; 6]);
        let mat_b = make_f32_buf(vec![2, 4], &[1.0; 8]);

        let result = backend
            .execute(
                TensorOp::MatMul {
                    transpose_a: false,
                    transpose_b: false,
                },
                &[&mat_a, &mat_b],
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(NexaCoreError::Hal {
                kind: HalErrorKind::DeviceFailure,
                ..
            })
        ));
    }

    // -------------------------------------------------------------------------
    // Add tests
    // -------------------------------------------------------------------------

    /// Element-wise addition produces correct values.
    #[tokio::test]
    async fn add_element_wise_correct() -> Result<()> {
        let backend = CpuBackend::new();
        let lhs = make_f32_buf(vec![3], &[1.0, 2.0, 3.0]);
        let rhs = make_f32_buf(vec![3], &[10.0, 20.0, 30.0]);

        let out = backend.execute(TensorOp::Add, &[&lhs, &rhs]).await?;
        assert_eq!(out.descriptor.shape, vec![3]);
        let vals = read_f32_buf(&out);
        assert!((vals[0] - 11.0_f32).abs() < 1e-6_f32);
        assert!((vals[1] - 22.0_f32).abs() < 1e-6_f32);
        assert!((vals[2] - 33.0_f32).abs() < 1e-6_f32);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // ReLU tests
    // -------------------------------------------------------------------------

    /// `ReLU` zeroes negative values and preserves positives.
    #[tokio::test]
    async fn relu_zeroes_negatives() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![4], &[-3.0, -0.5, 0.0, 2.5]);

        let out = backend.execute(TensorOp::Relu, &[&src]).await?;
        let vals = read_f32_buf(&out);
        assert!((vals[0] - 0.0_f32).abs() < 1e-6_f32, "vals[0]={}", vals[0]);
        assert!((vals[1] - 0.0_f32).abs() < 1e-6_f32, "vals[1]={}", vals[1]);
        assert!((vals[2] - 0.0_f32).abs() < 1e-6_f32, "vals[2]={}", vals[2]);
        assert!((vals[3] - 2.5_f32).abs() < 1e-6_f32, "vals[3]={}", vals[3]);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Softmax tests
    // -------------------------------------------------------------------------

    /// Softmax output values for a [1,4] input must sum to 1.0.
    #[tokio::test]
    async fn softmax_sums_to_one() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![1, 4], &[1.0, 2.0, 3.0, 4.0]);

        let out = backend
            .execute(TensorOp::Softmax { axis: 1 }, &[&src])
            .await?;
        let vals = read_f32_buf(&out);
        let total: f32 = vals.iter().sum();
        assert!((total - 1.0_f32).abs() < 1e-5_f32, "softmax sum={total}");
        Ok(())
    }

    /// Softmax along axis 0 on a [4,1] tensor also sums to 1.
    #[tokio::test]
    async fn softmax_axis0() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![4, 1], &[1.0, 2.0, 3.0, 4.0]);

        let out = backend
            .execute(TensorOp::Softmax { axis: 0 }, &[&src])
            .await?;
        assert_eq!(out.descriptor.shape, vec![4, 1]);
        let vals = read_f32_buf(&out);
        let total: f32 = vals.iter().sum();
        assert!(
            (total - 1.0_f32).abs() < 1e-5_f32,
            "softmax axis=0 sum={total}"
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // LayerNorm tests
    // -------------------------------------------------------------------------

    /// After LayerNorm, the mean of the last axis should be ≈ 0 and
    /// the variance ≈ 1.
    #[tokio::test]
    async fn layer_norm_basic() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![1, 4], &[1.0, 2.0, 3.0, 4.0]);

        let out = backend
            .execute(TensorOp::LayerNorm { epsilon: 1e-5 }, &[&src])
            .await?;
        assert_eq!(out.descriptor.shape, vec![1, 4]);

        let vals = read_f32_buf(&out);
        let mean: f32 = vals.iter().sum::<f32>() / 4.0_f32;
        let var: f32 = vals.iter().map(|v| (v - mean) * (v - mean)).sum::<f32>() / 4.0_f32;
        assert!(mean.abs() < 1e-4_f32, "mean={mean}");
        assert!((var - 1.0_f32).abs() < 1e-3_f32, "var={var}");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // EmbeddingLookup tests
    // -------------------------------------------------------------------------

    /// EmbeddingLookup selects the correct rows from the weight table.
    #[tokio::test]
    async fn embedding_lookup_basic() -> Result<()> {
        let backend = CpuBackend::new();
        // vocab_size=3, embed_dim=2: rows [[1,2],[3,4],[5,6]]
        let table = make_f32_buf(vec![3, 2], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let idx_desc = TensorDescriptor::new(vec![2], TensorDtype::U8);
        let idx_buf = TensorBuffer::new(idx_desc, vec![2u8, 0u8]);

        let out = backend
            .execute(TensorOp::EmbeddingLookup, &[&table, &idx_buf])
            .await?;
        assert_eq!(out.descriptor.shape, vec![2, 2]);
        let vals = read_f32_buf(&out);
        // Row 2 = [5.0, 6.0], row 0 = [1.0, 2.0]
        assert!((vals[0] - 5.0_f32).abs() < 1e-6_f32);
        assert!((vals[1] - 6.0_f32).abs() < 1e-6_f32);
        assert!((vals[2] - 1.0_f32).abs() < 1e-6_f32);
        assert!((vals[3] - 2.0_f32).abs() < 1e-6_f32);
        Ok(())
    }

    /// EmbeddingLookup returns an error for out-of-bounds indices.
    #[tokio::test]
    async fn embedding_lookup_oob_errors() {
        let backend = CpuBackend::new();
        let table = make_f32_buf(vec![3, 2], &[1.0; 6]);
        let idx_desc = TensorDescriptor::new(vec![1], TensorDtype::U8);
        let idx_buf = TensorBuffer::new(idx_desc, vec![5u8]);

        let result = backend
            .execute(TensorOp::EmbeddingLookup, &[&table, &idx_buf])
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(NexaCoreError::Hal {
                kind: HalErrorKind::DeviceFailure,
                ..
            })
        ));
    }

    // -------------------------------------------------------------------------
    // Reshape tests
    // -------------------------------------------------------------------------

    /// Reshape validates that the element count matches.
    #[tokio::test]
    async fn reshape_validates_element_count() {
        let backend = CpuBackend::new();
        // 6-element source, 8-element target → mismatch.
        let desc = TensorDescriptor::new(vec![2, 3], TensorDtype::F32);
        let buf = TensorBuffer::new(desc, vec![0u8; 24]);

        let result = backend
            .execute(
                TensorOp::Reshape {
                    new_shape: vec![4, 2],
                },
                &[&buf],
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(NexaCoreError::Hal {
                kind: HalErrorKind::DeviceFailure,
                ..
            })
        ));
    }

    // -------------------------------------------------------------------------
    // Transpose tests
    // -------------------------------------------------------------------------

    /// Transpose a [2,3] tensor → [3,2] and verify value placement.
    ///
    /// Input row-major:
    ///   [[1,2,3],[4,5,6]]
    /// Transposed (axes=[1,0]):
    ///   [[1,4],[2,5],[3,6]]
    #[tokio::test]
    async fn test_transpose_2d() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);

        let out = backend
            .execute(TensorOp::Transpose { axes: vec![1, 0] }, &[&src])
            .await?;

        assert_eq!(out.descriptor.shape, vec![3, 2]);
        let vals = read_f32_buf(&out);
        assert!((vals[0] - 1.0_f32).abs() < 1e-6_f32, "vals[0]={}", vals[0]);
        assert!((vals[1] - 4.0_f32).abs() < 1e-6_f32, "vals[1]={}", vals[1]);
        assert!((vals[2] - 2.0_f32).abs() < 1e-6_f32, "vals[2]={}", vals[2]);
        assert!((vals[3] - 5.0_f32).abs() < 1e-6_f32, "vals[3]={}", vals[3]);
        assert!((vals[4] - 3.0_f32).abs() < 1e-6_f32, "vals[4]={}", vals[4]);
        assert!((vals[5] - 6.0_f32).abs() < 1e-6_f32, "vals[5]={}", vals[5]);
        Ok(())
    }

    /// Transpose a [2,3,4] tensor with axes [2,0,1] → [4,2,3].
    #[tokio::test]
    async fn test_transpose_3d() -> Result<()> {
        let backend = CpuBackend::new();
        // Flat values 0..24.
        let vals_in: Vec<f32> = (0..24_u32).map(|v| v as f32).collect();
        let src = make_f32_buf(vec![2, 3, 4], &vals_in);

        let out = backend
            .execute(
                TensorOp::Transpose {
                    axes: vec![2, 0, 1],
                },
                &[&src],
            )
            .await?;

        assert_eq!(out.descriptor.shape, vec![4, 2, 3]);
        // Verify total element count is unchanged.
        assert_eq!(out.descriptor.num_elements(), 24);
        // Spot-check: out[0,0,0] = in[0,0,0] = 0.
        // out[1,0,0] corresponds to axes=[2,0,1]: out_coord=(1,0,0)→
        //   in_dim2_coord=1, in_dim0_coord=0, in_dim1_coord=0 → in[0,0,1]=1.
        let out_vals = read_f32_buf(&out);
        assert!((out_vals[0] - 0.0_f32).abs() < 1e-6_f32);
        // out_flat=1 → out_coord=(0,0,1) [shape 4,2,3] →
        //   axes=[2,0,1]: in_dim2=0,in_dim0=0,in_dim1=1 → in[0,1,0]=4.
        assert!(
            (out_vals[1] - 4.0_f32).abs() < 1e-6_f32,
            "out[0,0,1]={} expected 4",
            out_vals[1]
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // GeLU tests
    // -------------------------------------------------------------------------

    /// GELU(0) ≈ 0, GELU(1) ≈ 0.8413, GELU(-1) ≈ -0.1587.
    #[tokio::test]
    async fn test_gelu_basic() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![3], &[0.0, 1.0, -1.0]);

        let out = backend.execute(TensorOp::GeLU, &[&src]).await?;
        assert_eq!(out.descriptor.shape, vec![3]);
        let vals = read_f32_buf(&out);
        assert!(vals[0].abs() < 1e-5_f32, "GELU(0)={}", vals[0]);
        assert!(
            (vals[1] - 0.8413_f32).abs() < 1e-3_f32,
            "GELU(1)={} expected ≈0.8413",
            vals[1]
        );
        assert!(
            (vals[2] - (-0.1587_f32)).abs() < 1e-3_f32,
            "GELU(-1)={} expected ≈-0.1587",
            vals[2]
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Scale tests
    // -------------------------------------------------------------------------

    /// Scale [1,2,3] by 0.5 → [0.5,1.0,1.5].
    #[tokio::test]
    async fn test_scale_basic() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![3], &[1.0, 2.0, 3.0]);

        let out = backend
            .execute(TensorOp::Scale { scalar: 0.5 }, &[&src])
            .await?;
        assert_eq!(out.descriptor.shape, vec![3]);
        let vals = read_f32_buf(&out);
        assert!((vals[0] - 0.5_f32).abs() < 1e-6_f32, "vals[0]={}", vals[0]);
        assert!((vals[1] - 1.0_f32).abs() < 1e-6_f32, "vals[1]={}", vals[1]);
        assert!((vals[2] - 1.5_f32).abs() < 1e-6_f32, "vals[2]={}", vals[2]);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Concat tests
    // -------------------------------------------------------------------------

    /// Concatenate two [2,3] tensors along axis 0 → [4,3].
    #[tokio::test]
    async fn test_concat_axis0() -> Result<()> {
        let backend = CpuBackend::new();
        let a = make_f32_buf(vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let b = make_f32_buf(vec![2, 3], &[7.0, 8.0, 9.0, 10.0, 11.0, 12.0]);

        let out = backend
            .execute(TensorOp::Concat { axis: 0 }, &[&a, &b])
            .await?;
        assert_eq!(out.descriptor.shape, vec![4, 3]);
        let vals = read_f32_buf(&out);
        // First two rows from a, last two from b.
        assert!((vals[0] - 1.0_f32).abs() < 1e-6_f32);
        assert!((vals[3] - 4.0_f32).abs() < 1e-6_f32);
        assert!((vals[6] - 7.0_f32).abs() < 1e-6_f32);
        assert!((vals[9] - 10.0_f32).abs() < 1e-6_f32);
        Ok(())
    }

    /// Concatenate two [2,3] tensors along axis 1 → [2,6].
    #[tokio::test]
    async fn test_concat_axis1() -> Result<()> {
        let backend = CpuBackend::new();
        let a = make_f32_buf(vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let b = make_f32_buf(vec![2, 3], &[7.0, 8.0, 9.0, 10.0, 11.0, 12.0]);

        let out = backend
            .execute(TensorOp::Concat { axis: 1 }, &[&a, &b])
            .await?;
        assert_eq!(out.descriptor.shape, vec![2, 6]);
        let vals = read_f32_buf(&out);
        // Row 0: [1,2,3,7,8,9], row 1: [4,5,6,10,11,12].
        assert!((vals[0] - 1.0_f32).abs() < 1e-6_f32, "vals[0]={}", vals[0]);
        assert!((vals[3] - 7.0_f32).abs() < 1e-6_f32, "vals[3]={}", vals[3]);
        assert!((vals[6] - 4.0_f32).abs() < 1e-6_f32, "vals[6]={}", vals[6]);
        assert!((vals[9] - 10.0_f32).abs() < 1e-6_f32, "vals[9]={}", vals[9]);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // RmsNorm tests
    // -------------------------------------------------------------------------

    /// After RmsNorm, the RMS of each slice should be ≈ 1.
    #[tokio::test]
    async fn test_rms_norm() -> Result<()> {
        let backend = CpuBackend::new();
        let src = make_f32_buf(vec![1, 4], &[1.0, 2.0, 3.0, 4.0]);

        let out = backend
            .execute(TensorOp::RmsNorm { epsilon: 1e-5 }, &[&src])
            .await?;
        assert_eq!(out.descriptor.shape, vec![1, 4]);
        let vals = read_f32_buf(&out);
        // RMS of output slice should be ≈ 1.
        let mean_sq: f32 = vals.iter().map(|v| v * v).sum::<f32>() / 4.0_f32;
        let rms = mean_sq.sqrt();
        assert!((rms - 1.0_f32).abs() < 1e-4_f32, "rms={rms}");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Transformer forward pass smoke test
    // -------------------------------------------------------------------------

    /// Tiny transformer smoke test: verify output shape is [seq_len, vocab_size].
    ///
    /// Uses 2 layers, 2 heads, d_model=8, d_ff=16, vocab_size=16, seq_len=4.
    #[tokio::test]
    async fn test_transformer_forward_smoke() -> Result<()> {
        use crate::transformer::{
            TransformerConfig, TransformerLayerWeights, TransformerWeights, transformer_forward,
        };

        let backend = CpuBackend::new();
        let cfg = TransformerConfig {
            n_layers: 2,
            n_heads: 2,
            d_model: 8,
            d_ff: 16,
            vocab_size: 16,
            max_seq_len: 16,
            rms_norm_eps: 1e-5,
        };

        // Helper: create an F32 buffer filled with a repeating pattern.
        let make_weight = |rows: usize, cols: usize| -> TensorBuffer {
            let n = rows * cols;
            let vals: Vec<f32> = (0..n).map(|i| ((i % 7) as f32) * 0.1 + 0.01).collect();
            make_f32_buf(vec![rows, cols], &vals)
        };
        let make_vec = |size: usize| -> TensorBuffer {
            let vals: Vec<f32> = (0..size).map(|i| ((i % 5) as f32) * 0.1 + 0.01).collect();
            make_f32_buf(vec![size], &vals)
        };

        let layer = || -> TransformerLayerWeights {
            TransformerLayerWeights {
                attn_q: make_weight(cfg.d_model, cfg.d_model),
                attn_k: make_weight(cfg.d_model, cfg.d_model),
                attn_v: make_weight(cfg.d_model, cfg.d_model),
                attn_o: make_weight(cfg.d_model, cfg.d_model),
                ffn_gate: make_weight(cfg.d_model, cfg.d_ff),
                ffn_up: make_weight(cfg.d_model, cfg.d_ff),
                ffn_down: make_weight(cfg.d_ff, cfg.d_model),
                attn_norm: make_vec(cfg.d_model),
                ffn_norm: make_vec(cfg.d_model),
            }
        };

        let weights = TransformerWeights {
            token_embedding: make_weight(cfg.vocab_size, cfg.d_model),
            layers: vec![layer(), layer()],
            output_norm: make_vec(cfg.d_model),
            output_proj: make_weight(cfg.d_model, cfg.vocab_size),
            n_kv_heads: None,
        };

        let seq_len = 4usize;
        let idx_desc = TensorDescriptor::new(vec![seq_len], TensorDtype::U8);
        let input_ids = TensorBuffer::new(idx_desc, vec![0u8, 1, 2, 3]);

        let logits = transformer_forward(&backend, &cfg, &weights, &input_ids).await?;
        assert_eq!(logits.descriptor.shape, vec![seq_len, cfg.vocab_size]);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // SIMD matmul correctness tests
    // -------------------------------------------------------------------------

    /// Run [`exec_matmul`] on the given values and return the flat output.
    ///
    /// Returns `Err` if the matmul fails (e.g. dimension mismatch).
    fn run_matmul(
        a_vals: &[f32],
        a_shape: Vec<usize>,
        b_vals: &[f32],
        b_shape: Vec<usize>,
        transpose_a: bool,
        transpose_b: bool,
    ) -> Result<Vec<f32>> {
        let a_buf = make_f32_buf(a_shape, a_vals);
        let b_buf = make_f32_buf(b_shape, b_vals);
        let out = exec_matmul(&[&a_buf, &b_buf], transpose_a, transpose_b)?;
        Ok(read_f32_buf(&out))
    }

    /// Run [`matmul_scalar`] directly, bypassing any SIMD dispatch.
    ///
    /// Used as the reference result when comparing SIMD output.
    /// Returns `Err` on dimension mismatch.
    fn run_scalar(
        a_vals: &[f32],
        a_shape: Vec<usize>,
        b_vals: &[f32],
        b_shape: Vec<usize>,
        transpose_a: bool,
        transpose_b: bool,
    ) -> Result<Vec<f32>> {
        let a_buf = make_f32_buf(a_shape, a_vals);
        let b_buf = make_f32_buf(b_shape, b_vals);

        // Derive output dimensions (mirrors exec_matmul logic).
        let (rows_out, inner_a) = matmul_effective_dims(&a_buf.descriptor.shape, transpose_a)?;
        let (inner_b, cols_out) = matmul_effective_dims(&b_buf.descriptor.shape, transpose_b)?;
        if inner_a != inner_b {
            return Err(NexaCoreError::hal(
                HalErrorKind::DeviceFailure,
                "run_scalar::inner_dimension_mismatch",
            ));
        }

        let out_desc = TensorDescriptor::new(vec![rows_out, cols_out], TensorDtype::F32);
        let mut out_bytes = vec![0u8; out_desc.byte_size()];

        matmul_scalar(
            a_buf.as_bytes(),
            b_buf.as_bytes(),
            rows_out,
            cols_out,
            inner_a,
            transpose_a,
            transpose_b,
            &mut out_bytes,
        )?;

        // Decode output using the existing helper so indexing lint is avoided.
        let tmp = TensorBuffer::new(out_desc, out_bytes);
        Ok(read_f32_buf(&tmp))
    }

    /// Assert that two `f32` slices are element-wise close within `eps`.
    fn assert_f32_close(got: &[f32], want: &[f32], eps: f32, label: &str) {
        assert_eq!(
            got.len(),
            want.len(),
            "{label}: length mismatch got={} want={}",
            got.len(),
            want.len()
        );
        for (i, (&g, &w)) in got.iter().zip(want.iter()).enumerate() {
            assert!(
                (g - w).abs() <= eps,
                "{label}: element[{i}] got={g} want={w} diff={}",
                (g - w).abs()
            );
        }
    }

    /// 4×4 × 4×4 matmul: SIMD dispatcher result must match scalar within
    /// `1e-3`.  Tests the standard non-transposed path on square matrices
    /// whose inner dimension (4) is a multiple of the SSE4.2 lane width.
    #[test]
    fn matmul_simd_matches_scalar_small() -> Result<()> {
        // Non-trivial values to exercise accumulation paths.
        // i16 → f32 conversion is lossless (i16 range fits within f32 mantissa).
        let a: Vec<f32> = (1_i16..=16).map(f32::from).map(|x| x * 0.5).collect();
        let b: Vec<f32> = (1_i16..=16).map(f32::from).map(|x| x * 0.25).collect();

        let simd = run_matmul(&a, vec![4, 4], &b, vec![4, 4], false, false)?;
        let scalar = run_scalar(&a, vec![4, 4], &b, vec![4, 4], false, false)?;

        assert_f32_close(&simd, &scalar, 1e-3, "4x4 no-transpose");
        Ok(())
    }

    /// 7×5 × 5×3 matmul with non-power-of-2 dimensions.
    ///
    /// Exercises the scalar tail loop: `inner = 5`, so `5 % 8 = 5` elements
    /// remain after the AVX2 vectorised loop, and `5 % 4 = 1` element after
    /// the SSE4.2 vectorised loop.
    #[test]
    fn matmul_simd_matches_scalar_non_aligned() -> Result<()> {
        // Use `mul_add` to avoid the `clippy::float_arithmetic` multiply-then-
        // add pattern.  Values span both positive and negative range.
        // i16 → f32 is lossless; mul_add avoids the float_arithmetic lint.
        let a: Vec<f32> = (0_i16..35)
            .map(|x| f32::from(x).mul_add(0.3, -5.0))
            .collect();
        let b: Vec<f32> = (0_i16..15)
            .map(|x| f32::from(x).mul_add(0.7, 1.0))
            .collect();

        let simd = run_matmul(&a, vec![7, 5], &b, vec![5, 3], false, false)?;
        let scalar = run_scalar(&a, vec![7, 5], &b, vec![5, 3], false, false)?;

        assert_f32_close(&simd, &scalar, 1e-3, "7x5 x 5x3");
        Ok(())
    }

    /// Multiplying any matrix A by the identity matrix I must yield A.
    ///
    /// Verifies that the SIMD dispatcher produces the correct result on the
    /// identity case, where all output elements equal the corresponding input.
    #[test]
    fn matmul_simd_identity() -> Result<()> {
        // 4×4 identity matrix.
        #[rustfmt::skip]
        let identity: Vec<f32> = vec![
            1.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 1.0,
        ];
        let a: Vec<f32> = (1_i16..=16).map(f32::from).collect();

        let result = run_matmul(&a, vec![4, 4], &identity, vec![4, 4], false, false)?;

        assert_f32_close(&result, &a, 1e-3, "A x I = A");
        Ok(())
    }

    /// Multiplying any matrix A by the zero matrix must yield the zero matrix.
    #[test]
    fn matmul_simd_zero() -> Result<()> {
        let a: Vec<f32> = (1_i16..=16).map(f32::from).collect();
        let zero = vec![0.0_f32; 16];

        let result = run_matmul(&a, vec![4, 4], &zero, vec![4, 4], false, false)?;

        let expected = vec![0.0_f32; 16];
        assert_f32_close(&result, &expected, 1e-6, "A x 0 = 0");
        Ok(())
    }

    /// 64×64 × 64×64 matmul using the AVX2 path when available.
    ///
    /// Compares the dispatcher output (which will use AVX2 if the host CPU
    /// supports it) against the scalar reference.  On machines without AVX2
    /// both paths reduce to scalar so the test still passes — the comparison
    /// just verifies the scalar path itself in that case.
    ///
    /// Tolerance is `1e-3` to accommodate FMA3 single-rounding differences
    /// that accumulate over 64 inner-dimension multiplications.
    #[test]
    fn matmul_avx2_large() -> Result<()> {
        let n = 64_usize;
        // Deterministic but varied pattern to stress accumulation.
        // `usize` → `u32` → `f32` avoids `cast_precision_loss` on usize.
        // `i % 13` and `i % 7` always fit in u8; cast to u16 first so
        // `f32::from(u16)` is lossless (u16 range ≤ 65535 < 2^24 mantissa).
        let a: Vec<f32> = (0..n * n)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let v = (i % 13) as u16;
                f32::from(v).mul_add(0.1, -0.6)
            })
            .collect();
        let b: Vec<f32> = (0..n * n)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let v = (i % 7) as u16;
                f32::from(v).mul_add(0.2, 0.05)
            })
            .collect();

        let simd = run_matmul(&a, vec![n, n], &b, vec![n, n], false, false)?;
        let scalar = run_scalar(&a, vec![n, n], &b, vec![n, n], false, false)?;

        assert_f32_close(&simd, &scalar, 1e-3, "64x64 avx2_large");
        Ok(())
    }
}

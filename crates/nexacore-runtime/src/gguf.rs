//! GGUF v3 binary format parser.
//!
//! Implements the GGUF (GPT-Generated Unified Format) binary file format
//! used by llama.cpp and compatible model-distribution tools. The parser
//! reads model metadata and tensor layout information from a raw byte slice
//! without loading tensor data into memory — tensor weights remain in the
//! caller's buffer and are accessed by offset when inference actually runs.
//!
//! ## Format overview
//!
//! A GGUF file consists of, in order:
//!
//! 1. **Header**: 4-byte magic (`"GGUF"` LE), u32 version, u64 tensor count,
//!    u64 metadata KV count.
//! 2. **Metadata KV pairs**: variable-length key–value entries where keys are
//!    length-prefixed UTF-8 strings and values are typed unions.
//! 3. **Tensor info entries**: one entry per tensor carrying name, shape,
//!    data type, and byte offset within the data region.
//! 4. **Alignment padding**: the data region starts at the next multiple of
//!    [`GGUF_DEFAULT_ALIGNMENT`](crate::gguf::GGUF_DEFAULT_ALIGNMENT) after the last tensor info entry.
//! 5. **Tensor data**: contiguous raw bytes for all tensors, each individually
//!    aligned within this region.
//!
//! ## Versions supported
//!
//! GGUF v2 and v3 are accepted. v1 (deprecated in 2023) is rejected.
//!
//! ## Security properties
//!
//! - String lengths are capped at `MAX_STRING_LEN` (1 MiB) to prevent
//!   allocation exhaustion from a malicious file.
//! - Tensor count and metadata KV count are capped at `MAX_TENSOR_COUNT`
//!   (100 000) for the same reason.
//! - No `unsafe` code is used. All slice accesses go through bounds-checked
//!   helpers that return `Err` rather than panic on out-of-bounds.
//!
//! ## References
//!
//! - <https://github.com/ggml-org/ggml/blob/master/docs/gguf.md>
//! - <https://github.com/ggerganov/llama.cpp/blob/master/gguf-py/gguf/constants.py>

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown
)]

// Alloc types: re-exported by std's prelude on host builds, pulled from
// `alloc` when building without std (TASK-13-pre / ADR-0034).
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String, vec::Vec};

use nexacore_types::{NexaCoreError, Result};

// =============================================================================
// Public constants
// =============================================================================

/// GGUF file magic number: the bytes `G`, `G`, `U`, `F` in little-endian
/// order (i.e., stored as `0x46 0x55 0x47 0x47` on disk).
///
/// Validate this is the first four bytes of every GGUF file before
/// attempting further parsing.
pub const GGUF_MAGIC: u32 = 0x4655_4746;

/// Default alignment for the tensor data region in GGUF files, in bytes.
///
/// The data section begins at the next offset that is a multiple of this
/// value after the last tensor info entry. Individual tensor offsets (stored
/// in [`GgufTensorInfo::offset`]) are also multiples of this value relative
/// to the start of the data region.
pub const GGUF_DEFAULT_ALIGNMENT: usize = 32;

/// The GGUF format version supported as primary.
///
/// Version 2 is also accepted for compatibility with older llama.cpp releases.
pub const GGUF_VERSION_3: u32 = 3;

/// Maximum byte length of any single string in a GGUF file (1 MiB).
///
/// This cap prevents a maliciously crafted file from forcing multi-gigabyte
/// heap allocations through a single metadata value or tensor name.
const MAX_STRING_LEN: usize = 1024 * 1024; // 1 MiB

/// Maximum number of tensors or metadata KV pairs in a single GGUF file.
///
/// Real-world models top out well below this; the cap guards against integer
/// overflow in pre-allocation and against iterating a degenerate file.
const MAX_TENSOR_COUNT: u64 = 100_000;

// =============================================================================
// GgufMetadataValue
// =============================================================================

/// A typed metadata value read from a GGUF file's KV section.
///
/// Each variant corresponds directly to a [`GgufMetadataValueType`]
/// discriminant. The `Array` variant is recursive: it may contain any mix
/// of same-type values (the GGUF spec requires all elements of an array to
/// share the same type, but this enum does not enforce that invariant at the
/// type level — the parser enforces it).
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::gguf::GgufMetadataValue;
///
/// let v = GgufMetadataValue::String("llama".to_owned());
/// if let GgufMetadataValue::String(s) = v {
///     assert_eq!(s, "llama");
/// }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub enum GgufMetadataValue {
    /// Unsigned 8-bit integer.
    U8(u8),
    /// Signed 8-bit integer.
    I8(i8),
    /// Unsigned 16-bit integer.
    U16(u16),
    /// Signed 16-bit integer.
    I16(i16),
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Signed 32-bit integer.
    I32(i32),
    /// 32-bit IEEE 754 floating-point number.
    F32(f32),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Signed 64-bit integer.
    I64(i64),
    /// 64-bit IEEE 754 floating-point number.
    F64(f64),
    /// Boolean flag (stored as a single byte: `0x00` = false, anything else = true).
    Bool(bool),
    /// UTF-8 string, length-prefixed (u64), no null terminator.
    String(String),
    /// Homogeneous array of values; length-prefixed by u64 element count.
    Array(Vec<GgufMetadataValue>),
}

// =============================================================================
// GgufMetadataValueType
// =============================================================================

/// Discriminant tags for [`GgufMetadataValue`] variants as stored on disk.
///
/// The u32 value written to the file for each metadata entry's type field
/// must be one of these discriminants. Unknown discriminants cause the parser
/// to return an error.
///
/// Ordering matches the GGUF specification (ggml/docs/gguf.md §MetadataValueType).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GgufMetadataValueType {
    /// Corresponds to [`GgufMetadataValue::U8`].
    U8 = 0,
    /// Corresponds to [`GgufMetadataValue::I8`].
    I8 = 1,
    /// Corresponds to [`GgufMetadataValue::U16`].
    U16 = 2,
    /// Corresponds to [`GgufMetadataValue::I16`].
    I16 = 3,
    /// Corresponds to [`GgufMetadataValue::U32`].
    U32 = 4,
    /// Corresponds to [`GgufMetadataValue::I32`].
    I32 = 5,
    /// Corresponds to [`GgufMetadataValue::F32`].
    F32 = 6,
    /// Corresponds to [`GgufMetadataValue::Bool`].
    Bool = 7,
    /// Corresponds to [`GgufMetadataValue::String`].
    String = 8,
    /// Corresponds to [`GgufMetadataValue::Array`].
    Array = 9,
    /// Corresponds to [`GgufMetadataValue::U64`].
    U64 = 10,
    /// Corresponds to [`GgufMetadataValue::I64`].
    I64 = 11,
    /// Corresponds to [`GgufMetadataValue::F64`].
    F64 = 12,
}

impl GgufMetadataValueType {
    /// Convert a raw u32 discriminant to its typed enum variant.
    ///
    /// Returns `None` if the discriminant is not recognised, which the
    /// caller translates into a parse error.
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::U8),
            1 => Some(Self::I8),
            2 => Some(Self::U16),
            3 => Some(Self::I16),
            4 => Some(Self::U32),
            5 => Some(Self::I32),
            6 => Some(Self::F32),
            7 => Some(Self::Bool),
            8 => Some(Self::String),
            9 => Some(Self::Array),
            10 => Some(Self::U64),
            11 => Some(Self::I64),
            12 => Some(Self::F64),
            _ => None,
        }
    }
}

// =============================================================================
// GgufDtype
// =============================================================================

/// Tensor element data types as encoded in GGUF tensor info entries.
///
/// Discriminant values are fixed by the GGUF specification and must not
/// change across releases. This is a subset of the full GGML type table,
/// covering all formats present in Phase 2 models. Unknown discriminants
/// cause the parser to return an error.
///
/// The k-quant variant names (`Q2_K`, `Q3_K`, etc.) use the canonical GGUF
/// naming convention with underscores. `#[allow(non_camel_case_types)]` is
/// applied because renaming them would diverge from the spec and break
/// interoperability with llama.cpp tooling.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::gguf::GgufDtype;
///
/// let dt = GgufDtype::F32;
/// assert_eq!(dt as u32, 0);
/// ```
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum GgufDtype {
    /// 32-bit IEEE 754 float.
    F32 = 0,
    /// 16-bit IEEE 754 half-precision float.
    F16 = 1,
    /// 4-bit quantisation, scheme 0 (Q4_0).
    Q4_0 = 2,
    /// 4-bit quantisation, scheme 1 (Q4_1).
    Q4_1 = 3,
    /// 5-bit quantisation, scheme 0 (Q5_0).
    Q5_0 = 6,
    /// 5-bit quantisation, scheme 1 (Q5_1).
    Q5_1 = 7,
    /// 8-bit quantisation, scheme 0 (Q8_0).
    Q8_0 = 8,
    /// 8-bit quantisation, scheme 1 (Q8_1).
    Q8_1 = 9,
    /// 2-bit k-quant.
    Q2_K = 10,
    /// 3-bit k-quant.
    Q3_K = 11,
    /// 4-bit k-quant.
    Q4_K = 12,
    /// 5-bit k-quant.
    Q5_K = 13,
    /// 6-bit k-quant.
    Q6_K = 14,
    /// Signed 8-bit integer tensor.
    I8 = 16,
    /// Signed 16-bit integer tensor.
    I16 = 17,
    /// Signed 32-bit integer tensor.
    I32 = 18,
    /// Signed 64-bit integer tensor.
    I64 = 19,
    /// 64-bit double precision float.
    F64 = 20,
    /// Brain float 16 (bfloat16).
    Bf16 = 30,
}

impl GgufDtype {
    /// Convert a raw u32 discriminant (as stored on disk) to a typed variant.
    ///
    /// Returns `None` if the discriminant is not in the Phase 2 supported set,
    /// which the caller converts to a parse error.
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::F32),
            1 => Some(Self::F16),
            2 => Some(Self::Q4_0),
            3 => Some(Self::Q4_1),
            6 => Some(Self::Q5_0),
            7 => Some(Self::Q5_1),
            8 => Some(Self::Q8_0),
            9 => Some(Self::Q8_1),
            10 => Some(Self::Q2_K),
            11 => Some(Self::Q3_K),
            12 => Some(Self::Q4_K),
            13 => Some(Self::Q5_K),
            14 => Some(Self::Q6_K),
            16 => Some(Self::I8),
            17 => Some(Self::I16),
            18 => Some(Self::I32),
            19 => Some(Self::I64),
            20 => Some(Self::F64),
            30 => Some(Self::Bf16),
            _ => None,
        }
    }
}

// =============================================================================
// GgufTensorInfo
// =============================================================================

/// Layout information for a single tensor stored in a GGUF file.
///
/// Carries everything needed to locate tensor data within the file's data
/// region without actually reading that data. The caller uses `offset` plus
/// the data region's start position (available from [`GgufHeader::data_offset`])
/// to memory-map or read the raw weight bytes at inference time.
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::gguf::{GgufDtype, GgufTensorInfo};
///
/// let info = GgufTensorInfo {
///     name: "token_embd.weight".to_owned(),
///     n_dimensions: 2,
///     dimensions: vec![4096, 32000],
///     dtype: GgufDtype::F16,
///     offset: 0,
/// };
/// assert_eq!(info.n_dimensions, 2);
/// assert_eq!(info.dimensions.len(), 2);
/// ```
#[derive(Clone, Debug)]
pub struct GgufTensorInfo {
    /// Fully-qualified tensor name (e.g., `"token_embd.weight"`).
    pub name: String,
    /// Number of dimensions (rank of the tensor).
    pub n_dimensions: u32,
    /// Size of each dimension in elements.
    pub dimensions: Vec<u64>,
    /// Element data type.
    pub dtype: GgufDtype,
    /// Byte offset of this tensor's data within the data region, measured
    /// from the start of the data region (not from the start of the file).
    /// Always a multiple of [`GGUF_DEFAULT_ALIGNMENT`].
    pub offset: u64,
}

// =============================================================================
// GgufHeader
// =============================================================================

/// The parsed header of a GGUF file.
///
/// `GgufHeader` captures all structured information from a GGUF file except
/// the raw tensor weight bytes. It is the primary output of [`parse_gguf`].
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::gguf::{GGUF_MAGIC, GGUF_VERSION_3, parse_gguf};
///
/// // Build a minimal GGUF v3 file: magic + version + 0 tensors + 0 metadata.
/// let mut buf = Vec::new();
/// buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
/// buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
/// buf.extend_from_slice(&0u64.to_le_bytes()); // tensor_count
/// buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count
///
/// let header = parse_gguf(&buf).unwrap();
/// assert_eq!(header.version, 3);
/// assert_eq!(header.tensor_count, 0);
/// assert!(header.metadata.is_empty());
/// assert!(header.tensors.is_empty());
/// ```
#[derive(Clone, Debug)]
pub struct GgufHeader {
    /// GGUF format version (2 or 3).
    pub version: u32,
    /// Number of tensors declared in the file.
    pub tensor_count: u64,
    /// Ordered list of metadata key–value pairs.
    pub metadata: Vec<(String, GgufMetadataValue)>,
    /// Ordered list of tensor layout entries.
    pub tensors: Vec<GgufTensorInfo>,
    /// Byte offset in the source data slice where the tensor data region
    /// begins. All [`GgufTensorInfo::offset`] values are relative to this
    /// position.
    pub data_offset: usize,
}

// =============================================================================
// Public entry point
// =============================================================================

/// Parse a GGUF file from a byte slice.
///
/// Validates the magic number and version, then reads all metadata KV pairs
/// and tensor info entries sequentially. Returns the parsed [`GgufHeader`]
/// which includes the byte offset where tensor data begins. Tensor weight
/// bytes are NOT copied — they remain in `data` and are accessed via
/// [`GgufHeader::data_offset`] + [`GgufTensorInfo::offset`].
///
/// # Security
///
/// - String lengths are capped at 1 MiB (`MAX_STRING_LEN`).
/// - Tensor count and metadata KV count are capped at 100 000 (`MAX_TENSOR_COUNT`).
/// - All reads are bounds-checked; the function never panics on malformed input.
///
/// # Errors
///
/// Returns [`NexaCoreError::Internal`] if:
/// - `data` is too short to contain even the fixed-size header fields.
/// - The magic number does not equal [`GGUF_MAGIC`].
/// - The version is not 2 or 3.
/// - Tensor count or metadata count exceeds `MAX_TENSOR_COUNT`.
/// - Any metadata or tensor field cannot be decoded (truncated data, unknown
///   type discriminant, invalid UTF-8, etc.).
///
/// # Example
///
/// ```rust
/// use nexacore_runtime::gguf::{GGUF_MAGIC, GGUF_VERSION_3, parse_gguf};
///
/// let mut buf = Vec::new();
/// buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
/// buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
/// buf.extend_from_slice(&0u64.to_le_bytes());
/// buf.extend_from_slice(&0u64.to_le_bytes());
///
/// let h = parse_gguf(&buf).unwrap();
/// assert_eq!(h.version, 3);
/// ```
pub fn parse_gguf(data: &[u8]) -> Result<GgufHeader> {
    let mut pos: usize = 0;

    // --- Magic ---
    let magic = read_u32_le(data, &mut pos)?;
    if magic != GGUF_MAGIC {
        return Err(NexaCoreError::internal(
            "gguf::parse — magic mismatch: not a GGUF file",
        ));
    }

    // --- Version ---
    let version = read_u32_le(data, &mut pos)?;
    if version != 2 && version != GGUF_VERSION_3 {
        return Err(NexaCoreError::internal(
            "gguf::parse — unsupported GGUF version (only v2 and v3 accepted)",
        ));
    }

    // --- Counts ---
    let tensor_count = read_u64_le(data, &mut pos)?;
    let metadata_kv_count = read_u64_le(data, &mut pos)?;

    if tensor_count > MAX_TENSOR_COUNT {
        return Err(NexaCoreError::internal(
            "gguf::parse — tensor_count exceeds safety limit",
        ));
    }
    if metadata_kv_count > MAX_TENSOR_COUNT {
        return Err(NexaCoreError::internal(
            "gguf::parse — metadata_kv_count exceeds safety limit",
        ));
    }

    // Pre-allocate with the declared capacity (clamped above).
    let kv_cap = metadata_kv_count as usize;
    let tensor_cap = tensor_count as usize;
    let mut metadata: Vec<(String, GgufMetadataValue)> = Vec::with_capacity(kv_cap);
    let mut tensors: Vec<GgufTensorInfo> = Vec::with_capacity(tensor_cap);

    // --- Metadata KV pairs ---
    for _ in 0..kv_cap {
        let key = read_string(data, &mut pos)?;
        let value = read_metadata_value(data, &mut pos)?;
        metadata.push((key, value));
    }

    // --- Tensor info entries ---
    for _ in 0..tensor_cap {
        let name = read_string(data, &mut pos)?;
        let n_dimensions = read_u32_le(data, &mut pos)?;

        // Guard: GGUF spec allows up to 4 dimensions in practice; we cap at
        // 8 to allow future headroom while preventing malformed files from
        // allocating huge dimension vectors.
        if n_dimensions > 8 {
            return Err(NexaCoreError::internal(
                "gguf::parse — tensor n_dimensions exceeds 8",
            ));
        }

        let mut dimensions: Vec<u64> = Vec::with_capacity(n_dimensions as usize);
        for _ in 0..n_dimensions {
            dimensions.push(read_u64_le(data, &mut pos)?);
        }

        let dtype_raw = read_u32_le(data, &mut pos)?;
        let dtype = GgufDtype::from_u32(dtype_raw).ok_or(NexaCoreError::internal(
            "gguf::parse — unknown GgufDtype discriminant",
        ))?;

        let offset = read_u64_le(data, &mut pos)?;

        tensors.push(GgufTensorInfo {
            name,
            n_dimensions,
            dimensions,
            dtype,
            offset,
        });
    }

    // --- Compute data_offset: align `pos` up to GGUF_DEFAULT_ALIGNMENT ---
    // The data region begins at the first multiple of GGUF_DEFAULT_ALIGNMENT
    // that is >= pos (the byte immediately after the last tensor info entry).
    let data_offset = align_up(pos, GGUF_DEFAULT_ALIGNMENT);

    Ok(GgufHeader {
        version,
        tensor_count,
        metadata,
        tensors,
        data_offset,
    })
}

// =============================================================================
// Private helpers — low-level readers
// =============================================================================

/// Align `value` up to the nearest multiple of `align`.
///
/// `align` must be a power of two; this is guaranteed by the call site which
/// always passes [`GGUF_DEFAULT_ALIGNMENT`] (32 = 2^5).
fn align_up(value: usize, align: usize) -> usize {
    // Fast path for power-of-two alignments using bitwise arithmetic.
    // align - 1 gives a bitmask of the lower bits to zero out.
    (value + align - 1) & !(align - 1)
}

/// Read a single byte from `data` at `*pos`, advancing `*pos` by 1.
fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    let byte = *data.get(*pos).ok_or(NexaCoreError::internal(
        "gguf::parse — unexpected end of data reading u8",
    ))?;
    *pos += 1;
    Ok(byte)
}

/// Read a little-endian u16 from `data` at `*pos`, advancing `*pos` by 2.
fn read_u16_le(data: &[u8], pos: &mut usize) -> Result<u16> {
    let end = pos.checked_add(2).ok_or(NexaCoreError::internal(
        "gguf::parse — position overflow reading u16",
    ))?;
    let bytes: [u8; 2] = data
        .get(*pos..end)
        .ok_or(NexaCoreError::internal(
            "gguf::parse — unexpected end of data reading u16",
        ))?
        .try_into()
        .map_err(|_| {
            NexaCoreError::internal("gguf::parse — slice-to-array conversion failed for u16")
        })?;
    *pos = end;
    Ok(u16::from_le_bytes(bytes))
}

/// Read a little-endian u32 from `data` at `*pos`, advancing `*pos` by 4.
fn read_u32_le(data: &[u8], pos: &mut usize) -> Result<u32> {
    let end = pos.checked_add(4).ok_or(NexaCoreError::internal(
        "gguf::parse — position overflow reading u32",
    ))?;
    let bytes: [u8; 4] = data
        .get(*pos..end)
        .ok_or(NexaCoreError::internal(
            "gguf::parse — unexpected end of data reading u32",
        ))?
        .try_into()
        .map_err(|_| {
            NexaCoreError::internal("gguf::parse — slice-to-array conversion failed for u32")
        })?;
    *pos = end;
    Ok(u32::from_le_bytes(bytes))
}

/// Read a little-endian u64 from `data` at `*pos`, advancing `*pos` by 8.
fn read_u64_le(data: &[u8], pos: &mut usize) -> Result<u64> {
    let end = pos.checked_add(8).ok_or(NexaCoreError::internal(
        "gguf::parse — position overflow reading u64",
    ))?;
    let bytes: [u8; 8] = data
        .get(*pos..end)
        .ok_or(NexaCoreError::internal(
            "gguf::parse — unexpected end of data reading u64",
        ))?
        .try_into()
        .map_err(|_| {
            NexaCoreError::internal("gguf::parse — slice-to-array conversion failed for u64")
        })?;
    *pos = end;
    Ok(u64::from_le_bytes(bytes))
}

/// Read a signed i8 from `data` at `*pos`, advancing `*pos` by 1.
#[allow(dead_code)]
fn read_i8(data: &[u8], pos: &mut usize) -> Result<i8> {
    read_u8(data, pos).map(|v| v as i8)
}

/// Read a little-endian i16 from `data` at `*pos`, advancing `*pos` by 2.
#[allow(dead_code)]
fn read_i16_le(data: &[u8], pos: &mut usize) -> Result<i16> {
    read_u16_le(data, pos).map(|v| v as i16)
}

/// Read a little-endian i32 from `data` at `*pos`, advancing `*pos` by 4.
fn read_i32_le(data: &[u8], pos: &mut usize) -> Result<i32> {
    read_u32_le(data, pos).map(|v| v as i32)
}

/// Read a little-endian i64 from `data` at `*pos`, advancing `*pos` by 8.
fn read_i64_le(data: &[u8], pos: &mut usize) -> Result<i64> {
    read_u64_le(data, pos).map(|v| v as i64)
}

/// Read a little-endian f32 from `data` at `*pos`, advancing `*pos` by 4.
fn read_f32_le(data: &[u8], pos: &mut usize) -> Result<f32> {
    read_u32_le(data, pos).map(f32::from_bits)
}

/// Read a little-endian f64 from `data` at `*pos`, advancing `*pos` by 8.
fn read_f64_le(data: &[u8], pos: &mut usize) -> Result<f64> {
    read_u64_le(data, pos).map(f64::from_bits)
}

/// Read a boolean byte from `data` at `*pos`, advancing `*pos` by 1.
///
/// The GGUF spec treats `0x00` as false and any other byte as true.
fn read_bool(data: &[u8], pos: &mut usize) -> Result<bool> {
    read_u8(data, pos).map(|v| v != 0)
}

/// Read a GGUF length-prefixed string from `data` at `*pos`.
///
/// GGUF strings are encoded as a u64 byte length followed by that many UTF-8
/// bytes with no null terminator. The length is capped at [`MAX_STRING_LEN`]
/// to prevent allocation exhaustion from a malicious file.
///
/// # Errors
///
/// Returns an error if:
/// - Reading the u64 length fails (truncated data).
/// - The length exceeds [`MAX_STRING_LEN`].
/// - The data slice is shorter than the declared length.
/// - The bytes are not valid UTF-8.
fn read_string(data: &[u8], pos: &mut usize) -> Result<String> {
    let len_u64 = read_u64_le(data, pos)?;

    // DoS guard: reject strings that would exceed 1 MiB.
    let len = usize::try_from(len_u64).unwrap_or(usize::MAX);
    if len > MAX_STRING_LEN {
        return Err(NexaCoreError::internal(
            "gguf::parse — string length exceeds 1 MiB safety limit",
        ));
    }

    let end = pos.checked_add(len).ok_or(NexaCoreError::internal(
        "gguf::parse — position overflow reading string bytes",
    ))?;

    let bytes = data.get(*pos..end).ok_or(NexaCoreError::internal(
        "gguf::parse — unexpected end of data reading string bytes",
    ))?;

    let s = core::str::from_utf8(bytes)
        .map_err(|_| NexaCoreError::internal("gguf::parse — string bytes are not valid UTF-8"))?;

    *pos = end;
    Ok(s.to_owned())
}

/// Read a typed metadata value from `data` at `*pos`.
///
/// Reads the u32 type discriminant first, then dispatches to the appropriate
/// scalar or composite reader. For `Array` values the element type is read as
/// a nested u32 discriminant, then all elements are decoded individually.
///
/// # Errors
///
/// Returns an error if the type discriminant is unknown, or if any nested
/// field cannot be decoded.
fn read_metadata_value(data: &[u8], pos: &mut usize) -> Result<GgufMetadataValue> {
    let type_raw = read_u32_le(data, pos)?;
    let vtype = GgufMetadataValueType::from_u32(type_raw).ok_or(NexaCoreError::internal(
        "gguf::parse — unknown GgufMetadataValueType discriminant",
    ))?;

    match vtype {
        GgufMetadataValueType::U8 => read_u8(data, pos).map(GgufMetadataValue::U8),
        GgufMetadataValueType::I8 => read_u8(data, pos).map(|v| GgufMetadataValue::I8(v as i8)),
        GgufMetadataValueType::U16 => read_u16_le(data, pos).map(GgufMetadataValue::U16),
        GgufMetadataValueType::I16 => {
            read_u16_le(data, pos).map(|v| GgufMetadataValue::I16(v as i16))
        }
        GgufMetadataValueType::U32 => read_u32_le(data, pos).map(GgufMetadataValue::U32),
        GgufMetadataValueType::I32 => read_i32_le(data, pos).map(GgufMetadataValue::I32),
        GgufMetadataValueType::F32 => read_f32_le(data, pos).map(GgufMetadataValue::F32),
        GgufMetadataValueType::U64 => read_u64_le(data, pos).map(GgufMetadataValue::U64),
        GgufMetadataValueType::I64 => read_i64_le(data, pos).map(GgufMetadataValue::I64),
        GgufMetadataValueType::F64 => read_f64_le(data, pos).map(GgufMetadataValue::F64),
        GgufMetadataValueType::Bool => read_bool(data, pos).map(GgufMetadataValue::Bool),
        GgufMetadataValueType::String => read_string(data, pos).map(GgufMetadataValue::String),
        GgufMetadataValueType::Array => {
            // Array: element type (u32) + element count (u64) + elements.
            let elem_type_raw = read_u32_le(data, pos)?;
            let elem_type =
                GgufMetadataValueType::from_u32(elem_type_raw).ok_or(NexaCoreError::internal(
                    "gguf::parse — unknown array element GgufMetadataValueType",
                ))?;
            let count_u64 = read_u64_le(data, pos)?;
            // Use the same cap as tensor/metadata counts for array elements.
            if count_u64 > MAX_TENSOR_COUNT {
                return Err(NexaCoreError::internal(
                    "gguf::parse — array element count exceeds safety limit",
                ));
            }
            let count = count_u64 as usize;
            let mut elements: Vec<GgufMetadataValue> = Vec::with_capacity(count);
            for _ in 0..count {
                // Read the value directly using the known element type rather
                // than re-reading the type discriminant per element (array
                // elements in GGUF share a single type tag at the array head).
                let elem = read_value_of_type(data, pos, elem_type)?;
                elements.push(elem);
            }
            Ok(GgufMetadataValue::Array(elements))
        }
    }
}

/// Read a single value of the specified type without re-reading the type tag.
///
/// Used when decoding array elements: in a GGUF array the type is declared
/// once at the array header, not per element. This helper dispatches on the
/// already-decoded `elem_type`.
fn read_value_of_type(
    data: &[u8],
    pos: &mut usize,
    elem_type: GgufMetadataValueType,
) -> Result<GgufMetadataValue> {
    match elem_type {
        GgufMetadataValueType::U8 => read_u8(data, pos).map(GgufMetadataValue::U8),
        GgufMetadataValueType::I8 => read_u8(data, pos).map(|v| GgufMetadataValue::I8(v as i8)),
        GgufMetadataValueType::U16 => read_u16_le(data, pos).map(GgufMetadataValue::U16),
        GgufMetadataValueType::I16 => {
            read_u16_le(data, pos).map(|v| GgufMetadataValue::I16(v as i16))
        }
        GgufMetadataValueType::U32 => read_u32_le(data, pos).map(GgufMetadataValue::U32),
        GgufMetadataValueType::I32 => read_i32_le(data, pos).map(GgufMetadataValue::I32),
        GgufMetadataValueType::F32 => read_f32_le(data, pos).map(GgufMetadataValue::F32),
        GgufMetadataValueType::U64 => read_u64_le(data, pos).map(GgufMetadataValue::U64),
        GgufMetadataValueType::I64 => read_i64_le(data, pos).map(GgufMetadataValue::I64),
        GgufMetadataValueType::F64 => read_f64_le(data, pos).map(GgufMetadataValue::F64),
        GgufMetadataValueType::Bool => read_bool(data, pos).map(GgufMetadataValue::Bool),
        GgufMetadataValueType::String => read_string(data, pos).map(GgufMetadataValue::String),
        // Nested arrays are not supported by the GGUF spec; reject them to
        // avoid unbounded recursion on malicious input.
        GgufMetadataValueType::Array => Err(NexaCoreError::internal(
            "gguf::parse — nested arrays are not permitted by the GGUF spec",
        )),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Builder helpers
    // -------------------------------------------------------------------------

    /// Build a minimal valid GGUF v3 file with 0 tensors and 0 metadata.
    fn minimal_gguf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes()); // magic
        buf.extend_from_slice(&3u32.to_le_bytes()); // version
        buf.extend_from_slice(&0u64.to_le_bytes()); // tensor_count
        buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count
        buf
    }

    /// Encode a GGUF-format string (u64 length prefix + UTF-8 bytes).
    fn gguf_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf
    }

    // -------------------------------------------------------------------------
    // parse_minimal_gguf_succeeds
    // -------------------------------------------------------------------------

    #[test]
    fn parse_minimal_gguf_succeeds() {
        let buf = minimal_gguf();
        let header = parse_gguf(&buf).unwrap();
        assert_eq!(header.version, 3);
        assert_eq!(header.tensor_count, 0);
        assert!(header.metadata.is_empty());
        assert!(header.tensors.is_empty());
        // data_offset must be >= the raw header size (20 bytes), aligned to 32.
        assert_eq!(header.data_offset % GGUF_DEFAULT_ALIGNMENT, 0);
        // With no metadata or tensors the header is exactly 20 bytes;
        // align_up(20, 32) == 32.
        assert_eq!(header.data_offset, 32);
    }

    // -------------------------------------------------------------------------
    // parse_wrong_magic_fails
    // -------------------------------------------------------------------------

    #[test]
    fn parse_wrong_magic_fails() {
        let mut buf = minimal_gguf();
        // Overwrite the magic bytes with garbage.
        buf[0] = 0xDE;
        buf[1] = 0xAD;
        buf[2] = 0xBE;
        buf[3] = 0xEF;
        let err = parse_gguf(&buf).unwrap_err();
        match err {
            NexaCoreError::Internal { context } => {
                assert!(context.contains("magic"), "context: {context}");
            }
            _ => panic!("expected Internal error, got: {err:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // parse_unsupported_version_fails
    // -------------------------------------------------------------------------

    #[test]
    fn parse_unsupported_version_fails() {
        let mut buf = minimal_gguf();
        // Overwrite version field (bytes 4-7) with version 1 (unsupported).
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        let err = parse_gguf(&buf).unwrap_err();
        match err {
            NexaCoreError::Internal { context } => {
                assert!(context.contains("version"), "context: {context}");
            }
            _ => panic!("expected Internal error, got: {err:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // parse_truncated_fails
    // -------------------------------------------------------------------------

    #[test]
    fn parse_truncated_fails() {
        // Empty slice — not even room for the magic number.
        assert!(parse_gguf(&[]).is_err());
        // Partial magic (3 bytes).
        assert!(parse_gguf(&[0x47, 0x47, 0x55]).is_err());
        // Magic + partial version (6 bytes total).
        let mut partial = minimal_gguf();
        partial.truncate(6);
        assert!(parse_gguf(&partial).is_err());
    }

    // -------------------------------------------------------------------------
    // parse_with_metadata
    // -------------------------------------------------------------------------

    #[test]
    fn parse_with_metadata() {
        // Build a GGUF v3 file with one string metadata KV pair:
        // key = "general.architecture", value = "llama"
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes()); // version
        buf.extend_from_slice(&0u64.to_le_bytes()); // tensor_count
        buf.extend_from_slice(&1u64.to_le_bytes()); // metadata_kv_count = 1

        // KV entry: key "general.architecture"
        buf.extend_from_slice(&gguf_string("general.architecture"));
        // Value type = String (8)
        buf.extend_from_slice(&8u32.to_le_bytes());
        // Value
        buf.extend_from_slice(&gguf_string("llama"));

        let header = parse_gguf(&buf).unwrap();
        assert_eq!(header.metadata.len(), 1);
        let (key, val) = &header.metadata[0];
        assert_eq!(key, "general.architecture");
        assert_eq!(*val, GgufMetadataValue::String("llama".to_owned()));
    }

    // -------------------------------------------------------------------------
    // parse_with_tensor_info
    // -------------------------------------------------------------------------

    #[test]
    fn parse_with_tensor_info() {
        // Build a GGUF v3 file with one tensor info entry.
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes()); // version
        buf.extend_from_slice(&1u64.to_le_bytes()); // tensor_count = 1
        buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count = 0

        // Tensor info:
        buf.extend_from_slice(&gguf_string("token_embd.weight")); // name
        buf.extend_from_slice(&2u32.to_le_bytes()); // n_dimensions = 2
        buf.extend_from_slice(&4096u64.to_le_bytes()); // dim[0]
        buf.extend_from_slice(&32000u64.to_le_bytes()); // dim[1]
        buf.extend_from_slice(&1u32.to_le_bytes()); // dtype = F16
        buf.extend_from_slice(&0u64.to_le_bytes()); // offset = 0

        let header = parse_gguf(&buf).unwrap();
        assert_eq!(header.tensor_count, 1);
        assert_eq!(header.tensors.len(), 1);

        let t = &header.tensors[0];
        assert_eq!(t.name, "token_embd.weight");
        assert_eq!(t.n_dimensions, 2);
        assert_eq!(t.dimensions, vec![4096, 32000]);
        assert_eq!(t.dtype, GgufDtype::F16);
        assert_eq!(t.offset, 0);
    }

    // -------------------------------------------------------------------------
    // gguf_dtype_values_match_spec
    // -------------------------------------------------------------------------

    #[test]
    fn gguf_dtype_values_match_spec() {
        // Pin discriminant values to the GGUF specification. Any change to
        // these values is a breaking format incompatibility.
        assert_eq!(GgufDtype::F32 as u32, 0);
        assert_eq!(GgufDtype::F16 as u32, 1);
        assert_eq!(GgufDtype::Q4_0 as u32, 2);
        assert_eq!(GgufDtype::Q4_1 as u32, 3);
        assert_eq!(GgufDtype::Q5_0 as u32, 6);
        assert_eq!(GgufDtype::Q5_1 as u32, 7);
        assert_eq!(GgufDtype::Q8_0 as u32, 8);
        assert_eq!(GgufDtype::Q8_1 as u32, 9);
        assert_eq!(GgufDtype::Q2_K as u32, 10);
        assert_eq!(GgufDtype::Q3_K as u32, 11);
        assert_eq!(GgufDtype::Q4_K as u32, 12);
        assert_eq!(GgufDtype::Q5_K as u32, 13);
        assert_eq!(GgufDtype::Q6_K as u32, 14);
        assert_eq!(GgufDtype::I8 as u32, 16);
        assert_eq!(GgufDtype::I16 as u32, 17);
        assert_eq!(GgufDtype::I32 as u32, 18);
        assert_eq!(GgufDtype::I64 as u32, 19);
        assert_eq!(GgufDtype::F64 as u32, 20);
        assert_eq!(GgufDtype::Bf16 as u32, 30);
    }

    // -------------------------------------------------------------------------
    // parse_v2_succeeds
    // -------------------------------------------------------------------------

    #[test]
    fn parse_v2_succeeds() {
        // Version 2 should be accepted for compatibility.
        let mut buf = minimal_gguf();
        buf[4..8].copy_from_slice(&2u32.to_le_bytes());
        let header = parse_gguf(&buf).unwrap();
        assert_eq!(header.version, 2);
    }

    // -------------------------------------------------------------------------
    // parse_metadata_u32_value
    // -------------------------------------------------------------------------

    #[test]
    fn parse_metadata_u32_value() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes()); // 1 KV entry

        buf.extend_from_slice(&gguf_string("llama.context_length"));
        buf.extend_from_slice(&4u32.to_le_bytes()); // type = U32
        buf.extend_from_slice(&4096u32.to_le_bytes()); // value

        let header = parse_gguf(&buf).unwrap();
        assert_eq!(header.metadata[0].1, GgufMetadataValue::U32(4096));
    }

    // -------------------------------------------------------------------------
    // parse_data_offset_aligned
    // -------------------------------------------------------------------------

    #[test]
    fn parse_data_offset_aligned() {
        // Verify that data_offset is always a multiple of GGUF_DEFAULT_ALIGNMENT
        // regardless of the raw byte count of the preceding sections.
        let buf = minimal_gguf(); // 20 bytes; align_up(20, 32) == 32
        let header = parse_gguf(&buf).unwrap();
        assert_eq!(header.data_offset % GGUF_DEFAULT_ALIGNMENT, 0);
    }
}

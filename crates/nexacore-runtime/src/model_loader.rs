//! Load GGUF model files from the NCFS in-memory filesystem.
//!
//! This module bridges [`nexacore_fs::InMemoryFs`] and the GGUF tensor loader
//! ([`crate::tensor_loader`]). It provides a single-call API that reads a
//! GGUF file from the filesystem, parses the GGUF header, and extracts all
//! tensor weights into [`nexacore_hal::tensor::TensorBuffer`]s.
//!
//! # Typical usage
//!
//! ```rust
//! use nexacore_fs::InMemoryFs;
//! use nexacore_runtime::{
//!     gguf::{GGUF_MAGIC, GGUF_VERSION_3},
//!     model_loader::{load_model_from_fs, write_model_to_fs},
//! };
//!
//! // Build a minimal GGUF blob (empty model, no tensors).
//! let mut gguf_bytes = Vec::<u8>::new();
//! gguf_bytes.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
//! gguf_bytes.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
//! gguf_bytes.extend_from_slice(&0u64.to_le_bytes()); // tensor_count
//! gguf_bytes.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count
//!
//! let mut fs = InMemoryFs::format(256);
//! write_model_to_fs(&mut fs, "/models/test.gguf", &gguf_bytes).unwrap();
//! let loaded = load_model_from_fs(&fs, "/models/test.gguf").unwrap();
//! assert_eq!(loaded.tensors.len(), 0);
//! ```

use nexacore_fs::{FsError, InMemoryFs};
use nexacore_types::{NexaCoreError, Result};

use crate::{
    gguf::GgufHeader,
    tensor_loader::{LoadedTensor, load_all_tensors},
};

// =============================================================================
// LoadedModel
// =============================================================================

/// The result of loading a GGUF model from the filesystem.
///
/// Contains both the parsed header (metadata and tensor layout) and the
/// extracted tensor data buffers.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::InMemoryFs;
/// use nexacore_runtime::{
///     gguf::{GGUF_MAGIC, GGUF_VERSION_3},
///     model_loader::{load_model_from_fs, write_model_to_fs},
/// };
///
/// let mut gguf_bytes = Vec::<u8>::new();
/// gguf_bytes.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
/// gguf_bytes.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
/// gguf_bytes.extend_from_slice(&0u64.to_le_bytes());
/// gguf_bytes.extend_from_slice(&0u64.to_le_bytes());
///
/// let mut fs = InMemoryFs::format(64);
/// write_model_to_fs(&mut fs, "/m.gguf", &gguf_bytes).unwrap();
/// let lm = load_model_from_fs(&fs, "/m.gguf").unwrap();
/// assert_eq!(lm.header.version, 3);
/// assert!(lm.tensors.is_empty());
/// ```
#[derive(Debug)]
pub struct LoadedModel {
    /// Parsed GGUF header containing metadata and tensor layout.
    pub header: GgufHeader,
    /// All tensors extracted from the GGUF file, dequantized to F32 (or I8).
    pub tensors: Vec<LoadedTensor>,
}

// =============================================================================
// load_model_from_fs
// =============================================================================

/// Read a GGUF model file from an [`InMemoryFs`] and load all tensor weights.
///
/// Steps:
/// 1. Verify the file exists via [`InMemoryFs::stat_file`].
/// 2. Read the entire file into memory via [`InMemoryFs::read_file`].
/// 3. Parse the GGUF header with [`crate::gguf::parse_gguf`].
/// 4. Extract and dequantize all tensors with [`load_all_tensors`].
///
/// # Limitations
///
/// [`InMemoryFs::read_file`] takes a `u32` byte count. Files larger than
/// `u32::MAX` bytes (~4 GiB) are rejected with an error. In practice all
/// Phase 2 test models fit comfortably within this limit.
///
/// # Errors
///
/// - [`NexaCoreError::Internal`] if `path` does not exist in the filesystem.
/// - [`NexaCoreError::Internal`] if the file size exceeds `u32::MAX` bytes.
/// - [`NexaCoreError::Internal`] if reading the file fails (filesystem error).
/// - [`NexaCoreError::Internal`] if the file is not a valid GGUF v2/v3 file.
/// - [`NexaCoreError::Internal`] if any tensor extraction or conversion fails.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::InMemoryFs;
/// use nexacore_runtime::{
///     gguf::{GGUF_MAGIC, GGUF_VERSION_3},
///     model_loader::{load_model_from_fs, write_model_to_fs},
/// };
///
/// let mut gguf_bytes = Vec::<u8>::new();
/// gguf_bytes.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
/// gguf_bytes.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
/// gguf_bytes.extend_from_slice(&0u64.to_le_bytes());
/// gguf_bytes.extend_from_slice(&0u64.to_le_bytes());
///
/// let mut fs = InMemoryFs::format(64);
/// write_model_to_fs(&mut fs, "/model.gguf", &gguf_bytes).unwrap();
/// let lm = load_model_from_fs(&fs, "/model.gguf").unwrap();
/// assert_eq!(lm.header.tensor_count, 0);
/// ```
pub fn load_model_from_fs(fs: &InMemoryFs, path: &str) -> Result<LoadedModel> {
    // 1. Verify the file exists and get its size.
    let meta = fs
        .stat_file(path)
        .map_err(|e| fs_err_to_nexacore(e, path))?;

    // Guard: InMemoryFs::read_file uses u32 count. Reject files > 4 GiB.
    let size = u32::try_from(meta.size).map_err(|_| {
        NexaCoreError::internal("model_loader::load_from_fs — file exceeds 4 GiB read limit")
    })?;

    // 2. Read the entire file.
    let bytes = fs
        .read_file(path, 0, size)
        .map_err(|e| fs_err_to_nexacore(e, path))?;

    // 3. Parse the GGUF header.
    let header = crate::gguf::parse_gguf(&bytes)?;

    // 4. Extract and dequantize all tensors.
    let tensors = load_all_tensors(&bytes, &header)?;

    Ok(LoadedModel { header, tensors })
}

// =============================================================================
// write_model_to_fs
// =============================================================================

/// Write a GGUF model byte blob to an [`InMemoryFs`] at the given path.
///
/// Creates the file if it does not already exist. This is a convenience
/// helper for tests that need to populate the filesystem before calling
/// [`load_model_from_fs`].
///
/// # Errors
///
/// - [`NexaCoreError::Internal`] if the file already exists.
/// - [`NexaCoreError::Internal`] if the filesystem has insufficient free blocks.
/// - [`NexaCoreError::Internal`] if the write fails for any other reason.
///
/// # Example
///
/// ```rust
/// use nexacore_fs::InMemoryFs;
/// use nexacore_runtime::model_loader::write_model_to_fs;
///
/// let mut fs = InMemoryFs::format(64);
/// write_model_to_fs(&mut fs, "/test.bin", b"hello").unwrap();
/// assert!(fs.exists("/test.bin"));
/// ```
pub fn write_model_to_fs(fs: &mut InMemoryFs, path: &str, data: &[u8]) -> Result<()> {
    fs.create_file(path)
        .map_err(|e| fs_err_to_nexacore(e, path))?;
    fs.write_file(path, 0, data)
        .map_err(|e| fs_err_to_nexacore(e, path))?;
    Ok(())
}

// =============================================================================
// Private helpers
// =============================================================================

/// Convert an [`FsError`] to an [`NexaCoreError::Internal`].
///
/// Filesystem errors carry no sensitive runtime data, so we embed a static
/// context slug that identifies the call site and the error category.
fn fs_err_to_nexacore(e: FsError, _path: &str) -> NexaCoreError {
    match e {
        FsError::FileNotFound => NexaCoreError::internal("model_loader — file not found in NCFS"),
        FsError::FileAlreadyExists => {
            NexaCoreError::internal("model_loader — file already exists in NCFS")
        }
        FsError::NoSpace => NexaCoreError::internal("model_loader — NCFS volume out of space"),
        FsError::NotAFile => NexaCoreError::internal("model_loader — path is not a regular file"),
        FsError::PathTooLong => NexaCoreError::internal("model_loader — path exceeds MAX_PATH_LEN"),
        _ => NexaCoreError::internal("model_loader — NCFS operation failed"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gguf::{GGUF_DEFAULT_ALIGNMENT, GGUF_MAGIC, GGUF_VERSION_3};

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    fn gguf_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf
    }

    /// Build a minimal GGUF with zero tensors and zero metadata.
    fn minimal_gguf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf
    }

    /// Build a GGUF with two F32 tensors.
    fn two_tensor_gguf() -> Vec<u8> {
        let t1: Vec<u8> = [1.0f32, 2.0f32]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let t2: Vec<u8> = [3.0f32, 4.0f32, 5.0f32]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();

        let mut offsets = [0u64; 2];
        let mut running: u64 = 0;
        for (i, data) in [t1.as_slice(), t2.as_slice()].iter().enumerate() {
            offsets[i] = running;
            let next = running + data.len() as u64;
            running =
                (next + GGUF_DEFAULT_ALIGNMENT as u64 - 1) & !(GGUF_DEFAULT_ALIGNMENT as u64 - 1);
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&GGUF_VERSION_3.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes()); // tensor_count
        buf.extend_from_slice(&0u64.to_le_bytes()); // metadata_kv_count

        // tensor 0
        buf.extend_from_slice(&gguf_string("a"));
        buf.extend_from_slice(&1u32.to_le_bytes()); // n_dimensions
        buf.extend_from_slice(&2u64.to_le_bytes()); // dim[0]
        buf.extend_from_slice(&0u32.to_le_bytes()); // dtype F32
        buf.extend_from_slice(&offsets[0].to_le_bytes());

        // tensor 1
        buf.extend_from_slice(&gguf_string("b"));
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&3u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // dtype F32
        buf.extend_from_slice(&offsets[1].to_le_bytes());

        // Align to data region
        while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
            buf.push(0);
        }
        // tensor data
        buf.extend_from_slice(&t1);
        while buf.len() % GGUF_DEFAULT_ALIGNMENT != 0 {
            buf.push(0);
        }
        buf.extend_from_slice(&t2);
        buf
    }

    // -------------------------------------------------------------------------
    // test_load_model_from_fs
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_model_from_fs() {
        let gguf = two_tensor_gguf();
        let mut fs = InMemoryFs::format(1024);
        write_model_to_fs(&mut fs, "/models/test.gguf", &gguf).unwrap();

        let model = load_model_from_fs(&fs, "/models/test.gguf").unwrap();
        assert_eq!(model.tensors.len(), 2);
        assert_eq!(model.tensors[0].name, "a");
        assert_eq!(model.tensors[0].buffer.descriptor.shape, vec![2]);
        assert_eq!(model.tensors[1].name, "b");
        assert_eq!(model.tensors[1].buffer.descriptor.shape, vec![3]);
    }

    // -------------------------------------------------------------------------
    // test_load_model_not_found
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_model_not_found() {
        let fs = InMemoryFs::format(64);
        let err = load_model_from_fs(&fs, "/nonexistent.gguf").unwrap_err();
        match err {
            NexaCoreError::Internal { context } => {
                assert!(
                    context.contains("not found"),
                    "unexpected context: {context}"
                );
            }
            _ => panic!("expected Internal error, got: {err:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // test_write_model_to_fs_creates_file
    // -------------------------------------------------------------------------

    #[test]
    fn test_write_model_to_fs_creates_file() {
        let mut fs = InMemoryFs::format(64);
        write_model_to_fs(&mut fs, "/m.gguf", b"data").unwrap();
        assert!(fs.exists("/m.gguf"));
    }

    // -------------------------------------------------------------------------
    // test_load_model_empty_tensors
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_model_empty_tensors() {
        let gguf = minimal_gguf();
        let mut fs = InMemoryFs::format(64);
        write_model_to_fs(&mut fs, "/empty.gguf", &gguf).unwrap();
        let model = load_model_from_fs(&fs, "/empty.gguf").unwrap();
        assert!(model.tensors.is_empty());
        assert_eq!(model.header.tensor_count, 0);
    }
}

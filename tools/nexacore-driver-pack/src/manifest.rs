//! JSON manifest schema and deserialization for `nexacore-driver-pack`.
//!
//! The JSON manifest is the **human-authored source format** consumed by
//! `nexacore-driver-pack`. It is never embedded in the `.opack` blob; the
//! blob carries a postcard-encoded [`nexacore_kernel::driver_manifest::DriverManifestBody`]
//! instead.
//!
//! ## JSON manifest schema (example)
//!
//! ```json
//! {
//!   "meta": {
//!     "name": "nexacore-driver-net-virtio",
//!     "version": "0.2.0",
//!     "nexacore_issuer_pubkey": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
//!   },
//!   "capabilities": {
//!     "mmio_regions": [
//!       { "MmioRegion": { "phys_base": 4294967296, "len": 65536 } }
//!     ],
//!     "dma_windows": [
//!       { "DmaWindow": { "iova_base": 0, "len": 4294967296 } }
//!     ],
//!     "irq_lines": [],
//!     "pci_devices": []
//!   },
//!   "matchers": {
//!     "pci_vendor_device": [
//!       { "vendor": 6900, "device": 4161 }
//!     ],
//!     "acpi_hid": []
//!   }
//! }
//! ```
//!
//! ## Canonicalization rules
//!
//! The tool only READS JSON; it does not produce it. The expected input
//! format is:
//!
//! - UTF-8 encoding.
//! - Strict JSON (no comments, no trailing commas).
//! - Integer fields as integers (not `1.0`).
//! - Byte arrays as lowercase hex strings, no `0x` prefix.
//! - [`nexacore_capability::scope::Resource`] variants in serde's default
//!   externally-tagged format (`{"MmioRegion": {"phys_base": …, "len": …}}`).

use nexacore_kernel::driver_manifest::{DriverCapabilities, DriverMatchers};
use serde::Deserialize;

use crate::error::PackError;

// ---------------------------------------------------------------------------
// JSON schema types
// ---------------------------------------------------------------------------

/// The `meta` section of a JSON driver manifest.
///
/// `nexacore_image_hash` and `nexacore_signature` are deliberately absent: the
/// tool computes the image hash from the ELF bytes at pack time and
/// produces the signature itself. They are "filled-by-nexacore-driver-pack"
/// fields per the manifest comments.
#[derive(Debug, Deserialize)]
pub struct ManifestMetaJson {
    /// Short ASCII name used in boot logs and as the IPC channel namespace
    /// root (e.g. `nexacore.driver.<name>.*`).
    pub name: String,
    /// Semantic-version string.
    pub version: String,
    /// Ed25519 issuer verifying key, encoded as a 64-character lowercase
    /// hex string (= 32 raw bytes). This MUST match the verifying key
    /// corresponding to the `--signing-key` seed; the tool validates the
    /// match before producing the `.opack` blob (NCIP-013 § S5.4).
    pub nexacore_issuer_pubkey: String,
}

/// Top-level JSON driver manifest as authored by the driver developer.
///
/// This struct is the source-format type. The tool converts it into a
/// [`nexacore_kernel::driver_manifest::DriverManifestBody`] (postcard-encoded)
/// and signs it with the issuer's Ed25519 key.
///
/// `capabilities` and `matchers` reuse the kernel's serde-derived types
/// directly, which guarantees that the JSON representation matches the
/// postcard wire format the kernel expects (any field rename or
/// variant-order change in the kernel structs will be a compile error here).
#[derive(Debug, Deserialize)]
pub struct PackManifestJson {
    /// Identity fields (name, version, issuer pubkey).
    pub meta: ManifestMetaJson,
    /// Capability declarations the driver requests at `DriverLoad`.
    pub capabilities: DriverCapabilities,
    /// PCI/ACPI match rules for auto-claim.
    pub matchers: DriverMatchers,
}

impl PackManifestJson {
    /// Deserialize a [`PackManifestJson`] from raw JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::ManifestParse`] if the bytes are not valid JSON
    /// or the schema does not match (missing field, wrong type, etc.).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nexacore_driver_pack::manifest::PackManifestJson;
    ///
    /// let json = br#"{"meta":{"name":"test","version":"0.1.0",
    ///     "nexacore_issuer_pubkey":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"},
    ///     "capabilities":{"mmio_regions":[],"dma_windows":[],"irq_lines":[],"pci_devices":[]},
    ///     "matchers":{"pci_vendor_device":[],"acpi_hid":[]}}"#;
    /// let manifest = PackManifestJson::from_json(json, "test.json").unwrap();
    /// assert_eq!(manifest.meta.name, "test");
    /// ```
    pub fn from_json(json_bytes: &[u8], path: &str) -> Result<Self, PackError> {
        serde_json::from_slice(json_bytes).map_err(|source| PackError::ManifestParse {
            path: path.to_string(),
            source,
        })
    }

    /// Deserialize a [`PackManifestJson`] from raw TOML bytes.
    ///
    /// This is the canonical developer-side source format per NCIP-013
    /// § R4 — TOML wins over JSON on native comments, strict schema
    /// (no number-type ambiguity), and a well-audited reference crate
    /// (`toml = "0.8"`).
    ///
    /// The struct shape is the same one the JSON parser populates;
    /// only the wire format differs. The fields use the same serde
    /// attributes (`#[derive(Deserialize)]`) so any divergence between
    /// the two formats is a serde-decoded shape mismatch (caught at
    /// `from_toml` time, not at signing time).
    ///
    /// # Errors
    ///
    /// Returns [`PackError::ManifestParse`] if the bytes are not valid
    /// TOML or the schema does not match (missing field, wrong type,
    /// non-canonical enum variant tag, etc.).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nexacore_driver_pack::manifest::PackManifestJson;
    ///
    /// let toml_src = br#"
    ///     [meta]
    ///     name = "test"
    ///     version = "0.1.0"
    ///     nexacore_issuer_pubkey = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ///     [capabilities]
    ///     mmio_regions = []
    ///     dma_windows = []
    ///     irq_lines = []
    ///     pci_devices = []
    ///     [matchers]
    ///     pci_vendor_device = []
    ///     acpi_hid = []
    /// "#;
    /// let manifest = PackManifestJson::from_toml(toml_src, "test.toml").unwrap();
    /// assert_eq!(manifest.meta.name, "test");
    /// ```
    pub fn from_toml(toml_bytes: &[u8], path: &str) -> Result<Self, PackError> {
        let toml_str =
            core::str::from_utf8(toml_bytes).map_err(|e| PackError::ManifestParseToml {
                path: path.to_string(),
                msg: format!("UTF-8 decode failure: {e}"),
            })?;
        toml::from_str::<Self>(toml_str).map_err(|e| PackError::ManifestParseToml {
            path: path.to_string(),
            msg: e.to_string(),
        })
    }

    /// Auto-dispatch from a file path: parse as TOML if the extension
    /// is `.toml`, else as JSON. The default (no extension / unknown
    /// extension) is JSON for backwards compatibility with the
    /// pre-TOML test fixtures and the CI smoke `test-manifest.json`.
    ///
    /// # Errors
    ///
    /// Propagates [`PackError::ManifestParse`] (JSON path) or
    /// [`PackError::ManifestParseToml`] (TOML path).
    pub fn from_path_bytes(bytes: &[u8], path: &str) -> Result<Self, PackError> {
        let is_toml = std::path::Path::new(path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
        if is_toml {
            Self::from_toml(bytes, path)
        } else {
            Self::from_json(bytes, path)
        }
    }

    /// Decode `meta.nexacore_issuer_pubkey` from its 64-char hex representation
    /// to a 32-byte array.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::InvalidIssuerKeyLen`] if the hex string is not
    /// exactly 64 characters, or [`PackError::IssuerKeyHexDecode`] if it
    /// contains invalid hex digits.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nexacore_driver_pack::manifest::PackManifestJson;
    ///
    /// let json = br#"{"meta":{"name":"test","version":"0.1.0",
    ///     "nexacore_issuer_pubkey":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"},
    ///     "capabilities":{"mmio_regions":[],"dma_windows":[],"irq_lines":[],"pci_devices":[]},
    ///     "matchers":{"pci_vendor_device":[],"acpi_hid":[]}}"#;
    /// let manifest = PackManifestJson::from_json(json, "test.json").unwrap();
    /// let pubkey = manifest.decode_issuer_pubkey().unwrap();
    /// assert_eq!(pubkey.len(), 32);
    /// ```
    pub fn decode_issuer_pubkey(&self) -> Result<[u8; 32], PackError> {
        decode_hex32(&self.meta.nexacore_issuer_pubkey, HexContext::ManifestIssuer)
    }
}

// ---------------------------------------------------------------------------
// Hex decoding helpers
// ---------------------------------------------------------------------------

/// Context tag for the hex decoder — controls which [`PackError`] variant
/// is returned on failure.
#[derive(Clone, Copy)]
pub(crate) enum HexContext {
    /// The `nexacore_issuer_pubkey` field in the JSON manifest.
    ManifestIssuer,
    /// The `--signing-key` seed file.
    SigningKey,
}

/// Decode a 64-character hex string into a 32-byte array.
///
/// Accepts both lowercase (`a–f`) and uppercase (`A–F`) hex digits.
///
/// # Errors
///
/// The error variant produced depends on `ctx`:
/// - [`HexContext::ManifestIssuer`] → [`PackError::InvalidIssuerKeyLen`] /
///   [`PackError::IssuerKeyHexDecode`]
/// - [`HexContext::SigningKey`] → [`PackError::SigningKeyBadLength`] /
///   [`PackError::SigningKeyHexDecode`]
// Index-safety invariants proven at call sites:
// - `s.len() == 64` is enforced by the length guard at the top of the body.
// - `chunks_exact(2)` guarantees each chunk has exactly 2 elements (indices 0/1).
// - `i` runs 0..=31 (32 two-byte chunks of a 64-char string), so `out[i]` is
//   always in bounds for the 32-element output array.
#[allow(clippy::expect_used)] // provable by the invariants above
pub(crate) fn decode_hex32(s: &str, ctx: HexContext) -> Result<[u8; 32], PackError> {
    if s.len() != 64 {
        return Err(match ctx {
            HexContext::ManifestIssuer => PackError::InvalidIssuerKeyLen {
                len: s.len(),
                snippet: s.chars().take(16).collect(),
            },
            HexContext::SigningKey => PackError::SigningKeyBadLength { len: s.len() },
        });
    }

    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        // `chunks_exact(2)` contract: len == 2 always.
        let c0 = *chunk.first().expect("chunks_exact(2): index 0 in bounds");
        let c1 = *chunk.get(1).expect("chunks_exact(2): index 1 in bounds");
        let hi = decode_nibble(c0, i * 2, ctx)?;
        let lo = decode_nibble(c1, i * 2 + 1, ctx)?;
        // `i` is 0..=31 because `s.len()==64` yields exactly 32 two-byte chunks.
        *out.get_mut(i).expect("i < 32 since s.len()==64") = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a single ASCII hex nibble.
///
/// Returns the nibble value (0–15) on success or a [`PackError`] whose
/// variant depends on `ctx`.
fn decode_nibble(c: u8, pos: usize, ctx: HexContext) -> Result<u8, PackError> {
    let v = match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => {
            return Err(match ctx {
                HexContext::ManifestIssuer => PackError::IssuerKeyHexDecode { pos },
                HexContext::SigningKey => PackError::SigningKeyHexDecode { pos },
            });
        }
    };
    Ok(v)
}

/// Encode a byte slice as a lowercase hex string.
///
/// Used for human-readable error messages (e.g. [`PackError::IssuerKeyMismatch`])
/// and exported so the binary entry-point can format keys without pulling in
/// an additional `hex` dependency.
///
/// # Example
///
/// ```
/// use nexacore_driver_pack::manifest::hex_encode;
/// assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
/// ```
///
/// # Index-safety proof
///
/// `b >> 4` is at most `0x0F` (4-bit result); `b & 0x0F` is also at most
/// `0x0F`. Both are always valid indices into the 16-element `HEX` array.
/// The `#[allow(clippy::indexing_slicing)]` below is justified by this proof.
#[allow(clippy::indexing_slicing)] // proven safe: indices are always 0x0..=0xF
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_single_byte() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xFF]), "ff");
        assert_eq!(hex_encode(&[0xAB]), "ab");
    }

    #[test]
    fn hex_encode_multiple_bytes() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn decode_hex32_valid_lowercase() {
        let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let result = decode_hex32(hex, HexContext::ManifestIssuer).unwrap();
        assert_eq!(result[0], 0x9D);
        assert_eq!(result[31], 0x60);
    }

    #[test]
    fn decode_hex32_valid_uppercase() {
        let hex = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
        let result = decode_hex32(hex, HexContext::ManifestIssuer).unwrap();
        assert_eq!(result[0], 0x9D);
    }

    #[test]
    fn decode_hex32_rejects_short_string() {
        let hex = "9d61b19d";
        let err = decode_hex32(hex, HexContext::ManifestIssuer).unwrap_err();
        assert!(matches!(err, PackError::InvalidIssuerKeyLen { len: 8, .. }));
    }

    #[test]
    fn decode_hex32_rejects_invalid_char() {
        let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7fXX";
        let err = decode_hex32(hex, HexContext::ManifestIssuer).unwrap_err();
        assert!(matches!(err, PackError::IssuerKeyHexDecode { .. }));
    }

    #[test]
    fn from_json_parses_minimal_manifest() {
        let json = br#"{
            "meta": {
                "name": "test-driver",
                "version": "0.1.0",
                "nexacore_issuer_pubkey": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
            },
            "capabilities": {
                "mmio_regions": [],
                "dma_windows": [],
                "irq_lines": [],
                "pci_devices": []
            },
            "matchers": {
                "pci_vendor_device": [],
                "acpi_hid": []
            }
        }"#;
        let m = PackManifestJson::from_json(json, "test.json").unwrap();
        assert_eq!(m.meta.name, "test-driver");
        assert_eq!(m.meta.version, "0.1.0");
    }

    #[test]
    fn from_json_rejects_missing_field() {
        let json = br#"{"meta": {"name": "x"}}"#;
        let err = PackManifestJson::from_json(json, "bad.json");
        assert!(err.is_err());
    }

    #[test]
    fn from_toml_parses_minimal_manifest() {
        let toml_src = br#"
            [meta]
            name = "test-driver"
            version = "0.1.0"
            nexacore_issuer_pubkey = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
            [capabilities]
            mmio_regions = []
            dma_windows = []
            irq_lines = []
            pci_devices = []
            [matchers]
            pci_vendor_device = []
            acpi_hid = []
        "#;
        let m = PackManifestJson::from_toml(toml_src, "test.toml").unwrap();
        assert_eq!(m.meta.name, "test-driver");
    }

    #[test]
    fn from_path_bytes_dispatches_on_extension() {
        let json = br#"{
            "meta": {"name": "json-driver", "version": "0.1.0",
                "nexacore_issuer_pubkey": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"},
            "capabilities": {"mmio_regions": [], "dma_windows": [], "irq_lines": [], "pci_devices": []},
            "matchers": {"pci_vendor_device": [], "acpi_hid": []}
        }"#;
        let m = PackManifestJson::from_path_bytes(json, "driver.json").unwrap();
        assert_eq!(m.meta.name, "json-driver");
    }

    #[test]
    fn decode_issuer_pubkey_returns_32_bytes() {
        let json = br#"{
            "meta": {"name": "t", "version": "0.1.0",
                "nexacore_issuer_pubkey": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"},
            "capabilities": {"mmio_regions": [], "dma_windows": [], "irq_lines": [], "pci_devices": []},
            "matchers": {"pci_vendor_device": [], "acpi_hid": []}
        }"#;
        let m = PackManifestJson::from_json(json, "t.json").unwrap();
        let pk = m.decode_issuer_pubkey().unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(pk[0], 0x9D);
    }

    #[test]
    fn hex_encode_round_trips_with_decode_hex32() {
        let original = [0xCA; 32];
        let hex = hex_encode(&original);
        let decoded = decode_hex32(&hex, HexContext::ManifestIssuer).unwrap();
        assert_eq!(decoded, original);
    }
}

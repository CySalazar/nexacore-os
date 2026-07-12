//! Downloadable, signed monolingual NER language-pack format (WS5-12.1).
//!
//! A NER language pack bundles one monolingual, on-device Named Entity
//! Recognition encoder model together with the metadata needed to route to
//! it (WS5-12.2 language identification), gate it by policy (WS5-12.7), and
//! attest it (WS5-04 model signing). This module defines only the **format**:
//!
//! - [`NerPackManifest`] — the self-describing metadata header.
//! - [`NerPack`] — the manifest plus an opaque encoder-model byte blob.
//!
//! Lazy loading (WS5-12.3) and pipeline inference (WS5-12.4) are follow-ups
//! that consume this format; they are out of scope here.
//!
//! # On-wire layout
//!
//! Both types have a deterministic, length-prefixed, self-describing binary
//! encoding produced by [`NerPackManifest::encode`] / [`NerPack::encode`] and
//! parsed by the matching `decode`. Every multi-byte integer is **big-endian**
//! (network order); every variable-length field is preceded by its length.
//! Encoding is a pure function of the value, so `encode` round-trips
//! byte-for-byte.
//!
//! A manifest is framed as:
//!
//! ```text
//! magic[8]="NCNERMAN" | format_version:u16 | language:str
//! | pack_version(major:u16, minor:u16, patch:u16)
//! | model_kind(tag:u8 [, slug:str])
//! | measure(kind:u8, value_milli:u16)
//! | max_input_len:u32
//! | label_set(count:u32, label:str …)
//! | model_hash[32] | signature[64] | signing_key[32]
//! ```
//!
//! where `str` is `len:u32` big-endian followed by that many UTF-8 bytes. A
//! pack is framed as `magic[8]="NCNERPAK" | format_version:u16 |
//! manifest_len:u64 | manifest_bytes | blob_len:u64 | blob_bytes`.
//!
//! # Fail-closed validation
//!
//! Decoding rejects, without partial results, any input with a bad magic,
//! an unsupported format version, a truncated or over-long length prefix
//! (size overflow), a non-well-formed BCP-47 language tag, an out-of-range
//! per-mille measure, an unknown enum discriminant, invalid UTF-8, or an
//! invalid Ed25519 verifying key. Trailing bytes after a complete record are
//! also rejected. See [`PackError`].
//!
//! # Floats are forbidden
//!
//! Following the crate convention (see [`crate::langid`]), the recall/measure
//! reference is a fixed-point per-mille integer in `0..=1000`, never a float.

use nexacore_crypto::signing::{
    NexaCoreSignature, NexaCoreVerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// BLAKE3 digest length, in bytes (mirrors the WS5-04 model-signing scheme).
const MODEL_HASH_LEN: usize = 32;

/// Magic prefix of an encoded [`NerPackManifest`].
const MANIFEST_MAGIC: [u8; 8] = *b"NCNERMAN";

/// Magic prefix of an encoded [`NerPack`].
const PACK_MAGIC: [u8; 8] = *b"NCNERPAK";

/// On-wire format version understood by this build. Bumping it is a
/// wire-breaking change; older decoders reject a newer version fail-closed.
const FORMAT_VERSION: u16 = 1;

/// Largest per-mille value a [`MeasureRef`] may carry (`100.0%`).
const MAX_PER_MILLE: u16 = 1000;

// Model-kind discriminants (wire-stable).
const KIND_GLINER: u8 = 0;
const KIND_TOKEN_CLASSIFIER: u8 = 1;
const KIND_CUSTOM: u8 = 255;

// Measure-kind discriminants (wire-stable).
const MEASURE_RECALL: u8 = 0;
const MEASURE_PRECISION: u8 = 1;
const MEASURE_F1: u8 = 2;

// =============================================================================
// PackError
// =============================================================================

/// Reason an NER language pack failed to encode or decode.
///
/// Every decode failure is fail-closed: no partially-parsed value is ever
/// returned alongside an error.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackError {
    /// The leading magic bytes did not match the expected record type.
    #[error("bad magic: expected {expected:?}, found {found:?}")]
    BadMagic {
        /// The magic this decoder requires.
        expected: [u8; 8],
        /// The magic actually found at the start of the input.
        found: [u8; 8],
    },

    /// The framed format version is not understood by this build.
    #[error("unsupported format version {found} (this build understands {supported})")]
    UnsupportedVersion {
        /// The version read from the input.
        found: u16,
        /// The single version this build can decode.
        supported: u16,
    },

    /// The input ended before a fixed-size field could be read.
    #[error("truncated input at offset {offset}: needed {needed} more byte(s)")]
    Truncated {
        /// Byte offset at which the read was attempted.
        offset: usize,
        /// How many more bytes were required.
        needed: usize,
    },

    /// A length prefix declared more bytes than remain in the input.
    #[error("length {length} overflows the {remaining}-byte remainder")]
    LengthOverflow {
        /// The declared length.
        length: u64,
        /// Bytes actually remaining when the length was read.
        remaining: usize,
    },

    /// A value was too large to serialize into its length prefix.
    #[error("value too large to encode: {0}")]
    EncodeOverflow(&'static str),

    /// Extra bytes remained after a complete record was parsed.
    #[error("{0} trailing byte(s) after a complete record")]
    TrailingBytes(usize),

    /// The language tag is not a well-formed BCP-47 tag.
    #[error("invalid BCP-47 language tag: {0:?}")]
    BadLanguageTag(String),

    /// A per-mille measure exceeded `MAX_PER_MILLE`.
    #[error("per-mille measure {0} exceeds 1000")]
    MeasureOutOfRange(u16),

    /// An enum discriminant did not match any known variant.
    #[error("unknown {field} discriminant {value}")]
    UnknownDiscriminant {
        /// The field whose discriminant was unknown.
        field: &'static str,
        /// The unrecognized discriminant byte.
        value: u8,
    },

    /// A length-prefixed string was not valid UTF-8.
    #[error("invalid UTF-8 in {0}")]
    BadUtf8(&'static str),

    /// The embedded signing key was not a valid Ed25519 point.
    #[error("invalid model signing key")]
    BadVerifyingKey,
}

/// Result alias for pack (de)serialization.
pub type PackResult<T> = Result<T, PackError>;

// =============================================================================
// PackVersion
// =============================================================================

/// Semantic version of a language pack (independent of the model weights).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackVersion {
    /// Breaking-change component.
    pub major: u16,
    /// Backward-compatible feature component.
    pub minor: u16,
    /// Backward-compatible fix component.
    pub patch: u16,
}

// =============================================================================
// NerModelKind
// =============================================================================

/// Architecture family of the encoder model carried by a pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NerModelKind {
    /// A GLiNER-class encoder token-classifier (label/span matching without a
    /// fixed output head).
    GlinerClass,
    /// A generic encoder token-classifier with a fixed label head.
    TokenClassifierEncoder,
    /// A deployment-specific architecture identified by a stable slug.
    Custom(String),
}

// =============================================================================
// MeasureKind / MeasureRef
// =============================================================================

/// Which retrieval-quality statistic a [`MeasureRef`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MeasureKind {
    /// Recall (share of true entities recovered).
    Recall,
    /// Precision (share of predicted entities that are correct).
    Precision,
    /// Harmonic mean of precision and recall.
    F1,
}

/// A reference quality figure for the packed model, as fixed-point per-mille.
///
/// The crate forbids floating point (see [`crate::langid`]); `value_milli` is
/// an integer in `0..=1000` where `1000` means `100.0%`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasureRef {
    /// The statistic reported.
    pub kind: MeasureKind,
    /// The value in per-mille (`0..=1000`).
    pub value_milli: u16,
}

// =============================================================================
// ModelSignatureRef
// =============================================================================

/// The WS5-04 model signature carried by a pack, by field.
///
/// This mirrors the signed fields of `nexacore_runtime`'s `ModelManifest`:
/// an Ed25519 `signature` over the BLAKE3 `model_hash` of the encoder blob,
/// verifiable against `signing_key`. This module **carries** these fields;
/// it does not sign or verify — that is the runtime's responsibility at load
/// time (WS5-12.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSignatureRef {
    /// BLAKE3 hash of the encoder-model blob. The signature covers this field.
    pub model_hash: [u8; MODEL_HASH_LEN],
    /// Ed25519 signature over `model_hash` (WS5-04 model-signing scheme).
    pub signature: NexaCoreSignature,
    /// Ed25519 public key whose private half produced `signature`.
    pub signing_key: NexaCoreVerifyingKey,
}

// =============================================================================
// NerPackManifest
// =============================================================================

/// Self-describing metadata header of a NER language pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NerPackManifest {
    /// BCP-47 language tag the pack covers (e.g. `en`, `pt-BR`, `zh-Hant`).
    pub language: String,
    /// Semantic version of the pack.
    pub pack_version: PackVersion,
    /// Architecture family of the encoder model.
    pub model_kind: NerModelKind,
    /// Reference quality figure (fixed-point per-mille).
    pub measure: MeasureRef,
    /// Maximum input length, in bytes, the model accepts.
    pub max_input_len: u32,
    /// The entity labels the model can emit (e.g. `PER`, `ORG`, `LOC`).
    pub label_set: Vec<String>,
    /// The WS5-04 model signature, by field.
    pub model_signature: ModelSignatureRef,
}

impl NerPackManifest {
    /// Serialize the manifest to its deterministic on-wire byte layout.
    ///
    /// # Errors
    ///
    /// Returns [`PackError::BadLanguageTag`] for a non-well-formed language
    /// tag, [`PackError::MeasureOutOfRange`] for a per-mille measure above
    /// `1000`, or [`PackError::EncodeOverflow`] if a length exceeds its prefix.
    pub fn encode(&self) -> PackResult<Vec<u8>> {
        // Validate before writing so a bad manifest never produces bytes.
        if !is_well_formed_bcp47(&self.language) {
            return Err(PackError::BadLanguageTag(self.language.clone()));
        }
        if self.measure.value_milli > MAX_PER_MILLE {
            return Err(PackError::MeasureOutOfRange(self.measure.value_milli));
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(&MANIFEST_MAGIC);
        put_u16(&mut buf, FORMAT_VERSION);
        put_str(&mut buf, &self.language)?;

        put_u16(&mut buf, self.pack_version.major);
        put_u16(&mut buf, self.pack_version.minor);
        put_u16(&mut buf, self.pack_version.patch);

        match &self.model_kind {
            NerModelKind::GlinerClass => buf.push(KIND_GLINER),
            NerModelKind::TokenClassifierEncoder => buf.push(KIND_TOKEN_CLASSIFIER),
            NerModelKind::Custom(slug) => {
                buf.push(KIND_CUSTOM);
                put_str(&mut buf, slug)?;
            }
        }

        buf.push(match self.measure.kind {
            MeasureKind::Recall => MEASURE_RECALL,
            MeasureKind::Precision => MEASURE_PRECISION,
            MeasureKind::F1 => MEASURE_F1,
        });
        put_u16(&mut buf, self.measure.value_milli);

        put_u32(&mut buf, self.max_input_len);

        let label_count = u32::try_from(self.label_set.len())
            .map_err(|_| PackError::EncodeOverflow("label count"))?;
        put_u32(&mut buf, label_count);
        for label in &self.label_set {
            put_str(&mut buf, label)?;
        }

        buf.extend_from_slice(&self.model_signature.model_hash);
        buf.extend_from_slice(&self.model_signature.signature.to_bytes());
        buf.extend_from_slice(&self.model_signature.signing_key.as_bytes());

        Ok(buf)
    }

    /// Parse a manifest from its on-wire byte layout, fail-closed.
    ///
    /// # Errors
    ///
    /// Returns a [`PackError`] describing the first validation failure.
    pub fn decode(bytes: &[u8]) -> PackResult<Self> {
        let mut r = Reader::new(bytes);
        let manifest = Self::decode_body(&mut r)?;
        r.finish()?;
        Ok(manifest)
    }

    /// Decode the manifest fields from `r`, leaving any trailing-byte check to
    /// the caller (so a pack can decode a manifest embedded in a larger frame).
    fn decode_body(r: &mut Reader<'_>) -> PackResult<Self> {
        let magic = r.array::<8>()?;
        if magic != MANIFEST_MAGIC {
            return Err(PackError::BadMagic {
                expected: MANIFEST_MAGIC,
                found: magic,
            });
        }
        let version = r.u16()?;
        if version != FORMAT_VERSION {
            return Err(PackError::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            });
        }

        let language = r.string("language")?;
        if !is_well_formed_bcp47(&language) {
            return Err(PackError::BadLanguageTag(language));
        }

        let pack_version = PackVersion {
            major: r.u16()?,
            minor: r.u16()?,
            patch: r.u16()?,
        };

        let model_kind = match r.u8()? {
            KIND_GLINER => NerModelKind::GlinerClass,
            KIND_TOKEN_CLASSIFIER => NerModelKind::TokenClassifierEncoder,
            KIND_CUSTOM => NerModelKind::Custom(r.string("model_kind slug")?),
            other => {
                return Err(PackError::UnknownDiscriminant {
                    field: "model_kind",
                    value: other,
                });
            }
        };

        let measure_kind = match r.u8()? {
            MEASURE_RECALL => MeasureKind::Recall,
            MEASURE_PRECISION => MeasureKind::Precision,
            MEASURE_F1 => MeasureKind::F1,
            other => {
                return Err(PackError::UnknownDiscriminant {
                    field: "measure_kind",
                    value: other,
                });
            }
        };
        let value_milli = r.u16()?;
        if value_milli > MAX_PER_MILLE {
            return Err(PackError::MeasureOutOfRange(value_milli));
        }
        let measure = MeasureRef {
            kind: measure_kind,
            value_milli,
        };

        let max_input_len = r.u32()?;

        let label_count = usize_from_u32(r.u32()?);
        // Each label is at least a 4-byte length prefix, so the count can never
        // exceed the remaining bytes — reject an over-long count fail-closed
        // before allocating.
        if label_count > r.remaining() {
            return Err(PackError::LengthOverflow {
                length: u64::from(u32::try_from(label_count).unwrap_or(u32::MAX)),
                remaining: r.remaining(),
            });
        }
        let mut label_set = Vec::new();
        for _ in 0..label_count {
            label_set.push(r.string("label")?);
        }

        let model_hash = r.array::<MODEL_HASH_LEN>()?;
        let signature = NexaCoreSignature::from_bytes(r.array::<SIGNATURE_LEN>()?);
        let signing_key = NexaCoreVerifyingKey::from_bytes(&r.array::<VERIFYING_KEY_LEN>()?)
            .map_err(|_| PackError::BadVerifyingKey)?;

        Ok(Self {
            language,
            pack_version,
            model_kind,
            measure,
            max_input_len,
            label_set,
            model_signature: ModelSignatureRef {
                model_hash,
                signature,
                signing_key,
            },
        })
    }
}

// =============================================================================
// NerPack
// =============================================================================

/// A NER language pack: its [`NerPackManifest`] plus the opaque encoder blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NerPack {
    /// The pack metadata header.
    pub manifest: NerPackManifest,
    /// The opaque encoder-model bytes (format described by `manifest.model_kind`).
    pub model_blob: Vec<u8>,
}

impl NerPack {
    /// Serialize the pack to its deterministic on-wire byte layout.
    ///
    /// # Errors
    ///
    /// Propagates any [`NerPackManifest::encode`] error, or returns
    /// [`PackError::EncodeOverflow`] if a length exceeds its prefix.
    pub fn encode(&self) -> PackResult<Vec<u8>> {
        let manifest_bytes = self.manifest.encode()?;

        let mut buf = Vec::new();
        buf.extend_from_slice(&PACK_MAGIC);
        put_u16(&mut buf, FORMAT_VERSION);

        let manifest_len = u64::try_from(manifest_bytes.len())
            .map_err(|_| PackError::EncodeOverflow("manifest length"))?;
        put_u64(&mut buf, manifest_len);
        buf.extend_from_slice(&manifest_bytes);

        let blob_len = u64::try_from(self.model_blob.len())
            .map_err(|_| PackError::EncodeOverflow("model blob length"))?;
        put_u64(&mut buf, blob_len);
        buf.extend_from_slice(&self.model_blob);

        Ok(buf)
    }

    /// Parse a pack from its on-wire byte layout, fail-closed.
    ///
    /// # Errors
    ///
    /// Returns a [`PackError`] describing the first validation failure.
    pub fn decode(bytes: &[u8]) -> PackResult<Self> {
        let mut r = Reader::new(bytes);

        let magic = r.array::<8>()?;
        if magic != PACK_MAGIC {
            return Err(PackError::BadMagic {
                expected: PACK_MAGIC,
                found: magic,
            });
        }
        let version = r.u16()?;
        if version != FORMAT_VERSION {
            return Err(PackError::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            });
        }

        let manifest_len = r.length_within()?;
        let manifest_bytes = r.take(manifest_len)?;
        // The embedded manifest frame must be consumed exactly; NerPackManifest
        // ::decode enforces no trailing bytes within that slice.
        let manifest = NerPackManifest::decode(manifest_bytes)?;

        let blob_len = r.length_within()?;
        let model_blob = r.take(blob_len)?.to_vec();

        r.finish()?;

        Ok(Self {
            manifest,
            model_blob,
        })
    }
}

// =============================================================================
// Wire helpers
// =============================================================================

/// Append a big-endian `u16`.
fn put_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Append a big-endian `u32`.
fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Append a big-endian `u64`.
fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Append a `u32` length prefix followed by the UTF-8 bytes of `s`.
///
/// # Errors
///
/// [`PackError::EncodeOverflow`] if `s` is longer than [`u32::MAX`] bytes.
fn put_str(buf: &mut Vec<u8>, s: &str) -> PackResult<()> {
    let len = u32::try_from(s.len()).map_err(|_| PackError::EncodeOverflow("string length"))?;
    put_u32(buf, len);
    buf.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Widen a `u32` to `usize` (always lossless on supported targets).
fn usize_from_u32(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// A forward-only, bounds-checked cursor over an encoded record.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap `buf` with the cursor at the start.
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Consume exactly `n` bytes, or fail closed if fewer remain.
    fn take(&mut self, n: usize) -> PackResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| PackError::LengthOverflow {
                length: u64::try_from(n).unwrap_or(u64::MAX),
                remaining: self.remaining(),
            })?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| PackError::Truncated {
                offset: self.pos,
                needed: end.saturating_sub(self.buf.len()),
            })?;
        self.pos = end;
        Ok(slice)
    }

    /// Consume a fixed-size `[u8; N]` array.
    fn array<const N: usize>(&mut self) -> PackResult<[u8; N]> {
        let slice = self.take(N)?;
        // `take` guarantees `slice.len() == N`, so this conversion cannot fail;
        // map the impossible error to a fail-closed truncation just in case.
        slice.try_into().map_err(|_| PackError::Truncated {
            offset: self.pos,
            needed: 0,
        })
    }

    /// Consume a big-endian `u8`.
    fn u8(&mut self) -> PackResult<u8> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    /// Consume a big-endian `u16`.
    fn u16(&mut self) -> PackResult<u16> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    /// Consume a big-endian `u32`.
    fn u32(&mut self) -> PackResult<u32> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    /// Consume a big-endian `u64`.
    fn u64(&mut self) -> PackResult<u64> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    /// Read a `u64` length prefix and reject it if it exceeds the bytes that
    /// remain (size-overflow guard), returning it as a `usize`.
    fn length_within(&mut self) -> PackResult<usize> {
        let declared = self.u64()?;
        let remaining = self.remaining();
        match usize::try_from(declared) {
            Ok(len) if len <= remaining => Ok(len),
            _ => Err(PackError::LengthOverflow {
                length: declared,
                remaining,
            }),
        }
    }

    /// Read a `u32`-length-prefixed UTF-8 string, fail-closed.
    fn string(&mut self, field: &'static str) -> PackResult<String> {
        let declared = self.u32()?;
        let len = usize_from_u32(declared);
        if len > self.remaining() {
            return Err(PackError::LengthOverflow {
                length: u64::from(declared),
                remaining: self.remaining(),
            });
        }
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| PackError::BadUtf8(field))
    }

    /// Fail if any bytes remain after a complete record.
    fn finish(&self) -> PackResult<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(PackError::TrailingBytes(self.remaining()))
        }
    }
}

// =============================================================================
// BCP-47 well-formedness
// =============================================================================

/// Whether `tag` is a well-formed BCP-47 language tag.
///
/// This is a pragmatic well-formedness check, not full IANA-registry
/// validation: a non-empty, ASCII, `-`-separated sequence of 1–8 alphanumeric
/// subtags whose first (primary language) subtag is 2–8 ASCII letters. It
/// accepts `en`, `en-US`, `pt-BR`, `zh-Hant`, `de-CH-1901`; it rejects the
/// empty string, `en_US`, `e`, tags with spaces, and any subtag over 8 chars.
#[must_use]
fn is_well_formed_bcp47(tag: &str) -> bool {
    // A well-formed tag is ASCII, non-empty, and made of `-`-separated
    // subtags. Guard total length to keep the check cheap and bounded.
    if tag.is_empty() || tag.len() > 64 || !tag.is_ascii() {
        return false;
    }

    let mut subtags = tag.split('-');

    // Primary language subtag: 2–8 ASCII letters.
    let Some(primary) = subtags.next() else {
        return false;
    };
    if !(2..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }

    // Every remaining subtag: 1–8 ASCII alphanumerics.
    subtags
        .all(|sub| (1..=8).contains(&sub.len()) && sub.bytes().all(|b| b.is_ascii_alphanumeric()))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use nexacore_crypto::signing::NexaCoreSigningKey;

    use super::*;

    fn sample_manifest() -> NerPackManifest {
        let sk = NexaCoreSigningKey::from_bytes([0xAA; 32]);
        let signing_key = sk.verifying_key();
        let signature = NexaCoreSignature::from_bytes([7u8; SIGNATURE_LEN]);
        NerPackManifest {
            language: "pt-BR".to_string(),
            pack_version: PackVersion {
                major: 1,
                minor: 2,
                patch: 3,
            },
            model_kind: NerModelKind::GlinerClass,
            measure: MeasureRef {
                kind: MeasureKind::Recall,
                value_milli: 923,
            },
            max_input_len: 512,
            label_set: vec!["PER".to_string(), "ORG".to_string(), "LOC".to_string()],
            model_signature: ModelSignatureRef {
                model_hash: [0x11; MODEL_HASH_LEN],
                signature,
                signing_key,
            },
        }
    }

    fn sample_pack() -> NerPack {
        NerPack {
            manifest: sample_manifest(),
            model_blob: (0u16..600)
                .map(|n| u8::try_from(n % 256).unwrap_or(0))
                .collect(),
        }
    }

    // ---- Round-trip -------------------------------------------------------

    #[test]
    fn manifest_round_trips_byte_for_byte() {
        let m = sample_manifest();
        let bytes = m.encode().unwrap();
        let decoded = NerPackManifest::decode(&bytes).unwrap();
        assert_eq!(decoded, m);
        // Re-encoding the decoded value reproduces the exact same bytes.
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    #[test]
    fn pack_round_trips_byte_for_byte() {
        let p = sample_pack();
        let bytes = p.encode().unwrap();
        let decoded = NerPack::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    #[test]
    fn encoding_is_deterministic() {
        let p = sample_pack();
        assert_eq!(p.encode().unwrap(), p.encode().unwrap());
    }

    #[test]
    fn version_measure_and_label_set_are_preserved() {
        let m = sample_manifest();
        let decoded = NerPackManifest::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(decoded.pack_version, m.pack_version);
        assert_eq!(decoded.measure, m.measure);
        assert_eq!(decoded.label_set, m.label_set);
        assert_eq!(decoded.max_input_len, m.max_input_len);
    }

    #[test]
    fn custom_model_kind_round_trips() {
        let mut m = sample_manifest();
        m.model_kind = NerModelKind::Custom("bilstm-crf-v2".to_string());
        let decoded = NerPackManifest::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(decoded.model_kind, m.model_kind);
    }

    #[test]
    fn empty_label_set_and_blob_round_trip() {
        let mut p = sample_pack();
        p.manifest.label_set.clear();
        p.model_blob.clear();
        let decoded = NerPack::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }

    // ---- Fail-closed decode ----------------------------------------------

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = sample_manifest().encode().unwrap();
        bytes[0] = b'X';
        assert!(matches!(
            NerPackManifest::decode(&bytes),
            Err(PackError::BadMagic { .. })
        ));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = sample_manifest().encode().unwrap();
        // Version is the big-endian u16 right after the 8-byte magic; bump the
        // low byte from 1 to 2 to make it unsupported.
        bytes[9] = 2;
        assert!(matches!(
            NerPackManifest::decode(&bytes),
            Err(PackError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let bytes = sample_pack().encode().unwrap();
        let half = &bytes[..bytes.len().div_euclid(2)];
        assert!(NerPack::decode(half).is_err());
    }

    #[test]
    fn size_overflow_length_prefix_is_rejected() {
        let mut bytes = sample_manifest().encode().unwrap();
        // The language length prefix is the u32 at offset 10 (after magic[8]
        // + version[2]). Force it to a value larger than the buffer.
        bytes[10] = 0xFF;
        bytes[11] = 0xFF;
        bytes[12] = 0xFF;
        bytes[13] = 0xFF;
        assert!(matches!(
            NerPackManifest::decode(&bytes),
            Err(PackError::LengthOverflow { .. })
        ));
    }

    #[test]
    fn bad_language_tag_is_rejected_on_decode() {
        // "pt-BR" (len 5) sits at offset 14; overwrite it with spaces so the
        // length is unchanged but the tag is no longer well-formed.
        let mut bytes = sample_manifest().encode().unwrap();
        for b in bytes.iter_mut().skip(14).take(5) {
            *b = b' ';
        }
        assert!(matches!(
            NerPackManifest::decode(&bytes),
            Err(PackError::BadLanguageTag(_))
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample_manifest().encode().unwrap();
        bytes.push(0);
        assert!(matches!(
            NerPackManifest::decode(&bytes),
            Err(PackError::TrailingBytes(1))
        ));
    }

    // ---- Fail-closed encode ----------------------------------------------

    #[test]
    fn bad_language_tag_is_rejected_on_encode() {
        let mut m = sample_manifest();
        m.language = "en_US".to_string();
        assert!(matches!(m.encode(), Err(PackError::BadLanguageTag(_))));
    }

    #[test]
    fn out_of_range_measure_is_rejected_on_encode() {
        let mut m = sample_manifest();
        m.measure.value_milli = MAX_PER_MILLE + 1;
        assert!(matches!(
            m.encode(),
            Err(PackError::MeasureOutOfRange(1001))
        ));
    }

    // ---- BCP-47 well-formedness ------------------------------------------

    #[test]
    fn bcp47_accepts_common_tags() {
        for tag in ["en", "en-US", "pt-BR", "zh-Hant", "de-CH-1901"] {
            assert!(is_well_formed_bcp47(tag), "should accept {tag}");
        }
    }

    #[test]
    fn bcp47_rejects_malformed_tags() {
        for tag in ["", "e", "en_US", "en US", "en-", "toolongsubtag", "123"] {
            assert!(!is_well_formed_bcp47(tag), "should reject {tag:?}");
        }
    }
}

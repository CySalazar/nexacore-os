//! Lazy NER language-pack loader (WS5-12.3).
//!
//! [`NerPack`]s are registered by language with their
//! [`NerPackManifest`] known up-front — enough
//! to route to (WS5-12.2) and gate (WS5-12.7) a pack without touching the
//! model. The heavy encoder **bytes** are pulled only on first use, through the
//! [`PackSource`] seam: the host double serves them from memory, but a real
//! deployment might page them from disk or a signed download.
//!
//! Loaded packs are cached in the [`PackRegistry`]; [`unload`] drops a pack to
//! reclaim its memory, after which the next use re-fetches it. Resolution maps
//! a (possibly regional) detected language to the registered pack that serves
//! it — exact tag first, then a shared primary subtag.
//!
//! # Fail-closed loading
//!
//! A fetch is trusted only if it round-trips: the bytes must parse with
//! [`NerPack::decode`](crate::nerpack::NerPack::decode) **and** the decoded
//! manifest's language must match the one requested. Any source error, decode
//! error, or language mismatch surfaces as a [`LoadError`] and leaves the
//! registry cache untouched — a rejected pack is never partially cached.
//!
//! [`unload`]: PackRegistry::unload

use std::collections::BTreeMap;

use thiserror::Error;

use crate::nerpack::{NerPack, NerPackManifest, PackError};

// =============================================================================
// PackSource seam
// =============================================================================

/// Byte source for language-pack models — the lazy-loading seam (WS5-12.3).
///
/// Given a registered language tag, `fetch` returns the encoded
/// [`NerPack`] bytes for it (the same layout produced
/// by [`NerPack::encode`](crate::nerpack::NerPack::encode)). Implementations do
/// no validation of their own: the [`PackRegistry`] decodes and checks the
/// result fail-closed. The host test double simply serves bytes it already
/// holds in memory; a production source might read a file or a signed download.
pub trait PackSource {
    /// Fetch the encoded pack bytes for `language`.
    ///
    /// # Errors
    ///
    /// Returns a [`SourceError`] if the bytes cannot be produced (missing pack,
    /// I/O failure, …). The registry maps this into
    /// [`LoadError::Source`] and caches nothing.
    fn fetch(&self, language: &str) -> Result<Vec<u8>, SourceError>;
}

/// An opaque error raised by a [`PackSource`] while fetching pack bytes.
///
/// It carries a human-readable message so any backing implementation (file, in
/// memory, network) can report failure through the seam without leaking its
/// concrete error type.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("pack source error: {0}")]
pub struct SourceError(String);

impl SourceError {
    /// Build a source error from a message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// LoadError
// =============================================================================

/// Reason a registered pack could not be loaded on demand.
///
/// Every variant is fail-closed: when `get` returns a `LoadError`, no pack is
/// cached for that language, so a later retry starts clean.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// The [`PackSource`] failed to produce bytes for the language.
    #[error("pack source failed for language {language:?}: {source}")]
    Source {
        /// The requested (registered) language tag.
        language: String,
        /// The underlying source error.
        #[source]
        source: SourceError,
    },

    /// The fetched bytes did not parse as a [`NerPack`].
    #[error("pack for language {language:?} failed to decode: {source}")]
    Decode {
        /// The requested (registered) language tag.
        language: String,
        /// The underlying decode error.
        #[source]
        source: PackError,
    },

    /// The bytes decoded, but the pack declares a different language than the
    /// one requested — a fail-closed integrity guard against a mislabeled or
    /// misrouted pack.
    #[error("pack language mismatch: requested {requested:?} but pack declares {found:?}")]
    LanguageMismatch {
        /// The language the registry asked the source for.
        requested: String,
        /// The language the decoded pack actually declares.
        found: String,
    },
}

// =============================================================================
// PackRegistry
// =============================================================================

/// One registered language: its up-front manifest and lazily-loaded pack.
struct Entry {
    manifest: NerPackManifest,
    /// The decoded pack once fetched; `None` until first use or after `unload`.
    loaded: Option<NerPack>,
}

/// A lazy, caching registry of NER language packs over a [`PackSource`] seam.
///
/// Register a language by its [`NerPackManifest`];
/// the model bytes stay unfetched until [`get`](PackRegistry::get) first needs
/// them. See the [module docs](self) for the loading and fail-closed rules.
pub struct PackRegistry<S: PackSource> {
    source: S,
    /// Keyed by the pack's declared language tag. A `BTreeMap` keeps resolution
    /// order deterministic when several packs share a primary subtag.
    entries: BTreeMap<String, Entry>,
}

impl<S: PackSource> PackRegistry<S> {
    /// A new, empty registry backed by `source`.
    pub fn new(source: S) -> Self {
        Self {
            source,
            entries: BTreeMap::new(),
        }
    }

    /// Borrow the backing [`PackSource`].
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Register a pack by its manifest, keyed on the manifest's language.
    ///
    /// The model bytes are not fetched here — only on first
    /// [`get`](PackRegistry::get). Re-registering a language replaces its
    /// manifest and drops any cached pack.
    pub fn register(&mut self, manifest: NerPackManifest) {
        let language = manifest.language.clone();
        self.entries.insert(
            language,
            Entry {
                manifest,
                loaded: None,
            },
        );
    }

    /// The number of registered languages.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no languages are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve `language` (as detected) to the registered pack that serves it,
    /// returning that pack's canonical language tag, or `None` if none applies.
    ///
    /// Matching is: an exact (ASCII-case-insensitive) tag match first, then a
    /// pack whose primary subtag matches the detected tag's primary subtag (so
    /// a detected `pt` resolves a registered `pt-BR`). Deterministic on ties.
    pub fn resolve(&self, language: &str) -> Option<String> {
        if language.is_empty() {
            return None;
        }
        // Exact tag match wins (ASCII-case-insensitive, per BCP-47).
        if let Some(key) = self
            .entries
            .keys()
            .find(|key| key.eq_ignore_ascii_case(language))
        {
            return Some(key.clone());
        }
        // Otherwise fall back to a pack sharing the primary subtag. The
        // `BTreeMap` iterates in sorted order, so the tie-break is deterministic.
        let primary = primary_subtag(language);
        self.entries
            .keys()
            .find(|key| primary_subtag(key).eq_ignore_ascii_case(primary))
            .cloned()
    }

    /// The up-front manifest for whatever pack serves `language`, without
    /// fetching any bytes.
    pub fn manifest(&self, language: &str) -> Option<&NerPackManifest> {
        let key = self.resolve(language)?;
        self.entries.get(&key).map(|entry| &entry.manifest)
    }

    /// Whether the pack serving `language` currently has its bytes cached.
    pub fn is_loaded(&self, language: &str) -> bool {
        self.resolve(language)
            .and_then(|key| self.entries.get(&key))
            .is_some_and(|entry| entry.loaded.is_some())
    }

    /// Get the pack serving `language`, loading it on first use.
    ///
    /// Returns `None` when no registered pack resolves for `language`.
    /// Otherwise returns the cached pack, fetching and validating it fail-closed
    /// on the first use (and after an [`unload`](PackRegistry::unload)).
    ///
    /// # Errors
    ///
    /// [`LoadError`] if the source fails, the bytes do not decode, or the
    /// decoded pack declares a different language than requested. On any error
    /// nothing is cached.
    pub fn get(&mut self, language: &str) -> Option<Result<&NerPack, LoadError>> {
        let key = self.resolve(language)?;

        // Split the borrows so the immutable `source` and the mutable `entries`
        // can be held at once while loading.
        let Self { source, entries } = self;
        let entry = entries.get_mut(&key)?;

        if entry.loaded.is_none() {
            match Self::load_pack(source, &key) {
                Ok(pack) => entry.loaded = Some(pack),
                // Fail-closed: leave the cache empty so a retry starts clean.
                Err(err) => return Some(Err(err)),
            }
        }

        // `loaded` is `Some` here: either it was cached or we just set it.
        entry.loaded.as_ref().map(Ok)
    }

    /// Drop the cached bytes for the pack serving `language`, reclaiming memory.
    ///
    /// Returns `true` if a loaded pack was actually dropped. The registration
    /// itself remains, so the next [`get`](PackRegistry::get) re-fetches.
    pub fn unload(&mut self, language: &str) -> bool {
        let Some(key) = self.resolve(language) else {
            return false;
        };
        self.entries
            .get_mut(&key)
            .is_some_and(|entry| entry.loaded.take().is_some())
    }

    /// Fetch, decode, and validate the pack for `language` fail-closed.
    fn load_pack(source: &S, language: &str) -> Result<NerPack, LoadError> {
        let bytes = source.fetch(language).map_err(|source| LoadError::Source {
            language: language.to_owned(),
            source,
        })?;
        let pack = NerPack::decode(&bytes).map_err(|source| LoadError::Decode {
            language: language.to_owned(),
            source,
        })?;
        // Integrity guard: the pack must declare the language we asked for.
        if !pack.manifest.language.eq_ignore_ascii_case(language) {
            return Err(LoadError::LanguageMismatch {
                requested: language.to_owned(),
                found: pack.manifest.language,
            });
        }
        Ok(pack)
    }
}

/// The primary (first) subtag of a BCP-47 tag.
fn primary_subtag(tag: &str) -> &str {
    tag.split('-').next().unwrap_or(tag)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use nexacore_crypto::signing::{NexaCoreSignature, NexaCoreSigningKey, SIGNATURE_LEN};

    use super::*;
    use crate::nerpack::{
        MeasureKind, MeasureRef, ModelSignatureRef, NerModelKind, NerPack, PackVersion,
    };

    // ---- Fixtures ---------------------------------------------------------

    fn manifest_for(language: &str) -> NerPackManifest {
        let signing_key = NexaCoreSigningKey::from_bytes([0xAA; 32]).verifying_key();
        NerPackManifest {
            language: language.to_owned(),
            pack_version: PackVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            model_kind: NerModelKind::GlinerClass,
            measure: MeasureRef {
                kind: MeasureKind::Recall,
                value_milli: 900,
            },
            max_input_len: 256,
            label_set: vec!["PER".to_owned(), "ORG".to_owned()],
            model_signature: ModelSignatureRef {
                model_hash: [0x11; 32],
                signature: NexaCoreSignature::from_bytes([7u8; SIGNATURE_LEN]),
                signing_key,
            },
        }
    }

    fn pack_bytes(language: &str) -> Vec<u8> {
        NerPack {
            manifest: manifest_for(language),
            model_blob: vec![1, 2, 3, 4],
        }
        .encode()
        .expect("encode sample pack")
    }

    /// A `PackSource` double that records how many times it was fetched and
    /// serves a configured response per language.
    struct SpySource {
        responses: BTreeMap<String, Result<Vec<u8>, String>>,
        calls: Cell<usize>,
    }

    impl SpySource {
        fn new() -> Self {
            Self {
                responses: BTreeMap::new(),
                calls: Cell::new(0),
            }
        }

        fn serving(language: &str, bytes: Vec<u8>) -> Self {
            let mut source = Self::new();
            source.responses.insert(language.to_owned(), Ok(bytes));
            source
        }

        fn failing(language: &str, message: &str) -> Self {
            let mut source = Self::new();
            source
                .responses
                .insert(language.to_owned(), Err(message.to_owned()));
            source
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl PackSource for SpySource {
        fn fetch(&self, language: &str) -> Result<Vec<u8>, SourceError> {
            self.calls.set(self.calls.get() + 1);
            match self.responses.get(language) {
                Some(Ok(bytes)) => Ok(bytes.clone()),
                Some(Err(message)) => Err(SourceError::new(message.clone())),
                None => Err(SourceError::new(format!("no pack for {language}"))),
            }
        }
    }

    // ---- Lazy loading + caching ------------------------------------------

    #[test]
    fn source_is_not_fetched_until_first_use_then_cached() {
        let mut reg = PackRegistry::new(SpySource::serving("en", pack_bytes("en")));
        reg.register(manifest_for("en"));

        // Registration alone must not touch the source.
        assert_eq!(reg.source().calls(), 0, "registration must not fetch");

        let first = reg.get("en").expect("registered").expect("loads");
        assert_eq!(first.manifest.language, "en");
        assert_eq!(reg.source().calls(), 1, "first use fetches once");

        // A second use is served from cache — no new fetch.
        let _second = reg.get("en").expect("registered").expect("cached");
        assert_eq!(reg.source().calls(), 1, "cached use must not re-fetch");
    }

    #[test]
    fn unload_drops_cache_and_forces_reload() {
        let mut reg = PackRegistry::new(SpySource::serving("en", pack_bytes("en")));
        reg.register(manifest_for("en"));

        reg.get("en").expect("registered").expect("loads");
        assert_eq!(reg.source().calls(), 1);
        assert!(reg.is_loaded("en"));

        assert!(reg.unload("en"), "unload drops a loaded pack");
        assert!(!reg.is_loaded("en"), "pack is no longer cached");
        // Unloading an already-unloaded pack reports nothing was dropped.
        assert!(!reg.unload("en"));

        reg.get("en").expect("registered").expect("reloads");
        assert_eq!(reg.source().calls(), 2, "use after unload re-fetches");
    }

    // ---- Fail-closed loading ---------------------------------------------

    #[test]
    fn decode_failure_is_fail_closed() {
        let mut reg = PackRegistry::new(SpySource::serving("en", b"not a valid pack".to_vec()));
        reg.register(manifest_for("en"));

        let err = reg
            .get("en")
            .expect("registered")
            .expect_err("bad bytes must fail");
        assert!(matches!(err, LoadError::Decode { .. }), "got {err:?}");
        assert!(!reg.is_loaded("en"), "a rejected pack is never cached");
    }

    #[test]
    fn language_mismatch_is_fail_closed() {
        // The source serves bytes whose manifest declares a *different* language.
        let mut reg = PackRegistry::new(SpySource::serving("en", pack_bytes("de")));
        reg.register(manifest_for("en"));

        let err = reg
            .get("en")
            .expect("registered")
            .expect_err("mismatched language must fail");
        assert!(
            matches!(err, LoadError::LanguageMismatch { .. }),
            "got {err:?}"
        );
        assert!(!reg.is_loaded("en"));
    }

    #[test]
    fn source_error_is_fail_closed() {
        let mut reg = PackRegistry::new(SpySource::failing("en", "network down"));
        reg.register(manifest_for("en"));

        let err = reg
            .get("en")
            .expect("registered")
            .expect_err("source error must surface");
        assert!(matches!(err, LoadError::Source { .. }), "got {err:?}");
        assert!(!reg.is_loaded("en"));
    }

    // ---- Resolution -------------------------------------------------------

    #[test]
    fn unregistered_or_undetected_language_returns_none() {
        let mut reg = PackRegistry::new(SpySource::serving("en", pack_bytes("en")));
        reg.register(manifest_for("en"));

        assert!(reg.get("fr").is_none(), "unregistered language yields None");
        assert!(reg.resolve("fr").is_none());
        assert!(reg.get("").is_none(), "empty detection yields None");
        assert_eq!(
            reg.source().calls(),
            0,
            "no fetch for an unresolved language"
        );

        let mut empty = PackRegistry::new(SpySource::new());
        assert!(empty.get("en").is_none(), "empty registry yields None");
    }

    #[test]
    fn resolve_falls_back_to_primary_subtag() {
        let mut reg = PackRegistry::new(SpySource::serving("pt-BR", pack_bytes("pt-BR")));
        reg.register(manifest_for("pt-BR"));

        assert_eq!(reg.resolve("pt-BR").as_deref(), Some("pt-BR"));
        assert_eq!(
            reg.resolve("pt").as_deref(),
            Some("pt-BR"),
            "bare primary subtag resolves the regional pack"
        );
        assert_eq!(
            reg.resolve("pt-PT").as_deref(),
            Some("pt-BR"),
            "a sibling region resolves via the shared primary subtag"
        );
        assert!(
            reg.resolve("es").is_none(),
            "an unrelated tag does not resolve"
        );

        // A detected primary subtag actually loads the regional pack.
        let pack = reg.get("pt").expect("resolves").expect("loads");
        assert_eq!(pack.manifest.language, "pt-BR");
    }

    #[test]
    fn manifest_is_available_without_loading_bytes() {
        let mut reg = PackRegistry::new(SpySource::serving("en", pack_bytes("en")));
        reg.register(manifest_for("en"));

        let manifest = reg.manifest("en").expect("registered manifest");
        assert_eq!(manifest.language, "en");
        assert_eq!(reg.source().calls(), 0, "reading a manifest must not fetch");
        assert!(!reg.is_loaded("en"));
    }
}

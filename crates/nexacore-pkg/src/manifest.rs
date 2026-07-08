//! Package manifest schema with capability declaration (WS9-02.1).
//!
//! A [`PackageManifest`] is the signed description of a package: its identity
//! ([`PackageName`] + [`Version`]), the `BLAKE3` content hash of the artifact it
//! refers to, its [`Dependency`] list, and the [`CapabilityRequest`]s it needs
//! to run. The capability declaration reuses the OS capability vocabulary
//! ([`nexacore_capability::scope::Action`] / [`nexacore_capability::scope::Resource`]),
//! so what a package may do is expressed in exactly the terms the kernel
//! enforces — no parallel permission model.
//!
//! # Signing
//!
//! [`PackageManifest::canonical_bytes`] is the deterministic pre-image the
//! Sigstore signature (WS9-02.3) covers, produced with the workspace canonical
//! encoder ([`nexacore_types::wire::encode_canonical`], postcard / NCIP-Serde-004).
//! Two manifests are signature-equal iff their canonical bytes match.

use std::{collections::HashSet, fmt};

use nexacore_capability::scope::{Action, Resource};
use serde::{Deserialize, Serialize};

/// The `BLAKE3` content-hash width used for package content addresses.
pub const CONTENT_HASH_LEN: usize = 32;

/// The maximum length of a [`PackageName`].
pub const MAX_NAME_LEN: usize = 64;

/// What can go wrong validating or encoding a manifest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// A package name was empty, too long, or contained disallowed characters.
    #[error("invalid package name")]
    BadName,
    /// A version string was not `major.minor.patch` of unsigned integers.
    #[error("invalid version (expected major.minor.patch)")]
    BadVersion,
    /// The manifest declared the same dependency more than once.
    #[error("duplicate dependency")]
    DuplicateDependency,
    /// Canonical encoding of the manifest failed.
    #[error("manifest canonical encoding failed")]
    Encode,
}

/// A validated package name: 1–[`MAX_NAME_LEN`] characters, lowercase ASCII
/// alphanumeric or `-`, starting with a letter and not ending in `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageName(String);

impl PackageName {
    /// Validate and construct a package name.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::BadName`] if `name` violates the naming rules.
    pub fn new(name: impl Into<String>) -> Result<Self, ManifestError> {
        let name = name.into();
        let len_ok = (1..=MAX_NAME_LEN).contains(&name.len());
        let starts_with_letter = name.chars().next().is_some_and(|c| c.is_ascii_lowercase());
        let chars_ok = name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        let ends_ok = !name.ends_with('-');
        if len_ok && starts_with_letter && chars_ok && ends_ok {
            Ok(Self(name))
        } else {
            Err(ManifestError::BadName)
        }
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A `major.minor.patch` semantic version.
///
/// The derived [`Ord`] compares major, then minor, then patch — the usual
/// precedence — so version requirements can be checked with `>=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    /// Incompatible API changes.
    pub major: u32,
    /// Backwards-compatible additions.
    pub minor: u32,
    /// Backwards-compatible fixes.
    pub patch: u32,
}

impl Version {
    /// A version from its three components.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse a `major.minor.patch` string.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::BadVersion`] if `s` is not exactly three
    /// dot-separated unsigned integers.
    pub fn parse(s: &str) -> Result<Self, ManifestError> {
        let mut parts = s.split('.');
        let major = next_component(&mut parts)?;
        let minor = next_component(&mut parts)?;
        let patch = next_component(&mut parts)?;
        if parts.next().is_some() {
            return Err(ManifestError::BadVersion);
        }
        Ok(Self::new(major, minor, patch))
    }
}

/// Parse the next dot-separated version component as a `u32`.
fn next_component(parts: &mut core::str::Split<'_, char>) -> Result<u32, ManifestError> {
    parts
        .next()
        .ok_or(ManifestError::BadVersion)?
        .parse::<u32>()
        .map_err(|_| ManifestError::BadVersion)
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A dependency on another package at a minimum version.
///
/// Richer version ranges are a later concern (WS9-02.5); v1 records the lowest
/// acceptable version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// The depended-on package.
    pub name: PackageName,
    /// The lowest acceptable version.
    pub min_version: Version,
}

impl Dependency {
    /// A dependency on `name` at `min_version` or newer.
    #[must_use]
    pub const fn new(name: PackageName, min_version: Version) -> Self {
        Self { name, min_version }
    }
}

/// A capability a package requests, in the OS capability vocabulary: the right
/// to perform `action` on `resource`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// The action requested.
    pub action: Action,
    /// The resource the action targets.
    pub resource: Resource,
}

impl CapabilityRequest {
    /// A request for `action` on `resource`.
    #[must_use]
    pub const fn new(action: Action, resource: Resource) -> Self {
        Self { action, resource }
    }
}

/// The signed description of a package (WS9-02.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// The package name.
    pub name: PackageName,
    /// The package version.
    pub version: Version,
    /// `BLAKE3` content hash of the package artifact (its content address).
    pub content_hash: [u8; CONTENT_HASH_LEN],
    /// Other packages this one depends on.
    pub dependencies: Vec<Dependency>,
    /// The capabilities the package requests to run.
    pub capabilities: Vec<CapabilityRequest>,
    /// A short human-readable description.
    pub description: String,
}

impl PackageManifest {
    /// A manifest for `name` `version` addressing `content_hash`, with no
    /// dependencies, no capabilities, and an empty description.
    #[must_use]
    pub fn new(name: PackageName, version: Version, content_hash: [u8; CONTENT_HASH_LEN]) -> Self {
        Self {
            name,
            version,
            content_hash,
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            description: String::new(),
        }
    }

    /// Whether the manifest declares the capability to perform `action` on
    /// `resource`.
    #[must_use]
    pub fn declares(&self, action: Action, resource: &Resource) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.action == action && &c.resource == resource)
    }

    /// Validate the manifest: names well-formed and dependencies unique.
    ///
    /// (Construction via [`PackageName::new`] already validates names; this
    /// re-checks a manifest that was deserialized, where the derived
    /// `Deserialize` does not run the constructors.)
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::BadName`] for a malformed package or dependency
    /// name, or [`ManifestError::DuplicateDependency`] if a dependency appears
    /// more than once.
    pub fn validate(&self) -> Result<(), ManifestError> {
        PackageName::new(self.name.as_str())?;
        let mut seen = HashSet::new();
        for dep in &self.dependencies {
            PackageName::new(dep.name.as_str())?;
            if !seen.insert(dep.name.clone()) {
                return Err(ManifestError::DuplicateDependency);
            }
        }
        Ok(())
    }

    /// The deterministic byte pre-image the package signature covers
    /// ([`nexacore_types::wire::encode_canonical`]).
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Encode`] if canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        nexacore_types::wire::encode_canonical(self).map_err(|_| ManifestError::Encode)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn hash(tag: u8) -> [u8; CONTENT_HASH_LEN] {
        [tag; CONTENT_HASH_LEN]
    }

    fn name(s: &str) -> PackageName {
        PackageName::new(s).expect("valid test name")
    }

    #[test]
    fn package_name_accepts_valid_names() {
        assert!(PackageName::new("nexacore-shell").is_ok());
        assert!(PackageName::new("a").is_ok());
        assert!(PackageName::new("app7").is_ok());
        assert_eq!(
            PackageName::new("nexacore-shell")
                .map(|n| n.as_str().to_owned())
                .ok(),
            Some("nexacore-shell".to_owned())
        );
    }

    #[test]
    fn package_name_rejects_invalid_names() {
        assert_eq!(PackageName::new(""), Err(ManifestError::BadName));
        assert_eq!(PackageName::new("-leading"), Err(ManifestError::BadName));
        assert_eq!(PackageName::new("trailing-"), Err(ManifestError::BadName));
        assert_eq!(PackageName::new("9start"), Err(ManifestError::BadName));
        assert_eq!(PackageName::new("Upper"), Err(ManifestError::BadName));
        assert_eq!(PackageName::new("has space"), Err(ManifestError::BadName));
        assert_eq!(PackageName::new("under_score"), Err(ManifestError::BadName));
        assert_eq!(
            PackageName::new("x".repeat(MAX_NAME_LEN + 1)),
            Err(ManifestError::BadName)
        );
    }

    #[test]
    fn version_parses_and_orders() {
        assert_eq!(Version::parse("1.2.3"), Ok(Version::new(1, 2, 3)));
        assert_eq!(Version::parse("0.0.0"), Ok(Version::new(0, 0, 0)));
        assert_eq!(Version::parse("1.2"), Err(ManifestError::BadVersion));
        assert_eq!(Version::parse("1.2.3.4"), Err(ManifestError::BadVersion));
        assert_eq!(Version::parse("1.2.x"), Err(ManifestError::BadVersion));
        assert!(Version::new(1, 0, 0) > Version::new(0, 9, 9));
        assert!(Version::new(1, 2, 0) > Version::new(1, 1, 9));
        assert!(Version::new(1, 1, 2) > Version::new(1, 1, 1));
    }

    #[test]
    fn version_display_round_trips() {
        let v = Version::new(3, 14, 159);
        assert_eq!(Version::parse(&v.to_string()), Ok(v));
    }

    #[test]
    fn declares_finds_requested_capabilities() {
        let mut m = PackageManifest::new(name("editor"), Version::new(1, 0, 0), hash(1));
        m.capabilities.push(CapabilityRequest::new(
            Action::Read,
            Resource::Filesystem("/home/**".to_owned()),
        ));
        assert!(m.declares(Action::Read, &Resource::Filesystem("/home/**".to_owned())));
        // A different action or resource is not declared.
        assert!(!m.declares(Action::Write, &Resource::Filesystem("/home/**".to_owned())));
        assert!(!m.declares(
            Action::Read,
            &Resource::Network("example.com:443".to_owned())
        ));
    }

    #[test]
    fn validate_accepts_a_well_formed_manifest() {
        let mut m = PackageManifest::new(name("editor"), Version::new(1, 0, 0), hash(7));
        m.dependencies
            .push(Dependency::new(name("libfoo"), Version::new(0, 3, 0)));
        m.dependencies
            .push(Dependency::new(name("libbar"), Version::new(2, 0, 0)));
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_duplicate_dependencies() {
        let mut m = PackageManifest::new(name("editor"), Version::new(1, 0, 0), hash(7));
        m.dependencies
            .push(Dependency::new(name("libfoo"), Version::new(0, 3, 0)));
        m.dependencies
            .push(Dependency::new(name("libfoo"), Version::new(0, 4, 0)));
        assert_eq!(m.validate(), Err(ManifestError::DuplicateDependency));
    }

    #[test]
    fn canonical_bytes_are_deterministic_and_identity_sensitive() {
        let a = PackageManifest::new(name("editor"), Version::new(1, 0, 0), hash(1));
        let a2 = PackageManifest::new(name("editor"), Version::new(1, 0, 0), hash(1));
        let b = PackageManifest::new(name("editor"), Version::new(1, 0, 1), hash(1));
        let ca = a.canonical_bytes().expect("encode a");
        assert_eq!(ca, a2.canonical_bytes().expect("encode a2"));
        assert_ne!(ca, b.canonical_bytes().expect("encode b"));
    }

    #[test]
    fn canonical_bytes_round_trip_via_decode() {
        let mut m = PackageManifest::new(name("editor"), Version::new(2, 1, 0), hash(9));
        m.capabilities.push(CapabilityRequest::new(
            Action::Connect,
            Resource::Network("*:443".to_owned()),
        ));
        m.description = "a test package".to_owned();
        let bytes = m.canonical_bytes().expect("encode");
        let decoded: PackageManifest =
            nexacore_types::wire::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, m);
        assert_eq!(decoded.validate(), Ok(()));
    }
}
